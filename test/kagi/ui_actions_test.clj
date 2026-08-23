(ns kagi.ui-actions-test
  "The window against a REAL vault: real identity, real AccessGovernor, real
  reveal graph, real ledger — driven over the real loopback socket.

  Everything is genuine except two things, and both are the point:

  * the clipboard is `kagi.clipboard/memory-clipboard`, so the assertion can
    read what actually landed on it instead of trusting the report, and this
    suite does not clobber the clipboard of whoever runs it;
  * the vault is a `mem-store` seeded through the same `:item/create` op the
    CLI uses, so nothing is written to a disk that a later test would inherit.

  What this covers that `kagi.ui-server-test` cannot: that suite proves the
  server calls the actions it was handed. This one proves the actions handed
  to it by `kagi ui` really do reach the governor, and that a plaintext which
  genuinely exists still never reaches the page."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kagi.clipboard :as clipboard]
            [kagi.crypto :as crypto]
            [kagi.device :as device]
            [kagi.identity :as identity]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.ui.actions :as ui-actions]
            [kagi.ui.server :as ui-server]
            [langgraph.graph :as g])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest
            HttpRequest$BodyPublishers HttpResponse$BodyHandlers]))

(def ^:private gh-secret "ghp_this_value_must_never_render")

(defn- send! [method url headers body]
  (let [b (HttpRequest/newBuilder (URI/create url))]
    (doseq [[k v] headers] (.header b k v))
    (.send (.build (.followRedirects (HttpClient/newBuilder) HttpClient$Redirect/NEVER))
           (.build (.method b method (if body
                                       (HttpRequest$BodyPublishers/ofString body)
                                       (HttpRequest$BodyPublishers/noBody))))
           (HttpResponse$BodyHandlers/ofString))))

(defn- seed! [{:keys [store provider identity vmk]} item-id compartment category plaintext]
  (let [actor (op/build store {:crypto provider})]
    (g/run* actor
            {:request {:op :item/create :item-id item-id :compartment compartment
                       :category category :plaintext (.getBytes ^String plaintext "UTF-8")}
             :context {:did (:did identity) :role :owner :phase 1 :vmk vmk
                       :purpose :daily-use}}
            {:thread-id (str "seed-" item-id)})))

(defn- vault []
  (let [p (crypto/jvm-provider)
        id (identity/generate-identity p)
        st (store/mem-store {:members {(:did id) #:member{:did (:did id) :role :owner}}})
        session {:status :open :provider p :identity id :did (:did id)
                 :vmk (crypto/rand-bytes p 32) :store st :vault-home "/tmp/kagi-ui-test"}]
    (seed! session "gh-token" "work" :api-credential gh-secret)
    (seed! session "b2-key" "personal" :api-credential "b2-value")
    session))

(defn- meta-with-devices []
  (-> {}
      (device/register {:device-id "dev-1" :label "25mbair"
                        :fingerprint "AB-CD" :wrap-ref "keychain://kagi/dev-1"})
      (device/register {:device-id "dev-2" :label "old-mini"
                        :fingerprint "11-22" :wrap-ref "keychain://kagi/dev-2"})))

(defn- with-window [f]
  (let [session (vault)
        meta-state (atom (meta-with-devices))
        saved (atom [])
        clip (clipboard/memory-clipboard)
        window (ui-server/start!
                {:css "" :rand-fn #(crypto/rand-bytes (:provider session) %)
                 :actions (ui-actions/actions
                           {:session session
                            :meta-state meta-state
                            :save! #(swap! saved conj %)
                            :clipboard clip
                            :copy-ttl-sec 45
                            ;; The real one schedules a clearing future; this
                            ;; suite asserts on what was copied, and a stray
                            ;; timer outliving the test is a flake.
                            :clipboard-copy! (fn [c secret _opts] (clipboard/copy! c secret))
                            :vault-home "/tmp/kagi-ui-test"})})]
    (try (f {:window window :clip clip :saved saved :meta-state meta-state
              :session session})
         (finally ((:stop window))))))

(defn- get-page [window]
  (.body (send! "GET" (:origin window)
                {"Cookie" (str "kagi_ui_session=" (:token window))} nil)))

(defn- post! [window path form]
  (send! "POST" (str (:origin window) path)
         {"Cookie" (str "kagi_ui_session=" (:token window))
          "Origin" (:origin window)
          "Content-Type" "application/x-www-form-urlencoded"}
         (str "token=" (:token window) "&" form)))

(deftest the-list-comes-from-the-vault-and-carries-no-plaintext
  (with-window
    (fn [{:keys [window]}]
      (let [page (get-page window)]
        (is (str/includes? page "gh-token"))
        (is (str/includes? page "b2-key"))
        (is (str/includes? page "api-credential") "the category is read from the vault")
        (is (not (str/includes? page gh-secret))
            "a real secret reached the page")))))

(deftest copy-really-decrypts-and-the-value-goes-only-to-the-clipboard
  (with-window
    (fn [{:keys [window clip]}]
      (let [res (post! window "/copy" "item=gh-token")]
        (is (= 303 (.statusCode res)))
        (is (not (str/includes? (.body res) gh-secret))))
      (testing "the governor let it through and the plaintext is on the clipboard"
        (is (= gh-secret (clipboard/paste clip))))
      (testing "and is on nothing else"
        (is (not (str/includes? (get-page window) gh-secret)))))))

(deftest a-reveal-the-governor-refuses-is-reported-as-a-refusal
  ;; A reveal with no declared purpose is exactly what the AccessGovernor
  ;; exists to stop (kagi.vault-read-test asserts the same denial). Driving the
  ;; real denial — rather than a fake that returns nil — is what makes this a
  ;; test of the enforcement point and not of a stub.
  (with-redefs [ui-actions/copy-purpose nil]
    (with-window
      (fn [{:keys [window clip]}]
        (post! window "/copy" "item=gh-token")
        (is (nil? (not-empty (clipboard/paste clip)))
            "a refused reveal still reached the clipboard")
        (let [page (get-page window)]
          (is (str/includes? page "data-type=\"error\""))
          (is (str/includes? page "governor が拒否"))
          (is (not (str/includes? page gh-secret))))))))

(deftest an-item-that-does-not-exist-is-not-the-same-answer-as-a-refusal
  (with-window
    (fn [{:keys [window clip]}]
      (post! window "/copy" "item=no-such-item")
      (let [page (get-page window)]
        (is (str/includes? page "そんな item は無い"))
        (is (not (str/includes? page "governor が拒否"))
            "a typo was reported as a policy decision"))
      (is (str/blank? (clipboard/paste clip))))))

(deftest revoking-persists-and-the-next-page-shows-it
  (with-window
    (fn [{:keys [window saved meta-state]}]
      (is (str/includes? (get-page window) "25mbair"))
      (post! window "/device/revoke" "device-id=dev-1")
      (testing "the new meta was handed to the persister, not just held in memory"
        (is (= 1 (count @saved)))
        (is (some? (->> (device/devices (first @saved))
                        (filter #(= "dev-1" (:device/id %)))
                        first
                        :device/revoked-at))))
      (testing "and the page is rendered from the CURRENT meta"
        (let [page (get-page window)]
          (is (str/includes? page "revoked"))
          ;; dev-2 is untouched, so exactly one revoke control should remain.
          (is (= 1 (count (re-seq #"\?confirm=" page))))))
      (is (some? (:device/revoked-at
                  (first (filter #(= "dev-1" (:device/id %))
                                 (device/devices @meta-state)))))))))

(deftest the-unlock-view-shows-the-envelope-and-not-the-keys
  (with-window
    (fn [{:keys [window session]}]
      (let [page (get-page window)
            id (:identity session)]
        (is (str/includes? page (str (:did id))) "the window says whose vault this is")
        ;; The actual private halves of THIS session's identity, not a
        ;; freshly generated one — comparing against a different key would
        ;; pass no matter what the page contained.
        (doseq [[k v] (select-keys id [:private-b64 :mldsa-private-b64 :kem-secret])]
          (is (not (str/includes? page (str v)))
              (str (name k) " is on the page")))
        (is (not (str/includes? page (.encodeToString (java.util.Base64/getEncoder)
                                                      ^bytes (:vmk session))))
            "the VMK is on the page")))))
