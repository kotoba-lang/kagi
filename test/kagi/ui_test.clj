(ns kagi.ui-test
  "The renderer, against the two things it must never get wrong: showing a
  secret, and shipping a view nobody can reach."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kagi.ui :as ui]))

(def ^:private plaintext "correct-horse-battery-staple")

(def ^:private sample
  {:css ""
   :token "session-token"
   :clipboard-ttl-sec 45
   :items [{:item/id "gh-token" :item/compartment "work" :item/category :login
            :item/version 3 :item/updated-at "2026-08-20T09:00:00Z"}
           {:item/id "b2-key" :item/compartment "personal"
            :item/version 1 :item/created-at "2026-07-01T00:00:00Z"}]
   :devices [{:device/id "dev-1" :device/label "25mbair"
              :device/fingerprint "AB-CD-EF" :device/enrolled-at "2026-07-27T00:00:00Z"}
             {:device/id "dev-2" :device/label "old-mini"
              :device/fingerprint "11-22-33" :device/enrolled-at "2026-06-01T00:00:00Z"
              :device/revoked-at "2026-08-01T00:00:00Z"}]
   :vault {:did "did:key:zabc" :graph "k51xyz" :home "~/.kagi"
           :unlock {:wrap-count 2 :passphrase-recovery? true
                    :methods [{:method :os-keychain :provider :apple-keychain
                               :ref "keychain://kagi/…"}
                              {:method :passkey-prf :provider :webauthn
                               :ref "credential://…"}]}}})

(deftest renders-every-item-and-device
  (let [html (ui/document sample)]
    (doseq [id ["gh-token" "b2-key"]]
      (is (str/includes? html id) (str id " is missing from the item list")))
    (doseq [label ["25mbair" "old-mini"]]
      (is (str/includes? html label) (str label " is missing from the device list")))
    (testing "a revoked device offers no revoke control, an active one does"
      (is (str/includes? html "revoked 2026-08-01T00:00:00Z"))
      (is (= 1 (count (re-seq #"\?confirm=" html)))
          "exactly one device is still revocable"))))

(deftest revoking-asks-before-it-acts
  (let [listing (ui/document sample)
        confirming (ui/document (assoc sample :confirm "dev-1"))]
    (testing "the plain list has no POST form for revocation at all — the
              control is a link, so no GET can revoke anything"
      (is (not (str/includes? listing "action=\"/device/revoke\"")))
      (is (str/includes? listing "?confirm=dev-1")))
    (testing "confirming draws the form, for that device and no other"
      (is (str/includes? confirming "action=\"/device/revoke\""))
      (is (= 1 (count (re-seq #"name=\"device-id\"" confirming))))
      (is (str/includes? confirming "value=\"dev-1\""))
      (is (str/includes? confirming "本当に revoke する"))
      (is (str/includes? confirming "やめる") "there has to be a way out"))))

(deftest a-secret-handed-to-the-renderer-cannot-come-back-out
  ;; The server never passes one — this asserts the renderer would not print
  ;; it even if a future caller did, which is the only way the invariant
  ;; survives a change to the caller.
  (let [html (ui/document (-> sample
                              (assoc-in [:items 0 :item/plaintext] plaintext)
                              (assoc-in [:vault :secret] plaintext)))]
    (is (not (str/includes? html plaintext))
        "a plaintext reached the rendered document")))

(defn- nav-markup
  "Just the <nav> element.

  Asserting hrefs against the whole document does not discriminate: the
  routing CSS names every fragment too (`a[href=\"#vault\"]`), so a view
  dropped from the nav is still 'found' in the <style> block. Measured — the
  first version of this test passed with the last view removed from the nav."
  [html]
  (subs html (str/index-of html "<nav") (str/index-of html "</nav>")))

(deftest every-view-is-reachable-and-addressable
  (let [html (ui/document sample)
        nav (nav-markup html)]
    (doseq [{:keys [id fragment label]} ui/views]
      (is (str/includes? html (str "id=\"" (name id) "\""))
          (str label " has no section in the document"))
      (is (str/includes? nav (str "href=\"" fragment "\""))
          (str label " is in the document but not in the nav — a live-looking dead view")))
    (testing "the routing CSS names the default view, so an unaddressed document is not blank"
      (is (str/includes? html (str "body:not(:has(.kagi-view:target)) #"
                                   (name (:id ui/default-view))))))))

(deftest unknown-fragments-land-on-the-default
  (is (= (:id ui/default-view) (:id (ui/fragment->view nil))))
  (is (= (:id ui/default-view) (:id (ui/fragment->view ""))))
  (is (= (:id ui/default-view) (:id (ui/fragment->view "#nope"))))
  (is (= :devices (:id (ui/fragment->view "#devices")))))

(deftest an-empty-vault-says-what-to-do-rather-than-nothing
  (let [html (ui/document (assoc sample :items [] :devices []))]
    (is (str/includes? html "kagi add"))
    (is (str/includes? html "kagi device request"))))

(deftest a-failed-action-is-not-rendered-as-a-success
  (let [failed (ui/document (assoc sample :flash {:ok? false :heading "reveal を governor が拒否した"
                                                  :detail ":denied"}))
        ok (ui/document (assoc sample :flash {:ok? true :heading "コピーした"}))]
    (is (str/includes? failed "data-type=\"error\""))
    (is (str/includes? ok "data-type=\"success\""))))

(deftest the-document-carries-no-script
  (let [html (ui/document sample)]
    (is (not (str/includes? html "<script")))
    (is (not (re-find #"(?i)\son[a-z]+=" html))
        "an inline event handler is a script by another name")))

;; ── search ─────────────────────────────────────────────────────────────────

(deftest a-blank-query-shows-the-whole-vault
  ;; The realistic wrong implementation is a short-circuit to `[]` for a blank
  ;; query — "nothing was searched for, so nothing matches" — which empties
  ;; the window for anyone who presses the button without typing.
  (is (= 2 (count (ui/matching-items (:items sample) nil))))
  (is (= 2 (count (ui/matching-items (:items sample) ""))))
  (is (= 2 (count (ui/matching-items (:items sample) "   ")))
      "whitespace submitted by an empty form must not empty the vault"))

(deftest search-matches-the-three-things-the-row-shows
  (let [ids #(mapv :item/id (ui/matching-items (:items sample) %))]
    (is (= ["gh-token"] (ids "gh")) "id")
    (is (= ["b2-key"] (ids "personal")) "compartment")
    (is (= ["gh-token"] (ids "login")) "category")
    (is (= ["gh-token"] (ids "GH-TOKEN")) "case-insensitive")
    (is (= [] (ids "no-such-thing")))
    (testing "and nothing else — a list screen does not open items, so a query
              that could only match a secret's contents finds nothing"
      (is (= [] (ids "correct-horse"))))))

(deftest no-matches-is-not-an-empty-vault
  (let [none (ui/document (assoc sample :q "zzzz"))
        empty-vault (ui/document (assoc sample :items []))]
    (is (str/includes? none "2 件中 0 件"))
    (is (not (str/includes? none "kagi add"))
        "a filter that matched nothing was drawn as an empty vault")
    (is (str/includes? empty-vault "kagi add"))))

(deftest a-filtered-list-says-how-much-it-is-hiding
  (let [html (ui/document (assoc sample :q "gh"))]
    (is (str/includes? html "1 / 2 items"))
    (is (str/includes? html "gh-token"))
    (is (not (str/includes? html "b2-key")))
    (testing "and offers a way back to the whole list"
      (is (str/includes? html "解除")))))

;; ── detail ─────────────────────────────────────────────────────────────────

(def ^:private opened-item
  {:item/id "claude-pro" :item/category :membership :item/title "Claude Pro"
   :item/username "jun@example.com" :item/url "https://claude.ai"
   :item/sections
   [{:section/title "Login"
     :section/fields [{:field/id "username" :field/title "username"
                       :field/type :string :field/value "jun@example.com"}
                      {:field/id "password" :field/title "password"
                       :field/type :concealed :field/value nil :field/redacted? true}]}]})

(deftest an-opened-item-shows-its-shape-and-not-its-secrets
  (let [html (ui/document (assoc sample :detail {:status :ok :item opened-item
                                                 :item-id "claude-pro"}))]
    (is (str/includes? html "Claude Pro"))
    (is (str/includes? html "jun@example.com") "a non-sensitive field is shown")
    (testing "a concealed field is present and marked SET — not missing, which
              would read as 'no password'"
      (is (str/includes? html "password"))
      (is (str/includes? html "設定済み・伏せてある")))
    (is (not (str/includes? html plaintext)))))

(deftest a-concealed-value-that-somehow-survived-is-still-not-printed
  ;; strip-sensitive drops the value upstream. If it ever stopped, this is the
  ;; assertion that says so — the renderer is handed a field that IS marked
  ;; redacted but still carries a value, and must print the marker, not it.
  (let [leaky (assoc-in opened-item [:item/sections 0 :section/fields 1 :field/value]
                        plaintext)
        html (ui/document (assoc sample :detail {:status :ok :item leaky
                                                 :item-id "claude-pro"}))]
    (is (not (str/includes? html plaintext)))))

(deftest the-four-answers-to-opening-an-item-are-drawn-as-four-things
  (let [page #(ui/document (assoc sample :detail %))
        ok (page {:status :ok :item opened-item :item-id "claude-pro"})
        raw (page {:status :raw :item-id "note"})
        denied (page {:status :denied :item-id "gh-token"})
        absent (page {:status :absent :item-id "nope"})]
    (is (str/includes? ok "Claude Pro"))
    (is (str/includes? raw "素の secret"))
    (is (str/includes? raw "value=\"note\"") "raw still offers Copy, for the right item")
    (is (str/includes? denied "governor が拒否"))
    (is (str/includes? absent "そんな item は無い"))
    (testing "denied and absent are not the same screen"
      (is (not (str/includes? denied "そんな item は無い")))
      (is (not (str/includes? absent "governor が拒否"))))))

(deftest opening-an-item-keeps-the-search-that-found-it
  (is (= "/?item=gh-token&q=work#items" (ui/item-href "gh-token" "work")))
  (is (= "/?item=gh-token#items" (ui/item-href "gh-token" "")))
  (testing "and an id with a space or an ampersand stays one parameter"
    (is (str/includes? (ui/item-href "a b" "") "item=a+b"))
    (is (not (str/includes? (ui/item-href "a&b=c" "") "a&b=c"))))
  (testing "closing it keeps the search too"
    (is (str/includes? (ui/document (assoc sample :q "work"
                                           :detail {:status :ok :item opened-item
                                                    :item-id "claude-pro"}))
                       "/?q=work#items"))))
