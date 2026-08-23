(ns kagi.ui-server-test
  "The gates in front of the vault window, each asserted to refuse for its own
  reason.

  Every rejection below checks the reason string, not just the status. A test
  that only asserts 403 passes when the request was refused for some other
  reason entirely — which is how a control ends up green while the thing it
  claims to guard is wide open (CLAUDE.md, 'the six questions', item 6)."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kagi.ui :as ui]
            [kagi.ui.server :as ui-server])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest
            HttpRequest$BodyPublishers HttpResponse$BodyHandlers]))

(def ^:private plaintext "correct-horse-battery-staple")

(defn- client []
  ;; NEVER follow redirects: a 303 that is followed hides both the status and
  ;; the Set-Cookie this suite is about.
  (.build (.followRedirects (HttpClient/newBuilder) HttpClient$Redirect/NEVER)))

(defn- send! [method url headers body]
  (let [b (HttpRequest/newBuilder (URI/create url))]
    (doseq [[k v] headers] (.header b k v))
    (.send (client)
           (.build (.method b method (if body
                                       (HttpRequest$BodyPublishers/ofString body)
                                       (HttpRequest$BodyPublishers/noBody))))
           (HttpResponse$BodyHandlers/ofString))))

(defn- fake-actions [log]
  {:snapshot (fn []
               {:items [{:item/id "gh-token" :item/compartment "work"
                         :item/category :login :item/version 2}]
                :clipboard-ttl-sec 45
                :devices [{:device/id "dev-1" :device/label "25mbair"
                           :device/fingerprint "AB-CD" :device/enrolled-at "2026-07-27"}]
                :vault {:did "did:key:zabc" :graph "k51xyz" :home "~/.kagi"
                        :unlock {:wrap-count 1 :methods []}}})
   :copy! (fn [item]
            (swap! log conj [:copy! item])
            ;; What the real one returns: a report, never the value.
            {:ok? true :heading (str item " を clipboard にコピーした")})
   :revoke! (fn [device-id]
              (swap! log conj [:revoke! device-id])
              {:ok? true :heading (str device-id " を revoke した")})})

(defn- with-window [f]
  (let [log (atom [])
        window (ui-server/start! {:actions (fake-actions log)
                                  :css ""
                                  :rand-fn #(byte-array (repeat % (byte 7)))})]
    (try (f window log) (finally ((:stop window))))))

(defn- session [window]
  {"Cookie" (str "kagi_ui_session=" (:token window))})

(deftest the-socket-is-loopback-only
  (with-window
    (fn [window _log]
      (is (str/starts-with? (:origin window) "http://127.0.0.1:"))
      (testing "the URL handed to the browser carries the token once, in the query"
        (is (str/includes? (:url window) (str "?token=" (:token window))))))))

(deftest without-a-session-nothing-is-served
  (with-window
    (fn [window _log]
      (let [res (send! "GET" (:origin window) {} nil)]
        (is (= 403 (.statusCode res)))
        (is (str/includes? (.body res) "no-session")))
      (testing "a wrong token in the query is refused as a bad token, not served"
        (let [res (send! "GET" (str (:origin window) "/?token=guess") {} nil)]
          (is (= 403 (.statusCode res)))
          (is (str/includes? (.body res) "bad-session-token"))))
      (testing "a wrong cookie is not a session"
        (let [res (send! "GET" (:origin window) {"Cookie" "kagi_ui_session=guess"} nil)]
          (is (= 403 (.statusCode res)))
          (is (str/includes? (.body res) "no-session")))))))

(deftest the-token-is-exchanged-for-a-cookie-and-left-out-of-the-address-bar
  (with-window
    (fn [window _log]
      (let [res (send! "GET" (str (:origin window) "/?token=" (:token window)) {} nil)
            set-cookie (.orElse (.firstValue (.headers res) "set-cookie") "")
            location (.orElse (.firstValue (.headers res) "location") "")]
        (is (= 303 (.statusCode res)))
        (is (str/includes? set-cookie (str "kagi_ui_session=" (:token window))))
        (is (str/includes? set-cookie "HttpOnly"))
        (is (str/includes? set-cookie "SameSite=Strict"))
        (testing "the redirect goes to a bare path — no token left to be read back"
          (is (= (str "/" (:fragment ui/default-view)) location))
          (is (not (str/includes? location "token"))))))))

(deftest the-page-renders-the-snapshot-and-refuses-to-be-cached
  (with-window
    (fn [window _log]
      (let [res (send! "GET" (:origin window) (session window) nil)]
        (is (= 200 (.statusCode res)))
        (is (str/includes? (.body res) "gh-token"))
        (is (str/includes? (.body res) "25mbair"))
        (is (= "no-store" (.orElse (.firstValue (.headers res) "cache-control") "")))
        (testing "the browser is told the page may run nothing"
          (let [csp (.orElse (.firstValue (.headers res) "content-security-policy") "")]
            (is (str/includes? csp "default-src 'none'"))
            (is (str/includes? csp "frame-ancestors 'none'"))))))))

(deftest a-post-without-the-form-token-does-not-reach-the-vault
  (with-window
    (fn [window log]
      (let [res (send! "POST" (str (:origin window) "/copy")
                       (merge (session window)
                              {"Content-Type" "application/x-www-form-urlencoded"})
                       "item=gh-token")]
        (is (= 403 (.statusCode res)))
        (is (str/includes? (.body res) "bad-form-token")))
      (is (= [] @log) "the action ran despite the missing form token"))))

(deftest the-referrer-policy-does-not-suppress-the-origin-the-gate-requires
  ;; The one defect in this feature that no unit test could have found, and the
  ;; reason it is pinned here rather than described in a comment.
  ;;
  ;; The page went out with `Referrer-Policy: no-referrer`. A browser served
  ;; that header sends `Origin: null` on its OWN same-origin form POSTs — so
  ;; every Copy and every Revoke came back `bad-origin`, while this suite
  ;; stayed green, because an HTTP client sends whatever Origin the test hands
  ;; it. Measured in a real browser on 2026-08-23, then confirmed against an
  ;; echo server: `no-referrer` -> `Origin: "null"`, `same-origin` -> the real
  ;; origin.
  ;;
  ;; So: if this header is ever tightened back, this fails and says why.
  (with-window
    (fn [window log]
      (is (= "same-origin"
             (.orElse (.firstValue (.headers (send! "GET" (:origin window)
                                                    (session window) nil))
                                   "referrer-policy") ""))
          "no-referrer makes the browser send Origin: null to our own POST gate")
      (testing "and `null` itself is still refused — it is what a sandboxed or
                cross-site context sends, and accepting it would reopen the gate"
        (let [res (send! "POST" (str (:origin window) "/copy")
                         (merge (session window)
                                {"Origin" "null"
                                 "Content-Type" "application/x-www-form-urlencoded"})
                         (str "token=" (:token window) "&item=gh-token"))]
          (is (= 403 (.statusCode res)))
          (is (str/includes? (.body res) "bad-origin"))))
      (is (= [] @log)))))

(deftest a-post-from-another-origin-is-refused-by-name
  (with-window
    (fn [window log]
      (let [res (send! "POST" (str (:origin window) "/copy")
                       (merge (session window)
                              {"Origin" "https://evil.example"
                               "Content-Type" "application/x-www-form-urlencoded"})
                       (str "token=" (:token window) "&item=gh-token"))]
        (is (= 403 (.statusCode res)))
        (is (str/includes? (.body res) "bad-origin")))
      (is (= [] @log)))))

(deftest copy-reaches-the-vault-once-and-the-answer-carries-no-secret
  (with-window
    (fn [window log]
      (let [res (send! "POST" (str (:origin window) "/copy")
                       (merge (session window)
                              {"Origin" (:origin window)
                               "Content-Type" "application/x-www-form-urlencoded"})
                       (str "token=" (:token window) "&item=gh-token"))]
        (is (= 303 (.statusCode res)))
        (is (= (str "/" (:fragment (ui/view-by-id :items)))
               (.orElse (.firstValue (.headers res) "location") "")))
        (is (not (str/includes? (.body res) plaintext))))
      (is (= [[:copy! "gh-token"]] @log))
      (testing "the result shows up once, on the next page, and then is gone"
        (let [first-page (.body (send! "GET" (:origin window) (session window) nil))
              second-page (.body (send! "GET" (:origin window) (session window) nil))]
          (is (str/includes? first-page "clipboard にコピーした"))
          (is (not (str/includes? second-page "clipboard にコピーした"))))))))

(deftest asking-to-revoke-changes-nothing
  ;; The confirmation is reached by a link. If that GET could revoke, the
  ;; control would be one prefetch, one crawler or one mistyped URL away from
  ;; doing it — which is the whole reason the acting half is a POST.
  (with-window
    (fn [window log]
      (let [res (send! "GET" (str (:origin window) "/?confirm=dev-1")
                       (session window) nil)]
        (is (= 200 (.statusCode res)))
        (is (str/includes? (.body res) "本当に revoke する")))
      (is (= [] @log) "a GET revoked a device"))))

(deftest revoke-reaches-the-vault-with-the-device-it-was-given
  (with-window
    (fn [window log]
      (let [res (send! "POST" (str (:origin window) "/device/revoke")
                       (merge (session window)
                              {"Origin" (:origin window)
                               "Content-Type" "application/x-www-form-urlencoded"})
                       (str "token=" (:token window) "&device-id=dev-1"))]
        (is (= 303 (.statusCode res)))
        (is (= (str "/" (:fragment (ui/view-by-id :devices)))
               (.orElse (.firstValue (.headers res) "location") ""))))
      (is (= [[:revoke! "dev-1"]] @log)))))

(deftest an-action-that-throws-is-reported-as-a-failure
  (let [window (ui-server/start!
                {:css "" :rand-fn #(byte-array (repeat % (byte 7)))
                 :actions (assoc (fake-actions (atom []))
                                 :copy! (fn [_] (throw (ex-info "reveal denied" {}))))})]
    (try
      (send! "POST" (str (:origin window) "/copy")
             (merge (session window)
                    {"Origin" (:origin window)
                     "Content-Type" "application/x-www-form-urlencoded"})
             (str "token=" (:token window) "&item=gh-token"))
      (let [page (.body (send! "GET" (:origin window) (session window) nil))]
        (is (str/includes? page "data-type=\"error\"")
            "a thrown action was rendered as something other than an error")
        (is (str/includes? page "reveal denied")))
      (finally ((:stop window))))))

(deftest an-oversized-body-is-bounded-and-says-so
  (with-window
    (fn [window log]
      (let [res (send! "POST" (str (:origin window) "/copy")
                       (merge (session window)
                              {"Origin" (:origin window)
                               "Content-Type" "application/x-www-form-urlencoded"})
                       (str "token=" (:token window) "&item="
                            (apply str (repeat 9000 "x"))))]
        (is (= 400 (.statusCode res)))
        (is (str/includes? (.body res) "too large")))
      (is (= [] @log)))))

(deftest unknown-paths-and-methods-are-not-the-app
  (with-window
    (fn [window _log]
      (is (= 404 (.statusCode (send! "GET" (str (:origin window) "/nope")
                                     (session window) nil))))
      (is (= 404 (.statusCode (send! "POST" (str (:origin window) "/nope")
                                     (merge (session window)
                                            {"Origin" (:origin window)
                                             "Content-Type" "application/x-www-form-urlencoded"})
                                     (str "token=" (:token window)))))))))

(deftest dds-css-refuses-rather-than-returning-an-empty-stylesheet
  ;; The failure this rules out: a missing dependency rendering a page that
  ;; loads and looks broken, with nothing in the output to say why.
  (is (string? (ui-server/dds-css)))
  (is (str/includes? (ui-server/dds-css) "--color-")
      "the vendored DADS stylesheet does not look like DADS"))

;; ── the portable half ──────────────────────────────────────────────────────

(deftest a-repeated-key-cannot-make-the-parser-choose
  ;; A body carrying `token` twice — a valid one and a chosen one — is an
  ;; attempt to have the parser and the gate disagree about which is "the"
  ;; token. First wins, always, so there is nothing to disagree about.
  (is (= {"token" "good" "item" "gh-token"}
         (ui-server/form-decode "token=good&item=gh-token&token=evil")))
  (is (= {"a" "1 2" "b" "x=y"} (ui-server/form-decode "a=1+2&b=x%3Dy")))
  (is (= {"empty" ""} (ui-server/form-decode "empty=")))
  (is (= {} (ui-server/form-decode "")))
  (is (= {} (ui-server/form-decode nil))))

(deftest a-cookie-is-read-by-name-and-not-by-prefix
  (is (= "abc" (ui-server/cookie-value "kagi_ui_session=abc" "kagi_ui_session")))
  (is (= "abc" (ui-server/cookie-value "other=1; kagi_ui_session=abc; x=2"
                                       "kagi_ui_session")))
  (is (nil? (ui-server/cookie-value "kagi_ui_session_evil=abc" "kagi_ui_session"))
      "a longer name that starts the same is a different cookie")
  (is (nil? (ui-server/cookie-value "" "kagi_ui_session")))
  (is (nil? (ui-server/cookie-value nil "kagi_ui_session"))))
