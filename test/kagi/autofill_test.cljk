(ns kagi.autofill-test
  "Tests for the parts of the autofill path that do not need a browser —
  chosen because one of them is where the real bug was."
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.autofill :as af]))

;; --------------------------------------------------------------- reassembly

(defn- fresh [] [(atom (StringBuilder.)) (atom [])])

(deftest a-single-final-chunk-is-one-message
  (let [[p inbox] (fresh)]
    (af/accumulate! p inbox "{\"id\":1}" true)
    (is (= ["{\"id\":1}"] @inbox))))

(deftest a-message-split-across-chunks-is-reassembled
  (testing "the bug: each onText chunk was published as if it were a whole
            message, so json/read-str failed with `EOF in object`. It passed
            against a tiny fixture page whose frames arrived intact and failed
            on the real one — chunking is a property of the traffic, not of the
            code, which is why the fixture could not have caught it."
    (let [[p inbox] (fresh)]
      (af/accumulate! p inbox "{\"id\":1,\"res" false)
      (is (= [] @inbox) "nothing may be published before the final chunk")
      (af/accumulate! p inbox "ult\":{\"a\":1}}" true)
      (is (= ["{\"id\":1,\"result\":{\"a\":1}}"] @inbox)))))

(deftest many-chunks-reassemble-in-order
  (let [[p inbox] (fresh)
        whole "{\"id\":7,\"result\":{\"value\":\"0123456789\"}}"]
    (doseq [[i c] (map-indexed vector (map str whole))]
      (af/accumulate! p inbox c (= i (dec (count whole)))))
    (is (= [whole] @inbox))))

(deftest the-buffer-resets-between-messages
  (testing "without the reset the second message would carry the first"
    (let [[p inbox] (fresh)]
      (af/accumulate! p inbox "{\"id\":1}" true)
      (af/accumulate! p inbox "{\"id\":2}" true)
      (is (= ["{\"id\":1}" "{\"id\":2}"] @inbox)))))

(deftest interleaved-partials-of-one-message-do-not-leak-into-the-next
  (let [[p inbox] (fresh)]
    (af/accumulate! p inbox "{\"a\":" false)
    (af/accumulate! p inbox "1}" true)
    (af/accumulate! p inbox "{\"b\":" false)
    (af/accumulate! p inbox "2}" true)
    (is (= ["{\"a\":1}" "{\"b\":2}"] @inbox))))

;; ------------------------------------------------------------------ verdicts

(deftest a-full-length-write-matches
  (is (= :match (af/length-verdict 28 28))))

(deftest an-unreadable-field-is-absent
  (is (= :absent (af/length-verdict 28 nil))))

(deftest an-empty-field-is-unchanged-not-truncated
  (testing "zero is checked before the less-than branch: 'nothing landed' and
            'some of it landed' need different repairs"
    (is (= :unchanged (af/length-verdict 28 0)))))

(deftest a-short-field-is-truncated
  (is (= :truncated (af/length-verdict 28 15))))

(deftest a-longer-field-means-something-was-already-there
  (testing "the field is cleared before inserting, so more characters than
            were sent can only mean the clear failed and this appended to
            somebody else's value — never reported as success"
    (is (= :unexpected (af/length-verdict 28 40)))))

(deftest only-match-is-a-pass
  (doseq [observed [nil 0 15 40]]
    (is (not= :match (af/length-verdict 28 observed)) (str "observed " observed))))

;; -------------------------------------------------------------- page picking

(def targets
  [{:type "page" :url "about:blank" :webSocketDebuggerUrl "ws://x/1"}
   {:type "page" :url "https://app.prolific.com/register/researcher/email#password"
    :webSocketDebuggerUrl "ws://x/2"}
   {:type "page" :url "file:///tmp/fixture.html" :webSocketDebuggerUrl "ws://x/3"}])

(deftest a-named-page-is-preferred
  (testing "a fill aimed at the wrong tab is a password typed into somebody
            else's form, so the caller names the page it means"
    (is (= "ws://x/2" (:webSocketDebuggerUrl (af/pick-page targets "prolific.com"))))
    (is (= "ws://x/3" (:webSocketDebuggerUrl (af/pick-page targets "fixture.html"))))))

(deftest an-unmatched-name-does-not-silently-fall-back
  (testing "falling back to 'some other page' is exactly the wrong-tab failure"
    (is (nil? (af/pick-page targets "nonexistent.example")))))

(deftest with-no-name-about-blank-is-skipped
  (is (= "ws://x/2" (:webSocketDebuggerUrl (af/pick-page targets nil))))
  (is (= "ws://x/2" (:webSocketDebuggerUrl (af/pick-page targets "")))))

(deftest debug-base-keeps-the-port
  (is (= "http://127.0.0.1:61596"
         (af/debug-base "ws://127.0.0.1:61596/devtools/browser/22b1f386"))))
