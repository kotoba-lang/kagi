(ns kagi.clipboard-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.clipboard :as clipboard]))

;; Two sessions found this flake independently on 2026-07-30 and fixed it two
;; ways. The other widened the window to 500ms/800ms; this splits the test so
;; there is no window to lose. Both are kept where each is the right tool:
;; `ttl-ms`/`past-ttl-ms` below still serve the one assertion that must wait for
;; a non-event (a value NOT being cleared), which polling cannot express.
;;
;; The original was a single test asserting in OPPOSITE directions against one
;; 20ms timer — "the value is still there" right after the call, and "the value
;; is gone" after a fixed sleep. Either could lose; it failed about one run in
;; three. A wider budget lowers the odds, but this workspace runs many
;; concurrent sessions (the other session's own note says so), so the race
;; survives it. Presence and clearing are therefore separate tests: presence
;; uses a TTL long enough that the clear cannot interfere, and clearing is
;; awaited by polling rather than by guessing how slow the machine is.
(def ^:private ttl-ms 500)
(def ^:private past-ttl-ms 800)

(defn- wait-until
  "Poll `pred` up to `ms`. Returns true if it became true."
  [ms pred]
  (let [deadline (+ (System/currentTimeMillis) ms)]
    (loop []
      (cond (pred) true
            (> (System/currentTimeMillis) deadline) false
            :else (do (Thread/sleep 5) (recur))))))

(deftest a-copy-returns-metadata-only-and-leaves-the-value-in-place
  (let [cb (clipboard/memory-clipboard)
        r (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms 60000})]
    (is (true? (:ok? r)))
    (is (true? (:copied? r)))
    (is (= 60000 (:ttl-ms r)))
    (is (false? (:secret? r)))
    (is (= "secret-value" (clipboard/paste cb)))))

(deftest clipboard-ttl-clears-unchanged-secret
  (let [cb (clipboard/memory-clipboard)]
    (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms 20})
    (is (wait-until 3000 #(= "" (clipboard/paste cb)))
        "the scheduled clear must fire")))

(deftest clipboard-ttl-does-not-clear-user-replacement
  (testing "TTL clear does not erase a later clipboard value"
    (let [cb (clipboard/memory-clipboard)]
      (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms ttl-ms})
      (clipboard/copy! cb "replacement")
      (Thread/sleep past-ttl-ms)
      (is (= "replacement" (clipboard/paste cb))))))

(deftest no-secret-is-returned
  (testing "the result carries operational metadata and never the value"
    (let [cb (clipboard/memory-clipboard)
          r (clipboard/copy-secret-with-ttl! cb "top-secret" {:ttl-ms 10})]
      (is (not-any? #(and (string? %) (re-find #"top-secret" %))
                    (map str (vals r)))))))

;; ---------------------------------------------------------------------------
;; Custody must survive the caller returning.
;;
;; The clear used to be scheduled with `future`. Clojure's agent-pool threads
;; are daemons, so a CLI that prints and returns takes the JVM down with it and
;; kills the sleeping clear — the secret then stays on the clipboard while the
;; call reports {:ok? true :ttl-ms 900000}.
;;
;; The two tests above passed throughout, because a test JVM stays alive across
;; `Thread/sleep 80`. Nothing in the suite modelled the caller exiting, which is
;; the only condition under which the bug appears. Measured on the real CLI
;; 2026-07-30: `kagi copy --ttl 900` exited 0 in under a second and the password
;; was still pasteable afterwards.
;; ---------------------------------------------------------------------------

(deftest blocking-mode-has-already-cleared-when-it-returns
  (testing "a CLI cannot outlive its own cleanup, so with :block? the clear is
            done BEFORE the call returns — not scheduled for later"
    (let [cb (clipboard/memory-clipboard)
          r (clipboard/copy-secret-with-ttl! cb "secret-value"
                                             {:ttl-ms 20 :block? true})]
      (is (true? (:cleared? r)))
      (is (= :waited (:clear-mechanism r)))
      (is (= "" (clipboard/paste cb))
          "no sleep here on purpose: if this needs one, custody was not held"))))

(deftest non-blocking-mode-does-not-claim-to-have-cleared
  (testing "the honest report for a caller that did not wait — the clear now
            also happens when this process ends, which may be sooner than the
            TTL and is never later"
    ;; A long TTL on purpose. Written first with :ttl-ms 20, this raced its own
    ;; background clear: the assertion below asserts the value is STILL there,
    ;; and on a slow pass the 20ms timer won. It failed roughly one run in two.
    ;; A test that asserts "not yet cleared" must not be timed against a clock
    ;; it does not control.
    (let [cb (clipboard/memory-clipboard)
          r (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms 60000})]
      (is (false? (:cleared? r)))
      (is (= :on-exit (:clear-mechanism r)))
      (is (= "secret-value" (clipboard/paste cb))))))

(deftest opting-out-of-clearing-says-so
  (let [cb (clipboard/memory-clipboard)
        r (clipboard/copy-secret-with-ttl! cb "secret-value"
                                           {:ttl-ms 20 :clear? false})]
    (is (= :none (:clear-mechanism r)))
    (is (false? (:cleared? r)))
    (Thread/sleep 60)
    (is (= "secret-value" (clipboard/paste cb))
        "clear? false must really not clear")))

(deftest blocking-mode-leaves-a-later-value-alone
  (testing "the unchanged-only rule still holds when blocking"
    (let [cb (clipboard/memory-clipboard)
          done (future (clipboard/copy-secret-with-ttl!
                        cb "secret-value" {:ttl-ms 150 :block? true}))]
      (Thread/sleep 20)
      (clipboard/copy! cb "replacement")
      (let [r @done]
        (is (true? (:cleared? r)) "it waited and ran its clear")
        (is (= "replacement" (clipboard/paste cb))
            "but found the value changed and left it")))))
