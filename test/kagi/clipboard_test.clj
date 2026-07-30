(ns kagi.clipboard-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.clipboard :as clipboard]))

;; TTL は 20ms ではなく 500ms。20ms だと「copy した直後にまだ残っている」を確かめる
;; アサーションの予算が 20ms しかなく、負荷のかかったマシン(このワークスペースは
;; 並行セッションが常時走る)では TTL クリアが先に発火して paste が "" を返す。
;; 実測: フル実行で断続的に落ち、単独実行では 3/3 通る。テストが見たい性質
;; 「TTL 前は残る / TTL 後は消える」は据え置きで、窓だけ広げる。
(def ^:private ttl-ms 500)
(def ^:private past-ttl-ms 800)

(deftest clipboard-ttl-clears-unchanged-secret
  (testing "secret copy returns metadata only and clears unchanged clipboard"
    (let [cb (clipboard/memory-clipboard)
          r (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms ttl-ms})]
      (is (true? (:ok? r)))
      (is (true? (:copied? r)))
      (is (= ttl-ms (:ttl-ms r)))
      (is (false? (:secret? r)))
      (is (= "secret-value" (clipboard/paste cb)))
      (Thread/sleep past-ttl-ms)
      (is (= "" (clipboard/paste cb))))))

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
    (let [cb (clipboard/memory-clipboard)
          r (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms 20})]
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
