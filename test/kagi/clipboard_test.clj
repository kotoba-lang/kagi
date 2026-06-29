(ns kagi.clipboard-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.clipboard :as clipboard]))

(deftest clipboard-ttl-clears-unchanged-secret
  (testing "secret copy returns metadata only and clears unchanged clipboard"
    (let [cb (clipboard/memory-clipboard)]
      (is (= {:ok? true :copied? true :ttl-ms 20 :secret? false}
             (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms 20})))
      (is (= "secret-value" (clipboard/paste cb)))
      (Thread/sleep 80)
      (is (= "" (clipboard/paste cb))))))

(deftest clipboard-ttl-does-not-clear-user-replacement
  (testing "TTL clear does not erase a later clipboard value"
    (let [cb (clipboard/memory-clipboard)]
      (clipboard/copy-secret-with-ttl! cb "secret-value" {:ttl-ms 20})
      (clipboard/copy! cb "replacement")
      (Thread/sleep 80)
      (is (= "replacement" (clipboard/paste cb))))))
