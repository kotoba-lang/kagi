(ns kagi.sync-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.sync :as sync]))

(deftest optimistic-concurrency-gate
  (is (true? (sync/assert-expected-seq! 7 7)))
  (is (true? (sync/assert-expected-seq! nil 99)) "explicit legacy push remains available")
  (testing "a remote write after pull is never silently overwritten"
    (let [error (try (sync/assert-expected-seq! 7 8) nil
                     (catch clojure.lang.ExceptionInfo e (ex-data e)))]
      (is (= :sync-conflict (:reason error)))
      (is (= {:expected 7 :actual 8}
             (select-keys error [:expected :actual]))))))
