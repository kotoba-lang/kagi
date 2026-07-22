(ns kagi.recovery-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.recovery :as recovery]))

(deftest threshold-roundtrip
  (let [p (crypto/jvm-provider)
        vmk (crypto/rand-bytes p 32)
        shares (recovery/split p vmk 3 5)]
    (is (= (seq vmk) (seq (recovery/combine (take 3 shares)))))
    (is (= (seq vmk) (seq (recovery/combine [(shares 0) (shares 2) (shares 4)]))))
    (testing "fewer than threshold shares fail closed"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"insufficient"
                            (recovery/combine (take 2 shares)))))
    (testing "duplicates and tampering fail closed"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"incompatible"
                            (recovery/combine [(shares 0) (shares 0) (shares 2)])))
      (let [bad (update (shares 2) :recovery/value
                        #(doto (aclone ^bytes %) (aset-byte 0 (byte 0))))]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"integrity"
                              (recovery/combine [(shares 0) (shares 1) bad])))))))
