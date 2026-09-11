(ns kagi.kotobase-seal-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.kotobase-seal :as seal]))

(deftest callbacks-round-trip-edn-and-bind-the-compartment
  (let [provider (crypto/jvm-provider)
        options (seal/sealed-store-options
                 {:provider provider :vmk (crypto/rand-bytes provider 32)
                  :compartment "opaque-user-001" :key-epoch 3})
        value {:tx-data [[:db/add "e" :secret/value "private"]]}
        envelope ((:seal-fn options) value)]
    (is (= value ((:unseal-fn options) envelope)))
    (is (= 3 (:envelope/epoch envelope)))
    (is (= (seal/ciphertext-digest (:sealed/ciphertext envelope))
           (:sealed/ciphertext-digest envelope)))
    (is (not (re-find #"private" (pr-str (:sealed/ciphertext envelope)))))))

(deftest incomplete-context-fails-closed
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"incomplete"
                        (seal/sealed-store-options
                         {:provider (crypto/jvm-provider)
                          :compartment "opaque-user-001"}))))
