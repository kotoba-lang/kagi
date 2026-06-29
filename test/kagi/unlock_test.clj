(ns kagi.unlock-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.secret-store :as secret-store]
            [kagi.unlock :as unlock]))

(deftest os-keychain-vmk-wrap-roundtrip
  (testing "VMK can be wrapped with a SecretStore-backed device secret"
    (let [p (crypto/jvm-provider)
          vmk (crypto/rand-bytes p 32)
          store (secret-store/mem-secret-store)
          ref "keychain://com.junkawasaki.kagi/test-vmk"
          wrap (unlock/os-keychain-wrap p vmk store ref)
          secret (secret-store/get-secret store ref {})
          vmk2 (unlock/unwrap-vmk p wrap (.getBytes ^String secret "UTF-8"))]
      (is (= :os-keychain (:method wrap)))
      (is (= ref (:ref wrap)))
      (is (= (seq vmk) (seq vmk2)))
      (is (= "keychain://.../test-vmk" (get-in (unlock/status {:unlock/wraps [wrap]})
                                                [:methods 0 :ref]))))))

(deftest passkey-prf-shape-is-metadata-only
  (testing "passkey PRF support is represented as an envelope shape, not a secret"
    (let [shape (unlock/passkey-prf-envelope-shape)]
      (is (= :passkey-prf (:method shape)))
      (is (= :planned (:status shape)))
      (is (some #{:credential-id} (:fields shape)))
      (is (not (contains? shape :secret))))))
