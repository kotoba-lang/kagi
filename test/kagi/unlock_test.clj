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
      (is (= :implemented-core (:status shape)))
      (is (some #{:credential-id} (:fields shape)))
      (is (not (contains? shape :secret))))))

(deftest passkey-prf-vmk-roundtrip
  (let [p (crypto/jvm-provider)
        vmk (crypto/rand-bytes p 32)
        prf (crypto/rand-bytes p 32)
        wrap (unlock/passkey-prf-wrap p vmk prf
                                      {:rp-id "vault.example" :credential-id "cred-1"})]
    (is (= :passkey-prf (:method wrap)))
    (is (= "vault.example" (:rp-id wrap)))
    (is (= (seq vmk) (seq (unlock/unlock-with-passkey-prf p wrap prf))))
    (is (thrown? Exception
                 (unlock/unlock-with-passkey-prf p wrap (crypto/rand-bytes p 32))))))

(deftest device-unlock-secret-rotates-after-durable-metadata-commit
  (let [p (crypto/jvm-provider)
        vmk (crypto/rand-bytes p 32)
        store (secret-store/mem-secret-store)
        old-ref "mem://unlock/0"
        new-ref "mem://unlock/1"
        old-wrap (unlock/os-keychain-wrap p vmk store old-ref
                                          {:epoch 0 :now "2026-01-01T00:00:00Z"})
        persisted (atom nil)
        result (unlock/rotate-os-keychain!
                p {:unlock/wraps [old-wrap]} vmk store old-ref new-ref
                #(reset! persisted %)
                {:now "2026-07-18T00:00:00Z"})]
    (is (:rotated? result))
    (is (= 1 (:key-epoch result)))
    (is (not (secret-store/exists? store old-ref)))
    (is (secret-store/exists? store new-ref))
    (is (= new-ref (get-in @persisted [:unlock/wraps 0 :ref])))
    (is (= (:key/id old-wrap)
           (get-in @persisted [:unlock/wraps 0 :key/parent])))))

(deftest failed-unlock-metadata-commit-retains-old-secret
  (let [p (crypto/jvm-provider)
        vmk (crypto/rand-bytes p 32)
        store (secret-store/mem-secret-store)
        old-ref "mem://unlock/old"
        new-ref "mem://unlock/staged"
        wrap (unlock/os-keychain-wrap p vmk store old-ref)]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"disk failed"
                          (unlock/rotate-os-keychain!
                           p {:unlock/wraps [wrap]} vmk store old-ref new-ref
                           (fn [_] (throw (ex-info "disk failed" {}))))))
    (is (secret-store/exists? store old-ref)
        "old unlock path remains usable when metadata commit fails")))
