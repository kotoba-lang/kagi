(ns kagi.crypto-test
  "実装済みプリミティブ(AES-256-GCM / HKDF / item seal/open / DEK wrap)の往復テスト。
  PQC(ML-KEM/ML-DSA)は provider 配線後に kem/sign の往復を足す(現状 ex-info で未配線を明示)。"
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.crypto :as crypto]))

(deftest aead-roundtrip
  (testing "AES-256-GCM seal→open が往復、AAD 改竄で失敗"
    (let [p (crypto/bc-provider)
          key (crypto/rand-bytes p 32)
          nonce (crypto/rand-bytes p 12)
          pt (.getBytes "hello vault" "UTF-8")
          aad (.getBytes "item:1" "UTF-8")
          ct (crypto/aead-seal p key nonce pt aad)]
      (is (= "hello vault" (String. ^bytes (crypto/aead-open p key nonce ct aad) "UTF-8")))
      (is (thrown? Exception
                   (crypto/aead-open p key nonce ct (.getBytes "item:2" "UTF-8")))))))

(deftest item-seal-and-wrap-roundtrip
  (testing "seal-item → wrap-dek → unwrap-dek → open-item が往復"
    (let [p (crypto/bc-provider)
          vmk (crypto/rand-bytes p 32)
          kek (crypto/compartment-key p vmk "work")
          aad (.getBytes "item:gh" "UTF-8")
          {:keys [dek nonce ciphertext]} (crypto/seal-item p (.getBytes "ghp_x" "UTF-8") aad)
          wrap (crypto/wrap-dek p kek dek)
          dek2 (crypto/unwrap-dek p kek wrap)]
      (is (= (seq dek) (seq dek2)) "wrap/unwrap で DEK 復元")
      (is (= "ghp_x" (String. ^bytes (crypto/open-item p dek2 nonce ciphertext aad) "UTF-8"))))))

(deftest hkdf-deterministic
  (testing "HKDF は決定的、info で分岐"
    (let [p (crypto/bc-provider)
          ikm (crypto/rand-bytes p 32)
          a (crypto/hkdf p ikm (byte-array 0) (.getBytes "a" "UTF-8") 32)
          a2 (crypto/hkdf p ikm (byte-array 0) (.getBytes "a" "UTF-8") 32)
          b (crypto/hkdf p ikm (byte-array 0) (.getBytes "b" "UTF-8") 32)]
      (is (= (seq a) (seq a2)))
      (is (not= (seq a) (seq b))))))
