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

(deftest hybrid-kem-roundtrip
  (testing "X25519+ML-KEM-768 hybrid: encap の shared を decap が一致復元"
    (let [p (crypto/jvm-provider)
          {:keys [public secret]} (crypto/kem-keypair p)
          {:keys [ciphertext shared]} (crypto/kem-encap p public)
          shared2 (crypto/kem-decap p secret ciphertext)]
      (is (= 32 (count shared)))
      (is (= (seq shared) (seq shared2)) "両者の shared secret が一致")))
  (testing "別鍵で decap すると shared が一致しない(ML-KEM は implicit rejection で例外を投げず別値を返す)"
    (let [p (crypto/jvm-provider)
          a (crypto/kem-keypair p)
          b (crypto/kem-keypair p)
          {:keys [ciphertext shared]} (crypto/kem-encap p (:public a))
          wrong (crypto/kem-decap p (:secret b) ciphertext)]
      (is (not= (seq shared) (seq wrong)) "誤鍵 decap の shared は正規 shared と異なる"))))

(deftest hybrid-share-dek-roundtrip
  (testing "share-dek → accept-share で DEK が受信者だけ復元できる"
    (let [p (crypto/jvm-provider)
          {:keys [public secret]} (crypto/kem-keypair p)
          dek (crypto/rand-bytes p 32)
          env (crypto/share-dek p public dek)
          dek2 (crypto/accept-share p secret env)]
      (is (= (seq dek) (seq dek2))))))

(deftest hybrid-signature-roundtrip-and-tamper
  (testing "Ed25519+ML-DSA-65 hybrid: 正署名は verify、改竄/片側破損は reject"
    (let [p (crypto/jvm-provider)
          {:keys [public secret]} (crypto/sign-keypair p)
          msg (.getBytes "commit:item:gh:v1" "UTF-8")
          sig (crypto/sign* p secret msg)]
      (is (true? (crypto/verify* p public msg sig)) "両署名 valid → true")
      (is (false? (crypto/verify* p public (.getBytes "tampered" "UTF-8") sig)) "msg 改竄 → false")
      (is (false? (crypto/verify* p public msg (assoc sig :mldsa (byte-array (count (:mldsa sig))))))
          "片側(ML-DSA)破損 → false(両方必須)"))))

(deftest argon2id-deterministic
  (testing "Argon2id は同入力で決定的、salt で分岐(軽量パラメータでテスト)"
    (let [p (crypto/jvm-provider)
          pass (.getBytes "correct horse battery staple" "UTF-8")
          salt (crypto/rand-bytes p 16)
          prm {:m-kb 8192 :t 1 :p 1}
          k1 (crypto/argon2id p pass salt prm)
          k2 (crypto/argon2id p pass salt prm)
          k3 (crypto/argon2id p pass (crypto/rand-bytes p 16) prm)]
      (is (= 32 (count k1)))
      (is (= (seq k1) (seq k2)))
      (is (not= (seq k1) (seq k3))))))
