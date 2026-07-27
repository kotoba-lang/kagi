(ns kagi.crypto-test
  "AES-256-GCM/HKDFの標準KAT、hybrid ML-KEM/ML-DSA、Argon2id、item/DEKの
  roundtrip・negative・downgrade境界テスト。"
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [kagi.crypto :as crypto])
  (:import [java.util HexFormat Arrays]
           [java.security KeyFactory Signature]
           [java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec]
           [javax.crypto KEM]))

(defn- hex-bytes [s] (.parseHex (HexFormat/of) s))
(defn- hex [^bytes b] (.formatHex (HexFormat/of) b))

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

(deftest hkdf-rfc5869-case-1-known-answer
  (let [p (crypto/jvm-provider)
        ikm (byte-array (repeat 22 (unchecked-byte 0x0b)))
        salt (hex-bytes "000102030405060708090a0b0c")
        info (hex-bytes "f0f1f2f3f4f5f6f7f8f9")
        okm (crypto/hkdf p ikm salt info 42)]
    (is (= "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
           (hex okm)))
    (is (= 42 (count okm)) "multi-block expand must not zero-extend")))

(deftest hkdf-supports-full-counter-range-and-rejects-invalid-lengths
  (let [p (crypto/jvm-provider)
        ikm (byte-array 32)
        out (crypto/hkdf p ikm (byte-array 0) (byte-array 0) 4097)]
    (is (= 4097 (count out)) "counter values above 127 use unsigned octets")
    (is (thrown? clojure.lang.ExceptionInfo
                 (crypto/hkdf p ikm (byte-array 0) (byte-array 0) 0)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (crypto/hkdf p ikm (byte-array 0) (byte-array 0) 8161)))))

(deftest aes-256-gcm-nist-known-answer-and-policy-boundary
  (let [p (crypto/jvm-provider)
        key (byte-array 32)
        nonce (byte-array 12)
        plaintext (byte-array 16)
        ciphertext (crypto/aead-seal p key nonce plaintext (byte-array 0))]
    (is (= "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
           (hex ciphertext)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (crypto/aead-seal p (byte-array 16) nonce plaintext (byte-array 0)))
        "AES-128 downgrade is rejected")
    (is (thrown? clojure.lang.ExceptionInfo
                 (crypto/aead-seal p key (byte-array 16) plaintext (byte-array 0)))
        "non-96-bit GCM nonce is rejected")))

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

(deftest opaque-kem-decapsulation-and-shared-secret-zeroization
  (let [p (crypto/jvm-provider)
        {:keys [public secret]} (crypto/kem-keypair p)
        dek (crypto/rand-bytes p 32)
        envelope (crypto/share-dek p public dek)
        captured (atom nil)
        recipient (reify crypto/DecapsulationHandle
                    (decapsulate-hybrid [_ provider ciphertext]
                      (let [shared (crypto/kem-decap provider secret ciphertext)]
                        (reset! captured shared)
                        shared)))]
    (is (= (seq dek) (seq (crypto/accept-share p recipient envelope))))
    (is (every? zero? @captured)
        "combined native/software shared secret is erased after unwrap")))

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

(deftest mldsa65-nist-acvp-signature-verification
  (testing "JDK ML-DSA-65 verifies a pinned NIST ACVP FIPS 204 vector, not a self-generated round trip"
    (let [{:keys [source test-case parameter-set signature-interface pre-hash context
                  public-key message signature]}
          (-> "vectors/nist-acvp-mldsa65-tc35.edn" io/resource slurp edn/read-string)
          ;; SubjectPublicKeyInfo for id-ml-dsa-65 (2.16.840.1.101.3.4.3.18),
          ;; followed by the 1952-byte raw ACVP public key bit string.
          spki-prefix (hex-bytes "308207b2300b0609608648016503040312038207a100")
          raw-public (hex-bytes public-key)
          encoded-public (byte-array (+ (alength spki-prefix) (alength raw-public)))
          sig-bytes (hex-bytes signature)]
      (is (re-matches #"https://github.com/usnistgov/ACVP-Server/blob/[0-9a-f]{40}/.*" source)
          "vector provenance is immutable and reviewable")
      (is (= [35 "ML-DSA-65" "external" "pure" ""]
             [test-case parameter-set signature-interface pre-hash context]))
      (System/arraycopy spki-prefix 0 encoded-public 0 (alength spki-prefix))
      (System/arraycopy raw-public 0 encoded-public (alength spki-prefix) (alength raw-public))
      (let [public (.generatePublic (KeyFactory/getInstance "ML-DSA-65")
                                    (X509EncodedKeySpec. encoded-public))
            verify (fn [candidate]
                     (let [verifier (doto (Signature/getInstance "ML-DSA-65")
                                      (.initVerify public)
                                      (.update (hex-bytes message)))]
                       (.verify verifier candidate)))]
        (is (true? (verify sig-bytes)) "official valid signature must verify")
        (let [tampered (Arrays/copyOf sig-bytes (alength sig-bytes))]
          (aset-byte tampered 0 (unchecked-byte (bit-xor 1 (aget tampered 0))))
          (is (false? (verify tampered)) "one-bit signature corruption must fail"))))))

(deftest mlkem768-nist-acvp-decapsulation
  (testing "JDK ML-KEM-768 decapsulates a pinned NIST ACVP FIPS 203 vector"
    (let [{:keys [source test-case parameter-set function decapsulation-key
                  ciphertext shared-secret]}
          (-> "vectors/nist-acvp-mlkem768-tc86.edn" io/resource slurp edn/read-string)
          ;; PKCS#8 PrivateKeyInfo for id-alg-ml-kem-768 (2.16.840.1.101.3.4.4.2).
          ;; The inner OCTET STRING is the 2400-byte expanded ACVP decapsulation key.
          pkcs8-prefix (hex-bytes "30820978020100300b06096086480165030404020482096404820960")
          raw-private (hex-bytes decapsulation-key)
          encoded-private (byte-array (+ (alength pkcs8-prefix) (alength raw-private)))
          ct (hex-bytes ciphertext)]
      (is (re-matches #"https://github.com/usnistgov/ACVP-Server/blob/[0-9a-f]{40}/.*" source)
          "vector provenance is immutable and reviewable")
      (is (= [86 "ML-KEM-768" "decapsulation"]
             [test-case parameter-set function]))
      (System/arraycopy pkcs8-prefix 0 encoded-private 0 (alength pkcs8-prefix))
      (System/arraycopy raw-private 0 encoded-private (alength pkcs8-prefix) (alength raw-private))
      (let [private (.generatePrivate (KeyFactory/getInstance "ML-KEM-768")
                                      (PKCS8EncodedKeySpec. encoded-private))
            decap (fn [candidate]
                    (-> (KEM/getInstance "ML-KEM")
                        (.newDecapsulator private)
                        (.decapsulate candidate)
                        (.getEncoded)))]
        (is (= (seq (hex-bytes shared-secret)) (seq (decap ct)))
            "official ciphertext must produce the official shared secret")
        (let [tampered (Arrays/copyOf ct (alength ct))]
          (aset-byte tampered 0 (unchecked-byte (bit-xor 1 (aget tampered 0))))
          (is (not= (seq (hex-bytes shared-secret)) (seq (decap tampered)))
              "implicit rejection must not return the valid shared secret"))))))

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
