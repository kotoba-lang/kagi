(ns kagi.cacao-test
  "自己発行 CACAO の mint→verify 往復・改竄検知・audience 照合。"
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.cacao :as cacao]
            [kagi.identity :as identity])
  (:import [java.util Base64]))

(deftest mint-verify-roundtrip
  (testing "actor が自分の鍵で mint した CACAO を verify が通す(iss=自 did)"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/transact :scope (:graph id)}
                          {:aud "https://kotobase.net" :nonce "n1"})
          r   (cacao/verify tok {:aud "https://kotobase.net"})]
      (is (:ok? r))
      (is (= (:did id) (:iss r)))
      (is (= "https://kotobase.net" (:aud r))))))

(deftest tampered-signature-fails
  (testing "署名 byte を 1 bit 反転すると verify が落ちる"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)} {:aud "u" :nonce "n"})
          raw (.decode (Base64/getDecoder) tok)
          _   (aset-byte raw (dec (alength raw))
                         (unchecked-byte (bit-xor (aget raw (dec (alength raw))) 1)))
          bad (.encodeToString (Base64/getEncoder) raw)]
      (is (false? (:ok? (cacao/verify bad)))))))

(deftest wrong-audience-rejected
  (testing "audience 不一致は reject(同一なら通過)"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)} {:aud "https://a" :nonce "n"})]
      (is (true?  (:ok? (cacao/verify tok {:aud "https://a"}))))
      (is (false? (:ok? (cacao/verify tok {:aud "https://evil"})))))))

(deftest expired-token-rejected
  (testing "expiry を過ぎた CACAO は :now 照合で reject(期限内は ok)"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)}
                          {:aud "u" :nonce "n" :issued-at "2026-06-27T00:00:00Z"
                           :expiry "2026-06-27T01:00:00Z"})]
      (is (true? (:ok? (cacao/verify tok {:now "2026-06-27T00:30:00Z"}))))
      (let [r (cacao/verify tok {:now "2026-06-27T02:00:00Z"})]
        (is (false? (:ok? r)))
        (is (:expired? r))))))

(deftest replayed-nonce-rejected
  (testing "既出 nonce はリプレイとして reject"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)} {:aud "u" :nonce "n-123"})]
      (is (true? (:ok? (cacao/verify tok))))
      (let [r (cacao/verify tok {:nonce-seen? #{"n-123"}})]
        (is (false? (:ok? r)))
        (is (:replay? r))))))

(deftest forged-issuer-fails
  (testing "別人の鍵で署名し iss を被害者 did に詐称しても、iss から復元した鍵で検証され落ちる"
    (let [victim (identity/generate-identity)
          attacker (identity/generate-identity)
          ;; attacker が victim の did を iss に詐称(自分の鍵で署名)
          tok (cacao/mint {:private-key (:private-key attacker) :did (:did victim)}
                          {:cap :cap/admin :scope (:graph victim)} {:aud "u" :nonce "n"})]
      (is (false? (:ok? (cacao/verify tok)))
          "iss(victim)から復元した公開鍵では attacker 署名を検証できない"))))
