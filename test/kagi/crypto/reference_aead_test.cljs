(ns kagi.crypto.reference-aead-test
  "`kagi.crypto.reference` routes AEAD through `aes.gcm` and agrees with noble
  on random round-trips (same AES-256-GCM semantics, different implementation).

  Run from a west checkout (sibling `org-nist-aes`):
    npm run test:reference

  Or:
    nbb --classpath src:test:../org-nist-aes/src -m kagi.crypto.reference-aead-test"
  (:require [cljs.test :refer [deftest is testing run-tests]]
            [kagi.crypto :as c]
            [kagi.crypto.noble :as noble]
            [kagi.crypto.reference :as reference]))

(defn- bytes= [a b]
  (and (= (.-length a) (.-length b))
       (every? #(= (aget a %) (aget b %)) (range (.-length a)))))

(deftest reference-aead-matches-noble
  (let [noble-p (noble/noble-provider)
        ref-p (reference/reference-provider)
        key (c/rand-bytes noble-p 32)
        nonce (c/rand-bytes noble-p 12)
        aad (c/utf8-bytes "item-cid:reference-parity")
        pt (c/utf8-bytes "vault plaintext")]
    (testing "seal output matches noble"
      (is (bytes= (c/aead-seal noble-p key nonce pt aad)
                  (c/aead-seal ref-p key nonce pt aad))))
    (testing "reference open round-trips"
      (let [ct (c/aead-seal ref-p key nonce pt aad)]
        (is (bytes= pt (c/aead-open ref-p key nonce ct aad)))))
    (testing "AAD mismatch fails closed"
      (let [ct (c/aead-seal ref-p key nonce pt aad)]
        (is (thrown? js/Error
                     (c/aead-open ref-p key nonce ct (c/utf8-bytes "other-aad"))))))
    (testing "HKDF-SHA256 matches noble (zero salt)"
      (let [ikm (c/rand-bytes noble-p 48)
            salt (js/Uint8Array. 0)
            info (c/utf8-bytes "kagi-hkdf-context")]
        (is (bytes= (c/hkdf noble-p ikm salt info 64)
                    (c/hkdf ref-p ikm salt info 64))))))
  (testing "HKDF-SHA256 matches noble (non-empty salt)"
    (let [noble-p (noble/noble-provider)
          ref-p (reference/reference-provider)
          ikm (c/rand-bytes noble-p 32)
          salt (c/rand-bytes noble-p 16)
          info (c/utf8-bytes "salted")]
      (is (bytes= (c/hkdf noble-p ikm salt info 32)
                  (c/hkdf ref-p ikm salt info 32))))))

(defn -main [& _]
  (run-tests 'kagi.crypto.reference-aead-test))
