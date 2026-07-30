(ns kagi.crypto.noble-interop-test
  "`kagi.crypto.noble`(ブラウザ)が `kagi.crypto/jvm-provider` と**相互運用できる**ことの証明。

  自己往復だけでは足りない: 自己往復は「自分の決めた符号化で自分と話せる」しか示さず、
  JVM が封緘した item をブラウザで開けるかは何も保証しない。ここでは JVM が実際に
  生成したベクタ(`test/fixtures/jvm-crypto-vectors.edn`、`clojure -M:gen-vectors` で再生成)
  を読んで、ブラウザ側が同じ平文・同じ DEK・同じ KDF 出力に到達することを確かめる。

  実行:
    npm install
    npx nbb --classpath src:test -m kagi.crypto.noble-interop-test"
  (:require [cljs.test :refer [deftest is testing run-tests]]
            [clojure.edn :as edn]
            [kagi.crypto :as c]
            [kagi.crypto.noble :as noble]
            ["node:fs" :as fs]))

(def p (noble/noble-provider))

(defn- b64->bytes [s]
  (js/Uint8Array.from (js/Buffer.from s "base64")))

(defn- bytes= [a b]
  (and (= (.-length a) (.-length b))
       (every? #(= (aget a %) (aget b %)) (range (.-length a)))))

(def vectors
  (-> (fs/readFileSync "test/fixtures/jvm-crypto-vectors.edn" "utf8")
      edn/read-string))

;; ───────── 自己往復(ブラウザ単体で閉じているか) ─────────

(deftest aead-round-trip
  (let [key   (c/rand-bytes p 32)
        nonce (c/rand-bytes p 12)
        aad   (c/utf8-bytes "item-cid:self")
        pt    (c/utf8-bytes "秘密の平文")
        ct    (c/aead-seal p key nonce pt aad)]
    (is (bytes= pt (c/aead-open p key nonce ct aad)))
    (testing "AAD が違えば開かない(GCM の認証が効いている)"
      (is (thrown? js/Error
                   (c/aead-open p key nonce ct (c/utf8-bytes "item-cid:other")))))))

(deftest hybrid-kem-round-trip
  (let [{:keys [public secret]} (c/kem-keypair p)
        {:keys [ciphertext shared]} (c/kem-encap p public)]
    (is (= 32 (.-length shared)))
    (is (bytes= shared (c/kem-decap p secret ciphertext)))))

(deftest hybrid-signature-round-trip
  (let [{:keys [public secret]} (c/sign-keypair p)
        msg (c/utf8-bytes "sign me")
        sig (c/sign* p secret msg)]
    (is (true? (c/verify* p public msg sig)))
    (testing "片方の署名が壊れていれば false(両方 verify した時のみ有効)"
      (is (false? (c/verify* p public (c/utf8-bytes "other message") sig))))))

(deftest share-round-trip
  (let [recipient (c/kem-keypair p)
        dek (c/rand-bytes p 32)
        envelope (c/share-dek p (:public recipient) dek)]
    (is (bytes= dek (c/accept-share p (:secret recipient) envelope)))))

;; ───────── JVM → ブラウザ(本題) ─────────

(deftest opens-an-item-sealed-by-the-jvm-provider
  (let [{:keys [sealed message aad]} vectors]
    (is (bytes= (b64->bytes message)
                (c/open-item p
                             (b64->bytes (:dek sealed))
                             (b64->bytes (:nonce sealed))
                             (b64->bytes (:ciphertext sealed))
                             (b64->bytes aad))))))

(deftest accepts-a-share-minted-by-the-jvm-provider
  (testing "JVM が受信者公開鍵へ切った grant envelope から、同じ DEK を復元できる"
    (let [{:keys [share recipient sealed]} vectors
          secret {:x (b64->bytes (:x (:secret recipient)))
                  :pq (b64->bytes (:pq (:secret recipient)))
                  :x-pub (b64->bytes (:x-pub (:secret recipient)))
                  :pq-pub (b64->bytes (:pq-pub (:secret recipient)))}
          envelope {:kem-ct {:x (b64->bytes (:x (:kem-ct share)))
                             :pq (b64->bytes (:pq (:kem-ct share)))}
                    :nonce (b64->bytes (:nonce share))
                    :wrapped (b64->bytes (:wrapped share))}]
      (is (bytes= (b64->bytes (:dek sealed))
                  (c/accept-share p secret envelope))))))

(deftest verifies-a-signature-made-by-the-jvm-provider
  (let [{:keys [signer signature message]} vectors]
    (is (true? (c/verify* p
                          {:ed (b64->bytes (:ed (:public signer)))
                           :mldsa (b64->bytes (:mldsa (:public signer)))}
                          (b64->bytes message)
                          {:ed (b64->bytes (:ed signature))
                           :mldsa (b64->bytes (:mldsa signature))})))))

(deftest kdf-outputs-match-the-jvm-byte-for-byte
  (testing "HKDF-SHA256(空 salt は 32 ゼロに置換)"
    (let [{:keys [ikm info len out]} (:hkdf vectors)]
      (is (bytes= (b64->bytes out)
                  (c/hkdf p (b64->bytes ikm) (c/empty-bytes) (b64->bytes info) len)))))
  (testing "Argon2id"
    (let [{:keys [pass salt params out]} (:argon2id vectors)]
      (is (bytes= (b64->bytes out)
                  (c/argon2id p (b64->bytes pass) (b64->bytes salt) params))))))

;; ───────── ブラウザ → JVM(逆方向の材料を書き出す) ─────────

(defn- b64 [b] (.toString (js/Buffer.from b) "base64"))

(deftest ^:emit emits-vectors-for-the-jvm-to-verify
  (testing "ブラウザ側で生成したものを JVM が開けるかは kagi.crypto.noble-reverse-test が見る"
    (let [msg (c/utf8-bytes "kagi cross-runtime interop vector v1 (browser side)")
          aad (c/utf8-bytes "item-cid:interop-reverse")
          recipient (c/kem-keypair p)
          signer (c/sign-keypair p)
          sealed (c/seal-item p msg aad)
          share (c/share-dek p (:public recipient) (:dek sealed))
          sig (c/sign* p (:secret signer) msg)]
      (fs/writeFileSync
       "test/fixtures/noble-crypto-vectors.edn"
       (pr-str
        {:message (b64 msg)
         :aad (b64 aad)
         :sealed {:dek (b64 (:dek sealed))
                  :nonce (b64 (:nonce sealed))
                  :ciphertext (b64 (:ciphertext sealed))}
         :recipient {:secret {:x (b64 (:x (:secret recipient)))
                              :pq (b64 (:pq (:secret recipient)))
                              :x-pub (b64 (:x-pub (:secret recipient)))
                              :pq-pub (b64 (:pq-pub (:secret recipient)))}}
         :share {:kem-ct {:x (b64 (:x (:kem-ct share)))
                          :pq (b64 (:pq (:kem-ct share)))}
                 :nonce (b64 (:nonce share))
                 :wrapped (b64 (:wrapped share))}
         :signer {:public {:ed (b64 (:ed (:public signer)))
                           :mldsa (b64 (:mldsa (:public signer)))}}
         :signature {:ed (b64 (:ed sig))
                     :mldsa (b64 (:mldsa sig))}}))
      (is (true? (fs/existsSync "test/fixtures/noble-crypto-vectors.edn"))))))

(defn -main [& _]
  ;; ns を明示する。省略すると nbb の `-m` 起動では *current* ns(= `user`)を
  ;; 走らせてしまい、0 tests でも緑になる。
  (run-tests 'kagi.crypto.noble-interop-test))
