(ns kagi.crypto.gen-interop-vectors
  "JVM provider で相互運用ベクタを生成し `test/fixtures/jvm-crypto-vectors.edn` へ書く。

  ブラウザ provider(`kagi.crypto.noble`)がこれを読み、JVM が封緘した item を開け、
  JVM が切った share を受け取り、JVM の署名を検証できることを確かめる。**ベクタは
  生成物なのでコミットする** — CLJS 側テストが JVM を起動せずに走れるようにするため。

  再生成:
    clojure -M:test -m kagi.crypto.gen-interop-vectors"
  (:require [clojure.java.io :as io]
            [clojure.pprint]
            [kagi.crypto :as c])
  (:import [java.util Base64]))

(defn- b64 [^bytes b] (.encodeToString (Base64/getEncoder) b))

(defn vectors []
  (let [p (c/jvm-provider)
        message (c/utf8-bytes "kagi cross-runtime interop vector v1")
        aad     (c/utf8-bytes "item-cid:interop")
        recipient (c/kem-keypair p)
        signer    (c/sign-keypair p)
        sealed    (c/seal-item p message aad)
        share     (c/share-dek p (:public recipient) (:dek sealed))
        signature (c/sign* p (:secret signer) message)
        hkdf-ikm  (c/utf8-bytes "ikm")
        hkdf-info (c/utf8-bytes "kagi/interop/info")
        argon-salt (byte-array (range 16))]
    {:message   (b64 message)
     :aad       (b64 aad)
     :sealed    {:dek (b64 (:dek sealed))
                 :nonce (b64 (:nonce sealed))
                 :ciphertext (b64 (:ciphertext sealed))}
     :recipient {:public {:x (b64 (:x (:public recipient)))
                          :pq (b64 (:pq (:public recipient)))}
                 :secret {:x (b64 (:x (:secret recipient)))
                          :pq (b64 (:pq (:secret recipient)))
                          :x-pub (b64 (:x-pub (:secret recipient)))
                          :pq-pub (b64 (:pq-pub (:secret recipient)))}}
     :share     {:kem-ct {:x (b64 (:x (:kem-ct share)))
                          :pq (b64 (:pq (:kem-ct share)))}
                 :nonce (b64 (:nonce share))
                 :wrapped (b64 (:wrapped share))}
     :signer    {:public {:ed (b64 (:ed (:public signer)))
                          :mldsa (b64 (:mldsa (:public signer)))}}
     :signature {:ed (b64 (:ed signature))
                 :mldsa (b64 (:mldsa signature))}
     ;; 決定論的 KDF: ブラウザ側は同じ入力から同じ出力を出さねばならない。
     :hkdf      {:ikm (b64 hkdf-ikm)
                 :info (b64 hkdf-info)
                 :len 64
                 :out (b64 (c/hkdf p hkdf-ikm (c/empty-bytes) hkdf-info 64))}
     :argon2id  {:pass (b64 (c/utf8-bytes "correct horse battery staple"))
                 :salt (b64 argon-salt)
                 :params {:m-kb 8192 :t 1 :p 1}
                 :out (b64 (c/argon2id p (c/utf8-bytes "correct horse battery staple")
                                       argon-salt {:m-kb 8192 :t 1 :p 1}))}}))

(defn -main [& _]
  (let [f (io/file "test/fixtures/jvm-crypto-vectors.edn")]
    (io/make-parents f)
    (spit f (with-out-str (clojure.pprint/pprint (vectors))))
    (println "wrote" (.getPath f))))
