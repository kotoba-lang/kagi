(ns kagi.crypto.noble-reverse-test
  "相互運用の**逆方向**: ブラウザ provider が作ったものを JVM provider が開けるか。

  `kagi.crypto.noble-interop-test`(nbb) が `test/fixtures/noble-crypto-vectors.edn` を
  書き、ここがそれを読む。JVM→ブラウザだけを見ていると、ブラウザが「自分だけが読める
  独自符号化」を書いていても気づけない —— 実際にこの方向でしか露見しないのは、
  noble の raw 鍵に DER prefix を付け忘れる/間違える類の誤りである。

  再生成: npm install && npm run test:cljs"
  (:require [clojure.java.io :as io]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as c])
  (:import [java.util Base64]))

(defn- unb64 ^bytes [s] (.decode (Base64/getDecoder) ^String s))

(def vectors
  (let [f (io/file "test/fixtures/noble-crypto-vectors.edn")]
    (when (.exists f) (edn/read-string (slurp f)))))

(def ^:private p (delay (c/jvm-provider)))

(deftest jvm-opens-an-item-sealed-by-the-browser-provider
  (if-not vectors
    (println "SKIP: test/fixtures/noble-crypto-vectors.edn がない — `npm run test:cljs` を先に走らせる")
    (let [{:keys [sealed message aad]} vectors]
      (is (java.util.Arrays/equals
           (unb64 message)
           (c/open-item @p (unb64 (:dek sealed)) (unb64 (:nonce sealed))
                        (unb64 (:ciphertext sealed)) (unb64 aad)))))))

(deftest jvm-accepts-a-share-minted-by-the-browser-provider
  (when vectors
    (testing "ブラウザが切った hybrid grant envelope から JVM が同じ DEK を復元する"
      (let [{:keys [share recipient sealed]} vectors
            secret {:x (unb64 (:x (:secret recipient)))
                    :pq (unb64 (:pq (:secret recipient)))
                    :x-pub (unb64 (:x-pub (:secret recipient)))
                    :pq-pub (unb64 (:pq-pub (:secret recipient)))}
            envelope {:kem-ct {:x (unb64 (:x (:kem-ct share)))
                               :pq (unb64 (:pq (:kem-ct share)))}
                      :nonce (unb64 (:nonce share))
                      :wrapped (unb64 (:wrapped share))}]
        (is (java.util.Arrays/equals (unb64 (:dek sealed))
                                     (c/accept-share @p secret envelope)))))))

(deftest jvm-verifies-a-signature-made-by-the-browser-provider
  (when vectors
    (let [{:keys [signer signature message]} vectors]
      (is (true? (c/verify* @p
                            {:ed (unb64 (:ed (:public signer)))
                             :mldsa (unb64 (:mldsa (:public signer)))}
                            (unb64 message)
                            {:ed (unb64 (:ed signature))
                             :mldsa (unb64 (:mldsa signature))}))))))
