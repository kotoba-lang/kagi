(ns kagi.storj-block-store-test
  "本物の `io-storj` を通した SealedBlockStore の配線証明。

  ネットワークには出ない —— `storj.protocols/IHttp` に **S3 を演じる偽の transport**
  を差す。署名・URL 組み立て・応答形の解釈は本物の `storj.core` が行うので、ここで
  見えるのは「4 関数の契約と kagi のバイト表現が実際に噛み合うか」であって、
  fake だけのテストでは通ってしまう食い違い(io-storj は 0-255 の vector を返し、
  kagi の AEAD は `byte[]` を取る)がここで露見する。

  同じ経路が **Backblaze B2** にもそのまま使える —— B2 は S3 互換面を出すので、
  違うのは `storj.gateway` に渡す endpoint だけ。"
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.store :as store]
            [sigv4.crypto :as sigv4-crypto]
            [storj.core :as storj]
            [storj.protocols :as sp]
            [storj.store :as storj-store]))

(def ^:private bucket "kagi-sealed-blocks")

(defn- key-of
  "署名済みリクエストの URL から object key を復元する(偽 S3 の路由)。

  path は `/<bucket>/<key>` で、**key は percent-encode されている** —— kagi の cid は
  `cid:<item-id>:v<n>` なので `:` が `%3A` になる。デコードを省くと、この fake は
  実際に bucket に載る名前とは違う名前で辞書を引くことになり、テストが通っても
  本物の S3 では別のキーを指す。"
  [url]
  (-> url
      (str/split #"\?") first
      (str/replace (re-pattern (str "^https?://[^/]+/" bucket "/")) "")
      (java.net.URLDecoder/decode "UTF-8")))

(defrecord FakeS3 [objects requests]
  sp/IHttp
  (-request [_ {:keys [method url body]}]
    ;; storj.core は署名した通りの HTTP メソッド(大文字文字列 "GET"/"HEAD"/…)を
    ;; transport に渡す。入力側のキーワードのまま来ると思い込むと、この fake は
    ;; 実装ではなく自分の想像を試すことになる。
    (let [method (-> method name str/lower-case keyword)
          k (key-of url)]
      (swap! requests conj {:method method :key k})
      (case method
        :put (do (swap! objects assoc k body) {:status 200 :headers {} :body ""})
        :get (if-let [b (get @objects k)]
               {:status 200 :headers {} :body b}
               {:status 404 :headers {} :body ""})
        :head (if (contains? @objects k)
                {:status 200 :headers {"content-length" (str (count (get @objects k)))}}
                {:status 404 :headers {}})
        :delete (do (swap! objects dissoc k) {:status 204 :headers {} :body ""})))))

(defn- sealed-store-over-fake-s3 []
  (let [objects (atom {})
        requests (atom [])
        client (storj/client {:bucket bucket
                              :access-key "AKIAIOSFODNN7EXAMPLE"
                              :secret-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
                             {:crypto (sigv4-crypto/crypto)
                              :http (->FakeS3 objects requests)})
        fns (storj-store/store-fns client {:now (constantly "20260730T000000Z")
                                           :prefix "kagi/"})]
    {:sealed (store/object-sealed-block-store fns)
     :objects objects
     :requests requests}))

(deftest real-storj-client-carries-kagi-ciphertext-both-ways
  (let [{:keys [sealed objects]} (sealed-store-over-fake-s3)
        p (crypto/jvm-provider)
        aad (crypto/utf8-bytes "item:secret-1")
        pt (crypto/utf8-bytes "correct horse battery staple")
        {:keys [dek nonce ciphertext]} (crypto/seal-item p pt aad)]
    (store/sealed-put! sealed "cid:secret-1:v1" ciphertext)

    (testing "prefix 付きの key で bucket に着地している"
      (is (= ["kagi/cid:secret-1:v1"] (keys @objects))))

    (testing "bucket に載ったのは暗号文であって平文ではない"
      (let [stored (get @objects "kagi/cid:secret-1:v1")]
        (is (not (str/includes? (String. (byte-array (map unchecked-byte (seq stored))))
                                "correct horse")))))

    (testing "取り出して復号できる —— 表現変換で 1 バイトも壊れていない"
      (is (java.util.Arrays/equals
           pt
           (crypto/open-item p dek nonce (store/sealed-get sealed "cid:secret-1:v1") aad))))))

(deftest a-404-from-s3-becomes-nil-not-an-exception
  (let [{:keys [sealed]} (sealed-store-over-fake-s3)]
    (is (nil? (store/sealed-get sealed "cid:never-written:v1")))))

(deftest overwrite-protection-uses-head-before-put
  (let [{:keys [sealed requests]} (sealed-store-over-fake-s3)]
    (store/sealed-put! sealed "cid:secret-1:v1" (byte-array [1 2 3]))
    (testing "書き込み前に存在を確かめている(HEAD → PUT)"
      (is (= [:head :put] (mapv :method @requests))))
    (reset! requests [])
    (testing "違うバイト列での上書きは、S3 に届く前に落ちる"
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"already holds different ciphertext"
           (store/sealed-put! sealed "cid:secret-1:v1" (byte-array [9 9 9]))))
      (is (not-any? #(= :put (:method %)) @requests)))))
