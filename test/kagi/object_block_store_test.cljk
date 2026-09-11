(ns kagi.object-block-store-test
  "`object-sealed-block-store` の契約。

  前半は 4 関数を素の atom で差した純テスト(アダプタ自身のロジック)。後半は
  **本物の `storj.store/store-fns` を偽の `IHttp` 越しに**通して、バイト表現と
  S3 の応答形が実際に噛み合うことを見る —— アダプタだけを fake で試すと、
  『0-255 の vector を返す』という io-storj 側の契約と kagi の `byte[]` の食い違いが
  復号時まで露見しない。"
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.store :as store]))

;; ───────── 素の 4 関数(アダプタ自身) ─────────

(defn- atom-fns
  "storj.store/store-fns と同じ形。get は 0-255 の vector を返す(io-storj の契約)。"
  [a]
  {:get-object (fn [k] (when-let [b (get @a k)] (mapv #(bit-and % 0xff) b)))
   :put-object (fn [k bytes] (swap! a assoc k bytes) {:status 200})
   :exists?    (fn [k] (contains? @a k))})

(deftest round-trips-ciphertext-as-host-bytes
  (let [a (atom {})
        s (store/object-sealed-block-store (atom-fns a))
        ct (byte-array [0 1 127 -128 -1 42])]
    (store/sealed-put! s "cid:item-1:v1" ct)
    (let [got (store/sealed-get s "cid:item-1:v1")]
      (testing "crypto provider が食える host のバイト列で返る"
        (is (bytes? got))
        (is (java.util.Arrays/equals ct got))))))

(deftest a-missing-block-is-nil-not-an-empty-block
  (let [s (store/object-sealed-block-store (atom-fns (atom {})))]
    (testing "無いことと空であることを取り違えると、自分の記録が壊れているのか判断できない"
      (is (nil? (store/sealed-get s "cid:absent:v1"))))))

(deftest rewriting-a-key-with-different-ciphertext-is-refused
  (let [a (atom {})
        s (store/object-sealed-block-store (atom-fns a))]
    (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
    (testing "まだ grant が指している前の版の暗号文を黙って消させない"
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"already holds different ciphertext"
           (store/sealed-put! s "cid:item-1:v1" (byte-array [9 9 9])))))
    (testing "拒否した後も元のバイト列が残っている"
      (is (java.util.Arrays/equals (byte-array [1 2 3])
                                   (store/sealed-get s "cid:item-1:v1"))))))

(deftest re-putting-identical-ciphertext-succeeds
  (let [a (atom {})
        s (store/object-sealed-block-store (atom-fns a))
        ct (byte-array [1 2 3])]
    (store/sealed-put! s "cid:item-1:v1" ct)
    (testing "部分失敗からの正当なリトライを詰ませない"
      (is (some? (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3])))))))

(deftest overwrite-can-be-opted-into
  (let [a (atom {})
        s (store/object-sealed-block-store (atom-fns a) {:allow-overwrite? true})]
    (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
    (store/sealed-put! s "cid:item-1:v1" (byte-array [9 9 9]))
    (is (java.util.Arrays/equals (byte-array [9 9 9])
                                 (store/sealed-get s "cid:item-1:v1")))))

(deftest the-adapter-refuses-to-be-built-without-both-directions
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"needs :get-object and :put-object"
                        (store/object-sealed-block-store {:get-object (fn [_])}))))

;; ───────── 実 AEAD の暗号文が往復するか ─────────

(deftest real-ciphertext-survives-the-boundary
  (testing "境界を跨いだバイト列がそのまま復号できる(表現変換で 1 バイトも壊れない)"
    (let [p (crypto/jvm-provider)
          s (store/object-sealed-block-store (atom-fns (atom {})))
          aad (crypto/utf8-bytes "item:secret-1")
          pt (crypto/utf8-bytes "correct horse battery staple")
          {:keys [dek nonce ciphertext]} (crypto/seal-item p pt aad)]
      (store/sealed-put! s "cid:secret-1:v1" ciphertext)
      (is (java.util.Arrays/equals
           pt
           (crypto/open-item p dek nonce (store/sealed-get s "cid:secret-1:v1") aad))))))
