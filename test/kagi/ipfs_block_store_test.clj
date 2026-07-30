(ns kagi.ipfs-block-store-test
  "IPFS 版 SealedBlockStore の契約。

  偽 IPFS は本物と同じ性質だけを持つ: **バイト列を渡すと内容から決まるアドレスを
  返し、同じバイト列は必ず同じアドレスになる**。この 1 点が object store 版との
  違いを生むので、そこを fake で再現しないとテストが別物になる。"
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.store :as store])
  (:import [java.security MessageDigest]))

(defn- content-address [^bytes b]
  (str "bafy" (apply str (take 16 (map #(format "%02x" (bit-and % 0xff))
                                       (.digest (MessageDigest/getInstance "SHA-256") b))))))

(defn- fake-ipfs []
  (let [blocks (atom {})
        pointers (atom {})]
    {:blocks blocks
     :pointers pointers
     :fns {:add-bytes (fn [b] (let [c (content-address b)] (swap! blocks assoc c b) c))
           :cat-bytes (fn [c] (get @blocks c))
           :get-pointer (fn [k] (get @pointers k))
           :put-pointer! (fn [k c] (swap! pointers assoc k c))
           :verify-fn (fn [c b] (= c (content-address b)))}}))

(deftest ciphertext-round-trips-through-ipfs
  (let [{:keys [fns]} (fake-ipfs)
        s (store/ipfs-sealed-block-store fns)
        ct (byte-array [0 1 127 -128 -1 42])]
    (store/sealed-put! s "cid:item-1:v1" ct)
    (is (java.util.Arrays/equals ct (store/sealed-get s "cid:item-1:v1")))))

(deftest a-key-with-no-pointer-is-nil
  (let [{:keys [fns]} (fake-ipfs)
        s (store/ipfs-sealed-block-store fns)]
    (is (nil? (store/sealed-get s "cid:absent:v1")))))

(deftest the-pointer-layer-is-required
  (testing "隠して『IPFS に置ける』と言うと、ポインタをどこに永続化するかの問いが消える"
    (let [{:keys [fns]} (fake-ipfs)]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"missing required functions"
           (store/ipfs-sealed-block-store (dissoc fns :get-pointer :put-pointer!)))))))

(deftest identical-bytes-need-no-fetch-to-be-recognised-as-a-retry
  (testing "content addressing のおかげで、object store 版に要った GET+比較が要らない"
    (let [{:keys [blocks fns]} (fake-ipfs)
          s (store/ipfs-sealed-block-store fns)]
      (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
      (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
      (testing "同じ内容なので block も 1 つしか増えない"
        (is (= 1 (count @blocks)))))))

(deftest repointing-a-key-at-different-content-is-refused
  (let [{:keys [fns]} (fake-ipfs)
        s (store/ipfs-sealed-block-store fns)]
    (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"already points at different content"
         (store/sealed-put! s "cid:item-1:v1" (byte-array [9 9 9]))))
    (testing "拒否した後も元の内容が読める"
      (is (java.util.Arrays/equals (byte-array [1 2 3])
                                   (store/sealed-get s "cid:item-1:v1"))))))

(deftest a-gateway-that-lies-is-caught-when-verification-is-supplied
  (testing "本物の content addressing なので、取ってきたバイト列を検証できる"
    (let [{:keys [blocks fns]} (fake-ipfs)
          s (store/ipfs-sealed-block-store fns)]
      (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
      ;; gateway が別のバイト列を返す状況を作る
      (let [[c _] (first @blocks)]
        (swap! blocks assoc c (byte-array [6 6 6])))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"do not match the content address"
           (store/sealed-get s "cid:item-1:v1"))))))

(deftest without-a-verifier-the-gateway-is-trusted
  (testing "渡さなければ検証しない —— それを黙ってやらないよう docstring が明示している"
    (let [{:keys [blocks fns]} (fake-ipfs)
          s (store/ipfs-sealed-block-store (dissoc fns :verify-fn))]
      (store/sealed-put! s "cid:item-1:v1" (byte-array [1 2 3]))
      (let [[c _] (first @blocks)]
        (swap! blocks assoc c (byte-array [6 6 6])))
      (is (java.util.Arrays/equals (byte-array [6 6 6])
                                   (store/sealed-get s "cid:item-1:v1"))))))

(deftest real-aead-ciphertext-survives-the-ipfs-boundary
  (let [p (crypto/jvm-provider)
        {:keys [fns]} (fake-ipfs)
        s (store/ipfs-sealed-block-store fns)
        aad (crypto/utf8-bytes "item:secret-1")
        pt (crypto/utf8-bytes "correct horse battery staple")
        {:keys [dek nonce ciphertext]} (crypto/seal-item p pt aad)]
    (store/sealed-put! s "cid:secret-1:v1" ciphertext)
    (is (java.util.Arrays/equals
         pt (crypto/open-item p dek nonce (store/sealed-get s "cid:secret-1:v1") aad)))))
