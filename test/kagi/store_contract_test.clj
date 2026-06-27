(ns kagi.store-contract-test
  "Store contract。MemStore で検証し、同じ deftest を KotobaStore(:db-api 配線後)へ
  再利用する(MemStore ≡ KotobaStore)。"
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.store :as store]))

(defn- exercise [st]
  (store/put-item! st #:item{:id "a" :compartment "c" :cid "cid:a" :version 1})
  (store/put-grant! st #:grant{:id "g1" :item "a" :recipient "did:key:zR" :cap :viewer})
  st)

(deftest mem-store-roundtrips
  (testing "item / grant の put→get と compartment 絞り込み"
    (let [st (exercise (store/mem-store))]
      (is (= "cid:a" (:item/cid (store/item st "a"))))
      (is (= 1 (count (store/items-in st "c"))))
      (is (= "did:key:zR" (:grant/recipient (first (store/grants-of st "a")))))
      (store/revoke-grant! st "g1")
      (is (true? (:grant/revoked (first (store/grants-of st "a"))))))))

(deftest ledger-is-append-only-hash-chained
  (testing "append-ledger! は seq を採番し prev-hash で前 fact に連結する"
    (let [st (store/mem-store)
          _ (store/append-ledger! st {:t :committed :op :item/create})
          _ (store/append-ledger! st {:t :policy-hold :op :item/reveal})
          l (store/ledger st)]
      (is (= [0 1] (mapv :ledger/seq l)))
      (is (= (:ledger/hash (first l)) (:ledger/prev-hash (second l)))
          "2 番目の prev-hash は 1 番目の hash を指す"))))

(deftest block-store-roundtrips
  (testing "暗号文 blob の put→get"
    (let [st (store/mem-store)
          b (byte-array [1 2 3])]
      (store/block-put! st "cid:x" b)
      (is (= (seq b) (seq (store/block-get st "cid:x")))))))
