(ns kagi.store-contract-test
  "Store contract。MemStore で検証し、同じ deftest を KotobaStore(:db-api 配線後)へ
  再利用する(MemStore ≡ KotobaStore)。"
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.store :as store]
            [kagi.ledger :as ledger]
            [kagi.crypto :as crypto]
            [kagi.rotation :as rotation]))

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
  (testing "ledger/make-entry が seq を採番し prev-hash で前 fact に連結、store は append のみ"
    (let [st (store/mem-store)
          p  (crypto/jvm-provider)
          e0 (ledger/make-entry (store/ledger st) {:t :committed :op :item/create} p nil)
          _  (store/append-ledger! st e0)
          e1 (ledger/make-entry (store/ledger st) {:t :policy-hold :op :item/reveal} p nil)
          _  (store/append-ledger! st e1)
          l  (store/ledger st)]
      (is (= [0 1] (mapv :ledger/seq l)))
      (is (= (:ledger/hash (first l)) (:ledger/prev-hash (second l)))
          "2 番目の prev-hash は 1 番目の hash を指す"))))

(deftest block-store-roundtrips
  (testing "暗号文 blob の put→get"
    (let [st (store/mem-store)
          b (byte-array [1 2 3])]
      (store/block-put! st "cid:x" b)
      (is (= (seq b) (seq (store/block-get st "cid:x")))))))

(deftest append-chained-ledger-survives-real-concurrent-writers
  (testing "append-chained-ledger! (not a separate `(ledger s)` read +
            make-entry + append-ledger!, which kagi.operation used to do)
            must not let two concurrent writers compute the same
            :ledger/seq/:ledger/prev-hash from a stale snapshot -- that
            would make verify-chain flag two perfectly legitimate,
            non-tampered entries as a broken hash chain, indistinguishable
            from real tampering. Verified with genuine JVM threads, not a
            sequential simulation."
    (let [st (store/mem-store)
          n  50
          futs (doall (for [i (range n)]
                        (future
                          (store/append-chained-ledger!
                           st #(ledger/make-entry % {:t (keyword (str "fact-" i))} nil nil)))))]
      (doseq [f futs] @f)
      (let [l (store/ledger st)]
        (is (= n (count l)))
        (is (= n (count (distinct (map :ledger/seq l))))
            "every concurrent writer got a distinct seq -- none silently collided")
        (is (:ok? (ledger/verify-chain l nil (constantly nil)))
            "the hash chain is intact under real thread contention")))))

(deftest rekey-commit-is-all-or-nothing-when-ledger-build-fails
  (let [st (store/mem-store)
        before @(.-a ^kagi.store.MemStore st)
        event (rotation/new-event {:subject "item-1" :purpose :item-dek
                                   :from-key "dek-0" :to-key "dek-1" :from-epoch 0})
        plan {:block {:cid "cid:new" :bytes (byte-array [9])}
              :item #:item{:id "item-1" :cid "cid:new" :version 1}
              :grants [#:grant{:id "g" :item "item-1"}]
              :rotation-event event}]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"synthetic failure"
                          (store/commit-rekey!
                           st plan (fn [_] (throw (ex-info "synthetic failure" {}))))))
    (is (= before @(.-a ^kagi.store.MemStore st)))))

(deftest kotoba-store-fails-closed-without-atomic-rotation-api
  (let [st (store/kotoba-store {} :conn)]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"lacks atomic"
                          (store/commit-rekey! st {} identity)))))

(deftest kotoba-store-delegates-to-sealed-block-capability
  (let [blocks (atom {})
        api {:sealed-block-put! (fn [_ cid bytes] (swap! blocks assoc cid bytes))
             :sealed-block-get (fn [_ cid] (get @blocks cid))}
        st (store/kotoba-store api :conn)
        bytes (byte-array [4 5 6])]
    (store/block-put! st "cid:sealed" bytes)
    (is (= (seq bytes) (seq (store/block-get st "cid:sealed"))))))

(deftest kotoba-store-sealed-block-boundary-fails-closed)
  (let [st (store/kotoba-store {} :conn)]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"SealedBlockStore read"
                          (store/block-get st "cid:x")))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"SealedBlockStore write"
                          (store/block-put! st "cid:x" (byte-array 0)))))
