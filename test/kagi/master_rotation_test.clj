(ns kagi.master-rotation-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.master-rotation :as master]
            [kagi.persist :as persist]
            [kagi.rotation-store :as rotation-store]))

(defn- dag-store []
  (let [dir (doto (java.io.File/createTempFile "vmk-dag" ".tmp")
              (.delete) (.mkdirs))]
    (rotation-store/file-store (str (java.io.File. dir "dag.edn")))))

(deftest vmk-worker-rewraps-every-dek-and-atomically-commits
  (let [p (crypto/jvm-provider)
        identity (identity/generate-identity p)
        old-vmk (crypto/rand-bytes p 32)
        now "2026-07-18T00:00:00Z"
        old-key (master/new-vmk-key-record now "keychain://vmk/0" 0 nil)
        make-item (fn [id compartment]
                    (let [dek (crypto/rand-bytes p 32)
                          kek (crypto/compartment-key p old-vmk compartment)]
                      [id {:item/id id :item/compartment compartment
                           :item/wrap (crypto/wrap-dek p kek dek)
                           :expected-dek dek}]))
        seeded (into {} [(make-item "a" "personal") (make-item "b" "work")])
        state {:items (into {} (map (fn [[id item]] [id (dissoc item :expected-dek)]) seeded))
               :meta {:vmk-key old-key :unlock/wraps []}}
        plan0 (master/plan p identity state old-vmk
                           {:now "2026-07-19T00:00:00Z"
                            :custody-ref "keychain://vmk/1"
                            :wrap-meta (fn [new-vmk]
                                         {:unlock/wraps
                                          [{:method :test-wrap
                                            :digest (crypto/sha256 new-vmk)}]})})
        current {:subject (:authority-id identity) :purpose :vmk
                 :key-id (:key/id old-key) :epoch 0 :parent nil}
        plan (master/admit! (dag-store) p plan0 current)
        dir (doto (java.io.File/createTempFile "vmk-vault" ".tmp")
              (.delete) (.mkdirs))
        path (str (java.io.File. dir "vault.edn"))]
    (doseq [[id item] (:items (:next-state plan))]
      (let [new-kek (crypto/compartment-key p (:new-vmk plan) (:item/compartment item))
            dek (crypto/unwrap-dek p new-kek (:item/wrap item))]
        (is (java.util.Arrays/equals ^bytes (get-in seeded [id :expected-dek]) ^bytes dek))
        (is (= 1 (:item/vmk-epoch item)))))
    (is (:committed? (master/commit! path plan)))
    (is (= 1 (get-in (persist/load* path) [:meta :vmk-key :key/epoch])))
    (is (thrown? Exception
                 (let [item (get-in (:next-state plan) [:items "a"])
                       old-kek (crypto/compartment-key p old-vmk "personal")]
                   (crypto/unwrap-dek p old-kek (:item/wrap item)))))))

(deftest vmk-worker-rejects-raw-vmk-in-persisted-meta
  (let [p (crypto/jvm-provider)
        identity (identity/generate-identity p)
        old-vmk (crypto/rand-bytes p 32)
        old-key (master/new-vmk-key-record "2026-07-18T00:00:00Z" "keychain://vmk/0" 0 nil)]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"raw VMK"
         (master/plan p identity {:items {} :meta {:vmk-key old-key}} old-vmk
                      {:now "2026-07-19T00:00:00Z" :custody-ref "keychain://vmk/1"
                       :wrap-meta (fn [new-vmk] {:forbidden new-vmk})})))))
