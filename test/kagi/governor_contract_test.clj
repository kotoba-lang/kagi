(ns kagi.governor-contract-test
  "単一不変条件のテスト: Governor が拒否する op は副作用ゼロ + 台帳に 1 hold fact。"
  (:require [clojure.test :refer [deftest testing is]]
            [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.crypto :as crypto]))

(defn- fresh []
  (let [st (store/mem-store {:members {"did:key:zOwner" #:member{:did "did:key:zOwner" :role :owner}}})
        cr (crypto/bc-provider)]
    [st cr (op/build st {:crypto cr})]))

(defn- run [actor req ctx]
  (:state (g/run* actor {:request req :context ctx}
                  {:thread-id (str (:op req) "-" (:item-id req) "-" (:did ctx))})))

(deftest owner-create-then-reveal-roundtrips
  (testing "owner が作って自分で reveal すると平文が往復する(AES-256-GCM)"
    (let [[_st cr actor] (fresh)
          owner {:did "did:key:zOwner" :role :owner :phase 1
                 :vmk (crypto/rand-bytes cr 32) :purpose :daily-use}
          _ (run actor {:op :item/create :item-id "k1" :compartment "work"
                        :plaintext (.getBytes "s3cr3t" "UTF-8")} owner)
          rv (run actor {:op :item/reveal :item-id "k1"} owner)]
      (is (= :revealed (get-in rv [:result :effect])))
      (is (= "s3cr3t" (String. ^bytes (get-in rv [:result :plaintext]) "UTF-8"))))))

(deftest viewer-without-grant-is-held
  (testing "grant の無い viewer の reveal は HOLD、台帳に rbac-subject 根拠"
    (let [[st cr actor] (fresh)
          owner {:did "did:key:zOwner" :role :owner :phase 1
                 :vmk (crypto/rand-bytes cr 32) :purpose :daily-use}
          _ (run actor {:op :item/create :item-id "k2" :compartment "work"
                        :plaintext (.getBytes "x" "UTF-8")} owner)
          before (count (store/ledger st))
          rv (run actor {:op :item/reveal :item-id "k2"}
                  {:did "did:key:zViewer" :role :viewer :phase 1 :purpose :audit})]
      (is (= :held (get-in rv [:result :effect])))
      (is (some #{:rbac-subject} (-> (store/ledger st) last :basis)))
      (is (= (inc before) (count (store/ledger st))) "hold も 1 fact を残す"))))

(deftest reveal-without-purpose-is-held
  (testing "用途宣言の無い reveal は purpose 違反で HOLD"
    (let [[_st cr actor] (fresh)
          owner {:did "did:key:zOwner" :role :owner :phase 1 :vmk (crypto/rand-bytes cr 32)}
          _ (run actor {:op :item/create :item-id "k3" :compartment "work"
                        :plaintext (.getBytes "x" "UTF-8")}
                 (assoc owner :purpose :seed))
          rv (run actor {:op :item/reveal :item-id "k3"} owner)]
      (is (= :held (get-in rv [:result :effect]))))))

(deftest high-value-escalates-not-commits
  (testing "高価値カテゴリの reveal は自動 commit されず escalate(承認待ち)"
    (let [[_st cr actor] (fresh)
          owner {:did "did:key:zOwner" :role :owner :phase 1
                 :vmk (crypto/rand-bytes cr 32) :purpose :rotate}
          _ (run actor {:op :item/create :item-id "root" :compartment "work"
                        :category :root-credential
                        :plaintext (.getBytes "root" "UTF-8")} owner)
          rv (run actor {:op :item/reveal :item-id "root" :category :root-credential} owner)]
      ;; interrupt-before で停止 → result はまだ無い(承認で resume)
      (is (not= :revealed (get-in rv [:result :effect]))))))
