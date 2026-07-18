(ns kagi.governor-contract-test
  "単一不変条件のテスト: Governor が拒否する op は副作用ゼロ + 台帳に 1 hold fact。"
  (:require [clojure.test :refer [deftest testing is]]
            [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.vault :as vault]
            [kagi.ledger :as ledger]
            [kagi.identity :as identity]
            [kagi.cacao :as cacao]
            [kagi.crypto :as crypto]))

(defn- fresh []
  (let [st (store/mem-store {:members {"did:key:zOwner" #:member{:did "did:key:zOwner" :role :owner}}})
        cr (crypto/bc-provider)]
    [st cr (op/build st {:crypto cr})]))

(defn- run [actor req ctx]
  (:state (g/run* actor {:request req :context (assoc ctx :now (str (java.time.Instant/now)))}
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

(deftest actor-produces-verifiable-signed-ledger
  (testing "actor を :signer 付きで動かすと、commit/hold 全てが hybrid 署名され鎖検証できる"
    (let [cr (crypto/jvm-provider)
          id (identity/generate-identity)
          st (store/mem-store {:members {(:did id) #:member{:did (:did id) :role :owner}}})
          actor (op/build st {:crypto cr :signer (identity/sign-secret id)})
          owner {:did (:did id) :role :owner :phase 1
                 :vmk (crypto/rand-bytes cr 32) :purpose :daily-use}
          _ (run actor {:op :item/create :item-id "a" :compartment "work"
                        :plaintext (.getBytes "x" "UTF-8")} owner)
          _ (run actor {:op :item/reveal :item-id "a"} owner)
          _ (run actor {:op :item/reveal :item-id "a"}
                 {:did "did:key:zV" :role :viewer :phase 1 :purpose :audit}) ; → hold
          led (store/ledger st)]
      (is (= 3 (count led)) "commit, commit, hold の 3 fact")
      (is (every? :ledger/sig led) "全て hybrid 署名済み")
      (is (:ok? (ledger/verify-chain led cr (constantly (identity/sign-public id))))
          "actor 生成の台帳が改竄検知チェーンとして verify"))))

(deftest pqc-share-end-to-end
  (testing "owner が共有 → 受信者が hybrid KEM grant envelope を decap して平文を復元"
    (let [cr     (crypto/jvm-provider)
          rid    (identity/generate-identity cr)
          rkp    {:public (identity/kem-public rid) :secret (identity/kem-secret rid)}
          rdid   (:did rid)
          st     (store/mem-store
                  {:members {"did:key:zOwner" #:member{:did "did:key:zOwner" :role :owner}
                             rdid (identity/member-record rid :member)}})
          actor  (op/build st {:crypto cr})
          owner  {:did "did:key:zOwner" :role :owner :phase 2
                  :vmk (crypto/rand-bytes cr 32) :purpose :daily-use :consent? true}
          secret "ghp_shared_token"
          _ (run actor {:op :item/create :item-id "sh" :compartment "work"
                        :plaintext (.getBytes secret "UTF-8")} owner)
          _ (run actor {:op :share/grant :item-id "sh" :recipient-did rdid} owner)
          grant (first (store/grants-of st "sh"))
          it    (store/item st "sh")
          ;; 受信者: 自分の hybrid 秘密鍵で envelope から DEK を復元 → block を復号
          dek   (crypto/accept-share cr (:secret rkp) (:grant/envelope grant))
          pt    (crypto/open-item cr dek (:item/nonce it)
                                  (store/block-get st (:item/cid it))
                                  (vault/item-aad "sh"))]
      (is (= rdid (:grant/recipient grant)))
      (is (= secret (String. ^bytes pt "UTF-8")) "受信者が PQC envelope から平文を復元"))))

(deftest authn-self-registers-member
  (testing "authn が :register(member-record)を depth-1 self-mint で登録する"
    (let [cr (crypto/jvm-provider)
          id (identity/generate-identity cr)
          st (store/mem-store)
          actor (op/build st {:crypto cr})
          _ (run actor {:op :item/list :compartment "work"}
                 {:did (:did id) :role :owner :phase 1
                  :register (identity/member-record id :owner)})]
      (is (some? (store/member st (:did id))) "メンバー登録された")
      (is (= :owner (:member/role (store/member st (:did id))))))))

(deftest authn-rejects-invalid-cacao
  (testing "無効な CACAO は authn で弾かれ副作用に進まず HOLD"
    (let [cr (crypto/jvm-provider)
          st (store/mem-store {:members {"did:key:zO" #:member{:did "did:key:zO" :role :owner}}})
          actor (op/build st {:crypto cr})
          ctx {:did "did:key:zO" :role :owner :phase 1 :vmk (crypto/rand-bytes cr 32)
               :purpose :daily :aud "https://kotobase.net" :cacao "not-a-valid-cacao"}
          r (run actor {:op :item/list :compartment "work"} ctx)]
      (is (= :held (get-in r [:result :effect]))))))

(deftest authn-accepts-valid-cacao
  (testing "自己発行した有効 CACAO は authn を通過して op を実行"
    (let [cr (crypto/jvm-provider)
          id (identity/generate-identity cr)
          tok (cacao/mint id {:cap :cap/transact :scope (:graph id)}
                          {:aud "https://kotobase.net" :nonce "n"})
          st (store/mem-store {:members {(:did id) #:member{:did (:did id) :role :owner}}})
          actor (op/build st {:crypto cr})
          ctx {:did (:did id) :role :owner :phase 1 :vmk (crypto/rand-bytes cr 32)
               :purpose :daily :aud "https://kotobase.net" :cacao tok}
          r (run actor {:op :item/list :compartment "work"} ctx)]
      (is (= :listed (get-in r [:result :effect]))))))

(deftest pqc-share-with-real-identities
  (testing "実 identity 同士: owner が共有 → 受信者が自分の identity KEM 秘密鍵で復元"
    (let [cr (crypto/jvm-provider)
          owner-id (identity/generate-identity cr)
          recip-id (identity/generate-identity cr)
          st (store/mem-store)
          _ (store/put-member! st (identity/member-record owner-id :owner))
          _ (store/put-member! st (identity/member-record recip-id :member))
          actor (op/build st {:crypto cr :signer (identity/sign-secret owner-id)})
          owner {:did (:did owner-id) :role :owner :phase 2
                 :vmk (crypto/rand-bytes cr 32) :purpose :daily-use :consent? true}
          secret "ghp_real_identities"
          _ (run actor {:op :item/create :item-id "ri" :compartment "work"
                        :plaintext (.getBytes secret "UTF-8")} owner)
          _ (run actor {:op :share/grant :item-id "ri" :recipient-did (:did recip-id)} owner)
          grant (first (store/grants-of st "ri"))
          it    (store/item st "ri")
          dek   (crypto/accept-share cr (identity/kem-secret recip-id) (:grant/envelope grant))
          pt    (crypto/open-item cr dek (:item/nonce it)
                                  (store/block-get st (:item/cid it)) (vault/item-aad "ri"))]
      (is (= (:did recip-id) (:grant/recipient grant)))
      (is (= secret (String. ^bytes pt "UTF-8"))
          "受信者は自分の identity 秘密鍵だけで PQC envelope を開ける"))))

(deftest revoke-rotates-dek-and-reenvelopes-remaining-recipients
  (let [cr (crypto/jvm-provider)
        owner-id (identity/generate-identity cr)
        r1 (identity/generate-identity cr)
        r2 (identity/generate-identity cr)
        st (store/mem-store)
        _ (store/put-member! st (identity/member-record owner-id :owner))
        _ (store/put-member! st (identity/member-record r1 :member))
        _ (store/put-member! st (identity/member-record r2 :member))
        actor (op/build st {:crypto cr :signer (identity/sign-secret owner-id)
                            :signer-key (:signing-key owner-id)})
        owner {:did (:did owner-id) :role :owner :phase 3
               :vmk (crypto/rand-bytes cr 32) :purpose :revoke :consent? true}
        _ (run actor {:op :item/create :item-id "shared" :compartment "work"
                      :plaintext (.getBytes "rotated-secret" "UTF-8")} owner)
        _ (run actor {:op :share/grant :item-id "shared" :recipient-did (:did r1)} owner)
        _ (run actor {:op :share/grant :item-id "shared" :recipient-did (:did r2)} owner)
        old-item (store/item st "shared")
        result (run actor {:op :share/revoke :item-id "shared" :recipient-did (:did r1)} owner)
        next-item (store/item st "shared")
        grants (store/grants-of st "shared")
        g1 (first (filter #(= (:did r1) (:grant/recipient %)) grants))
        g2 (first (filter #(= (:did r2) (:grant/recipient %)) grants))
        dek2 (crypto/accept-share cr (identity/kem-secret r2) (:grant/envelope g2))
        pt2 (crypto/open-item cr dek2 (:item/nonce next-item)
                              (store/block-get st (:item/cid next-item))
                              (vault/item-aad "shared"))]
    (is (= :revoked-and-rekeyed (get-in result [:result :effect])))
    (is (= (inc (:item/version old-item)) (:item/version next-item)))
    (is (:grant/revoked g1))
    (is (= (:item/key-epoch next-item) (:grant/key-epoch g2)))
    (is (= "rotated-secret" (String. ^bytes pt2 "UTF-8")))
    (is (thrown? Exception
                 (crypto/accept-share cr (identity/kem-secret r1)
                                      (:grant/envelope g2))))))

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
