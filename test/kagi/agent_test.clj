(ns kagi.agent-test
  "The claim this suite has to hold up: an agent principal reads exactly what
  it was granted, with no VMK anywhere in its process, and un-granting takes
  the access away for real rather than on paper."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest testing is]]
            [kagi.agent :as agent]
            [kagi.agent-protocol :as proto]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.operation :as op]
            [kagi.persist :as persist]
            [kagi.store :as store]
            [langgraph.graph :as g])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.time Instant]
           [java.time.temporal ChronoUnit]))

(defn- tmp-home []
  (str (.toAbsolutePath (Files/createTempDirectory "kagi-agent-test" (make-array FileAttribute 0)))))

(defn- now [] (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS)))

(defn- owner-context [id vmk purpose]
  {:did (:did id) :role :owner :phase 3 :vmk vmk :purpose purpose :now (now)
   :consent? true :register (identity/member-record id :owner)})

(defn- run-owner [p id st vmk req purpose]
  (let [actor (op/build st {:crypto p :signer (identity/sign-secret id)
                            :signer-key (:signing-key id)})]
    (:state (g/run* actor {:request req :context (owner-context id vmk purpose)}
                    {:thread-id (str (:op req) "-" (:item-id req) "-" (rand))}))))

(defn- save-vault! [home st meta]
  (persist/save! (str home "/vault.edn")
                 (assoc (select-keys @(:a st) [:members :items :grants :blocks
                                               :ledger :rotation-events])
                        :meta meta)))

(defn- fixture
  "An owner vault holding two items, plus an enrolled agent granted ONE of
  them. Returns everything the assertions need."
  [& [{:keys [ops ttl-sec compartments]}]]
  (let [p (crypto/jvm-provider)
        home (tmp-home)
        owner (identity/generate-identity p)
        vmk (crypto/rand-bytes p 32)
        st (store/mem-store {:members {(:did owner) (identity/member-record owner :owner)}})
        _ (run-owner p owner st vmk {:op :item/create :item-id "granted" :compartment "ops"
                                     :plaintext (.getBytes "s3cr3t-value" "UTF-8")} :seed)
        _ (run-owner p owner st vmk {:op :item/create :item-id "withheld" :compartment "ops"
                                     :plaintext (.getBytes "not-for-the-agent" "UTF-8")} :seed)
        {:keys [request]} (agent/make-request! p {:label "resident@test" :custody :file :home home})
        invite #:invite{:id "test-invite"
                        :compartments (set (or compartments #{"ops"}))
                        :ops (set (or ops proto/default-ops))
                        :purposes #{}
                        :agent-ttl-sec (or ttl-sec 3600)}
        {:keys [token principal]} (agent/approve p request {:invite invite})
        ;; the member record is derived from the principal, not stored twice
        _ (store/put-member! st (agent/member-of principal))
        _ (run-owner p owner st vmk {:op :share/grant :item-id "granted"
                                     :recipient-did (:agent/did principal)} :grant)
        registry (agent/update-registry! home #(agent/register % principal))]
    ;; the registry is its OWN object — the vault snapshot never carries it
    (save-vault! home st {})
    {:p p :home home :owner owner :vmk vmk :store st :principal principal
     :token token :registry registry :agent-id (:agent/id principal)}))

(deftest agent-opens-only-what-it-was-granted
  (testing "granted item は開き、granted でない item は開かない"
    (let [{:keys [home]} (fixture)
          session (agent/open {:home home})]
      (is (= :open (:status session)))
      (is (nil? (:vmk session)) "agent の session に VMK は無い")
      (is (= "s3cr3t-value" (agent/reveal session "granted" :test)))
      (is (= :denied (:status (agent/read-one session "withheld" :test)))
          "grant の無い item は governor が拒否する")
      (is (= {:status :absent} (agent/read-one session "no-such-item" :test))))))

(deftest list-is-grant-filtered
  (testing "agent には自分が開ける item の名前しか見えない"
    (let [{:keys [home]} (fixture)
          session (agent/open {:home home})]
      (is (= ["granted"] (agent/items session "ops"))))))

(deftest ungrant-rekeys-and-actually-revokes
  (testing ":share/revoke で再鍵されると、古い envelope はもう何も開かない"
    (let [{:keys [p home owner vmk store principal]} (fixture)
          session (agent/open {:home home})
          _ (is (= "s3cr3t-value" (agent/reveal session "granted" :before)))
          state (run-owner p owner store vmk
                           {:op :share/revoke :item-id "granted"
                            :recipient-did (:agent/did principal)} :ungrant)
          _ (is (= :revoked-and-rekeyed (get-in state [:result :effect])))
          _ (save-vault! home store {})
          after (agent/open {:home home})]
      (is (= :denied (:status (agent/read-one after "granted" :after)))
          "取り消し後は同じ principal・同じ鍵でも開かない"))))

(deftest governor-refuses-a-capability-that-was-not-granted
  (testing ":agent/ops に無い op は :agent-op で hold される"
    (let [{:keys [home]} (fixture {:ops #{:item/list}})
          session (agent/open {:home home})
          r (agent/read-one session "granted" :test)]
      (is (= :denied (:status r)))
      (is (some #{:agent-op} (:basis r))
          (str "expected :agent-op in " (pr-str (:basis r)))))))

(deftest governor-refuses-an-expired-principal
  (testing "not-after を過ぎた principal は :agent-expired"
    (let [{:keys [home agent-id]} (fixture)
          _ (agent/update-registry!
             home (fn [reg] (update reg :agent/registry
                                    (fn [rs] (mapv #(assoc % :agent/not-after
                                                           "2000-01-01T00:00:00Z") rs)))))
          session (agent/open {:home home :agent-id agent-id})]
      ;; `open` itself refuses first, which is the point: an expired principal
      ;; does not get as far as asking the governor.
      (is (= :expired (:status session))))))

(deftest revoked-principal-cannot-open-a-session
  (testing "revoke された principal の session は :revoked"
    (let [{:keys [home agent-id]} (fixture)
          _ (agent/update-registry! home #(agent/revoke-agent % agent-id (now)))]
      (is (= :revoked (:status (agent/open {:home home :agent-id agent-id})))))))

(deftest session-states-are-distinguishable
  (testing "vault 無し / principal 無し / 未登録 が別々に答えられる"
    (let [empty-home (tmp-home)]
      (is (= :absent (:status (agent/open {:home empty-home}))))
      (let [{:keys [p home]} (fixture)
            other (tmp-home)]
        ;; a machine with a key but no vault
        (agent/make-request! p {:label "orphan" :custody :file :home other})
        (is (= :absent (:status (agent/open {:home other}))))
        ;; a machine whose key the vault never approved
        (let [{:keys [request]} (agent/make-request! p {:label "unapproved" :custody :file
                                                        :home home})]
          (is (= :not-registered
                 (:status (agent/open {:home home :agent-id (:agent/id request)})))))))))

(deftest every-read-lands-on-the-agents-own-signed-chain
  (testing "reveal も refusal も agent 自身の鍵で署名された鎖に残り、検証できる"
    (let [{:keys [home registry agent-id]} (fixture)
          session (agent/open {:home home})
          _ (agent/reveal session "granted" :audited)
          _ (agent/read-one session "withheld" :audited)
          entries (:ledger (persist/load* (agent/ledger-path home agent-id)))]
      (is (= 2 (count entries)) "commit 1 件と hold 1 件")
      (is (every? :ledger/sig entries) "全て hybrid 署名済み")
      (is (= [:committed :policy-hold] (mapv :t entries)))
      (let [r (agent/verify-ledger home agent-id registry)]
        (is (:ok? r) (pr-str r))
        (is (= 2 (:entries r)))))))

(deftest approve-derives-the-did-and-refuses-a-substituted-one
  (testing "did は公開鍵から導出され、request が別の did を主張したら拒否する"
    (let [p (crypto/jvm-provider)
          home (tmp-home)
          {:keys [request]} (agent/make-request! p {:label "x" :custody :file :home home})
          invite #:invite{:id "i" :compartments #{} :ops proto/default-ops
                          :purposes #{} :agent-ttl-sec 3600}]
      (is (= (:agent/did request)
             (:agent/did (:principal (agent/approve p request {:invite invite}))))
          "正しい did はそのまま通る")
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"agent enrollment refused"
           (agent/approve p (assoc request :agent/did "did:key:zSomeoneElse")
                          {:invite invite}))))))

(deftest approve-requires-a-matching-fingerprint-when-one-is-offered
  (testing "読み上げられた fingerprint が合わなければ拒否する"
    (let [p (crypto/jvm-provider)
          home (tmp-home)
          {:keys [request fingerprint]} (agent/make-request! p {:label "x" :custody :file
                                                                :home home})
          invite #:invite{:id "i" :compartments #{} :ops proto/default-ops
                          :purposes #{} :agent-ttl-sec 3600}]
      (is (:principal (agent/approve p request {:invite invite
                                                :confirmed-fingerprint fingerprint})))
      (is (thrown? clojure.lang.ExceptionInfo
                   (agent/approve p request {:invite invite
                                             :confirmed-fingerprint "AAAA-BBBB-CCCC"}))))))

(deftest the-private-key-never-appears-in-the-request
  (testing "request に秘密素材が一切載っていない"
    (let [p (crypto/jvm-provider)
          home (tmp-home)
          {:keys [request]} (agent/make-request! p {:label "x" :custody :file :home home})
          printed (pr-str request)]
      (doseq [field ["private-b64" "mldsa-private-b64" "kem-secret"]]
        (is (not (str/includes? printed field))
            (str field " が request に載っている"))))))

(deftest the-registry-is-not-in-the-vault-snapshot
  (testing "principal は vault.edn に載らない — push が 9.5MB を書き直さず、
            owner の次の push が enrollment を消さない"
    (let [{:keys [home agent-id]} (fixture)
          snapshot (persist/load* (str home "/vault.edn"))]
      (is (empty? (:agent/registry (:meta snapshot))))
      (is (empty? (:agent/invites (:meta snapshot))))
      (is (= agent-id (:agent/id (agent/principal (agent/load-registry home) agent-id))))
      (testing "owner が古い snapshot を書き戻しても principal は残る"
        (persist/save! (str home "/vault.edn") (assoc snapshot :meta {}))
        (is (= :open (:status (agent/open {:home home :agent-id agent-id}))))))))

(deftest a-legacy-registry-in-vault-metadata-is-migrated-once
  (testing "分離前の vault（:meta に registry がある）を読んでも :not-registered にしない"
    (let [{:keys [home agent-id]} (fixture)
          registry (agent/load-registry home)
          ;; put it back the old way and remove the new file
          _ (let [data (persist/load* (str home "/vault.edn"))]
              (persist/save! (str home "/vault.edn")
                             (assoc data :meta (select-keys registry
                                                            [:agent/registry :agent/invites]))))
          _ (.delete (java.io.File. (agent/registry-path home)))
          _ (is (empty? (:agent/registry (agent/load-registry home)))
                "移行前は空に見える")
          session (agent/open {:home home :agent-id agent-id})]
      (is (= :open (:status session)))
      (is (.exists (java.io.File. (agent/registry-path home))) "移行はファイルを作る")
      (is (= agent-id (:agent/id (agent/principal (agent/load-registry home) agent-id)))))))

(deftest a-refused-enrollment-does-not-bump-the-sequence
  (testing "書かない更新は seq を進めない（招待を無駄に消費しない）"
    (let [{:keys [home]} (fixture)
          before (:agent/seq (agent/load-registry home))]
      (is (nil? (agent/update-registry! home (fn [_] nil))))
      (is (= before (:agent/seq (agent/load-registry home)))))))
