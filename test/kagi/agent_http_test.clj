(ns kagi.agent-http-test
  "End to end over a real socket: an agent enrolls itself with an invite,
  reads one item it was granted, and is refused everything else.

  The point of driving `kagi.agent-client` rather than hand-rolled requests is
  that the last step — turning released ciphertext into a secret — happens in
  the CLIENT. If the server ever started returning plaintext, this suite would
  keep passing only if the SDK also stopped decrypting, and it does not."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest testing is]]
            [kagi.agent :as agent]
            [kagi.agent-client :as client]
            [kagi.agent-http :as agent-http]
            [kagi.agent-service :as agent-service]
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

(def ^:private test-difficulty
  "8 bits ≈ 256 hashes. The production default is 20 and the suite should not
  spend a second per enrollment proving a constant."
  8)

(defn- tmp-home []
  (str (.toAbsolutePath (Files/createTempDirectory "kagi-agent-http" (make-array FileAttribute 0)))))

(defn- now [] (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS)))

(defn- run-owner [p id st vmk req purpose]
  (let [actor (op/build st {:crypto p :signer (identity/sign-secret id)
                            :signer-key (:signing-key id)})]
    (:state (g/run* actor
                    {:request req
                     :context {:did (:did id) :role :owner :phase 3 :vmk vmk
                               :purpose purpose :now (now) :consent? true
                               :register (identity/member-record id :owner)}}
                    {:thread-id (str (:op req) "-" (:item-id req) "-" (rand))}))))

(defn- save! [home st meta]
  (persist/save! (str home "/vault.edn")
                 (assoc (select-keys @(:a st) [:members :items :grants :blocks
                                               :ledger :rotation-events])
                        :meta meta)))

(defn- fixture
  "An owner vault with two items and one invite, plus a running server."
  [& [{:keys [uses ops compartments]}]]
  (let [p (crypto/jvm-provider)
        home (tmp-home)
        owner (identity/generate-identity p)
        vmk (crypto/rand-bytes p 32)
        st (store/mem-store {:members {(:did owner) (identity/member-record owner :owner)}})
        _ (run-owner p owner st vmk {:op :item/create :item-id "shared" :compartment "ops"
                                     :plaintext (.getBytes "over-the-wire-secret" "UTF-8")} :seed)
        _ (run-owner p owner st vmk {:op :item/create :item-id "private" :compartment "ops"
                                     :plaintext (.getBytes "never-shared" "UTF-8")} :seed)
        {:keys [secret record]} (agent/mint-invite p {:compartments (or compartments #{"ops"})
                                                      :ops ops
                                                      :uses (or uses 1)
                                                      :ttl-sec 600
                                                      :agent-ttl-sec 3600})
        _ (save! home st {})
        _ (agent/update-registry! home #(agent/add-invite % record))
        svc (agent-service/service home)
        ;; file-backed docs carry no DID, so the tenant has to be named
        server (agent-http/start! svc {:difficulty-bits test-difficulty
                                       :tenant (:did owner)})]
    {:p p :home home :owner owner :vmk vmk :store st :invite secret
     :svc svc :server server
     :grant! (fn [did item]
               ;; The owner shares an item AFTER the agent enrolled. The server
               ;; wrote nothing into the snapshot, so the member record is
               ;; materialised here from the registry — the same thing
               ;; `kagi agent grant` does.
               (let [data (persist/load* (str home "/vault.edn"))
                     st* (store/mem-store (dissoc data :meta))
                     prin (first (filter #(= did (:agent/did %))
                                         (:agent/registry (agent/load-registry home))))
                     _ (store/put-member! st* (agent/member-of prin))
                     state (run-owner p owner st* vmk
                                      {:op :share/grant :item-id item :recipient-did did}
                                      :grant)]
                 (save! home st* (:meta data))
                 (get-in state [:result :effect])))}))

(defn- stop! [{:keys [server]}] ((:stop server)))

(defn- enroll [{:keys [server invite]} label]
  (let [c (client/client {:base-url (:origin server) :tenant (:tenant server)})]
    (client/enroll! c {:invite invite :label label})))

(deftest an-agent-enrolls-itself-and-reads-exactly-one-item
  (let [f (fixture)]
    (try
      (let [{:keys [agent-id account-key secret principal] :as enrolled} (enroll f "resident")]
        (is (some? account-key) (pr-str enrolled))
        (is (str/starts-with? account-key "kagi_agt_"))
        (is (some? agent-id))

        (testing "登録直後は何も読めない — enrollment は scope であって鍵ではない"
          (let [c (client/client {:base-url (:origin (:server f)) :account-key account-key :tenant (:tenant (:server f))})]
            (is (= [] (client/items c)))))

        (testing "owner が 1 件共有すると、その 1 件だけが見えて開ける"
          (is (= :shared ((:grant! f) (:did principal) "shared")))
          (let [c (client/client {:base-url (:origin (:server f)) :account-key account-key :tenant (:tenant (:server f))})]
            (is (= ["shared"] (mapv :item/id (client/items c))))
            (let [r (client/open-item! c (:kem secret) "shared")]
              (is (= :ok (:status r)))
              (is (= "over-the-wire-secret" (:plaintext r))))
            (testing "共有されていない item は :no-grant で断られる"
              (let [r (client/open-item! c (:kem secret) "private")]
                (is (= :forbidden (:status r)))
                (is (= "no-grant" (:basis r))))))))
      (finally (stop! f)))))

(deftest the-server-never-sends-plaintext
  (testing "sealed 応答の中に平文は現れない — 開くのはクライアント側"
    (let [f (fixture)]
      (try
        (let [{:keys [account-key principal]} (enroll f "resident")
              _ ((:grant! f) (:did principal) "shared")
              c (client/client {:base-url (:origin (:server f)) :account-key account-key :tenant (:tenant (:server f))})
              raw (client/call c {:method "GET" :path "/items/shared/sealed"})]
          (is (= 200 (:status raw)))
          (is (not (str/includes? (pr-str (:body raw)) "over-the-wire-secret"))
              "released 素材は暗号文のまま")
          (is (every? (:body raw) [:envelope :nonce :ciphertext])))
        (finally (stop! f))))))

(deftest enrollment-without-an-invite-is-refused
  (let [f (fixture)]
    (try
      (let [c (client/client {:base-url (:origin (:server f)) :tenant (:tenant (:server f))})
            r (client/enroll! c {:label "uninvited"})]
        (is (= "enrollment-refused" (:error r)))
        (is (some #{"invite-missing"} (map :rule (:errors r)))
            (pr-str (:errors r))))
      (finally (stop! f)))))

(deftest an-invite-is-spent-when-it-is-used
  (testing "uses 1 の invite で 2 度目の enrollment は通らない"
    (let [f (fixture {:uses 1})]
      (try
        (is (some? (:account-key (enroll f "first"))))
        (let [r (enroll f "second")]
          (is (= "enrollment-refused" (:error r)))
          (is (some #{"invite-exhausted"} (map :rule (:errors r))) (pr-str (:errors r))))
        (finally (stop! f))))))

(deftest a-challenge-cannot-be-reused
  (testing "同じ challenge_id を使い回すと :challenge-unknown"
    (let [f (fixture {:uses 5})]
      (try
        (let [c (client/client {:base-url (:origin (:server f)) :tenant (:tenant (:server f))})
              challenge (:body (client/call c {:method "POST" :path "/agents/challenges"
                                               :body {}}))
              nonce (client/solve challenge)
              {:keys [public]} (client/keypair (crypto/jvm-provider))
              body (client/enrollment-body challenge nonce
                                           {:invite (:invite f) :label "a" :public public})
              first-try (client/call c {:method "POST" :path "/agents" :body body})
              second-try (client/call c {:method "POST" :path "/agents" :body body})]
          (is (= 201 (:status first-try)))
          (is (= 403 (:status second-try)))
          (is (some #{"challenge-unknown"} (map :rule (:errors (:body second-try))))
              (pr-str (:body second-try))))
        (finally (stop! f))))))

(deftest bad-work-is-refused-and-burns-the-challenge
  (let [f (fixture {:uses 5})]
    (try
      (let [c (client/client {:base-url (:origin (:server f)) :tenant (:tenant (:server f))})
            challenge (:body (client/call c {:method "POST" :path "/agents/challenges"
                                             :body {}}))
            {:keys [public]} (client/keypair (crypto/jvm-provider))
            r (client/call c {:method "POST" :path "/agents"
                              :body (client/enrollment-body challenge "definitely-wrong"
                                                            {:invite (:invite f) :label "a"
                                                             :public public})})]
        (is (= 403 (:status r)))
        (is (some #{"pow-failed"} (map :rule (:errors (:body r)))) (pr-str (:body r))))
      (finally (stop! f)))))

(deftest revocation-takes-effect-without-restarting-the-server
  (testing "kagi agent revoke 相当を書いた直後から token が死ぬ"
    (let [f (fixture)]
      (try
        (let [{:keys [account-key agent-id principal]} (enroll f "resident")
              _ ((:grant! f) (:did principal) "shared")
              c (client/client {:base-url (:origin (:server f)) :account-key account-key :tenant (:tenant (:server f))})
              _ (is (= 200 (:status (client/call c {:method "GET" :path "/items"})))
                    "revoke 前は通る")
              _ (agent/update-registry! (:home f) #(agent/revoke-agent % agent-id (now)))
              after (client/call c {:method "GET" :path "/items"})]
          (is (= 403 (:status after)))
          (is (= "revoked" (:error (:body after)))))
        (finally (stop! f))))))

(deftest an-unknown-token-is-unauthorized
  (let [f (fixture)]
    (try
      (let [c (client/client {:base-url (:origin (:server f)) :account-key "kagi_agt_nope"
                                 :tenant (:tenant (:server f))})]
        (is (= 403 (:status (client/call c {:method "GET" :path "/whoami"}))))
        (is (= 401 (:status (client/call (client/client {:base-url (:origin (:server f)) :tenant (:tenant (:server f))})
                                         {:method "GET" :path "/whoami"})))))
      (finally (stop! f)))))

(deftest a-non-loopback-base-url-must-be-https
  (testing "平文で LAN へ token を投げる client は作れない"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"requires HTTPS"
                          (client/client {:base-url "http://10.0.0.5:8080" :tenant "did:key:z1"})))
    (is (map? (client/client {:base-url "https://vault.example" :tenant "did:key:z1"})))
    (is (map? (client/client {:base-url "http://127.0.0.1:9999" :tenant "did:key:z1"})))
    (testing ":tenant は必須 — 経路が tenant を名指すので省略できない"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #":tenant"
                            (client/client {:base-url "https://vault.example"}))))))

(deftest enrollment-does-not-rewrite-the-vault-snapshot
  (testing "server は registry しか書かない — owner の次の push が enrollment を消さない"
    (let [f (fixture)]
      (try
        (let [path (str (:home f) "/vault.edn")
              before (slurp path)
              {:keys [agent-id]} (enroll f "resident")]
          (is (= before (slurp path)) "snapshot のバイト列が変わっていない")
          (is (some #(= agent-id (:agent/id %))
                    (:agent/registry (agent/load-registry (:home f))))
              "principal は registry に在る"))
        (finally (stop! f))))))

;; ── tenant routing ─────────────────────────────────────────────────────────

(deftest an-unknown-tenant-is-refused-rather-than-served
  (testing "別の tenant の経路がこのサービスに届かない"
    (let [f (fixture)]
      (try
        (let [origin (:origin (:server f))
              c (client/client {:base-url origin :tenant "did:key:zSomebodyElse"})]
          (is (= 404 (:status (client/call c {:method "POST" :path "/agents/challenges"}))))
          (is (= "unknown-tenant"
                 (:error (:body (client/call c {:method "POST" :path "/agents/challenges"}))))))
        (finally (stop! f))))))

(deftest a-path-without-a-tenant-is-not-served
  (testing "tenant を名指さない経路は 404、しかも何故かを言う"
    (let [f (fixture)]
      (try
        (let [req (-> (java.net.http.HttpRequest/newBuilder
                       (java.net.URI/create (str (:origin (:server f)) "/v1/items")))
                      (.header "accept" "application/json")
                      (.GET) (.build))
              resp (.send (java.net.http.HttpClient/newHttpClient) req
                          (java.net.http.HttpResponse$BodyHandlers/ofString))]
          (is (= 404 (.statusCode resp)))
          (is (str/includes? (.body resp) "/v1/t/")))
        (finally (stop! f))))))

(deftest the-server-reports-the-base-url-an-agent-should-use
  (let [f (fixture)]
    (try
      (let [s (:server f)]
        (is (= (str (:origin s) "/v1/t/" (:tenant s)) (:base-url s))))
      (finally (stop! f)))))

;; ── stateless challenges ───────────────────────────────────────────────────

(def ^:private pow-errors #'kagi.agent-http/pow-errors)

(defn- solved [challenge]
  {:challenge_id (:challenge_id challenge)
   :nonce (client/solve challenge)})

(deftest a-challenge-carries-its-own-validity
  (testing "同じ鍵を持つ別インスタンスが、自分で発行していない challenge を受理する"
    (let [p (crypto/jvm-provider)
          key* (byte-array (repeat 32 (byte 7)))
          minted (agent-http/mint-challenge key* p {:difficulty-bits test-difficulty})
          ;; a SECOND instance: its own `spent` set, no shared state at all
          other-spent (atom #{})]
      (is (empty? (pow-errors key* other-spent {:pow (solved minted)}))))))

(deftest a-challenge-signed-by-another-key-is-not-ours
  (let [p (crypto/jvm-provider)
        mine (byte-array (repeat 32 (byte 7)))
        theirs (byte-array (repeat 32 (byte 9)))
        minted (agent-http/mint-challenge theirs p {:difficulty-bits test-difficulty})]
    (is (some #{:challenge-unknown}
              (map :rule (pow-errors mine (atom #{}) {:pow (solved minted)}))))))

(deftest an-altered-challenge-token-is-refused
  (let [p (crypto/jvm-provider)
        key* (byte-array (repeat 32 (byte 7)))
        minted (agent-http/mint-challenge key* p {:difficulty-bits test-difficulty})
        tampered (assoc minted :challenge_id
                        (str/replace (:challenge_id minted) #"^." "Z"))]
    (is (some #{:challenge-unknown}
              (map :rule (pow-errors key* (atom #{}) {:pow (solved tampered)}))))))

(deftest a-spent-challenge-is-refused-on-the-instance-that-saw-it
  (testing "単一インスタンス内では使い回しを弾く（分散では invite の uses が効く）"
    (let [p (crypto/jvm-provider)
          key* (byte-array (repeat 32 (byte 7)))
          spent (atom #{})
          minted (agent-http/mint-challenge key* p {:difficulty-bits test-difficulty})
          pow (solved minted)]
      (is (empty? (pow-errors key* spent {:pow pow})))
      (is (some #{:challenge-unknown} (map :rule (pow-errors key* spent {:pow pow})))))))

(deftest a-wrong-nonce-also-spends-the-challenge
  (testing "外した答えでも challenge は焼く（オフラインで挽けないように）"
    (let [p (crypto/jvm-provider)
          key* (byte-array (repeat 32 (byte 7)))
          spent (atom #{})
          minted (agent-http/mint-challenge key* p {:difficulty-bits test-difficulty})]
      (is (some #{:pow-failed}
                (map :rule (pow-errors key* spent {:pow {:challenge_id (:challenge_id minted)
                                                         :nonce "nope"}}))))
      (is (some #{:challenge-unknown}
                (map :rule (pow-errors key* spent {:pow (solved minted)})))))))

;; ── the audit loop ─────────────────────────────────────────────────────────

(deftest an-agent-signs-what-it-opened-and-the-owner-can-verify-it
  (testing "HTTP 経路には governor 実行が無いので、開示の記録は client が作る"
    (let [f (fixture)]
      (try
        (let [{:keys [account-key principal secret]}
              (enroll f "audited")
              _ ((:grant! f) (:did principal) "shared")
              c (client/client {:base-url (:origin (:server f))
                                :tenant (:tenant (:server f))
                                :account-key account-key
                                :agent-did (:did principal)
                                :sign-secret (:sign secret)})]
          (is (= :ok (:status (client/open-item! c (:kem secret) "shared" :publish))))
          (is (= :forbidden (:status (client/open-item! c (:kem secret) "private" :publish))))

          (let [r (client/submit-audit! c)]
            (is (= :accepted (:status r)) (pr-str r))
            (is (= 2 (:entries r)))
            (is (= 2 (:new r))))

          (testing "2 度目は差分だけが新規として数えられる"
            (client/open-item! c (:kem secret) "shared" :again)
            (let [r (client/submit-audit! c)]
              (is (= :accepted (:status r)))
              (is (= 3 (:entries r)))
              (is (= 1 (:new r)))))

          (testing "短い鎖を出し直しても受け付けない"
            (let [{:keys [status body]}
                  (client/call c {:method "POST" :path "/audit" :edn? true
                                  :body {:ledger (vec (take 1 @(:ledger c)))}})]
              (is (= 409 status))
              (is (= "truncated" (name (:basis body)))))))
        (finally (stop! f))))))

(deftest a-tampered-audit-chain-is-rejected-not-stored
  (let [f (fixture)]
    (try
      (let [{:keys [account-key principal secret]} (enroll f "tamper")
            _ ((:grant! f) (:did principal) "shared")
            c (client/client {:base-url (:origin (:server f))
                              :tenant (:tenant (:server f))
                              :account-key account-key
                              :agent-did (:did principal)
                              :sign-secret (:sign secret)})]
        (client/open-item! c (:kem secret) "shared" :publish)
        (let [forged (mapv #(assoc % :purpose :something-else) @(:ledger c))
              {:keys [status body]} (client/call c {:method "POST" :path "/audit"
                                                    :edn? true :body {:ledger forged}})]
          (is (= 409 status))
          (is (= "chain-broken" (name (:basis body))))))
      (finally (stop! f)))))

(deftest a-client-without-a-signing-key-says-so-rather-than-posting-nothing
  (let [f (fixture)]
    (try
      (let [{:keys [account-key principal secret]} (enroll f "unsigned")
            _ ((:grant! f) (:did principal) "shared")
            c (client/client {:base-url (:origin (:server f))
                              :tenant (:tenant (:server f))
                              :account-key account-key})]
        (client/open-item! c (:kem secret) "shared" :publish)
        (is (= :nothing-to-submit (:status (client/submit-audit! c)))))
      (finally (stop! f)))))
