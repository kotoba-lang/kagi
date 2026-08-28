(ns kagi.agent-object-service-test
  "The agent API served from an object store instead of a local vault file.

  This is the shape a public endpoint has: the server has no `$KAGI_HOME`, no
  vault file, and no VMK. It reads the snapshot and the registry out of a
  bucket, releases ciphertext, and the client decrypts. If this passes, `kagi
  agent serve` can run somewhere the vault is not — which is the whole
  prerequisite for putting the API behind a URL."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kagi.agent :as agent]
            [kagi.agent-client :as client]
            [kagi.agent-docs :as docs]
            [kagi.agent-http :as agent-http]
            [kagi.agent-service :as agent-service]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.operation :as op]
            [kagi.persist :as persist]
            [kagi.store :as store]
            [kagi.sync :as sync]
            [langgraph.graph :as g])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.time Instant]
           [java.time.temporal ChronoUnit]))

(defn- tmp-home []
  (str (.toAbsolutePath (Files/createTempDirectory "kagi-obj-svc" (make-array FileAttribute 0)))))

(defn- now [] (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS)))

(defn- fake-store []
  (let [a (atom {})]
    {:a a
     :fns {:get-object (fn [k] (get @a k))
           :put-object (fn [k v] (swap! a assoc k (vec v)) {:ok? true})
           :exists? (fn [k] (contains? @a k))}}))

(defn- run-owner [p id st vmk req purpose]
  (let [actor (op/build st {:crypto p :signer (identity/sign-secret id)
                            :signer-key (:signing-key id)})]
    (:state (g/run* actor
                    {:request req
                     :context {:did (:did id) :role :owner :phase 3 :vmk vmk
                               :purpose purpose :now (now) :consent? true
                               :register (identity/member-record id :owner)}}
                    {:thread-id (str (:op req) "-" (rand))}))))

(defn- fixture
  "An owner vault pushed into a bucket, with an invite in the bucket's
  registry. Nothing the server needs is on local disk."
  []
  (let [p (crypto/jvm-provider)
        home (tmp-home)                      ; owner-side only
        vault-path (str home "/vault.edn")
        owner (identity/generate-identity p)
        did (:did owner)
        vmk (crypto/rand-bytes p 32)
        st (store/mem-store {:members {did (identity/member-record owner :owner)}})
        {:keys [a fns]} (fake-store)
        save! (fn []
                (persist/save! vault-path
                               (assoc (select-keys @(:a st) [:members :items :grants :blocks
                                                             :ledger :rotation-events])
                                      :meta {}))
                (sync/object-push! {:fns fns :did did :vault-path vault-path}))
        _ (run-owner p owner st vmk {:op :item/create :item-id "shared" :compartment "ops"
                                     :plaintext (.getBytes "secret-from-a-bucket" "UTF-8")} :seed)
        _ (save!)
        object-docs (docs/object-docs {:fns fns :did did})
        {:keys [secret record]} (agent/mint-invite p {:compartments #{"ops"} :uses 3
                                                      :ttl-sec 600 :agent-ttl-sec 3600})
        _ ((:update-registry! object-docs) #(agent/add-invite % record))
        svc (agent-service/service object-docs)
        server (agent-http/start! svc {:difficulty-bits 8})]
    {:objects a :fns fns :did did :invite secret :server server :docs object-docs
     :grant! (fn [agent-did item]
               (let [prin (first (filter #(= agent-did (:agent/did %))
                                         (:agent/registry ((:registry object-docs)))))]
                 (store/put-member! st (agent/member-of prin))
                 (let [state (run-owner p owner st vmk
                                        {:op :share/grant :item-id item
                                         :recipient-did agent-did} :grant)]
                   (save!)
                   (get-in state [:result :effect]))))}))

(defn- stop! [f] ((:stop (:server f))))

(deftest an-agent-enrolls-and-reads-from-a-server-with-no-vault-file
  (let [f (fixture)]
    (try
      (let [c (client/client {:base-url (:origin (:server f)) :tenant (:did f)})
            {:keys [account-key principal secret] :as enrolled}
            (client/enroll! c {:invite (:invite f) :label "remote-agent"})]
        (is (some? account-key) (pr-str enrolled))

        (testing "principal は bucket の registry に載る（ローカルには何も書かない）"
          (is (some #(= (:agent_id principal) (:agent/id %))
                    (:agent/registry ((:registry (:docs f)))))))

        (is (= :shared ((:grant! f) (:did principal) "shared")))

        (let [c2 (client/client {:base-url (:origin (:server f)) :account-key account-key :tenant (:did f)})]
          (is (= ["shared"] (mapv :item/id (client/items c2))))
          (let [r (client/open-item! c2 (:kem secret) "shared")]
            (is (= :ok (:status r)))
            (is (= "secret-from-a-bucket" (:plaintext r))))))
      (finally (stop! f)))))

(deftest the-bucket-only-ever-holds-ciphertext
  (let [f (fixture)]
    (try
      (let [c (client/client {:base-url (:origin (:server f)) :tenant (:did f)})
            {:keys [principal]} (client/enroll! c {:invite (:invite f) :label "x"})]
        ((:grant! f) (:did principal) "shared")
        (let [everything (str/join " " (map (fn [[k v]]
                                              (str k " " (String. (byte-array
                                                                   (map unchecked-byte v))
                                                                  "UTF-8")))
                                            @(:objects f)))]
          (is (not (str/includes? everything "secret-from-a-bucket")))
          (testing "registry も token を保持しない"
            (is (not (str/includes? everything "kagi_agt_"))))))
      (finally (stop! f)))))

(deftest keys-are-scoped-to-the-tenant-did
  (let [f (fixture)]
    (try
      (client/enroll! (client/client {:base-url (:origin (:server f)) :tenant (:did f)})
                      {:invite (:invite f) :label "x"})
      (is (every? #(str/starts-with? % (str "kagi/" (:did f) "/")) (keys @(:objects f))))
      (is (contains? @(:objects f) (str "kagi/" (:did f) "/registry/HEAD")))
      (is (contains? @(:objects f) (str "kagi/" (:did f) "/catalog/HEAD")))
      (finally (stop! f)))))

(deftest revocation-in-the-bucket-takes-effect-immediately
  (let [f (fixture)]
    (try
      (let [c (client/client {:base-url (:origin (:server f)) :tenant (:did f)})
            {:keys [account-key principal]} (client/enroll! c {:invite (:invite f) :label "x"})
            c2 (client/client {:base-url (:origin (:server f)) :account-key account-key :tenant (:did f)})]
        (is (= 200 (:status (client/call c2 {:method "GET" :path "/items"}))))
        ((:update-registry! (:docs f)) #(agent/revoke-agent % (:agent_id principal) (now)))
        (let [after (client/call c2 {:method "GET" :path "/items"})]
          (is (= 403 (:status after)))
          (is (= "revoked" (:error (:body after))))))
      (finally (stop! f)))))

(deftest a-second-enrollment-at-the-same-registry-sequence-is-refused
  (testing "object store の版付きキーが並行 enrollment の CAS になる"
    (let [f (fixture)
          reg ((:registry (:docs f)))]
      (try
        ;; simulate a writer that read the registry before another one landed
        (is (some? ((:update-registry! (:docs f)) #(agent/add-invite % #:invite{:id "a"}))))
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"cloud vault changed since pull"
             (sync/object-write! {:fns (:fns f) :did (:did f) :doc :registry
                                  :expected-seq (:agent/seq reg 0)
                                  :text (persist/->edn (assoc reg :agent/seq 99))})))
        (finally (stop! f))))))
