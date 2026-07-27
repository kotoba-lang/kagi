(ns kagi.rotation-admission-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.recovery :as recovery]
            [kagi.rotation :as rotation]
            [kagi.rotation-admission :as admission]
            [kagi.rotation-store :as rotation-store]
            [kagi.witness :as witness]))

(defn- temp-store []
  (let [dir (doto (java.io.File/createTempFile "kagi-admission" ".tmp")
              (.delete) (.mkdirs))]
    (rotation-store/file-store (str (java.io.File. dir "dag.edn")))))

(deftest normal-authority-rotation-requires-continuity-and-both-keys
  (let [p (crypto/jvm-provider)
        old (crypto/sign-keypair p)
        new (crypto/sign-keypair p)
        store (temp-store)
        event0 (rotation/new-event {:subject "did:owner" :purpose :authority
                                    :from-key "k0" :to-key "k1" :from-epoch 0})
        event (rotation/sign-normal p event0 (:secret old) (:secret new))
        opts {:current {:subject "did:owner" :purpose :authority
                        :key-id "k0" :epoch 0 :parent nil}
              :old-public (:public old) :new-public (:public new)}]
    (is (:stored? (admission/admit! store p event opts)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"rejected"
                          (admission/admit! (temp-store) p event
                                            (assoc-in opts [:current :epoch] 1))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"rejected"
                          (admission/admit! (temp-store) p event
                                            (assoc opts :old-public (:public new)))))))

(deftest compromise-recovery-requires-distinct-recovery-and-witness-quorums
  (let [p (crypto/jvm-provider)
        new (crypto/sign-keypair p)
        recovery-keys (into {} (for [id ["r1" "r2" "r3"]]
                                 [id (crypto/sign-keypair p)]))
        witness-keys (into {} (for [id ["w1" "w2" "w3"]]
                                [id (crypto/sign-keypair p)]))
        event0 (rotation/new-event {:subject "did:owner" :purpose :authority
                                    :from-key "lost" :to-key "k2" :from-epoch 7
                                    :reason :compromise :policy-cid "policy-v1"})
        base (rotation/sign-recovery p event0 (:secret new))
        approvals (mapv #(recovery/approve p base % (get-in recovery-keys [% :secret]))
                        ["r1" "r2"])
        checkpoints (mapv #(witness/create-checkpoint
                            p % 1 [(:rotation/id base)] nil
                            (get-in witness-keys [% :secret]))
                          ["w1" "w2"])
        event (assoc base :rotation/recovery-approvals approvals
                          :rotation/witness-checkpoints checkpoints)
        opts {:current {:subject "did:owner" :purpose :authority
                        :key-id "lost" :epoch 7 :parent nil}
              :new-public (:public new)
              :recovery-policy {:policy-cid "policy-v1"
                                :k 2 :members #{"r1" "r2" "r3"}
                                :public-of #(get-in recovery-keys [% :public])}
              :witness-policy {:policy-cid "policy-v1"
                               :k 2 :members #{"w1" "w2" "w3"}
                               :public-of #(get-in witness-keys [% :public])}}]
    (is (:stored? (admission/admit! (temp-store) p event opts)))
    (testing "one recovery approver cannot satisfy 2-of-3"
      (is (thrown? clojure.lang.ExceptionInfo
                   (admission/admit! (temp-store) p
                                     (assoc event :rotation/recovery-approvals
                                                  [(first approvals)]) opts))))
    (testing "out-of-band policy substitution is rejected"
      (is (thrown? clojure.lang.ExceptionInfo
                   (admission/admit! (temp-store) p event
                                     (assoc-in opts [:recovery-policy :policy-cid]
                                               "attacker-policy")))))
    (testing "two witness ids backed by one physical key cannot satisfy quorum"
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"witness policy reuses"
           (admission/admit!
            (temp-store) p event
            (assoc opts :witness-policy
                   {:policy-cid "policy-v1" :k 2 :members #{"w1" "alias-w1"}
                    :public-of (constantly (get-in witness-keys ["w1" :public]))})))))
    (testing "a checkpoint for another event is not an inclusion proof"
      (let [wrong (witness/create-checkpoint p "w2" 1 [(:rotation/id
                                                         (rotation/new-event
                                                          {:subject "x" :purpose :authority
                                                           :from-key "a" :to-key "b"
                                                           :from-epoch 0}))]
                                             nil (get-in witness-keys ["w2" :secret]))]
        (is (thrown? clojure.lang.ExceptionInfo
                     (admission/admit! (temp-store) p
                                       (assoc event :rotation/witness-checkpoints
                                                    [(first checkpoints) wrong]) opts)))))))

(deftest competing-child-is-rejected-without-mutating-dag
  (let [p (crypto/jvm-provider)
        old (crypto/sign-keypair p)
        a-key (crypto/sign-keypair p)
        b-key (crypto/sign-keypair p)
        store (temp-store)
        mk #(rotation/sign-normal
             p (rotation/new-event {:subject "did:o" :purpose :authority
                                    :from-key "k0" :to-key %1 :from-epoch 0})
             (:secret old) %2)
        a (mk "a" (:secret a-key))
        b (mk "b" (:secret b-key))
        base {:current {:subject "did:o" :purpose :authority
                        :key-id "k0" :epoch 0 :parent nil}
              :old-public (:public old)}]
    (admission/admit! store p a (assoc base :new-public (:public a-key)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (admission/admit! store p b (assoc base :new-public (:public b-key)))))
    (is (= [(:rotation/id a)] (mapv :rotation/id (rotation-store/events store))))
    (is (empty? (rotation-store/quarantined store)))))
