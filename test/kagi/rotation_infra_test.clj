(ns kagi.rotation-infra-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.recovery :as recovery]
            [kagi.rotation :as rotation]
            [kagi.rotation-scheduler :as scheduler]
            [kagi.rotation-store :as rotation-store]
            [kagi.witness :as witness]
            [kagi.witness-service :as witness-service]))

(deftest scheduler-proposes-only-due-active-keys
  (let [keys [{:key/id "due" :key/class :recipient-kem :key/purpose :kem
               :key/epoch 2 :key/state :active :key/created-at "2026-01-01T00:00:00Z"}
              {:key/id "new" :key/class :recipient-kem :key/purpose :kem
               :key/epoch 1 :key/state :active :key/created-at "2026-07-01T00:00:00Z"}
              {:key/id "retired" :key/class :recipient-kem :key/purpose :kem
               :key/epoch 1 :key/state :decrypt-or-verify-only
               :key/created-at "2020-01-01T00:00:00Z"}]
        jobs (scheduler/due-rotations keys "2026-07-18T00:00:00Z")]
    (is (= ["due/2"] (mapv :rotation/job-id jobs)))))

(deftest durable-scheduler-is-idempotent-leased-and-retryable
  (let [dir (doto (java.io.File/createTempFile "kagi-jobs" ".tmp") (.delete) (.mkdirs))
        path (str (java.io.File. dir "jobs.edn"))
        store (scheduler/file-job-store path)
        record {:key/id "due" :key/class :recipient-kem :key/purpose :kem
                :key/epoch 2 :key/state :active :key/created-at "2026-01-01T00:00:00Z"}
        now "2026-07-18T00:00:00Z"
        calls (atom 0)
        failed (scheduler/run-due! store [record] now
                                   {:owner "node-a" :max-attempts 2
                                    :worker (fn [_] (swap! calls inc)
                                              (throw (ex-info "boom" {})))})]
    (is (= 1 @calls))
    (is (= :retry (:job/status (first failed))))
    (is (= 1 (count (scheduler/jobs (scheduler/file-job-store path))))
        "restart sees one idempotent persistent job")
    (is (empty? (scheduler/run-due! store [record] now
                                    {:owner "node-b" :worker identity}))
        "backoff prevents immediate duplicate execution")
    (let [later "2026-07-18T00:02:00Z"
          completed (scheduler/run-due! store [record] later
                                        {:owner "node-b" :worker (constantly :rotated)})]
      (is (= :complete (:job/status (first completed))))
      (is (= :rotated (:job/result (first completed)))))))

(deftest scheduler-bounds-each-catch-up-batch
  (let [dir (doto (java.io.File/createTempFile "kagi-bounded-jobs" ".tmp") (.delete) (.mkdirs))
        store (scheduler/file-job-store (str (java.io.File. dir "jobs.edn")))
        records (mapv (fn [n] {:key/id (str "due-" n) :key/class :item-dek
                               :key/purpose :item-dek :key/epoch 1 :key/state :active
                               :key/created-at "2020-01-01T00:00:00Z"})
                      (range 4))
        results (scheduler/run-due! store records "2026-07-18T00:00:00Z"
                                    {:owner "bounded" :max-jobs 2 :worker identity})]
    (is (= 2 (count results)))
    (is (= 2 (count (filter #(= :complete (:job/status %)) (scheduler/jobs store)))))
    (is (= 2 (count (filter #(= :queued (:job/status %)) (scheduler/jobs store)))))))

(deftest scheduler-lease-prevents-concurrent-owner-and-expiry-recovers
  (let [dir (doto (java.io.File/createTempFile "kagi-lease" ".tmp") (.delete) (.mkdirs))
        store (scheduler/file-job-store (str (java.io.File. dir "jobs.edn")))
        proposal {:rotation/job-id "k/1" :rotation/due-at "2026-01-01T00:00:00Z"}]
    (scheduler/enqueue! store [proposal] "2026-01-01T00:00:00Z")
    (is (= "node-a" (:job/owner
                     (scheduler/claim! store "node-a" "2026-01-01T00:00:00Z" 60))))
    (is (nil? (scheduler/claim! store "node-b" "2026-01-01T00:00:30Z" 60)))
    (is (= "node-b" (:job/owner
                     (scheduler/claim! store "node-b" "2026-01-01T00:01:01Z" 60))))))

(deftest file-store-persists-and-quarantines-forks
  (let [dir (doto (java.io.File/createTempFile "kagi-rotation" ".tmp") (.delete) (.mkdirs))
        path (str (java.io.File. dir "dag.edn"))
        store (rotation-store/file-store path)
        e1 (rotation/new-event {:subject "did:o" :purpose :kem :from-key "a"
                                :to-key "b" :from-epoch 0})
        _ (rotation-store/put-event! store e1)
        e2 (rotation/new-event {:subject "did:o" :purpose :kem :from-key "b"
                                :to-key "c" :from-epoch 1 :parents [(:rotation/id e1)]})
        fork (rotation/new-event {:subject "did:o" :purpose :kem :from-key "b"
                                  :to-key "evil" :from-epoch 1 :parents [(:rotation/id e1)]})]
    (rotation-store/put-event! store e2)
    (is (:quarantined? (rotation-store/put-event! store fork)))
    (is (= 3 (count (rotation-store/events (rotation-store/file-store path)))))
    (is (= #{(:rotation/id e2) (:rotation/id fork)}
           (rotation-store/quarantined store)))))

(deftest recovery-requires-distinct-threshold-approvers
  (let [p (crypto/jvm-provider)
        keys (into {} (for [id ["a" "b" "c"]] [id (crypto/sign-keypair p)]))
        event (rotation/new-event {:subject "did:o" :purpose :authority :from-key "old"
                                   :to-key "new" :from-epoch 4 :reason :compromise})
        approvals [(recovery/approve p event "a" (get-in keys ["a" :secret]))
                   (recovery/approve p event "b" (get-in keys ["b" :secret]))]
        policy {:k 2 :members #{"a" "b" "c"}
                :public-of #(get-in keys [% :public])}]
    (is (recovery/threshold-authorized? p event approvals policy))
    (is (false? (recovery/threshold-authorized? p event [(first approvals) (first approvals)] policy)))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"reuses a signing key"
         (recovery/threshold-authorized?
          p event approvals
          {:k 2 :members #{"a" "alias-of-a"}
           :public-of #(if (= % "a")
                         (get-in keys ["a" :public])
                         (get-in keys ["a" :public]))})))))

(deftest witness-checkpoints-verify-and-detect-split-view
  (let [p (crypto/jvm-provider)
        signer (crypto/sign-keypair p)
        id1 (:rotation/id (rotation/new-event {:subject "s" :purpose :kem :from-key "a"
                                               :to-key "b" :from-epoch 0}))
        id2 (:rotation/id (rotation/new-event {:subject "x" :purpose :kem :from-key "a"
                                               :to-key "b" :from-epoch 0}))
        a (witness/create-checkpoint p "w1" 1 [id1] nil (:secret signer))
        b (witness/create-checkpoint p "w1" 1 [id2] nil (:secret signer))]
    (is (witness/valid-checkpoint? p a (:public signer)))
    (is (false? (witness/valid-checkpoint?
                 p (assoc a :checkpoint/event-ids [id2]) (:public signer))))
    (is (:split-view? (witness/merge-gossip [a] [b])))))

(deftest independent-witness-service-persists-and-flags-equivocation
  (let [p (crypto/jvm-provider)
        signer (crypto/sign-keypair p)
        dir (doto (java.io.File/createTempFile "kagi-witness" ".tmp") (.delete) (.mkdirs))
        service (witness-service/file-service
                 (str (java.io.File. dir "checkpoints.edn")) p
                 #(when (= % "w1") (:public signer)))
        id1 (:rotation/id (rotation/new-event {:subject "s1" :purpose :kem
                                               :from-key "a" :to-key "b" :from-epoch 0}))
        id2 (:rotation/id (rotation/new-event {:subject "s2" :purpose :kem
                                               :from-key "a" :to-key "b" :from-epoch 0}))
        a (witness/create-checkpoint p "w1" 1 [id1] nil (:secret signer))
        b (witness/create-checkpoint p "w1" 1 [id2] nil (:secret signer))]
    (is (:accepted? (witness-service/submit! service a)))
    (is (:idempotent? (witness-service/submit! service a)))
    (is (:split-view? (witness-service/submit! service b)))
    (is (= 2 (count (witness-service/gossip-snapshot service))))
    (is (= 2 (count (witness-service/conflicts service))))))

(deftest witness-service-enforces-checkpoint-chain-continuity
  (let [p (crypto/jvm-provider)
        signer (crypto/sign-keypair p)
        dir (doto (java.io.File/createTempFile "kagi-witness-chain" ".tmp")
              (.delete) (.mkdirs))
        service (witness-service/file-service
                 (str (java.io.File. dir "checkpoints.edn")) p
                 #(when (= % "w1") (:public signer)))
        event (:rotation/id (rotation/new-event {:subject "s" :purpose :kem
                                                  :from-key "a" :to-key "b"
                                                  :from-epoch 0}))
        genesis (witness/create-checkpoint p "w1" 1 [event] nil (:secret signer))
        next (witness/create-checkpoint p "w1" 2 [event]
                                        (:checkpoint/id genesis) (:secret signer))
        wrong-link (witness/create-checkpoint p "w1" 3 [event]
                                              "not-the-previous-id" (:secret signer))
        gap (witness/create-checkpoint p "w1" 4 [event]
                                       (:checkpoint/id next) (:secret signer))]
    (is (:accepted? (witness-service/submit! service genesis)))
    (is (:accepted? (witness-service/submit! service next)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"previous link mismatch"
                          (witness-service/submit! service wrong-link)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"sequence gap"
                          (witness-service/submit! service gap)))
    (is (= 2 (count (witness-service/gossip-snapshot service))))))

(deftest same-root-different-chain-link-is-equivocation
  (let [p (crypto/jvm-provider)
        signer (crypto/sign-keypair p)
        event (:rotation/id (rotation/new-event {:subject "s" :purpose :kem
                                                  :from-key "a" :to-key "b"
                                                  :from-epoch 0}))
        a (witness/create-checkpoint p "w1" 2 [event] "parent-a" (:secret signer))
        b (witness/create-checkpoint p "w1" 2 [event] "parent-b" (:secret signer))]
    (is (= (:checkpoint/root a) (:checkpoint/root b)))
    (is (:split-view? (witness/merge-gossip [a] [b])))))

(deftest separate-service-instances-serialize-shared-state-file
  (let [p (crypto/jvm-provider)
        signer (crypto/sign-keypair p)
        dir (doto (java.io.File/createTempFile "kagi-witness-lock" ".tmp")
              (.delete) (.mkdirs))
        path (str (java.io.File. dir "state.edn"))
        public-of #(when (= % "w1") (:public signer))
        a-service (witness-service/file-service path p public-of)
        b-service (witness-service/file-service path p public-of)
        id1 (:rotation/id (rotation/new-event {:subject "s1" :purpose :kem
                                                :from-key "a" :to-key "b"
                                                :from-epoch 0}))
        id2 (:rotation/id (rotation/new-event {:subject "s2" :purpose :kem
                                                :from-key "a" :to-key "b"
                                                :from-epoch 0}))
        genesis (witness/create-checkpoint p "w1" 1 [id1] nil (:secret signer))
        left (witness/create-checkpoint p "w1" 2 [id1]
                                        (:checkpoint/id genesis) (:secret signer))
        right (witness/create-checkpoint p "w1" 2 [id2]
                                         (:checkpoint/id genesis) (:secret signer))]
    (witness-service/submit! a-service genesis)
    (let [results (mapv deref [(future (witness-service/submit! a-service left))
                               (future (witness-service/submit! b-service right))])]
      (is (= 1 (count (filter :accepted? results))))
      (is (= 1 (count (filter :split-view? results))))
      (is (= 3 (count (witness-service/gossip-snapshot a-service)))
          "neither process-local service loses the other's checkpoint"))))
