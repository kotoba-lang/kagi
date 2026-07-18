(ns kagi.security-readiness-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.security-readiness :as readiness]
            [kagi.crypto :as crypto]))

(def now "2026-07-18T12:00:00Z")

(def provider (crypto/jvm-provider))
(def reviewer (crypto/sign-keypair provider))

(defn- attestation [id issuer]
  (readiness/issue-attestation
   provider (:secret reviewer) id
   {:issuer issuer :performed-at "2026-07-18T11:00:00Z"
    :artifact-sha256 (apply str (repeat 64 "a"))}))

(def base
  {:now now
   :crypto-provider provider
   :trusted-attestors (into {} (map (fn [id] [(name id) (:public reviewer)])
                                    readiness/required-attestations))
   :identity {:native-signing-handle {:custody :non-exportable-native-handle
                                      :private-exported? false}
              :native-kem-handle {:custody :non-exportable-native-handle
                                  :private-exported? false}}
   :records [{:key/id "i" :key/class :item-dek :key/purpose :item-dek
              :key/epoch 1 :key/state :active :key/created-at "2026-07-17T12:00:00Z"}
             {:key/id "s" :key/class :identity-signing :key/purpose :authority
              :key/epoch 1 :key/state :active :key/created-at "2026-07-17T12:00:00Z"}
             {:key/id "k" :key/class :recipient-kem :key/purpose :recipient-kem
              :key/epoch 1 :key/state :active :key/created-at "2026-07-17T12:00:00Z"}
             {:key/id "v" :key/class :vmk :key/purpose :vmk
              :key/epoch 1 :key/state :active :key/created-at "2026-07-17T12:00:00Z"}
             {:key/id "u" :key/class :device-unlock :key/purpose :device-unlock
              :key/epoch 1 :key/state :active :key/created-at "2026-07-17T12:00:00Z"}]
   :unlock-wraps [{:method :passkey-prf}]
   :rotation-events [{:rotation/id "event"}]
   :jobs []
   :attestations (into {} (map (fn [id] [id (attestation id (name id))])
                               readiness/required-attestations))})

(deftest complete-evidence-can-pass
  (let [result (readiness/assess base)]
    (is (true? (:security/production-ready? result)))
    (is (= :high (:security/assurance result)))
    (is (empty? (:security/blockers result)))))

(deftest attestation-issuance-validates-control-and-digest
  (is (thrown? clojure.lang.ExceptionInfo
               (readiness/issue-attestation provider (:secret reviewer) :invented
                                            {:issuer "reviewer" :performed-at now
                                             :artifact-sha256 (apply str (repeat 64 "a"))})))
  (is (thrown? clojure.lang.ExceptionInfo
               (readiness/issue-attestation provider (:secret reviewer)
                                            :independent-crypto-review
                                            {:issuer "reviewer" :performed-at now
                                             :artifact-sha256 "not-a-digest"}))))

(deftest local-and-external-gaps-fail-closed
  (let [result (readiness/assess
                (-> base
                    (assoc-in [:identity :private-b64] "must-not-exist")
                    (assoc :unlock-wraps [] :rotation-events [])
                    (assoc-in [:attestations :independent-crypto-review :artifact-sha256] "unsigned")))]
    (is (false? (:security/production-ready? result)))
    (is (every? (set (:security/blockers result))
                [:no-persisted-raw-private-keys :passkey-prf-enrolled
                 :durable-rotation-dag-present :independent-crypto-review]))))

(deftest stale-rotation-and-dead-letter-block-production
  (let [result (readiness/assess
                (-> base
                    (assoc-in [:records 0 :key/created-at] "2020-01-01T00:00:00Z")
                    (assoc :jobs [{:rotation/job-id "i/1" :job/status :dead-letter}])))]
    (is (= #{:no-overdue-rotation :no-rotation-dead-letter}
           (set (filter #{:no-overdue-rotation :no-rotation-dead-letter}
                        (:security/blockers result)))))))

(deftest future-or-self-asserted-evidence-is-not-accepted
  (testing "boolean/self-assertion and future timestamps do not become assurance"
    (let [bad (-> base
                  (assoc-in [:attestations :real-browser-passkey] true)
                  (assoc-in [:attestations :hardware-handle-integration :performed-at]
                            "2027-01-01T00:00:00Z"))
          blockers (set (:security/blockers (readiness/assess bad)))]
      (is (contains? blockers :real-browser-passkey))
      (is (contains? blockers :hardware-handle-integration)))))
