(ns kagi.governor-abac-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.governor :as governor]
            [kagi.store :as store]))

(def st (store/mem-store))
(def request {:op :item/reveal :item-id "secret" :tenant "alpha"
              :classification :confidential})
(def context {:did "did:key:owner" :role :owner :purpose :operations
              :tenant "alpha" :clearance :restricted
              :device-trusted? true :network-zone :private
              :now "2026-07-19T12:00:00Z"})
(def policy {:id "vault-read-v1" :allowed-purposes #{:operations}
             :tenant-isolation? true :require-device-trust? true
             :allowed-network-zones #{:private}
             :not-before "2026-07-19T00:00:00Z"
             :expires-at "2026-07-20T00:00:00Z"
             :max-reveal-bytes 1024})
(def proposal {:confidence 1.0 :plaintext-bytes 64})

(deftest complete-abac-context-is-authorized-and-receipted
  (let [decision (governor/check request (assoc context :abac-policy policy)
                                 proposal st)]
    (is (:ok? decision))
    (is (= "vault-read-v1" (:policy-id decision)))
    (is (= :confidential (get-in decision [:attributes :resource :classification])))
    (is (= :private (get-in decision [:attributes :environment :network-zone])))))

(deftest every-abac-axis-fails-closed
  (doseq [[label update-context update-request expected]
          [[:purpose #(assoc % :purpose :marketing) identity :abac-purpose]
           [:device #(assoc % :device-trusted? false) identity :abac-device]
           [:network #(assoc % :network-zone :public) identity :abac-network-zone]
           [:tenant identity #(assoc % :tenant "beta") :abac-tenant]
           [:clearance #(assoc % :clearance :internal) identity :abac-clearance]
           [:expired #(assoc % :now "2026-07-21T00:00:00Z") identity :abac-expired]]]
    (testing (name label)
      (let [decision (governor/check (update-request request)
                                     (assoc (update-context context) :abac-policy policy)
                                     proposal st)]
        (is (false? (:ok? decision)))
        (is (some #(= expected (:rule %)) (:violations decision)))))))

(deftest missing-disclosure-measurement-is-denied
  (let [decision (governor/check request (assoc context :abac-policy policy)
                                 (dissoc proposal :plaintext-bytes) st)]
    (is (some #(= :abac-disclosure-size (:rule %)) (:violations decision)))))

(deftest classification-downgrade-requires-exact-declassification-grant
  (let [downgrade-request (assoc request :output-classification :public)
        denied (governor/check downgrade-request context proposal st nil)
        grant {:id :support-ticket :subject (:did context)
               :purpose (:purpose context) :from :confidential :to :public
               :expires-at "2026-07-20T00:00:00Z"}
        allowed (governor/check downgrade-request
                                (assoc context :declassification-grant grant)
                                proposal st nil)]
    (is (some #(= :information-flow/declassification-required (:rule %))
              (:violations denied)))
    (is (not-any? #(= :information-flow/declassification-required (:rule %))
                  (:violations allowed)))))
