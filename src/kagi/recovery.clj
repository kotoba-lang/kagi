(ns kagi.recovery
  "Threshold hybrid approvals for compromised-key recovery."
  (:require [cbor.core :as cbor]
            [kagi.crypto :as crypto])
  (:import [java.util Base64]))

(def approval-domain "kotoba/key-recovery-approval/v1")

(defn approval-bytes ^bytes [event-id approver-id]
  (cbor/encode {:domain approval-domain :rotation/id event-id
                :approver/id approver-id}))

(defn approve [p event approver-id secret]
  {:recovery/approver approver-id
   :recovery/rotation-id (:rotation/id event)
   :recovery/signature (crypto/sign-with p secret
                                     (approval-bytes (:rotation/id event) approver-id))})

(defn valid-approval? [p event approval public]
  (and (= (:rotation/id event) (:recovery/rotation-id approval))
       (crypto/verify* p public
                       (approval-bytes (:rotation/id event) (:recovery/approver approval))
                       (:recovery/signature approval))))

(defn validate-distinct-members!
  "Resolve every policy member and reject aliases that map multiple logical
  IDs to one physical hybrid signing key. Returns the resolved id->public map."
  [label members public-of]
  (let [resolved (into {} (map (fn [member] [member (public-of member)]) members))
        missing (->> resolved (filter (comp nil? val)) (map key) set)
        fingerprints (map (fn [[_ public]]
                            (.encodeToString (.withoutPadding (Base64/getUrlEncoder))
                                             (crypto/sha256 (cbor/encode public))))
                          resolved)]
    (when (seq missing)
      (throw (ex-info (str label " policy has unresolved members") {:members missing})))
    (when-not (= (count resolved) (count (set fingerprints)))
      (throw (ex-info (str label " policy reuses a signing key across member ids") {})))
    resolved))

(defn threshold-authorized?
  "Require k distinct allowlisted valid hybrid approvals. public-of resolves approver id."
  [p event approvals {:keys [k members public-of]}]
  (when-not (and (pos-int? k) (<= k (count members)))
    (throw (ex-info "invalid recovery threshold" {:k k :members (count members)})))
  (let [resolved (validate-distinct-members! "recovery" members public-of)
        valid (->> approvals
                   (filter #(contains? (set members) (:recovery/approver %)))
                   (filter #(when-let [pub (get resolved (:recovery/approver %))]
                              (valid-approval? p event % pub)))
                   (map :recovery/approver)
                   distinct
                   count)]
    (>= valid k)))

(defn attach-approvals [event approvals]
  (assoc event :rotation/recovery-approvals (vec approvals)))
