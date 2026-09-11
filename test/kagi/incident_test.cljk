(ns kagi.incident-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.incident :as incident]))

(def p (crypto/jvm-provider))
(def signer (crypto/sign-keypair p))
(def detection #:incident{:id "inc-1" :detected-at "2026-07-19T12:00:00Z"
                          :signals [:invalid-signature :split-view]
                          :compromised-keys ["key-b" "key-a" "key-a"]
                          :clean-backup-id "backup-7"})
(def digest (apply str (repeat 64 "a")))

(deftest compromise-response-is-ordered-and-signed
  (let [calls (atom [])
        handler (fn [action _]
                  (swap! calls conj [(:action action) (:target action)])
                  {:ok? true :artifact-sha256 digest})
        handlers (zipmap (keys incident/action-order) (repeat handler))
        result (incident/execute! p (:secret signer) (incident/plan detection) handlers)]
    (is (= :recovered (:incident/status result)))
    (is (= [[:contain "inc-1"]
            [:revoke "key-a"] [:revoke "key-b"]
            [:rotate "key-a"] [:rotate "key-b"]
            [:restore "backup-7"] [:verify "inc-1"]]
           @calls))
    (is (every? #(incident/valid-receipt? p (:public signer) %)
                (:incident/receipts result)))))

(deftest failed-revocation-stops-before-rotation-or-restore
  (let [calls (atom [])
        handlers {:contain (fn [action _]
                             (swap! calls conj (:action action))
                             {:ok? true :artifact-sha256 digest})
                  :revoke (fn [action _]
                            (swap! calls conj (:action action))
                            {:ok? false})
                  :rotate (fn [_ _] (throw (ex-info "must not run" {})))
                  :restore (fn [_ _] (throw (ex-info "must not run" {})))
                  :verify (fn [_ _] (throw (ex-info "must not run" {})))}
        result (incident/execute! p (:secret signer) (incident/plan detection) handlers)]
    (is (= :blocked (:incident/status result)))
    (is (= [:contain :revoke] @calls))
    (is (= 1 (count (:incident/receipts result))))))

(deftest missing-authority-is-not-a-successful-no-op
  (testing "an absent isolation authority blocks before any receipt"
    (let [result (incident/execute! p (:secret signer) (incident/plan detection) {})]
      (is (= :missing-authority (:incident/reason result)))
      (is (empty? (:incident/receipts result))))))
