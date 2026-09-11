(ns kagi.key-registry-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.key-registry :as registry]))

(def base
  {:id "sign-7" :purpose :identity-signing :suite :authority-v1 :epoch 7
   :created-at "2026-07-18T00:00:00Z" :not-before "2026-07-18T00:00:00Z"
   :originator-not-after "2027-07-18T00:00:00Z" :custody-ref "keychain://sign/7"})

(deftest use-time-state-and-expiry-enforcement
  (let [pre (registry/key-record base)
        active (registry/transition pre :active "2026-07-18T00:00:00Z")
        retired (registry/transition active :decrypt-or-verify-only "2027-07-18T00:00:01Z")]
    (is (false? (registry/allowed-use? pre :sign "2026-07-18T00:00:00Z")))
    (is (registry/allowed-use? active :sign "2026-12-01T00:00:00Z"))
    (is (false? (registry/allowed-use? active :sign "2027-07-18T00:00:01Z")))
    (is (false? (registry/allowed-use? retired :sign "2027-07-18T00:00:01Z")))
    (is (registry/allowed-use? retired :verify "2030-01-01T00:00:00Z"))))

(deftest duplicate-active-key-fails-closed
  (let [a (registry/transition (registry/key-record base) :active "2026-07-18T00:00:00Z")
        b (registry/transition (registry/key-record (assoc base :id "sign-8" :epoch 8))
                               :active "2026-07-18T00:00:00Z")]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"multiple active keys"
                          (registry/current-key {"a" a "b" b} :identity-signing)))))
