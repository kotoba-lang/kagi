(ns kagi.rotation-main-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.rotation-main :as main]
            [kagi.cli :as cli]))

(deftest scheduler-interval-is-bounded-and-fails-closed
  (is (= 3600 (main/interval-seconds nil)))
  (is (= 900 (main/interval-seconds "900")))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"too short"
                        (main/interval-seconds "59")))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"invalid"
                        (main/interval-seconds "not-a-number"))))

(deftest due-inventory-covers-every-key-class
  (let [old "2020-01-01T00:00:00Z"
        key (fn [id purpose epoch]
              {:key/id id :key/purpose purpose :key/epoch epoch
               :key/state :active :key/created-at old})
        id {:signing-key (key "sign-1" :identity-signing 1)
            :kem-key (key "kem-1" :recipient-kem 2)}
        data {:items {"item-1" {:item/id "item-1" :item/version 3
                                :item/key-created-at old}}
              :meta {:vmk-key (key "vmk-1" :vmk 4)
                     :unlock/wraps [(merge (key "unlock-1" :device-unlock 5)
                                           {:method :os-keychain})]}}
        records (cli/all-schedule-records id data)]
    (is (= #{:item-dek :identity-signing :recipient-kem :vmk :device-unlock}
           (set (map :key/class records))))
    (is (= 5 (count records)))))
