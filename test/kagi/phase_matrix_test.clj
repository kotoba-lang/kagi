(ns kagi.phase-matrix-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.phase :as phase]))

(def phases [-1 0 1 2 3 4])
(def operations
  [:item/create :item/update :item/rotate :share/grant :share/revoke
   :item/reveal :item/list :unknown/op])
(def dispositions [:hold :commit :escalate :unknown/disposition])

(defn expected [phase-value op disposition]
  (let [level (if (<= 0 phase-value 3) phase-value 1)
        write? (contains? #{:item/create :item/update :item/rotate
                            :share/grant :share/revoke} op)
        read? (contains? #{:item/reveal :item/list} op)
        auto? (or (= level 3)
                  (contains? #{:item/create :item/update} op)
                  (and (= level 2) (= op :share/grant)))]
    (cond
      (= disposition :hold) {:disposition :hold :reason nil}
      read? {:disposition disposition :reason nil}
      (or (= level 0) (not write?)) {:disposition :hold :reason :phase-disabled}
      (and (= disposition :commit) (not auto?))
      {:disposition :escalate :reason :phase-approval}
      :else {:disposition disposition :reason nil})))

(deftest exhaustive-phase-gate-matrix
  (doseq [phase-value phases op operations disposition dispositions]
    (is (= (expected phase-value op disposition)
           (phase/gate phase-value {:op op} disposition))
        (str [phase-value op disposition]))))
