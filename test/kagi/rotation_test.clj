(ns kagi.rotation-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.rotation :as rotation]))

(deftest normal-rotation-requires-old-and-new-hybrid-proofs
  (let [p (crypto/jvm-provider)
        old (crypto/sign-keypair p)
        new (crypto/sign-keypair p)
        event (rotation/new-event {:subject "did:key:owner" :purpose :authority
                                   :from-key "old" :to-key "new" :from-epoch 3
                                   :parents ["bafy-parent"]})
        signed (rotation/sign-normal p event (:secret old) (:secret new))]
    (is (rotation/valid-normal? p signed (:public old) (:public new)))
    (is (false? (rotation/valid-normal? p signed (:public new) (:public old))))
    (is (false? (rotation/valid-normal? p (assoc signed :rotation/to-epoch 9)
                                       (:public old) (:public new))))))

(deftest competing-children-are-quarantinable
  (let [base {:subject "did:key:owner" :purpose :kem :from-key "a" :from-epoch 1}
        a (rotation/new-event (assoc base :to-key "b"))
        b (rotation/new-event (assoc base :to-key "evil"))]
    (is (= #{(:rotation/id a) (:rotation/id b)}
           (set (map :rotation/id (rotation/competing-children [a b])))))))

(deftest dag-cbor-is-independent-of-map-insertion-order
  (let [fields [[:subject "did:key:owner"] [:purpose :authority]
                [:from-key "old"] [:to-key "new"] [:from-epoch 3]
                [:not-before "2026-07-18T00:00:00Z"]]
        a (rotation/new-event (into {} fields))
        b (rotation/new-event (into {} (reverse fields)))]
    (is (= (:rotation/id a) (:rotation/id b)))
    (is (= (seq (rotation/signing-bytes a))
           (seq (rotation/signing-bytes b))))))
