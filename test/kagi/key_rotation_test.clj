(ns kagi.key-rotation-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.key-rotation :as key-rotation]
            [kagi.rotation-store :as rotation-store]
            [kagi.secret-store :as secret-store]))

(defn- store []
  (let [dir (doto (java.io.File/createTempFile "key-rotation" ".tmp")
              (.delete) (.mkdirs))]
    (rotation-store/file-store (str (java.io.File. dir "dag.edn")))))

(deftest authority-worker-dual-signs-before-admission
  (let [p (crypto/jvm-provider)
        old (identity/generate-identity p)
        plan (key-rotation/prepare-authority
              p old {:custody-ref "pkcs11://slot/new-sign"})
        current {:subject (:authority-id old) :purpose :authority
                 :key-id (get-in old [:signing-key :key/id])
                 :epoch (get-in old [:signing-key :key/epoch]) :parent nil}
        dag (store)]
    (is (not= (:did old) (get-in plan [:next :did])))
    (is (= 1 (get-in plan [:next :signing-key :key/epoch])))
    (is (= :decrypt-or-verify-only
           (get-in plan [:next :retired-signing-epochs 0 :key :key/state])))
    (is (get-in (key-rotation/admit-authority! dag p plan current)
                [:admission :stored?]))
    (is (= 1 (count (rotation-store/events dag))))))

(deftest kem-worker-proves-possession-and-is-authority-certified
  (let [p (crypto/jvm-provider)
        old (identity/generate-identity p)
        plan (key-rotation/prepare-kem p old {:custody-ref "pkcs11://slot/new-kem"})
        next (:next plan)
        current {:subject (:authority-id old) :purpose :recipient-kem
                 :key-id (get-in old [:kem-key :key/id])
                 :epoch (get-in old [:kem-key :key/epoch]) :parent nil}
        dag (store)
        dek (crypto/rand-bytes p 32)
        envelope (crypto/share-dek p (identity/kem-public next) dek)]
    (is (= 1 (get-in next [:kem-key :key/epoch])))
    (is (= :decrypt-or-verify-only
           (get-in next [:retired-kem-epochs 0 :key :key/state])))
    (is (get-in (key-rotation/admit-kem! dag p plan current)
                [:admission :stored?]))
    (is (java.util.Arrays/equals ^bytes dek
                                ^bytes (crypto/accept-share p (identity/kem-secret next)
                                                           envelope)))))

(deftest admitted-identity-switch-is-secret-backed-and-crash-recoverable
  (let [p (crypto/jvm-provider)
        secret-store (secret-store/mem-secret-store)
        old-ref "mem://identity/epoch-0"
        new-ref "mem://identity/epoch-1"
        old0 (identity/generate-identity p)
        old (assoc old0 :secret-ref old-ref)
        _ (secret-store/put-edn! secret-store old-ref
                                 (select-keys old identity/secret-fields))
        plan0 (key-rotation/prepare-kem p old {:custody-ref new-ref})
        current {:subject (:authority-id old) :purpose :recipient-kem
                 :key-id (get-in old [:kem-key :key/id])
                 :epoch 0 :parent nil}
        plan (key-rotation/admit-kem! (store) p plan0 current)
        dir (doto (java.io.File/createTempFile "identity-commit" ".tmp")
              (.delete) (.mkdirs))
        path (str (java.io.File. dir "identity.edn"))
        result (key-rotation/commit-secret-backed! path secret-store new-ref plan)
        loaded (identity/load-or-create-identity!
                path p {:secret-store secret-store :secret-ref new-ref})]
    (is (:committed? result))
    (is (secret-store/exists? secret-store old-ref)
        "old epoch is retained for the bounded rollback/decrypt window")
    (is (= 1 (get-in loaded [:kem-key :key/epoch])))
    (is (= 1 (count (:retired-kem-epochs loaded))))
    (is (not (.exists (java.io.File. (str path ".rotation.pending.edn")))))))
