(ns kagi.identity-store-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.secret-store :as ss]))

(deftest identity-secret-store-migration
  (testing "identity secret key material can move out of identity.edn"
    (let [p (crypto/jvm-provider)
          id (identity/generate-identity p)
          dir (doto (java.io.File/createTempFile "kagi-identity" ".tmp")
                (.delete)
                (.mkdirs))
          path (str (java.io.File. dir "identity.edn"))
          ref "keychain://com.junkawasaki.kagi/test-identity"
          store (ss/mem-secret-store)]
      (identity/migrate-identity-secret! path id store ref)
      (let [public-file (read-string (slurp path))]
        (is (= ref (:secret-ref public-file)))
        (is (nil? (:private-b64 public-file)))
        (is (nil? (:mldsa-private-b64 public-file)))
        (is (nil? (:kem-secret public-file)))
        (is (= (:public-b64 id) (:public-b64 public-file)))
        (is (= (select-keys id identity/secret-fields)
               (ss/get-edn store ref))))
      (let [loaded (identity/load-or-create-identity! path p {:secret-store store})]
        (is (= (:did id) (:did loaded)))
        (is (= (:private-b64 id) (:private-b64 loaded)))
        (is (= (:kem-secret id) (:kem-secret loaded)))))))
