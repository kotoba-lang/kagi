(ns kagi.identity-store-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.secret-store :as ss]
            [kagi.native-key :as native-key]))

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

(deftest plaintext-identity-persistence-is-denied-by-default
  (let [p (crypto/jvm-provider)
        dir (doto (java.io.File/createTempFile "kagi-deny-identity" ".tmp")
              (.delete) (.mkdirs))
        path (str (java.io.File. dir "identity.edn"))]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"refusing to persist plaintext identity"
                          (identity/load-or-create-identity! path p)))
    (is (not (.exists (java.io.File. path))))))

(deftest legacy-plaintext-identity-is-denied-until-migration
  (let [p (crypto/jvm-provider)
        id (identity/generate-identity p)
        file (java.io.File/createTempFile "kagi-legacy-identity" ".edn")]
    (spit file (pr-str (select-keys id (into identity/secret-fields identity/public-fields))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"requires migration"
                          (identity/load-or-create-identity! (.getPath file) p)))
    (is (= (:did id)
           (:did (identity/load-or-create-identity!
                  (.getPath file) p {:allow-existing-plaintext? true}))))))

(deftest native-signing-migration-removes-exportable-keys-only-after-possession-test
  (let [p (crypto/jvm-provider)
        id (identity/generate-identity p)
        dir (doto (java.io.File/createTempFile "kagi-native-identity" ".tmp")
              (.delete) (.mkdirs))
        path (str (java.io.File. dir "identity.edn"))
        ref "keychain://com.junkawasaki.kagi/native-test"
        store (ss/mem-secret-store)
        public (identity/migrate-identity-secret! path id store ref)
        opaque (reify crypto/SigningHandle
                 (sign-hybrid [_ provider message]
                   (crypto/sign* provider (identity/sign-secret id) message))
                 (sign-ed25519 [_ _] (throw (ex-info "not used" {}))))
        opaque-kem (reify crypto/DecapsulationHandle
                     (decapsulate-hybrid [_ provider ciphertext]
                       (crypto/kem-decap provider (identity/kem-secret id) ciphertext)))
        native {:keystore :test :handle :test :kem-handle :kem-test}]
    (testing "failed token binding leaves the old exportable keys intact"
      (with-redefs [native-key/bound-signer (fn [& _] (throw (ex-info "wrong alias" {})))]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"wrong alias"
                              (identity/migrate-native-signing! path public store native))))
      (is (every? #(contains? (ss/get-edn store ref) %)
                  [:private-b64 :mldsa-private-b64])))
    (testing "successful binding and hybrid possession remove both signing encodings"
      (with-redefs [native-key/bound-signer (fn [& _] opaque)
                    native-key/bound-kem-recipient (fn [& _] opaque-kem)
                    native-key/metadata (fn [_] {:custody :non-exportable-native-handle
                                                 :keystore-id "test-token"
                                                 :aliases {:ed "ed" :mldsa "ml"}
                                                 :private-exported? false})
                    native-key/kem-metadata (fn [_] {:custody :non-exportable-native-handle
                                                     :keystore-id "test-token"
                                                     :aliases {:x25519 "x" :mlkem "kem"}
                                                     :private-exported? false})]
        (is (:migrated? (identity/migrate-native-signing! path public store native)))
        (is (not-any? #(contains? (ss/get-edn store ref) %)
                      [:private-b64 :mldsa-private-b64]))
        (is (nil? (:kem-secret (ss/get-edn store ref)))
            "exportable KEM custody is removed after its own possession test")
        (let [loaded (identity/load-or-create-identity!
                      path p {:secret-store store :native-signing native})]
          (is (satisfies? crypto/SigningHandle (identity/sign-secret loaded)))
          (is (satisfies? crypto/DecapsulationHandle (identity/kem-secret loaded)))
          (is (nil? (:private-key loaded))))))))
