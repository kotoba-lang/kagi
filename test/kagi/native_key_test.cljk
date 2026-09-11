(ns kagi.native-key-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.native-key :as native-key])
  (:import [java.security KeyStore]))

(deftest native-handle-metadata-never-contains-private-material
  (let [h (native-key/handle "pkcs11:slot-1" "ed-current" "mldsa-current")
        m (native-key/metadata h)]
    (is (= :non-exportable-native-handle (:custody m)))
    (is (false? (:private-exported? m)))
    (is (not-any? #(re-find #"(?i)private|secret" (name %)) (keys (:aliases m))))))

(deftest missing-token-alias-fails-closed
  (let [ks (doto (KeyStore/getInstance "JCEKS") (.load nil nil))
        h (native-key/handle "memory-test" "missing-ed" "missing-ml")]
    (is (false? (native-key/native-keystore? ks)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"software keystore"
                          (native-key/sign ks h (.getBytes "x" "UTF-8"))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"software keystore"
                          (native-key/load-keystore "JCEKS" nil nil nil)))))
