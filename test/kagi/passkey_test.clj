(ns kagi.passkey-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.passkey :as passkey]
            [kagi.unlock :as unlock])
  (:import [java.util Base64]))

(defn- b64 [^bytes value]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) value))

(deftest browser-bridge-to-vmk-envelope
  (let [p (crypto/jvm-provider)
        vmk (crypto/rand-bytes p 32)
        prf (crypto/rand-bytes p 32)
        input {:rpId "vault.example" :credentialId (b64 (byte-array [1 2 3]))
               :prfSalt (b64 (crypto/rand-bytes p 32))
               :prfOutput (b64 prf) :secret true}
        consumed (passkey/consume-bridge-input input "vault.example")
        wrap (unlock/passkey-prf-wrap p vmk (:prf-output consumed)
                                      (select-keys consumed [:rp-id :credential-id :prf-salt]))]
    (is (= (:prfSalt input) (:prf-salt wrap)))
    (is (= (seq vmk)
           (seq (unlock/unlock-with-passkey-prf p wrap (:prf-output consumed)))))
    (is (not (contains? (dissoc consumed :prf-output) :prf-output)))
    (testing "RP substitution and truncated PRF output fail closed"
      (is (thrown? clojure.lang.ExceptionInfo
                   (passkey/consume-bridge-input input "evil.example")))
      (is (thrown? clojure.lang.ExceptionInfo
                   (passkey/consume-bridge-input (assoc input :prfOutput (b64 (byte-array [1])))
                                                 "vault.example"))))))
