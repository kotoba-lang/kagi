(ns kagi.recovery-drill-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.secret-store :as secret-store]
            [kagi.unlock :as unlock]))

(deftest lost-device-secret-falls-back-to-passphrase-recovery
  (testing "loss of the device key neither unlocks the VMK nor destroys recovery"
    (let [p (crypto/jvm-provider)
          vmk (crypto/rand-bytes p 32)
          passphrase (.getBytes "synthetic recovery phrase" "UTF-8")
          pass-salt (crypto/rand-bytes p 16)
          pass-kek (crypto/hkdf p passphrase pass-salt
                                (.getBytes "kagi/recovery-drill/v1" "UTF-8") 32)
          pass-nonce (crypto/rand-bytes p 12)
          pass-wrap (crypto/aead-seal p pass-kek pass-nonce vmk
                                      (.getBytes "passphrase" "UTF-8"))
          device-store (secret-store/mem-secret-store)
          ref "memory://lost-device"
          device-secret (unlock/new-device-secret p)
          device-wrap (unlock/wrap-vmk p vmk :os-keychain
                                       (.getBytes ^String device-secret "UTF-8") {:ref ref})
          meta {:salt pass-salt :nonce pass-nonce :wrapped pass-wrap
                :unlock/wraps [(assoc device-wrap :ref ref)]}]
      (secret-store/put-secret! device-store ref device-secret {})
      (with-redefs [secret-store/store-for-ref (constantly device-store)]
        (is (= (seq vmk) (seq (unlock/unlock-with-os-keychain p meta)))))
      (secret-store/delete-secret! device-store ref {})
      (with-redefs [secret-store/store-for-ref (constantly device-store)]
        (is (nil? (unlock/unlock-with-os-keychain p meta))))
      (is (= (seq vmk)
             (seq (crypto/aead-open p pass-kek (:nonce meta) (:wrapped meta)
                                    (.getBytes "passphrase" "UTF-8"))))))))
