(ns kagi.secret-store-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.secret-store :as ss]))

(deftest ref-parse-and-redaction
  (testing "secret refs parse without exposing full values in metadata"
    (is (= {:scheme "keychain"
            :body "com.junkawasaki.kagi/identity"
            :raw "keychain://com.junkawasaki.kagi/identity"}
           (ss/parse-ref "keychain://com.junkawasaki.kagi/identity")))
    (is (= "keychain://.../identity"
           (ss/redact-ref "keychain://com.junkawasaki.kagi/identity")))))

(deftest apple-keychain-store-shell-contract
  (testing "Apple Keychain provider uses generic-password commands and never logs secret metadata"
    (let [calls (atom [])
          store (ss/apple-keychain-store
                 (fn [& args]
                   (swap! calls conj (vec args))
                   (case (second args)
                     "add-generic-password" {:exit 0 :out "" :err ""}
                     "find-generic-password" {:exit 0 :out "secret-value\n" :err ""}
                     "delete-generic-password" {:exit 0 :out "" :err ""}
                     {:exit 9 :out "" :err "unexpected"})))]
      (is (= {:ok? true :ref "keychain://.../work" :provider :apple-keychain}
             (ss/put-secret! store "keychain://manimani.gmail/work" "secret-value" {})))
      (is (= "secret-value"
             (ss/get-secret store "keychain://manimani.gmail/work" {})))
      (is (= {:ok? true :ref "keychain://.../work" :provider :apple-keychain}
             (ss/delete-secret! store "keychain://manimani.gmail/work" {})))
      (is (= ["security" "add-generic-password" "-U" "-s" "manimani.gmail" "-a" "work" "-w" "secret-value"]
             (first @calls)))
      (is (= :os-keychain
             (:custody (ss/metadata store "keychain://manimani.gmail/work")))))))

(deftest memory-secret-store-roundtrip
  (testing "test provider supports EDN identity payloads"
    (let [store (ss/mem-secret-store)
          ref "keychain://test/identity"
          payload {:private-b64 "p" :mldsa-private-b64 "m"}]
      (ss/put-edn! store ref payload)
      (is (= payload (ss/get-edn store ref)))
      (is (true? (ss/exists? store ref))))))
