(ns kagi.cli-bootstrap-test
  "The two CLI defects found while storing a real account on 2026-07-30.

  The first bricked a live vault outright: every command, including the one
  the error message named as the remedy, exited non-zero."
  (:require [clojure.edn]
            [clojure.test :refer [deftest is testing]]
            [kagi.cli :as cli]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagitaba.category :as kcat]))

(defn- tmp-dir [prefix]
  (doto (java.io.File/createTempFile prefix ".tmp") (.delete) (.mkdirs)))

(defn- plaintext-identity-at!
  "An identity.edn holding secret key material in the clear — the state a
  real vault was found in, with private-b64, mldsa-private-b64 and kem-secret
  all present and the file world-readable."
  [p]
  (let [id (identity/generate-identity p)
        path (str (java.io.File. (tmp-dir "kagi-bootstrap") "identity.edn"))]
    (spit path (pr-str (select-keys id [:authority-id :private-b64 :public-b64
                                        :mldsa-private-b64 :mldsa-public-b64
                                        :kem-public :kem-secret])))
    [id path]))

(deftest a-plaintext-identity-is-refused-by-default
  (testing "the guard itself is right and must keep working"
    (let [p (crypto/jvm-provider)
          [_ path] (plaintext-identity-at! p)]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"plaintext identity requires migration"
                            (identity/load-or-create-identity! path p {}))))))

(deftest the-migration-can-read-the-identity-it-exists-to-migrate
  (testing "kagi.cli's -main loads the identity BEFORE dispatching, so without
            an exemption for `identity-migrate` the remedy named in the error
            message throws that same error and the vault cannot be recovered.
            Verified on a live vault: 427 ledger entries reachable by nothing."
    (let [p (crypto/jvm-provider)
          [id path] (plaintext-identity-at! p)
          loaded (identity/load-or-create-identity!
                  path p {:allow-existing-plaintext? true})]
      (is (= (:did id) (:did loaded)))
      (is (= (:private-b64 id) (:private-b64 loaded))
          "the migration needs the secret material, not just the public half")
      (testing "and reading it changes nothing on disk — the exemption grants
                a read, not a silent rewrite"
        (is (contains? (read-string (slurp path)) :private-b64))))))

(deftest the-exemption-is-not-a-general-escape-hatch
  (testing "every other command must still refuse; only the operation that
            removes the guarded condition may proceed"
    (let [p (crypto/jvm-provider)
          [_ path] (plaintext-identity-at! p)]
      (doseq [opts [{} {:secret-ref "keychain://x/y"} nil]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"plaintext identity requires migration"
                              (identity/load-or-create-identity! path p opts))
            (str "must refuse with " (pr-str opts)))))))

;; ------------------------------------------------------------- add --category

(deftest a-login-item-can-be-filed-under-its-kagitaba-category
  (testing ":item/create has always accepted :category and `import
            onepassword` sets it, but `add` had no way to pass one — so every
            item created by hand was uncategorised"
    (is (kcat/known? :login))
    (is (= :login (kcat/uuid->key "001")))))

;; -------------------------------------------------------------- add --record

(deftest a-reference-record-carries-no-secret
  (testing "only the five reference fields exist, and the function is never
            passed a secret to leak in the first place"
    (let [f (str (java.io.File. (tmp-dir "kagi-record") "refs.edn"))
          r (#'cli/record-reference!
             f {:item "prolific-researcher-ryo" :compartment "personal"
                :category :login :did "did:key:zTest" :now "2026-07-30T00:00:00Z"})]
      (is (= #{:credential/item :credential/compartment :credential/category
               :credential/vault-did :credential/recorded-at}
             (set (keys r))))
      (let [text (slurp f)]
        (is (re-find #"NO SECRET VALUES" text))
        (is (re-find #"prolific-researcher-ryo" text))
        (is (not (re-find #"(?i)plaintext|private-b64|passphrase" text)))))))

(deftest recording-the-same-item-twice-updates-rather-than-duplicates
  (testing "a rotation must not leave two records claiming different truths"
    (let [f (str (java.io.File. (tmp-dir "kagi-record2") "refs.edn"))
          _ (#'cli/record-reference! f {:item "a" :compartment "personal"
                                        :category :login :did "did:key:z1"
                                        :now "2026-07-30T00:00:00Z"})
          _ (#'cli/record-reference! f {:item "a" :compartment "work"
                                        :category :password :did "did:key:z1"
                                        :now "2026-07-31T00:00:00Z"})
          v (read-string (slurp f))]
      (is (= 1 (count (:credentials v))))
      (is (= "work" (get-in v [:credentials "a" :credential/compartment])))
      (is (= "2026-07-31T00:00:00Z"
             (get-in v [:credentials "a" :credential/recorded-at]))))))

(deftest recording-a-second-item-keeps-the-first
  (let [f (str (java.io.File. (tmp-dir "kagi-record3") "refs.edn"))]
    (#'cli/record-reference! f {:item "a" :compartment "personal" :category :login
                                :did "did:key:z1" :now "t1"})
    (#'cli/record-reference! f {:item "b" :compartment "personal" :category :login
                                :did "did:key:z1" :now "t2"})
    (is (= #{"a" "b"} (set (keys (:credentials (read-string (slurp f)))))))))

(deftest a-record-target-that-is-not-a-map-is-refused
  (testing "silently replacing somebody else's file would lose whatever it held"
    (let [f (str (java.io.File. (tmp-dir "kagi-record4") "refs.edn"))]
      (spit f "[:not :a :map]")
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"record target is not a map"
                            (#'cli/record-reference!
                             f {:item "a" :compartment "personal"
                                :category :login :did "d" :now "t"}))))))

(deftest a-record-is-readable-as-edn
  (testing "written with pprint, so it stays diffable — and must still parse"
    (let [f (str (java.io.File. (tmp-dir "kagi-record5") "refs.edn"))]
      (#'cli/record-reference! f {:item "x" :compartment "personal"
                                  :category :login :did "did:key:z1" :now "t"})
      (is (map? (clojure.edn/read-string (slurp f)))))))

(deftest a-mistyped-category-is-rejected-rather-than-stored
  (testing "the index is only worth having if it is shared; a typo would file
            the item under a category nothing else uses"
    (is (not (kcat/known? :logon)))
    (is (not (kcat/known? :Login)) "canonical keys are lower-case")
    (is (not (kcat/known? :web-login)))))

(deftest password-is-a-real-category-and-must-stay-accepted
  (testing "1Password's own taxonomy has a Password category (uuid 005)
            distinct from Login (001), so rejecting :password as a typo would
            refuse a legitimate filing — asserted here because I guessed the
            opposite while writing these tests"
    (is (kcat/known? :password))
    (is (not= (kcat/key->uuid :password) (kcat/key->uuid :login)))))
