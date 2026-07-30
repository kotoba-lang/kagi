(ns kagi.cli-bootstrap-test
  "The two CLI defects found while storing a real account on 2026-07-30.

  The first bricked a live vault outright: every command, including the one
  the error message named as the remedy, exited non-zero."
  (:require [clojure.test :refer [deftest is testing]]
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
