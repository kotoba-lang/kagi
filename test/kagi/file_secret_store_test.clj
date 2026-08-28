(ns kagi.file-secret-store-test
  "The `file://` provider exists because the Keychain one cannot be used under
  launchd. It is the weaker custody, so the properties that make it acceptable
  have to be checked rather than assumed."
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.secret-store :as secret-store])
  (:import [java.nio.file Files LinkOption Paths]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

(defn- tmp-dir []
  (str (.toAbsolutePath (Files/createTempDirectory "kagi-file-store" (make-array FileAttribute 0)))))

(defn- path-of [s] (Paths/get s (make-array String 0)))

(deftest a-stored-secret-round-trips
  (let [ref (str "file://" (tmp-dir) "/nested/secret")
        st (secret-store/store-for-ref ref)]
    (is (= :file (:provider (secret-store/put-secret! st ref "s3cr3t" {}))))
    (is (= "s3cr3t" (secret-store/get-secret st ref {})))
    (is (secret-store/exists? st ref))
    (secret-store/delete-secret! st ref {})
    (is (not (secret-store/exists? st ref)))))

(deftest the-file-lands-mode-600-not-chmodded-afterwards
  (testing "作られた瞬間から 600 —— 書いてから chmod する窓が無い"
    (let [ref (str "file://" (tmp-dir) "/k")
          st (secret-store/store-for-ref ref)]
      (secret-store/put-secret! st ref "x" {})
      (is (= "rw-------"
             (PosixFilePermissions/toString
              (Files/getPosixFilePermissions (path-of (subs ref 7))
                                             (make-array LinkOption 0))))))))

(deftest a-loose-secret-is-refused-rather-than-read
  (testing "他人が読めるファイルは値を返さない(警告して返す、をしない)"
    (let [ref (str "file://" (tmp-dir) "/k")
          st (secret-store/store-for-ref ref)]
      (secret-store/put-secret! st ref "x" {})
      (Files/setPosixFilePermissions (path-of (subs ref 7))
                                     (PosixFilePermissions/fromString "rw-r--r--"))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"mode 600"
                            (secret-store/get-secret st ref {}))))))

(deftest a-relative-path-is-refused
  (testing "相対パスは、プロセスの作業ディレクトリ次第で別の場所になる"
    (let [st (secret-store/file-secret-store)]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"absolute path"
                            (secret-store/get-secret st "file://relative/key" {}))))))

(deftest metadata-says-which-custody-this-is
  (testing "os-keychain と一目で区別できる — どの principal が盗みやすいかが見える"
    (let [ref (str "file://" (tmp-dir) "/k")
          st (secret-store/store-for-ref ref)]
      (is (= :file-0600 (:custody (secret-store/metadata st ref))))
      (is (true? (:secret-readable? (secret-store/metadata st ref))))
      (is (= :os-keychain
             (:custody (secret-store/metadata (secret-store/apple-keychain-store)
                                              "keychain://svc/acct")))))))

(deftest the-ref-is-redacted-for-display
  (is (= "file://.../k" (secret-store/redact-ref "file:///tmp/whatever/k"))))
