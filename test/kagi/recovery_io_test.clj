(ns kagi.recovery-io-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.recovery :as recovery]
            [kagi.recovery-io :as recovery-io]))

(deftest owner-only-exclusive-share-ceremony
  (let [p (crypto/jvm-provider)
        vmk (crypto/rand-bytes p 32)
        dir (str (java.nio.file.Files/createTempDirectory
                  "kagi-recovery" (make-array java.nio.file.attribute.FileAttribute 0)))
        written (recovery-io/write-shares! dir (recovery/split p vmk 2 3))
        files (mapv :path written)]
    (is (= 3 (count written)))
    (is (every? recovery-io/owner-only? files))
    (is (every? #(not (contains? % :recovery/value)) written))
    (is (= (seq vmk) (seq (recovery-io/combine-files (take 2 files)))))
    (testing "rerun never overwrites an existing recovery share"
      (is (thrown? java.nio.file.FileAlreadyExistsException
                   (recovery-io/write-shares! dir (recovery/split p vmk 2 3)))))))
