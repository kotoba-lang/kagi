(ns kagi.persist-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.persist :as persist])
  (:import [java.nio.file Files]
           [java.nio.file.attribute PosixFilePermissions]))

(deftest atomic-save-roundtrip-and-restrictive-permissions
  (let [dir (Files/createTempDirectory "kagi-persist-test" (make-array java.nio.file.attribute.FileAttribute 0))
        path (str (.resolve dir "vault.edn"))
        value {:bytes (byte-array [1 2 3]) :nested {:epoch 7}}]
    (is (= value (persist/save! path value)))
    (is (= (seq (:bytes value)) (seq (:bytes (persist/load* path)))))
    (is (= {:epoch 7} (:nested (persist/load* path))))
    (try
      (is (= "rw-------"
             (PosixFilePermissions/toString (Files/getPosixFilePermissions
                                              (.resolve dir "vault.edn")
                                              (make-array java.nio.file.LinkOption 0)))))
      (catch UnsupportedOperationException _ (is true)))))

(deftest concurrent-saves-never-expose-partial-edn
  (let [dir (Files/createTempDirectory "kagi-persist-race" (make-array java.nio.file.attribute.FileAttribute 0))
        path (str (.resolve dir "vault.edn"))
        values (mapv (fn [n] {:writer n :payload (vec (repeat 500 n))}) (range 12))]
    (doall (pmap #(persist/save! path %) values))
    (is (some #{(persist/load* path)} values))
    (with-open [paths (Files/list dir)]
      (is (not-any? #(.startsWith (.getFileName %) ".kagi-persist-")
                    (iterator-seq (.iterator paths)))))))
