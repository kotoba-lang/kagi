(ns kagi.digest.reference-test
  "`kagi.digest.reference` agrees with `@noble/hashes` SHA-256 (same import
  path as `kagi.crypto.noble`).

  Run from a west checkout (sibling `org-nist-sha2`):
    npm run test:reference-hashes"
  (:require [cljs.test :refer [deftest is testing run-tests]]
            [kagi.digest.reference :as reference]
            ["@noble/hashes/sha2.js" :refer [sha256]]))

(defn- bytes= [a b]
  (and (= (.-length a) (.-length b))
       (every? #(= (aget a %) (aget b %)) (range (.-length a)))))

(deftest reference-sha256-matches-noble
  (testing "empty input"
    (let [empty (js/Uint8Array. 0)]
      (is (bytes= (sha256 empty)
                  (reference/sha256-bytes empty)))))
  (testing "utf8 string"
    (is (bytes= (sha256 (.encode (js/TextEncoder.) "vault ledger anchor"))
                (reference/sha256-utf8 "vault ledger anchor"))))
  (testing "random block"
    (let [bs (js/crypto.getRandomValues (js/Uint8Array. 128))]
      (is (bytes= (sha256 bs)
                  (reference/sha256-bytes bs))))))

(defn -main [& _]
  (run-tests 'kagi.digest.reference-test))
