(ns kagi.digest-noble-test
  "`kagi.digest` actually loads, and hashes what SHA-256 hashes.

  The namespace's own docstring says a hash computed in a browser and one
  computed on the JVM are the same bytes. Nothing executed that: the JVM half
  is covered by `kagi.digest.reference-test` (which takes SHA-256 from
  org-nist-sha2, not from noble), so the `:cljs` branch's import was never
  loaded by a test. It was wrong — `@noble/hashes` v2 exports `./sha2.js` and
  the require asked for `./sha2` — and every ClojureScript consumer of
  `kagi.ledger`, which is every chain check outside the JVM, failed at import
  time with `Package subpath './sha2' is not defined by exports`.

  This test loads the namespace, which is most of the point, and then checks
  the canonical vector so a future edit cannot satisfy it with a stub.

  実行:
    npm install
    npx nbb --classpath src:test -m kagi.digest-noble-test"
  (:require [cljs.test :refer [deftest is run-tests]]
            [kagi.digest :as digest]))

(defn- hex [bs]
  (apply str (map #(.padStart (.toString % 16) 2 "0") (array-seq bs))))

(deftest sha256-of-abc
  ;; FIPS 180-4 / the most-published SHA-256 vector there is.
  (is (= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
         (hex (digest/sha256-utf8 "abc")))))

(deftest sha256-of-the-empty-string
  (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
         (hex (digest/sha256-utf8 "")))))

(deftest digest-length-is-32-bytes
  (is (= 32 (.-length (digest/sha256-utf8 "kagi")))))

(defn -main [& _]
  ;; ns を明示する。省略すると nbb の `-m` 起動では *current* ns(= `user`)を
  ;; 走らせてしまい、0 tests でも緑になる。
  (run-tests 'kagi.digest-noble-test))
