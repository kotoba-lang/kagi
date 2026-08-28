(ns kagi.digest
  "SHA-256, portably.

  `kagi.crypto/sha256` lives inside that namespace's JVM-only half, and the
  `Provider` protocol has no digest method — so anything that needs a hash
  WITHOUT a provider in hand (a ledger link, a proof-of-work check, an object
  key) had nowhere portable to get one.

  Deliberately not added to `Provider`: a digest is not a key operation, every
  runtime has one, and widening the protocol would oblige both implementations
  and any future one to carry a method whose behaviour cannot vary.

  The `:cljs` branch takes `@noble/hashes`, which this repo already depends on
  for `kagi.crypto.noble` — the same library, so a hash computed in a browser
  and one computed on the JVM are the same bytes."
  (:require [kagi.crypto :as crypto]
            #?(:cljs ["@noble/hashes/sha2" :refer [sha256]])))

(defn sha256-bytes
  "bytes → 32 digest bytes."
  [bs]
  #?(:clj (.digest (java.security.MessageDigest/getInstance "SHA-256") ^bytes bs)
     :cljs (sha256 bs)))

(defn sha256-utf8
  "string → 32 digest bytes. The UTF-8 step is `crypto/utf8-bytes` so the two
  runtimes agree about what the bytes of a string are."
  [s]
  (sha256-bytes (crypto/utf8-bytes (str s))))
