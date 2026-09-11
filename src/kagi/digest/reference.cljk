(ns kagi.digest.reference
  "SHA-256 through first-party `sha2.core` for `@noble/hashes` host substitution.

  Production paths keep `kagi.digest` / `@noble/hashes`. This namespace is the
  correctness / CI seam (ADR-2608301100), same ladder as `kagi.crypto.reference`."
  (:require [sha2.core :as sha2]))

(defn- u8-vec [^js u8] (vec (js/Array.from u8)))

(defn- vec-u8 [v] (js/Uint8Array.from (clj->js v)))

(defn sha256-bytes
  "bytes → 32 digest bytes via `org-nist-sha2`."
  [bs]
  (vec-u8 (sha2/sha256 (u8-vec bs))))

(defn sha256-utf8
  [s]
  (sha256-bytes (.encode (js/TextEncoder.) s)))
