(ns kagi.pubkey
  "Portable operations on PUBLIC keys — the ones that need no provider and no
  private material.

  Two of them, and both blocked the agent API from running anywhere but a JVM:

  - **did:key from an encoded Ed25519 public key.** `kagi.identity` derives it
    through `java.security.KeyFactory`, which is the right thing when you are
    also holding the private half. A server that only checks an enrollment
    request holds a base64 SPKI and nothing else, and the derivation it needs
    is: drop the fixed 12-byte prefix, hand the 32 raw bytes to
    `ed25519/did-key-from-pub`.
  - **A fingerprint.** `kagi.device` computes one for a human to read aloud;
    the same value has to be checkable where the request arrives.

  Neither is a second implementation of anything: the did:key alphabet and
  multicodec live in `org-ietf-ed25519` (already `.cljc`), and the digest in
  `kagi.digest`."
  (:require [clojure.string :as str]
            [ed25519.core :as ed25519]
            [kagi.b64 :as b64]
            [kagi.digest :as digest]))

(def ^:const ed25519-spki-prefix-length
  "`302a300506032b6570032100` — the X.509 SubjectPublicKeyInfo header the JDK
  emits for Ed25519, which `kagi.crypto.noble/wrap-der` reproduces byte for
  byte so the two runtimes exchange the same encoding. Fixed length, so the
  raw key is the last 32 bytes and this is a slice rather than a DER parser."
  12)

(defn raw-ed25519-pub
  "Encoded Ed25519 public key (SPKI bytes) → the 32 raw bytes.

  Throws on a length that is not prefix+32: a silently truncated key would
  derive a did:key that belongs to nobody, and enrollment would succeed and
  then refuse every operation for a reason nothing states."
  [bs]
  (let [n (count bs)
        expected (+ ed25519-spki-prefix-length 32)]
    (cond
      (= n 32) (vec bs)                       ; already raw
      (= n expected) (vec (drop ed25519-spki-prefix-length bs))
      :else (throw (ex-info "not an Ed25519 public key encoding"
                            {:length n :expected #{32 expected}})))))

(defn did-key-from-spki-b64
  "base64 SPKI (what an enrollment request carries) → `did:key:z…`, or nil when
  the value is not one."
  [b64-string]
  (when-not (str/blank? (str b64-string))
    (try
      (ed25519/did-key-from-pub
       (let [raw (raw-ed25519-pub (b64/decode b64-string))]
         #?(:clj (byte-array (map unchecked-byte raw))
            :cljs (js/Uint8Array. (into-array raw)))))
      (catch #?(:clj Exception :cljs :default) _ nil))))

(defn fingerprint
  "A short, human-readable digest of a PUBLIC key.

  Six groups of four base32-ish characters, because the operator has to read
  this aloud or retype it and a 64-char hex string invites 'looks about right'.
  Derived from the full public key, so substituting the key changes it.

  Moved out of `kagi.device` unchanged — the value has to be computable where
  the request is checked, not only where it was printed."
  [public-key]
  ;; base64 the byte values first, exactly as `kagi.device/b64-map` did. The
  ;; same key reaches this as raw bytes (the machine that generated it) and as
  ;; base64 (the request that carries it), and a fingerprint that differed
  ;; between those two would fail the one check it exists to perform.
  (let [host-bytes? (fn [v] #?(:clj (bytes? v) :cljs (instance? js/Uint8Array v)))
        normalized (into {} (map (fn [[k v]] [k (if (host-bytes? v) (b64/encode v) v)]))
                         public-key)
        material (digest/sha256-utf8 (pr-str normalized))
        alphabet "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  ; no I/O/0/1
        idx (fn [b] (mod (bit-and (int b) 0xff) 32))
        chars (map #(nth alphabet (idx %))
                   (take 24 #?(:clj (seq material) :cljs (array-seq material))))]
    (->> chars (partition 4) (map #(apply str %)) (str/join "-"))))
