(ns kagi.crypto.reference
  "Browser `Provider` that routes AES-256-GCM through first-party `aes.gcm`
  and HKDF-SHA256 through `sha2.core`, while keeping KEM, signatures, and
  Argon2id on `kagi.crypto.noble`.

  This is the **correctness / CI** path for `@noble/ciphers` and
  `@noble/hashes` host substitution (ADR-2608301100). Production hot paths
  should keep `noble-provider`; do not delete `@noble/*` from package.json
  while noble still owns those primitives on-path."
  (:require [kagi.crypto :as c]
            [kagi.crypto.noble :as noble]
            [aes.gcm :as gcm]
            [sha2.core :as sha2]))

(defn- u8->vec [^js u8]
  (vec (js/Array.from u8)))

(defn- vec->u8 [v]
  (js/Uint8Array.from (clj->js v)))

(defn- hmac-sha256 [^js key ^js message]
  (vec->u8 (sha2/hmac-sha256 (u8->vec key) (u8->vec message))))

(defn- hkdf-sha256-ref
  "RFC 5869 HKDF-SHA256 via `sha2.core`, matching `kagi.crypto.noble` salt rules."
  [^js ikm ^js salt ^js info len]
  (when-not (and (int? len) (pos? len) (<= len (* 255 32)))
    (throw (ex-info "invalid HKDF-SHA256 output length"
                    {:length len :maximum (* 255 32)})))
  (let [salt' (if (zero? (.-length salt)) (js/Uint8Array. 32) salt)
        prk (hmac-sha256 salt' ikm)
        hash-len 32
        n (js/Math.ceil (/ len hash-len))
        all (loop [i 1 prev [] acc []]
              (if (> i n)
                acc
                (let [input (into (vec prev) (concat (u8->vec info) [i]))
                      t (hmac-sha256 prk (vec->u8 input))]
                  (recur (inc i) (u8->vec t) (conj acc t)))))]
    (.slice (vec->u8 (apply concat (map u8->vec all))) 0 len)))

(defn- aes-gcm-seal [key nonce pt aad]
  (when-not (= 32 (.-length key))
    (throw (ex-info "AES-256-GCM requires a 32-byte key" {:length (.-length key)})))
  (when-not (= 12 (.-length nonce))
    (throw (ex-info "AES-GCM requires a 96-bit nonce" {:length (.-length nonce)})))
  (vec->u8 (gcm/seal! (u8->vec key) (u8->vec nonce) (u8->vec aad) (u8->vec pt))))

(defn- aes-gcm-open [key nonce ct aad]
  (when-not (= 32 (.-length key))
    (throw (ex-info "AES-256-GCM requires a 32-byte key" {:length (.-length key)})))
  (when-not (= 12 (.-length nonce))
    (throw (ex-info "AES-GCM requires a 96-bit nonce" {:length (.-length nonce)})))
  (vec->u8 (gcm/open! (u8->vec key) (u8->vec nonce) (u8->vec aad) (u8->vec ct))))

(defn reference-provider
  "`kagi.crypto/Provider` with AEAD via `aes.gcm` and everything else via noble."
  []
  (let [n (noble/noble-provider)]
    (reify c/Provider
      (rand-bytes [_ len] (c/rand-bytes n len))
      (kem-keypair [_] (c/kem-keypair n))
      (kem-encap [_ pk] (c/kem-encap n pk))
      (kem-decap [_ sk ct] (c/kem-decap n sk ct))
      (sign-keypair [_] (c/sign-keypair n))
      (sign* [_ sk msg] (c/sign* n sk msg))
      (verify* [_ pk msg sig] (c/verify* n pk msg sig))
      (aead-seal [_ key nonce pt aad] (aes-gcm-seal key nonce pt aad))
      (aead-open [_ key nonce ct aad] (aes-gcm-open key nonce ct aad))
      (hkdf [_ ikm salt info len] (hkdf-sha256-ref ikm salt info len))
      (argon2id [_ pass salt params] (c/argon2id n pass salt params)))))
