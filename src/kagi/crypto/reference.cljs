(ns kagi.crypto.reference
  "Browser `Provider` that routes AES-256-GCM through first-party `aes.gcm`
  while keeping KEM, signatures, HKDF, and Argon2id on `kagi.crypto.noble`.

  This is the **correctness / CI** path for `@noble/ciphers` substitution
  (ADR-2608301100): kagi uses `@noble/ciphers/aes.js` only for GCM — the
  portable substitute is `org-nist-aes`, not ChaCha20. Production hot paths
  should keep `noble-provider`; do not delete `@noble/ciphers` from
  package.json while noble still owns AEAD there."
  (:require [kagi.crypto :as c]
            [kagi.crypto.noble :as noble]
            [aes.gcm :as gcm]))

(defn- u8->vec [^js u8]
  (vec (js/Array.from u8)))

(defn- vec->u8 [v]
  (js/Uint8Array.from (clj->js v)))

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
      (hkdf [_ ikm salt info len] (c/hkdf n ikm salt info len))
      (argon2id [_ pass salt params] (c/argon2id n pass salt params)))))
