(ns kagi.crypto
  "★ kagi の対量子(PQC)暗号コア(JVM)。

  方針(ADR-2606272330): 古典を捨てず PQC を **加法的(hybrid)** に重ねる。両方が破られない
  限り安全。プリミティブは `Provider` プロトコル越しにのみ呼び、実装を差し替えてもコアは
  不変に保つ(`:db-api` seam と同型)。

  jvm-provider の実装基盤(probe で確認):
    - ML-KEM-768 : **JDK 24 標準**(JEP 496, FIPS 203)。`KeyPairGenerator/KEM \"ML-KEM-768\"`。
    - ML-DSA-65  : **JDK 24 標準**(JEP 497, FIPS 204)。`Signature \"ML-DSA-65\"`。
    - Ed25519 / X25519 / AES-256-GCM / HMAC : JDK 標準。
    - Argon2id   : BouncyCastle の実 Argon2id。利用不能なら fail closed。
  (CLJS/WASM は kotoba-crypto Rust を束ねた別ファイルの cljs provider で同 Protocol を実装。)

  hybrid 構成:
    - KEM     : X25519(ECDH) + ML-KEM-768。combiner = HKDF-SHA256(ss_x ‖ ss_pq, transcript)。
    - 署名     : Ed25519 + ML-DSA-65。連結し **両方 verify** で有効。
    - 対称     : AES-256-GCM(AAD=item-cid)。Grover 後も 128-bit 相当。
    - unlock  : Argon2id + passkey PRF(WebAuthn hmac-secret)。"
  (:import [java.security KeyPairGenerator KeyFactory Signature SecureRandom MessageDigest KeyPair Key]
           [java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec]
           [javax.crypto Cipher Mac KEM KeyAgreement]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]
           [org.bouncycastle.crypto.generators Argon2BytesGenerator]
           [org.bouncycastle.crypto.params Argon2Parameters Argon2Parameters$Builder]))

;; ───────── Provider seam ─────────

(defprotocol Provider
  "暗号プリミティブの差し替え境界。古典+PQC の両系統を 1 つの実装が束ねる。
  鍵/暗号文/署名は `{:x <bytes> :pq <bytes> ...}` の map(各値は encoded bytes)で授受し、
  graph へはそのまま base64 で publish できる。"
  (kem-keypair [p] "→ {:public {:x :pq} :secret {:x :pq :x-pub :pq-pub}}")
  (kem-encap [p hybrid-pk] "→ {:ciphertext {:x :pq} :shared <32B>}")
  (kem-decap [p hybrid-sk kem-ct] "→ shared <32B>")
  (sign-keypair [p] "→ {:public {:ed :mldsa} :secret {:ed :mldsa}}")
  (sign* [p sign-sk msg] "→ {:ed <sig> :mldsa <sig>} 連結署名")
  (verify* [p sign-pk msg hybrid-sig] "両方 verify した時のみ true")
  (aead-seal [p key nonce plaintext aad] "→ ciphertext(GCM)")
  (aead-open [p key nonce ciphertext aad] "→ plaintext")
  (hkdf [p ikm salt info len] "→ derived key bytes")
  (argon2id [p pass salt params] "→ KEK(32B)。params {:m-kb :t :p}")
  (rand-bytes [p n] "→ CSPRNG n bytes"))

(defprotocol SigningHandle
  "Opaque signing capability. Implementations may delegate to a non-exportable
  OS/HSM key and must never expose private-key encoding through this protocol."
  (sign-hybrid [signer provider message] "Return {:ed :mldsa} signatures.")
  (sign-ed25519 [signer message] "Return an Ed25519 signature for CACAO."))

(defprotocol DecapsulationHandle
  "Opaque hybrid KEM decapsulation capability backed by non-exportable keys."
  (decapsulate-hybrid [recipient provider ciphertext] "Return the combined 32-byte secret."))

(defn sign-with
  "Sign with either an opaque SigningHandle or the legacy encoded secret bundle.
  The latter remains a compatibility path for migration and tests."
  [provider signer ^bytes message]
  (if (satisfies? SigningHandle signer)
    (sign-hybrid signer provider message)
    (sign* provider signer message)))

(defn kem-decap-with
  "Decapsulate through an opaque handle or a legacy encoded secret bundle."
  [provider recipient ciphertext]
  (if (satisfies? DecapsulationHandle recipient)
    (decapsulate-hybrid recipient provider ciphertext)
    (kem-decap provider recipient ciphertext)))

;; ───────── 可搬ヘルパ(provider 越し) ─────────

(def ^:const kem-info "kagi/kem/v1")
(def ^:const dek-info "kagi/dek/v1")

(defn compartment-key
  "VMK から compartment-id 用の鍵を HKDF 導出。"
  [p ^bytes vmk compartment-id]
  (hkdf p vmk (byte-array 0)
        (.getBytes (str "kagi/compartment/" compartment-id) "UTF-8") 32))

;; ───────── item 封緘 / 開封 ─────────

(defn seal-item
  "item 平文を新規 DEK で封緘 → {:dek :nonce :ciphertext}。"
  [p ^bytes plaintext ^bytes aad]
  (let [dek   (rand-bytes p 32)
        nonce (rand-bytes p 12)]
    {:dek dek :nonce nonce :ciphertext (aead-seal p dek nonce plaintext aad)}))

(defn open-item
  [p ^bytes dek ^bytes nonce ^bytes ciphertext ^bytes aad]
  (aead-open p dek nonce ciphertext aad))

(defn wrap-dek
  "DEK を KEK(compartment/VMK 由来)で AES-256-GCM key-wrap。"
  [p ^bytes kek ^bytes dek]
  (let [nonce (rand-bytes p 12)]
    {:nonce nonce :wrapped (aead-seal p kek nonce dek (byte-array 0))}))

(defn unwrap-dek
  [p ^bytes kek {:keys [nonce wrapped]}]
  (aead-open p kek nonce wrapped (byte-array 0)))

(defn share-dek
  "共有: 受信者 hybrid 公開鍵へ DEK を encapsulate(PQC) → grant envelope。"
  [p recipient-hybrid-pk ^bytes dek]
  (let [{:keys [ciphertext shared]} (kem-encap p recipient-hybrid-pk)
        nonce (rand-bytes p 12)]
    (try
      {:kem-ct ciphertext :nonce nonce
       :wrapped (aead-seal p shared nonce dek (byte-array 0))}
      (finally
        (java.util.Arrays/fill ^bytes shared (byte 0))))))

(defn accept-share
  "受信者が自分の hybrid 秘密鍵で decapsulate → DEK 復元。"
  [p hybrid-sk {:keys [kem-ct nonce wrapped]}]
  (let [shared (kem-decap-with p hybrid-sk kem-ct)]
    (try
      (aead-open p shared nonce wrapped (byte-array 0))
      (finally
        (java.util.Arrays/fill ^bytes shared (byte 0))))))

;; ───────── 低レベル JCA ヘルパ ─────────

(defn- ba ^bytes [xs] (byte-array (mapcat seq xs)))

(defn- gcm [mode ^bytes key ^bytes nonce ^bytes in ^bytes aad]
  (when-not (= 32 (alength key))
    (throw (ex-info "AES-256-GCM requires a 32-byte key" {:length (alength key)})))
  (when-not (= 12 (alength nonce))
    (throw (ex-info "AES-GCM requires a 96-bit nonce" {:length (alength nonce)})))
  (let [c (Cipher/getInstance "AES/GCM/NoPadding")]
    (.init c (int mode) (SecretKeySpec. key "AES") (GCMParameterSpec. 128 nonce))
    (when (and aad (pos? (alength aad))) (.updateAAD c aad))
    (.doFinal c in)))

(defn- hmac-sha256 ^bytes [^bytes key ^bytes msg]
  (let [m (Mac/getInstance "HmacSHA256")]
    (.init m (SecretKeySpec. (if (zero? (alength key)) (byte-array 1) key) "HmacSHA256"))
    (.doFinal m msg)))

(defn sha256 ^bytes [^bytes b]
  (.digest (MessageDigest/getInstance "SHA-256") b))

(defn- hkdf-sha256 ^bytes [^bytes ikm ^bytes salt ^bytes info len]
  ;; RFC 5869 extract+expand. The previous one-block implementation silently
  ;; zero-extended requests above 32 bytes via Arrays/copyOf -- catastrophic
  ;; if a future caller split those predictable bytes into another key.
  (when-not (and (integer? len) (pos? len) (<= len (* 255 32)))
    (throw (ex-info "invalid HKDF-SHA256 output length"
                    {:length len :maximum (* 255 32)})))
  (let [salt* (if (zero? (alength salt)) (byte-array 32) salt)
        prk (hmac-sha256 salt* ikm)
        output (byte-array len)]
    (try
      (loop [counter 1 previous (byte-array 0) offset 0]
        (let [block (hmac-sha256 prk (ba [previous info [(unchecked-byte counter)]]))
              take (min 32 (- len offset))]
          (System/arraycopy block 0 output offset take)
          (when (pos? (alength previous))
            (java.util.Arrays/fill ^bytes previous (byte 0)))
          (if (= len (+ offset take))
            (do (java.util.Arrays/fill ^bytes block (byte 0)) output)
            (recur (inc counter) block (+ offset take)))))
      (finally
        (java.util.Arrays/fill ^bytes prk (byte 0))))))

(defn legacy-kdf-v0
  "Read-only compatibility KDF for vaults created before the real Argon2id fix.
  Never use this function to create or re-wrap an envelope."
  ^bytes [^bytes pass ^bytes salt {:keys [m-kb t p] :or {m-kb 262144 t 3 p 4}}]
  (loop [i 0
         out (hkdf-sha256 pass salt
                          (.getBytes (str "kagi/argon2id-compat/v1:"
                                          m-kb ":" t ":" p)
                                     "UTF-8")
                          32)]
    (if (< i (max 1 (int t)))
      (recur (inc i)
             (hkdf-sha256 out salt
                          (ba [(.getBytes "kagi/argon2id-compat/round" "UTF-8")
                               [(byte (bit-and i 0xff))]])
                          32))
      out)))

(defn- argon2id-real
  ^bytes [^bytes pass ^bytes salt {:keys [m-kb t p] :or {m-kb 262144 t 3 p 4}}]
  (when (or (< (long m-kb) 8192) (< (long t) 1) (< (long p) 1))
    (throw (ex-info "unsafe Argon2id parameters"
                    {:m-kb m-kb :t t :p p :minimum {:m-kb 8192 :t 1 :p 1}})))
  (let [params (-> (Argon2Parameters$Builder. Argon2Parameters/ARGON2_id)
                   (.withVersion Argon2Parameters/ARGON2_VERSION_13)
                   (.withSalt salt)
                   (.withMemoryAsKB (int m-kb))
                   (.withIterations (int t))
                   (.withParallelism (int p))
                   (.build))
        generator (doto (Argon2BytesGenerator.) (.init params))
        out (byte-array 32)]
    (.generateBytes generator pass out)
    out))

(defn- pub-key [alg ^bytes enc] (.generatePublic (KeyFactory/getInstance alg) (X509EncodedKeySpec. enc)))
(defn- priv-key [alg ^bytes enc] (.generatePrivate (KeyFactory/getInstance alg) (PKCS8EncodedKeySpec. enc)))

(defn- gen-kp ^KeyPair [alg] (.generateKeyPair (KeyPairGenerator/getInstance alg)))
(defn- enc ^bytes [^Key k] (.getEncoded k))

(defn- jca-sign ^bytes [alg priv ^bytes msg]
  (let [s (doto (Signature/getInstance alg) (.initSign priv) (.update msg))] (.sign s)))
(defn- jca-verify [alg pub ^bytes msg ^bytes sig]
  (let [v (doto (Signature/getInstance alg) (.initVerify pub) (.update msg))] (.verify v sig)))

(defn- x25519-ka ^bytes [priv pub]
  (let [ka (doto (KeyAgreement/getInstance "X25519") (.init priv))]
    (.doPhase ka pub true) (.generateSecret ka)))

(defn hybrid-kem-shared
  "Combine native or software X25519/ML-KEM shared secrets with the exact
  transcript used by kagi/kem/v1. The input secrets remain caller-owned; the
  temporary concatenation is erased here."
  [^bytes ss-x ^bytes ss-pq ^bytes recipient-x-public ^bytes ephemeral-x-public
   ^bytes recipient-pq-public ^bytes pq-ciphertext]
  (let [transcript (sha256 (ba [recipient-x-public ephemeral-x-public
                                recipient-pq-public pq-ciphertext]))
        ikm (ba [ss-x ss-pq])]
    (try
      (hkdf-sha256 ikm (byte-array 0)
                   (ba [(.getBytes ^String kem-info "UTF-8") transcript]) 32)
      (finally
        (java.util.Arrays/fill ^bytes ikm (byte 0))))))

;; ───────── jvm-provider(JDK24 標準 PQC + JDK-only KDF) ─────────

(defn jvm-provider
  "JDK24 標準の ML-KEM-768 / ML-DSA-65 / Ed25519 / X25519 / AES-GCM と、
   JDK-only の deterministic KDF を束ねた provider。"
  []
  (let [rng (SecureRandom.)]
    (reify Provider
      (rand-bytes [_ n] (let [b (byte-array n)] (.nextBytes rng b) b))

      (aead-seal [_ key nonce pt aad] (gcm Cipher/ENCRYPT_MODE key nonce pt aad))
      (aead-open [_ key nonce ct aad] (gcm Cipher/DECRYPT_MODE key nonce ct aad))
      (hkdf [_ ikm salt info len] (hkdf-sha256 ikm salt info len))

      ;; --- hybrid KEM: X25519(ECDH) + ML-KEM-768 ---
      (kem-keypair [_]
        (let [xk (gen-kp "X25519")
              pk (gen-kp "ML-KEM-768")
              x-pub (enc (.getPublic xk))
              pq-pub (enc (.getPublic pk))]
          {:public {:x x-pub :pq pq-pub}
           :secret {:x (enc (.getPrivate xk)) :pq (enc (.getPrivate pk))
                    :x-pub x-pub :pq-pub pq-pub}}))
      (kem-encap [_ {:keys [x pq]}]
        (let [x-pub  (pub-key "X25519" x)
              pq-pub (pub-key "ML-KEM-768" pq)
              eph    (gen-kp "X25519")
              eph-pub (enc (.getPublic eph))
              ss-x   (x25519-ka (.getPrivate eph) x-pub)
              encr   (.newEncapsulator (KEM/getInstance "ML-KEM") pq-pub)
              r      (.encapsulate encr)
              ss-pq  (enc (.key r))
              ct-pq  (.encapsulation r)]
          (try
            {:ciphertext {:x eph-pub :pq ct-pq}
             :shared (hybrid-kem-shared ss-x ss-pq x eph-pub pq ct-pq)}
            (finally
              (doseq [secret [ss-x ss-pq]]
                (java.util.Arrays/fill ^bytes secret (byte 0)))))))
      (kem-decap [_ {:keys [x pq x-pub pq-pub]} {ct-x :x ct-pq :pq}]
        (let [x-priv  (priv-key "X25519" x)
              pq-priv (priv-key "ML-KEM-768" pq)
              eph-pub (pub-key "X25519" ct-x)
              ss-x    (x25519-ka x-priv eph-pub)
              dec     (.newDecapsulator (KEM/getInstance "ML-KEM") pq-priv)
              ss-pq   (enc (.decapsulate dec ct-pq))]
          (try
            (hybrid-kem-shared ss-x ss-pq x-pub ct-x pq-pub ct-pq)
            (finally
              (doseq [secret [ss-x ss-pq]]
                (java.util.Arrays/fill ^bytes secret (byte 0)))))))

      ;; --- hybrid 署名: Ed25519 + ML-DSA-65 ---
      (sign-keypair [_]
        (let [ed (gen-kp "Ed25519") ml (gen-kp "ML-DSA-65")]
          {:public {:ed (enc (.getPublic ed)) :mldsa (enc (.getPublic ml))}
           :secret {:ed (enc (.getPrivate ed)) :mldsa (enc (.getPrivate ml))}}))
      (sign* [_ {:keys [ed mldsa]} msg]
        {:ed    (jca-sign "Ed25519"  (priv-key "Ed25519" ed) msg)
         :mldsa (jca-sign "ML-DSA-65" (priv-key "ML-DSA-65" mldsa) msg)})
      (verify* [_ {:keys [ed mldsa]} msg sig]
        (and (jca-verify "Ed25519"  (pub-key "Ed25519" ed) msg (:ed sig))
             (jca-verify "ML-DSA-65" (pub-key "ML-DSA-65" mldsa) msg (:mldsa sig))))

      ;; --- real Argon2id; no silent downgrade ---
      (argon2id [_ pass salt params]
        (argon2id-real pass salt params)))))

;; 後方互換: 旧称 bc-provider は jvm-provider を返す。
(def bc-provider jvm-provider)
