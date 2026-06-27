(ns kagi.crypto
  "★ kagi の対量子(PQC)暗号コア(JVM)。

  方針(ADR-2606272330): 古典を捨てず PQC を **加法的(hybrid)** に重ねる。両方が破られない
  限り安全。プリミティブは `Provider` プロトコル越しにのみ呼び、実装を差し替えてもコアは
  不変に保つ(`:db-api` seam と同型):

    - JVM       : `bc-provider`  — BouncyCastle(JCA) で ML-KEM-768 / ML-DSA-65 / SLH-DSA、
                                  Ed25519 / AES-256-GCM は JDK+BC。
    - CLJS/WASM : kotoba-crypto(Rust, ml-kem/ml-dsa を増設) を束ねた別ファイルの cljs provider。

  hybrid 構成:
    - KEM     : X25519 + ML-KEM-768。combiner = HKDF-SHA256(ss_x ‖ ss_pq, transcript)。
    - 署名     : Ed25519 + ML-DSA-65。連結し **両方 verify** で有効。
    - 対称     : AES-256-GCM(AAD=item-cid)。Grover 後も 128-bit 相当。
    - unlock  : Argon2id + passkey PRF(WebAuthn hmac-secret)。"
  (:import [java.security SecureRandom MessageDigest]
           [javax.crypto Cipher Mac]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]))

;; ───────── Provider seam ─────────

(defprotocol Provider
  "暗号プリミティブの差し替え境界。古典+PQC の両系統を 1 つの実装が束ねる。"
  (kem-keypair [p] "→ {:public <hybrid-pk> :secret <hybrid-sk>}")
  (kem-encap [p hybrid-pk] "→ {:ciphertext <kem-ct> :shared <32B>}")
  (kem-decap [p hybrid-sk kem-ct] "→ shared <32B>")
  (sign-keypair [p] "→ {:public <ed+mldsa pk> :secret <ed+mldsa sk>}")
  (sign* [p sign-sk msg] "→ {:ed <sig> :mldsa <sig>} 連結署名")
  (verify* [p sign-pk msg hybrid-sig] "両方 verify した時のみ true")
  (aead-seal [p key nonce plaintext aad] "→ ciphertext(GCM)")
  (aead-open [p key nonce ciphertext aad] "→ plaintext")
  (hkdf [p ikm salt info len] "→ derived key bytes")
  (argon2id [p pass salt params] "→ KEK(32B)")
  (rand-bytes [p n] "→ CSPRNG n bytes"))

;; ───────── 可搬ヘルパ(provider 越し) ─────────

(def ^:const kem-info "kagi/kem/v1")
(def ^:const dek-info "kagi/dek/v1")

(defn hybrid-kem-combine
  "robustly-binding combiner: HKDF(ikm = ss_x ‖ ss_pq,
   info = \"kagi/kem/v1\" ‖ H(pk_x ‖ ct_x ‖ pk_pq ‖ ct_pq))。transcript を縛り、
   どちらの片側 secret だけが漏れても shared を復元できない。"
  [p {:keys [ss-x ss-pq transcript]}]
  (let [ikm  (byte-array (concat (seq ss-x) (seq ss-pq)))
        info (byte-array (concat (.getBytes ^String kem-info "UTF-8") (seq transcript)))]
    (hkdf p ikm (byte-array 0) info 32)))

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
    {:kem-ct ciphertext :nonce nonce
     :wrapped (aead-seal p shared nonce dek (byte-array 0))}))

(defn accept-share
  "受信者が自分の hybrid 秘密鍵で decapsulate → DEK 復元。"
  [p hybrid-sk {:keys [kem-ct nonce wrapped]}]
  (let [shared (kem-decap p hybrid-sk kem-ct)]
    (aead-open p shared nonce wrapped (byte-array 0))))

;; ───────── 参照 JVM provider(古典は実装済 / PQC は段階導入) ─────────

(defn- gcm [mode ^bytes key ^bytes nonce ^bytes in ^bytes aad]
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

(defn bc-provider
  "参照 provider。AES-GCM / HKDF / CSPRNG は JDK で実装済み。ML-KEM/ML-DSA/Argon2id は
   BouncyCastle 配線を段階導入(現状は ex-info で未配線を明示)。"
  []
  (let [rng (SecureRandom.)]
    (reify Provider
      (rand-bytes [_ n] (let [b (byte-array n)] (.nextBytes rng b) b))
      (aead-seal [_ key nonce pt aad] (gcm Cipher/ENCRYPT_MODE key nonce pt aad))
      (aead-open [_ key nonce ct aad] (gcm Cipher/DECRYPT_MODE key nonce ct aad))
      (hkdf [_ ikm salt info len]
        ;; RFC5869(HMAC-SHA256), 単一ブロック(len<=32)前提の最小実装
        (let [prk (hmac-sha256 salt ikm)
              t   (hmac-sha256 prk (byte-array (concat (seq info) [(byte 1)])))]
          (java.util.Arrays/copyOf t (int len))))
      (kem-keypair [_] (throw (ex-info "ML-KEM-768 keypair 未配線: BouncyCastle JCA を結線" {})))
      (kem-encap [_ _pk] (throw (ex-info "ML-KEM-768 encap 未配線" {})))
      (kem-decap [_ _sk _ct] (throw (ex-info "ML-KEM-768 decap 未配線" {})))
      (sign-keypair [_] (throw (ex-info "Ed25519+ML-DSA-65 keypair 未配線" {})))
      (sign* [_ _sk _msg] (throw (ex-info "hybrid sign 未配線" {})))
      (verify* [_ _pk _msg _sig] (throw (ex-info "hybrid verify 未配線" {})))
      (argon2id [_ _pass _salt _params]
        (throw (ex-info "Argon2id 未配線: BouncyCastle Argon2BytesGenerator" {}))))))
