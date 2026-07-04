(ns kagi.identity
  "vault actor の自己主権 identity(JVM)。`itonami/cacao.clj` を継承:
  Ed25519 did:key と鍵由来 IPNS 名(`k51…`)がそのまま actor の graph = vault namespace。
  CACAO は自己発行(owner hand-off も共有 token も不要)。**kotoba authority は不変**で、
  ここに hybrid 署名用の ML-DSA-65 公開鍵を加法的に併記する(graph に publish)。

  秘密鍵(Ed25519 + ML-DSA + KEM)は `.kagi/identity.edn` に永続し **git に絶対コミット
  しない**(.gitignore)。"
  (:require [clojure.edn :as edn]
            [ed25519.core :as ed25519]
            [ipns.core :as ipns]
            [kagi.crypto :as crypto]
            [kagi.secret-store :as secret-store])
  (:import [java.security KeyPairGenerator KeyFactory Key]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.util Base64]))

(defn- enc ^bytes [^Key k] (.getEncoded k))
(defn- b64 ^String [^bytes b] (.encodeToString (Base64/getEncoder) b))
(defn- unb64 ^bytes [^String s] (.decode (Base64/getDecoder) s))
(defn- b64-map [m] (into {} (map (fn [[k v]] [k (b64 v)])) m))
(defn- unb64-map [m] (into {} (map (fn [[k v]] [k (unb64 v)])) m))

(defn- raw-pub ^bytes [pub]
  (let [enc (.getEncoded pub)]
    (java.util.Arrays/copyOfRange enc (- (alength enc) 32) (alength enc))))

;; did:key + IPNS-name derivation delegated to kotoba-lang/ed25519 and
;; kotoba-lang/ipns (ADR-2607050100) — this used to be a private
;; BigInteger-based reimplementation.

(defn- did-key [pub]
  (ed25519/did-key-from-pub (raw-pub pub)))

(defn- ipns-name
  "actor の graph = 鍵由来 libp2p-key IPNS 名(`k51…`)。鍵を持つことが graph の authority。"
  [pub]
  (ipns/pubkey->name (raw-pub pub)))

(defn generate-identity
  "fresh hybrid identity。Ed25519 が **authority**(did:key/IPNS graph、kotoba 不変)で、
   ML-DSA-65 を vault commit/台帳の **hybrid 共同署名** として加法的に併発行する
   (`:mldsa-public-b64` は graph に publish)。provider を渡すと **hybrid KEM 受信鍵**
   (X25519+ML-KEM-768)も生成し、他メンバーがこの identity へ secret を共有できる。"
  ([] (generate-identity nil))
  ([provider]
   (let [kp  (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))
         pub (.getPublic kp)
         ml  (.generateKeyPair (KeyPairGenerator/getInstance "ML-DSA-65"))
         kem (when provider (crypto/kem-keypair provider))]
     (cond-> {:private-key (.getPrivate kp) :public-key pub
              :did (did-key pub) :graph (ipns-name pub)
              :private-b64 (b64 (enc (.getPrivate kp)))
              :public-b64  (b64 (enc pub))
              :mldsa-private-b64 (b64 (enc (.getPrivate ml)))
              :mldsa-public-b64  (b64 (enc (.getPublic ml)))}
       kem (assoc :kem-public (b64-map (:public kem))
                  :kem-secret (b64-map (:secret kem)))))))

(defn kem-public
  "他メンバーがこの identity へ encapsulate するための hybrid KEM 公開 bundle {:x :pq}。"
  [id]
  (some-> (:kem-public id) unb64-map))

(defn kem-secret
  "accept-share で envelope を開くための hybrid KEM 秘密 bundle。"
  [id]
  (some-> (:kem-secret id) unb64-map))

(defn sign-secret
  "crypto provider の `sign*` に渡す秘密 bundle {:ed <pkcs8> :mldsa <pkcs8>}。"
  [{:keys [private-b64 mldsa-private-b64]}]
  {:ed (unb64 private-b64) :mldsa (unb64 mldsa-private-b64)})

(defn sign-public
  "`verify*` / graph publish 用の公開 bundle {:ed <x509> :mldsa <x509>}。"
  [{:keys [public-b64 mldsa-public-b64]}]
  {:ed (unb64 public-b64) :mldsa (unb64 mldsa-public-b64)})

(defn member-record
  "graph に publish するメンバー entity(depth-1 self-mint)。公開鍵束のみ(秘密は出さない)。"
  [id role]
  (cond-> #:member{:did (:did id) :role role :sign-pub (b64-map (sign-public id))}
    (:kem-public id) (assoc :member/kem-pub (kem-public id))))

(defn load-identity [{:keys [private-b64 public-b64] :as m}]
  (let [kf (KeyFactory/getInstance "Ed25519")
        pub  (.generatePublic kf (X509EncodedKeySpec. (.decode (Base64/getDecoder) public-b64)))]
    (cond-> (merge m {:public-key pub :did (did-key pub) :graph (ipns-name pub)})
      private-b64 (assoc :private-key
                         (.generatePrivate kf (PKCS8EncodedKeySpec.
                                                (.decode (Base64/getDecoder) private-b64)))))))

(def secret-fields #{:private-b64 :mldsa-private-b64 :kem-secret})
(def public-fields #{:public-b64 :mldsa-public-b64 :kem-public})

(defn split-identity [id]
  {:public (select-keys id public-fields)
   :secret (select-keys id secret-fields)})

(defn secret-backed-identity? [m]
  (and (:secret-ref m)
       (not (:private-b64 m))))

(defn load-secret-backed-identity [m secret-store]
  (let [secret (secret-store/get-edn secret-store (:secret-ref m))]
    (load-identity (merge m secret))))

(defn migrate-identity-secret!
  "Move secret key material from an identity map into SecretStore.

  Returns the public identity map that should be written to identity.edn."
  [path id secret-store secret-ref]
  (let [{:keys [public secret]} (split-identity id)
        public* (assoc public :secret-ref secret-ref :secret-provider :secret-store)]
    (secret-store/put-edn! secret-store secret-ref secret)
    (spit path (pr-str public*))
    public*))

(defn load-or-create-identity!
  "per-actor 鍵を `path`(.kagi/identity.edn) から読込、無ければ生成→永続(b64 のみ保存)。
   provider を渡すと hybrid KEM 受信鍵も生成・永続する。"
  ([path] (load-or-create-identity! path nil))
  ([path provider] (load-or-create-identity! path provider nil))
  ([path provider {:keys [secret-store secret-ref]}]
   (let [f (java.io.File. ^String path)]
     (if (.exists f)
       (let [m (edn/read-string (slurp f))]
         (if (secret-backed-identity? m)
           (load-secret-backed-identity
            m
            (or secret-store (secret-store/store-for-ref (:secret-ref m))))
           (load-identity m)))
       (let [id (generate-identity provider)
             parent (.getParentFile (.getAbsoluteFile f))]
         (when parent (.mkdirs parent))
         (if (and secret-store secret-ref)
           (migrate-identity-secret! path id secret-store secret-ref)
           (spit f (pr-str (select-keys id [:private-b64 :public-b64
                                            :mldsa-private-b64 :mldsa-public-b64
                                            :kem-public :kem-secret]))))
         id)))))
