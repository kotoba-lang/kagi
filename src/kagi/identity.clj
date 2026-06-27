(ns kagi.identity
  "vault actor の自己主権 identity(JVM)。`itonami/cacao.clj` を継承:
  Ed25519 did:key と鍵由来 IPNS 名(`k51…`)がそのまま actor の graph = vault namespace。
  CACAO は自己発行(owner hand-off も共有 token も不要)。**kotoba authority は不変**で、
  ここに hybrid 署名用の ML-DSA-65 公開鍵を加法的に併記する(graph に publish)。

  秘密鍵(Ed25519 + ML-DSA + KEM)は `.kagi/identity.edn` に永続し **git に絶対コミット
  しない**(.gitignore)。"
  (:require [clojure.edn :as edn])
  (:import [java.security KeyPairGenerator KeyFactory Key]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.util Base64]))

(defn- enc ^bytes [^Key k] (.getEncoded k))
(defn- b64 ^String [^bytes b] (.encodeToString (Base64/getEncoder) b))
(defn- unb64 ^bytes [^String s] (.decode (Base64/getDecoder) s))

(def ^:private b58 "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defn- base58btc [^bytes data]
  (let [zeros (count (take-while zero? data))
        sb (StringBuilder.) k (java.math.BigInteger/valueOf 58)]
    (loop [n (java.math.BigInteger. 1 data)]
      (when (pos? (.signum n))
        (.append sb (.charAt b58 (.intValue (.mod n k))))
        (recur (.divide n k))))
    (dotimes [_ zeros] (.append sb \1))
    (.toString (.reverse sb))))

(def ^:private b36 "0123456789abcdefghijklmnopqrstuvwxyz")

(defn- base36 [^bytes data]
  (let [sb (StringBuilder.) k (java.math.BigInteger/valueOf 36)]
    (loop [n (java.math.BigInteger. 1 data)]
      (when (pos? (.signum n))
        (.append sb (.charAt b36 (.intValue (.mod n k))))
        (recur (.divide n k))))
    (.toString (.reverse sb))))

(defn- raw-pub ^bytes [pub]
  (let [enc (.getEncoded pub)]
    (java.util.Arrays/copyOfRange enc (- (alength enc) 32) (alength enc))))

(defn- did-key [pub]
  ;; multicodec ed25519-pub = 0xED 0x01, then raw key; base58btc; 'z' multibase.
  (let [framed (byte-array (concat [(unchecked-byte 0xED) (unchecked-byte 0x01)]
                                   (seq (raw-pub pub))))]
    (str "did:key:z" (base58btc framed))))

(defn- ipns-name
  "actor の graph = 鍵由来 libp2p-key IPNS 名(`k51…`)。鍵を持つことが graph の authority。"
  [pub]
  (let [raw (raw-pub pub)
        pb  (byte-array (map unchecked-byte (concat [0x08 0x01 0x12 0x20] (seq raw))))
        mh  (byte-array (map unchecked-byte (concat [0x00 (alength pb)] (seq pb))))
        cid (byte-array (map unchecked-byte (concat [0x01 0x72] (seq mh))))]
    (str "k" (base36 cid))))

(defn generate-identity
  "fresh hybrid identity。Ed25519 が **authority**(did:key/IPNS graph、kotoba 不変)で、
   ML-DSA-65 を vault commit/台帳の **hybrid 共同署名** として加法的に併発行する
   (`:mldsa-public-b64` は graph に publish)。KEM 受信鍵は別途 crypto provider で生成。"
  []
  (let [kp  (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))
        pub (.getPublic kp)
        ml  (.generateKeyPair (KeyPairGenerator/getInstance "ML-DSA-65"))]
    {:private-key (.getPrivate kp) :public-key pub
     :did (did-key pub) :graph (ipns-name pub)
     :private-b64 (b64 (enc (.getPrivate kp)))
     :public-b64  (b64 (enc pub))
     :mldsa-private-b64 (b64 (enc (.getPrivate ml)))
     :mldsa-public-b64  (b64 (enc (.getPublic ml)))}))

(defn sign-secret
  "crypto provider の `sign*` に渡す秘密 bundle {:ed <pkcs8> :mldsa <pkcs8>}。"
  [{:keys [private-b64 mldsa-private-b64]}]
  {:ed (unb64 private-b64) :mldsa (unb64 mldsa-private-b64)})

(defn sign-public
  "`verify*` / graph publish 用の公開 bundle {:ed <x509> :mldsa <x509>}。"
  [{:keys [public-b64 mldsa-public-b64]}]
  {:ed (unb64 public-b64) :mldsa (unb64 mldsa-public-b64)})

(defn load-identity [{:keys [private-b64 public-b64] :as m}]
  (let [kf (KeyFactory/getInstance "Ed25519")
        priv (.generatePrivate kf (PKCS8EncodedKeySpec. (.decode (Base64/getDecoder) private-b64)))
        pub  (.generatePublic kf (X509EncodedKeySpec. (.decode (Base64/getDecoder) public-b64)))]
    (merge m {:private-key priv :public-key pub :did (did-key pub) :graph (ipns-name pub)})))

(defn load-or-create-identity!
  "per-actor 鍵を `path`(.kagi/identity.edn) から読込、無ければ生成→永続(b64 のみ保存)。"
  [path]
  (let [f (java.io.File. ^String path)]
    (if (.exists f)
      (load-identity (edn/read-string (slurp f)))
      (let [id (generate-identity)
            parent (.getParentFile (.getAbsoluteFile f))]
        (when parent (.mkdirs parent))
        (spit f (pr-str (select-keys id [:private-b64 :public-b64
                                         :mldsa-private-b64 :mldsa-public-b64
                                         :kem-private-b64 :kem-public-b64])))
        id))))
