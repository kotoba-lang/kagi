(ns kagi.cacao
  "自己発行 CACAO(SIWE/EIP-4361 を Ed25519 did:key で署名、CBOR wire、base64)。
  `ai-gftd-itonami/src/itonami/cacao.clj` の **mint** 側を移植し、kagi では **verify** 側
  (CBOR decode + did:key→公開鍵復元 + Ed25519 検証)も実装する。actor は自分の鍵で graph の
  owner なので depth-1 self-mint が構造的に authorized(owner hand-off も共有 token も不要)。

  SIWE/wire ビルダは `kotoba.cacao` の byte-exact 純関数の写し(同期して保つ)。crypto は
  JDK Ed25519 + 最小 CBOR(definite-length)。"
  (:require [clojure.string :as str])
  (:import [java.security Signature KeyFactory]
           [java.security.spec X509EncodedKeySpec]
           [java.io ByteArrayOutputStream]
           [java.util Base64]
           [java.math BigInteger]))

;; ───────── pure SIWE builders (mirror of kotoba.cacao / itonami) ─────────

(def ^:private cap->op {:cap/read "datom:read" :cap/transact "datom:transact" :cap/admin "tx:create"})

(defn grant->resources [{:keys [cap scope]}]
  [(str "kotoba://op/" (cap->op cap)) (str "kotoba://graph/" scope)])

(defn grant->payload [grant {:keys [iss aud nonce issued-at expiry domain version statement]
                             :or {domain "com.junkawasaki.kagi" version "1"}}]
  {:iss iss :aud aud :issued-at issued-at :expiry expiry :nonce nonce
   :domain domain :statement statement :version version
   :resources (grant->resources grant)})

(defn- iss-address [iss] (last (str/split iss #":")))
(defn- iss-chain-id [iss]
  (if (str/starts-with? iss "did:key:") "1"
      (let [segs (str/split iss #":")]
        (if (>= (count segs) 2) (nth segs (- (count segs) 2)) "1"))))

(defn siwe-message [{:keys [iss aud issued-at expiry nonce domain statement version resources]}]
  (->> (concat
        [(str domain " wants you to sign in with your Ethereum account:") (iss-address iss) ""]
        (when statement [statement ""])
        [(str "URI: " aud) (str "Version: " version) (str "Chain ID: " (iss-chain-id iss))
         (str "Nonce: " nonce) (str "Issued At: " issued-at)]
        (when expiry [(str "Expiration Time: " expiry)])
        (when (seq resources) (cons "Resources:" (map #(str "- " %) resources))))
       (str/join "\n")))

(defn ->wire [payload sig-b64]
  {"h" {"t" "eip4361"}
   "p" (cond-> {"iss" (:iss payload) "aud" (:aud payload) "iat" (:issued-at payload)
                "nonce" (:nonce payload) "domain" (:domain payload)
                "version" (:version payload) "resources" (:resources payload)}
         (:expiry payload)    (assoc "exp" (:expiry payload))
         (:statement payload) (assoc "statement" (:statement payload)))
   "s" {"t" "EdDSA" "s" (or sig-b64 "")}})

;; ───────── minimal CBOR encode (definite-length) ─────────

(defn- cbor-head [^ByteArrayOutputStream o major n]
  (cond (< n 24)    (.write o (int (+ (bit-shift-left major 5) n)))
        (< n 256)   (do (.write o (int (+ (bit-shift-left major 5) 24))) (.write o (int n)))
        (< n 65536) (do (.write o (int (+ (bit-shift-left major 5) 25)))
                        (.write o (int (bit-and (unsigned-bit-shift-right n 8) 0xff)))
                        (.write o (int (bit-and n 0xff))))
        :else (throw (ex-info "cbor len too big" {:n n}))))

(defn- cbor-val [^ByteArrayOutputStream o v]
  (cond
    (string? v)     (let [b (.getBytes ^String v "UTF-8")] (cbor-head o 3 (alength b)) (.write o b 0 (alength b)))
    (map? v)        (do (cbor-head o 5 (count v)) (doseq [[k vv] v] (cbor-val o (name k)) (cbor-val o vv)))
    (sequential? v) (do (cbor-head o 4 (count v)) (doseq [x v] (cbor-val o x)))
    :else           (cbor-val o (str v))))

(defn- cbor-bytes ^bytes [v]
  (let [o (ByteArrayOutputStream.)] (cbor-val o v) (.toByteArray o)))

;; ───────── minimal CBOR decode (text/array/map; verify 用) ─────────

(defn- ub [^bytes b i] (bit-and (int (aget b i)) 0xff))

(defn- cbor-read
  "[value next-pos] を返す。text(3)/array(4)/map(5)、追加情報 0-23/24/25 のみ対応。"
  [^bytes b pos]
  (let [ib (ub b pos) major (bit-shift-right ib 5) info (bit-and ib 0x1f)
        [n p1] (cond (< info 24) [info (inc pos)]
                     (= info 24) [(ub b (inc pos)) (+ pos 2)]
                     (= info 25) [(bit-or (bit-shift-left (ub b (inc pos)) 8) (ub b (+ pos 2))) (+ pos 3)]
                     :else (throw (ex-info "cbor: unsupported head" {:info info})))]
    (case (int major)
      3 [(String. (java.util.Arrays/copyOfRange b p1 (+ p1 n)) "UTF-8") (+ p1 n)]
      4 (loop [i 0 p p1 acc []]
          (if (< i n) (let [[v np] (cbor-read b p)] (recur (inc i) np (conj acc v))) [acc p]))
      5 (loop [i 0 p p1 acc {}]
          (if (< i n)
            (let [[k p2] (cbor-read b p) [v p3] (cbor-read b p2)] (recur (inc i) p3 (assoc acc k v)))
            [acc p]))
      (throw (ex-info "cbor: unsupported major" {:major major})))))

;; ───────── base58btc encode/decode + did:key ─────────

(def ^:private b58 "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defn- base58-decode ^bytes [^String s]
  (let [ones (count (take-while #(= % \1) s))
        n (reduce (fn [^BigInteger acc ch]
                    (.add (.multiply acc (BigInteger/valueOf 58))
                          (BigInteger/valueOf (.indexOf b58 (str ch)))))
                  BigInteger/ZERO (seq s))
        raw (.toByteArray n)
        raw (if (and (> (alength raw) 1) (zero? (aget raw 0)))
              (java.util.Arrays/copyOfRange raw 1 (alength raw)) raw)
        out (byte-array (+ ones (alength raw)))]
    (System/arraycopy raw 0 out ones (alength raw))
    out))

(def ^:private ed25519-spki-prefix
  ;; SubjectPublicKeyInfo header for Ed25519: 302a300506032b6570032100
  (byte-array (map unchecked-byte [0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00])))

(defn did-key->public
  "did:key:z… (Ed25519) → java PublicKey。multicodec 0xED01 を剥がし X.509 SPKI に包む。"
  [iss]
  (let [mb     (subs iss (count "did:key:z"))
        framed (base58-decode mb)                                 ; 0xED 0x01 ‖ raw32
        raw    (java.util.Arrays/copyOfRange framed 2 (alength framed))
        spki   (byte-array (concat (seq ed25519-spki-prefix) (seq raw)))]
    (.generatePublic (KeyFactory/getInstance "Ed25519") (X509EncodedKeySpec. spki))))

;; ───────── Ed25519 ─────────

(defn- ed-sign ^bytes [priv ^bytes msg]
  (let [s (doto (Signature/getInstance "Ed25519") (.initSign priv))] (.update s msg) (.sign s)))

(defn- ed-verify? [pub ^bytes msg ^bytes sig]
  (let [v (doto (Signature/getInstance "Ed25519") (.initVerify pub))] (.update v msg) (.verify v sig)))

;; ───────── mint / verify ─────────

(defn mint
  "actor が自分の Ed25519 鍵で base64 cacao を自己発行する。
   identity: {:private-key :did}、grant: {:cap :scope}、opts: {:aud :nonce :issued-at :expiry}。"
  [{:keys [private-key did]} grant {:keys [aud nonce issued-at expiry]}]
  (let [payload (grant->payload grant {:iss did :aud aud :nonce nonce
                                       :issued-at issued-at :expiry expiry})
        msg     (siwe-message payload)
        sig     (ed-sign private-key (.getBytes ^String msg "UTF-8"))
        sig-b64 (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) sig)]
    (.encodeToString (Base64/getEncoder) (cbor-bytes (->wire payload sig-b64)))))

(defn verify
  "自己発行 cacao を検証 → {:ok? :iss :aud :resources}。SIWE を再構成し iss(did:key)から
   公開鍵を復元して Ed25519 署名を検証する。opts {:aud} を渡すと audience も照合。"
  ([cacao-b64] (verify cacao-b64 nil))
  ([cacao-b64 {:keys [aud]}]
   (try
     (let [wire (first (cbor-read (.decode (Base64/getDecoder) ^String cacao-b64) 0))
           p    (get wire "p")
           sigb (.decode (Base64/getUrlDecoder) ^String (get-in wire ["s" "s"]))
           payload {:iss (get p "iss") :aud (get p "aud") :issued-at (get p "iat")
                    :expiry (get p "exp") :nonce (get p "nonce") :domain (get p "domain")
                    :statement (get p "statement") :version (get p "version")
                    :resources (get p "resources")}
           msg  (siwe-message payload)
           pub  (did-key->public (:iss payload))
           sig-ok? (ed-verify? pub (.getBytes ^String msg "UTF-8") sigb)
           aud-ok? (or (nil? aud) (= aud (:aud payload)))]
       {:ok? (boolean (and sig-ok? aud-ok?))
        :iss (:iss payload) :aud (:aud payload) :resources (:resources payload)})
     (catch Exception e {:ok? false :error (.getMessage e)}))))
