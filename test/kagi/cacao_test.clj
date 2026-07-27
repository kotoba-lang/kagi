(ns kagi.cacao-test
  "自己発行 CACAO の mint→verify 往復・改竄検知・audience 照合。"
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.cacao :as cacao]
            [kagi.identity :as identity]
            [ed25519.core :as ed25519])
  (:import [java.util Base64]))

(deftest mint-verify-roundtrip
  (testing "actor が自分の鍵で mint した CACAO を verify が通す(iss=自 did)"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/transact :scope (:graph id)}
                          {:aud "https://kotobase.net" :nonce "n1"})
          r   (cacao/verify tok {:aud "https://kotobase.net"})]
      (is (:ok? r))
      (is (= (:did id) (:iss r)))
      (is (= "https://kotobase.net" (:aud r))))))

(deftest tampered-signature-fails
  (testing "CBOR byte を 1 bit 反転すると verify が落ちる(署名 or payload の改竄検知)"
    ;; NOTE: the CBOR is canonical dag-cbor (map keys sorted length-then-bytewise
    ;; for the live kotobase.net edge), so the signature is NOT the trailing
    ;; bytes ("s" < "t" inside the {t,s} sig map). Flip a byte in the middle of
    ;; the token — it lands in the payload or signature region either way, and
    ;; both are covered by the Ed25519 verify (payload corruption changes the
    ;; reconstructed SIWE message; signature corruption fails directly).
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)} {:aud "u" :nonce "n"})
          raw (.decode (Base64/getDecoder) tok)
          i   (quot (alength raw) 2)
          _   (aset-byte raw i (unchecked-byte (bit-xor (aget raw i) 1)))
          bad (.encodeToString (Base64/getEncoder) raw)]
      (is (false? (:ok? (cacao/verify bad)))))))

(deftest wrong-audience-rejected
  (testing "audience 不一致は reject(同一なら通過)"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)} {:aud "https://a" :nonce "n"})]
      (is (true?  (:ok? (cacao/verify tok {:aud "https://a"}))))
      (is (false? (:ok? (cacao/verify tok {:aud "https://evil"})))))))

(deftest expired-token-rejected
  (testing "expiry を過ぎた CACAO は :now 照合で reject(期限内は ok)"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)}
                          {:aud "u" :nonce "n" :issued-at "2026-06-27T00:00:00Z"
                           :expiry "2026-06-27T01:00:00Z"})]
      (is (true? (:ok? (cacao/verify tok {:now "2026-06-27T00:30:00Z"}))))
      (let [r (cacao/verify tok {:now "2026-06-27T02:00:00Z"})]
        (is (false? (:ok? r)))
        (is (:expired? r))))))

(deftest replayed-nonce-rejected
  (testing "既出 nonce はリプレイとして reject"
    (let [id  (identity/generate-identity)
          tok (cacao/mint id {:cap :cap/read :scope (:graph id)} {:aud "u" :nonce "n-123"})]
      (is (true? (:ok? (cacao/verify tok))))
      (let [r (cacao/verify tok {:nonce-seen? #{"n-123"}})]
        (is (false? (:ok? r)))
        (is (:replay? r))))))

(deftest non-ed25519-did-key-rejected
  (testing "did:key の multicodec が 0xED01(Ed25519)でない場合、did-key->public は例外を
            投げ、verify は :ok? false で fail-closed する(黙って別鍵種別のバイト列を
            Ed25519 公開鍵として受理してはいけない)"
    (is (thrown? clojure.lang.ExceptionInfo
                 ;; 0xEC01 = X25519 multicodec, not Ed25519 -- forged via ed25519.core's
                 ;; own base58btc encoder so this is a genuinely well-formed did:key,
                 ;; just of the wrong key type.
                 (cacao/did-key->public
                  (str "did:key:z"
                       (ed25519/b58
                        (byte-array (concat [(unchecked-byte 0xec) (unchecked-byte 0x01)]
                                            (repeat 32 (unchecked-byte 0)))))))))
    (let [id (identity/generate-identity)
          non-ed25519-did (str "did:key:z"
                               (ed25519/b58
                                (byte-array (concat [(unchecked-byte 0xec) (unchecked-byte 0x01)]
                                                    (repeat 32 (unchecked-byte 0))))))
          tok (cacao/mint {:private-key (:private-key id) :did non-ed25519-did}
                          {:cap :cap/read :scope (:graph id)} {:aud "u" :nonce "n"})]
      (is (false? (:ok? (cacao/verify tok)))
          "verify must fail-closed (not throw uncaught) when iss is a wrongly-typed did:key"))))

(deftest forged-issuer-fails
  (testing "別人の鍵で署名し iss を被害者 did に詐称しても、iss から復元した鍵で検証され落ちる"
    (let [victim (identity/generate-identity)
          attacker (identity/generate-identity)
          ;; attacker が victim の did を iss に詐称(自分の鍵で署名)
          tok (cacao/mint {:private-key (:private-key attacker) :did (:did victim)}
                          {:cap :cap/admin :scope (:graph victim)} {:aud "u" :nonce "n"})]
      (is (false? (:ok? (cacao/verify tok)))
          "iss(victim)から復元した公開鍵では attacker 署名を検証できない"))))

;; ───────── the live apex's own acceptance rules ─────────
;; Every assertion below corresponds to a check in net-kotobase's
;; `kotobase.edge-cacao/validate-cacao`. They exist because `kagi push`
;; answered 401 for as long as this file diverged from that one, and the
;; failure was invisible from here: the apex returns a bare
;; `{"ok":false,"error":"Unauthorized"}` for every one of these causes.

(defn- apex-cacao []
  (let [id (identity/generate-identity)
        now (java.time.Instant/parse "2026-07-27T10:15:30Z")]
    [id (cacao/mint-kotobase id {:nonce "n-apex-1"
                                 :issued-at (str now)
                                 :expiry (str (.plusSeconds now 300))})]))

(defn- payload-of [tok]
  (:payload (cacao/decode-wire tok)))

(deftest apex-mint-carries-the-pin-capability
  (testing "validate-cacao: `CACAO missing kotobase:pin capability`"
    (let [[_ tok] (apex-cacao)]
      (is (some #{"kotoba://can/kotobase:pin"} (:resources (payload-of tok)))))))

(deftest apex-mint-scopes-the-graph-to-the-issuer-did
  (testing "validate-cacao: `CACAO graph scope does not include issuer DID`.
            The scope is the DID, NOT a graph CID -- the request body still
            names the CID, only the CACAO scope moved."
    (let [[id tok] (apex-cacao)
          p (payload-of tok)
          scopes (->> (:resources p)
                      (filter #(clojure.string/starts-with? % "kotoba://graph/"))
                      (map #(subs % (count "kotoba://graph/"))))]
      (is (seq scopes) "a mint with no graph scope at all is what shipped, and 401'd")
      (is (some #{(:did id)} scopes)))))

(deftest apex-timestamps-are-iso-seconds-and-nothing-else
  (testing "the actual cause of the 401. `parse-utc-seconds` matches
            ^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$ and NOTHING else: not
            epoch seconds, not a fractional part. `(str (Instant/now))`
            renders nanoseconds whenever they are non-zero, so most mints
            were rejected and the ones landing on a whole second passed --
            which is worse than failing every time."
    (let [iso #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
          [_ tok] (apex-cacao)
          p (payload-of tok)]
      (is (re-matches iso (str (:issued-at p))))
      (is (re-matches iso (str (:expiry p))))
      (testing "the shapes that were tried and rejected"
        (is (not (re-matches iso "2026-07-27T10:15:30.123456789Z")))
        (is (not (re-matches iso "1785140000")))))))

(deftest apex-wire-carries-the-caip122-header
  (testing "an earlier comment asserted the apex wanted NO `h` field; that was
            true of the pre-cutover pod"
    (let [[_ tok] (apex-cacao)]
      (is (= "caip122" (:header-type (cacao/decode-wire tok)))))))

(deftest apex-cacao-is-strict-dag-cbor
  (testing "the edge decodes with @ipld/dag-cbor, which REJECTS a
            non-canonical map -- so key order is load-bearing even though it
            never affects the signature (that is over the SIWE string)"
    (let [[_ tok] (apex-cacao)
          p (payload-of tok)]
      (is (map? p))
      (is (= (sort-by (fn [k] [(count (name k)) (name k)]) (keys p))
             (sort-by (fn [k] [(count (name k)) (name k)]) (keys p)))))))
