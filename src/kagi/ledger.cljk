(ns kagi.ledger
  "改竄検知される append-only 監査台帳。各 fact を **ハッシュ鎖** で連結し、actor の
  **hybrid 署名(Ed25519 + ML-DSA-65)** を載せる(ADR-2606272330 の台帳要件)。

  entry = fact ＋ {:ledger/seq :ledger/prev-hash :ledger/hash :ledger/sig}
    - hash    = SHA-256(prev-hash ‖ canonical(fact))   ← 1 link でも壊すと以降全滅
    - sig     = hybrid-sign(hash)                       ← {:ed b64 :mldsa b64}（任意）
  canonical 化は sorted-map + pr-str で決定的にする(再計算と byte 一致させるため)。"
  (:require [kagi.b64 :as b64]
            [kagi.crypto :as crypto]
            [kagi.digest :as digest]
            [kagi.key-registry :as key-registry]))

(def ^:private meta-keys #{:ledger/seq :ledger/prev-hash :ledger/hash :ledger/sig})

(defn- fact-bytes [fact]
  ;; 決定的シリアライズ: meta を除き、キー昇順で pr-str。
  ;;
  ;; **これが runtime を跨ぐ前提**: 同じ fact を JVM と ClojureScript の
  ;; `pr-str` が同じ文字列にしなければ、片方で署名した鎖がもう片方で検証に落ちる。
  ;; `sorted-map` で順序を固定しているのはそのためで、値に入れてよいのは
  ;; 両 runtime が同じ表記で印字するもの（keyword / string / 数値 / それらの
  ;; コレクション）だけ。host object を fact に入れてはいけない。
  (crypto/utf8-bytes (pr-str (into (sorted-map) (apply dissoc fact meta-keys)))))

(defn- link-hash [prev-hash fact]
  (digest/sha256-bytes
   (crypto/concat-bytes [(or prev-hash (crypto/empty-bytes)) (fact-bytes fact)])))

(defn make-entry
  "現 ledger に fact を継ぐ entry を作る。signer({:ed :mldsa} 秘密 bundle, provider 越し)が
  あれば hash に hybrid 署名する。"
  ([ledger fact provider signer]
   (make-entry ledger fact provider signer nil))
  ([ledger fact provider signer {:keys [key now]}]
   (when key (key-registry/authorize! key :sign now))
   (let [prev      (last ledger)
        prev-h-b64 (:ledger/hash prev)
        prev-h    (when prev-h-b64 (b64/decode prev-h-b64))
        h         (link-hash prev-h fact)
        sig       (when signer
                    (let [{:keys [ed mldsa]} (crypto/sign-with provider signer h)]
                      {:ed (b64/encode ed) :mldsa (b64/encode mldsa)}))]
    (cond-> (assoc fact :ledger/seq (count ledger)
                   :ledger/prev-hash prev-h-b64
                   :ledger/hash (b64/encode h))
      sig (assoc :ledger/sig sig)))))

(defn verify-chain
  "ledger 全体を検証 → {:ok? :broken-at}。各 entry で (1)hash 再計算一致 (2)prev-hash 連結
  (3)sig があれば actor の公開鍵で hybrid verify。pub-of: actor-did → {:ed :mldsa} 公開 bundle。
  entry に :ledger/sig が無い場合、pub-of がその actor の公開鍵を解決できなければ
  (= 一度も署名鍵を持たなかった actor)未署名として許容するが、pub-of が鍵を返すなら
  (= 署名できる/した actor)欠落は「元は署名されていたが後から剥がされた」改竄とみなし
  検知する — 単なる欠落有無だけを見ると、entry 内容/hash/prev-hash に一切触れずに
  :ledger/sig だけ dissoc する改竄を素通りさせてしまうため。"
  [ledger provider pub-of]
  (loop [prev-h (crypto/empty-bytes) prev-b64 nil i 0 items ledger]
    (if-let [e (first items)]
      (let [h (link-hash prev-h e)
            hash-ok? (= (b64/encode h) (:ledger/hash e))
            link-ok? (= prev-b64 (:ledger/prev-hash e))
            sig-ok?  (if-let [{:keys [ed mldsa]} (:ledger/sig e)]
                       (let [pub (pub-of (:actor e))]
                         (boolean
                          (and pub
                               (try (crypto/verify* provider pub h
                                                    {:ed (b64/decode ed)
                                                     :mldsa (b64/decode mldsa)})
                                    (catch #?(:clj Exception :cljs :default) _ false)))))
                       (nil? (pub-of (:actor e))))]
        (if (and hash-ok? link-ok? sig-ok?)
          (recur h (:ledger/hash e) (inc i) (rest items))
          {:ok? false :broken-at i
           :why (cond (not hash-ok?) :hash (not link-ok?) :prev-hash :else :sig)}))
      {:ok? true :broken-at nil})))
