(ns kagi.cli
  "`kagi` CLI — 1Password の `op` 相当。自己主権 + 対量子(PQC) vault をコマンドで操作する。

  保存先(カレント直下):
    .kagi/identity.edn  — actor の Ed25519/ML-DSA 鍵 + KEM 受信鍵(gitignore)
    .kagi/vault.edn     — 暗号文 item + wrap 済み鍵 + 台帳(平文・素 VMK は出ない)

  unlock: master passphrase → Argon2id(salt) → KEK → VMK(wrap 解除)。passphrase は
  環境変数 KAGI_MASTER か、無ければ端末プロンプト。

  使い方:
    kagi init                       # 鍵生成 + vault 作成(passphrase 設定)
    kagi add <name> [-c comp]       # secret を stdin/プロンプトから登録
    kagi get <name>                 # secret を復号して stdout に出す
    kagi ls                         # item 一覧(復号しない)
    kagi rotate <name>              # DEK を回転(再封緘)
    kagi log                        # 監査台帳(hybrid 署名 + ハッシュ鎖)を検証して表示
    kagi whoami                     # 自分の did:key / IPNS graph"
  (:require [clojure.string :as str]
            [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.crypto :as crypto]
            [kagi.cacao :as cacao]
            [kagi.ledger :as ledger]
            [kagi.identity :as identity]
            [kagi.persist :as persist])
  (:import [java.time Instant]
           [java.util UUID]))

(def ^:private dir ".kagi")
(def ^:private id-path (str dir "/identity.edn"))
(def ^:private vault-path (str dir "/vault.edn"))
(def ^:private aud "https://kotobase.net")

(defn- die [& msg] (binding [*out* *err*] (apply println msg)) (System/exit 1))

(defn- passphrase [confirm?]
  (or (System/getenv "KAGI_MASTER")
      (if-let [c (System/console)]
        (let [a (String. (.readPassword c "master passphrase: " (object-array 0)))]
          (when confirm?
            (let [b (String. (.readPassword c "confirm: " (object-array 0)))]
              (when-not (= a b) (die "passphrase mismatch"))))
          a)
        (do (binding [*out* *err*] (print "master passphrase: ") (flush)) (read-line)))))

;; ───────── VMK unlock ─────────

(defn- derive-kek [p pass salt]
  (crypto/argon2id p (.getBytes ^String pass "UTF-8") salt {:m-kb 262144 :t 3 :p 4}))

(defn- new-vmk-meta [p pass]
  (let [vmk  (crypto/rand-bytes p 32)
        salt (crypto/rand-bytes p 16)
        kek  (derive-kek p pass salt)
        n    (crypto/rand-bytes p 12)]
    {:vmk vmk :meta {:salt salt :nonce n :wrapped (crypto/aead-seal p kek n vmk (byte-array 0))}}))

(defn- unlock-vmk [p pass {:keys [salt nonce wrapped]}]
  (try (crypto/aead-open p (derive-kek p pass salt) nonce wrapped (byte-array 0))
       (catch Exception _ (die "wrong passphrase (VMK unlock failed)"))))

;; ───────── vault / actor ─────────

(defn- load-store [data]
  (store/mem-store (or data {})))

(defn- save-store! [st meta]
  (let [a @(:a st)]
    (persist/save! vault-path (assoc (select-keys a [:members :items :grants :blocks :ledger])
                                     :meta meta))))

(defn- self-cacao [id]
  (cacao/mint id {:cap :cap/admin :scope (:graph id)}
              {:aud aud :nonce (str (UUID/randomUUID))
               :issued-at (str (Instant/now)) :expiry (str (.plusSeconds (Instant/now) 3600))}))

(defn- context [id vmk purpose]
  {:did (:did id) :role :owner :phase 3 :vmk vmk :purpose purpose
   :aud aud :cacao (self-cacao id) :register (identity/member-record id :owner)})

(defn- run-op! [p id store vmk req purpose]
  (let [actor (op/build store {:crypto p :signer (identity/sign-secret id)})]
    (:state (g/run* actor {:request req :context (context id vmk purpose)}
                    {:thread-id (str (:op req) "-" (:item-id req) "-" (UUID/randomUUID))}))))

;; ───────── opts ─────────

(defn- arg-val [args flag] (->> args (drop-while #(not= flag %)) second))
(defn- positional [args] (remove #(str/starts-with? % "-") (rest args)))

;; ───────── commands ─────────

(defn- cmd-init [p id]
  (when (persist/load* vault-path) (die "vault already exists at" vault-path))
  (let [pass (passphrase true)
        {:keys [meta]} (new-vmk-meta p pass)
        st (load-store {})]
    (store/put-member! st (identity/member-record id :owner))
    (save-store! st meta)
    (println "vault created:" vault-path)
    (println "did   :" (:did id))
    (println "graph :" (:graph id))))

(defn- with-vault [p f]
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        pass (passphrase false)
        vmk  (unlock-vmk p pass (:meta data))
        st   (load-store (dissoc data :meta))]
    (f st vmk)
    (save-store! st (:meta data))))

(defn- cmd-add [p id args]
  (let [name (first (positional args))
        comp (or (arg-val args "-c") "personal")]
    (when-not name (die "usage: kagi add <name> [-c compartment]"))
    (with-vault p
      (fn [st vmk]
        (let [secret (str/trim (slurp *in*))]
          (when (str/blank? secret) (die "empty secret on stdin"))
          (run-op! p id st vmk {:op :item/create :item-id name :compartment comp
                                :plaintext (.getBytes secret "UTF-8")} :cli-add)
          (println "stored" name "in" comp))))))

(defn- cmd-get [p id args]
  (let [name (first (positional args))]
    (when-not name (die "usage: kagi get <name>"))
    (with-vault p
      (fn [st vmk]
        (when-not (store/item st name) (die "no such item:" name))
        (let [r (run-op! p id st vmk {:op :item/reveal :item-id name} :cli-get)
              pt (get-in r [:result :plaintext])]
          (if pt (print (String. ^bytes pt "UTF-8"))
              (die "reveal denied:" (get-in r [:result :effect]))))))))

(defn- cmd-ls []
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))]
    (doseq [it (sort-by :item/id (vals (:items data)))]
      (println (format "%-24s %s  v%s" (:item/id it) (:item/compartment it) (:item/version it))))))

(defn- cmd-rotate [p id args]
  (let [name (first (positional args))]
    (when-not name (die "usage: kagi rotate <name>"))
    (with-vault p
      (fn [st vmk]
        (when-not (store/item st name) (die "no such item:" name))
        (run-op! p id st vmk {:op :item/rotate :item-id name} :cli-rotate)
        (println "rotated" name "→ v" (:item/version (store/item st name)))))))

(defn- cmd-log [p id]
  (let [data (or (persist/load* vault-path) (die "no vault"))
        led  (:ledger data)
        r    (ledger/verify-chain led p (constantly (identity/sign-public id)))]
    (doseq [e led]
      (println (format "%3d  %-14s %-14s %s" (:ledger/seq e) (name (or (:t e) "?"))
                       (str (:op e)) (or (:disposition e) ""))))
    (println "chain:" (if (:ok? r) "OK (hybrid-signed, hash-chained)" (str "BROKEN at " (:broken-at r))))))

(defn- cmd-whoami [id]
  (println "did   :" (:did id))
  (println "graph :" (:graph id)))

(defn- help []
  (println (str/trim "
kagi — 自己主権・対量子(PQC) secrets vault (op 相当)

  kagi init                 鍵生成 + vault 作成
  kagi add <name> [-c c]    secret を stdin から登録   (printf '%s' s | kagi add foo)
  kagi get <name>           secret を復号して stdout へ
  kagi ls                   item 一覧
  kagi rotate <name>        DEK 回転(再封緘)
  kagi log                  監査台帳を検証して表示
  kagi whoami               自分の did:key / IPNS graph

passphrase は環境変数 KAGI_MASTER か端末プロンプト。鍵/vault は ./.kagi/(gitignore)。")))

(defn -main [& args]
  (let [p  (crypto/jvm-provider)
        id (identity/load-or-create-identity! id-path p)]
    (case (first args)
      "init"   (cmd-init p id)
      "add"    (cmd-add p id args)
      "get"    (cmd-get p id args)
      "ls"     (cmd-ls)
      "rotate" (cmd-rotate p id args)
      "log"    (cmd-log p id)
      "whoami" (cmd-whoami id)
      (help))
    (flush)))
