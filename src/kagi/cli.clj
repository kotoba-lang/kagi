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
            [kagi.persist :as persist]
            [kagi.secret-store :as secret-store]
            [kagi.clipboard :as clipboard]
            [kagi.unlock :as unlock]
            [kagi.sync :as sync]
            [kagi.import.onepassword :as import-1p])
  (:import [java.time Instant]
           [java.util UUID]))

;; Vault home resolution (ADR-2607170500). The vault MUST NOT live in a repo
;; checkout / per-agent worktree: those get cleaned, re-cloned, or clobbered by
;; concurrent sessions — which is exactly how the fleet signing keys were lost
;; (2026-07-16). Resolution order:
;;   1. $KAGI_HOME               — explicit override
;;   2. ~/.kagi                  — canonical, stable across checkouts (default)
;;   3. ./.kagi (legacy in-repo) — read-only fallback, one-time auto-migrated
;;      to the canonical home on first use so nothing is silently lost.
(def ^:private legacy-dir ".kagi")

(defn- home-dir []
  (or (not-empty (System/getenv "KAGI_HOME"))
      (str (System/getProperty "user.home") "/.kagi")))

(defn- migrate-legacy!
  "One-time: if the canonical home has no vault but a legacy ./.kagi vault
  exists, COPY it up (not move — a concurrent session may still hold the legacy
  checkout) so the canonical home becomes authoritative without data loss."
  [home]
  (let [home-vault   (java.io.File. (str home "/vault.edn"))
        legacy-vault (java.io.File. (str legacy-dir "/vault.edn"))]
    (when (and (not (.exists home-vault)) (.exists legacy-vault))
      (.mkdirs (java.io.File. ^String home))
      (doseq [f ["vault.edn" "identity.edn"]]
        (let [src (java.io.File. (str legacy-dir "/" f))]
          (when (.exists src)
            (java.nio.file.Files/copy (.toPath src)
                                      (.toPath (java.io.File. (str home "/" f)))
                                      (into-array java.nio.file.CopyOption
                                                  [java.nio.file.StandardCopyOption/COPY_ATTRIBUTES])))))
      (binding [*out* *err*]
        (println "kagi: migrated legacy ./.kagi vault ->" home
                 "(canonical). The in-repo ./.kagi is now deprecated; its copy remains untouched.")))))

(def ^:private dir
  (let [h (home-dir)]
    (migrate-legacy! h)
    h))
(def ^:private id-path (str dir "/identity.edn"))
(def ^:private vault-path (str dir "/vault.edn"))
(def ^:private aud "https://kotobase.net")
(def ^:private default-identity-ref "keychain://com.junkawasaki.kagi/identity")
(def ^:private default-unlock-ref "keychain://com.junkawasaki.kagi/vmk-unlock")

(defn- die [& msg] (binding [*out* *err*] (apply println msg)) (System/exit 1))

(defn- passphrase [confirm?]
  (or (System/getenv "KAGI_MASTER")
      (if-let [c (System/console)]
        (let [a (String. (.readPassword c "master passphrase: " (object-array 0)))]
          (when confirm?
            (let [b (String. (.readPassword c "confirm: " (object-array 0)))]
              (when-not (= a b) (die "passphrase mismatch"))))
          a)
        (do
          (binding [*out* *err*] (print "master passphrase: ") (flush))
          (or (read-line)
              (die "KAGI_MASTER required in non-interactive mode"))))))

(defn- identity-options []
  (let [ref (or (not-empty (System/getenv "KAGI_IDENTITY_REF"))
                (when (= "keychain" (System/getenv "KAGI_IDENTITY_STORE"))
                  default-identity-ref))]
    (when ref
      {:secret-ref ref
       :secret-store (secret-store/store-for-ref ref)})))

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

(defn- unlock-vmk-auto [p meta]
  (if-let [pass (System/getenv "KAGI_MASTER")]
    (unlock-vmk p pass meta)
    (or (unlock/unlock-with-os-keychain p meta (not-empty (System/getenv "KAGI_UNLOCK_REF")))
        (unlock-vmk p (passphrase false) meta))))

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
(defn- parse-long* [s default]
  (if (str/blank? (str s))
    default
    (try
      (Long/parseLong (str s))
      (catch NumberFormatException _
        (die "expected integer, got:" s)))))

;; ───────── commands ─────────

(defn- cmd-init [p id]
  ;; Guard against clobbering an existing vault OR silently orphaning items
  ;; behind a fresh identity (a re-init mints a new did:key → new graph →
  ;; the previous vault's items become unreachable even if the file survives).
  ;; This is the failure mode that lost the fleet keys on 2026-07-16.
  (when (persist/load* vault-path)
    (die (str "vault already exists at " vault-path
              " — refusing to re-init (would orphan existing items). "
              "To start over, move it aside explicitly first.")))
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
        vmk  (unlock-vmk-auto p (:meta data))
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

(defn- cmd-copy [p id args]
  (let [name (first (positional args))
        purpose (or (not-empty (arg-val args "--purpose"))
                    (die "usage: kagi copy <name> --purpose <purpose> [--ttl seconds]"))
        ttl-sec (parse-long* (arg-val args "--ttl") 45)]
    (when-not name (die "usage: kagi copy <name> --purpose <purpose> [--ttl seconds]"))
    (when-not (pos? ttl-sec) (die "--ttl must be positive"))
    (with-vault p
      (fn [st vmk]
        (when-not (store/item st name) (die "no such item:" name))
        (let [r (run-op! p id st vmk {:op :item/reveal :item-id name} purpose)
              pt (get-in r [:result :plaintext])]
          (if pt
            (let [secret (String. ^bytes pt "UTF-8")
                  result (clipboard/copy-secret-with-ttl!
                          (clipboard/macos-clipboard)
                          secret
                          {:ttl-ms (* ttl-sec 1000)})]
              (println (pr-str (merge result
                                      {:item name
                                       :purpose purpose
                                       :provider :macos-pbcopy
                                       :approval :human-approved
                                       :secret? false}))))
            (die "reveal denied:" (get-in r [:result :effect]))))))))

(defn- cmd-ls []
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))]
    (doseq [it (sort-by :item/id (vals (:items data)))]
      (println (format "%-24s %-12s %-16s v%s" (:item/id it) (:item/compartment it)
                       (str (or (:item/category it) "")) (:item/version it))))))

(defn- cmd-import-onepassword [p id args]
  (let [path (first (positional args))
        comp-override (arg-val args "-c")
        include-archived? (some #{"--include-archived"} args)]
    (when-not path (die "usage: kagi import onepassword <file.1pux> [-c compartment] [--include-archived]"))
    (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
          existing-ids (set (keys (:items data)))
          {:keys [warnings entries]} (import-1p/plan
                                       path
                                       {:existing-ids existing-ids
                                        :include-archived? (boolean include-archived?)
                                        :compartment-fn (if comp-override
                                                          (constantly comp-override)
                                                          import-1p/slugify)})]
      (doseq [w warnings] (binding [*out* *err*] (println "warn:" w)))
      (with-vault p
        (fn [st vmk]
          (doseq [{:keys [item-id compartment category plaintext title]} entries]
            (run-op! p id st vmk {:op :item/create :item-id item-id :compartment compartment
                                  :category category :plaintext plaintext}
                    :cli-import-onepassword)
            (println "imported" item-id (str "\"" title "\"") "→" compartment (str category)))))
      (println (count entries) "item(s) imported from" path))))

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

(defn- cmd-identity-migrate [_p id args]
  (let [ref (or (arg-val args "--ref")
                (not-empty (System/getenv "KAGI_IDENTITY_REF"))
                default-identity-ref)
        raw (persist/load* id-path)]
    (when-not raw (die "no identity at" id-path))
    (if (identity/secret-backed-identity? raw)
      (println "identity already secret-backed:" (secret-store/redact-ref (:secret-ref raw)))
      (do
        (identity/migrate-identity-secret! id-path id (secret-store/store-for-ref ref) ref)
        (println "identity secret keys moved to" (secret-store/redact-ref ref))
        (println "identity.edn now stores public metadata + secret ref only")))))

(defn- cmd-unlock-enable-keychain [p _id args]
  (let [ref (or (arg-val args "--ref")
                (not-empty (System/getenv "KAGI_UNLOCK_REF"))
                default-unlock-ref)
        data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        pass (passphrase false)
        vmk (unlock-vmk p pass (:meta data))
        store (secret-store/store-for-ref ref)
        wrap (unlock/os-keychain-wrap p vmk store ref)
        meta (unlock/add-wrap (:meta data) wrap)
        st (load-store (dissoc data :meta))]
    (save-store! st meta)
    (println (pr-str {:ok? true
                      :enabled :os-keychain
                      :ref (secret-store/redact-ref ref)
                      :secret? false
                      :passphrase-recovery? true}))))

(defn- cmd-unlock-status []
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))]
    (println (pr-str (unlock/status (:meta data))))))

;; ───────── cloud sync (kotobase.net) ─────────

(defn- cmd-push [id args]
  (when-not (persist/load* vault-path) (die "no vault — run: kagi init"))
  (let [pod (not-empty (arg-val args "--pod"))
        r (sync/push! {:id id :vault-path vault-path :pod pod})]
    (println (pr-str (assoc r :ok? true :secret? false)))))

(defn- cmd-pull [id args]
  (let [pod (not-empty (arg-val args "--pod"))
        r (sync/pull! {:id id :vault-path vault-path :pod pod})]
    (if (:seq r)
      (println (pr-str (assoc r :ok? true :backup (str vault-path ".bak") :secret? false)))
      (die "cloud has no vault snapshot for this graph yet — run: kagi push"))))

(defn- cmd-sync [id args]
  (let [pod (not-empty (arg-val args "--pod"))
        pulled (sync/pull! {:id id :vault-path vault-path :pod pod})
        pushed (sync/push! {:id id :vault-path vault-path :pod pod
                            :expected-seq (or (:seq pulled) 0)})]
    (println (pr-str {:ok? true :pulled (:seq pulled) :pushed (:seq pushed) :secret? false}))))

(defn- help []
  (println (str/trim "
kagi — 自己主権・対量子(PQC) secrets vault (op 相当)

  kagi init                 鍵生成 + vault 作成
  kagi add <name> [-c c]    secret を stdin から登録   (printf '%s' s | kagi add foo)
  kagi get <name>           secret を復号して stdout へ
  kagi copy <name> --purpose p [--ttl 45]
                            secret を stdout に出さず clipboard へ一時コピー
  kagi ls                   item 一覧
  kagi import onepassword <file.1pux> [-c compartment] [--include-archived]
                            1Password の 1PUX export を取り込む(kagitaba 経由)
  kagi rotate <name>        DEK 回転(再封緘)
  kagi log                  監査台帳を検証して表示
  kagi whoami               自分の did:key / IPNS graph
  kagi identity-migrate     identity 秘密鍵を OS keychain へ移す
  kagi unlock-enable-keychain [--ref keychain://service/account]
                            VMK unlock を OS keychain に追加(passphrase は recovery として残す)
  kagi unlock-status        VMK unlock methods を metadata のみ表示
  kagi push [--pod URL]     暗号化 vault を kotobase.net へ同期(cloud 永続化)
  kagi pull [--pod URL]     cloud の vault を取得(現ローカルは .bak に退避)
  kagi sync [--pod URL]     pull(あれば)→ push。iCloud Keychain 型 E2E 同期

passphrase は環境変数 KAGI_MASTER か端末プロンプト。
KAGI_UNLOCK_REF=keychain://... で device unlock ref を指定。
KAGI_IDENTITY_STORE=keychain で新規 identity 秘密鍵を Apple Keychain に保存。
鍵/vault は $KAGI_HOME(既定 ~/.kagi)。repo checkout の外なので checkout/worktree
の掃除・再clone・並行セッションで壊れない(ADR-2607170500)。旧 ./.kagi があれば
初回に ~/.kagi へ自動移行(copy)する。")))

(defn -main [& args]
  (if (or (empty? args)
          (#{"help" "-h" "--help"} (first args))
          (some #{"-h" "--help"} args))
    (help)
    (let [p  (crypto/jvm-provider)
          id (identity/load-or-create-identity! id-path p (identity-options))]
      (case (first args)
        "init"   (cmd-init p id)
        "add"    (cmd-add p id args)
        "get"    (cmd-get p id args)
        "copy"   (cmd-copy p id args)
        "ls"     (cmd-ls)
        "import" (case (second args)
                   "onepassword" (cmd-import-onepassword p id (rest args))
                   (die "usage: kagi import onepassword <file.1pux> [-c compartment] [--include-archived]"))
        "rotate" (cmd-rotate p id args)
        "log"    (cmd-log p id)
        "whoami" (cmd-whoami id)
        "identity-migrate" (cmd-identity-migrate p id args)
        "unlock-enable-keychain" (cmd-unlock-enable-keychain p id args)
        "unlock-status" (cmd-unlock-status)
        "push"   (cmd-push id args)
        "pull"   (cmd-pull id args)
        "sync"   (cmd-sync id args)
        (help))))
  (flush)
  ;; futures (clipboard/process slurps) leave non-daemon pool threads alive;
  ;; without this the JVM lingers ~60s after the command completes.
  (shutdown-agents))
