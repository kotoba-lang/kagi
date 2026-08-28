(ns kagi.cli
  "`kagi` CLI — 1Password の `op` 相当。自己主権 + 対量子(PQC) vault をコマンドで操作する。

  保存先(カレント直下):
    .kagi/identity.edn  — actor の Ed25519/ML-DSA 鍵 + KEM 受信鍵(gitignore)
    .kagi/vault.edn     — 暗号文 item + wrap 済み鍵 + 台帳(平文・素 VMK は出ない)

  unlock: master passphrase → Argon2id(salt) → KEK → VMK(wrap 解除)。passphrase は
  環境変数 KAGI_MASTER か、無ければ端末プロンプト。

  使い方:
    kagi init                       # 鍵生成 + vault 作成(passphrase 設定)
    kagi add <name> [-c comp] [--category login] [--record refs.edn]
                                    # secret を stdin/プロンプトから登録
                                    # --category は kagitaba の正準 keyword で検証する
                                    # --record は item id 等の非機微参照だけを EDN に記録
                                    #   (ls による総当たり列挙を避けて狙い撃ちで引くため)
    kagi get <name>                 # secret を復号して stdout に出す
    kagi fill <name> --purpose <p> --selector <css> --cdp <ws>
                                    # ブラウザの入力欄へ直接注入(clipboard 不使用、
                                    # 値は argv にも JS 式にも載らない)
    kagi ls                         # item 一覧(復号しない)
    kagi rotate <name>              # DEK を回転(再封緘)
    kagi log                        # 監査台帳(hybrid 署名 + ハッシュ鎖)を検証して表示
    kagi whoami                     # 自分の did:key / IPNS graph"
  (:require [clojure.edn :as edn]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.crypto :as crypto]
            [kagi.cacao :as cacao]
            [kagi.ledger :as ledger]
            [kagi.identity :as identity]
            [kagi.persist :as persist]
            [kagi.device :as device]
            [kagi.agent :as agent]
            [kagi.agent-docs :as agent-docs]
            [kagi.agent-http :as agent-http]
            [kagi.agent-protocol :as agent-proto]
            [kagi.agent-service :as agent-service]
            [kagi.secret-store :as secret-store]
            [kagi.clipboard :as clipboard]
            [kagi.autofill :as autofill]
            [kagi.unlock :as unlock]
            [kagi.recovery :as recovery]
            [kagi.recovery-io :as recovery-io]
            [kagi.passkey :as passkey]
            [kagi.passkey-bridge :as passkey-bridge]
            [kagi.ui.actions :as ui-actions]
            [kagi.ui.server :as ui-server]
            [kagi.sync :as sync]
            [kagi.import.onepassword :as import-1p]
            [kagitaba.category :as kcat])
  (:import [java.time Instant]
           [java.awt Desktop Desktop$Action]
           [java.net URI]
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
    ;; `:rotation-events` was missing here, so every event `store/commit-rekey!`
    ;; minted (rotation and `:share/revoke`) was written into the in-memory
    ;; store and then dropped on the way to disk — the item kept pointing at an
    ;; `:item/rotation-event` id that nothing resolved.
    (persist/save! vault-path (assoc (select-keys a [:members :items :grants :blocks
                                                     :ledger :rotation-events])
                                     :meta meta))))

(defn- self-cacao [id]
  (cacao/mint id {:cap :cap/admin :scope (:graph id)}
              {:aud aud :nonce (str (UUID/randomUUID))
               :issued-at (str (Instant/now)) :expiry (str (.plusSeconds (Instant/now) 3600))}))

(defn- context [id vmk purpose]
  ;; `:now` is not decoration: `do-effect` stamps `:item/key-created-at` with
  ;; it (it was nil for every item this CLI ever wrote), and
  ;; `key-registry/authorize!` fails closed without a current time, which is
  ;; what `:share/grant` needs to check a recipient's KEM key lifecycle.
  {:did (:did id) :role :owner :phase 3 :vmk vmk :purpose purpose
   :now (str (Instant/now))
   :aud aud :cacao (self-cacao id) :register (identity/member-record id :owner)})

(defn- run-op! [p id store vmk req purpose]
  (let [actor (op/build store {:crypto p :signer (identity/sign-secret id)})]
    (:state (g/run* actor {:request req :context (context id vmk purpose)}
                    {:thread-id (str (:op req) "-" (:item-id req) "-" (UUID/randomUUID))}))))

(defn- run-op-with!
  "`run-op!` plus two things the sharing commands need.

  `extra` merges into the context (`:consent?` for `:share/grant` — the owner
  typing the command IS the consent the governor asks for).

  `:signer-key` is passed to `op/build` because `:effect` REFUSES to re-key
  without one, and `:share/revoke` re-keys. Note this is scoped to these
  commands on purpose: `run-op!` still omits it, so `kagi rotate` still throws
  `rotation requires an active managed authority signer` — a pre-existing gap
  reported in ADR-2608281100 rather than quietly widened here, since passing a
  key makes `key-registry/authorize!` run on EVERY ledger entry and that is a
  change to commands this work has no business touching."
  [p id store vmk req purpose extra]
  (let [actor (op/build store {:crypto p
                               :signer (identity/sign-secret id)
                               :signer-key (:signing-key id)})]
    (:state (g/run* actor {:request req :context (merge (context id vmk purpose) extra)}
                    {:thread-id (str (:op req) "-" (:item-id req) "-" (UUID/randomUUID))}))))

;; ───────── opts ─────────

(defn- arg-val [args flag] (->> args (drop-while #(not= flag %)) second))
(defn- arg-vals
  "Every value of a flag that may repeat (`--compartment a --compartment b`).
  `arg-val` returns the first and silently loses the rest, which for a scope
  flag would mean granting less than the operator asked for without saying so."
  [args flag]
  (->> args (partition 2 1) (keep (fn [[a b]] (when (= flag a) b))) vec))
(defn- positional [args] (remove #(str/starts-with? % "-") (rest args)))
(defn- parse-long* [s default]
  (if (str/blank? (str s))
    default
    (try
      (Long/parseLong (str s))
      (catch NumberFormatException _
        (die "expected integer, got:" s)))))

(defn- object-backend
  "The object-store wiring, or nil when it is not configured.

  `requiring-resolve` rather than a top-level require: io-storj is an extra-dep
  of the `:cli` and `:test` aliases, not of the library, so `kagi.cli` has to
  stay loadable without it. You need the wiring dependency when you use the
  wiring — see `kagi.object-store`'s ns docstring."
  []
  (try
    ((requiring-resolve 'kagi.object-store/from-env)
     {:prefix (not-empty (System/getenv "KAGI_OBJECT_PREFIX"))})
    (catch java.io.FileNotFoundException _
      (die (str "object backend needs io-storj on the classpath — run through "
                "bin/kagi (the :cli alias carries it)")))))

(defn- sync-backend
  "Which backend `push`/`pull`/`sync` use.

  Explicit `--backend` wins, then `KAGI_SYNC_BACKEND`, then: the object store
  if it is configured, otherwise kotobase. Auto-selecting on configuration is
  the useful default — nobody sets four bucket variables by accident — and the
  chosen backend is echoed in every command's output so it is never a guess.

  NOTE (2026-08-28): the kotobase backend currently answers 401 for every call.
  The graph-database runs with `KOTOBASE_BISCUIT_AUTH_MODE=required` and
  refuses any non-Biscuit Authorization before the CACAO branch is reached; the
  CACAO this repo mints is correct (ADR-2608281200). That is why the object
  backend exists, and why it is preferred when configured."
  [args]
  (let [asked (or (not-empty (arg-val args "--backend"))
                  (not-empty (System/getenv "KAGI_SYNC_BACKEND")))]
    (case (or asked "auto")
      "kotobase" {:backend :kotobase}
      "object" (or (some-> (object-backend) (assoc :backend :object))
                   (die (str "object backend is not configured. 必要な環境変数:\n"
                             @(requiring-resolve 'kagi.object-store/env-help))))
      "auto" (or (some-> (object-backend) (assoc :backend :object))
                 {:backend :kotobase})
      (die "usage: --backend kotobase|object"))))

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

(defn- record-reference!
  "Append or update a NON-SECRET reference to `path` so the item can be found
  later by id.

  A vault item nobody recorded is one forgotten id away from unreachable, and
  `ls` cannot be the fallback: enumerating a vault to locate one item is the
  exhaustive credential access the fleet's own floor forbids. A targeted
  lookup needs a known id, so the id has to be written down — and a step that
  has to be remembered separately is a step that gets skipped, which is why
  this happens inside the same command that creates the secret rather than
  afterwards by hand.

  Only these five fields are ever written. There is no path by which a secret
  reaches this function: it is not passed one."
  [path {:keys [item compartment category did now]}]
  (let [existing (if (.exists (java.io.File. ^String path))
                   (let [v (edn/read-string (slurp path))]
                     (if (map? v) v
                         (throw (ex-info "record target is not a map" {:path path}))))
                   {})
        record {:credential/item item
                :credential/compartment compartment
                :credential/category category
                :credential/vault-did did
                :credential/recorded-at now}
        merged (assoc-in existing [:credentials item]
                         (merge (get-in existing [:credentials item]) record))
        ;; Written through a temp file and renamed: a half-written registry is
        ;; worse than none, because it reads as authoritative.
        tmp (str path ".tmp")]
    (spit tmp (with-out-str
                (println ";; kagi credential references — NO SECRET VALUES.")
                (println ";; Written by `kagi add --record`. Safe to commit.")
                (pprint/pprint merged)))
    (.renameTo (java.io.File. tmp) (java.io.File. ^String path))
    record))

(defn- cmd-add [p id args]
  (let [name (first (positional args))
        comp (or (arg-val args "-c") "personal")
        record-path (arg-val args "--record")
        ;; `:item/category` is a non-sensitive plaintext index (vault.cljc) and
        ;; `:item/create` has always accepted it — `import onepassword` sets it
        ;; from the 1PUX category. Only `add` had no way to pass one, so every
        ;; item created by hand was uncategorised and `ls` showed a blank
        ;; column. An account stored as an untyped blob is not managed; it is
        ;; just a string somebody has to remember the shape of.
        cat (some-> (arg-val args "--category") keyword)]
    (when-not name
      (die "usage: kagi add <name> [-c compartment] [--category kind] [--record path.edn]"))
    ;; Validated against kagitaba's taxonomy rather than accepted freely: a
    ;; typo'd `--category logon` would file the item under a category nothing
    ;; else uses, and the index is only worth having if it is shared.
    (when (and cat (not (kcat/known? cat)))
      (die (str "unknown category: " cat
                " — kagitaba knows " (pr-str (sort (map name kcat/known-keys))))))
    (with-vault p
      (fn [st vmk]
        (let [secret (str/trim (slurp *in*))]
          (when (str/blank? secret) (die "empty secret on stdin"))
          (run-op! p id st vmk (cond-> {:op :item/create :item-id name
                                        :compartment comp
                                        :plaintext (.getBytes secret "UTF-8")}
                                 cat (assoc :category cat))
                   :cli-add)
          (println "stored" name "in" comp (if cat (str "as " cat) ""))
          ;; After the store, never before: a reference to an item that failed
          ;; to save would send a later reader to fetch something absent.
          (when record-path
            (let [r (record-reference! record-path
                                       {:item name :compartment comp
                                        :category cat :did (:did id)
                                        :now (str (Instant/now))})]
              (println "recorded" (:credential/item r) "->" record-path))))))))

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
            (let [secret (String. ^bytes pt "UTF-8")]
              ;; Printed BEFORE the wait, so the operator can paste while this
              ;; holds custody. It used to print and exit, which killed the
              ;; daemon thread that was supposed to clear the clipboard and
              ;; left the secret pasteable indefinitely.
              (println (pr-str {:item name :purpose purpose
                                :ttl-ms (* ttl-sec 1000)
                                :provider :macos-pbcopy
                                :approval :human-approved
                                :holding-until-ttl? true
                                :secret? false}))
              (flush)
              (let [result (clipboard/copy-secret-with-ttl!
                            (clipboard/macos-clipboard)
                            secret
                            {:ttl-ms (* ttl-sec 1000) :block? true})]
                (println (pr-str (select-keys result
                                              [:cleared? :clear-mechanism
                                               :ttl-ms])))))
            (die "reveal denied:" (get-in r [:result :effect]))))))))

(defn- cmd-fill [p id args]
  (let [name (first (positional args))
        purpose (or (not-empty (arg-val args "--purpose"))
                    (die "usage: kagi fill <name> --purpose <purpose> --selector <css> [--cdp <ws-url>] [--page <url-substring>]"))
        selector (or (not-empty (arg-val args "--selector"))
                     (die "--selector is required — a fill aimed at the wrong field is a password typed somewhere it does not belong"))
        cdp (or (not-empty (arg-val args "--cdp"))
                (die "--cdp <ws-url> is required (get it with: agent-browser get cdp-url)"))
        page-match (arg-val args "--page")]
    (when-not name (die "usage: kagi fill <name> --purpose <purpose> --selector <css> --cdp <ws-url>"))
    (with-vault p
      (fn [st vmk]
        (when-not (store/item st name) (die "no such item:" name))
        (let [r (run-op! p id st vmk {:op :item/reveal :item-id name} purpose)
              pt (get-in r [:result :plaintext])]
          (if-not pt
            (die "reveal denied:" (get-in r [:result :effect]))
            (let [base (autofill/debug-base cdp)
                  targets (autofill/page-targets base)
                  page (or (autofill/pick-page targets page-match)
                           (die (str "no debuggable page"
                                     (when page-match (str " matching " page-match)))))
                  out (autofill/fill-secret!
                       {:page-ws (:webSocketDebuggerUrl page)
                        :selector selector
                        :secret (String. ^bytes pt "UTF-8")})]
              ;; Lengths, never the value: enough to tell a landed write from
              ;; a truncated one, not enough to disclose a character of it.
              (println (pr-str (assoc (select-keys out [:ok? :verdict :expected-length
                                                        :observed-length])
                                      :item name
                                      :purpose purpose
                                      :selector selector
                                      :page (:url page)
                                      :approval :human-approved
                                      :secret? false)))
              ;; Nonzero on anything but :match, so a caller can gate on it
              ;; rather than reading the verdict by eye.
              (when-not (:ok? out) (System/exit 1)))))))))

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

(defn- cmd-device-request
  "On the NEW device. Prints the request to carry to the enrolled device, and
  the FINGERPRINT to read aloud. No vault is needed here — this machine has
  nothing yet, which is the point."
  [p args]
  (let [{:keys [request fingerprint]} (device/make-request!
                                       p {:label (arg-val args "--label")})
        out (or (arg-val args "--out") "device-request.edn")]
    (spit out (pr-str request))
    (println (pr-str {:ok? true :wrote out
                      :device-id (:device/id request)
                      :fingerprint fingerprint
                      :next (str "enrolled 端末で: kagi device grant " out
                                 " --fingerprint " fingerprint)}))))

(defn- cmd-device-grant
  "On the ENROLLED device. Encapsulates the VMK to the requesting device.

  `--fingerprint` is REQUIRED and must match what the new device printed. It
  is the only thing that catches a substituted public key, and a check that
  can be skipped is not a check."
  [p args]
  ;; args are ["device" "grant" "<file>" ...] -- the file is the THIRD element.
  (let [file (or (nth args 2 nil) (die "usage: kagi device grant <request.edn> --fingerprint FP"))
        request (edn/read-string (slurp file))
        confirmed (arg-val args "--fingerprint")
        data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        vmk (unlock-vmk-auto p (:meta data))
        ttl (some-> (arg-val args "--ttl") Long/parseLong)
        grant (try
                (device/make-grant p vmk request confirmed
                                   {:ttl-sec (or ttl device/default-ttl-sec)})
                (catch clojure.lang.ExceptionInfo e
                  (die (str "device grant refused: "
                            (pr-str (:device/errors (ex-data e)))))))
        out (or (arg-val args "--out") "device-grant.edn")]
    (spit out (pr-str grant))
    (println (pr-str {:ok? true :wrote out
                      :device-id (:grant/device-id grant)
                      :expires-at (:grant/expires-at grant)
                      :secret? false
                      :note "grant は短命・単回限り。使ったら消すこと"}))))

(defn- cmd-device-accept
  "On the NEW device. Recovers the VMK, adds this machine's own keychain wrap,
  records the device, and writes the vault. The grant is not needed again."
  [p args]
  (let [file (or (nth args 2 nil) (die "usage: kagi device accept <grant.edn>"))
        grant (edn/read-string (slurp file))
        data (or (persist/load* vault-path)
                 (die "no vault — run: kagi pull first (grant unlocks it, it does not create it)"))
        {:keys [vmk wrap device-id]}
        (try (device/accept-grant! p grant {})
             (catch clojure.lang.ExceptionInfo e
               (die (str "device accept refused: " (pr-str (:device/errors (ex-data e)))))))
        meta (-> (:meta data)
                 (unlock/add-wrap wrap)
                 (device/register {:device-id device-id
                                   :label (:grant/label grant)
                                   :fingerprint (:grant/fingerprint grant)
                                   :wrap-ref (:ref wrap)}))
        st (load-store (dissoc data :meta))]
    (save-store! st meta)
    (println (pr-str {:ok? true :device-id device-id
                      :unlock (unlock/status meta)
                      :secret? false
                      :next (str "この grant ファイルを削除すること: " file)}))
    ;; the VMK is live in this process only; nothing writes it out
    (when vmk :ok)))

(defn- cmd-device-ls [_p]
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))]
    (println (pr-str (device/status (:meta data))))))

(defn- cmd-device-revoke [_p args]
  (let [device-id (or (nth args 2 nil) (die "usage: kagi device revoke <device-id>"))
        data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        meta (device/revoke-device (:meta data) device-id)
        st (load-store (dissoc data :meta))]
    (save-store! st meta)
    (println (pr-str {:ok? true :revoked device-id
                      :unlock (unlock/status meta)
                      :warning "これはアクセス一覧の変更であって、その端末が既に得た VMK を
                                取り消すものではない。紛失端末は vault 侵害として扱い、
                                secret 自体を rotate すること"}))))


;; ───────── agent principals ─────────
;;
;; The verbs mirror `device` (request → approve) because it is the same
;; problem with a different second party, and an operator who learned one
;; should not have to learn the other. What differs is what gets handed over:
;; a device grant carries the VMK, an agent approval carries nothing at all.
;; The agent's reach is built afterwards, one `kagi agent grant <id> <item>`
;; at a time, which is why revoking it can actually re-key.

(defn- agent-store
  "Where the agent commands read and write principals.

  Local files by default; the object store with `--backend object`, so the
  same commands manage a registry that a server elsewhere is serving. Without
  this, `kagi agent invite` would mint an invite into a registry the bucket-
  served API never reads — an invite that exists and cannot be used.

  Separate from `vault.edn` either way (`kagi.agent`'s ns docstring says why):
  enrolling a principal must not rewrite a 9.5 MB snapshot, and must not be
  erased by the owner's next `kagi push`."
  [id args]
  (let [backend (sync-backend args)]
    (if (= :object (:backend backend))
      (agent-docs/object-docs {:fns (:fns backend)
                               :did (or (not-empty (arg-val args "--did"))
                                        (not-empty (System/getenv "KAGI_AGENT_TENANT_DID"))
                                        (:did id))
                               :prefix (not-empty (System/getenv "KAGI_OBJECT_PREFIX"))})
      (agent-docs/local-docs dir))))

(defn- agent-registry [id args] ((:registry (agent-store id args))))

(defn- parse-ops
  "`reveal,list` or `item/reveal,share/grant`. Unknown names die rather than
  being dropped: a typo'd capability that silently disappears grants less than
  the operator believes they granted, and they will find out from a failure
  weeks later."
  [s]
  (when s
    (let [ops (into #{} (map (fn [t] (if (str/includes? t "/") (keyword t) (keyword "item" t)))
                             (remove str/blank? (str/split s #","))))]
      (when-let [unknown (seq (remove agent-proto/ops ops))]
        (die (str "unknown --ops: " (pr-str (vec unknown))
                  "\n  known: " (pr-str (vec (sort (map (comp str symbol) agent-proto/ops)))))))
      ops)))

(defn- agent-scope [args]
  {:compartments (set (arg-vals args "--compartment"))
   :ops (or (parse-ops (arg-val args "--ops")) agent-proto/default-ops)
   :purposes (set (arg-vals args "--purpose"))
   :agent-ttl-sec (* 86400 (parse-long* (arg-val args "--ttl-days") 30))})

(defn- cmd-agent-request
  "On the AGENT's machine. Generates this principal's own keypair, keeps the
  private half in a SecretStore, and prints the request plus the FINGERPRINT
  to read aloud. No vault is needed here."
  [p args]
  (let [custody (if (= "file" (arg-val args "--custody")) :file :keychain)
        {:keys [request fingerprint secret-ref]}
        (agent/make-request! p {:label (arg-val args "--label") :custody custody :home dir})
        out (or (arg-val args "--out") "agent-request.edn")]
    (spit out (pr-str request))
    (println (pr-str {:ok? true :wrote out
                      :agent-id (:agent/id request)
                      :did (:agent/did request)
                      :fingerprint fingerprint
                      :secret-ref secret-ref
                      :secret? false
                      :next (str "vault 側で: kagi agent approve " out
                                 " --fingerprint " fingerprint
                                 " --compartment <名前>")}))))

(defn- cmd-agent-approve
  "On the OWNER's machine. Registers the principal and prints its account_key
  ONCE. `--fingerprint` is required for the same reason `kagi device grant`
  requires it: it is the only thing that catches a substituted public key."
  [p id args]
  (let [file (or (nth args 2 nil)
                 (die "usage: kagi agent approve <agent-request.edn> --fingerprint FP [--compartment C]... [--ops reveal,list] [--ttl-days 30]"))
        request (edn/read-string (slurp file))
        confirmed (or (arg-val args "--fingerprint")
                      (die "--fingerprint は必須。agent が表示した値を読み上げて渡すこと —
                            省くと攻撃者の公開鍵を登録しても気付けない"))
        scope (agent-scope args)
        _ (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        store* (agent-store id args)           ; migrates a legacy registry once
        invite (merge #:invite{:id (str "direct:" (java.util.UUID/randomUUID))}
                      {:invite/compartments (:compartments scope)
                       :invite/ops (:ops scope)
                       :invite/purposes (:purposes scope)
                       :invite/agent-ttl-sec (:agent-ttl-sec scope)})
        {:keys [token principal]}
        (try (agent/approve p request {:invite invite :confirmed-fingerprint confirmed})
             (catch clojure.lang.ExceptionInfo e
               (die (str "agent approval refused: " (pr-str (:agent/errors (ex-data e)))))))]
    ;; The vault is not touched. The member record `:share/grant` needs is
    ;; derived from the principal at grant time (`kagi.agent/member-of`).
    ((:update-registry! store*) #(agent/register % principal))
    (println (pr-str {:ok? true
                      :agent-id (:agent/id principal)
                      :did (:agent/did principal)
                      :ops (vec (sort (map (comp str symbol) (:agent/ops principal))))
                      :compartments (vec (sort (:agent/compartments principal)))
                      :not-after (:agent/not-after principal)
                      :account-key token
                      :note "account_key はこれ以降取り出せない(vault はハッシュしか持たない)。
                             まだ何も読めない — kagi agent grant <agent-id> <item> で item を渡すこと"}))))

(defn- cmd-agent-invite
  "Mint an invite for the SELF-SERVICE path (`kagi agent serve`). The scope is
  decided here, before any agent asks for it."
  [p id args]
  (let [scope (agent-scope args)
        _ (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        store* (agent-store id args)
        {:keys [secret record]}
        (agent/mint-invite p (assoc scope
                                    :ttl-sec (parse-long* (arg-val args "--ttl") 900)
                                    :uses (parse-long* (arg-val args "--uses") 1)
                                    :note (arg-val args "--note")))]
    ((:update-registry! store*) #(agent/add-invite % record))
    (println (pr-str {:ok? true
                      :invite secret
                      :invite-id (:invite/id record)
                      :ops (vec (sort (map (comp str symbol) (:invite/ops record))))
                      :compartments (vec (sort (:invite/compartments record)))
                      :uses (:invite/uses-left record)
                      :expires-at (:invite/expires-at record)
                      :note "invite は一度しか表示されない(vault はハッシュしか持たない)"}))))

(defn- cmd-agent-ls [_p id args]
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        st (load-store (dissoc data :meta))]
    (println (pr-str (assoc (agent/status (agent-registry id args) st)
                            :store (agent-docs/describe (agent-store id args)))))))

(defn- principal-or-die [registry agent-id]
  (or (agent/principal registry agent-id)
      (die (str "no such agent principal: " agent-id
                "\n  kagi agent ls で登録済みの principal を確認すること"))))

(defn- refusal-detail
  "Why an op did not commit, in a form an operator can act on.

  `(:basis (last policy-holds))` alone answers nil whenever the run never
  reached the governor — an `authn` failure routes straight to `:hold` with no
  verdict — and \"grant refused: nil\" is exactly the refusal that cannot say
  what refused it. Report the disposition and the audit trail too."
  [state]
  {:disposition (:disposition state)
   :basis (:basis (last (filter #(= :policy-hold (:t %)) (:audit state))))
   :audit (mapv #(select-keys % [:t :verified? :actor :op :basis :phase-reason]) (:audit state))
   :effect (get-in state [:result :effect])})

(defn- cmd-agent-grant
  "Share one item with a principal. This is `:share/grant`: the item's DEK is
  encapsulated to the agent's hybrid public key, so the agent can open THIS
  item and learns nothing about any other."
  [p id args]
  (let [agent-id (or (nth args 2 nil) (die "usage: kagi agent grant <agent-id> <item>"))
        item (or (nth args 3 nil) (die "usage: kagi agent grant <agent-id> <item>"))
        prin (principal-or-die (agent-registry id args) agent-id)]
    (with-vault p
      (fn [st vmk]
        ;; The member record is materialised from the principal HERE, in the
        ;; owner's own vault write. Keeping it out of the registry means one
        ;; fact in one place; keeping it out of the server means enrollment
        ;; never has to touch the snapshot.
        (store/put-member! st (agent/member-of prin))
        (let [it (or (store/item st item) (die "no such item:" item))]
          (when (and (seq (:agent/compartments prin))
                     (not (contains? (set (:agent/compartments prin)) (:item/compartment it))))
            ;; The declared scope is checked BEFORE the grant, not only when
            ;; the item is released: a grant that exists but is refused at read
            ;; time reads as a working share in `kagi agent ls`.
            (die (str "item " item " は compartment " (pr-str (:item/compartment it))
                      " にあり、principal の scope "
                      (pr-str (vec (sort (:agent/compartments prin)))) " の外にある")))
          (let [state (run-op-with! p id st vmk
                                    {:op :share/grant :item-id item
                                     :recipient-did (:agent/did prin)}
                                    :cli-agent-grant
                                    ;; The operator typing this command is the
                                    ;; consent `governor/consent-violations`
                                    ;; asks for.
                                    {:consent? true})]
            (if (= :shared (get-in state [:result :effect]))
              (println (pr-str {:ok? true :granted item :to agent-id
                                :did (:agent/did prin)}))
              (die (str "grant refused: " (pr-str (refusal-detail state))))))))) ))

(defn- cmd-agent-ungrant
  "Un-share one item — `:share/revoke`, which RE-KEYS the item and
  re-encapsulates it to every remaining recipient. This is the revocation that
  actually closes the door: the principal's old envelope opens a DEK that no
  longer decrypts anything."
  [p id args]
  (let [agent-id (or (nth args 2 nil) (die "usage: kagi agent ungrant <agent-id> <item>"))
        item (or (nth args 3 nil) (die "usage: kagi agent ungrant <agent-id> <item>"))
        prin (principal-or-die (agent-registry id args) agent-id)]
    (with-vault p
      (fn [st vmk]
        (when-not (store/item st item) (die "no such item:" item))
        (let [state (run-op-with! p id st vmk
                                  {:op :share/revoke :item-id item
                                   :recipient-did (:agent/did prin)}
                                  :cli-agent-ungrant {})]
          (if-let [v (get-in state [:result :version])]
            (println (pr-str {:ok? true :ungranted item :from agent-id :item-version v
                              :note "item は再鍵された。残りの受信者には新しい envelope が配られている"}))
            (die (str "ungrant refused: " (pr-str (refusal-detail state))))))))))

(defn- cmd-agent-revoke [_p id args]
  (let [agent-id (or (nth args 2 nil) (die "usage: kagi agent revoke <agent-id>"))
        data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        store* (agent-store id args)
        prin (principal-or-die ((:registry store*)) agent-id)
        registry ((:update-registry! store*) #(agent/revoke-agent % agent-id nil))
        st (load-store (dissoc data :meta))
        held (get-in (agent/status registry st) [:agents])
        grants (:agent/grants (first (filter #(= agent-id (:agent/id %)) held)))]
    (println (pr-str {:ok? true :revoked agent-id :did (:agent/did prin)
                      :token :dead
                      :outstanding-grants (vec grants)
                      :next (if (seq grants)
                              (str "まだ開ける item がある。閉じるには: "
                                   (str/join "; " (map #(str "kagi agent ungrant " agent-id " " %)
                                                       grants)))
                              "残っている grant は無い")}))))

(defn- cmd-agent-serve
  "Run the self-service API. Loopback unless `--host` says otherwise; this
  process never holds a VMK, so what it serves is ciphertext.

  `--backend object` serves the vault and registry out of the object store
  instead of this machine's files, which is what lets the API run somewhere
  the vault is not. It needs `--did` (or `KAGI_AGENT_TENANT_DID`) because a
  bucket can hold many vaults and the server is not one of them — it does not
  hold an identity to derive the tenant from."
  [id args]
  (let [backend (sync-backend args)
        tenant (or (not-empty (arg-val args "--did"))
                   (not-empty (System/getenv "KAGI_AGENT_TENANT_DID"))
                   (:did id))
        svc (agent-service/service
             (if (= :object (:backend backend))
               (agent-docs/object-docs {:fns (:fns backend) :did tenant
                                        :prefix (not-empty (System/getenv "KAGI_OBJECT_PREFIX"))})
               dir))
        host (or (arg-val args "--host") "127.0.0.1")
        port (parse-long* (arg-val args "--port") 0)
        {:keys [origin base-url warning stop]}
        (agent-http/start! svc {:host host :port port :tenant tenant})]
    (println (pr-str (cond-> {:ok? true :listening origin
                              ;; the URL an agent is actually given: every route
                              ;; names its tenant
                              :base-url base-url
                              :tenant tenant
                              :endpoints ["POST <base>/agents/challenges" "POST <base>/agents"
                                          "GET <base>/whoami" "GET <base>/items"
                                          "GET <base>/items/<id>/sealed" "POST <base>/audit"]
                              :store (agent-docs/describe svc)}
                       (:bucket backend) (assoc :bucket (:bucket backend)
                                                :endpoint (:endpoint backend))
                       warning (assoc :warning warning))))
    (println "Ctrl-C で停止")
    (.addShutdownHook (Runtime/getRuntime) (Thread. ^Runnable stop))
    @(promise)))

(defn- cmd-agent-log
  "Verify one principal's own signed chain against the public key the VAULT
  recorded for it."
  [id args]
  (let [agent-id (or (nth args 2 nil) (die "usage: kagi agent log <agent-id>"))
        r (agent/verify-ledger dir agent-id (agent-registry id args))]
    (doseq [e (:ledger (persist/load* (agent/ledger-path dir agent-id)))]
      (println (format "%3d  %-14s %-14s %s" (:ledger/seq e) (name (or (:t e) "?"))
                       (str (:op e)) (or (:disposition e) ""))))
    (println (pr-str r))))

(defn- cmd-agent-audit
  "What a REMOTE agent submitted about itself.

  Distinct from `kagi agent log`, which reads the chain a LOCAL agent wrote
  next to the vault. Over HTTP there is no governor run and no vault-side
  ledger — the server releases ciphertext and the SDK decrypts — so the record
  of what was opened exists only because the client signed one and handed it
  back. Verified here against the public key the registry recorded at
  enrollment, never against one the submission supplies."
  [p id args]
  (let [agent-id (or (nth args 2 nil) (die "usage: kagi agent audit <agent-id>"))
        store* (agent-store id args)
        prin (principal-or-die ((:registry store*)) agent-id)
        submitted (:ledger ((:read-audit store*) agent-id))
        pub (some-> (:agent/sign-pub prin) identity/decode-bundle)]
    (if (empty? submitted)
      (println (pr-str {:ok? true :entries 0
                        :note "この principal はまだ何も提出していない（local agent なら kagi agent log）"}))
      (do
        (doseq [e submitted]
          (println (format "%3d  %-10s %-24s %s"
                           (:ledger/seq e) (name (or (:t e) "?"))
                           (str (:item e)) (str (:purpose e)))))
        (println (pr-str (assoc (ledger/verify-chain submitted p
                                                     (fn [did] (when (= did (:agent/did prin)) pub)))
                                :entries (count submitted)
                                :received-at (:received-at ((:read-audit store*) agent-id)))))))))

(defn- cmd-agent-get
  "On the AGENT's machine. Opens one granted item with THIS principal's own
  key — no VMK, no prompt, no passphrase. The four outcomes stay apart so a
  refusal cannot be read as an empty secret."
  [args]
  (let [item (or (nth args 2 nil) (die "usage: kagi agent get <item> --purpose <用途>"))
        purpose (or (arg-val args "--purpose")
                    (die "--purpose は必須 — なぜ開けたのかが台帳に残らない開示は後から検証できない"))
        session (agent/open {:home dir :agent-id (arg-val args "--agent")})]
    (case (:status session)
      :open (let [r (agent/read-one session item purpose)]
              (case (:status r)
                :ok (println (:plaintext r))
                :denied (die (str "governor refused: " (pr-str (:basis r))))
                :absent (die (str "no such item: " item))
                (die (pr-str r))))
      (die (pr-str (select-keys session [:status :hint :vault-home :agent-id
                                         :revoked-at :not-after]))))))

(defn- cmd-unlock-status []
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))]
    (println (pr-str (unlock/status (:meta data))))))

(defn- cmd-unlock-enable-passkey [p]
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        vmk (unlock-vmk-auto p (:meta data))
        st (load-store (dissoc data :meta))
        bridge (passkey-bridge/start!
                p {:timeout-seconds 120
                   :on-input
                   (fn [input]
                     (let [result (passkey/consume-bridge-input input "127.0.0.1")
                           wrap (unlock/passkey-prf-wrap
                                 p vmk (:prf-output result)
                                 (select-keys result [:rp-id :credential-id :prf-salt]))]
                       (save-store! st (unlock/add-wrap (:meta data) wrap))
                       {:enabled :passkey-prf :credential-id (:credential-id result)}))})]
    (try
      (if (and (Desktop/isDesktopSupported)
               (.isSupported (Desktop/getDesktop) Desktop$Action/BROWSE))
        (.browse (Desktop/getDesktop) (URI/create (:url bridge)))
        (println "open in a browser:" (:url bridge)))
      (let [result ((:await bridge))]
        (if (= result :kagi.passkey-bridge/timeout)
          (die "passkey registration timed out")
          (println (pr-str {:ok? true :enabled :passkey-prf :secret? false}))))
      (finally ((:stop bridge))))))

(def ^:private ui-clipboard-ttl-sec
  "Same default as `kagi copy`. A window does not get a longer grace period
  than the command does — the clipboard is the same machine-wide surface
  either way."
  45)

(defn- cmd-ui
  "Open the local vault window: the item list, the enrolled devices, and how
  this vault unlocks.

  The vault is opened ONCE, here, where unlock already knows how to prompt —
  `kagi.vault-read/open` deliberately cannot (a server process has no TTY, and
  a prompt would hang a request). What the window can do is
  `kagi.ui.actions`; what serves it is `kagi.ui.server`, which is handed those
  three functions and never sees the vault. This command is the wiring and
  nothing else."
  [p id args]
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        vmk (unlock-vmk-auto p (:meta data))
        st (load-store (dissoc data :meta))
        meta-state (atom (:meta data))
        ttl-sec (parse-long* (arg-val args "--ttl") ui-clipboard-ttl-sec)
        idle-sec (parse-long* (arg-val args "--idle") 900)
        window (ui-server/start!
                {:css (ui-server/dds-css)
                 :rand-fn #(crypto/rand-bytes p %)
                 :idle-timeout-seconds idle-sec
                 :actions (ui-actions/actions
                           {:session {:status :open :provider p :identity id
                                      :did (:did id) :vmk vmk :store st}
                            :meta-state meta-state
                            :save! #(save-store! st %)
                            :clipboard (clipboard/macos-clipboard)
                            :copy-ttl-sec ttl-sec
                            :vault-home vault-path})})]
    (try
      (println (pr-str {:ok? true :window (:origin window)
                        :idle-timeout-sec idle-sec
                        :clipboard-ttl-sec ttl-sec
                        :secret? false}))
      (if (and (Desktop/isDesktopSupported)
               (.isSupported (Desktop/getDesktop) Desktop$Action/BROWSE))
        (.browse (Desktop/getDesktop) (URI/create (:url window)))
        (println "open in a browser:" (:url window)))
      (println (str "Ctrl-C で閉じる。" idle-sec " 秒 無操作でも閉じる。"))
      (flush)
      ((:await window))
      (println (pr-str {:ok? true :closed true :secret? false}))
      (finally ((:stop window))))))

(defn- cmd-recovery-create [p args]
  (let [out (or (arg-val args "--out") (die "recovery create requires --out DIR"))
        k (parse-long* (arg-val args "--threshold") 3)
        n (parse-long* (arg-val args "--shares") 5)]
    (with-vault p
      (fn [_ vmk]
        (let [written (recovery-io/write-shares! out (recovery/split p vmk k n))]
          (println (pr-str {:ok? true :threshold k :shares n
                            :paths (mapv :path written) :secret? false})))))))

(defn- cmd-recovery-verify [args]
  (let [files (vec (drop 2 args))]
    (when (empty? files) (die "usage: kagi recovery verify <share.edn>..."))
    (recovery-io/combine-files files)
    (println (pr-str {:ok? true :shares (count files) :secret? false}))))

(defn- cmd-recovery-get [p id args]
  (let [item-id (nth args 2 nil)
        files (vec (drop 3 args))]
    (when (or (nil? item-id) (empty? files))
      (die "usage: kagi recovery get <item> <share.edn>..."))
    (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
          vmk (recovery-io/combine-files files)
          st (load-store (dissoc data :meta))
          result (run-op! p id st vmk {:op :item/reveal :item-id item-id} :recovery-get)
          plaintext (get-in result [:result :plaintext])]
      (save-store! st (:meta data))
      (if plaintext (print (String. ^bytes plaintext "UTF-8"))
          (die "recovery reveal denied")))))

;; ───────── cloud sync (kotobase.net) ─────────

(defn- push-with [backend id args expected-seq]
  (if (= :object (:backend backend))
    (sync/object-push! {:fns (:fns backend) :did (:did id) :vault-path vault-path
                        :prefix (not-empty (System/getenv "KAGI_OBJECT_PREFIX"))
                        :expected-seq expected-seq})
    (sync/push! {:id id :vault-path vault-path :pod (not-empty (arg-val args "--pod"))
                 :expected-seq expected-seq})))

(defn- pull-with [backend id args]
  (if (= :object (:backend backend))
    (sync/object-pull! {:fns (:fns backend) :did (:did id) :vault-path vault-path
                        :prefix (not-empty (System/getenv "KAGI_OBJECT_PREFIX"))})
    (sync/pull! {:id id :vault-path vault-path :pod (not-empty (arg-val args "--pod"))})))

(defn- backend-report [backend]
  (cond-> {:backend (:backend backend)}
    (:bucket backend) (assoc :bucket (:bucket backend) :endpoint (:endpoint backend))))

(defn- cmd-push [id args]
  (when-not (persist/load* vault-path) (die "no vault — run: kagi init"))
  (let [backend (sync-backend args)
        r (push-with backend id args nil)]
    (println (pr-str (merge r (backend-report backend) {:ok? true :secret? false})))))

(defn- cmd-pull [id args]
  (let [backend (sync-backend args)
        r (pull-with backend id args)]
    (if (:seq r)
      (println (pr-str (merge r (backend-report backend)
                              {:ok? true :backup (str vault-path ".bak") :secret? false})))
      (die "cloud has no vault snapshot for this vault yet — run: kagi push"))))

(defn- cmd-sync [id args]
  (let [backend (sync-backend args)
        pulled (pull-with backend id args)
        pushed (push-with backend id args (or (:seq pulled) 0))]
    (println (pr-str (merge (backend-report backend)
                            {:ok? true :pulled (:seq pulled) :pushed (:seq pushed)
                             :secret? false})))))

(defn- help []
  (println (str/trim "
kagi — 自己主権・対量子(PQC) secrets vault (op 相当)

  kagi init                 鍵生成 + vault 作成
  kagi add <name> [-c c]    secret を stdin から登録   (printf '%s' s | kagi add foo)
  kagi get <name>           secret を復号して stdout へ
  kagi copy <name> --purpose p [--ttl 45]
                            secret を stdout に出さず clipboard へ一時コピー
  kagi ls                   item 一覧
  kagi ui [--ttl 45] [--idle 900]
                            item / 端末 / unlock を見る窓を 127.0.0.1 に開く
  kagi import onepassword <file.1pux> [-c compartment] [--include-archived]
                            1Password の 1PUX export を取り込む(kagitaba 経由)
  kagi rotate <name>        DEK 回転(再封緘)
  kagi log                  監査台帳を検証して表示
  kagi whoami               自分の did:key / IPNS graph
  kagi identity-migrate     identity 秘密鍵を OS keychain へ移す
  kagi unlock-enable-keychain [--ref keychain://service/account]
                            VMK unlock を OS keychain に追加(passphrase は recovery として残す)
  kagi unlock-status        VMK unlock methods を metadata のみ表示
  kagi device request --label NAME [--out F]
                            [新端末] hybrid 鍵を生成し request + fingerprint を出す
  kagi device grant <request.edn> --fingerprint FP [--ttl 900] [--out F]
                            [登録済端末] VMK を相手の公開鍵に封入。fingerprint 必須
  kagi device accept <grant.edn>
                            [新端末] VMK を復元し、自端末の keychain wrap を追加
  kagi device ls            登録済み端末を表示(鍵素材は出ない)
  kagi device revoke <id>   その端末の wrap を外す(既得の VMK は取り消せない)
  kagi unlock-enable-passkey
                            one-shot loopback bridgeでWebAuthn PRF unlockを追加
  kagi recovery create --out DIR [--threshold 3] [--shares 5]
  kagi recovery verify <share.edn>...
  kagi recovery get <item> <share.edn>...
  kagi agent request --label <名前> [--custody file]
                            agent 側: 自分の鍵を作り request と fingerprint を出す
  kagi agent approve <request.edn> --fingerprint FP [--compartment C]... [--ops reveal,list] [--ttl-days 30]
                            owner 側: principal を登録し account_key を1度だけ表示
  kagi agent invite [--compartment C]... [--ops ...] [--ttl 900] [--uses 1]
                            self-service 経路(kagi agent serve)用の招待を発行
  kagi agent grant <agent-id> <item>      item を 1 件その agent に共有(:share/grant)
  kagi agent ungrant <agent-id> <item>    共有を取り消し item を再鍵(:share/revoke)
  kagi agent ls / revoke <agent-id> / log <agent-id> / audit <agent-id>
                            log は local agent 自身の鎖、audit は remote agent が提出した鎖
  kagi agent serve [--host H] [--port P] [--backend object --did <tenant did>]
                            agent 向け HTTP API(VMK を持たない)。object backend なら
                            vault ファイルの無いホストでも動く
  kagi agent get <item> --purpose <用途>  agent 側: 自分の鍵で 1 件開く(対話なし)
  kagi push [--backend object|kotobase] [--pod URL]
                            暗号化 vault を cloud へ同期(object store / kotobase.net)
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
          cmd (first args)
          ;; `identity-migrate` must be able to READ the very plaintext
          ;; identity it exists to move into a SecretStore.
          ;;
          ;; Without this the vault is unusable and unfixable. The identity is
          ;; loaded here, before dispatch, so a plaintext identity throws
          ;; "plaintext identity requires migration — run kagi
          ;; identity-migrate before other commands"; but identity-migrate is
          ;; itself dispatched after the load, so it throws the same error.
          ;; The remediation the message prescribes cannot be executed. Found
          ;; on a real vault (2026-07-30) whose identity.edn held private-b64,
          ;; mldsa-private-b64 and kem-secret in world-readable plaintext:
          ;; every command, migration included, exited non-zero.
          ;;
          ;; Scoped to this one command on purpose. Every other command still
          ;; refuses a plaintext identity, so the guard keeps its meaning —
          ;; the exception is exactly the operation that removes the condition
          ;; being guarded against.
          id (identity/load-or-create-identity!
              id-path p
              (cond-> (identity-options)
                (= "identity-migrate" cmd) (assoc :allow-existing-plaintext? true)))]
      (case cmd
        "init"   (cmd-init p id)
        "add"    (cmd-add p id args)
        "get"    (cmd-get p id args)
        "copy"   (cmd-copy p id args)
        "fill"   (cmd-fill p id args)
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
        "ui"     (cmd-ui p id args)
        "device" (case (second args)
                   "request" (cmd-device-request p args)
                   "grant"   (cmd-device-grant p args)
                   "accept"  (cmd-device-accept p args)
                   "ls"      (cmd-device-ls p)
                   "revoke"  (cmd-device-revoke p args)
                   (die "usage: kagi device request|grant|accept|ls|revoke ..."))
        "agent"  (case (second args)
                   "request" (cmd-agent-request p args)
                   "approve" (cmd-agent-approve p id args)
                   "invite"  (cmd-agent-invite p id args)
                   "ls"      (cmd-agent-ls p id args)
                   "grant"   (cmd-agent-grant p id args)
                   "ungrant" (cmd-agent-ungrant p id args)
                   "revoke"  (cmd-agent-revoke p id args)
                   "serve"   (cmd-agent-serve id args)
                   "log"     (cmd-agent-log id args)
                   "audit"   (cmd-agent-audit p id args)
                   "get"     (cmd-agent-get args)
                   (die "usage: kagi agent request|approve|invite|ls|grant|ungrant|revoke|serve|log|audit|get ..."))
        "unlock-enable-passkey" (cmd-unlock-enable-passkey p)
        "recovery" (case (second args)
                     "create" (cmd-recovery-create p args)
                     "verify" (cmd-recovery-verify args)
                     "get" (cmd-recovery-get p id args)
                     (die "usage: kagi recovery create|verify|get ..."))
        "push"   (cmd-push id args)
        "pull"   (cmd-pull id args)
        "sync"   (cmd-sync id args)
        (help))))
  (flush)
  ;; futures (clipboard/process slurps) leave non-daemon pool threads alive;
  ;; without this the JVM lingers ~60s after the command completes.
  (shutdown-agents))
