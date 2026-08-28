(ns kagi.agent
  "Agent principals — custody for actors that are not people.

  ## The gap

  Every other way into this vault assumes an operator. `kagi get` prompts,
  `kagi device grant` refuses without a fingerprint a human read aloud, `kagi
  ui` opens a browser. A resident agent has none of that, and under launchd
  the Keychain cannot even prompt — so the workspace's secrets map records
  what actually happened: long-lived agents read `~/.gftd/<name>` in mode-600
  plaintext, outside the vault, outside the governor, outside the ledger.

  This namespace is the supported answer to that, and it is deliberately NOT
  \"let the agent unlock the vault without a human\".

  ## What an agent principal actually holds

  Its own hybrid keypair, and nothing else.

      owner:  VMK → compartment KEK → item DEK        (the whole vault)
      agent:  its own KEM secret → the DEK of each item it was GRANTED

  The VMK never reaches an agent in any form, not even a compartment key. The
  agent reads exactly the items the owner ran `kagi agent grant` for, through
  `kagi.operation`'s recipient path, which means:

  - **Revocation is real.** `kagi agent ungrant` is `:share/revoke`, which
    RE-KEYS the item and re-encapsulates it to every remaining recipient. The
    revoked agent's envelope opens a DEK that no longer decrypts anything.
    Contrast `kagi.device/revoke-device`, whose own docstring has to admit it
    is an access-list change — a device that already unlocked the vault keeps
    the VMK forever. An agent cannot be in that position because it was never
    given anything vault-wide to keep.
  - **Reach is enumerable.** `kagi agent ls` can list what a principal can
    open, because that is a set of grants rather than a derived key.
  - **Every read is governed and signed.** Reveals go through the same
    AccessGovernor as `kagi get`, and each one lands on a hash chain signed by
    THE AGENT's own key, so the ledger says which principal read what.

  ## Enrollment: two paths, different assurances, stated rather than implied

  1. **Offline (`request` → `approve` → the owner grants items).** The agent
     prints a fingerprint; a human reads it on the owner's machine. Same
     discipline as device enrollment, same reason: it is the only thing that
     catches a substituted public key.

  2. **Online (`kagi.agent-http`, the agentmail-shaped API).** The agent
     enrolls itself with an INVITE the owner minted in advance, plus a
     proof-of-work. No human is present at request time; the human was present
     when the invite was minted, and the invite already names the scope, the
     operations and the expiry.

     The proof-of-work is a rate limit, not authentication —
     `kagi.agent-protocol` says so where a reader will hit it. An inbox handed
     to whoever solves a puzzle costs what the puzzle costs; a vault does not.

  ## The registry is its own object, not part of the vault snapshot

  Principals and invites live in `$KAGI_HOME/agents/registry.edn`, NOT in
  `vault.edn`'s metadata, and that is not tidiness.

  `kagi push` uploads the whole snapshot as one string under
  `:kagi.vault/snapshot` and resolves conflicts last-writer-wins by
  `:kagi.vault/seq`. The real vault on this machine is 9.5 MB. So a registry
  inside it would mean (a) every enrollment rewrites and re-uploads 9.5 MB to
  record ~1 KB, and (b) an enrollment the server accepted is silently erased by
  the owner's next `kagi push`, because that push carries a snapshot whose
  registry predates it. The failure would look like an agent that enrolled
  successfully in the morning and is `:not-registered` by the afternoon, with
  nothing in any log.

  Splitting it also means the two objects have honestly different contents:
  the snapshot is ciphertext, and the registry is public metadata — public
  keys, token HASHES, invite hashes. Nothing in it is secret, which is what
  makes it safe for a server to write.

  ## The agent's ledger is its own file, on purpose

  An agent must not be able to write `vault.edn` — a read-only principal that
  can rewrite the store it reads from is not read-only. So its entries chain
  into `$KAGI_HOME/agents/<id>.ledger.edn`, signed by its own key, verifiable
  with `kagi agent log <id>`. This IS a second chain, and the alternative was
  giving an unattended process write access to the vault to record that it had
  read from it.

  ## `.cljc` with only a `:clj` branch, and saying so\n\n  This is the agent-side session: it opens a vault file, decapsulates a grant,\n  runs the governor and signs a ledger. All of that is JVM work and belongs\n  where the vault is, so the `:cljs` branch is empty rather than pretending.\n  The extension follows the rule that new production code is portable-first\n  (ADR-2608201300); the portable half of this surface already exists as\n  `kagi.agent-registry` and is guarded by `kagi.portable-slice-test`."
  #?@(:clj [(:require [clojure.java.io :as io]
            [clojure.string :as str]
            [kagi.cacao :as cacao]
            [kagi.chain-signer :as chain-signer]
            [kagi.crypto :as crypto]
            [kagi.device :as device]
            [kagi.agent-registry :as registry]
            [kagi.identity :as identity]
            [kagi.ledger :as ledger]
            [kagi.operation :as op]
            [kagi.persist :as persist]
            [kagi.secret-store :as secret-store]
            [kagi.store :as store]
            [kagi.vault-read :as vault-read]
            [langgraph.graph :as g])])
  #?@(:clj [(:import [java.util UUID])]))

#?(:clj
   (do


;; ── the registry half lives in `kagi.agent-registry` (portable) ────────────
;;
;; Re-exported rather than moved out of sight: every caller in this repo and
;; every test refers to these through `kagi.agent`, and the split is about
;; WHERE the code can run, not about renaming the API. `kagi.agent-registry`'s
;; ns docstring says which half is which.

(def now-iso registry/now-iso)
(def plus-sec registry/plus-sec)
(def sha256-b64 registry/sha256-b64)
(def empty-registry registry/empty-registry)
(def mint-invite registry/mint-invite)
(def find-invite registry/find-invite)
(def add-invite registry/add-invite)
(def consume-invite registry/consume-invite)
(def invites registry/invites)
(def approve registry/approve)
(def member-of registry/member-of)
(def register registry/register)
(def principal registry/principal)
(def principal-by-token registry/principal-by-token)
(def revoke-agent registry/revoke-agent)
(def status registry/status)



(def ^:private aud "https://kotobase.net")










;; ───────────────────────────── where things live ─────────────────────────

(defn agents-dir
  "`$KAGI_HOME/agents`. Holds one non-secret pointer per principal enrolled ON
  THIS MACHINE, plus that principal's ledger. No key material — the keys are
  in a SecretStore, which is the whole point of having one."
  ([] (agents-dir (vault-read/vault-home)))
  ([home] (str home "/agents")))

(defn registry-path
  "Principals and invites. Separate from `vault.edn` — see the ns docstring."
  [home]
  (str (agents-dir home) "/registry.edn"))



(defn load-registry
  "Read the registry, migrating a legacy one out of vault metadata if that is
  where it still lives.

  The fallback is not permanent politeness: vaults written before the split
  carry `:agent/registry` inside `:meta`, and a reader that ignored it would
  report every principal in them as `:not-registered` — a revocation-shaped
  answer for a vault that revoked nothing. `vault-meta` may be nil for callers
  that have no reason to open the snapshot."
  ([home] (load-registry home nil))
  ([home vault-meta]
   (or (persist/load* (registry-path home))
       (when (or (seq (:agent/registry vault-meta)) (seq (:agent/invites vault-meta)))
         (merge empty-registry
                {:agent/registry (vec (:agent/registry vault-meta))
                 :agent/invites (vec (:agent/invites vault-meta))
                 :agent/migrated-from :vault-meta}))
       empty-registry)))

(defn update-registry!
  "Read → `f` → write, under a cross-process file lock, with a sequence check.

  The lock is the point. `kagi agent approve` (a CLI on this machine) and
  `POST /v1/agents` (the server, possibly the same machine) both modify this
  file, and `persist/save!` locks only its own write — a read-modify-write
  spanning two of them would lose whichever landed first. `:agent/seq` then
  catches the case the lock cannot see: a writer that read the file before
  this process even started.

  `f` receives the current registry and returns the next one, or nil to abort
  without writing (an enrollment that turned out to be refused should not bump
  the sequence)."
  [home f]
  (let [path (registry-path home)
        ;; NOT `<path>.lock` — that is `kagi.persist/save!`'s own lock file, and
        ;; a JVM FileLock is held per PROCESS: locking it here and then calling
        ;; save! inside throws OverlappingFileLockException. Two locks, two
        ;; files, two jobs (this one spans the read-modify-write; persist's
        ;; spans its write).
        lock-path (str path ".update.lock")]
    (io/make-parents lock-path)
    (with-open [ch (java.nio.channels.FileChannel/open
                    (java.nio.file.Paths/get lock-path (make-array String 0))
                    (into-array java.nio.file.StandardOpenOption
                                [java.nio.file.StandardOpenOption/CREATE
                                 java.nio.file.StandardOpenOption/WRITE]))
                _lock (.lock ch)]
      (let [current (load-registry home)
            next (f current)]
        (when next
          (let [saved (assoc next :agent/seq (inc (:agent/seq current 0))
                             :agent/updated-at (now-iso))]
            (persist/save! path saved)
            saved))))))

(defn migrate-registry!
  "One-time: write `registry.edn` from a vault's legacy `:meta` registry if the
  file does not exist yet.

  Called from every entry point that reads or writes the registry (the CLI,
  `open`, and the service constructor) rather than left to whichever runs
  first. A migration only some callers perform is a migration some callers
  race."
  [home vault-meta]
  (when (and (not (.exists (java.io.File. ^String (registry-path home))))
             (or (seq (:agent/registry vault-meta)) (seq (:agent/invites vault-meta))))
    (update-registry! home (fn [_] (load-registry home vault-meta)))))

(defn pointer-path [home agent-id] (str (agents-dir home) "/" agent-id ".edn"))
(defn ledger-path [home agent-id] (str (agents-dir home) "/" agent-id ".ledger.edn"))

(defn default-secret-ref
  "Where a principal keeps its own private key.

  Keychain by default, because it is stronger. `--custody file` switches to a
  mode-600 file, and that is not a lesser default sneaking in — it is the only
  thing that works under launchd, where the Keychain cannot prompt. Which one
  a principal uses is recorded on the principal and shown by `kagi agent ls`,
  so 'this one is cheaper to steal from' is visible rather than inferred."
  [home agent-id custody]
  (case custody
    ;; Under the vault home, not under `$HOME` directly: a test (or a second
    ;; vault behind `$KAGI_HOME`) that wrote its principal keys into the real
    ;; home would be writing real key material somewhere nobody looked.
    :file (str "file://" home "/agents/" agent-id ".key")
    (str "keychain://kagi-agent/" agent-id)))

;; ───────────────────────────── agent side: request ────────────────────────

(defn make-request!
  "On the AGENT's machine. Generates this principal's own hybrid identity,
  puts the private half in a SecretStore, writes a non-secret pointer, and
  returns the public request to carry to the vault owner.

  The private key never appears in the request and never leaves this machine —
  the same contract `kagi.device/make-request!` keeps, and the reason an agent
  can be enrolled over a channel nobody trusts."
  [p {:keys [label custody store home]}]
  (let [agent-id (str (UUID/randomUUID))
        home (or home (vault-read/vault-home))
        ref (default-secret-ref home agent-id (or custody :keychain))
        st (or store (secret-store/store-for-ref ref))
        id (identity/generate-identity p)
        persisted (merge (:public (identity/split-identity id))
                         (:secret (identity/split-identity id)))]
    (secret-store/put-edn! st ref persisted)
    (persist/save! (pointer-path home agent-id)
                   {:agent/id agent-id
                    :agent/label (or label agent-id)
                    :agent/did (:did id)
                    :agent/secret-ref ref
                    :agent/custody (:custody (secret-store/metadata st ref))
                    :agent/created-at (now-iso)})
    {:request #:agent{:id agent-id
                      :label (or label agent-id)
                      :did (:did id)
                      :public {:kem (:kem-public id)
                               :sign {:ed (:public-b64 id)
                                      :mldsa (:mldsa-public-b64 id)}}
                      :created-at (now-iso)}
     :fingerprint (device/fingerprint (identity/kem-public id))
     :secret-ref (secret-store/redact-ref ref)}))

;; ───────────────────────────── owner side: invites ────────────────────────











;; ───────────────────────────── owner side: approve ────────────────────────

















;; ───────────────────────────── agent side: session ────────────────────────

(defn- pointers
  "Every principal enrolled on THIS machine, read from the pointer files in the
  agents directory.

  Selected by CONTENT (`:agent/id` + `:agent/secret-ref`), not by filename.
  The directory also holds `registry.edn`, `<id>.ledger.edn` and lock files,
  and a name-based filter has to be updated every time something else lands
  there — which it was not when the registry moved in, and every session
  without an explicit `--agent` became `:no-principal` because the count of
  \"pointers\" was suddenly two."
  [home]
  (let [d (java.io.File. ^String (agents-dir home))]
    (when (.isDirectory d)
      (->> (.listFiles d)
           (filter #(str/ends-with? (.getName ^java.io.File %) ".edn"))
           (keep #(try (persist/load* (.getPath ^java.io.File %)) (catch Exception _ nil)))
           (filter #(and (map? %) (:agent/id %) (:agent/secret-ref %)))
           vec))))

(defn- resolve-pointer [home agent-id]
  (let [ps (pointers home)]
    (cond
      agent-id (first (filter #(= agent-id (:agent/id %)) ps))
      (= 1 (count ps)) (first ps)
      :else nil)))

(defn- load-agent-ledger [home agent-id]
  (or (:ledger (persist/load* (ledger-path home agent-id))) []))

(defn open
  "Open a NON-INTERACTIVE agent session. No prompt, no TTY, no `KAGI_MASTER`,
  no VMK.

  The answer distinguishes six states, because collapsing them is how an
  operator ends up debugging the wrong thing:

    :absent          この機械に vault が無い
    :no-principal    この機械に agent の鍵が無い（まだ `kagi agent request` していない）
    :not-registered  鍵は在るが、vault 側に principal が無い（approve されていない）
    :revoked / :expired
    :open

  In particular `:not-registered` is not `:no-principal`: the first is an
  enrollment nobody approved, the second is a machine that never asked."
  ([] (open {}))
  ([{:keys [home agent-id secret-store]}]
   (let [home (or home (vault-read/vault-home))
         agent-id (or agent-id (not-empty (System/getenv "KAGI_AGENT_ID")))
         data (persist/load* (str home "/vault.edn"))]
     (if-not data
       {:status :absent :vault-home home}
       (if-let [ptr (resolve-pointer home agent-id)]
         (let [p (crypto/jvm-provider)
               ref (:agent/secret-ref ptr)
               st (or secret-store (secret-store/store-for-ref ref))
               id (identity/load-identity (secret-store/get-edn st ref))
               _ (migrate-registry! home (:meta data))
               prin (principal (load-registry home) (:agent/id ptr))
               now (now-iso)]
           (cond
             (nil? prin)
             {:status :not-registered :vault-home home :agent-id (:agent/id ptr) :did (:did id)}

             (:agent/revoked-at prin)
             {:status :revoked :vault-home home :agent-id (:agent/id ptr)
              :revoked-at (:agent/revoked-at prin)}

             (and (:agent/not-after prin) (pos? (compare now (:agent/not-after prin))))
             {:status :expired :vault-home home :agent-id (:agent/id ptr)
              :not-after (:agent/not-after prin)}

             :else
             {:status :open
              :vault-home home
              :agent-id (:agent/id ptr)
              :provider p
              :identity id
              :did (:did id)
              :principal prin
              :custody (:agent/custody ptr)
              ;; The vault's own ledger is replaced by THIS principal's chain
              ;; (see the ns docstring): the agent never writes vault.edn, so
              ;; chaining onto entries it cannot persist would produce a chain
              ;; that verifies nowhere.
              :store (store/mem-store (assoc (dissoc data :meta)
                                             :ledger (load-agent-ledger home (:agent/id ptr))))}))
         {:status :no-principal :vault-home home
          :hint "kagi agent request --label <名前> を先に実行すること"})))))

(defn- context [{:keys [identity principal]} purpose]
  (let [now (now-iso)]
    {:did (:did identity)
     :role :member
     :phase 3
     :now now
     :purpose purpose
     :kem-secret (identity/kem-secret identity)
     :agent principal
     :aud aud
     :cacao (cacao/mint identity {:cap :cap/read :scope (:graph identity)}
                        {:aud aud :nonce (str (UUID/randomUUID))
                         :issued-at now :expiry (plus-sec now 3600)})
     ;; depth-1 self-mint, exactly as the owner path does it — but as a
     ;; :member, so `governor/access-violations` still demands a grant for
     ;; every item this session opens.
     :register (identity/member-record identity :member)}))

(defn- persist-ledger! [session]
  (persist/save! (ledger-path (:vault-home session) (:agent-id session))
                 {:ledger (store/ledger (:store session))}))

(defn- run-op! [session req purpose]
  (let [actor (op/build (:store session)
                        {:crypto (:provider session)
                         :signer (identity/sign-secret (:identity session))})
        state (:state (g/run* actor
                              {:request req :context (context session purpose)}
                              {:thread-id (str (:op req) "-" (:item-id req) "-"
                                               (UUID/randomUUID))}))]
    ;; Written whether the op committed or was HELD. A refusal that leaves no
    ;; trace is the one an operator cannot investigate, and the governor emits
    ;; a hold fact precisely so it can be read later.
    (persist-ledger! session)
    state))

(defn items
  "Item metadata this principal can open. Grant-filtered by
  `kagi.operation` — an agent is not shown the names of items it cannot read."
  ([session] (items session "personal"))
  ([session compartment]
   (when (= :open (:status session))
     (get-in (run-op! session {:op :item/list :compartment compartment} :inventory)
             [:result :items]))))

(defn reveal
  "Reveal one item through the governor, opening it with THIS principal's own
  KEM secret. Returns the plaintext string, or nil when the governor refused.

  `purpose` lands on the agent's ledger. An unattended process reading a
  credential without recording why is the thing this whole namespace exists to
  stop being normal."
  [session item-id purpose]
  (when (= :open (:status session))
    (let [state (run-op! session {:op :item/reveal :item-id item-id} purpose)]
      (when-let [pt (get-in state [:result :plaintext])]
        (String. ^bytes pt "UTF-8")))))

(defn read-one
  "Like `reveal` but the four outcomes stay distinguishable:

    {:status :ok :plaintext \"…\"}
    {:status :denied :basis [:agent-op …]}   ; governor が拒否した(理由付き)
    {:status :absent}                        ; そんな item は無い
    {:status :locked}                        ; session が開いていない

  `:denied` carries the governor's own rule keywords. A refusal that cannot
  say what refused it is a refusal an operator has to guess at — the
  workspace's rule about checks that cannot name what they rejected."
  [session item-id purpose]
  (cond
    (not= :open (:status session)) {:status :locked :session (:status session)}
    (not (store/item (:store session) item-id)) {:status :absent}
    :else
    (let [state (run-op! session {:op :item/reveal :item-id item-id} purpose)]
      (if-let [pt (get-in state [:result :plaintext])]
        {:status :ok :plaintext (String. ^bytes pt "UTF-8")}
        {:status :denied
         :basis (or (:basis (last (filter #(= :policy-hold (:t %)) (:audit state)))) [])}))))

(defn verify-ledger
  "Verify this principal's chain against the public key the VAULT recorded for
  it — not against a key the ledger file supplies. A chain that carries its
  own verification key proves only that whoever wrote it was internally
  consistent."
  [home agent-id registry]
  (let [entries (load-agent-ledger home agent-id)
        prin (principal registry agent-id)
        pub (some-> (:agent/sign-pub prin) identity/decode-bundle)]
    (cond
      (nil? prin) {:ok? false :why :not-registered}
      (empty? entries) {:ok? true :entries 0}
      :else (assoc (ledger/verify-chain entries (crypto/jvm-provider)
                                        (fn [did] (when (= did (:agent/did prin)) pub)))
                   :entries (count entries)))))

(defn signer
  "A `wallet.signer/Signer` whose key material is an item this principal was
  granted — the Turnkey-shaped surface, built out of parts that already exist.

  `kagi.chain-signer` reveals the BIP-39 seed through the governor for EVERY
  signature and never caches it; pointing its `reveal-fn` at this session
  means the derive-and-sign happens in the agent's own process and each
  signature lands on the agent's ledger with the derivation path in the
  purpose string. Callers get public keys and signatures. They do not get the
  seed."
  [session item-id & [opts]]
  (chain-signer/signer (fn [purpose] (reveal session item-id purpose)) (or opts {})))))
