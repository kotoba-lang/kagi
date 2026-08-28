(ns kagi.agent-service
  "The vault side of the agent API — everything `kagi.agent-http` needs and no
  socket.

  ## This service never decrypts anything

  It has no VMK and cannot get one. What it serves is material that is ALREADY
  ciphertext in the vault:

      GET /v1/items/<id>/sealed  →  {envelope, nonce, ciphertext}
                                     ↑ the grant kagi already encapsulated to
                                       THIS principal's public key

  The agent opens it with its own KEM secret, in its own process. So a TLS
  terminator, a reverse proxy, a heap dump of this server and an operator
  reading its logs all see the same thing the vault file already showed them:
  ciphertext. That is the whole zero-knowledge claim in the kagi README,
  applied to the remote case instead of quietly dropped for it.

  The enforcement point is therefore **release**, not decryption: no envelope,
  no plaintext. `sealed` refuses on revocation, expiry, missing capability and
  missing grant, and each refusal says which.

  ## Why the documents are re-read on every request

  A registry cached at startup is a revocation that does not take effect until
  someone remembers to restart a daemon. `kagi agent revoke` has to work while
  this is running, so every request reads it fresh — and the alternative is a
  security control with a restart in the middle of it.

  ## Where it reads from is a seam

  `kagi.agent-docs` supplies `{:vault :registry :update-registry! :read-audit
  :write-audit!}`. Local files when the vault is on this machine; an
  S3-compatible object store when the server runs somewhere it is not. This
  namespace never learns which — it is why the same code can serve a loopback
  socket and a public endpoint.

  ## The only thing this writes is the registry

  Enrollment appends a principal to `$KAGI_HOME/agents/registry.edn` and spends
  an invite. It does not touch `vault.edn` at all.

  That separation is load-bearing rather than tidy: `kagi push` uploads the
  snapshot as one string and resolves conflicts last-writer-wins, and the real
  vault here is 9.5 MB. A server that wrote the registry into the snapshot
  would re-upload 9.5 MB per enrollment AND have each one silently erased by
  the owner's next push. The member record the vault needs for `:share/grant`
  is DERIVED from the principal (`kagi.agent/member-of`) when the owner grants,
  so nothing has to be copied into the snapshot ahead of time.

  ## What DOES need the owner

  Granting an item (`kagi agent grant`) encapsulates that item's DEK to the
  principal, which needs the VMK. It is an owner CLI command on purpose and
  has no endpoint: deciding what an agent may read is the decision that should
  cost a human a command.

  ## `.cljc` with only a `:clj` branch, and saying so\n\n  Most of this namespace is pure logic over the documents seam and could run\n  anywhere; what pins it to the JVM today is `kagi.vault-read` (for the vault\n  home) and the store it builds. Separating those is the remaining Worker-port\n  work (ADR-2608281100). The extension follows the portable-first rule\n  (ADR-2608201300) and this comment is here so it does not overclaim."
  #?@(:clj [(:require [clojure.string :as str]
            [kagi.agent :as agent]
            [kagi.agent-docs :as docs]
            [kagi.agent-protocol :as proto]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.ledger :as ledger]
            [kagi.store :as store]
            [kagi.vault-read :as vault-read])])
  #?@(:clj [(:import [java.time Instant]
           [java.time.temporal ChronoUnit])]))

#?(:clj
   (do


(defn- now-iso [] (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS)))

(defn service
  "Bind the service to its documents.

  Takes a vault home (local files, the default) or a `kagi.agent-docs` map
  already built — an object store, for a server that does not sit next to the
  vault."
  ([] (service (vault-read/vault-home)))
  ([home-or-docs]
   (if (map? home-or-docs)
     home-or-docs
     (docs/local-docs home-or-docs))))

(defn- load-catalog
  "Members, item metadata, grants and the ledger — everything that decides who
  may have what, and none of the ciphertext that makes it big."
  [svc]
  (or ((:catalog svc))
      (throw (ex-info "no vault in this store — run kagi init (and push, for an object store)"
                      {:store (docs/describe svc)}))))

;; ───────────────────────────── enrollment ─────────────────────────────

(defn enroll!
  "Register a principal against an invite. Returns
  `{:ok? true :principal … :token …}` or `{:ok? false :errors [{:rule …}]}`.

  The token is in the return value and nowhere else — only its hash reaches
  the vault, so this is the one moment it exists. `kagi.agent-protocol/token-hash`
  says why.

  PoW validity is decided by the caller (`kagi.agent-http` owns challenge
  state, because a challenge is a property of a connection and not of a
  vault). What this checks is the invite: that it exists, has not expired and
  has uses left, which is the part that carries the authorization."
  [svc {:keys [invite label] :as request} {:keys [pow-errors]}]
  (let [refusal (volatile! nil)
        result
        ((:update-registry! svc)
         (fn [reg]
           (let [record (agent/find-invite reg invite)
          ;; The transport already decided the PoW, because challenge state
          ;; belongs to a connection and not to a vault. So the codes that
          ;; depend on it are dropped from what `enrollment-errors` produces
          ;; HERE — and the transport's own verdict is kept.
          ;;
          ;; Dropping them from the combined list instead, which is what this
          ;; did first, deleted the transport's `:pow-failed` too and made the
          ;; proof of work unenforced end to end: an enrollment with the nonce
          ;; "definitely-wrong" was answered 201. `bad-work-is-refused-and-
          ;; burns-the-challenge` exists to keep that from coming back.
                 errs (into (vec pow-errors)
                            (remove #(#{:challenge-unknown :challenge-expired :pow-failed}
                                      (:rule %))
                                    (proto/enrollment-errors
                                     request
                                     {:challenge :checked-by-transport
                                      :invite-record record
                                      :now (now-iso)}
                                     agent/sha256-b64)))]
             (if (seq errs)
               (do (vreset! refusal {:ok? false :errors (vec errs)}) nil)
               (let [p (crypto/jvm-provider)
                     {:keys [token principal]}
                     (agent/approve p (assoc request :agent/label label) {:invite record})
                     existing (first (filter #(or (= (:agent/id principal) (:agent/id %))
                                                  (= (:agent/did principal) (:agent/did %)))
                                             (:agent/registry reg)))]
                 ;; Re-enrolling the same keypair would mint a SECOND principal
                 ;; sharing the first one's grants — revoking one would leave
                 ;; the other reading. An agent that wants a fresh token asks
                 ;; the owner to revoke and then enrolls with a fresh keypair.
                 ;; Returned as a refusal rather than thrown, so it reaches the
                 ;; client as a named rule like every other reason an
                 ;; enrollment does not happen.
                 ;;
                 ;; Returning nil from here aborts the write: a refused
                 ;; enrollment must not bump `:agent/seq` or spend the invite.
                 (if existing
                   (do (vreset! refusal
                                {:ok? false
                                 :errors [{:rule :already-enrolled
                                           :detail (str "この鍵/id は既に principal "
                                                        (:agent/id existing)
                                                        " として登録されている")}]})
                       nil)
                   (do (vreset! refusal {:ok? true :token token :principal principal})
                       (-> reg
                           (agent/register principal)
                           (agent/consume-invite (:invite/id record))))))))))]
    (cond-> @refusal
      (and (:ok? @refusal) result) (assoc :seq (:agent/seq result)))))

;; ───────────────────────────── authentication ─────────────────────────────

(defn authenticate
  "Bearer token → `{:ok? true :principal …}` or `{:ok? false :reason …}`.

  Revocation and expiry are answered HERE rather than left to the governor,
  because the governor runs in the agent's process on the agent's copy — and
  a check that only runs on the other side of the wire is not a check this
  side performed."
  [svc token]
  (let [prin (agent/principal-by-token ((:registry svc)) token)]
    (cond
      (nil? prin) {:ok? false :reason :unknown-token}
      (:agent/revoked-at prin) {:ok? false :reason :revoked
                                :at (:agent/revoked-at prin)}
      (and (:agent/not-after prin)
           (pos? (compare (now-iso) (:agent/not-after prin))))
      {:ok? false :reason :expired :at (:agent/not-after prin)}
      :else {:ok? true :principal prin})))

;; ───────────────────────────── release ─────────────────────────────

(defn- open-grant-for [st item-id did]
  (first (filter #(and (= did (:grant/recipient %)) (not (:grant/revoked %)))
                 (store/grants-of st item-id))))

(defn items
  "Metadata for the items this principal actually holds a grant on. Nothing is
  decrypted and nothing outside its grants is named — an agent is not told
  what it cannot open."
  [svc principal]
  (let [data (load-catalog svc)
        st (store/mem-store (dissoc data :meta))]
    (->> (vals (:items data))
         (filter #(open-grant-for st (:item/id %) (:agent/did principal)))
         (map #(select-keys % [:item/id :item/compartment :item/category :item/version]))
         (sort-by :item/id)
         vec)))

(defn sealed
  "Release one item's sealed material to a principal that is entitled to it.

  Answers are distinguishable, and each refusal names itself:

    {:status :ok :envelope … :nonce … :ciphertext … :aad …}
    {:status :forbidden :basis :agent-op}      ; その principal に reveal 権限が無い
    {:status :forbidden :basis :no-grant}      ; grant が無い/失効している
    {:status :forbidden :basis :compartment}   ; principal の compartment 外
    {:status :absent}                          ; そんな item は無い"
  [svc principal item-id]
  (let [data (load-catalog svc)
        st (store/mem-store (dissoc data :meta))
        it (store/item st item-id)]
    (cond
      (not (contains? (set (:agent/ops principal)) :item/reveal))
      {:status :forbidden :basis :agent-op}

      (nil? it) {:status :absent}

      (and (seq (:agent/compartments principal))
           (not (contains? (set (:agent/compartments principal)) (:item/compartment it))))
      ;; A second fence outside the grant: even if an item in another
      ;; compartment was granted by mistake, the principal's declared scope
      ;; still refuses it.
      {:status :forbidden :basis :compartment}

      :else
      (if-let [grant (open-grant-for st item-id (:agent/did principal))]
        {:status :ok
         :item-id item-id
         :envelope (:grant/envelope grant)
         :nonce (:item/nonce it)
         ;; ONE block, fetched by cid — not the whole vault. This is the read
         ;; the catalog/block split exists for.
         :ciphertext ((:block svc) (:item/cid it))
         :version (:item/version it)}
        {:status :forbidden :basis :no-grant}))))

;; ───────────────────────────── audit submission ───────────────────────────

(defn submit-audit!
  "Accept the principal's own signed ledger and keep it next to the vault.

  Verified against the public key the VAULT recorded at enrollment, never
  against one the submission supplies — a chain that carries its own
  verification key proves only internal consistency. A chain that does not
  verify is REJECTED rather than stored with a warning: a tamper-detecting
  log that keeps entries it could not authenticate has stopped detecting
  anything.

  Entries are also refused if they do not extend what was submitted before,
  so an agent cannot quietly replace its own history with a shorter one."
  [svc principal entries]
  (let [pub (some-> (:agent/sign-pub principal) identity/decode-bundle)
        previous (or (:ledger ((:read-audit svc) (:agent/id principal))) [])
        verdict (ledger/verify-chain entries (crypto/jvm-provider)
                                     (fn [did] (when (= did (:agent/did principal)) pub)))]
    (cond
      (not (:ok? verdict))
      {:status :rejected :basis :chain-broken :at (:broken-at verdict) :why (:why verdict)}

      (< (count entries) (count previous))
      {:status :rejected :basis :truncated
       :held (count previous) :submitted (count entries)}

      (not= (mapv :ledger/hash previous)
            (mapv :ledger/hash (take (count previous) entries)))
      {:status :rejected :basis :diverged :held (count previous)}

      :else
      (do ((:write-audit! svc) (:agent/id principal)
           {:ledger (vec entries) :received-at (now-iso)})
          {:status :accepted :entries (count entries)
           :new (- (count entries) (count previous))}))))

(defn whoami [_svc principal]
  (-> principal
      (dissoc :agent/token-hash :agent/kem-pub :agent/sign-pub)
      (assoc :agent/token :never-stored)))

(defn redact-token
  "For logs. Keeps the `kagi_agt_` prefix so a reader can tell WHAT kind of
  credential appeared, and nothing that helps them use it."
  [token]
  (let [t (str token)]
    (if (str/starts-with? t proto/token-prefix)
      (str proto/token-prefix "…" (subs t (max 0 (- (count t) 4))))
      "…")))))
