(ns kagi.agent-docs
  "Where `kagi.agent-service` reads and writes, as four functions.

  ## Why a seam and not a path

  The agent API started out reading `$KAGI_HOME/vault.edn` and
  `agents/registry.edn` off local disk, which is correct for the case it was
  built for — an agent and a vault on the same machine. A public endpoint is
  the other case: the server runs somewhere the vault file is not, and the
  documents live in an object store.

  Both are the same three documents with the same rules, so what changes is
  where they are, not what they mean:

      :catalog   members, item METADATA, grants, ledger — read only, small
      :block     one item's ciphertext, by cid            — read only, the bulk
      :registry  principals and invites                   — enrollment appends here
      audit/<id> one agent's submitted ledger             — verified before storage

  The catalog/block split is measured rather than aesthetic: the real vault is
  9.58 MB across 93 blocks, and answering about ONE item used to mean fetching
  and parsing all of it (~125 ms locally, a full egress over a network). The
  bulk is the ciphertext; the metadata that decides who may have it is small.

  ## The service never writes the vault, in either backend

  `local-docs` exposes no vault write at all, and `object-docs` does not
  either. That is the same rule as the local case (`kagi.agent`'s ns docstring:
  a read-only principal that can rewrite the store it reads from is not
  read-only), and it holds harder over a network.

  ## Conflicts

  `local-docs` uses `kagi.agent/update-registry!` — a cross-process file lock
  plus a sequence check. `object-docs` uses the versioned-key discipline in
  `kagi.sync/object-write!`: a second writer at the same sequence finds bytes
  it did not write and is refused, rather than erasing the first one's
  registry. Different mechanisms because the substrates differ; the same
  guarantee, and both fail closed.

  ## `.cljc` with only a `:clj` branch, and saying so\n\n  `local-docs` is file IO and stays JVM; `object-docs` is already portable in\n  substance and only waits on `kagi.sync` following it. The extension follows\n  the portable-first rule (ADR-2608201300); the split is tracked in\n  ADR-2608281100."
  #?@(:clj [(:require [kagi.agent :as agent]
            [kagi.persist :as persist]
            [kagi.sync :as sync])]))

#?(:clj
   (do


;; ───────────────────────────── local files ─────────────────────────────

(defn local-docs
  "The documents under a vault home. This is what `kagi agent serve` uses when
  the vault is on the same machine."
  [home]
  {:label :local
   :home home
   ;; Local pays two file reads for a `sealed` (catalog, then block). That is
   ;; the honest cost of one seam serving both backends, it is unchanged in
   ;; kind from the single read it replaces, and local is loopback — the split
   ;; exists for the case where the bytes cross a network.
   :catalog (fn [] (some-> (persist/load* (str home "/vault.edn")) (dissoc :blocks)))
   :block (fn [cid] (get (:blocks (persist/load* (str home "/vault.edn"))) cid))
   :registry (fn []
               (agent/migrate-registry! home (:meta (persist/load* (str home "/vault.edn"))))
               (agent/load-registry home))
   :update-registry! (fn [f] (agent/update-registry! home f))
   :read-audit (fn [agent-id]
                 (persist/load* (str (agent/agents-dir home) "/" agent-id ".submitted.edn")))
   :write-audit! (fn [agent-id value]
                   (persist/save! (str (agent/agents-dir home) "/" agent-id ".submitted.edn")
                                  value)
                   value)})

;; ───────────────────────────── object store ─────────────────────────────

(defn- read-doc [{:keys [fns did prefix]} doc]
  (when-let [{:keys [text]} (sync/object-read {:fns fns :did did :doc doc :prefix prefix})]
    (persist/<-edn text)))

(defn object-docs
  "The same three documents in an S3-compatible object store, under one DID.

  `fns` is `{:get-object :put-object :exists?}` — the shape
  `kagi.object-store/from-env` returns and `kagi.store` already takes, so a
  server run from a bucket needs no new client.

  `did` is the tenant: every key is `<prefix><did>/<doc>/…`, so one bucket can
  hold many vaults and none of them can name another's key."
  [{:keys [fns did prefix] :as cfg}]
  (when-not (and fns did)
    (throw (ex-info "object-docs needs :fns and :did" {:got (keys cfg)})))
  {:label :object
   :did did
   :catalog (fn [] (read-doc cfg :catalog))
   :block (fn [cid] (sync/object-get-block cfg cid))
   :registry (fn [] (or (read-doc cfg :registry) agent/empty-registry))
   :update-registry!
   (fn [f]
     ;; Read → f → versioned write. `:expected-seq` makes the store refuse a
     ;; write that would land on top of somebody else's, so a concurrent
     ;; enrollment loses its own write rather than the other one's.
     (let [current (or (read-doc cfg :registry) agent/empty-registry)
           next (f current)]
       (when next
         (let [saved (assoc next :agent/seq (inc (:agent/seq current 0)))]
           (sync/object-write! {:fns fns :did did :doc :registry :prefix prefix
                                :expected-seq (:agent/seq current 0)
                                :text (persist/->edn saved)})
           saved))))
   :read-audit (fn [agent-id] (read-doc cfg (str "audit-" agent-id)))
   :write-audit! (fn [agent-id value]
                   (sync/object-write! {:fns fns :did did :doc (str "audit-" agent-id)
                                        :prefix prefix :text (persist/->edn value)})
                   value)})

(defn describe
  "What `kagi agent serve` prints so an operator can see which store is being
  served. Never includes a credential."
  [docs]
  (select-keys docs [:label :home :did]))))
