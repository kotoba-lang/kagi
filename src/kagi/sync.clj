(ns kagi.sync
  "Cloud persistence for the kagi vault, iCloud-Keychain / 1Password style
  (ADR-2607170500). The vault snapshot is ALREADY end-to-end encrypted on disk
  (ciphertext items + wrapped VMK + ledger — `kagi.persist/->edn` emits no
  plaintext, no raw VMK), so pushing that exact blob to an untrusted server is
  safe: kotobase.net only ever holds ciphertext, and the master passphrase /
  OS-keychain VMK unlock never leaves the device. That is precisely the
  iCloud-Keychain trust model — the server is a sync relay, not a trust root.

  Transport: the encrypted snapshot is stored as a single upserted datom in the
  actor's own tenant graph `kotobase/db/<did>/kagi-vault` on kotobase.net,
  authorized by a depth-1 self-minted CACAO. The actor owns the graph by
  construction (graph CID = hash of its own DID + db-name), so no handed token
  and no coordination-server auth-key are needed.

    kagi push   local vault -> cloud (upsert snapshot under this actor's graph)
    kagi pull   cloud -> local vault (with a local backup first)
    kagi sync   pull-if-newer then push (last-writer-wins by :kagi.vault/seq)

  ## Two backends, because one of them is currently refused

  `kotobase` (above) is the original. As of 2026-08-28 it does not work: the
  graph-database runs with `KOTOBASE_BISCUIT_AUTH_MODE=required` and answers
  401 to any non-Biscuit Authorization before the CACAO branch is reached
  (ADR-2608281200). The CACAO this namespace mints is correct — it verifies
  against the gateway's own algorithm — so there is nothing to fix here; the
  plane moved and getting a Biscuit needs a tenant record and a service
  account this vault does not have.

  `object` (below) is the second backend: the same already-encrypted snapshot,
  put into an S3-compatible object store (Backblaze B2, Storj) through the
  SAME four functions `kagi.store/object-sealed-block-store` takes. It exists
  so vault persistence does not have to wait on that provisioning decision,
  and it keeps the same trust model — the store holds ciphertext and the
  unlock secret never leaves the device."
  (:require [json.data-json :as json]
            [clojure.string :as str]
            [kagi.cacao :as cacao]
            [kagi.crypto :as crypto]
            [kagi.persist :as persist])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
            HttpResponse$BodyHandlers]
           [java.time Instant]
           [java.time.temporal ChronoUnit]
           [java.util UUID]))

(def default-pod "https://kotobase.net")
(def default-db-name "kagi-vault")

;; ── schema (idempotent; installed via :db/add VECTOR datoms every push) ──────
;; The live kotobase-server needs :db/add vector forms, NOT map-entity forms,
;; and MAP-shaped queries (confirmed live by cloud-murakumo/queue_kotoba
;; 2026-07-12 — a vector query silently returns zero rows). :kagi.vault/id is
;; unique-identity so pushes UPSERT the single vault entity.
(def ^:private vault-attrs
  [[:kagi.vault/id       :db.type/string :db.cardinality/one :db.unique/identity]
   [:kagi.vault/snapshot :db.type/string :db.cardinality/one nil]
   [:kagi.vault/seq      :db.type/long   :db.cardinality/one nil]
   [:kagi.vault/at       :db.type/string :db.cardinality/one nil]])

(defn- schema-eid [ident] (str "schema:" (subs (str ident) 1)))

(def ^:private vault-schema-tx
  (vec (mapcat (fn [[ident vt card uniq]]
                 (let [e (schema-eid ident)]
                   (cond-> [[:db/add e :db/ident ident]
                            [:db/add e :db/valueType vt]
                            [:db/add e :db/cardinality card]]
                     uniq (conj [:db/add e :db/unique uniq]))))
               vault-attrs)))

(defn jvm-http-fn
  "host-caps :http-fn over the JDK HTTP client (no dependency)."
  [{:keys [url method headers body]}]
  (let [b (HttpRequest/newBuilder (URI/create url))]
    (doseq [[k v] headers] (.header b k v))
    (let [req  (-> b (.method (str/upper-case (name (or method :post)))
                            (if body
                              (HttpRequest$BodyPublishers/ofString body)
                              (HttpRequest$BodyPublishers/noBody)))
                   (.build))
          resp (.send (HttpClient/newHttpClient) req (HttpResponse$BodyHandlers/ofString))]
      {:status (.statusCode resp) :body (.body resp)})))

;; Direct XRPC (not langchain.kotoba-db's api map): the live worker returns
;; query rows under `:rows` (kdb's :q reads the stale `:rows_edn` name → always
;; empty here), writes require `:db_name` (the edge derives the tenant graph),
;; reads require the canonical `:graph` CID. Auth is a fresh mint-kotobase CACAO
;; in the Authorization header AND the body cacao_b64 (the tenant-cap write gate
;; wants both).

(defn- fresh-cacao
  "A CACAO for exactly one apex call.

  `iat`/`exp` must be ISO-8601 SECONDS precision — exactly
  `YYYY-MM-DDTHH:MM:SSZ`. The apex's `parse-utc-seconds` matches that regex
  and NOTHING else: it accepts neither epoch seconds nor a fractional part,
  and a value it cannot parse becomes `invalid CACAO iat` -> 401.

  This is why `kagi push` was failing. `(str (Instant/now))` renders
  nanoseconds whenever they are non-zero (`2026-07-27T10:15:30.123456789Z`),
  so most mints did not match, and the ones that happened to land on a whole
  second did. `truncatedTo SECONDS` makes it unconditional.

  A fresh nonce per call is mandatory — the edge records nonces for replay
  protection, so reusing one across a retry 401s."
  [id]
  (let [now (.truncatedTo (Instant/now) ChronoUnit/SECONDS)]
    (cacao/mint-kotobase id {:nonce (str (UUID/randomUUID))
                             :issued-at (str now)
                             :expiry (str (.plusSeconds now 300))})))

(defn- xrpc! [url nsid id body]
  (let [c    (fresh-cacao id)
        resp (jvm-http-fn {:url (str url "/xrpc/ai.gftd.apps.kotobase." nsid)
                           :method :post
                           :headers {"content-type" "application/json"
                                     "authorization" (str "CACAO " c)
                                     "x-kotoba-did" (:did id)}
                           :body (json/write-str (assoc body :cacao_b64 c))})
        data (json/read-str (:body resp) :key-fn keyword)]
    (when-not (and (#{200 201} (:status resp)) (:ok data))
      (throw (ex-info (str "kotobase " nsid " failed: " (:error data))
                      {:status (:status resp) :body (:body resp)})))
    data))

(defn- q! [url id db-name query]
  (let [graph (cacao/canonical-graph (:did id) db-name)]
    (:rows (xrpc! url "datomic.q" id {:graph graph :query_edn (pr-str query)}))))

(defn- transact! [url id db-name tx]
  (xrpc! url "datomic.transact" id {:db_name db-name :tx_edn (pr-str (vec tx))}))

;; MAP-shaped queries only — a vector query silently hits the triple-pattern
;; engine and returns zero rows (cloud-murakumo/queue_kotoba, 2026-07-12).
(def ^:private seq-query
  '{:find [?s] :where [[?e :kagi.vault/id "vault"] [?e :kagi.vault/seq ?s]]})
(def ^:private snapshot-query
  '{:find [?snap ?s]
    :where [[?e :kagi.vault/id "vault"]
            [?e :kagi.vault/snapshot ?snap]
            [?e :kagi.vault/seq ?s]]})

(defn- ->long [x] (if (number? x) (long x) (Long/parseLong (str x))))

(defn- read-remote-seq
  "Current max :kagi.vault/seq on the server (0 if none). Transport and auth
  failures propagate: treating an unreadable remote as empty would enable overwrite."
  [url id db-name]
  (reduce max 0 (map (comp ->long first) (q! url id db-name seq-query))))

(defn assert-expected-seq!
  "Optimistic concurrency gate. Prevents a device from overwriting a snapshot
  changed after its pull. nil retains explicit legacy/force-push semantics."
  [expected actual]
  (when (and (some? expected) (not= (long expected) (long actual)))
    (throw (ex-info "cloud vault changed since pull"
                    {:reason :sync-conflict :expected expected :actual actual})))
  true)


;; ───────────────────────── object-store backend ──────────────────────────
;;
;; Layout under `<prefix><did>/`:
;;
;;     v<seq>.edn   the encrypted snapshot at that sequence — NEVER overwritten
;;     HEAD         {:seq N :at <iso> :bytes M} — which version is current
;;
;; The versioned key is the concurrency control. An object store gives no
;; compare-and-swap through the four-function seam, but it gives something
;; that is enough here: refusing to overwrite a key that already holds
;; DIFFERENT bytes. Two devices that both push from sequence N both try to
;; write `v<N+1>.edn`; the second one finds bytes it did not write and fails
;; with `:sync-conflict` instead of erasing the first one's vault. A retry of
;; the SAME bytes (a partial failure) passes, because that is a retry and not
;; a second writer — the same distinction `kagi.store/object-sealed-block-store`
;; draws, for the same reason.
;;
;; HEAD is last-writer-wins, and that is survivable: it is a pointer, and every
;; version it could have pointed at is still in the store. A lost HEAD race
;; costs a `pull` and a re-push, not a vault.

(def ^:const default-prefix "kagi/")

(defn- ->text
  "The four functions contract 0-255 vectors (that is what `storj.store`
  returns); the snapshot is UTF-8 text. Converting at the seam rather than in
  each caller is why `kagi.store` has `->host-bytes` — the path that forgets is
  the one that only fails at read time."
  [v]
  (cond
    (nil? v) nil
    (string? v) v
    (sequential? v) (String. (byte-array (map unchecked-byte v)) "UTF-8")
    (bytes? v) (String. ^bytes v "UTF-8")
    :else (str v)))

(defn- ->octets [^String s]
  (vec (map #(bit-and % 0xff) (.getBytes s "UTF-8"))))

(defn- object-keys
  "Keys for one named document under one DID.

  `doc` exists because the vault snapshot is not the only thing that has to
  live next to a vault: `kagi.agent-service` keeps the principal registry and
  each agent's submitted ledger in the same store, and they need the same
  versioned-write discipline. One layout, one conflict rule, rather than a
  second mechanism per document."
  [prefix did doc]
  (let [base (str (or prefix default-prefix) did "/" (name doc) "/")]
    {:head (str base "HEAD") :version #(str base "v" % ".edn")}))

(defn- read-head [{:keys [get-object]} keys*]
  (try
    (when-let [t (->text (get-object (:head keys*)))]
      (persist/<-edn t))
    (catch Exception _ nil)))

(defn object-write!
  "Write one version of a named document. `text` is the exact bytes to store —
  the caller has already made it ciphertext or decided it is not secret.

  Returns `{:seq :previous-seq :bytes :key :backend}`."
  [{:keys [fns did doc prefix expected-seq text]}]
  (let [keys* (object-keys prefix did (or doc :vault))
        head (read-head fns keys*)
        remote-seq (long (or (:seq head) 0))
        _ (assert-expected-seq! expected-seq remote-seq)
        next-seq (inc remote-seq)
        version-key ((:version keys*) next-seq)
        existing (when-let [e (:exists? fns)]
                   (when (e version-key) (->text ((:get-object fns) version-key))))]
    (when (and existing (not= existing text))
      (throw (ex-info "cloud vault changed since pull"
                      {:reason :sync-conflict :expected expected-seq :actual next-seq
                       :doc (or doc :vault)
                       :detail (str "another writer already wrote " version-key)})))
    ((:put-object fns) version-key (->octets text))
    ((:put-object fns) (:head keys*)
     (->octets (persist/->edn {:seq next-seq :at (str (Instant/now))
                               :bytes (count text) :did did :doc (or doc :vault)})))
    {:seq next-seq :previous-seq remote-seq :bytes (count text)
     :key version-key :backend :object}))

(defn object-read
  "Read the current version of a named document → `{:seq :text}`, or nil when
  the store has none.

  A HEAD that points at a version the store does not have throws rather than
  answering nil: 'never written' and 'the version it names is gone' are
  different situations, and a caller that overwrites a local file on the second
  one loses the vault."
  [{:keys [fns did doc prefix]}]
  (let [keys* (object-keys prefix did (or doc :vault))
        head (read-head fns keys*)]
    (when (:seq head)
      (let [text (->text ((:get-object fns) ((:version keys*) (:seq head))))]
        (when (str/blank? (str text))
          (throw (ex-info "HEAD points at a version the store does not have"
                          {:reason :sync-missing-version :seq (:seq head)
                           :doc (or doc :vault)})))
        {:seq (long (:seq head)) :text text}))))

(defn- block-key
  "`blocks/<sha256(cid) hex>`, not the cid itself, for two reasons.

  **It has to be key-safe.** A cid is `cid:<item-id>:v<n>`; item ids are
  arbitrary strings and the colons are ours. Backblaze answered `HTTP 500` to a
  PUT of `blocks/cid:manimani-…:v1` (measured 2026-08-28) — whatever the cause
  in their stack, a key shape that only sometimes survives is not one to build
  on.

  **And the key must not name the secret.** `blocks/cid:manimani-gmail-root-…`
  tells anyone who can LIST the bucket that a credential by that name exists.
  The snapshot layout leaked nothing because it was one opaque blob; splitting
  it per item would have turned the item index into the key space. Hashing
  keeps the split and gives that back.

  Deterministic, so a reader computes the same key from the catalog's cid."
  [prefix did cid]
  (str (or prefix default-prefix) did "/blocks/"
       (str/join (map #(format "%02x" (bit-and % 0xff))
                      (crypto/sha256 (.getBytes ^String (str cid) "UTF-8"))))))

(defn object-put-block!
  "Store one item's ciphertext under its own key.

  Refuses a key that already holds DIFFERENT bytes, and passes an identical
  re-PUT. That is `kagi.store/object-sealed-block-store`'s rule, for its
  reason: a cid carries the version, so the same key receiving different bytes
  is a bug or an attack, and silently overwriting erases ciphertext a grant may
  still point at. An identical re-PUT is a retry from a partial failure, and
  refusing those would jam the recovery path.

  Returns `:written`, `:already-there`, or throws."
  [{:keys [fns did prefix]} cid ^bytes bytes*]
  (let [k (block-key prefix did cid)
        existing (when-let [e (:exists? fns)]
                   (when (e k) ((:get-object fns) k)))]
    (cond
      (nil? existing) (do ((:put-object fns) k (vec (map #(bit-and % 0xff) bytes*))) :written)
      (= (vec (map #(bit-and % 0xff) existing))
         (vec (map #(bit-and % 0xff) bytes*))) :already-there
      :else (throw (ex-info "object block key already holds different ciphertext"
                            {:reason :block-conflict :cid cid
                             :existing-bytes (count existing)
                             :incoming-bytes (alength bytes*)})))))

(defn object-get-block
  "One item's ciphertext, or nil. Returns host bytes, which is what
  `kagi.crypto`'s AEAD takes."
  [{:keys [fns did prefix]} cid]
  (when-let [v ((:get-object fns) (block-key prefix did cid))]
    (if (bytes? v) v (byte-array (map unchecked-byte v)))))

(defn object-push!
  "Upload the vault as a CATALOG, a LEDGER, and one object per ciphertext block.

  The split is measured, and the first measurement was wrong in an instructive
  way. The real vault is 9,576,873 bytes, and the guess was that the ciphertext
  was the bulk. It is not:

      ledger    9,502,228 bytes   n=1965   ← 99.2%
      items        37,637 bytes   n=88
      blocks       31,040 bytes   n=93
      members       5,382 bytes   n=1
      grants/meta      507 bytes

  Every governed operation appends a hybrid-signed entry, and an ML-DSA-65
  signature is ~3.3 KB of base64. **The audit trail is the vault**, by two
  orders of magnitude over everything it audits.

  So the catalog is members + item metadata + grants — the ~43 KB that decides
  who may read what — and the ledger is its own document, fetched only by
  something that wants the audit trail. A server answering `/items` or
  `/sealed` now reads ~43 KB instead of 9.58 MB.

  Blocks are still separate and still worth it: they are immutable per version
  (the cid carries it), so a push after changing one item re-sends one block
  rather than all of them.

  `fns` is `{:get-object :put-object :exists?}` — the shape
  `storj.store/store-fns` returns, so Storj and B2 differ only by endpoint."
  [{:keys [fns did vault-path prefix expected-seq] :as cfg}]
  (let [data (persist/load* vault-path)
        _ (when-not data (throw (ex-info "no vault to push" {:path vault-path})))
        blocks (:blocks data)
        written (reduce (fn [acc [cid bytes*]]
                          (update acc (object-put-block! cfg cid bytes*) (fnil inc 0)))
                        {} blocks)
        ;; The catalog names EVERY block that was uploaded, not just the ones
        ;; current items point at. A vault can hold superseded versions (a
        ;; rotation leaves the previous ciphertext behind), and deriving the
        ;; set from `:item/cid` on the way back silently restored 88 of 93 —
        ;; a backup that quietly returns less than it was given. The
        ;; four-function seam has no `list`, so the manifest has to be written
        ;; down rather than discovered.
        catalog (assoc (dissoc data :blocks :ledger)
                       :kagi.sync/block-cids (vec (sort (keys blocks))))
        ledger-result (object-write! {:fns fns :did did :doc :ledger :prefix prefix
                                      :text (persist/->edn (:ledger data))})
        result (object-write! {:fns fns :did did :doc :catalog :prefix prefix
                               :expected-seq expected-seq
                               :text (persist/->edn catalog)})]
    (assoc result
           :blocks (count blocks)
           :blocks-written (get written :written 0)
           :blocks-already-there (get written :already-there 0)
           :catalog-bytes (:bytes result)
           :ledger-bytes (:bytes ledger-result)
           :ledger-entries (count (:ledger data)))))

(defn object-pull!
  "Fetch the current snapshot and write it to `vault-path` (backing the local
  file up to `<vault-path>.bak` first). Returns `{:seq :bytes}`, or
  `{:seq nil}` when the store has none."
  [{:keys [fns did vault-path prefix] :as cfg}]
  (let [current (object-read {:fns fns :did did :doc :catalog :prefix prefix})]
    (if-not current
      {:seq nil}
      (let [catalog (persist/<-edn (:text current))
            ledger (some-> (object-read {:fns fns :did did :doc :ledger :prefix prefix})
                           :text persist/<-edn)
            ;; Fetch every block the catalog names BEFORE touching the local
            ;; file. A restore that wrote a vault whose ciphertext is missing
            ;; would look like a vault whose items are empty.
            ;; The manifest the push wrote, falling back to the item cids for a
            ;; catalog written before there was one.
            cids (or (seq (:kagi.sync/block-cids catalog))
                     (into #{} (comp (map :item/cid) (remove nil?)) (vals (:items catalog))))
            blocks (reduce (fn [acc cid]
                             (if-let [b (object-get-block cfg cid)]
                               (assoc acc cid b)
                               (throw (ex-info "catalog names a block the store does not have"
                                               {:reason :sync-missing-block :cid cid}))))
                           {} cids)
            restored (-> catalog
                         (dissoc :kagi.sync/block-cids)
                         (assoc :blocks blocks :ledger (vec ledger)))
            snap (persist/->edn restored)
            f (java.io.File. ^String vault-path)]
        (when (.exists f)
          (java.nio.file.Files/copy (.toPath f)
                                    (.toPath (java.io.File. (str vault-path ".bak")))
                                    (into-array java.nio.file.CopyOption
                                                [java.nio.file.StandardCopyOption/REPLACE_EXISTING])))
        (spit vault-path snap)
        {:seq (long (:seq current)) :bytes (count snap) :blocks (count blocks)
         :ledger-entries (count ledger) :backend :object}))))

(defn object-remote-seq
  "Current sequence in the store, 0 when empty. Used by `sync` to decide
  whether a pull is needed before pushing."
  [{:keys [fns did doc prefix]}]
  (long (or (:seq (read-head fns (object-keys prefix did (or doc :catalog)))) 0)))

(defn push!
  "Upsert the local encrypted vault snapshot into the actor's cloud graph.
  Returns {:seq :bytes :graph :pod}."
  [{:keys [id vault-path pod db-name expected-seq]}]
  (let [url  (or pod default-pod)
        db   (or db-name default-db-name)
        snap (slurp vault-path)                 ; already ciphertext-only
        remote-seq (read-remote-seq url id db)
        _ (assert-expected-seq! expected-seq remote-seq)
        seq  (inc remote-seq)
        eid  "kagi.vault:vault"
        tx   (into vault-schema-tx
                   [[:db/add eid :kagi.vault/id "vault"]
                    [:db/add eid :kagi.vault/snapshot snap]
                    [:db/add eid :kagi.vault/seq seq]
                    [:db/add eid :kagi.vault/at (str (Instant/now))]])]
    (transact! url id db tx)
    {:seq seq :previous-seq remote-seq :bytes (count snap)
     :graph (cacao/canonical-graph (:did id) db) :pod url}))

(defn pull!
  "Fetch the latest cloud vault snapshot and write it to vault-path (after
  backing up the current local file to <vault-path>.bak). Returns {:seq :bytes}
  or {:seq nil} if the cloud has no snapshot."
  [{:keys [id vault-path pod db-name]}]
  (let [url  (or pod default-pod)
        db   (or db-name default-db-name)
        rows (q! url id db snapshot-query)]
    (if (empty? rows)
      {:seq nil}
      (let [[snap seq] (apply max-key (comp ->long second) rows)]
        ;; sanity: it must parse as a kagi vault snapshot before we overwrite.
        (persist/<-edn snap)
        (let [f (java.io.File. ^String vault-path)]
          (when (.exists f)
            (java.nio.file.Files/copy (.toPath f)
                                      (.toPath (java.io.File. (str vault-path ".bak")))
                                      (into-array java.nio.file.CopyOption
                                                  [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))))
        (spit vault-path snap)
        {:seq (->long seq) :bytes (count snap)}))))
