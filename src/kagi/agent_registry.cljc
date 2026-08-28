(ns kagi.agent-registry
  "The agent registry as DATA — the half of `kagi.agent` a server needs and a
  JVM is not required for.

  ## Why this is split out

  `kagi.agent` holds two different things. One is an agent-side session: open
  a vault, decapsulate a grant, run the governor, sign a ledger. That is JVM
  work and belongs where the vault is. The other is what a SERVER does with an
  enrollment: check an invite, derive a DID from a public key, mint a
  principal, look one up by token, revoke it. None of that touches a private
  key or a vault file, and all of it has to run wherever the API runs —
  including a Worker.

  So the registry operations live here, portably, and `kagi.agent` re-exports
  them. Callers do not have to know which half they are using; the boundary is
  visible in the requires.

  ## What stayed behind

  Reading and writing `registry.edn` — file locks and paths. A Worker reads the
  registry through `kagi.agent-docs` from an object store instead, so the file
  path was never the portable part."
  (:require [clojure.string :as str]
            [kagi.agent-protocol :as proto]
            [kagi.b64 :as b64]
            [kagi.crypto :as crypto]
            [kagi.digest :as digest]
            [kagi.key-registry :as key-registry]
            [kagi.pubkey :as pubkey]
            [kagi.store :as store]))

(defn random-id
  "A fresh opaque id. `random-uuid` exists on both runtimes."
  []
  (str #?(:clj (java.util.UUID/randomUUID) :cljs (random-uuid))))

(defn- unb64-map
  "`{:x \"b64\" :pq \"b64\"}` → the same map with host bytes. `crypto/kem-encap`
  encapsulates to bytes; the registry carries base64 because it is EDN."
  [m]
  (into {} (map (fn [[k v]] [k (if (string? v) (b64/decode v) v)])) m))

(defn now-iso
  "Seconds-precision UTC, `YYYY-MM-DDTHH:MM:SSZ`.

  Truncated on BOTH runtimes rather than only the JVM one. Sub-second
  precision has already cost this workspace a live outage once —
  `kagi.sync/fresh-cacao`'s docstring records `kagi push` failing because
  `(str (Instant/now))` renders nanoseconds and the apex's parser matches that
  regex and nothing else. Two runtimes producing differently-shaped timestamps
  for the same field is the same defect with a second way in."
  []
  #?(:clj (str (.truncatedTo (java.time.Instant/now) java.time.temporal.ChronoUnit/SECONDS))
     :cljs (str (subs (.toISOString (js/Date.)) 0 19) "Z")))

(defn plus-sec
  "`iso` + `sec`, at the same seconds precision."
  [iso sec]
  #?(:clj (str (.plusSeconds (java.time.Instant/parse ^String iso) (long sec)))
     :cljs (str (subs (.toISOString (js/Date. (+ (.getTime (js/Date. iso)) (* 1000 sec))))
                      0 19)
                "Z")))

(defn sha256-b64
  "The printable-digest seam `kagi.agent-protocol` asks for: base64, so a
  digest can sit in EDN and be compared as a value."
  [s]
  (b64/encode (digest/sha256-utf8 s)))

(defn- rand-token [p prefix n]
  (str prefix (b64/encode-url (crypto/rand-bytes p n))))

(def empty-registry {:agent/registry [] :agent/invites [] :agent/seq 0})

(defn mint-invite
  "Owner-side pre-authorization: the scope exists BEFORE any agent asks for
  it.

  Returns `{:secret :record}`. The secret is shown once and only its hash is
  stored — an invite a server can read back is an invite a server can leak,
  and this one is worth exactly the scope it names."
  [p {:keys [compartments ops purposes ttl-sec uses agent-ttl-sec note]}]
  (let [secret (rand-token p "kagi_inv_" 24)
        issued (now-iso)
        ops (set (or (seq ops) proto/default-ops))]
    (when-let [unknown (seq (remove proto/ops ops))]
      (throw (ex-info "unknown agent operation" {:ops (vec unknown)
                                                 :known (vec (sort (map str proto/ops)))})))
    {:secret secret
     :record #:invite{:id (random-id)
                      :secret-hash (proto/token-hash sha256-b64 secret)
                      :compartments (set compartments)
                      :ops ops
                      :purposes (set purposes)
                      :agent-ttl-sec (or agent-ttl-sec proto/default-agent-ttl-sec)
                      :uses-left (or uses 1)
                      :note note
                      :issued-at issued
                      :expires-at (plus-sec issued (or ttl-sec 900))}}))

(defn find-invite
  "Look an invite up by its SECRET, never by its id. The id is not a
  credential and the secret is, so the lookup key has to be the secret —
  otherwise an attacker who can read the registry (it is metadata, it is not
  encrypted) could enroll against any invite in it."
  [registry secret]
  (when-not (str/blank? (str secret))
    (let [h (proto/token-hash sha256-b64 secret)]
      (first (filter #(= h (:invite/secret-hash %)) (:agent/invites registry))))))

(defn add-invite [registry record]
  (update registry :agent/invites (fnil conj []) record))

(defn consume-invite
  "Decrement an invite's remaining uses. Called only after the enrollment it
  authorized actually landed — an invite spent on a refused enrollment would
  let a bad request burn a good invite."
  [registry invite-id]
  (update registry :agent/invites
          (fn [invites]
            (mapv (fn [i] (cond-> i
                            (= invite-id (:invite/id i))
                            (update :invite/uses-left (fnil dec 1))))
                  invites))))

(defn invites [registry]
  (mapv #(-> % (dissoc :invite/secret-hash) (assoc :invite/secret :redacted))
        (:agent/invites registry)))

(defn approve
  "Turn an enrollment request plus an invite into a principal and its API
  token.

  Pure: it neither writes the vault nor mints crypto beyond the token, so the
  caller keeps the persistence decision — and its ledger entry — the way
  `kagi.device/make-grant` does.

  `confirmed-fingerprint` is checked when supplied and REQUIRED for the
  offline path (the CLI passes it; the HTTP path substitutes the invite
  secret, which the enrolling agent could only have gotten from the owner).
  Mismatch is its own refusal code because it is the one that might be an
  attack.

  **The DID is derived here, never taken from the request.** `:member/did` is
  the key a grant names its recipient by, so a principal that could choose its
  own DID could choose one that already has grants — and `kagi.operation`'s
  recipient path would then hand it envelopes minted for somebody else. The
  DID follows from the Ed25519 public key by construction, so deriving it
  costs nothing and closes that entirely. A request that supplied a DID which
  disagrees is refused rather than quietly corrected: it is either a broken
  client or exactly the substitution just described."
  [p request {:keys [invite confirmed-fingerprint now]}]
  (let [sign-pub (get-in request [:agent/public :sign])
        ;; Derived from the encoded public key alone — no KeyFactory, no
        ;; private half, so this runs where the request arrives.
        derived-did (when (:ed sign-pub) (pubkey/did-key-from-spki-b64 (:ed sign-pub)))
        errs (cond-> []
               (or (nil? (get-in request [:agent/public :kem])) (nil? sign-pub))
               (conj {:rule :incomplete-keys :detail "public.kem と public.sign の両方が要る"})

               (and sign-pub (nil? derived-did))
               (conj {:rule :unreadable-key
                      :detail "public.sign.ed が Ed25519 公開鍵として読めない"})

               (and derived-did (seq (str (:agent/did request)))
                    (not= derived-did (:agent/did request)))
               (conj {:rule :did-mismatch
                      :detail (str "request の did が公開鍵から導かれる did と一致しない —"
                                   " 他の principal の grant を狙った差し替えの可能性がある")})

               (and (seq (str confirmed-fingerprint))
                    (get-in request [:agent/public :kem])
                    (not= (str/upper-case (str confirmed-fingerprint))
                          (pubkey/fingerprint (get-in request [:agent/public :kem]))))
               (conj {:rule :fingerprint-mismatch
                      :detail "request の KEM 公開鍵と読み上げられた fingerprint が一致しない —
                               中止して経路を確認すること"}))]
    (when (seq errs)
      (throw (ex-info "agent enrollment refused" {:agent/errors errs})))
    (let [token (rand-token p "kagi_agt_" 32)
          at (or now (now-iso))
          request (assoc request
                         :agent/did derived-did
                         :agent/id (or (not-empty (str (:agent/id request)))
                                       (random-id)))]
      {:token token
       :principal #:agent{:id (:agent/id request)
                          :label (:agent/label request)
                          :did (:agent/did request)
                          :fingerprint (pubkey/fingerprint (get-in request [:agent/public :kem]))
                          :kem-pub (get-in request [:agent/public :kem])
                          :sign-pub (get-in request [:agent/public :sign])
                          :compartments (set (:invite/compartments invite))
                          :ops (set (:invite/ops invite))
                          :purposes (set (:invite/purposes invite))
                          :token-hash (proto/token-hash sha256-b64 token)
                          :invite (:invite/id invite)
                          :enrolled-at at
                          :not-after (plus-sec at (or (:invite/agent-ttl-sec invite)
                                                      proto/default-agent-ttl-sec))}
       })))

(defn member-of
  "The vault member record this principal acts as — DERIVED from the principal
  rather than stored beside it.

  Registered as a MEMBER, never an owner. `kagi.governor/permissions` then caps
  it at reveal/list/update before `:agent/ops` narrows it further, and
  `access-violations` makes every reveal need an explicit grant. Two
  independent fences, and neither is this namespace's own code.

  Derived, not stored, because the registry already holds every input: a
  second copy is a second thing to keep in step, and the one that drifts is
  always the copy nobody reads until a grant fails.

  `:member/kem-pub` is RAW BYTES, not the base64 the registry carries —
  `crypto/kem-encap` encapsulates to bytes. `:member/kem-key` is minted from
  the principal's own expiry: `key-registry/authorize!` fails closed on a
  missing key, so a principal without one simply cannot be granted anything."
  [{:agent/keys [id did kem-pub sign-pub enrolled-at not-after]}]
  #:member{:did did
           :role :member
           :kem-pub (unb64-map kem-pub)
           :sign-pub sign-pub
           :kem-key (key-registry/transition
                     (key-registry/key-record
                      {:id (str "kem:agent:" id)
                       :purpose :recipient-kem
                       :suite :kem-v1
                       :epoch 0
                       :created-at enrolled-at
                       :not-before enrolled-at
                       :originator-not-after not-after
                       :custody-ref (str "agent://" id)})
                     :active enrolled-at)})

(defn register [registry principal]
  (update registry :agent/registry (fnil conj []) principal))

(defn principal
  ([registry agent-id]
   (first (filter #(= agent-id (:agent/id %)) (:agent/registry registry)))))

(defn principal-by-token
  "Resolve a bearer token to its principal, or nil. Compares HASHES — the
  vault never held the token itself, so there is nothing here to compare
  against in the clear."
  [registry token]
  (when-not (str/blank? (str token))
    (let [h (proto/token-hash sha256-b64 token)]
      (first (filter #(= h (:agent/token-hash %)) (:agent/registry registry))))))

(defn revoke-agent
  "Mark a principal revoked. Its token stops working immediately and the
  governor refuses every op (`:agent-revoked`).

  READ THIS BEFORE RELYING ON IT: like every revocation, it does not reach
  into a machine that already has something. What makes it different from
  `kagi.device/revoke-device` is what the agent HAS — grants, not a VMK — so
  the follow-up that actually closes the door exists: `kagi agent ungrant`
  (`:share/revoke`) re-keys each item and re-encapsulates it to the remaining
  recipients. Revoke, then ungrant every item, and the principal's envelopes
  open nothing. `status` reports the outstanding grants so 'then ungrant every
  item' is a list and not a memory exercise."
  [registry agent-id at]
  (update registry :agent/registry
          (fn [rs] (mapv (fn [r] (cond-> r
                                   (= agent-id (:agent/id r))
                                   (assoc :agent/revoked-at (or at (now-iso)))))
                         rs))))

(defn- redact-principal
  "What `kagi agent ls` should actually show.

  The public keys are dropped even though they are public: two of them are
  ~2KB of base64 each, and a listing nobody can read is a listing nobody
  checks. `:agent/fingerprint` is the short form of the same material and is
  what an operator compares anyway."
  [p]
  (-> p
      (dissoc :agent/token-hash :agent/kem-pub :agent/sign-pub)
      (assoc :agent/token :never-stored)))

(defn status
  "What `kagi agent ls` shows. No key material, no token, ever.

  `store` is optional; with it, each principal reports the items it can
  actually open. That number is the honest answer to 'what does this agent
  reach', and it is only knowable because the answer is a set of grants."
  ([registry] (status registry nil))
  ([registry st]
   {:agents (mapv (fn [a]
                    (cond-> (redact-principal a)
                      st (assoc :agent/grants
                                (vec (sort (keep (fn [it]
                                                   (when (some #(and (= (:agent/did a) (:grant/recipient %))
                                                                     (not (:grant/revoked %)))
                                                               (store/grants-of st (:item/id it)))
                                                     (:item/id it)))
                                                 (vals (:items @(:a st)))))))))
                  (:agent/registry registry))
    :invites (invites registry)
    :seq (:agent/seq registry 0)}))
