(ns kagi.agent-http
  "The agent-facing HTTP surface — an API an agent can enroll itself into, in
  the shape of the agent-inbox host this workspace already talks to
  (`scripts/agentmail-inbox-create.cljs`).

  ## The flow, and it is the same three calls

      1. POST /v1/agents/challenges   {purpose}
           -> {challenge_id, algorithm:\"sha256-v1\", challenge,
               difficulty_bits, expires_at}
      2. (solve locally: sha256(challenge \":\" nonce) の先頭 N bit が 0)
      3. POST /v1/agents              {invite, label, public{kem,sign},
                                       pow{challenge_id, nonce}}
           -> {agent_id, account_key, not_after, ops, compartments}

  `account_key` is returned **once** and is not recoverable — the vault stored
  only its hash. That is the same contract the inbox host keeps, and this
  workspace has already paid for getting it wrong: an inbox was lost on
  2026-08-21 to a key written once, badly, and never readable again.

  ## The invite is the authorization; the proof-of-work is not

  An enrollment with a perfect PoW and no invite is refused
  (`kagi.agent-protocol/enrollment-errors`, `:invite-missing`). An inbox
  handed to whoever solves a puzzle is worth what the puzzle costs. A vault is
  not, and shipping the puzzle as if it were the gate is how an API like this
  becomes a footgun with a nice SDK. The owner mints the invite, and the
  invite already names the compartments, the operations and the expiry before
  any agent asks.

  What the PoW does buy is that guessing invites costs ~2^20 hashes per
  attempt.

  ## Nothing here decrypts anything

  See `kagi.agent-service`: `/v1/items/<id>/sealed` releases material that is
  already ciphertext, encapsulated to the requesting principal's own public
  key. This process never holds a VMK, so terminating TLS in front of it,
  dumping its heap or reading its logs yields ciphertext — the same thing the
  vault file already yields.

  ## Binding

  127.0.0.1 by default. A non-loopback bind is allowed and returns a
  `:warning` saying what it now requires (TLS in front, and an operator who
  meant it) rather than silently being an unauthenticated-looking plaintext
  service on a LAN.

  ## Two encodings, one shape

  Handlers build ONE response map with snake_case keys; `accept:
  application/edn` renders it as EDN (byte arrays round-trip exactly through
  `kagi.persist`), anything else as JSON with byte arrays base64'd. A response
  described in two places is a response that drifts in one of them.

  ## `.cljc` with only a `:clj` branch, and saying so\n\n  Everything below binds a socket through `com.sun.net.httpserver`, so the JVM\n  half is the only half that exists today. The file carries the portable\n  extension because the RULE is that new production code is portable-first\n  (ADR-2608201300), and because the split this needs is real rather than\n  cosmetic: routing, the challenge token shape and the response encoding are\n  host-independent, and `kagi.ui.server` is the worked example of separating\n  them in this repo. That separation is the remaining Worker-port work\n  (ADR-2608281100), and this comment is here so the extension does not claim\n  it has already happened."
  #?@(:clj [(:require [json.data-json :as json]
            [clojure.string :as str]
            [clojure.walk :as walk]
            [kagi.agent-protocol :as proto]
            [kagi.agent-service :as service]
            [kagi.crypto :as crypto]
            [kagi.persist :as persist])])
  #?@(:clj [(:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.io ByteArrayOutputStream]
           [java.net InetAddress InetSocketAddress]
           [java.nio.charset StandardCharsets]
           [java.time Instant]
           [java.time.temporal ChronoUnit]
           [java.util Base64])]))

#?(:clj
   (do


(def ^:const max-request-bytes
  "An enrollment body is a few hundred bytes of base64 public key. Nothing
  legitimate is near this, and an unbounded read on a socket is a way for a
  client to make this JVM allocate until it dies."
  65536)

(def ^:const max-remembered-challenges
  "How many spent challenges are remembered for best-effort single use. Bounded
  because the set is filled by anyone who can reach the port."
  4096)

(def ^:private b64-url (.withoutPadding (Base64/getUrlEncoder)))

(defn- now-iso [] (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS)))
(defn- plus-sec [iso sec] (str (.plusSeconds (Instant/parse ^String iso) (long sec))))
(defn- expired? [iso] (pos? (compare (now-iso) (str iso))))

;; ───────────────────────────── encoding ─────────────────────────────

(defn- json-safe
  "byte[] → base64 string, keyword → name, set → vector. JSON has none of
  those three, and a client that gets `[B@1a2b3c` in a field has been handed a
  JVM implementation detail as data."
  [x]
  (walk/postwalk
   (fn [v]
     (cond
       (bytes? v) (.encodeToString (Base64/getEncoder) ^bytes v)
       (keyword? v) (if-let [ns* (namespace v)] (str ns* "/" (name v)) (name v))
       (set? v) (vec (sort-by str v))
       :else v))
   x))

(defn- render [accept value]
  (if (str/includes? (str/lower-case (str accept)) "application/edn")
    ["application/edn; charset=utf-8" (persist/->edn value)]
    ;; `:escape-slash false`: JSON's optional `\/` escaping is legal and makes
    ;; every path in an error body unreadable (`\/v1\/t\/…`). Nothing here is
    ;; embedded in HTML, which is the only reason that escaping exists.
    ["application/json; charset=utf-8" (json/write-str (json-safe value) :escape-slash false)]))

(defn- reply! [^HttpExchange exchange status accept value]
  (let [[content-type body] (render accept value)
        bytes (.getBytes ^String body StandardCharsets/UTF_8)
        headers (.getResponseHeaders exchange)]
    (.set headers "content-type" content-type)
    (.set headers "cache-control" "no-store")
    (.set headers "x-content-type-options" "nosniff")
    (.sendResponseHeaders exchange (int status) (alength bytes))
    (with-open [out (.getResponseBody exchange)] (.write out bytes))))

(def ^:const max-audit-bytes
  "An audit submission is a whole ledger, so it is legitimately larger than an
  enrollment. Still bounded: this is the one endpoint that accepts bulk data
  from an authenticated principal."
  1048576)

(defn- read-body
  "Parse a request body. JSON by default; EDN when the request says so.

  EDN is not decoration here. The audit endpoint takes a hash-chained,
  SIGNED ledger, and a JSON round-trip silently changes it: only keys are
  keywordized, so a fact's keyword VALUES (`:t :opened`) come back as strings,
  `pr-str` produces different bytes, and `kagi.ledger/verify-chain` rejects a
  chain that was never tampered with. A transport that alters what it carries
  cannot carry a tamper-evident log."
  [^HttpExchange exchange & [{:keys [max-bytes]}]]
  (let [limit (or max-bytes max-request-bytes)
        edn? (str/includes? (str/lower-case
                             (str (.getFirst (.getRequestHeaders exchange) "Content-Type")))
                            "application/edn")]
    (with-open [in (.getRequestBody exchange)
                out (ByteArrayOutputStream.)]
      (let [buf (byte-array 4096)]
        (loop [total 0]
          (let [n (.read in buf)]
            (if (neg? n)
              (let [s (.toString out "UTF-8")]
                (cond (str/blank? s) {}
                      edn? (persist/<-edn s)
                      :else (json/read-str s :key-fn keyword)))
              (let [next-total (+ total n)]
                (when (> next-total limit)
                  (throw (ex-info "agent API request too large" {:max limit})))
                (.write out buf 0 n)
                (recur next-total)))))))))

;; ───────────────────────────── challenges ─────────────────────────────

(defn- sha256-bytes [s]
  (crypto/sha256 (.getBytes ^String (str s) "UTF-8")))

(defn- hmac ^bytes [^bytes key ^bytes message]
  (let [m (javax.crypto.Mac/getInstance "HmacSHA256")]
    (.init m (javax.crypto.spec.SecretKeySpec. key "HmacSHA256"))
    (.doFinal m message)))

(defn challenge-key
  "The key that signs challenge tokens.

  `KAGI_AGENT_CHALLENGE_KEY` (base64) when set, so several instances behind one
  URL accept each other's challenges. Otherwise a fresh random key per process,
  which means a restart invalidates outstanding challenges — acceptable, they
  live 120 seconds, and the alternative is an instance-affinity requirement
  hidden inside an enrollment flow."
  [p]
  (if-let [k (not-empty (System/getenv "KAGI_AGENT_CHALLENGE_KEY"))]
    (.decode (Base64/getDecoder) ^String k)
    (crypto/rand-bytes p 32)))

;; A challenge is a SIGNED TOKEN, not a row in a table:
;;
;;     <payload-b64url>.<hmac-b64url>       payload = {:c … :d … :x …}
;;
;; The server therefore keeps no per-challenge state, which is what lets more
;; than one instance sit behind one URL, and lets an instance restart without
;; failing enrollments that are mid-flight.
;;
;; What statelessness costs, stated rather than discovered: a solved challenge
;; can be presented more than once until it expires. `spent` is a best-effort,
;; bounded, in-memory set that catches the single-instance case; it is NOT a
;; guarantee and is not treated as one. The bound that actually holds is
;; elsewhere — every enrollment also needs an invite, and invites have
;; `uses-left`. The proof of work throttles bulk attempts; it was never the
;; thing standing between a stranger and the vault (`kagi.agent-protocol` says
;; so where a reader hits it first).

(defn mint-challenge
  "A signed, self-describing challenge. Creates no server state."
  [^bytes key p {:keys [difficulty-bits ttl-sec]}]
  (let [issued (now-iso)
        expires (plus-sec issued (or ttl-sec proto/default-challenge-ttl-sec))
        bits (or difficulty-bits proto/default-difficulty-bits)
        challenge (.encodeToString b64-url ^bytes (crypto/rand-bytes p 24))
        payload (persist/->edn {:c challenge :d bits :x expires})
        payload-b64 (.encodeToString b64-url (.getBytes ^String payload "UTF-8"))
        sig (.encodeToString b64-url (hmac key (.getBytes ^String payload-b64 "UTF-8")))]
    {:challenge_id (str payload-b64 "." sig)
     :algorithm proto/algorithm
     :challenge challenge
     :difficulty_bits bits
     :issued_at issued
     :expires_at expires}))

(defn- open-challenge
  "Verify a challenge token and return its payload, or nil."
  [^bytes key token]
  (try
    (let [[payload-b64 sig] (str/split (str token) #"\." 2)]
      (when (and payload-b64 sig)
        (let [expected (.encodeToString b64-url (hmac key (.getBytes ^String payload-b64 "UTF-8")))]
          ;; Constant-time: this compares a value an attacker supplies against
          ;; one derived from a key they would like to forge against.
          (when (java.security.MessageDigest/isEqual
                 (.getBytes ^String expected "UTF-8") (.getBytes ^String sig "UTF-8"))
            (persist/<-edn (String. (.decode (Base64/getUrlDecoder) ^String payload-b64)
                                    "UTF-8"))))))
    (catch Exception _ nil)))

(defn- remember-spent! [spent token]
  (swap! spent (fn [s] (if (>= (count s) max-remembered-challenges) #{token} (conj s token))))
  nil)

(defn- pow-errors
  "Validate the proof of work against a signed challenge token.

  A forged or altered token is `:challenge-unknown`, an old one is
  `:challenge-expired`, and a wrong nonce is `:pow-failed` — three codes,
  because they are three different situations and only one of them is somebody
  probing."
  [^bytes key spent {:keys [pow]}]
  (let [token (:challenge_id pow)
        payload (open-challenge key token)]
    (cond
      (nil? payload) [{:rule :challenge-unknown
                       :detail "その challenge は発行されたものではない（署名が合わない）"}]
      (expired? (:x payload)) [{:rule :challenge-expired
                                :detail "challenge が失効している — 取り直すこと"}]
      (contains? @spent token) [{:rule :challenge-unknown
                                 :detail "その challenge は既に使われている"}]
      (not (proto/pow-satisfies? sha256-bytes (:c payload) (:nonce pow) (:d payload)))
      (do (remember-spent! spent token)
          [{:rule :pow-failed
            :detail (str "sha256(challenge \":\" nonce) の先頭 " (:d payload)
                         " bit が 0 になっていない")}])
      :else (do (remember-spent! spent token) []))))


;; ───────────────────────────── handlers ─────────────────────────────

(defn- enroll-response [{:keys [principal token]}]
  {:agent_id (:agent/id principal)
   ;; The only time this value exists outside the enrolling process.
   :account_key token
   :did (:agent/did principal)
   :fingerprint (:agent/fingerprint principal)
   :ops (:agent/ops principal)
   :compartments (:agent/compartments principal)
   :not_after (:agent/not-after principal)
   :enrolled_at (:agent/enrolled-at principal)
   :note "account_key は一度しか返らない。保存に失敗したら enroll し直すこと"})

(defn- with-principal [svc ^HttpExchange exchange accept f]
  (let [token (proto/bearer-token (.getFirst (.getRequestHeaders exchange) "Authorization"))
        {:keys [ok? principal reason at]} (when token (service/authenticate svc token))]
    (cond
      (nil? token) (reply! exchange 401 accept {:error "unauthorized"
                                                :detail "Authorization: Bearer <account_key> が要る"})
      (not ok?) (reply! exchange 403 accept (cond-> {:error (name (or reason :forbidden))}
                                              at (assoc :at at)))
      :else (f principal))))

(defn- handler [resolve-tenant ^bytes challenge-key spent p opts]
  (reify HttpHandler
    (handle [_ exchange]
      (let [^HttpExchange ex exchange
            accept (.getFirst (.getRequestHeaders ex) "Accept")]
        (try
          (let [method (.getRequestMethod ex)
                path (.getPath (.getRequestURI ex))
                ;; Every route names its tenant. One server can hold many
                ;; vaults, and a path that did not say which one would make the
                ;; answer depend on how the process was started rather than on
                ;; what was asked — the difference matters the moment there is
                ;; a second tenant, and changing the shape afterwards breaks
                ;; every enrolled agent's stored base URL.
                [_ tenant rest*] (re-matches #"^/v1/t/([^/]+)(/.*)$" path)
                svc (when tenant (resolve-tenant tenant))
                sealed-item (when rest* (second (re-matches #"^/items/([^/]+)/sealed$" rest*)))]
            (cond
              (nil? tenant)
              (reply! ex 404 accept
                      {:error "not-found"
                       :detail "すべての経路は /v1/t/<tenant did>/… の形をとる"})

              (nil? svc)
              (reply! ex 404 accept {:error "unknown-tenant" :tenant tenant})

              (and (= "POST" method) (= "/agents/challenges" rest*))
              (reply! ex 200 accept (mint-challenge challenge-key p opts))

              (and (= "POST" method) (= "/agents" rest*))
              (let [body (read-body ex)
                    errs (pow-errors challenge-key spent body)
                    result (service/enroll! svc
                                            ;; No :agent/id — `kagi.agent/approve`
                                            ;; mints it. A client-chosen id could
                                            ;; name a principal that already
                                            ;; exists. The client's :did IS passed
                                            ;; through, so approve can refuse a
                                            ;; mismatch rather than silently
                                            ;; correcting one.
                                            {:invite (:invite body)
                                             :label (:label body)
                                             :pow (:pow body)
                                             :public (:public body)
                                             :agent/label (:label body)
                                             :agent/did (:did body)
                                             :agent/public (:public body)}
                                            {:pow-errors errs})]
                (if (:ok? result)
                  (reply! ex 201 accept (enroll-response result))
                  (reply! ex 403 accept {:error "enrollment-refused"
                                         :errors (mapv (fn [e] {:rule (name (:rule e))
                                                                :detail (:detail e)})
                                                       (:errors result))})))

              (and (= "GET" method) (= "/whoami" rest*))
              (with-principal svc ex accept
                (fn [prin] (reply! ex 200 accept (service/whoami svc prin))))

              (and (= "GET" method) (= "/items" rest*))
              (with-principal svc ex accept
                (fn [prin] (reply! ex 200 accept {:items (service/items svc prin)})))

              (and (= "GET" method) sealed-item)
              (with-principal svc ex accept
                (fn [prin]
                  (let [r (service/sealed svc prin sealed-item)]
                    (case (:status r)
                      :ok (reply! ex 200 accept r)
                      :absent (reply! ex 404 accept {:error "not-found"})
                      (reply! ex 403 accept {:error "forbidden"
                                             :basis (name (:basis r))})))))

              (and (= "POST" method) (= "/audit" rest*))
              (with-principal svc ex accept
                (fn [prin]
                  (let [body (read-body ex {:max-bytes max-audit-bytes})
                        r (service/submit-audit! svc prin (:ledger body))]
                    (reply! ex (if (= :accepted (:status r)) 200 409) accept r))))

              :else (reply! ex 404 accept {:error "not-found"})))
          (catch Exception e
            ;; The message, never the stack. A body over the limit should say
            ;; so; nothing else here has anything a caller could act on.
            (reply! ex 400 accept {:error "refused" :detail (ex-message e)}))
          (finally (.close ex)))))))

(defrecord AgentHttpServer [^HttpServer server origin]
  java.io.Closeable
  (close [_] (.stop server 0)))

(defn- single-tenant-resolver
  "One service, reachable at exactly one tenant path.

  The DID is required rather than inferred-and-hoped: an object-backed service
  carries `:did`, a file-backed one does not, and a server that answered for
  ANY tenant segment would hand one vault's material to a request that named a
  different vault."
  [svc tenant]
  (let [did (or tenant (:did svc))]
    (when-not did
      (throw (ex-info (str "kagi.agent-http: pass :tenant — this service does not carry a DID, "
                           "and every route names its tenant")
                      {:store (keys svc)})))
    [did (fn [asked] (when (= asked did) svc))]))

(defn start!
  "Bind and serve. Returns `{:origin :base-url :tenant :port :server :stop}`,
  plus a `:warning` when the bind is not loopback.

  `opts`:
    `:tenant`   the DID this service answers for (required unless the service
                carries one).
    `:tenants`  `(fn [did] service-or-nil)` instead, to serve many vaults.
    `:host` `:port` `:difficulty-bits` `:ttl-sec`.

  Port 0 chooses an ephemeral port, which is what the tests use."
  ([svc] (start! svc {}))
  ([svc {:keys [host port tenant tenants] :or {host "127.0.0.1" port 0} :as opts}]
   (let [p (crypto/jvm-provider)
         spent (atom #{})
         ckey (challenge-key p)
         [did resolve-tenant] (if tenants
                                [tenant tenants]
                                (single-tenant-resolver svc tenant))
         server (HttpServer/create
                 (InetSocketAddress. (InetAddress/getByName host) (int port)) 32)]
     (.createContext server "/" (handler resolve-tenant ckey spent p opts))
     (.setExecutor server nil)
     (.start server)
     (let [bound (.getAddress server)
           origin (str "http://" (.getHostString bound) ":" (.getPort bound))]
       (cond-> {:origin origin
                :tenant did
                :base-url (when did (str origin "/v1/t/" did))
                :port (.getPort bound)
                :server (->AgentHttpServer server origin)
                :stop #(.stop server 0)}
         (not (contains? #{"127.0.0.1" "localhost" "::1"} host))
         (assoc :warning
                (str "loopback ではない bind (" host ") — この面は平文 HTTP を話す。"
                     "TLS を前段で終端し、到達できる範囲を絞ること。"
                     "release される素材は暗号文のままだが、account_key は平文で流れる")))))))))
