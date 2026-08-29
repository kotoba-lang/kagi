(ns kagi.agent-client
  "The SDK an agent uses to talk to `kagi.agent-http`.

  ## What it does that a curl script cannot

  The API releases SEALED material — a grant envelope encapsulated to this
  principal's own hybrid public key, plus the item's ciphertext. Turning that
  into a secret is X25519 + ML-KEM-768 decapsulation, an AES-256-GCM open, and
  an AAD that has to match what sealed it. That is the part worth shipping,
  and it is why this SDK opens items **in the caller's process**: the server
  has no VMK and never sees plaintext, so the last step has to happen here or
  the property is decorative.

  ## One implementation, two runtimes

  Portable through the `kagi.crypto/Provider` seam, which is the same
  arrangement the vault itself uses:

      JVM   (crypto/jvm-provider)   — BouncyCastle / JDK
      nbb   (noble/noble-provider)  — pure JS `@noble/*`, synchronous

  The crypto is therefore shared, not reimplemented — `kagi.crypto.noble` and
  the JVM provider are already pinned against each other by interop vectors in
  both directions, so an item sealed by the vault opens in a browser and the
  suite would notice if it stopped.

  **What differs is only the transport**, because it has to: `java.net.http`
  is synchronous and `fetch` returns promises. The `:clj` driver returns
  values; the `:cljs` driver returns promises. Pretending otherwise would mean
  propagating promises through the JVM path — the exact trade-off
  `kagi.crypto.noble` refused when it chose `@noble/*` over Web Crypto.

  ## Coverage, stated rather than implied

  `kagi.agent-client-test` exercises the portable core and the JVM driver
  against a live in-process server. The `:cljs` driver is written against the
  same portable core but is NOT yet in a CI suite — `npm install` has never
  been run in this repo and `npm run test:cljs` covers the crypto, not this.
  Treat the JVM path as proven and the browser/nbb path as unexercised.

  ## Enrollment

      (def c (client {:base-url \"http://127.0.0.1:8765\" :tenant \"did:key:z6Mk…\"}))
      (def enrolled (enroll! c {:invite \"kagi_inv_…\" :label \"resident@mac-1\"}))
      ;; -> {:agent-id … :account-key … :secret {…}}   ← account_key は一度だけ

  Keep `:account-key` and `:secret` somewhere a `kagi.secret-store` ref points
  at. Losing either means enrolling again: the vault kept only a hash of the
  token, and the private key was never sent."
  (:require [clojure.string :as str]
            [kagi.agent-protocol :as proto]
            [kagi.b64 :as b64]
            [kagi.crypto :as crypto]
            [kagi.digest :as digest]
            [kagi.vault :as vault])
  #?(:clj (:import [java.net URI]
                   [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
                    HttpResponse$BodyHandlers])))

;; ───────────────────────────── portable primitives ────────────────────────

;; base64 and sha256 were written here first and then needed by `kagi.ledger`
;; too. They live in `kagi.b64` / `kagi.digest` now; these names stay because
;; the SDK's callers and tests use them, and a second implementation of either
;; is how two runtimes end up disagreeing about a signature.
(def b64 b64/encode)
(def unb64 b64/decode)
(def sha256-bytes
  "The raw-digest seam `kagi.agent-protocol` asks for."
  digest/sha256-utf8)

(defn- b64-map [m] (into {} (map (fn [[k v]] [k (b64 v)]) m)))
(defn- unb64-map [m] (into {} (map (fn [[k v]] [k (unb64 v)]) m)))

(defn keypair
  "Generate this principal's own hybrid identity through `provider`.

  Both halves come back; only `:public` is ever sent. The DER encodings the
  providers emit are byte-identical across runtimes (`kagi.crypto.noble`'s
  `wrap-der` exists for exactly this), so a principal enrolled from nbb is
  loadable by the JVM vault and vice versa."
  [p]
  (let [kem (crypto/kem-keypair p)
        sign (crypto/sign-keypair p)]
    {:public {:kem (b64-map (:public kem))
              :sign {:ed (b64 (:ed (:public sign)))
                     :mldsa (b64 (:mldsa (:public sign)))}}
     :secret {:kem (:secret kem)
              :sign (:secret sign)}}))

(defn solve
  "Solve a challenge from `POST /v1/agents/challenges`."
  [challenge]
  (proto/solve-pow sha256-bytes (:challenge challenge) (:difficulty_bits challenge)))

(defn enrollment-body [challenge nonce {:keys [invite label public did]}]
  {:invite invite
   :label label
   :did did
   :public public
   :pow {:challenge_id (:challenge_id challenge) :nonce nonce}})

(defn open-sealed
  "Turn a `/v1/items/<id>/sealed` response into the plaintext string.

  Nothing here talks to the network: given the sealed material and this
  principal's KEM secret, the decapsulation and the AEAD open are local. That
  is the property — the server could not have done this step even if it
  wanted to."
  [p kem-secret {:keys [item-id envelope nonce ciphertext] :as sealed}]
  (let [item-id (or item-id (:item_id sealed))
        dek (crypto/accept-share p kem-secret
                                 {:kem-ct (unb64-map (:kem-ct envelope))
                                  :nonce (unb64 (:nonce envelope))
                                  :wrapped (unb64 (:wrapped envelope))})
        pt (crypto/open-item p dek (unb64 nonce) (unb64 ciphertext)
                             (vault/item-aad item-id))]
    #?(:clj (String. ^bytes pt "UTF-8")
       :cljs (.decode (js/TextDecoder.) pt))))

;; ───────────────────────────── request shapes ─────────────────────────────

(defn tenant-path
  "Every route names its tenant: `/v1/t/<did>/…`. One server can hold many
  vaults, and a path that did not say which one would make the answer depend on
  how the server was started rather than on what was asked."
  [tenant path]
  (str "/v1/t/" tenant path))

(defn requests
  "Every call this SDK makes, as data. Exposed so the shapes can be asserted
  without a socket, and so a caller on a runtime neither driver covers can
  still drive the API without re-deriving the paths from prose."
  [{:keys [account-key tenant]}]
  (let [auth (when account-key {"authorization" (str "Bearer " account-key)})
        p* #(tenant-path tenant %)]
    {:challenge {:method "POST" :path (p* "/agents/challenges") :body {}}
     :enroll    {:method "POST" :path (p* "/agents")}
     :whoami    {:method "GET" :path (p* "/whoami") :headers auth}
     :items     {:method "GET" :path (p* "/items") :headers auth}
     :sealed    {:method "GET" :path-fn #(p* (str "/items/" % "/sealed")) :headers auth}
     :audit     {:method "POST" :path (p* "/audit") :headers auth}}))

;; ───────────────────────────── drivers ─────────────────────────────

#?(:clj
   (defn- json->clj [s]
     ;; data.json is required lazily so the portable half of this namespace
     ;; carries no JVM-only dependency into a cljs compile.
     ((requiring-resolve 'json.data-json/read-str) s :key-fn keyword)))

#?(:clj
   (defn- clj->json [v]
     ((requiring-resolve 'json.data-json/write-str) v)))

#?(:clj
   (defn client
     "A JVM client. `:base-url` must be HTTPS unless it is loopback — a token
     that opens a vault does not travel in the clear across a network, and a
     client that merely warned would be a client whose warning is in a log
     nobody reads."
     [{:keys [base-url account-key provider tenant agent-did sign-secret]}]
     (when (str/blank? (str tenant))
       (throw (ex-info "kagi.agent-client/client: :tenant (the vault's did:key) is required — every route names it"
                       {:base-url base-url})))
     (let [uri (URI/create base-url)]
       (when-not (or (= "https" (.getScheme uri))
                     (contains? #{"127.0.0.1" "localhost" "::1"} (.getHost uri)))
         (throw (ex-info "remote kagi agent API requires HTTPS"
                         {:base-url base-url}))))
     {:base-url (str/replace base-url #"/$" "")
      :tenant tenant
      :account-key account-key
      :agent-did agent-did
      :sign-secret sign-secret
      ;; The agent's own record of what it opened. See `record-open!`: over
      ;; HTTP there is no governor run and therefore no vault-side ledger, so
      ;; if the client does not keep one, nothing does.
      :ledger (atom [])
      :provider (or provider (crypto/jvm-provider))
      :http (HttpClient/newHttpClient)}))

#?(:clj
   (defn call
     "One request. Returns `{:status :body}` with the body parsed from JSON —
     including for a refusal, because the refusal codes ARE the API (a client
     that throws away a 403 body cannot tell `:invite-expired` from
     `:pow-failed`)."
     [{:keys [base-url account-key tenant ^HttpClient http]} {:keys [method path body edn?]}]
     (let [builder (-> (HttpRequest/newBuilder (URI/create (str base-url (tenant-path tenant path))))
                       (.header "accept" "application/json"))
           builder (cond-> builder
                     account-key (.header "authorization" (str "Bearer " account-key)))
           request (.build (if (= "POST" method)
                             (-> builder
                                 (.header "content-type" (if edn? "application/edn"
                                                             "application/json"))
                                 (.POST (HttpRequest$BodyPublishers/ofString
                                         (if edn?
                                           ;; EDN, because the audit body is a
                                           ;; signed hash chain and JSON would
                                           ;; alter it — see `read-body` in
                                           ;; kagi.agent-http.
                                           ((requiring-resolve 'kagi.persist/->edn)
                                            (or body {}))
                                           (clj->json (or body {}))))))
                             (.GET builder)))
           response (.send http request (HttpResponse$BodyHandlers/ofString))]
       {:status (.statusCode response)
        :body (try (json->clj (.body response))
                   (catch Exception _ {:error "unparseable" :raw (.body response)}))})))

#?(:clj
   (defn enroll!
     "challenge → solve → enroll, the three calls the API takes.

     Returns `{:agent-id :account-key :secret :principal}` on success, or
     `{:error … :errors [{:rule …}]}` — the refusal is a value, so a caller can
     branch on `:invite-expired` without parsing prose."
     [{:keys [provider] :as c} {:keys [invite label]}]
     (let [{:keys [status body]} (call c {:method "POST" :path "/agents/challenges"
                                          :body {:purpose "enroll"}})]
       (if-not (= 200 status)
         {:error (or (:error body) "challenge-refused") :status status :body body}
         (if-let [nonce (solve body)]
           (let [{:keys [public secret]} (keypair provider)
                 enroll (call c {:method "POST" :path "/agents"
                                 :body (enrollment-body body nonce
                                                        {:invite invite :label label
                                                         :public public})})]
             (if (= 201 (:status enroll))
               {:agent-id (:agent_id (:body enroll))
                :account-key (:account_key (:body enroll))
                :secret secret
                :principal (:body enroll)}
               {:error (or (:error (:body enroll)) "enrollment-refused")
                :status (:status enroll)
                :errors (:errors (:body enroll))}))
           {:error "pow-unsolved"
            :detail (str "difficulty_bits=" (:difficulty_bits body) " を解けなかった")})))))

#?(:clj
   (defn items [c]
     (:items (:body (call c {:method "GET" :path "/items"})))))

#?(:clj
   (defn record-open!
     "Append a signed entry to this client's own chain.

     Over HTTP there is no governor run and no vault-side ledger: the server
     releases ciphertext and the SDK decrypts. So the record of WHAT was opened
     and WHY exists only here, or nowhere. `submit-audit!` hands it back to the
     owner, who verifies it against the public key the vault recorded at
     enrollment.

     Silently does nothing without `:sign-secret` — a client built for a
     read-only probe should not have to carry a key it will not use — and
     `submit-audit!` says so rather than posting an empty chain."
     [{:keys [ledger provider agent-did sign-secret]} fact]
     (when sign-secret
       (swap! ledger
              (fn [entries]
                (conj (vec entries)
                      ((requiring-resolve 'kagi.ledger/make-entry)
                       entries (assoc fact :actor agent-did) provider sign-secret)))))))

#?(:clj
   (defn open-item!
     "Fetch one item's sealed material and open it locally. Returns the
     plaintext, or a refusal map — never nil, because 'no secret' and 'you may
     not have this secret' are different answers and a caller that gets nil
     cannot tell them apart.

     `purpose` lands on this client's chain. It is optional only because the
     API is usable without an audit key; when one is present, an open with no
     stated purpose records `:unstated` rather than nothing, so the gap is
     visible in the log instead of being absent from it."
     ([c kem-secret item-id] (open-item! c kem-secret item-id nil))
     ([{:keys [provider] :as c} kem-secret item-id purpose]
      (let [{:keys [status body]} (call c {:method "GET"
                                           :path (str "/items/" item-id "/sealed")})
            result (case (long status)
                     200 {:status :ok :plaintext (open-sealed provider kem-secret body)}
                     403 {:status :forbidden :basis (:basis body)}
                     404 {:status :absent}
                     {:status :error :http status :body body})]
        (record-open! c {:t (if (= :ok (:status result)) :opened :refused)
                         :item item-id
                         :purpose (or purpose :unstated)
                         :basis (:basis result)
                         :at (str (java.time.Instant/now))})
        result))))

#?(:clj
   (defn submit-audit!
     "Hand this client's signed chain to the owner.

     The server verifies it against the public key the VAULT recorded at
     enrollment and refuses a chain that is broken, truncated, or diverges from
     what it already holds — so this is append-only from the owner's side even
     though the agent is the one writing it."
     [{:keys [ledger] :as c}]
     (let [entries @ledger]
       (if (empty? entries)
         {:status :nothing-to-submit
          :detail "この client は署名鍵を持たないか、まだ何も開いていない"}
         (let [{:keys [status body]} (call c {:method "POST" :path "/audit"
                                              :edn? true :body {:ledger entries}})]
           ;; JSON hands back strings; every other function in this SDK answers
           ;; with keywords, and a caller should not have to know which
           ;; encoding happened to be used on the way home.
           (cond-> (assoc body :http status)
             (:status body) (assoc :status (keyword (name (:status body))))
             (:basis body) (assoc :basis (keyword (name (:basis body))))))))))

;; ── the cljs driver ───────────────────────────────────────────────────────
;;
;; Promise-returning, because `fetch` is. See the ns docstring: this half is
;; written against the same portable core but is not covered by a suite in
;; this repo yet.
#?(:cljs
   (defn client [{:keys [base-url account-key provider tenant]}]
     (when (str/blank? (str tenant))
       (throw (js/Error. "kagi.agent-client/client: :tenant (the vault's did:key) is required")))
     (when-not provider
       (throw (js/Error. (str "kagi.agent-client/client: pass :provider — "
                              "(kagi.crypto.noble/noble-provider) on nbb or in a browser"))))
     {:base-url (str/replace base-url #"/$" "")
      :tenant tenant
      :account-key account-key
      :provider provider}))

#?(:cljs
   (defn call [{:keys [base-url account-key tenant]} {:keys [method path body]}]
     (-> (js/fetch (str base-url (tenant-path tenant path))
                   (clj->js (cond-> {:method method
                                     :headers (cond-> {"accept" "application/json"}
                                                account-key
                                                (assoc "authorization"
                                                       (str "Bearer " account-key))
                                                (= "POST" method)
                                                (assoc "content-type" "application/json"))}
                              (= "POST" method) (assoc :body (js/JSON.stringify
                                                              (clj->js (or body {})))))))
         (.then (fn [res]
                  (-> (.text res)
                      (.then (fn [t]
                               {:status (.-status res)
                                :body (try (js->clj (js/JSON.parse t) :keywordize-keys true)
                                           (catch :default _ {:error "unparseable" :raw t}))}))))))))

#?(:cljs
   (defn enroll! [{:keys [provider] :as c} {:keys [invite label]}]
     (-> (call c {:method "POST" :path "/agents/challenges" :body {:purpose "enroll"}})
         (.then (fn [{:keys [status body]}]
                  (if-not (= 200 status)
                    {:error (or (:error body) "challenge-refused") :status status}
                    (if-let [nonce (solve body)]
                      (let [{:keys [public secret]} (keypair provider)]
                        (-> (call c {:method "POST" :path "/agents"
                                     :body (enrollment-body body nonce
                                                            {:invite invite :label label
                                                             :public public})})
                            (.then (fn [enroll]
                                     (if (= 201 (:status enroll))
                                       {:agent-id (:agent_id (:body enroll))
                                        :account-key (:account_key (:body enroll))
                                        :secret secret
                                        :principal (:body enroll)}
                                       {:error (or (:error (:body enroll)) "enrollment-refused")
                                        :errors (:errors (:body enroll))})))))
                      {:error "pow-unsolved"})))))))

#?(:cljs
   (defn open-item! [{:keys [provider] :as c} kem-secret item-id]
     (-> (call c {:method "GET" :path (str "/items/" item-id "/sealed")})
         (.then (fn [{:keys [status body]}]
                  (case status
                    200 {:status :ok :plaintext (open-sealed provider kem-secret body)}
                    403 {:status :forbidden :basis (:basis body)}
                    404 {:status :absent}
                    {:status :error :http status :body body}))))))
