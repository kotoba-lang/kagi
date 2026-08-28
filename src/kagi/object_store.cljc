(ns kagi.object-store
  "The wiring that turns object-store credentials into the four functions
  `kagi.sync`'s object backend takes.

  ## Why this is a separate namespace

  `kagi.store` and `kagi.sync` deliberately depend on NOTHING here: they take
  `{:get-object :put-object :exists?}` and never learn whose bucket it is.
  `kagi.store/object-sealed-block-store`'s docstring states that as the design
  and names who is supposed to hold both dependencies — 'the application doing
  the wiring'. For this repo that is `bin/kagi`, so io-storj is an extra-dep of
  the `:cli` alias (and of `:test`) rather than a library dependency, and this
  namespace is where it is allowed to appear.

  A consequence worth stating: requiring this namespace without one of those
  aliases fails. That is the boundary being honest rather than a packaging
  accident.

  ## Credentials come from the environment, never from a lookup here

  `from-env` reads env vars and nothing else. It opens no vault, runs no
  `security find-generic-password`, and searches no 1Password — the workspace's
  safety floor is that credentials are fetched by a known identifier through
  credential tooling, by whoever runs the command, and a sync backend that went
  looking on its own would be doing exactly what that floor forbids.

  ## Backblaze B2

  B2 exposes an S3-compatible surface, so the same signer works; what differs
  is the endpoint host and the region. `storj.gateway/validate` refuses a
  non-Storj host unless told otherwise, which is a good default and wrong for
  us, so `:allow-any-host? true` is passed explicitly — visible in a diff
  rather than hidden in a default.

  ## `.cljc` with only a `:clj` branch, and saying so\n\n  This is host wiring by definition — a JDK HTTP client behind io-storj. The\n  browser/Worker equivalent is a `fetch`-based `IHttp` against the same\n  `storj.core`, which is a different implementation rather than the same one\n  compiled twice. The extension follows the portable-first rule\n  (ADR-2608201300) and this comment says which half is missing."
  #?@(:clj [(:require [clojure.string :as str]
            [sigv4.crypto :as sigv4-crypto]
            [storj.core :as storj]
            [storj.protocols :as sp]
            [storj.store :as storj-store])])
  #?@(:clj [(:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$Builder
            HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.time Instant]
           [java.time.temporal ChronoUnit])]))

#?(:clj
   (do


(defn- ->body-publisher [body]
  (cond
    (nil? body) (HttpRequest$BodyPublishers/noBody)
    (bytes? body) (HttpRequest$BodyPublishers/ofByteArray ^bytes body)
    (string? body) (HttpRequest$BodyPublishers/ofString ^String body)
    (sequential? body) (HttpRequest$BodyPublishers/ofByteArray
                        (byte-array (map unchecked-byte body)))
    :else (HttpRequest$BodyPublishers/ofString (str body))))

(def ^:private jdk-restricted-headers
  "Headers `java.net.http` refuses to let a caller set (it throws
  `restricted header name`), because it sets them itself.

  Dropping them is safe HERE and it is worth saying why rather than trusting
  it: SigV4 signs `host`, and the JDK derives `Host` from the request URI —
  which is the same origin `storj.gateway/validate` normalized and
  `storj.core/sign` signed. Setting it a second time is refused; not setting it
  sends the identical value. `content-length` likewise comes from the body
  publisher. If either of those ever stopped matching what was signed, the
  store would answer 403 and `kagi.object-store-test` would fail against a real
  socket — which is why that test does not stub the transport."
  #{"connection" "content-length" "date" "expect" "from" "host" "upgrade" "via" "warning"})

(defrecord JdkHttp [^HttpClient client]
  sp/IHttp
  (-request [_ {:keys [method url headers body]}]
    (let [b (reduce (fn [acc [k v]]
                      (if (jdk-restricted-headers (str/lower-case (str (name k))))
                        acc
                        (.header ^HttpRequest$Builder acc (str (name k)) (str v))))
                    (HttpRequest/newBuilder (URI/create url))
                    headers)
          ;; storj.core signs the method it is going to send and hands it over
          ;; as an upper-case string; passing anything else here would sign one
          ;; request and send another.
          req (.build (.method ^HttpRequest$Builder b (str/upper-case (name method))
                               (->body-publisher body)))
          resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))]
      {:status (.statusCode resp)
       ;; Header names are lower-cased by the JDK's map view already; take the
       ;; first value because S3 responses carry no repeated headers we read.
       :headers (into {} (map (fn [[k v]] [k (first v)]) (.map (.headers resp))))
       :body (.body resp)})))

(defn jdk-http [] (->JdkHttp (HttpClient/newHttpClient)))

(defn- now-iso [] (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS)))

(defn- env [& names]
  (some #(not-empty (System/getenv %)) names))

(defn config-from-env
  "Read object-store config from the environment. Returns nil when nothing is
  configured — 'not set up' is not an error, it is the default state.

  `KAGI_OBJECT_*` wins over `B2_*` so a second bucket can be used for the vault
  without disturbing the DataLad/annex credentials `manifest/repos.edn` already
  documents under the `B2_*` names."
  []
  (let [bucket (env "KAGI_OBJECT_BUCKET" "B2_BUCKET")
        access (env "KAGI_OBJECT_KEY_ID" "B2_KEY_ID")
        secret (env "KAGI_OBJECT_APP_KEY" "B2_APP_KEY")
        endpoint (env "KAGI_OBJECT_ENDPOINT" "B2_ENDPOINT")
        region (env "KAGI_OBJECT_REGION" "B2_REGION")]
    (when (and bucket access secret endpoint)
      (cond-> {:bucket bucket :access-key access :secret-key secret
               :endpoint endpoint
               ;; B2's host is not a Storj gateway; say so deliberately.
               :allow-any-host? true}
        region (assoc :region region)))))

(defn store-fns
  "Build `{:get-object :put-object :exists?}` for `config`. Synchronous on the
  JVM (`storj.core`'s sync/async duality resolves to plain values here)."
  ([config] (store-fns config {}))
  ([config {:keys [http prefix]}]
   (storj-store/store-fns
    (storj/client config {:crypto (sigv4-crypto/crypto) :http (or http (jdk-http))})
    {:now now-iso :prefix prefix})))

(defn from-env
  "`config-from-env` → the four functions, or nil when unconfigured.

  Returns the config alongside so a caller can report WHICH bucket it is about
  to write to. The secret is not included; a report that echoed it would put it
  in a terminal and a scrollback."
  ([] (from-env {}))
  ([opts]
   (when-let [config (config-from-env)]
     {:fns (store-fns config opts)
      :bucket (:bucket config)
      :endpoint (:endpoint config)
      :region (:region config)})))

(def env-help
  "What an operator has to set. Printed by the CLI when the backend is asked
  for and not configured — a refusal that names the missing thing."
  (str/join "\n"
            ["  KAGI_OBJECT_BUCKET   (or B2_BUCKET)    バケット名"
             "  KAGI_OBJECT_KEY_ID   (or B2_KEY_ID)    アクセスキー ID"
             "  KAGI_OBJECT_APP_KEY  (or B2_APP_KEY)   シークレット"
             "  KAGI_OBJECT_ENDPOINT (or B2_ENDPOINT)  例 https://s3.us-west-004.backblazeb2.com"
             "  KAGI_OBJECT_REGION   (or B2_REGION)    任意。例 us-west-004"
             "  KAGI_OBJECT_PREFIX                     任意。既定 kagi/"]))))
