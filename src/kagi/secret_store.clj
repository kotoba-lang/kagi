(ns kagi.secret-store
  "SecretStore providers for kagi key custody.

  Secret values are returned only to runtime code that needs them. Callers must
  not log returned values."
  (:require [clojure.edn :as edn]
            [clojure.java.shell :as sh]
            [clojure.string :as str])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file CopyOption Files LinkOption Path Paths StandardCopyOption]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

(defprotocol SecretStore
  (put-secret! [store ref secret opts])
  (get-secret [store ref opts])
  (delete-secret! [store ref opts])
  (exists? [store ref])
  (metadata [store ref]))

(defn parse-ref [s]
  (let [s* (str/trim (str s))]
    (when-not (str/blank? s*)
      (if-let [[_ scheme body] (re-matches #"^([A-Za-z][A-Za-z0-9+.-]*)://(.+)$" s*)]
        {:scheme (str/lower-case scheme) :body body :raw s*}
        {:scheme "keychain" :body s* :raw (str "keychain://" s*)}))))

(defn redact-ref [s]
  (when-let [{:keys [scheme body]} (parse-ref s)]
    (let [tail (last (remove str/blank? (str/split body #"/")))]
      (str scheme "://.../" (or tail "secret")))))

(defn- service-account [ref]
  (let [{:keys [scheme body raw]} (parse-ref ref)]
    (when-not (= "keychain" scheme)
      (throw (ex-info "AppleKeychainStore only supports keychain:// refs"
                      {:ref (redact-ref raw) :scheme scheme})))
    (let [[service account] (str/split body #"/" 2)]
      {:service service :account (or account "default")})))

(defn- sh-ok [{:keys [exit out err] :as result} context]
  (if (zero? exit)
    (str/trim-newline (or out ""))
    (throw (ex-info (str "secret store command failed: " context)
                    {:context context
                     :exit exit
                     :err (some-> err str/trim)
                     :result (dissoc result :out)}))))

(defrecord AppleKeychainStore [sh-fn]
  SecretStore
  (put-secret! [_ ref secret _opts]
    (let [{:keys [service account]} (service-account ref)]
      (sh-ok (sh-fn "security" "add-generic-password"
                    "-U" "-s" service "-a" account "-w" (str secret))
             (str "apple-keychain put " service "/" account))
      {:ok? true :ref (redact-ref ref) :provider :apple-keychain}))
  (get-secret [_ ref _opts]
    (let [{:keys [service account]} (service-account ref)]
      (sh-ok (sh-fn "security" "find-generic-password"
                    "-s" service "-a" account "-w")
             (str "apple-keychain get " service "/" account))))
  (delete-secret! [_ ref _opts]
    (let [{:keys [service account]} (service-account ref)]
      (sh-ok (sh-fn "security" "delete-generic-password"
                    "-s" service "-a" account)
             (str "apple-keychain delete " service "/" account))
      {:ok? true :ref (redact-ref ref) :provider :apple-keychain}))
  (exists? [store ref]
    (try
      (boolean (seq (get-secret store ref {})))
      (catch Exception _ false)))
  (metadata [_ ref]
    (let [{:keys [service account]} (service-account ref)]
      {:ref (redact-ref ref)
       :provider :apple-keychain
       :service service
       :account account
       :custody :os-keychain
       :secret-readable? false})))

(defn apple-keychain-store
  ([] (apple-keychain-store sh/sh))
  ([sh-fn] (->AppleKeychainStore sh-fn)))

(defrecord EnvStore []
  SecretStore
  (put-secret! [_ _ _ _]
    (throw (ex-info "env store is read-only" {:provider :env})))
  (get-secret [_ ref _]
    (let [{:keys [scheme body raw]} (parse-ref ref)]
      (when-not (= "env" scheme)
        (throw (ex-info "EnvStore only supports env:// refs"
                        {:ref (redact-ref raw) :scheme scheme})))
      (or (not-empty (System/getenv body))
          (throw (ex-info "missing env secret" {:env body})))))
  (delete-secret! [_ _ _]
    (throw (ex-info "env store is read-only" {:provider :env})))
  (exists? [store ref] (try (boolean (seq (get-secret store ref {}))) (catch Exception _ false)))
  (metadata [_ ref] {:ref (redact-ref ref) :provider :env :custody :process-env}))

(defn env-store [] (->EnvStore))

;; ───────────────────────────── file://, mode 0600 ─────────────────────────
;;
;; This provider is WEAKER than the Keychain one and exists because the
;; Keychain one cannot be used at all in the place that needs it most.
;;
;; The workspace's own secrets map records the situation: `launchd` 下では kagi が
;; 使えない (Keychain unlock prompt を出せず timeout する) — so every long-lived
;; agent ended up reading `~/.gftd/<name>` in mode-600 plaintext, by hand, with
;; no provider, no metadata and nothing that could say where a value came from.
;; That practice is what this replaces: same custody, but through the same
;; SecretStore seam as everything else, so `kagi agent ls` can SHOW which
;; principals are the cheap ones to steal from instead of leaving it implicit.

(defn- expand-home [^String path]
  (if (str/starts-with? path "~/")
    (str (System/getProperty "user.home") (subs path 1))
    path))

(defn- secret-path ^Path [ref]
  (let [{:keys [scheme body raw]} (parse-ref ref)]
    (when-not (= "file" scheme)
      (throw (ex-info "FileSecretStore only supports file:// refs"
                      {:ref (redact-ref raw) :scheme scheme})))
    (let [expanded (expand-home body)]
      (when-not (str/starts-with? expanded "/")
        ;; A relative path resolves against whatever directory the process
        ;; happens to be in, which for a launchd agent is not a place anybody
        ;; chose. A secret that lands somewhere different depending on the
        ;; working directory is a secret that gets written twice and read once.
        (throw (ex-info "file:// secret ref must be an absolute path (or ~/…)"
                        {:ref (redact-ref raw)})))
      (.toAbsolutePath (Paths/get expanded (make-array String 0))))))

(defrecord FileSecretStore []
  SecretStore
  (put-secret! [_ ref secret _opts]
    (let [target (secret-path ref)
          parent (.getParent target)
          perms (PosixFilePermissions/fromString "rw-------")]
      (Files/createDirectories parent (make-array FileAttribute 0))
      (try
        (Files/setPosixFilePermissions parent (PosixFilePermissions/fromString "rwx------"))
        (catch Exception _))
      ;; Written to a temp file that is ALREADY mode 600 and then renamed, so
      ;; the secret is never briefly world-readable at the real path. Doing it
      ;; the other way round (write, then chmod) leaves a window whose width is
      ;; the filesystem's, not ours.
      (let [tmp (Files/createTempFile parent ".kagi-secret-" ".tmp"
                                      (make-array FileAttribute 0))]
        (try
          (Files/setPosixFilePermissions tmp perms)
          (Files/write tmp (.getBytes (str secret) StandardCharsets/UTF_8)
                       (make-array java.nio.file.OpenOption 0))
          (Files/move tmp target
                      (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING]))
          (finally
            (Files/deleteIfExists tmp))))
      {:ok? true :ref (redact-ref ref) :provider :file}))
  (get-secret [_ ref _opts]
    (let [target (secret-path ref)]
      (when-not (Files/exists target (make-array LinkOption 0))
        (throw (ex-info "missing file secret" {:ref (redact-ref ref)})))
      ;; Refuse a secret anyone else on the box can read. Returning it anyway
      ;; and warning would mean the guard's only effect is a line in a log the
      ;; agent that just leaked the value will not read.
      (let [perms (try (PosixFilePermissions/toString (Files/getPosixFilePermissions
                                                       target (make-array LinkOption 0)))
                       (catch UnsupportedOperationException _ nil))]
        (when (and perms (not= "rw-------" perms))
          (throw (ex-info "file secret is not mode 600 — refusing to read it"
                          {:ref (redact-ref ref) :permissions perms
                           :remediation (str "chmod 600 " (redact-ref ref))}))))
      (str/trim-newline (String. (Files/readAllBytes target) StandardCharsets/UTF_8))))
  (delete-secret! [_ ref _opts]
    (Files/deleteIfExists (secret-path ref))
    {:ok? true :ref (redact-ref ref) :provider :file})
  (exists? [_ ref]
    (try (Files/exists (secret-path ref) (make-array LinkOption 0))
         (catch Exception _ false)))
  (metadata [_ ref]
    {:ref (redact-ref ref)
     :provider :file
     ;; Named so a reader can tell it apart from :os-keychain at a glance. A
     ;; process running as this user reads this without any prompt — which is
     ;; the point under launchd, and the cost everywhere else.
     :custody :file-0600
     :secret-readable? true}))

(defn file-secret-store [] (->FileSecretStore))

(defrecord MemSecretStore [a]
  SecretStore
  (put-secret! [_ ref secret _] (swap! a assoc (:raw (parse-ref ref)) (str secret)) {:ok? true})
  (get-secret [_ ref _] (or (get @a (:raw (parse-ref ref)))
                            (throw (ex-info "missing mem secret" {:ref (redact-ref ref)}))))
  (delete-secret! [_ ref _] (swap! a dissoc (:raw (parse-ref ref))) {:ok? true})
  (exists? [_ ref] (contains? @a (:raw (parse-ref ref))))
  (metadata [_ ref] {:ref (redact-ref ref) :provider :mem :custody :test-only}))

(defn mem-secret-store
  ([] (mem-secret-store {}))
  ([seed] (->MemSecretStore (atom seed))))

(defn store-for-ref [ref]
  (case (:scheme (parse-ref ref))
    "keychain" (apple-keychain-store)
    "env" (env-store)
    "file" (file-secret-store)
    (throw (ex-info "unsupported secret ref scheme" {:ref (redact-ref ref)}))))

(defn put-edn! [store ref value]
  (put-secret! store ref (pr-str value) {:content-type "application/edn"}))

(defn get-edn [store ref]
  (edn/read-string (get-secret store ref {:content-type "application/edn"})))
