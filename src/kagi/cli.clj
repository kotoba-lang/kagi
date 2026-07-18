(ns kagi.cli
  "`kagi` CLI — 1Password の `op` 相当。自己主権 + 対量子(PQC) vault をコマンドで操作する。

  保存先(カレント直下):
    .kagi/identity.edn  — actor の公開鍵 + SecretStore/native handle参照(gitignore)
    .kagi/vault.edn     — 暗号文 item + wrap 済み鍵 + 台帳(平文・素 VMK は出ない)

  unlock: master passphrase → Argon2id(salt) → KEK → VMK(wrap 解除)。passphrase は
  環境変数 KAGI_MASTER か、無ければ端末プロンプト。

  使い方:
    kagi init                       # 鍵生成 + vault 作成(passphrase 設定)
    kagi add <name> [-c comp]       # secret を stdin/プロンプトから登録
    kagi get <name>                 # secret を復号して stdout に出す
    kagi ls                         # item 一覧(復号しない)
    kagi rotate <name>              # DEK を回転(再封緘)
    kagi log                        # 監査台帳(hybrid 署名 + ハッシュ鎖)を検証して表示
    kagi whoami                     # 自分の did:key / IPNS graph"
  (:require [clojure.string :as str]
            [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.crypto :as crypto]
            [kagi.cacao :as cacao]
            [kagi.ledger :as ledger]
            [kagi.identity :as identity]
            [kagi.persist :as persist]
            [kagi.secret-store :as secret-store]
            [kagi.native-key :as native-key]
            [kagi.clipboard :as clipboard]
            [kagi.unlock :as unlock]
            [kagi.key-rotation :as key-rotation]
            [kagi.master-rotation :as master-rotation]
            [kagi.rotation-store :as rotation-store]
            [kagi.rotation-scheduler :as rotation-scheduler]
            [kagi.security-readiness :as security-readiness]
            [kagi.import.onepassword :as import-1p])
  (:import [java.time Instant]
           [java.util UUID]))

(def ^:private dir ".kagi")
(def ^:private id-path (str dir "/identity.edn"))
(def ^:private vault-path (str dir "/vault.edn"))
(def ^:private rotation-dag-path (str dir "/rotation-dag.edn"))
(def ^:private rotation-jobs-path (str dir "/rotation-jobs.edn"))
(def ^:private security-evidence-path (str dir "/security-evidence.edn"))
(def ^:private security-trust-roots-path (str dir "/security-trust-roots.edn"))
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

(defn- native-signing-config [required?]
  (if-let [type (not-empty (System/getenv "KAGI_SIGNING_KEYSTORE_TYPE"))]
    (let [pin-required? (= "true" (System/getenv "KAGI_SIGNING_KEYSTORE_REQUIRE_PIN"))
          pin (when pin-required?
                (if-let [console (System/console)]
                  (.readPassword console "native keystore PIN: " (object-array 0))
                  (throw (ex-info "native keystore PIN requires an interactive console" {}))))]
      (try
        (native-key/bootstrap
         {:type type
          :provider-name (not-empty (System/getenv "KAGI_SIGNING_KEYSTORE_PROVIDER"))
          :password pin
          :keystore-id (System/getenv "KAGI_SIGNING_KEYSTORE_ID")
          :ed-alias (System/getenv "KAGI_SIGNING_ED_ALIAS")
          :mldsa-alias (System/getenv "KAGI_SIGNING_MLDSA_ALIAS")
          :x25519-alias (not-empty (System/getenv "KAGI_KEM_X25519_ALIAS"))
          :mlkem-alias (not-empty (System/getenv "KAGI_KEM_MLKEM_ALIAS"))})
        (finally
          (when pin (java.util.Arrays/fill ^chars pin (char 0))))))
    (when required?
      (throw (ex-info "KAGI_SIGNING_KEYSTORE_TYPE is required" {})))))

(defn- identity-options [command]
  (let [development? (= "plaintext-development" (System/getenv "KAGI_IDENTITY_STORE"))
        production? (= "production" (System/getenv "KAGI_SECURITY_PROFILE"))
        ref (or (not-empty (System/getenv "KAGI_IDENTITY_REF"))
                (when-not development? default-identity-ref))
        native (native-signing-config false)]
    (when (and production? (or development? (nil? native) (nil? (:kem-handle native))))
      (throw (ex-info "production profile requires native non-exportable signing and KEM handles"
                      {:profile :production
                       :plaintext-development? development?
                       :native-signing-configured? (boolean native)
                       :native-kem-configured? (boolean (:kem-handle native))})))
    ;; identity-migrate must be able to read the one legacy plaintext file it
    ;; immediately moves into SecretStore. All other commands fail closed.
    (cond-> (if ref
              {:secret-ref ref :secret-store (secret-store/store-for-ref ref)}
              {:allow-plaintext? true :allow-existing-plaintext? true})
      native (assoc :native-signing native)
      (= command "identity-migrate") (assoc :allow-existing-plaintext? true))))

;; ───────── VMK unlock ─────────

(defn- derive-kek [p pass salt]
  (crypto/argon2id p (.getBytes ^String pass "UTF-8") salt {:m-kb 262144 :t 3 :p 4}))

(def ^:private current-kdf
  {:name :argon2id :version 1 :m-kb 262144 :t 3 :p 4})

(defn- derive-meta-kek [p pass {:keys [salt kdf]}]
  (let [pass-bytes (.getBytes ^String pass "UTF-8")]
    (case [(:name kdf) (:version kdf)]
      [:argon2id 1] (crypto/argon2id p pass-bytes salt kdf)
      ;; Legacy snapshots had no KDF marker and used the historical HKDF loop.
      [nil nil] (crypto/legacy-kdf-v0 pass-bytes salt {:m-kb 262144 :t 3 :p 4})
      (throw (ex-info "unsupported vault KDF" {:kdf kdf})))))

(defn- new-vmk-meta [p pass]
  (let [now (str (Instant/now))
        vmk  (crypto/rand-bytes p 32)
        salt (crypto/rand-bytes p 16)
        kek  (derive-kek p pass salt)
        n    (crypto/rand-bytes p 12)]
    {:vmk vmk :meta {:kdf current-kdf :salt salt :nonce n
                     :wrapped (crypto/aead-seal p kek n vmk (byte-array 0))
                     :vmk-key (master-rotation/new-vmk-key-record
                               now "wrapped://vault-meta/vmk" 0 nil)}}))

(defn- unlock-vmk [p pass {:keys [nonce wrapped] :as meta}]
  (try (crypto/aead-open p (derive-meta-kek p pass meta) nonce wrapped (byte-array 0))
       (catch Exception _ (die "wrong passphrase (VMK unlock failed)"))))

(defn- rewrap-vmk-meta [p pass vmk meta]
  (if (:kdf meta)
    meta
    (let [salt (crypto/rand-bytes p 16)
          nonce (crypto/rand-bytes p 12)
          kek (crypto/argon2id p (.getBytes ^String pass "UTF-8") salt current-kdf)]
      (assoc meta :kdf current-kdf :salt salt :nonce nonce
             :wrapped (crypto/aead-seal p kek nonce vmk (byte-array 0))
             :kdf/migrated-from :legacy-hkdf-loop-v0))))

(defn- unlock-vmk-auto [p meta]
  (if-let [pass (System/getenv "KAGI_MASTER")]
    (let [vmk (unlock-vmk p pass meta)]
      {:vmk vmk :meta (rewrap-vmk-meta p pass vmk meta)})
    (if-let [vmk (unlock/unlock-with-os-keychain p meta
                                                 (not-empty (System/getenv "KAGI_UNLOCK_REF")))]
      {:vmk vmk :meta meta}
      (let [pass (passphrase false)
            vmk (unlock-vmk p pass meta)]
        {:vmk vmk :meta (rewrap-vmk-meta p pass vmk meta)}))))

(defn- ensure-vmk-key [meta]
  (if (:vmk-key meta)
    meta
    (assoc meta :vmk-key
           (master-rotation/new-vmk-key-record
            "1970-01-01T00:00:00Z" "wrapped://vault-meta/legacy-vmk" 0 nil))))

;; ───────── vault / actor ─────────

(defn- load-store [data]
  (store/mem-store (or data {})))

(defn- save-store! [st meta]
  (let [a @(:a st)]
    (persist/save! vault-path (assoc (select-keys a [:members :items :grants :blocks :ledger
                                                      :rotation-events])
                                     :meta meta))))

(defn- self-cacao [id]
  (cacao/mint id {:cap :cap/admin :scope (:graph id)}
              {:aud aud :nonce (str (UUID/randomUUID))
               :issued-at (str (Instant/now)) :expiry (str (.plusSeconds (Instant/now) 3600))}))

(defn- context [id vmk purpose]
  {:did (:did id) :role :owner :phase 3 :vmk vmk :purpose purpose
   :now (str (Instant/now))
   :aud aud :cacao (self-cacao id) :register (identity/member-record id :owner)})

(defn- run-op! [p id store vmk req purpose]
  (let [actor (op/build store {:crypto p :signer (identity/sign-secret id)
                               :signer-key (:signing-key id)})]
    (:state (g/run* actor {:request req :context (context id vmk purpose)}
                    {:thread-id (str (:op req) "-" (:item-id req) "-" (UUID/randomUUID))}))))

;; ───────── opts ─────────

(defn- arg-val [args flag] (->> args (drop-while #(not= flag %)) second))
(defn- positional [args] (remove #(str/starts-with? % "-") (rest args)))
(defn- parse-long* [s default]
  (if (str/blank? (str s))
    default
    (try
      (Long/parseLong (str s))
      (catch NumberFormatException _
        (die "expected integer, got:" s)))))

;; ───────── commands ─────────

(defn- cmd-init [p id]
  (when (persist/load* vault-path) (die "vault already exists at" vault-path))
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
        {vmk :vmk meta0 :meta} (unlock-vmk-auto p (:meta data))
        meta (ensure-vmk-key meta0)
        st   (load-store (dissoc data :meta))]
    (try
      (let [result (f st vmk)]
        (save-store! st meta)
        result)
      (finally (java.util.Arrays/fill ^bytes vmk (byte 0))))))

(defn- cmd-add [p id args]
  (let [name (first (positional args))
        comp (or (arg-val args "-c") "personal")]
    (when-not name (die "usage: kagi add <name> [-c compartment]"))
    (with-vault p
      (fn [st vmk]
        (let [secret (str/trim (slurp *in*))]
          (when (str/blank? secret) (die "empty secret on stdin"))
          (run-op! p id st vmk {:op :item/create :item-id name :compartment comp
                                :plaintext (.getBytes secret "UTF-8")} :cli-add)
          (println "stored" name "in" comp))))))

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
            (let [secret (String. ^bytes pt "UTF-8")
                  result (clipboard/copy-secret-with-ttl!
                          (clipboard/macos-clipboard)
                          secret
                          {:ttl-ms (* ttl-sec 1000)})]
              (println (pr-str (merge result
                                      {:item name
                                       :purpose purpose
                                       :provider :macos-pbcopy
                                       :approval :human-approved
                                       :secret? false}))))
            (die "reveal denied:" (get-in r [:result :effect]))))))))

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

(defn- item-schedule-records [data]
  (mapv (fn [it]
          {:key/id (:item/id it)
           :key/class :item-dek
           :key/purpose :item-dek
           :key/epoch (or (:item/key-epoch it) (:item/version it) 0)
           :key/state :active
           :key/high-value? (contains? #{:recovery-code :root-credential :signing-key}
                                       (:item/category it))
           ;; Legacy items without a timestamp are immediately due so they
           ;; acquire a fresh epoch under the versioned lifecycle.
           :key/created-at (or (:item/key-created-at it) "1970-01-01T00:00:00Z")})
        (vals (:items data))))

(defn- lifecycle-schedule-record [key class purpose]
  (when key
    {:key/id (:key/id key)
     :key/class class
     :key/purpose purpose
     :key/epoch (:key/epoch key)
     :key/state (:key/state key)
     :key/high-value? (boolean (:key/high-value? key))
     :key/created-at (:key/created-at key)
     :key/last-rotated-at (:key/last-rotated-at key)}))

(defn all-schedule-records
  "Inventory every cryptographic key class. Only item DEKs are safely
  unattended today; the other records still need HSM/passkey provisioning,
  but must be visible to the same due-date policy rather than silently omitted."
  [id data]
  (let [meta (:meta data)
        identity [(lifecycle-schedule-record (:signing-key id)
                                             :identity-signing :authority)
                  (lifecycle-schedule-record (:kem-key id)
                                             :recipient-kem :recipient-kem)]
        vmk [(lifecycle-schedule-record (:vmk-key meta) :vmk :vmk)]
        unlocks (map #(lifecycle-schedule-record % :device-unlock :device-unlock)
                     (:unlock/wraps meta))]
    (vec (concat (item-schedule-records data)
                 (remove nil? identity) (remove nil? vmk) (remove nil? unlocks)))))

(defn- cmd-rotation-due [id]
  (let [data (update (or (persist/load* vault-path) (die "no vault — run: kagi init"))
                     :meta ensure-vmk-key)]
    (doseq [job (rotation-scheduler/due-rotations
                 (all-schedule-records id data) (str (Instant/now)))]
      (println
       (pr-str
        (assoc job :rotation/execution
               (if (= :item-dek (:rotation/purpose job))
                 :automatic
                 :manual-provisioning-required)))))))

(defn- cmd-rotation-run [p id]
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        {vmk :vmk meta0 :meta} (unlock-vmk-auto p (:meta data))
        meta (ensure-vmk-key meta0)
        st (load-store (dissoc data :meta))
        job-store (rotation-scheduler/file-job-store rotation-jobs-path)
        now (str (Instant/now))
        owner (str (.getHostName (java.net.InetAddress/getLocalHost)) ":"
                   (.pid (java.lang.ProcessHandle/current)))]
    (try
      (let [results
            (rotation-scheduler/run-due!
             job-store (item-schedule-records data) now
             {:owner owner
              :max-jobs (parse-long* (System/getenv "KAGI_ROTATION_MAX_JOBS_PER_TICK") 5)
              :worker
              (fn [job]
                (let [before @(:a st)]
                  (try
                    (run-op! p id st vmk
                             {:op :item/rotate :item-id (:rotation/key-id job)}
                             :scheduled-rotation)
                    ;; Persist before the scheduler marks the job complete.
                    (save-store! st meta)
                    {:item-id (:rotation/key-id job)
                     :from-epoch (:rotation/from-epoch job)
                     :to-epoch (inc (:rotation/from-epoch job))}
                    (catch Exception e
                      (reset! (:a st) before)
                      (throw e)))))} )]
        (doseq [result results]
          (println (pr-str (select-keys result [:rotation/job-id :job/status
                                                :job/result :job/attempts]))))
        results)
      (finally (java.util.Arrays/fill ^bytes vmk (byte 0))))))

(defn- current-parent [dag subject purpose key-id epoch]
  (let [matches (filter #(and (= subject (:rotation/subject %))
                              (= purpose (:rotation/purpose %))
                              (= key-id (:rotation/to-key %))
                              (= epoch (:rotation/to-epoch %)))
                        (rotation-store/events dag))]
    (when (> (count matches) 1)
      (throw (ex-info "multiple rotation parents for active key" {:key-id key-id})))
    (:rotation/id (first matches))))

(defn- require-new-ref [args]
  (or (not-empty (arg-val args "--new-ref"))
      (die "--new-ref is required and must not reuse the active identity ref")))

(defn- rotated-vault-snapshot [data old-id next-id]
  (let [members (-> (:members data)
                    (dissoc (:did old-id))
                    (assoc (:did next-id) (identity/member-record next-id :owner)))]
    (assoc data :members members)))

(defn- cmd-identity-key-rotate [p id args]
  (let [class (second args)
        new-ref (require-new-ref args)
        old-ref (:secret-ref id)
        _ (when (= old-ref new-ref) (die "--new-ref must differ from active identity ref"))
        data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        dag (rotation-store/file-store rotation-dag-path)
        secret-store (secret-store/store-for-ref new-ref)
        [purpose key]
        (case class
          "authority" [:authority (:signing-key id)]
          "kem" [:recipient-kem (:kem-key id)]
          (die "usage: kagi key-rotate authority|kem --new-ref keychain://service/account"))
        parent (current-parent dag (:authority-id id) purpose
                               (:key/id key) (:key/epoch key))
        current {:subject (:authority-id id) :purpose purpose
                 :key-id (:key/id key) :epoch (:key/epoch key) :parent parent}
        plan0 (case class
                "authority" (key-rotation/prepare-authority
                             p id {:custody-ref new-ref :parent parent})
                "kem" (key-rotation/prepare-kem
                       p id {:custody-ref new-ref :parent parent}))
        plan (case class
               "authority" (key-rotation/admit-authority! dag p plan0 current)
               "kem" (key-rotation/admit-kem! dag p plan0 current))
        vault-next (rotated-vault-snapshot data id (:next plan))
        committed (key-rotation/commit-secret-backed!
                   id-path secret-store new-ref plan
                   {:additional-snapshots {vault-path vault-next}})]
    (println (pr-str (assoc committed :class (keyword class) :secret? false)))))

(defn- rewrap-all-unlock-methods [p pass old-meta new-vmk]
  (when (some #(= :passkey-prf (:method %)) (:unlock/wraps old-meta))
    (throw (ex-info "VMK rotation requires an interactive Passkey PRF bridge"
                    {:remediation "rotate VMK from the local browser flow so every wrap is preserved"})))
  (let [salt (crypto/rand-bytes p 16)
        nonce (crypto/rand-bytes p 12)
        kek (derive-kek p pass salt)
        wraps (mapv
               (fn [{:keys [method ref] :as old-wrap}]
                 (case method
                   :os-keychain
                   (let [store (secret-store/store-for-ref ref)
                         secret (secret-store/get-secret store ref {:purpose "kagi-vmk-unlock"})]
                     (unlock/wrap-vmk p new-vmk method (.getBytes ^String secret "UTF-8")
                                      (select-keys old-wrap [:ref :provider :created-by
                                                             :key/id :key/epoch :key/parent
                                                             :key/state :key/created-at])))
                   (throw (ex-info "unsupported unlock wrap during VMK rotation"
                                   {:method method}))))
               (:unlock/wraps old-meta))]
    (-> old-meta
        (assoc :kdf current-kdf :salt salt :nonce nonce
               :wrapped (crypto/aead-seal p kek nonce new-vmk (byte-array 0))
               :unlock/wraps wraps)
        (dissoc :vmk-key))))

(defn- cmd-vmk-rotate [p id]
  (let [data0 (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        meta0 (ensure-vmk-key (:meta data0))
        pass (passphrase false)
        old-vmk (unlock-vmk p pass meta0)
        data (assoc data0 :meta meta0)
        old-key (:vmk-key meta0)
        dag (rotation-store/file-store rotation-dag-path)
        parent (current-parent dag (:authority-id id) :vmk
                               (:key/id old-key) (:key/epoch old-key))
        current {:subject (:authority-id id) :purpose :vmk
                 :key-id (:key/id old-key) :epoch (:key/epoch old-key) :parent parent}]
    (try
      (let [plan0 (master-rotation/plan
                   p id data old-vmk
                   {:custody-ref "wrapped://vault-meta/vmk"
                    :parent parent
                    :wrap-meta #(rewrap-all-unlock-methods p pass meta0 %)})
            plan (master-rotation/admit! dag p plan0 current)
            result (master-rotation/commit! vault-path plan)]
        (println (pr-str (assoc result :class :vmk :secret? false)))
        (java.util.Arrays/fill ^bytes (:new-vmk plan) (byte 0)))
      (finally
        (java.util.Arrays/fill ^bytes old-vmk (byte 0))))))

(defn- cmd-device-unlock-rotate [p args]
  (let [old-ref (or (arg-val args "--old-ref")
                    (die "--old-ref is required"))
        new-ref (or (arg-val args "--new-ref")
                    (die "--new-ref is required"))
        data (or (persist/load* vault-path) (die "no vault — run: kagi init"))
        pass (passphrase false)
        vmk (unlock-vmk p pass (:meta data))
        store (secret-store/store-for-ref new-ref)]
    (try
      (let [result (unlock/rotate-os-keychain!
                    p (:meta data) vmk store old-ref new-ref
                    #(persist/save! vault-path (assoc data :meta %)))]
        (println (pr-str (assoc (dissoc result :meta) :class :device-unlock
                               :secret? false))))
      (finally (java.util.Arrays/fill ^bytes vmk (byte 0))))))

(defn- cmd-key-rotate [p id args]
  (case (second args)
    ("authority" "kem") (cmd-identity-key-rotate p id args)
    "vmk" (cmd-vmk-rotate p id)
    "device-unlock" (cmd-device-unlock-rotate p args)
    (die "usage: kagi key-rotate authority|kem|vmk|device-unlock [options]")))

(defn- recover-pending-identity! []
  (when-let [journal (persist/load* (str id-path ".rotation.pending.edn"))]
    (let [ref (:new-secret-ref journal)]
      (key-rotation/recover-pending! id-path (secret-store/store-for-ref ref))
      (binding [*out* *err*]
        (println "recovered pending identity rotation" (:event-id journal))))))

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

(defn- cmd-identity-native-migrate []
  (let [raw (or (persist/load* id-path) (die "no identity at" id-path))
        _ (when-not (identity/secret-backed-identity? raw)
            (die "run kagi identity-migrate before native migration"))
        native (native-signing-config true)
        public-id (identity/load-identity raw)
        store (secret-store/store-for-ref (:secret-ref raw))
        result (identity/migrate-native-signing! id-path public-id store native)]
    (println (pr-str (assoc result :secret? false)))
    result))

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

(defn- cmd-unlock-status []
  (let [data (or (persist/load* vault-path) (die "no vault — run: kagi init"))]
    (println (pr-str (unlock/status (:meta data))))))

(defn- cmd-security-status [fail?]
  (let [id (or (persist/load* id-path) {})
        data (or (persist/load* vault-path) {})
        evidence (or (persist/load* security-evidence-path) {})
        trust-roots (or (persist/load* security-trust-roots-path) {})
        dag (rotation-store/file-store rotation-dag-path)
        job-store (rotation-scheduler/file-job-store rotation-jobs-path)
        result (security-readiness/assess
                {:identity id
                 :records (all-schedule-records id data)
                 :unlock-wraps (get-in data [:meta :unlock/wraps])
                 :rotation-events (rotation-store/events dag)
                 :jobs (rotation-scheduler/jobs job-store)
                 :attestations (:attestations evidence)
                 :trusted-attestors (:trusted-attestors trust-roots)
                 :crypto-provider (crypto/jvm-provider)
                 :now (str (Instant/now))})]
    (println (pr-str result))
    (when (and fail? (not (:security/production-ready? result)))
      (System/exit 2))
    result))

(defn- cmd-security-attest [p id args]
  (let [[control-name digest] (positional args)
        control-id (some-> control-name keyword)
        issuer (or (arg-val args "--issuer")
                   (not-empty (System/getenv "KAGI_ATTESTATION_ISSUER"))
                   (die "--issuer is required"))
        attestation (security-readiness/issue-attestation
                     p (identity/sign-secret id) control-id
                     {:issuer issuer :performed-at (str (Instant/now))
                      :artifact-sha256 digest})]
    (println (persist/->edn {:attestations {control-id attestation}}))))

(defn- cmd-security-trust-root [id args]
  (let [issuer (or (arg-val args "--issuer")
                   (not-empty (System/getenv "KAGI_ATTESTATION_ISSUER"))
                   (die "--issuer is required"))]
    (println (persist/->edn {:trusted-attestors {issuer (identity/sign-public id)}}))))

(defn- help []
  (println (str/trim "
kagi — 自己主権・対量子(PQC) secrets vault (op 相当)

  kagi init                 鍵生成 + vault 作成
  kagi add <name> [-c c]    secret を stdin から登録   (printf '%s' s | kagi add foo)
  kagi get <name>           secret を復号して stdout へ
  kagi copy <name> --purpose p [--ttl 45]
                            secret を stdout に出さず clipboard へ一時コピー
  kagi ls                   item 一覧
  kagi import onepassword <file.1pux> [-c compartment] [--include-archived]
                            1Password の 1PUX export を取り込む(kagitaba 経由)
  kagi rotate <name>        DEK 回転(再封緘)
  kagi rotation-due         期限到来した item DEK rotation job を表示
  kagi rotation-run         期限到来した item DEK を Governor 経由で回転
  kagi key-rotate authority --new-ref keychain://service/new-account
                            identity authority を dual-sign DAG rotation
  kagi key-rotate kem --new-ref keychain://service/new-account
                            recipient KEM を authority-certified rotation
  kagi key-rotate vmk       全 item DEK を新 VMKへtransactional re-wrap
  kagi key-rotate device-unlock --old-ref keychain://... --new-ref keychain://...
                            device unlock secret をstage/test/commit/delete rotation
  kagi log                  監査台帳を検証して表示
  kagi whoami               自分の did:key / IPNS graph
  kagi identity-migrate     identity 秘密鍵を OS keychain へ移す
  kagi identity-native-migrate
                            token公開鍵と署名を検証後、exportable署名鍵を除去
  kagi unlock-enable-keychain [--ref keychain://service/account]
                            VMK unlock を OS keychain に追加(passphrase は recovery として残す)
  kagi unlock-status        VMK unlock methods を metadata のみ表示
  kagi security-status      local state + signed external evidence を評価
  kagi security-check       production-readyでなければ exit 2
  kagi security-attest <control> <artifact-sha256> --issuer <id>
                            reviewerが再現artifactへhybrid署名（stdoutのみ）
  kagi security-trust-root --issuer <id>
                            reviewer公開鍵trust-root fragmentをstdoutへ出力

passphrase は環境変数 KAGI_MASTER か端末プロンプト。
KAGI_UNLOCK_REF=keychain://... で device unlock ref を指定。
KAGI_IDENTITY_STORE=keychain で新規 identity 秘密鍵を Apple Keychain に保存。
native署名には KAGI_SIGNING_KEYSTORE_TYPE/ID、KAGI_SIGNING_ED_ALIAS、
KAGI_SIGNING_MLDSA_ALIAS、KAGI_KEM_X25519_ALIAS、KAGI_KEM_MLKEM_ALIAS を設定。
PINが必要なら
KAGI_SIGNING_KEYSTORE_REQUIRE_PIN=true（対話入力のみ、環境変数PINは禁止）。
鍵/vault は ./.kagi/(gitignore)。")))

(defn -main [& args]
  (if (or (empty? args)
          (#{"help" "-h" "--help"} (first args))
          (some #{"-h" "--help"} args))
    (help)
    (let [_  (recover-pending-identity!)
          p  (crypto/jvm-provider)
          command (first args)]
      (case command
        "identity-native-migrate" (cmd-identity-native-migrate)
        "security-status" (cmd-security-status false)
        "security-check" (cmd-security-status true)
        (let [id (identity/load-or-create-identity! id-path p (identity-options command))]
          (case command
        "init"   (cmd-init p id)
        "add"    (cmd-add p id args)
        "get"    (cmd-get p id args)
        "copy"   (cmd-copy p id args)
        "ls"     (cmd-ls)
        "import" (case (second args)
                   "onepassword" (cmd-import-onepassword p id (rest args))
                   (die "usage: kagi import onepassword <file.1pux> [-c compartment] [--include-archived]"))
        "rotate" (cmd-rotate p id args)
        "rotation-due" (cmd-rotation-due id)
        "rotation-run" (cmd-rotation-run p id)
        "key-rotate" (cmd-key-rotate p id args)
        "log"    (cmd-log p id)
        "whoami" (cmd-whoami id)
        "identity-migrate" (cmd-identity-migrate p id args)
        "unlock-enable-keychain" (cmd-unlock-enable-keychain p id args)
            "unlock-status" (cmd-unlock-status)
            "security-attest" (cmd-security-attest p id args)
            "security-trust-root" (cmd-security-trust-root id args)
            (help))))))
  (flush))
