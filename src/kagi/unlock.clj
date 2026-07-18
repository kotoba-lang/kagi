(ns kagi.unlock
  "VMK unlock envelopes.

  The vault stores wrapped VMK envelopes. Device-local unlock secrets live in a
  SecretStore, not in vault EDN, stdout, logs, or manimani state."
  (:require [kagi.crypto :as crypto]
            [kagi.secret-store :as secret-store])
  (:import [java.util Base64 UUID]
           [java.time Instant]))

(def ^:private info-os-keychain (.getBytes "kagi/unlock/os-keychain/v1" "UTF-8"))
(def ^:private info-passkey-prf (.getBytes "kagi/unlock/passkey-prf/v1" "UTF-8"))

(defn- b64 [^bytes b]
  (.encodeToString (Base64/getEncoder) b))

(defn new-device-secret
  "Return a printable secret suitable for OS keychain storage."
  [p]
  (b64 (crypto/rand-bytes p 32)))

(defn- info-for [method]
  (case method
    :os-keychain info-os-keychain
    :passkey-prf info-passkey-prf
    info-os-keychain))

(defn wrap-vmk
  [p ^bytes vmk method secret-material fields]
  (let [salt (crypto/rand-bytes p 16)
        kek (crypto/hkdf p secret-material salt (info-for method) 32)
        nonce (crypto/rand-bytes p 12)]
    (merge {:method method
            :salt salt
            :nonce nonce
            :wrapped (crypto/aead-seal p kek nonce vmk (byte-array 0))}
           fields)))

(defn unwrap-vmk
  [p {:keys [method salt nonce wrapped]} secret-material]
  (let [kek (crypto/hkdf p secret-material salt (info-for method) 32)]
    (crypto/aead-open p kek nonce wrapped (byte-array 0))))

(defn os-keychain-wrap
  ([p vmk store ref] (os-keychain-wrap p vmk store ref {}))
  ([p vmk store ref {:keys [epoch parent now]
                     :or {epoch 0 now (str (Instant/now))}}]
  (let [secret (new-device-secret p)
        key-id (str "unlock:" (UUID/randomUUID))]
    (secret-store/put-secret! store ref secret {:content-type "text/plain"
                                                :purpose "kagi-vmk-unlock"})
    (wrap-vmk p vmk :os-keychain (.getBytes ^String secret "UTF-8")
              {:ref ref
               :provider :apple-keychain
               :created-by :kagi-unlock-enable
               :key/id key-id :key/epoch epoch :key/parent parent
               :key/state :active :key/created-at now}))))

(defn add-wrap [meta wrap]
  (update meta :unlock/wraps (fnil conj []) wrap))

(defn os-keychain-wraps [meta]
  (filter #(= :os-keychain (:method %)) (:unlock/wraps meta)))

(defn unlock-with-os-keychain
  ([p meta] (unlock-with-os-keychain p meta nil))
  ([p meta preferred-ref]
   (let [wraps (cond->> (os-keychain-wraps meta)
                 preferred-ref
                 (sort-by #(if (= preferred-ref (:ref %)) 0 1)))]
     (some (fn [{:keys [ref] :as wrap}]
             (try
               (let [store (secret-store/store-for-ref ref)
                     secret (secret-store/get-secret store ref {:purpose "kagi-vmk-unlock"})]
                 (unwrap-vmk p wrap (.getBytes ^String secret "UTF-8")))
               (catch Exception _ nil)))
           wraps))))

(defn rotate-os-keychain!
  "Crash-safe ordering for a device unlock secret. The new secret is staged
  and tested before metadata is persisted; the old secret is deleted only
  after persist-meta! succeeds."
  [p meta vmk store old-ref new-ref persist-meta! & [{:keys [now]
                                                       :or {now (str (Instant/now))}}]]
  (when-not (and (not= old-ref new-ref) (ifn? persist-meta!))
    (throw (ex-info "unlock rotation requires distinct refs and persistence callback" {})))
  (let [old (first (filter #(and (= :os-keychain (:method %))
                                 (= old-ref (:ref %)))
                           (:unlock/wraps meta)))]
    (when-not old
      (throw (ex-info "old unlock wrap not found" {:ref (secret-store/redact-ref old-ref)})))
    (let [new-wrap (os-keychain-wrap p vmk store new-ref
                                     {:epoch (inc (or (:key/epoch old) 0))
                                      :parent (:key/id old) :now now})
          recovered (let [secret (secret-store/get-secret
                                  store new-ref {:purpose "kagi-vmk-unlock"})]
                      (unwrap-vmk p new-wrap (.getBytes ^String secret "UTF-8")))]
      (when-not (java.util.Arrays/equals ^bytes vmk ^bytes recovered)
        (throw (ex-info "new unlock wrap self-test failed" {})))
      (let [meta* (assoc meta :unlock/wraps
                         (conj (vec (remove #(and (= :os-keychain (:method %))
                                                 (= old-ref (:ref %)))
                                           (:unlock/wraps meta)))
                               new-wrap))]
        (persist-meta! meta*)
        (secret-store/delete-secret! store old-ref {:purpose "kagi-vmk-unlock"})
        {:rotated? true :meta meta* :old-ref (secret-store/redact-ref old-ref)
         :new-ref (secret-store/redact-ref new-ref)
         :key-epoch (:key/epoch new-wrap)}))))

(defn passkey-prf-envelope-shape []
  {:method :passkey-prf
   :status :implemented-core
   :fields [:rp-id :credential-id :salt :nonce :wrapped]
   :flow ["navigator.credentials.create with prf extension"
          "navigator.credentials.get returns PRF output"
          "HKDF(PRF output, salt, kagi/unlock/passkey-prf/v1) unwraps VMK"]
   :fallback [:os-keychain :passphrase-recovery]})

(defn passkey-prf-wrap
  "Wrap VMK with WebAuthn PRF extension output. The credential private key is
  never exposed to kagi; only RP/credential metadata and this envelope persist."
  [p vmk ^bytes prf-output {:keys [rp-id credential-id]}]
  (when-not (and (seq rp-id) (seq credential-id) (= 32 (alength prf-output)))
    (throw (ex-info "invalid passkey PRF registration material"
                    {:rp-id? (boolean (seq rp-id)) :credential-id? (boolean (seq credential-id))
                     :prf-bytes (alength prf-output)})))
  (wrap-vmk p vmk :passkey-prf prf-output
            {:rp-id rp-id :credential-id credential-id
             :provider :webauthn-prf :created-by :kagi-passkey-register}))

(defn unlock-with-passkey-prf [p wrap ^bytes prf-output]
  (when-not (= :passkey-prf (:method wrap))
    (throw (ex-info "not a passkey PRF envelope" {:method (:method wrap)})))
  (unwrap-vmk p wrap prf-output))

(defn status [meta]
  {:wrap-count (count (:unlock/wraps meta))
   :methods (mapv (fn [w]
                    (cond-> {:method (:method w)
                             :provider (:provider w)
                             :ref (secret-store/redact-ref (:ref w))}
                      (:rp-id w) (assoc :rp-id (:rp-id w))))
                  (:unlock/wraps meta))
   :passphrase-recovery? (boolean (and (:salt meta) (:nonce meta) (:wrapped meta)))
   :passkey-prf (passkey-prf-envelope-shape)})
