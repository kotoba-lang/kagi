(ns kagi.device-test
  "Device enrollment: a second machine gets the vault without the master
  passphrase ever being copied to it."
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.crypto :as crypto]
            [kagi.device :as device]
            [kagi.secret-store :as secret-store]
            [kagi.unlock :as unlock]))

(defn- p [] (crypto/jvm-provider))

(defn- enrolled-vmk [] (crypto/rand-bytes (p) 32))

(defn- request-on-new-device []
  (let [store (secret-store/mem-secret-store)
        {:keys [request fingerprint]} (device/make-request! (p) {:label "mac-b" :store store})]
    {:store store :request request :fingerprint fingerprint}))

;; ───────────────── the happy path ─────────────────

(deftest a-second-device-recovers-the-vmk-without-the-passphrase
  (testing "the whole point: nothing long-lived is copied between machines"
    (let [vmk (enrolled-vmk)
          {:keys [store request fingerprint]} (request-on-new-device)
          grant (device/make-grant (p) vmk request fingerprint)
          vault-store (secret-store/mem-secret-store)
          {recovered :vmk wrap :wrap} (device/accept-grant!
                                       (p) grant {:store store :vault-store vault-store})]
      (is (= (seq vmk) (seq recovered)) "byte-identical VMK on the new device")
      (is (= :os-keychain (:method wrap))
          "and it lands as an ordinary keychain wrap, so the grant is never needed again"))))

(deftest the-new-device-can-then-unlock-on-its-own
  (let [vmk (enrolled-vmk)
        {:keys [store request fingerprint]} (request-on-new-device)
        grant (device/make-grant (p) vmk request fingerprint)
        vault-store (secret-store/mem-secret-store)
        {wrap :wrap} (device/accept-grant! (p) grant {:store store :vault-store vault-store})
        meta (unlock/add-wrap {} wrap)]
    (with-redefs [secret-store/store-for-ref (constantly vault-store)]
      (is (= (seq vmk) (seq (unlock/unlock-with-os-keychain (p) meta)))
          "unlock goes through the normal path -- enrollment adds a device, not a second mechanism"))))

;; ───────────────── the fingerprint is the whole defence ─────────────────

(deftest a-grant-without-a-confirmed-fingerprint-is-refused
  (testing "an operator who pipes an untrusted request straight into grant has
            no way to notice a substituted public key, so this REFUSES rather
            than printing a warning nobody reads"
    (let [{:keys [request]} (request-on-new-device)]
      (is (thrown? clojure.lang.ExceptionInfo
                   (device/make-grant (p) (enrolled-vmk) request nil)))
      (is (some #{:fingerprint-missing} (mapv :rule (device/grant-errors request nil)))))))

(deftest a-substituted-public-key-changes-the-fingerprint
  (testing "the attack this defends against: the request is intercepted and the
            attacker's own public key put in its place. The fingerprint the
            NEW DEVICE printed no longer matches what arrived."
    (let [{:keys [request fingerprint]} (request-on-new-device)
          attacker (request-on-new-device)
          swapped (assoc request :device/public (:device/public (:request attacker)))]
      (is (not= fingerprint (device/fingerprint
                             (into {} (map (fn [[k v]] [k v]) (:device/public swapped)))))
          "different key, different fingerprint")
      (is (some #{:fingerprint-mismatch}
                (mapv :rule (device/grant-errors swapped fingerprint))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (device/make-grant (p) (enrolled-vmk) swapped fingerprint))))))

(deftest a-mismatch-and-a-missing-check-are-different-codes
  (testing "one is an operator who skipped the step; the other is an operator
            who did it and it failed, which may be an attack. A ledger that
            cannot tell them apart is less useful than one that can."
    (let [{:keys [request]} (request-on-new-device)]
      (is (= [:fingerprint-missing] (mapv :rule (device/grant-errors request ""))))
      (is (= [:fingerprint-mismatch] (mapv :rule (device/grant-errors request "AAAA-BBBB-CCCC")))))))

(deftest the-fingerprint-is-readable-out-loud
  (testing "the operator has to retype this, so it excludes I/O/0/1 and is
            grouped -- a 64-char hex string invites 'looks about right'"
    (let [{:keys [fingerprint]} (request-on-new-device)]
      (is (re-matches #"[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){5}" fingerprint)))))

;; ───────────────── the grant is a message, not a standing offer ─────────────────

(deftest an-expired-grant-is-refused
  (testing "a grant sitting in a chat log is a standing offer of the whole
            vault to anyone who also has the device key -- and that key is on
            a machine not yet trusted enough to have been enrolled"
    (let [{:keys [store request fingerprint]} (request-on-new-device)
          grant (device/make-grant (p) (enrolled-vmk) request fingerprint {:ttl-sec 900})]
      (is (empty? (device/accept-errors grant (:grant/issued-at grant))))
      (is (some #{:grant-expired}
                (mapv :rule (device/accept-errors grant "2099-01-01T00:00:00Z"))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (device/accept-grant! (p) grant {:store store :now "2099-01-01T00:00:00Z"}))))))

(deftest a-grant-carries-no-key-material-in-the-clear
  (let [vmk (enrolled-vmk)
        {:keys [request fingerprint]} (request-on-new-device)
        grant (device/make-grant (p) vmk request fingerprint)
        blob (pr-str grant)]
    (is (not (clojure.string/includes? blob (String. (byte-array (map #(bit-and % 0x7f) vmk))))))
    (is (nil? (:grant/vmk grant)))
    (testing "what it does carry is an encapsulation only the device can open"
      (is (some? (:grant/kem-ct grant)))
      (is (some? (:grant/wrapped grant))))))

(deftest another-device-cannot-open-a-grant-addressed-elsewhere
  (testing "the encapsulation is to ONE public key"
    (let [vmk (enrolled-vmk)
          b (request-on-new-device)
          c (request-on-new-device)
          grant (device/make-grant (p) vmk (:request b) (:fingerprint b))]
      (is (thrown? Exception
                   (device/accept-grant! (p) (assoc grant :grant/device-id
                                                    (:device/id (:request c)))
                                         {:store (:store c)}))))))

;; ───────────────── registry ─────────────────

(deftest a-registry-entry-and-a-wrap-are-separate-facts
  (testing "an entry with no wrap is a device recorded but never completed,
            and that should be visible rather than look enrolled"
    (let [meta (device/register {} {:device-id "d1" :label "mac-b"
                                    :fingerprint "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"
                                    :wrap-ref "keychain://kagi/vmk-unlock-d1"})]
      (is (= 1 (count (device/devices meta))))
      (is (zero? (:wrap-count (:unlock (device/status meta))))
          "registered, not yet unlockable"))))

(deftest revoke-removes-the-wrap-and-marks-the-entry
  (let [wrap {:method :os-keychain :ref "keychain://kagi/vmk-unlock-d1"}
        meta (-> {}
                 (unlock/add-wrap wrap)
                 (device/register {:device-id "d1" :label "mac-b"
                                   :fingerprint "F" :wrap-ref (:ref wrap)}))
        after (device/revoke-device meta "d1")]
    (is (= 1 (count (:unlock/wraps meta))))
    (is (zero? (count (:unlock/wraps after))))
    (is (some? (:device/revoked-at (first (device/devices after)))))))

(deftest revoke-does-not-touch-another-device
  (let [w1 {:method :os-keychain :ref "keychain://kagi/vmk-unlock-d1"}
        w2 {:method :os-keychain :ref "keychain://kagi/vmk-unlock-d2"}
        meta (-> {} (unlock/add-wrap w1) (unlock/add-wrap w2)
                 (device/register {:device-id "d1" :wrap-ref (:ref w1)})
                 (device/register {:device-id "d2" :wrap-ref (:ref w2)}))
        after (device/revoke-device meta "d1")]
    (is (= ["keychain://kagi/vmk-unlock-d2"] (mapv :ref (:unlock/wraps after))))))

(deftest status-never-shows-key-material
  (let [{:keys [store request fingerprint]} (request-on-new-device)
        grant (device/make-grant (p) (enrolled-vmk) request fingerprint)
        vault-store (secret-store/mem-secret-store)
        {wrap :wrap device-id :device-id} (device/accept-grant!
                                           (p) grant {:store store :vault-store vault-store})
        meta (-> {} (unlock/add-wrap wrap)
                 (device/register {:device-id device-id :label "mac-b"
                                   :fingerprint fingerprint :wrap-ref (:ref wrap)}))
        blob (pr-str (device/status meta))]
    (testing "the MATERIAL, not the field names.

             A first version of this test grepped the rendered status for the
             strings \"wrapped\" and \"salt\" and failed -- because
             `unlock/status` documents the passkey envelope SHAPE, whose
             `:fields` list contains those words as keyword names. Matching a
             field name proves nothing about whether its value leaked, which is
             the same mistake as searching printed output for PII and calling a
             namespaced-key map clean."
      (is (not (clojure.string/includes? blob (String. ^bytes (:wrapped wrap) "ISO-8859-1"))))
      (is (not (clojure.string/includes? blob (String. ^bytes (:salt wrap) "ISO-8859-1"))))
      (is (empty? (filter bytes? (tree-seq coll? seq (device/status meta))))
          "no byte array survives into the status at all"))
    (is (clojure.string/includes? blob "mac-b"))))
