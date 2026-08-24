(ns kagi.chain-signer-test
  "The derive/sign core of kagi.chain-signer, tested WITHOUT a vault via the
  reveal-fn arity (the vault path composes the same core with
  kagi.vault-read/reveal, whose governor/ledger behavior is covered by
  kagi's own operation/governor tests). What is pinned here:

  1. PARITY — the kagi signer is byte-identical to wallet.signer/seed-signer
     over the same mnemonic (which is itself byte-identical to the legacy
     private-key path, by wallet's own parity oracle).
  2. EVERY operation reveals — no caching. Two operations must reach the
     reveal-fn twice; a cache would make 'every signature is governed' false
     while all other assertions stay green.
  3. The purpose string names the operation and the derivation path — the
     audit trail says WHICH key did WHAT, not merely that the seed was read.
  4. A refused reveal (nil) is a NAMED refusal, and a locked/absent vault
     session is refused at construction."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [btc-crypto.bip32 :as bip32]
            [btc-crypto.bip39 :as bip39]
            [kagi.chain-signer :as cs]
            [wallet.chain :as w]
            [wallet.signer :as wsigner]
            [wallet.siwe :as siwe]))

(def ^:private mnemonic
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

(def ^:private reference
  (wsigner/seed-signer (bip32/seed->master (bip39/mnemonic->seed mnemonic))))

(defn- refusal-reason [thunk]
  (try (thunk) ::no-throw
       (catch clojure.lang.ExceptionInfo e (:reason (ex-data e)))))

(deftest parity-with-seed-signer
  (let [sgnr (cs/signer (fn [_] mnemonic))
        path "m/44'/60'/0'/0/0"
        digest (byte-array 32 (byte 7))]
    (is (= (seq (wsigner/public-key64 reference path))
           (seq (wsigner/public-key64 sgnr path))))
    (is (= (wsigner/sign-digest! reference path digest)
           (wsigner/sign-digest! sgnr path digest)))))

(deftest whole-stack-parity-account-tx-siwe
  ;; the kagi signer must be a drop-in Signer for wallet.chain / wallet.siwe
  (let [sgnr (cs/signer (fn [_] mnemonic))
        acct (w/account-with sgnr :eth)
        tx {:nonce 9 :gas-price 20000000000 :gas 21000
            :to "0x3535353535353535353535353535353535353535"
            :value 1000000000000000000 :data "0x" :chain-id 1}]
    (is (= (w/account-with reference :eth) acct))
    (is (= (w/sign-tx-with reference acct tx) (w/sign-tx-with sgnr acct tx)))
    (is (:ok? (siwe/verify-sign-in
               (siwe/sign-in-with {:domain "example.com" :address (:address acct)
                                   :uri "https://example.com" :chain-id 1
                                   :nonce "n-1" :issued-at "2026-08-24T00:00:00Z"}
                                  sgnr (:path acct))
               {:expected-domain "example.com"})))))

(deftest every-operation-reveals-nothing-is-cached
  (let [purposes (atom [])
        sgnr (cs/signer (fn [purpose] (swap! purposes conj purpose) mnemonic))
        path "m/44'/60'/0'/0/0"]
    (wsigner/public-key64 sgnr path)
    (wsigner/sign-digest! sgnr path (byte-array 32))
    (wsigner/sign-digest! sgnr path (byte-array 32 (byte 1)))
    (is (= 3 (count @purposes))
        "3 operations must mean 3 governed reveals — a cache here silently
         un-governs every signature after the first")
    (is (every? #(str/includes? % path) @purposes)
        "the audit purpose must name the derivation path")
    (is (some #(str/includes? % "sign-digest") @purposes))
    (is (some #(str/includes? % "public-key") @purposes))))

(deftest refused-reveal-is-a-named-refusal
  (let [sgnr (cs/signer (fn [_] nil))]
    (is (= :kagi.chain-signer/reveal-refused
           (refusal-reason #(wsigner/sign-digest! sgnr "m/44'/60'/0'/0/0" (byte-array 32)))))
    (is (= :kagi.chain-signer/reveal-refused
           (refusal-reason #(wsigner/public-key64 sgnr "m/44'/60'/0'/0/0"))))))

(deftest locked-or-absent-vault-refused-at-construction
  (is (= :kagi.chain-signer/vault-not-open
         (refusal-reason #(cs/vault-signer {:status :locked} "item-1"))))
  (is (= :kagi.chain-signer/vault-not-open
         (refusal-reason #(cs/vault-signer {:status :absent} "item-1")))))

(deftest passphrase-changes-the-derived-key
  ;; BIP-39 passphrase is a real second factor — same mnemonic, different tree.
  (let [a (cs/signer (fn [_] mnemonic))
        b (cs/signer (fn [_] mnemonic) {:passphrase "TREZOR"})]
    (is (not= (seq (wsigner/public-key64 a "m/44'/60'/0'/0/0"))
              (seq (wsigner/public-key64 b "m/44'/60'/0'/0/0"))))))
