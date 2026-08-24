(ns kagi.chain-signer
  "Production custody for the wallet signer seam (wallet.signer/Signer):
  the BIP-39 seed phrase lives in a kagi vault item and NEVER leaves this
  process — callers get public keys and signatures, exactly the boundary a
  hardware wallet draws (ADR-2608241100, generalizing ADR-2608039900
  decision 1: saifu は鍵を保管しない。kagi が署名する).

  ## Every operation is governed, none is cached

  Each `public-key64` / `sign-digest!` call reveals the seed item through
  `kagi.vault-read/reveal` — the same `kagi.operation` graph the CLI's
  `kagi get` uses, so the AccessGovernor censors and the append-only ledger
  records EVERY signature, with a purpose string naming the operation and
  derivation path. The mnemonic is deliberately NOT cached between calls:
  caching would turn 'every signature is governed' into 'the first
  signature was governed', which is the ambient-authority degradation this
  layer exists to prevent. A signature is worth a governor round-trip.

  ## What this is NOT

  - Not a key generator: the seed item must already exist in the vault
    (`kagi put` a secure note whose value is the mnemonic). A read-only
    signing path that could mint keys would be a second, unaudited custody
    surface.
  - Not a policy engine: spend limits / msg-type allow-lists / dispositions
    are saifu.policy's job (evaluated against the ledger). This layer only
    guarantees custody + audit.

  ## Layering

    wallet.chain / wallet.siwe        tx assembly, addresses  (no keys)
    wallet.signer/Signer              the seam                (this side owns keys)
    kagi.chain-signer  ← here         reveal→derive→sign→drop
    kagi.vault-read → kagi.operation  governor + ledger
    kagi vault (compartment/DEK)      the seed at rest

  JVM-only today (the vault itself is): the :cljs arities throw, in the
  btc-crypto stub style, rather than pretending a browser can hold this
  boundary."
  (:require [btc-crypto.bip32 :as bip32]
            [btc-crypto.bip39 :as bip39]
            [clojure.string :as str]
            [eth-crypto.core :as eth]
            #?(:clj [kagi.vault-read :as vault-read])
            [wallet.signer :as wsigner]))

(defn- refuse [reason message data]
  (throw (ex-info message (assoc data :reason reason))))

#?(:clj
   (defn- with-master
     "Reveal the mnemonic via `reveal-fn` (purpose-string → plaintext-or-nil),
     derive the master node, apply `f`, and let the plaintext go out of scope.
     A nil reveal is the governor REFUSING — surfaced as a named refusal, not
     a NullPointerException three frames later."
     [reveal-fn passphrase purpose f]
     (let [mnemonic (reveal-fn purpose)]
       (when (or (nil? mnemonic) (str/blank? mnemonic))
         (refuse :kagi.chain-signer/reveal-refused
                 "kagi.chain-signer: the vault refused to reveal the seed (locked vault, unknown item, or governor denial) — refusing to sign"
                 {:purpose purpose}))
       (f (bip32/seed->master
           (bip39/mnemonic->seed (str/trim mnemonic) (or passphrase "")))))))

#?(:clj
   (defn signer
     "A wallet.signer/Signer over `reveal-fn` — (fn [purpose] mnemonic-or-nil).
     `opts`: {:passphrase <optional BIP-39 passphrase>}.

     This arity exists so the derive/sign core is testable against
     wallet.signer/seed-signer parity WITHOUT a vault; production callers use
     `vault-signer` below, whose reveal-fn is the governed path."
     ([reveal-fn] (signer reveal-fn {}))
     ([reveal-fn {:keys [passphrase]}]
      (reify wsigner/Signer
        (public-key64 [_ path]
          (with-master reveal-fn passphrase (str "chain-signer public-key " path)
            (fn [master]
              (eth/private->public (:private-key (bip32/derive-path master path))))))
        (sign-digest! [_ path digest]
          (with-master reveal-fn passphrase (str "chain-signer sign-digest " path)
            (fn [master]
              (eth/secp256k1-sign (:private-key (bip32/derive-path master path)) digest)))))))
   :cljs
   (defn signer [& _]
     (throw (js/Error. "kagi.chain-signer/signer: JVM-only (the vault is)"))))

#?(:clj
   (defn vault-signer
     "The production Signer: seed custody in the kagi vault, every operation
     through the governor and onto the ledger.

       session  : an OPEN kagi.vault-read/open session
       item-id  : the vault item whose plaintext is the BIP-39 mnemonic
       passphrase : optional BIP-39 passphrase (NOT stored here — a caller
                    that has it holds a second factor the vault does not)

     The ledger purpose for each reveal is
     \"chain-signer <op> <derivation-path>\" — an audit trail that says which
     key was used for what, not merely that the seed was read."
     [session item-id & [{:keys [passphrase]}]]
     (when-not (= :open (:status session))
       (refuse :kagi.chain-signer/vault-not-open
               (str "kagi.chain-signer: vault session is " (pr-str (:status session))
                    " — open (and unlock) the vault before constructing a signer")
               {:status (:status session)}))
     (signer (fn [purpose] (vault-read/reveal session item-id purpose))
             {:passphrase passphrase}))
   :cljs
   (defn vault-signer [& _]
     (throw (js/Error. "kagi.chain-signer/vault-signer: JVM-only (the vault is)"))))
