(ns kagi.agent-protocol
  "The wire contract between a kagi vault and a principal that is not a person.

  ## Why this namespace exists at all

  Everything else in kagi assumes an operator: `kagi get` prompts, `kagi
  device grant` refuses without a fingerprint a human read aloud, `kagi ui`
  opens a browser. Under launchd there is no operator — the Keychain cannot
  prompt, so the workspace's own secrets map records the actual outcome:
  long-lived agents ended up reading `~/.gftd/<name>` in mode-600 plaintext,
  outside the vault, outside the governor, outside the ledger. This is the
  surface that makes the vault reachable without a human in the loop, so that
  fallback stops being the only thing that works.

  ## Server and client share THIS file, not a description of it

  `kagi.agent-http` (server) and `kagi.agent-client` / `sdk/kagi-agent.mjs`
  (clients) both build and check the same shapes here. A protocol described
  twice is a protocol that drifts: the enrollment flow this mirrors changed
  under us between 2026-08-17 and 2026-08-21 (see
  `scripts/agentmail-inbox-create.cljs`, which documents the cost of finding
  out from a 410).

  ## What the proof-of-work is and is NOT

  It is the SAME construction as the agent-inbox host this API is shaped
  after: `sha256(challenge \":\" nonce)` with `difficulty-bits` leading zero
  bits. It exists so enrollment cannot be attempted thousands of times a
  second, and for nothing else.

  **It is not authentication.** An inbox handed to whoever solves a puzzle is
  worth what it costs to solve; a vault is not, and an API that let a solved
  puzzle reach one would be a footgun with a nice SDK. Scope always comes from
  an INVITE the owner minted (`kagi agent invite`), which names the
  compartments, the operations and the expiry before any agent asks. The PoW
  throttles guesses at that invite. `enrollment-errors` therefore refuses a
  request with no invite even when the PoW is perfect.

  Portable on purpose: the digest functions are injected rather than required,
  so this compiles on nbb, in a browser and on the JVM without any of them
  pulling a provider they do not have. There are TWO of them and they are not
  interchangeable — `sha256-bytes-fn` must return raw digest bytes (the PoW
  counts leading zero BITS, which a hex string does not have), while
  `digest-string-fn` returns a printable digest that can sit in EDN and be
  compared as a value. Passing one where the other belongs silently changes
  what a difficulty level means."
  (:require [clojure.string :as str]))

(def ^:const algorithm
  "The only PoW algorithm this protocol speaks. Named on the wire so a future
  one is a value change rather than a silent reinterpretation of the same
  bytes."
  "sha256-v1")

(def ^:const default-difficulty-bits
  "20 bits ≈ 10^6 hashes ≈ well under a second in Node or on the JVM, and
  ~17 minutes to make a million attempts. That ratio is the whole point: a
  cost an honest agent does not notice and a bulk attempt cannot pay."
  20)

(def ^:const default-challenge-ttl-sec 120)

(def ^:const default-agent-ttl-sec
  "30 days. Long enough that a resident agent is not re-enrolling constantly,
  short enough that an abandoned one stops working before anyone remembers to
  revoke it. `kagi agent ls` shows the expiry so it is visible, not merely
  configured."
  (* 30 24 60 60))

(def ops
  "Operations an agent principal can be granted — the vault ops themselves, so
  a capability here is a capability the AccessGovernor actually evaluates.
  Deliberately a closed set: `:item/create` and `:share/grant` are here so they
  CAN be granted, and are never in a default, because an agent that can write
  is an agent that can overwrite the item it was supposed to read.

  There is deliberately no `:sign/digest`. Signing is `:item/reveal` of the
  seed item plus `kagi.agent/signer`, and a capability keyword that no check
  ever reads would look like a fence while fencing nothing."
  #{:item/reveal :item/list :item/create :item/update :item/rotate
    :share/grant :share/revoke})

(def default-ops
  "What an invite grants when nobody said. Read-only: the two operations that
  cannot change what is in the vault."
  #{:item/reveal :item/list})

;; ───────────────────────────── proof of work ─────────────────────────────

(defn- digest-length
  "`count`/`nth` reach a JVM `byte[]` and a Clojure vector, but NOT a
  `Uint8Array` — which is exactly what `@noble/hashes` returns, so a portable
  digest helper that used them would work on every runtime except the one the
  browser SDK runs on."
  [d]
  #?(:clj (count d)
     :cljs (if (nil? (.-length d)) (count d) (.-length d))))

(defn- digest-byte [d i]
  #?(:clj (bit-and (int (nth d i)) 0xff)
     :cljs (bit-and (int (if (nil? (.-length d)) (nth d i) (aget d i))) 0xff)))

(defn leading-zero-bits
  "Count leading ZERO bits of a digest. Takes a JVM `byte[]`, a `Uint8Array`
  or a vector.

  Zeros, not ones — and the distinction is not academic. The first version of
  this counted leading ones, and every solve/verify test still passed, because
  the solver and the checker call the SAME function and agreed with each other
  about the wrong thing. What it broke was interoperability: `difficulty_bits`
  would have meant something no other implementation of `sha256-v1` means.
  `leading-zero-bits-counts-bits-not-bytes` pins the values directly for that
  reason."
  [digest]
  (let [n (digest-length digest)]
    (loop [i 0 bits 0]
      (if (>= i n)
        bits
        (let [b (digest-byte digest i)]
          (if (zero? b)
            (recur (inc i) (+ bits 8))
            (+ bits
               (loop [mask 0x80 extra 0]
                 (if (or (zero? mask) (not (zero? (bit-and b mask))))
                   extra
                   (recur (bit-shift-right mask 1) (inc extra)))))))))))

(defn pow-input
  "The exact bytes-as-string that gets hashed. One function, so the solver and
  the checker cannot disagree about the separator — which is the classic way
  a PoW ends up unsolvable in production and fine in the test suite."
  [challenge nonce]
  (str challenge ":" nonce))

(defn pow-satisfies?
  "`sha256-bytes-fn` must return raw digest bytes — see the ns docstring."
  [sha256-bytes-fn challenge nonce difficulty-bits]
  (and (not (str/blank? (str challenge)))
       (not (str/blank? (str nonce)))
       (>= (leading-zero-bits (sha256-bytes-fn (pow-input challenge nonce)))
           (or difficulty-bits default-difficulty-bits))))

(defn solve-pow
  "Find a nonce satisfying the challenge, or nil when `max-attempts` runs out.

  Returns nil rather than looping forever: a client that hangs on an
  unsolvable difficulty is indistinguishable from a network stall, and the
  caller can say which one it hit only if this can answer 'I gave up'."
  ([sha256-bytes-fn challenge difficulty-bits]
   (solve-pow sha256-bytes-fn challenge difficulty-bits {}))
  ([sha256-bytes-fn challenge difficulty-bits {:keys [max-attempts start]
                                               :or {max-attempts 50000000 start 0}}]
   (loop [nonce (long start) tried 0]
     (cond
       (>= tried max-attempts) nil
       (pow-satisfies? sha256-bytes-fn challenge (str nonce) difficulty-bits) (str nonce)
       :else (recur (inc nonce) (inc tried))))))

;; ───────────────────────────── enrollment ─────────────────────────────

(defn enrollment-errors
  "Everything that makes an enrollment refuse, as data — one code per distinct
  cause.

  Separate codes are load-bearing here in the same way they are in
  `kagi.device/grant-errors`: `:pow-failed` is a client that got the
  construction wrong, `:challenge-expired` is a slow solver, and
  `:invite-unknown` is somebody guessing invites. Collapsing them into one
  403 makes the third invisible, and the third is the only one that is an
  attack."
  [{:keys [invite pow public label]} {:keys [challenge difficulty-bits expired? invite-record now]}
   sha256-bytes-fn]
  (cond-> []
    (str/blank? (str invite))
    (conj {:rule :invite-missing
           :detail "招待が要る。PoW は enrollment の速度制限であって認証ではない —
                    `kagi agent invite --compartment <名前>` で発行する"})

    (and (seq (str invite)) (nil? invite-record))
    (conj {:rule :invite-unknown :detail "その招待は存在しないか、既に使い切られている"})

    (and invite-record (:invite/expires-at invite-record) now
         (pos? (compare (str now) (str (:invite/expires-at invite-record)))))
    (conj {:rule :invite-expired
           :detail (str "この招待は " (:invite/expires-at invite-record) " に失効している")})

    (and invite-record (some-> (:invite/uses-left invite-record) (<= 0)))
    (conj {:rule :invite-exhausted :detail "この招待は使用回数を使い切っている"})

    (nil? challenge)
    (conj {:rule :challenge-unknown :detail "その challenge_id は発行されていない"})

    expired?
    (conj {:rule :challenge-expired :detail "challenge が失効している — 取り直すこと"})

    (and challenge (not expired?)
         (not (pow-satisfies? sha256-bytes-fn challenge (:nonce pow) difficulty-bits)))
    (conj {:rule :pow-failed
           :detail (str "sha256(challenge \":\" nonce) の先頭 " difficulty-bits
                        " bit が 0 になっていない")})

    (or (nil? public) (nil? (:kem public)) (nil? (:sign public)))
    (conj {:rule :incomplete-keys
           :detail "public.kem(hybrid KEM 公開鍵)と public.sign(Ed25519+ML-DSA 公開鍵)の両方が要る"})

    (str/blank? (str label))
    (conj {:rule :label-missing
           :detail "label が要る — 誰が何のために持っている principal か、
                    後から台帳を読む人に分かる名前を付けること"})))

;; ───────────────────────────── bearer tokens ─────────────────────────────

(def ^:const token-prefix
  "`kagi_agt_` so a leaked token is greppable in a log or a paste, and a
  secret scanner has something to match. The workspace lost an inbox once to a
  key that looked like nothing in particular."
  "kagi_agt_")

(defn token-hash
  "What the vault stores instead of the token. `digest-string-fn` returns a
  PRINTABLE digest (it ends up in EDN and is compared as a value), which is
  the other of the two digest seams this namespace takes — see the ns
  docstring. The token itself is returned
  exactly once, at enrollment, and is not recoverable afterwards — the same
  contract the agent-inbox host uses for `account_key`, and for the same
  reason: a credential a server can read back is a credential a server can
  leak."
  [digest-string-fn token]
  (digest-string-fn (str "kagi/agent/token/v1:" token)))

(defn bearer-token
  "Strip `Bearer ` from an Authorization header. Returns nil for anything that
  is not a bearer credential rather than treating the whole header as a token
  — a client sending Basic auth should be told it is unauthorized, not have
  its base64 compared against a hash."
  [authorization]
  (let [s (str/trim (str authorization))]
    (when (str/starts-with? (str/lower-case s) "bearer ")
      (not-empty (str/trim (subs s 7))))))
