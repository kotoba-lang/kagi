# Changelog

## 0.6.0 — 2026-08-28

- Add agent principals (`kagi agent`): a non-person actor holds only its own
  hybrid keypair and reads exactly the items it was granted, never the VMK or a
  compartment key (ADR-2608281100).
- Add the recipient reveal path to `kagi.operation`, so a `:share/grant`
  envelope can be opened through the governor instead of only by hand in a
  test; `:item/list` is grant-filtered for non-owners.
- Enforce agent scope in the AccessGovernor: `:agent-op`, `:agent-expired`,
  `:agent-clock`, `:agent-revoked`, `:agent-purpose`.
- Add the self-service agent API (`kagi agent serve`) and its SDK
  (`kagi.agent-client`). The server holds no VMK and releases only sealed
  material; the SDK decrypts in the caller's process.
- Require an owner-minted invite for enrollment. The proof of work is a rate
  limit, not authentication.
- Add a `file://` SecretStore provider (mode 600, refuses looser permissions),
  the only custody that works under launchd.
- Record each agent's reveals and refusals on its own signed chain
  (`kagi agent log`), and accept them back through `POST /v1/audit`.
- Fix `save-store!` dropping `:rotation-events`, and the CLI context carrying no
  `:now` (every item this CLI wrote had a nil `:item/key-created-at`).
- Make `kagi.vault/item-aad` portable; it called `.getBytes` inside a `.cljc`.
- Keep the principal registry in its own object (`agents/registry.edn`) rather
  than in the vault snapshot, so enrolling does not rewrite (and `kagi push`
  does not erase) 9.5 MB of ciphertext; writes go through a cross-process file
  lock with a sequence check, and a legacy in-metadata registry is migrated
  once.
- Derive the vault member record from the principal instead of storing a second
  copy of it.

- Add an object-store sync backend (`kagi push --backend object`): the same
  already-encrypted snapshot into any S3-compatible store (Backblaze B2,
  Storj), over the four functions `kagi.store/object-sealed-block-store`
  already takes. Versioned keys plus a HEAD pointer make refusing to overwrite
  the concurrency control, so a second writer at the same sequence is refused
  rather than erasing the first one's vault. Credentials come from the
  environment only.
- Add `kagi.object-store`, the wiring that builds those four functions from B2
  credentials. io-storj is an extra-dep of the `:cli` and `:test` aliases, not
  of the library.

- Serve the agent API from an object store: `kagi.agent-docs` is the storage
  seam (`:vault`, `:registry`, audit), so `kagi agent serve --backend object
  --did <tenant>` runs on a host with no vault file and no VMK. Registry writes
  in the store use the same versioned-key CAS as the vault snapshot.
- Route every `kagi agent` command through that seam, so an invite minted with
  `--backend object` lands in the registry the served API actually reads.
- Generalize the object backend to named documents
  (`kagi/<did>/<doc>/v<N>.edn` + `HEAD`), used by both the vault snapshot and
  the registry.
- Refuse to overwrite an identity secret that already exists at a
  `KAGI_IDENTITY_REF` with a different key. Pointing that variable at another
  home's secret while `identity.edn` was absent silently replaced the private
  key, after which every operation was held with `verified? false` — an
  authorization-shaped symptom for a destroyed key. `:replace? true` is the
  deliberate override.
- Report why an op did not commit: `grant refused: nil` could not distinguish
  an `authn` failure (which never reaches the governor) from a policy hold.

- Name the tenant in every route (`/v1/t/<did>/…`), so one server can hold many
  vaults and no path's meaning depends on how the process was started. An
  unknown tenant is 404, not another vault's data. `kagi agent serve` prints
  the base URL an agent should use, and the SDK takes `:tenant`.
- Make challenges stateless: a `<payload>.<HMAC>` token carrying its own
  difficulty and expiry, so several instances can sit behind one URL and a
  restart does not fail enrollments in flight. Single use is best-effort and
  documented as such; the bound that holds is the invite's `uses-left`.
- Stop escaping `/` in JSON bodies — an error naming a path was unreadable.

- Close the audit loop for remote agents: the SDK keeps its own hash-chained,
  hybrid-signed record of what it opened and why, `submit-audit!` hands it to
  the owner, and `kagi agent audit <id>` verifies it against the public key the
  registry recorded. Until now `POST /audit` had no producer — the HTTP path
  runs no governor, so nothing was recording remote reads at all.
- Accept `application/edn` request bodies. A JSON round-trip turns a fact's
  keyword values into strings, which changes the canonical bytes and makes
  `verify-chain` reject an untampered ledger.

- Split the object-store layout into catalog / ledger / blocks. Measured, and
  the first guess was wrong: the ciphertext is not the bulk — the audit ledger
  is 9,502,228 of 9,576,873 bytes (1,965 hybrid-signed entries at ~3.3 KB of
  ML-DSA base64 each). A server answering `/items` or `/sealed` now reads
  46,861 bytes instead of 9,576,873.
- Key blocks by `sha256(cid)`, not the cid. B2 answered HTTP 500 to a PUT of
  `blocks/cid:manimani-…:v1`, and the cid in a key told anyone who could list
  the bucket that a credential by that name existed.
- Record the uploaded block cids in the catalog. Deriving them from item cids
  on restore silently returned 88 of 93 blocks, dropping superseded versions.

- Make `kagi.ledger` portable (`.clj` → `.cljc`), so audit verification can run
  where the API runs. Adds `kagi.b64` and `kagi.digest` — one implementation of
  base64 and SHA-256 for both runtimes, because two implementations are how two
  runtimes end up disagreeing about a signature. `kagi.agent-client`'s own
  copies now delegate to them.

- Split the registry half of `kagi.agent` into `kagi.agent-registry` (`.cljc`),
  so enrollment, lookup and revocation can run where the API runs;
  `kagi.agent` re-exports them, so no caller changes. Adds `kagi.pubkey` — did:key
  derivation from an encoded public key and the device fingerprint, both
  pinned by test against the JVM implementations they replace.
- Add `kagi.portable-slice-test`: the transitive require graph of the portable
  namespaces must be all `.cljc`. Structural rather than a cljs run, and it is
  the check that catches how this actually breaks.

### Known blocker

- `kagi push` / `pull` / `sync` do not work against live kotobase.net. The CACAO
  this repo mints is correct — it verifies against the gateway's own algorithm
  (SIWE reconstruction byte-identical, Ed25519 signature valid, every
  `validate-cacao*` condition satisfied). The graph-database backend now runs
  with `KOTOBASE_BISCUIT_AUTH_MODE=required`, which answers 401 to any
  non-Biscuit Authorization before the CACAO branch is reached. Obtaining a
  Biscuit needs a tenant record and a service-account credential this vault
  does not have. See ADR-2608281200.

## 0.5.0 — 2026-07-22

- Add `kagi unlock-enable-passkey` with a loopback-only one-shot browser bridge.
- Require exact Origin and 256-bit token binding; reject replay and expire after 120 seconds.
- Serve the Passkey UI with no-store and restrictive Content Security Policy headers.
- Add real localhost HTTP integration coverage for hostile Origin and replay attempts.

## 0.4.0 — 2026-07-22

- Add WebAuthn PRF browser registration/authentication adapter and minimal accessible UX.
- Add a strict browser-to-JVM base64url bridge with RP, credential, salt and length validation.
- Persist only the public PRF salt/credential metadata; PRF output remains ephemeral secret input.
- Run browser adapter tests in CI.

## 0.3.0 — 2026-07-22

- Add owner-only, exclusive-create recovery share files and CLI create/verify/get ceremony.
- Keep reconstructed VMKs process-local and out of vault snapshots and command metadata.
- Add host-adapter-ready WebAuthn PRF VMK wrap/unlock APIs.

## 0.2.0 — 2026-07-22

- Add k-of-n Shamir VMK recovery shares with set and integrity validation.
- Add optimistic cloud sequence checks so `kagi sync` cannot silently overwrite
  a snapshot changed after pull.
- Remove the sync path that converted pull/network errors into an unsafe push.

## 0.1.0 — 2026-07-22

- Hybrid ML-KEM-768/X25519 encryption and ML-DSA-65/Ed25519 signatures.
- Governed vault operations, signed hash-chain ledger, local CLI and encrypted cloud snapshots.
- SecretStore-backed device unlock with passphrase recovery fallback.
- Injected SealedBlockStore boundary with ciphertext end-to-end contract coverage.
- Recovery drill covering loss of a device-local unlock secret.

This is a security-focused technical preview. It has not received an independent external audit.
