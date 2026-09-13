# Case key custody boundary

`kagi.case-keys/operate!` is an internal asynchronous facade for create, encrypt,
decrypt, revoke and destroy. It reuses `kagi.governor`, requires case, tenant,
principal, purpose, slot and unexpired server-owned authorization, commits audit
before custody, and projects results without keys. AEAD associated data binds
format version, case, applicant subject and evidence slot.

This is a library boundary, not a deployed KMS. Production custody, private HTTP
authentication and Kotobase transaction adapters are not included. Do not enable
real identity intake based on these tests.

## Host contract

Supply `:now!` (trusted epoch milliseconds) and `:with-case!`. The latter accepts
request metadata and an async callback. It authenticates service/caller, loads
current authorization from private canonical Kotobase state, then supplies
`:scope`, `:context`, `:store`, `:audit!`, `:custody!`. Never derive these from
caller JSON. Hold authoritative cross-process case serialization until the
callback promise settles, including against revocation. Local locks are not enough.

Scope contains case-id, tenant, applicant subject, principal, purpose, allowed-ops,
slots, expires-at and custody status. Governor context carries the same principal
DID and tenant, role, clearance and applicable ABAC policy. Its rejection is final;
never manufacture an owner role to pass admission.

`audit!` durably appends the exact metadata event, returning committed status,
that event and receipt-ref. Do not log plaintext or keys. `custody!` receives the
audited operation, AAD and input bytes. It independently enforces authenticated
scope and persistent revocation. Public Workers must not expose an arbitrary
operation proxy. There is no raw-key operation.

Custody allocates independent random per-case keys inside its private boundary,
not deterministically derived from a shared master. Create/revoke/destroy must be
idempotent by case and request ID with persistent bindings and conflicting reuse
rejection. Never recreate revoked/destroyed keys. Encrypt requires fresh nonces.
Bound I/O and output. Reconcile uncertain operations before retrying.

Results bind case-id/request-id and include receipt-ref. Create returns active,
encrypt/decrypt return ok plus bytes, revoke returns revoked. Destroy requires
prior revocation and stays destroy-pending until all copies, wraps, histories,
replicas and recovery material have been handled. Only a qualified provider may
return destroyed, coverage all-key-copies and independently verifiable evidence-ref.
The facade checks receipt shape, not truth of the provider claim. File/secret
record deletion or dropping a runtime reference is not proof of crypto erasure.

## Deployment work still required

Provision private custody; verify restarts, persistent revocation, serialization
races, replay handling and old-backup behavior. Connect private Kotobase audit and
state, proving CID privacy and CAS. Replace eKYC identity-vault's key-returning port
with remote operations. This AEAD v1 differs from the old evidence envelope: use
explicit versions and no transparent fallback. Cloudflare Secrets Store may hold
narrow service credentials; it does not establish case-key destruction semantics.
Connect review and retention execution and run a consented end-to-end test before
opening intake. Revocation is an access decision, not a ZK identity proof.

## Validation, 2026-09-13

kbb SCI: three tests / 20 assertions. A test-only in-memory provider uses real
non-extractable AES-256-GCM keys. Covered: round trip, AEAD subject binding,
cross-case/principal/tenant denial, expiry, audit failure, revoke-before-destroy,
no decryption after revocation and rejecting unsubstantiated destruction.
Runtime-reference deletion correctly stays pending. This does not qualify
restarts, replicas, old backups, production or native/Q9.
