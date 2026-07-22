# Changelog

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
