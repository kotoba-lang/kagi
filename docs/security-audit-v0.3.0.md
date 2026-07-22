# v0.3.0 security review delta

Status: ready for independent review; external audit not yet performed.

Review `kagi.recovery-io` and the recovery CLI paths for exclusive creation, file permissions,
share/VMK disclosure, error handling and lifecycle. Verify that reconstructed VMKs remain
process-local. Review `passkey-prf-wrap` and `unlock-with-passkey-prf` for RP/credential binding,
domain separation and hostile host input.

Known limitation: browser registration UX and authenticator support detection remain host work;
the JVM API consumes PRF output produced by a WebAuthn-capable trusted host adapter.
