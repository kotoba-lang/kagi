# v0.1.0 security review package

Status: ready for independent review; external audit not yet performed.

## Scope

- `kagi.crypto`: hybrid KEM/signatures, AEAD, KDF boundaries and test vectors.
- `kagi.operation` / `kagi.governor`: authorization topology and fail-closed behavior.
- `kagi.store` / `kagi.sync` / `kagi.persist`: ciphertext custody, metadata and cloud relay.
- `kagi.unlock` / `kagi.secret-store`: device loss and recovery boundaries.
- `kagi.ledger` / `kagi.cacao`: integrity, identity and replay/audience checks.

## Security claims to verify

1. Governor denial cannot reach a reveal, write, share or key operation side effect.
2. Cloud and SealedBlockStore boundaries receive ciphertext only; VMK and plaintext stay local.
3. Hybrid verification fails if either classical or PQ signature fails.
4. A lost device secret does not defeat passphrase recovery and cannot independently open a vault.
5. Ledger deletion, insertion, modification and signature stripping are detected.

## Reproducible evidence

```bash
java -version                 # JDK 24 is required
clojure -M:test               # unit, contract and recovery-drill evidence
clojure -M:lint               # static checks; zero warnings required
```

Relevant focused tests: `crypto_test`, `governor_contract_test`, `store_contract_test`,
`recovery_drill_test`, `ledger_test`, `cacao_test`, and `unlock_test`.

## Known limitations / explicit exclusions

- No independent audit has been completed.
- Cloud snapshot synchronization is last-writer-wins, not item-level conflict merging.
- Passkey PRF registration UI and threshold Shamir recovery are not release features.
- Apple Keychain is the only production SecretStore provider currently supplied.
- Memory zeroization and browser autofill/phishing defenses are not complete.

## Auditor deliverables requested

- Findings classified by severity and exploit prerequisites.
- Review of protocol composition and domain separation, not only primitive selection.
- Reproduction cases that can be added as regression tests.
- Explicit statement of reviewed commit SHA and exclusions.
