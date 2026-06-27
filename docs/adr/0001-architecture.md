# ADR-0001: kagi-clj architecture（actor 化された PQC vault）

**Status**: proposed · **Date**: 2026-06-27 · **Deciders**: Jun Kawasaki

正本は superproject の `90-docs/adr/2606272330-kagi-clj-pqc-vault.md`。本書はリポ内サマリ。

## Decision

1. **hybrid PQC**: KEM = X25519 + ML-KEM-768(FIPS 203)、署名 = Ed25519 + ML-DSA-65(FIPS 204)、
   対称 = AES-256-GCM、unlock = Argon2id + passkey PRF、復旧 = Shamir k-of-n。古典を捨てず併記。
2. **鍵階層**: unlock → VMK(多重 wrap) → compartment(HKDF) → per-item DEK → AES-256-GCM 封緘。
3. **ストレージ分割(zero-knowledge)**: 暗号文 blob は kotoba `SealedBlockStore`(B2/IPFS)、
   index/ACL/grant/envelope/version は Datomic graph(CACAO-gated)、台帳はハッシュ鎖 append-only。
4. **actor**: langgraph-clj StateGraph。intake→authn→advise→govern→decide→{reveal|write|share|rotate|hold}。
   単一不変条件「Governor が拒否する 開示/書込/共有/鍵操作/認証 を kagi は決して行わない」を位相で保証。
5. **注入境界(swap)**: Store(`:db-api` MemStore≡KotobaStore)・Crypto Provider(JVM BouncyCastle ‖ WASM
   kotoba-crypto Rust)・Phase(0→3) を差し替えてもコア不変。contract test で等価保証。
6. **identity**: `itonami/cacao.clj` 継承。Ed25519 did:key/IPNS は不変、ML-DSA を加法。秘密鍵は
   `.kagi/identity.edn`(gitignore)。

## Seams（プロトコル）

- `kagi.store/Store`（`:db-api` 越し）
- `kagi.crypto/Provider`（kem/sign/aead/kdf）
- `kagi.advisor/Advisor`（risk proposal のみ）
- `kagi.phase/gate`（caution を足すのみ、外せない）

## 段階導入

0 read-only(shadow) → 1 self-vault → 2 team share → 3 supervised auto-rotation。
