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
5. **注入境界(swap)**: Store(`:db-api` MemStore≡KotobaStore)・Crypto Provider(JVM=JDK24 標準
   ML-KEM-768/ML-DSA-65 + BouncyCastle Argon2id ‖ WASM=kotoba-crypto Rust)・Phase(0→3) を
   差し替えてもコア不変。contract test で等価保証。
6. **identity**: `itonami/cacao.clj` 継承。Ed25519 did:key/IPNS は不変、ML-DSA を加法。秘密鍵は
   `.kagi/identity.edn`(gitignore)。
7. **secret custody refs**: manimani などの consumer は secret 値を保持せず、
   `kagi://...` / `keychain://...` の参照だけを保存する。secret reveal は runtime adapter の
   最終境界でのみ行い、LLM prompt・activity log・Kotoba facts へ平文を渡さない。

## Seams（プロトコル）

- `kagi.store/Store`（`:db-api` 越し）
- `kagi.crypto/Provider`（kem/sign/aead/kdf）
- `kagi.advisor/Advisor`（risk proposal のみ）
- `kagi.phase/gate`（caution を足すのみ、外せない）

## 段階導入

0 read-only(shadow) → 1 self-vault → 2 team share → 3 supervised auto-rotation。

## Current implementation status

CLI 実装は `./.kagi` ローカル vault を中心に動く。

- `vault.edn`: 暗号文 item、wrap 済み DEK、grant envelope、ledger を保存する。平文 item と
  raw VMK は保存しない。
- VMK: `master passphrase -> Argon2id(256MiB, t=3, p=4) -> KEK` で導出した鍵で
  AES-256-GCM wrap する。
- item: per-item DEK + AES-256-GCM。DEK は VMK/compartment key 由来 KEK で wrap する。
- share: 受信者 KEM public key へ `X25519 + ML-KEM-768` で DEK grant envelope を作る。
- ledger: hash-chain + `Ed25519 + ML-DSA-65` hybrid signature。

未完了の信頼境界:

- `.kagi/identity.edn` は actor signing/KEM 秘密鍵を local file として持つ。これは gitignore
  だけでは十分な custody ではない。`kagi.secret-store/SecretStore` と Apple Keychain provider
  を追加したため、新規 identity は `KAGI_IDENTITY_STORE=keychain` で OS keychain custody に
  できる。既存 identity は `kagi identity-migrate` で移行する。
- KotobaStore は注入式 SealedBlockStore 境界を持ち、暗号化→blob/metadata分離→取得→復号を
  contract test で検証する。CLI の既定 backend は local `.kagi` snapshot、cloud CLIは
  暗号化snapshot同期。B2/IPFS production adapterは未実装。
- Passkey PRF browser registration UIはarchitecture target。hostからPRF outputを受ける
  VMK wrap/unlock APIと、Shamir recoveryのowner-only create/verify/get CLI ceremonyは実装済み。
  `kagi.recovery` はVMK用k-of-n分割・復元とset/integrity検証を行う。通常のCLI unlockは
  master passphraseに加えてOS keychain device unlock envelopeをサポートする。

## Multi-device model

複数端末では plaintext secret や 1 つの identity file を横流ししない。推奨は device ごとに
identity を作り、owner が必要 item の DEK を device identity に grant すること。

```text
owner identity
  ├─ grants item DEK -> laptop identity
  ├─ grants item DEK -> phone identity
  └─ revokes phone grant when lost
```

この model では端末紛失時に device identity 単位で revoke/rotate でき、ledger にどの端末へ
grant したかが残る。bootstrap のために `.kagi` を trusted channel でコピーする場合も、
その後は device-specific identity へ re-grant して identity file 共有を終える。

## SecretStore provider contract

```clojure
(defprotocol SecretStore
  (put-secret! [store ref secret opts])
  (get-secret [store ref opts])
  (delete-secret! [store ref opts])
  (exists? [store ref])
  (metadata [store ref]))
```

Implemented:

- `keychain://service/account`: Apple Keychain generic password provider.
- `env://NAME`: read-only process env bridge.
- in-memory provider for tests.

Planned:

- Android Keystore provider.
- Windows Credential Manager provider.
- passkey PRF backed VMK unwrap UI/registration.

## Device unlock envelopes

`KAGI_MASTER` を端末へ保存しない。端末に保存する場合は master passphrase ではなく、
ランダムな device unlock secret を OS keychain に置く。vault 側には VMK の追加 envelope
だけを保存する。

```edn
{:unlock/wraps
 [{:method :os-keychain
   :ref "keychain://com.junkawasaki.kagi/vmk-unlock"
   :provider :apple-keychain
   :salt ...
   :nonce ...
   :wrapped ...}]}
```

Unlock order:

1. `KAGI_MASTER` があれば既存 Argon2id envelope で VMK unwrap。
2. 無ければ `:os-keychain` envelope の `:ref` を解決し、device unlock secret から
   `HKDF(secret, salt, "kagi/unlock/os-keychain/v1")` で KEK を作り VMK unwrap。
3. keychain unlock が使えなければ端末 prompt / recovery に fallback。

`kagi unlock-enable-keychain` は一度だけ master passphrase を要求し、device unlock secret
を Apple Keychain に保存して `:unlock/wraps` を追加する。結果は metadata only。

Passkey/WebAuthn PRF は同じ envelope 形に載せる:

```edn
{:method :passkey-prf
 :rp-id "manimani.local"
 :credential-id ...
 :salt ...
 :nonce ...
 :wrapped ...}
```

通常の passkey 秘密鍵を取り出すのではなく、WebAuthn PRF extension output を
`HKDF(PRF, salt, "kagi/unlock/passkey-prf/v1")` で KEK 化する。PRF support は
browser / OS / authenticator 依存なので、OS keychain と passphrase recovery を fallback
として維持する。

## Reveal and clipboard policy

`kagi get` remains available for pipe-based CLI compatibility, but 1Password-class UX should prefer
approval-gated reveal:

- purpose is mandatory for reveal.
- high-value categories escalate through Governor.
- GUI must not show raw `kagi get` output by default.
- `kagi copy <item> --purpose <purpose> [--ttl seconds]` is the approved GUI
  bridge on macOS. It invokes the normal `:item/reveal` path, writes the secret
  to `/usr/bin/pbcopy`, returns metadata only, and clears the clipboard after
  TTL if the copied value has not been replaced.
- Non-interactive callers must set `KAGI_MASTER`; otherwise the CLI fails fast
  instead of blocking on a passphrase prompt.

## Threat model checklist

| Threat | Current control | Remaining work |
|---|---|---|
| `.env` credential leakage | manimani stores refs only | remove legacy `*_PASS` usage |
| identity file theft | SecretStore + Apple Keychain provider | migrate all identities; add Android/Windows providers |
| master passphrase exposure | OS keychain device unlock envelope; passphrase stays recovery | passkey PRF registration UX |
| device loss | device identity + grant/revoke model | GUI grant/revoke and rotate workflow |
| HNDL / quantum harvest | X25519 + ML-KEM-768, Ed25519 + ML-DSA-65 | external audit |
| memory scraping | short-lived CLI processes | zeroization / hardened reveal process |
| sync tampering | hash-chain + hybrid signatures | KotobaStore/sealed-block production sync |
| phishing/autofill | no autofill surface | browser extension hardening not implemented |
