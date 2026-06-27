# kagi-clj — 対量子(PQC)シークレット vault（1Password 代替）

**主権 + 対量子 + governed** な secrets vault。kotoba を SSoT/台帳に、PQC を古典暗号へ
**加法的(hybrid)** に重ね、全ての開示(reveal)/共有(share)/鍵操作を独立 Governor が検閲する。

設計の正は **`90-docs/adr/2606272330-kagi-clj-pqc-vault.md`**（superproject 側）と
本リポの `docs/adr/0001-architecture.md`。

## なぜ

- **データ主権**: ベンダ SaaS ではなく、自分の Ed25519 鍵由来 IPNS graph(`k51…`) が自分の vault。
  CACAO 自己発行（owner hand-off も共有 token も不要、`itonami/cacao.clj` 継承）。
- **対量子(HNDL 対策)**: long-lived secret を「今盗んで後で量子復号」する harvest-now-decrypt-later
  に備え、DEK wrap / 共有を **X25519 + ML-KEM-768**(FIPS 203)、署名を **Ed25519 + ML-DSA-65**(FIPS 204)
  の hybrid に。両方が破られない限り安全。
- **governed**: 全開示/書込/共有を AccessGovernor が検閲、append-only ハッシュ鎖台帳に記録。

## 鍵階層

```text
unlock(passphrase Argon2id / passkey PRF / Shamir recovery)
  → VMK(wrapped 多重保管) → compartment key(HKDF) → per-item DEK → AES-256-GCM 封緘
```
item 平文・鍵はサーバに出ない（client-side E2E、zero-knowledge）。

## レイヤ

| ns | 役割 |
|----|------|
| `kagi.crypto` | ★ hybrid PQC エンベロープ（Provider seam: JVM=JDK24 標準 ML-KEM-768/ML-DSA-65 + BC Argon2id / WASM=kotoba-crypto Rust） |
| `kagi.identity` | Ed25519 did:key + 鍵由来 IPNS + ML-DSA 公開鍵（CACAO 自己発行） |
| `kagi.vault` | item/compartment/grant/version/ledger スキーマ |
| `kagi.store` | `:db-api` seam → `MemStore` ≡ `KotobaStore`（contract test で等価保証） |
| `kagi.governor` | AccessGovernor（RBAC/purpose/JIT-TTL/consent/break-glass） |
| `kagi.phase` | 0→3 段階導入 |
| `kagi.advisor` | risk/anomaly 知能ノード（proposal のみ） |
| `kagi.operation` | langgraph-clj StateGraph（1 op = 1 run） |
| `kagi.sim` | デモドライバ |

## 単一不変条件

> AccessGovernor が拒否する 開示/書込/共有/鍵操作/認証 を kagi は決して行わない。

グラフ位相で保証（`:advise` から副作用ノードへ `:govern`/`:decide` を迂回する辺が無い）。

## 開発

```bash
clojure -M:lint           # clj-kondo（errors fail）
clojure -M:dev:test       # contract tests
clojure -M:dev:run        # デモ
```

> **状態**: JVM provider(`jvm-provider`)は **実 PQC を配線済み** — JDK 24 標準の
> ML-KEM-768 / ML-DSA-65、X25519/Ed25519/AES-256-GCM、BouncyCastle Argon2id。さらに:
> - **hybrid identity**(`kagi.identity`): Ed25519 authority(did:key/IPNS graph) + ML-DSA-65 共同署名。
> - **改竄検知台帳**(`kagi.ledger`): ハッシュ鎖 + entry ごとの hybrid 署名、`verify-chain` で検証。
> - actor が `:signer` 付きで commit/hold を全署名し、`verify-chain` で鎖検証(end-to-end test)。
> - **自己発行 CACAO**(`kagi.cacao`): SIWE/EIP-4361 を Ed25519 did:key で mint、`verify` が
>   CBOR decode + did:key→公開鍵復元 + Ed25519 検証(iss 詐称・改竄・audience 不一致を reject)。
>   actor `:authn` が CACAO を実検証し、失敗を `:hold` に送る。
> - **メンバー登録/共有**: `:authn` が depth-1 self-mint 登録、実 identity 同士の PQC 共有。
>
> 検証: **28 tests / 58 assertions pass**(KEM 往復・署名 tamper reject・PQC 共有・Argon2id・
> 台帳改竄検知・CACAO 詐称/改竄 reject・authn 強制)。CLJS/WASM provider(kotoba-crypto Rust)と
> kotoba-server 実 backend(`KotobaStore` XRPC)・SealedBlockStore 配線は段階導入。
> 秘密鍵は `.kagi/identity.edn`（gitignore）。git に絶対コミットしない。
