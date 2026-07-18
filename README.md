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
| `kagi.crypto` | ★ hybrid PQC エンベロープ（Provider seam: JVM=JDK24 標準 ML-KEM-768/ML-DSA-65 + JDK-only KDF / WASM=host crypto adapter） |
| `kagi.identity` | Ed25519 did:key + 鍵由来 IPNS + ML-DSA 公開鍵（CACAO 自己発行） |
| `kagi.vault` | item/compartment/grant/version/ledger スキーマ |
| `kagi.store` | `:db-api` seam → `MemStore` ≡ `KotobaStore`（contract test で等価保証） |
| `kagi.governor` | AccessGovernor（RBAC/purpose/JIT-TTL/consent/break-glass） |
| `kagi.phase` | 0→3 段階導入 |
| `kagi.advisor` | risk/anomaly 知能ノード（proposal のみ） |
| `kagi.operation` | langgraph-clj StateGraph（1 op = 1 run） |
| `kagi.sim` | デモドライバ |
| `kagi.import.onepassword` | kagitaba(1Password 互換 item モデル + 1PUX パーサ)から vault item を組み立てる glue 層 |

## 単一不変条件

> AccessGovernor が拒否する 開示/書込/共有/鍵操作/認証 を kagi は決して行わない。

グラフ位相で保証（`:advise` から副作用ノードへ `:govern`/`:decide` を迂回する辺が無い）。

## CLI（`op` 相当）

```bash
bin/kagi init                         # 鍵生成 + vault 作成（master passphrase 設定）
printf '%s' "$SECRET" | bin/kagi add gh-token -c work   # secret を stdin から登録
bin/kagi get gh-token                 # 復号して stdout へ（パイプ可）
bin/kagi ls                           # item 一覧（復号しない）
bin/kagi import onepassword <file.1pux> [-c compartment] [--include-archived]
                                       # 1Password の 1PUX export を取り込む（kagitaba 経由）
bin/kagi rotate gh-token              # DEK を回転（再封緘、平文は不変）
bin/kagi log                          # 監査台帳を検証して表示（hybrid 署名 + ハッシュ鎖）
bin/kagi whoami                       # 自分の did:key / IPNS graph
bin/kagi identity-migrate             # identity 秘密鍵を Apple Keychain へ移す
bin/kagi unlock-enable-keychain       # VMK unlock を Apple Keychain に追加
bin/kagi unlock-status                # unlock envelope metadata を表示
bin/kagi push                         # 暗号化済み vault snapshot を kotobase.net へ upsert
bin/kagi pull                         # cloud の最新 snapshot を取得（local .bak を先に取る）
bin/kagi sync                         # pull-if-newer してから push（last-writer-wins）
```

- `bin/kagi` は `clojure -M:dev:cli` のラッパ（PQC は JDK24 標準 provider を使うため bb 不可）。
- master passphrase は環境変数 **`KAGI_MASTER`** か端末プロンプト。`unlock-enable-keychain`
  後は device-local OS keychain unlock を先に試し、passphrase は recovery として残す。
- 保存先は **`$KAGI_HOME`（既定 `~/.kagi`、repo 外）**（ADR-2607170500、2026-07-17）:
  - `identity.edn` — Ed25519/ML-DSA 鍵 + KEM 受信鍵
  - `vault.edn` — **暗号文 item + wrap 済み鍵 + 台帳のみ**（平文・素の VMK は出ない。
    unlock = passphrase→Argon2id(256MiB)→KEK→VMK 復号）
  - `init` は home に既存 vault があれば拒否する（再init による上書き事故 — 2026-07-16
    に共有 checkout の `./.kagi/` が並行セッションの再init で失われ、fleet 署名鍵を
    ローテーションする羽目になった実例、ADR-2607170500 — の再発防止）。旧 `./.kagi/`
    （repo-local）しか無い環境では初回アクセス時に自動で home へ移行する。
- `op` 対応: `op item get` → `kagi get` / `op item create` → `kagi add` / `op item list` → `kagi ls`。

## cloud 永続化（iCloud Keychain / 1Password 相当、ADR-2607170500）

vault はディスク上で既に暗号文のみ（ciphertext item + wrap 済み鍵 + 台帳、平文・生 VMK
は一切出ない）なので、その blob をそのまま untrusted なサーバへ送るのは安全 —
kotobase.net は ciphertext しか保持せず、master passphrase / OS-keychain VMK unlock は
端末を離れない。これが iCloud Keychain と同じ信頼モデル（サーバは同期リレーで、
信頼の根ではない）。

```bash
bin/kagi push   # 自分の graph kotobase/db/<did>/kagi-vault へ暗号化 snapshot を upsert
bin/kagi pull   # cloud から最新 snapshot を取得して local vault を置換（先に .bak へ退避）
bin/kagi sync   # pull-if-newer → push（:kagi.vault/seq で last-writer-wins）
```

- 認可は depth-1 の自己発行 CACAO（actor が自分の DID を graph に持つので、
  handed token も coordination-server auth-key も不要）。
- multi-device 同時編集の merge は非対応（1Password 同様、実用上は稀という判断。
  follow-up として記録済み、item 粒度の sync は現状 vault 単位の follow-up）。
- 新デバイスは `bin/kagi pull` だけで vault を復元できる（+ master passphrase /
  device unlock）。

### identity key custody

新規 vault で identity 秘密鍵を Apple Keychain に置く:

```bash
KAGI_IDENTITY_STORE=keychain bin/kagi init
```

既存 `.kagi/identity.edn` から秘密鍵部分を Apple Keychain に移す:

```bash
bin/kagi identity-migrate
```

移行後の `identity.edn` は公開鍵束と `keychain://...` ref だけを持つ。secret 値や秘密鍵は
stdout / log / manimani GUI に出さない。

### device unlock custody

master passphrase を端末に保存しない。代わりに、kagi はランダムな device unlock secret を
Apple Keychain に保存し、その secret から HKDF した KEK で VMK を追加 wrap する。

```bash
bin/kagi unlock-enable-keychain
bin/kagi unlock-status
```

`unlock-enable-keychain` は一度だけ master passphrase で vault を開き、`.kagi/vault.edn`
の `:unlock/wraps` に OS-keychain envelope を追加する。以後の `bin/kagi copy/get/add/...`
は `KAGI_MASTER` が無い場合、keychain unlock を試してから passphrase prompt に fallback する。

Passkey / WebAuthn PRF は同じ envelope 形式で追加予定:

```edn
{:method :passkey-prf
 :rp-id "manimani.local"
 :credential-id "..."
 :salt #bytes "..."
 :nonce #bytes "..."
 :wrapped #bytes "..."}
```

通常の passkey 署名鍵を取り出すのではなく、WebAuthn PRF output を HKDF して VMK unwrap
KEK にする。PRF 非対応環境では OS keychain unlock と passphrase recovery を使う。

## 開発

```bash
clojure -M:lint           # clj-kondo（errors fail）
clojure -M:test           # contract tests
clojure -M:dev:run        # デモ（actor 直叩き）
clojure -M:dev:cli <cmd>  # CLI（bin/kagi と同じ）
```

> **状態**: JVM provider(`jvm-provider`)は **実 PQC を配線済み** — JDK 24 標準の
> ML-KEM-768 / ML-DSA-65、X25519/Ed25519/AES-256-GCM、JDK-only KDF。さらに:
> - **hybrid identity**(`kagi.identity`): Ed25519 authority(did:key/IPNS graph) + ML-DSA-65 共同署名。
> - **改竄検知台帳**(`kagi.ledger`): ハッシュ鎖 + entry ごとの hybrid 署名、`verify-chain` で検証。
> - actor が `:signer` 付きで commit/hold を全署名し、`verify-chain` で鎖検証(end-to-end test)。
> - **自己発行 CACAO**(`kagi.cacao`): SIWE/EIP-4361 を Ed25519 did:key で mint、`verify` が
>   CBOR decode + did:key→公開鍵復元 + Ed25519 検証(iss 詐称・改竄・audience 不一致を reject)。
>   actor `:authn` が CACAO を実検証し、失敗を `:hold` に送る。
> - **メンバー登録/共有**: `:authn` が depth-1 self-mint 登録、実 identity 同士の PQC 共有。
>
> 検証: **38 tests / 94 assertions pass**(KEM 往復・署名 tamper reject・PQC 共有・KDF・
> 台帳改竄検知・CACAO 詐称/改竄 reject・authn 強制)。CLJS/WASM provider(kotoba-crypto Rust)と
> kotoba-server 実 backend(`KotobaStore` XRPC)・SealedBlockStore 配線は段階導入。
> 秘密鍵は `.kagi/identity.edn`（gitignore）。git に絶対コミットしない。
