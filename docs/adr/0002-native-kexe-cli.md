# ADR — kagi CLI の kexe 化 (amu native compiler 前提)

- **Status**: Accepted (owner direction 2026-09-13, "bin/kagi を kotoba, amu native compiler で動くように天井突破" / "kexe 化を前提に")
- **Date**: 2026-09-13
- **Supersedes**: 「bin/kagi は JVM (`kbb -M:dev:cli`) を exec する」前提 — kbb cutover 4900d4a で書き換えられたが、kagi は JVM 専用機能 (`java.time.Instant`, JCA/BouncyCastle Argon2id, `java.nio.file`) に依存し kbb/sci で動かなかった (実測: `Unable to resolve classname: java.time.Instant`)。kexe 化が正解。

## Context

bin/kagi は 3 世代を経た:

1. **JVM Clojure** (`clojure -M:dev:cli`) — 実装の完全性はあるが JVM が要る (Q9 の逆向き)。
2. **kbb/sci** (`kbb -M:dev:cli` を exec, 2026-09-11) — JVM-free のはずが、kagi の crypto/persist/cacao が java.* に深く依存しており sci 上で ns 解決が落ちる (実測)。
3. **amu native kexe** (本 ADR) — decision core を `.kotoba` guest に落とし、host 境界を capability (wire 3/7/20/33/35) に分離、`amu compile --target x86_64-macos` + `extract-native` で `bin/kagi` を kexe exec shim に差し替える。

## Decision

### 1. 分離: decision core (guest) / host adapter (capability)

| 面 | 載せるもの | 形 |
|---|---|---|
| **guest (.kotoba)** | phase gate / governor check / cacao verify (SIWE 再構成 + Ed25519 verify) / vault schema decision | 純粋、effect row は derive される、DefCID が identity |
| **host (kbb host / kexe loader)** | crypto primitive (wire 3 hash / 署名), clock (wire 7), vault file I/O (wire 35), keychain (wire 20 grant-index), env (wire 33) | provider 実装。crypto は noble provider (`@noble/*` 純 JS, Argon2id 含む) — kbb 実測緑済み |

**正本の分離原則** (ADR-portable-effect-host-profile): 純粋な admission/state/deterministic 判定は guest、物理 I/O / credential / metering は host。guest に大きい値を載せない — string 65,536 上限は native 経路では per-run budget (`KEXE_STRING_POOL`, amu 2a3d4333) で持ち上げられるが、**kagi の guest は digest/verify のような小さい確定値のみ扱う (Digest first)** ので上限は本質的でない。

### 2. crypto provider は noble (JVM ではない)

- `kagi.crypto/default-provider` (:cljs = noble, :clj = jvm-provider) — kagi main 028287a で着地済み。
- noble provider 実測: hybrid KEM (X25519+ML-KEM-768, DER wrap/unwrap で JVM と transcript 互換) / hybrid 署名 (Ed25519+ML-DSA-65) / AES-GCM / HKDF / **実 Argon2id** (`@noble/hashes/argon2`)。kbb 上 noble-interop-test 9/13 assert 緑、digest 3/3、wrap→unwrap round-trip 緑。
- kexe の host 側 crypto は noble を Node から使う (kbb host) または guest 純 cljc (`ed25519.sign` RFC 8032 — cacao verify で実測済み byte-exact) のどちらか。Argon2id は host 側 (wire 経由) に置く。

### 3. ビルドと実行の形

```
amu compile <decision core>.kotoba --target x86_64-macos --jvm-free \
  --policy kagi-policy.edn --output kagi-core.kexe
amu extract-native kagi-core.kexe --symbol main --output kagi-native.bin
bin/kagi → exec kexe shim (capability grant + wire providers 同梱)
```

- `bin/kagi` は shims に差し替える (JVM exec は廃止、kbb/sci exec も廃止)。
- capability は package 時に bake (`--string-pool`, grant index, scopes) — caller が環境変数で持ち上げられない fail-closed 形 (amu 2a3d4333 の規律)。

### 4. 段階 (実測済みの状態を明記)

| 段 | 内容 | 状態 (2026-09-13) |
|---|---|---|
| S1 | crypto provider seam (default-provider) + host 境界 fn (Instant/UUID) | **着地済み** kagi main `028287a` |
| S2 | cacao.cljk java.* 撤去 (cacao-host 経由) — graph-cid byte-exact 突合 ✓, mint→decode 形状 ✓, verify round-trip は ed25519.core :cljs branch の host 依存 (did-key-from-pub b58 短絡) で fail → cacao-host 側で did 生成完結させる | worktree 未 commit (`agent/kagi-native-ceiling`) |
| S3 | decision core (.kotoba): phase.kotoba 済 / governor check / cacao verify guest 化 | 未着手 |
| S4 | kexe 化 + `bin/kagi` shim 差し替え + capability bake | 未着手 |
| S5 | hyakka resident pipeline 復旧 (publish-kotobase FAILED → kagi get exit 0) | 未着手 (S4 後) |

## Consequences

- **JVM 依存の削除**: kagi CLI は JVM 無しで動く。Q9 の「JVM は最後の手段」に整合する唯一の形。
- **PQC は保持**: hybrid 構成は変えない (Argon2id を含む)。noble が `@noble/post-quantum` で ML-KEM-768/ML-DSA-65 を供給する。
- **DefCID が identity**: decision core の変更は definition CID で追跡され、package lock に乗る。
- **keychain は grant-index**: `kbb.proc` (wire 20) の policy literal に `security add/find-generic-password` を登録し総当たり禁止の床と整合 (攻撃面は「index 0,1 のみ」)。
- **string 上限**: native 経路は per-run budget で緩むが、kagi guest は小さい値しか扱わない設計 (Digest first) — 上限は実務上非本質。
- **CI**: phase gate 192 combination の 3-runtime 突合 (README 既存) は guest 形でも維持 (amu check + wasm run)。

## Verification (予定)

- `amu check --jvm-free` / `amu compile --target x86_64-macos --jvm-free` 全 guest 緑。
- `bin/kagi get <name>` が `~/.kagi` 実 vault で exit 0 (実測対象あり)。
- kexe と既存 JVM CLI の出力 byte 比較 (echo/cat 先例 — amu 2a3d4333 の byte-identical 規律)。
- hyakka resident: publish-kotobase 段 FAILED 解消を log で確認。
