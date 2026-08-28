# kagi-clj — 対量子(PQC)シークレット vault（1Password 代替）

`src/kagi/phase.kotoba` is the capability-free typed form of the phase gate.
It preserves the rule that a phase may only add caution and can never relax a
policy disposition. CI compares 192 phase/operation/disposition combinations
on CLJC, restricted Web JavaScript, and typed Wasm. Cryptography, stores,
identity, and effects remain outside this pure gate.

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
| `kagi.crypto` | ★ hybrid PQC エンベロープ（`.cljc`。Provider seam + 可搬な封緘/wrap/share ヘルパ。JVM 実装=JDK24 標準 ML-KEM-768/ML-DSA-65 は `#?(:clj ...)` 内） |
| `kagi.crypto.noble` | 同じ `Provider` のブラウザ実装（`.cljs`、同期、純 JS `@noble/*`） |
| `kagi.identity` | Ed25519 did:key + 鍵由来 IPNS + ML-DSA 公開鍵（CACAO 自己発行） |
| `kagi.vault` | item/compartment/grant/version/ledger スキーマ |
| `kagi.store` | `:db-api` seam → `MemStore` ≡ `KotobaStore`（contract test で等価保証） |
| `kagi.governor` | AccessGovernor（RBAC/purpose/JIT-TTL/consent/break-glass） |
| `kagi.phase` | 0→3 段階導入 |
| `kagi.advisor` | risk/anomaly 知能ノード（proposal のみ） |
| `kagi.operation` | langgraph-clj StateGraph（1 op = 1 run） |
| `kagi.sim` | デモドライバ |
| `kagi.import.onepassword` | kagitaba(1Password 互換 item モデル + 1PUX パーサ)から vault item を組み立てる glue 層 |

## ブラウザで動かす（client-side E2E）

`kagi.crypto` は `.cljc` で、`Provider` プロトコルと provider 越しの封緘/wrap/share
ヘルパは JVM と ClojureScript の両方から見える。ブラウザ側の実装は
**`kagi.crypto.noble`** —— `@noble/*` の純 JS 実装だけで同じ hybrid 構成
（X25519+ML-KEM-768 / Ed25519+ML-DSA-65 / AES-256-GCM / HKDF-SHA256 / Argon2id）を満たす。

- **同期のまま**。Web Crypto は AES-GCM しか要らないのに Promise を全体へ伝播させる
  ので採らない（`kotoba-lang/org-signal` が JVM/CLJS を分けた理由はまさにこれ。
  `@noble/*` は同期なのでその二択が発生しない）。
- **PQC を縮退させない**。ML-KEM-768(FIPS 203) / ML-DSA-65(FIPS 204) は
  `@noble/post-quantum` にある。**Rust/WASM は要らない。**
- **JVM と相互運用する**。JCA は X.509/PKCS#8 の DER 符号化を graph に載せ、noble は
  raw を扱う。KEM combiner はその符号化済みバイト列を transcript にハッシュするので、
  `kagi.crypto.noble/wrap-der` / `unwrap-der` が 6 種の固定長 prefix を付け外しする
  （剥がす時は prefix 一致を検証、合わなければ throw）。

```sh
npm install
npm run test:cljs      # nbb。JVM が封緘した item/share/署名をブラウザ側が処理できるか
clojure -M:gen-vectors # 相互運用ベクタを JVM から再生成
clojure -M:test -n kagi.crypto.noble-reverse-test  # 逆方向（ブラウザ→JVM）
```

相互運用は**両方向**を実ベクタで検証している。片方向だけだと、ブラウザが「自分だけが
読める独自符号化」を書いていても気づけない。

## 暗号文 blob を object store に着地させる（Storj / B2）

`kagi.store/object-sealed-block-store` は `{:get-object :put-object :exists?}` の
4 関数の上に `SealedBlockStore` を張る。この 4 関数は
[`storj.store/store-fns`](https://github.com/kotoba-lang/io-storj) が返す形そのもの。

```clojure
(require '[kagi.store :as store] '[storj.core :as storj] '[storj.store :as storj-store]
         '[sigv4.crypto :as sigv4-crypto])

(def client (storj/client {:bucket "kagi-sealed-blocks"
                           :access-key (System/getenv "STORJ_ACCESS_KEY")
                           :secret-key (System/getenv "STORJ_SECRET_KEY")}
                          {:crypto (sigv4-crypto/crypto) :http my-http}))

(def blocks
  (store/object-sealed-block-store
    (storj-store/store-fns client {:now #(iso-now) :prefix "kagi/"})))

(store/kotoba-store db-api conn blocks)
```

- **kagi は io-storj に依存しない。** 4 関数を受け取るだけなので、両方に依存するのは
  配線するアプリケーション側 —— これは `storj.store` の ns docstring が明示している
  設計意図でもある。テストだけが io-storj を引く。
- **同じ経路が Backblaze B2 に載る。** B2 は S3 互換面を出すので、違うのは
  `storj.gateway` に渡す endpoint だけ(`s3.us-west-004.backblazeb2.com`)。
- **既存キーへの上書きは既定で拒む。** cid は `cid:<item-id>:v<version>` で version 込み
  なので、同じキーに違うバイト列が来るのは bug か攻撃であり、黙って上書きすると
  **まだ grant が指している前の版の暗号文が消える**。同一バイト列の再 PUT(部分失敗
  からのリトライ)は通す。外すには `{:allow-overwrite? true}`。
- **`cid` は content hash ではない。** `SealedBlockStore` の docstring は長く
  「content-addressed」と書いていたが、実際に届く id は `kagi.operation` が作る
  **パス**であって、バイト列を検証できるハッシュではない。検証できないものを
  検証していると謳わない代わりに、上書き拒否で「1 キー = 1 版」を守る。
- **IPFS は別のアダプタ**(`store/ipfs-sealed-block-store`)。同じものには載らない ——
  object store は「呼び出し側が名前を決める」面、IPFS は「内容がアドレスを決める」面で、
  kagi が渡す `cid` はパスなので IPFS に渡す先が無い。したがって IPFS 版は
  **name→CID の可変ポインタ層を注入させる**(隠すと、ポインタをどこに永続化するかという
  本質的な問いが消える)。引き換えに、同一バイト列が同じ CID になるのでリトライの冪等性を
  GET せずに判定でき、`:verify-fn` を渡せば取得したバイト列を検証できる。

検証はネットワークに出ずに行う: `kagi.storj-block-store-test` が
`storj.protocols/IHttp` に S3 を演じる偽 transport を差し、署名・URL 組み立て・
応答解釈は**本物の** `storj.core` にやらせる。アダプタだけを fake で試すと、
io-storj が返す「0-255 の vector」と kagi の AEAD が食う `byte[]` の食い違いが
復号時まで露見しない。

## 単一不変条件

> AccessGovernor が拒否する 開示/書込/共有/鍵操作/認証 を kagi は決して行わない。

グラフ位相で保証（`:advise` から副作用ノードへ `:govern`/`:decide` を迂回する辺が無い）。

## CLI（`op` 相当）

```bash
bin/kagi init                         # 鍵生成 + vault 作成（master passphrase 設定）
printf '%s' "$SECRET" | bin/kagi add gh-token -c work   # secret を stdin から登録
bin/kagi get gh-token                 # 復号して stdout へ（パイプ可）
bin/kagi ls                           # item 一覧（復号しない）
bin/kagi ui [--ttl 45] [--idle 900]   # item / 端末 / unlock を見る窓を 127.0.0.1 に開く
bin/kagi import onepassword <file.1pux> [-c compartment] [--include-archived]
                                       # 1Password の 1PUX export を取り込む（kagitaba 経由）
bin/kagi rotate gh-token              # DEK を回転（再封緘、平文は不変）
bin/kagi log                          # 監査台帳を検証して表示（hybrid 署名 + ハッシュ鎖）
bin/kagi whoami                       # 自分の did:key / IPNS graph
bin/kagi identity-migrate             # identity 秘密鍵を Apple Keychain へ移す
bin/kagi unlock-enable-keychain       # VMK unlock を Apple Keychain に追加
bin/kagi unlock-status                # unlock envelope metadata を表示
bin/kagi unlock-enable-passkey        # one-shot loopback bridgeでPasskey PRFを登録
bin/kagi recovery create --out <dir> --threshold 3 --shares 5
bin/kagi recovery verify <share.edn>...
bin/kagi recovery get <item> <share.edn>...
bin/kagi agent request|approve|invite|ls|grant|ungrant|revoke|serve|log|get
                                      # 人でない principal（下記「人でない principal」）
bin/kagi push                         # 暗号化済み vault snapshot を kotobase.net へ upsert
bin/kagi pull                         # cloud の最新 snapshot を取得（local .bak を先に取る）
bin/kagi sync                         # pull後のremote seq一致時だけpush（競合はfail-closed）
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

## 人でない principal（`kagi agent`、ADR-2608281100）

`kagi get` はプロンプトを出し、`kagi device grant` は人が読み上げた fingerprint を
要求し、`kagi ui` はブラウザを開く。**常駐 agent にはそのどれも無い** —— launchd 下
では Keychain が prompt を出せずに timeout するので、実際には agent は
`~/.gftd/<name>` の mode-600 平文を読んでいた。vault の外、governor の外、台帳の外。

agent principal はその答えで、**「人抜きで vault を開ける」ではない**。

```text
owner:  VMK → compartment KEK → item DEK          （vault 全体）
agent:  自分の KEM 秘密鍵 → grant された item の DEK だけ
```

VMK も compartment 鍵も agent には渡らない。読めるのは owner が
`kagi agent grant` した item だけで、これは既存の `:share/grant` そのものなので:

- **取り消しが本当に効く。** `kagi agent ungrant` は `:share/revoke` ——
  item を再鍵し、残りの受信者へ再封入する。取り消された principal の envelope は
  もう何も復号しない鍵を開ける。`kagi device revoke` が docstring で「これは
  アクセス一覧の変更であって、その端末が既に得た VMK を取り消すものではない」と
  認めざるを得ないのと対照的で、その差は **agent が vault 全体に効く物を最初から
  持っていない**ことから来る。
- **reach が列挙できる。** `kagi agent ls` が principal ごとに開ける item を出す。
- **開示も拒否も、agent 自身の鍵で署名された鎖に残る**
  （`$KAGI_HOME/agents/<id>.ledger.edn`、`kagi agent log <id>` が検証）。
  agent は `vault.edn` を書けない —— 読むだけの principal が読み元を書き換えられる
  なら読むだけではないので、台帳は別ファイルにした。

```bash
# agent 側（vault は要らない。自分の鍵を作って fingerprint を表示する）
bin/kagi agent request --label resident@mac-1 --custody file --out req.edn

# owner 側（fingerprint は必須 — 公開鍵の差し替えを捕まえる唯一の手段）
bin/kagi agent approve req.edn --fingerprint 5QFB-... --compartment ops --ttl-days 30
#   → account_key は一度だけ表示される。この時点ではまだ何も読めない
bin/kagi agent grant <agent-id> fleet-token    # item を 1 件渡す
bin/kagi agent ls                              # principal と、開ける item

# agent 側（プロンプト無し、passphrase 無し、VMK 無し）
KAGI_AGENT_ID=<agent-id> bin/kagi agent get fleet-token --purpose publish

# 取り消し
bin/kagi agent ungrant <agent-id> fleet-token  # 再鍵。ここで実際に閉じる
bin/kagi agent revoke <agent-id>               # token を殺す + 残る grant を列挙
```

principal と invite は **`$KAGI_HOME/agents/registry.edn`**（`vault.edn` の外）。
`kagi push` は snapshot 全体を 1 文字列として上げ last-writer-wins で解決するので、
registry を snapshot に入れると **1 KB を記録するために 9.5 MB を再送**し、しかも
**server が受理した enrollment を owner の次の push が黙って消す**（朝 enroll できた
agent が昼には `:not-registered` になり、どのログにも何も残らない）。分離した結果、
中身の性質も揃っている — snapshot は暗号文、registry は公開メタデータ（公開鍵・
token の**ハッシュ**）で、秘密が無いからこそ server が書いてよい。
`:share/grant` が要る member record は principal から**導出**する（複製しない）。

`--custody file` は `$KAGI_HOME/agents/<id>.key`（mode 600）。Keychain より弱く、
launchd 下で動く唯一の選択肢でもある。どちらを使っているかは principal に記録され
`kagi agent ls` に出る —— 「どれが盗みやすいか」は暗黙より見える方が良い。

## agent が自分で登録する API（`kagi agent serve`）

agentmail.to と同じ 3 コール。**`account_key` は一度しか返らない。**

**経路は必ず tenant を名指す** — `<base> = /v1/t/<tenant did>`。1 台のサーバが複数の
vault を持てるので、どれかを言わない経路は「どう起動したか」で答えが変わってしまう。
`kagi agent serve` はそのまま貼れる `:base-url` を出力する。

```text
POST <base>/agents/challenges  → {challenge_id, algorithm:"sha256-v1", challenge,
                                  difficulty_bits, expires_at}
  ローカルで解く: sha256(challenge ":" nonce) の先頭 N bit が 0
POST <base>/agents             → {agent_id, account_key, not_after, ops, compartments}

GET  <base>/whoami                    （Authorization: Bearer <account_key>）
GET  <base>/items                     grant のある item のメタデータだけ
GET  <base>/items/<id>/sealed         封緘済み素材（下記）
POST <base>/audit                     agent 自身の署名済み台帳を提出する
```

**challenge はサーバ状態を持たない。** `<payload>.<HMAC>` の署名済みトークンで、
`{challenge, difficulty, expiry}` を自分で運ぶ。だから 1 つの URL の裏に複数
インスタンスを置けるし、再起動が飛行中の enrollment を落とさない
（`KAGI_AGENT_CHALLENGE_KEY` を共有すると相互に受理する。未設定ならプロセスごとの
ランダム鍵 = 再起動で失効、TTL 120 秒なので許容）。

代償も書いておく: **解いた challenge は失効まで再提示できる。** in-memory の
`spent` 集合は単一インスタンスでの使い回しを弾くが保証ではない。実際に効いている
上限は別のところ —— enrollment には必ず invite が要り、invite には `uses-left` がある。
PoW は総当たりの速度制限であって、最初から stranger と vault の間に立つものではない。

**PoW は認証ではない。** scope は必ず owner が先に発行した invite
（`kagi agent invite --compartment ops`）から来る。PoW が完璧でも invite 無しの
enrollment は `:invite-missing` で拒否される。puzzle を解いた者に渡して良いのは
puzzle の値段のものだけで、vault は違う。PoW が買うのは「invite の総当たりが
1 回 ~2^20 hash かかる」ことだけ。

**この server は VMK を持たない。** `/sealed` が返すのは *その principal の公開鍵へ
既に封入済みの* grant envelope と item の暗号文で、開くのは SDK（呼び出し側の
プロセス）。だから TLS 終端・リバースプロキシ・この server の heap dump・ログの
どれからも出てくるのは暗号文で、`vault.edn` が既に見せているものと同じ。
強制点は復号ではなく **release** —— envelope を出さなければ平文は無い。

item を渡す判断（`kagi agent grant`）だけは VMK が要るので owner の CLI に残した。
agent が何を読めるかを決めるのは、人にコマンド 1 本のコストを払わせて良い判断。

### vault の無いホストで serve する（公開 URL の前提）

```bash
# owner 側（vault のある機械）
bin/kagi push                                   # 暗号化 snapshot を bucket へ
bin/kagi agent invite --compartment ops         # 招待は bucket 側の registry に入る

# server 側（vault ファイルが 1 つも無いホスト）
bin/kagi agent serve --backend object --did <tenant did> --port 8901
# {:ok? true, :listening "http://…", :store {:label :object, :did "did:key:z6Mk…"}, :bucket "…"}

# agent 側
#   enroll → owner が grant → open-item!  で平文が出る
```

server は **vault ファイルも VMK も持ちません**。bucket から snapshot と registry を読み、
封緘済み素材を release するだけです（復号は SDK 側）。`kagi.agent-docs` が
`{:vault :registry :update-registry! :read-audit :write-audit!}` の seam で、
local ファイルと object store のどちらでも同じサービスコードが動きます。

registry は object store 側でも版付きキーで CAS されます（`kagi/<did>/registry/v<N>.edn`
＋ `HEAD`）。並行 enrollment は後から来た方が自分の書き込みを失うだけで、
相手の registry を消しません。

`kagi agent invite` / `approve` / `ls` / `revoke` / `grant` も `--backend object` を取ります
—— でないと「存在するのに使えない招待」（local registry に入ったが bucket 側の API は
読まない）が作れてしまいます。

### remote agent の監査 — 記録を作るのは client 側

HTTP 経路には **governor 実行が無い**（server は封緘済み素材を release するだけで、
復号は SDK 側）。だから「何を、なぜ開いたか」の記録は **client が署名して作るか、
どこにも無いか**のどちらかになる。SDK は自分の鎖を持ち、owner に返せる:

```clojure
(def c (agent/client {:base-url … :tenant … :account-key …
                      :agent-did (:did principal)
                      :sign-secret (:sign (:secret enrolled))}))   ; ← 監査鍵

(agent/open-item! c kem "fleet-token" :publish)   ; purpose が鎖に載る
(agent/submit-audit! c)                            ; => {:status :accepted :entries 2 :new 2}
```

owner 側:

```bash
bin/kagi agent audit <agent-id>    # 提出された鎖を、registry の公開鍵で検証して表示
bin/kagi agent log   <agent-id>    # local agent が vault の隣に書いた鎖（別物）
```

server は **registry が記録した公開鍵**で検証し、壊れた鎖・短くなった鎖・既に持っている
ものと分岐した鎖を拒否する。agent が書いていても owner 側から見れば append-only。

⚠ 提出は EDN で行う。JSON 往復は fact の keyword 値を文字列に変え、`pr-str` のバイト列が
変わって、改竄されていない鎖が検証に落ちる —— **運ぶものを書き換える transport は
改竄検知ログを運べない**。

### SDK（`kagi.agent-client`、`.cljc`）

```clojure
(require '[kagi.agent-client :as agent])

(def c (agent/client {:base-url "https://vault.example" :tenant "did:key:z6Mk…"}))
(def enrolled (agent/enroll! c {:invite "kagi_inv_…" :label "resident@mac-1"}))
;; => {:agent-id … :account-key "kagi_agt_…" :secret {:kem … :sign …}}

(def c2 (agent/client {:base-url "https://vault.example" :tenant "did:key:z6Mk…"
                       :account-key (:account-key enrolled)}))
(agent/items c2)
(agent/open-item! c2 (:kem (:secret enrolled)) "fleet-token")
;; => {:status :ok :plaintext "…"}   ← 復号はここで起きる
```

crypto は `kagi.crypto/Provider` seam 越しなので JVM(BouncyCastle) と
nbb/ブラウザ(`@noble/*`) で**同じ実装**を通る（両方向の interop ベクタが既にある）。
違うのは transport だけ（`java.net.http` は同期、`fetch` は promise を返す）。
**JVM 経路は suite で実証済み、cljs 経路はこの repo の CI では未実行。**

`kagi.agent/signer` は `kagi.chain-signer` を agent session に繋いだもので、
署名鍵の item を governor 経由で毎回開き、公開鍵と署名だけを返す（seed は返さない）。

## ローカルの窓（`kagi ui`）

1Password の一覧画面にあたるものを、**この端末の 127.0.0.1 にだけ**開く。

```bash
bin/kagi ui               # 既定のブラウザが開く。Ctrl-C か 900 秒無操作で閉じる
bin/kagi ui --ttl 30 --idle 300
```

見えるのは 3 面 —— **Items**（item 一覧。復号しない）/ **Devices**（登録端末と
revoke）/ **Vault**（unlock envelope と did / graph）。1 文書・script なし・
`Content-Security-Policy: default-src 'none'`。

- **絞り込みは GET。** id / compartment / category に部分一致（大文字小文字を問わない）。
  **ciphertext には触らない** —— 一覧を検索することは vault を開く理由にならないので、
  secret の中身にしか一致しない語は 0 件になる。それが正しい答え。
  「0 件」と「item が 1 つも無い」は別の画面として描く。
- **item 名をクリックすると 1 件だけ開く。** ここで初めて復号が起き、
  governor を通り、台帳に purpose `:ui-detail` で残る（Copy の `:ui-copy` とは
  別の語 —— 形を見たことと値を取ったことは別の行為）。**開いても機微値は出ない**:
  `kagi.vault-read/strip-sensitive` が concealed / totp / credit-card / ssh-key の値を
  落とし、画面には「設定済み・伏せてある」とだけ出る（field ごと消すと「未設定」に
  見えてしまうため、field は残す）。値が出る経路は Copy だけ。
- **一覧を描くだけでは何も開かない。** `:detail` は item を名指しされた時にだけ呼ばれる
  （検査あり）。開いた結果は 4 通りを 4 つとも別の画面にする ——
  `:ok`（構造）/ `:raw`（`kagi add` の素の値。構造が無いので値も出さない）/
  `:denied`（governor の拒否）/ `:absent`（そんな item は無い）。

- **平文はブラウザに渡らない。** Copy は governor 経由で復号し、値を
  **この JVM から直接 clipboard** に置く。ページにも loopback socket にも
  平文は出ない。TTL は `kagi copy` と同じ既定 45 秒で、内容が変わっていなければ消える。
- **開けるのはこの端末のブラウザだけ。** 3 つの独立した門: ①socket が 127.0.0.1
  ②`?token=` を 1 度だけ受けて cookie に替え、URL からは消す（HttpOnly /
  SameSite=Strict）③POST は body にも同じ token を要求する（cookie は「この
  ブラウザ」の証明、form token は「このページ」の証明）。拒否は必ず理由の名前を返す
  （`no-session` / `bad-origin` / `bad-form-token`）。
- **revoke は 2 手。** 一覧の Revoke は GET のリンクで、何も変えずに確認を出す。
  実際に変えるのは POST の側だけ。
- **vault を開けるのは CLI 側で 1 度だけ。** server は
  `kagi.ui.actions` の 3 関数だけを渡され、vault も VMK も持たない。

> **なぜ JavaScript が無いか。** ここは vault を開いた session の隣で動くページなので、
> 「このページの script に何ができるか」への一番安い正しい答えは **script が無いこと**。
> 代わりに失うのは mount で、操作のたびに文書を描き直す —— loopback では数ミリ秒。
> ADR-2608231200（superproject）。

## cloud 永続化（iCloud Keychain / 1Password 相当、ADR-2607170500）

vault はディスク上で既に暗号文のみ（ciphertext item + wrap 済み鍵 + 台帳、平文・生 VMK
は一切出ない）なので、その blob をそのまま untrusted なサーバへ送るのは安全 —
kotobase.net は ciphertext しか保持せず、master passphrase / OS-keychain VMK unlock は
端末を離れない。これが iCloud Keychain と同じ信頼モデル（サーバは同期リレーで、
信頼の根ではない）。

```bash
bin/kagi push   # 暗号化 snapshot を cloud へ upsert
bin/kagi pull   # cloud から最新 snapshot を取得して local vault を置換（先に .bak へ退避）
bin/kagi sync   # pull → optimistic seq check → push（途中のremote更新は競合として拒否）
```

### backend は 2 つある（一方は現在 401 で拒否される）

```bash
bin/kagi push --backend object     # S3 互換 object store（Backblaze B2 / Storj）
bin/kagi push --backend kotobase   # kotobase.net の tenant graph（従来）
bin/kagi push                      # auto: object が設定されていればそれ、無ければ kotobase
```

**⚠ `kotobase` backend は 2026-08-28 時点で通らない。** `kotobase-graph-database` が
`KOTOBASE_BISCUIT_AUTH_MODE=required` で動いており、**Biscuit 以外の Authorization を
CACAO の分岐に到達する前に 401 にする**（ADR-2608281200）。この repo が mint する CACAO は
正しい —— gateway 自身のアルゴリズムで SIWE がバイト一致し Ed25519 検証も通る —— ので
kagi 側に直すものは無い。Biscuit を得るには tenant レコードと service account が要り、
この vault はどちらも持っていない。

**`object` backend はそのための第 2 の保管先**で、信頼モデルは同じ（store は ciphertext
しか持たず、unlock secret は端末を離れない）。`kagi.store/object-sealed-block-store` が
取るのと**同じ 4 関数**の上に張ってある。

```
kagi/<did>/catalog/v<n>.edn   members + item メタ + grants + block 目録（小さい）
kagi/<did>/ledger/v<n>.edn    監査台帳（実測 99.2%。これがかさばる）
kagi/<did>/blocks/<sha256>    item 1 個の暗号文（immutable）
                              各 doc に HEAD ポインタ
```

**何がかさばるかは測って初めて分かった。** 最初「暗号文が bulk だろう」と推測して
分割したが、実測は逆だった:

| | bytes | n |
|---|---:|---:|
| **ledger** | **9,502,228** | 1,965 |
| items | 37,637 | 88 |
| blocks | 31,040 | 93 |
| members | 5,382 | 1 |
| grants / meta | 507 | |

governed op ごとに hybrid 署名 entry が付き、ML-DSA-65 の署名は base64 で ~3.3 KB。
**監査する対象より監査記録のほうが 2 桁大きい。** よって catalog は
「誰が何を読んでよいかを決める ~43 KB」だけにし、台帳は別 doc にした。
`/items` `/sealed` を答える server が読むのは **9,576,873 → 46,861 bytes**。

block キーは **cid ではなく `sha256(cid)`**。理由は 2 つあり、どちらも実測:
B2 が `blocks/cid:manimani-…:v1` の PUT に **HTTP 500** を返したこと、そして
**キーが item 名を漏らす**こと（bucket を list できる者に「そういう名前の資格情報が
ある」と教えてしまう。snabshot 1 個の時は漏れていなかった）。

catalog は **push した block の目録を書き留める**。item の cid から導出すると、
rotation で置き換わった旧版が復元されず **93 → 88 に黙って減った**。
4 関数の seam に `list` は無いので、目録は書くしかない。

version 付きキーが並行制御そのもの。object store は 4 関数の seam に CAS を持たないが、
**「既に別のバイト列が入っているキーへの書き込みを拒む」**ことはできる。2 台が同じ
seq から push すると両方 `v<N+1>.edn` を狙い、後から来た方は自分が書いていないバイト列を
見つけて `:sync-conflict` で落ちる —— 相手の vault を消さない。同一バイト列の再 PUT
（部分失敗からのリトライ）は通る。HEAD は last-writer-wins だが、**指しうる版は全部
store に残っている**ので、HEAD の競合に負けても失うのは pull と再 push の手間だけ。

設定は環境変数のみ（この経路は vault も 1Password も自分で引かない — credential は
実行する人が渡す）:

```bash
export KAGI_OBJECT_BUCKET=my-kagi-vault
export KAGI_OBJECT_KEY_ID=...            # or B2_KEY_ID
export KAGI_OBJECT_APP_KEY=...           # or B2_APP_KEY
export KAGI_OBJECT_ENDPOINT=https://s3.us-west-004.backblazeb2.com
export KAGI_OBJECT_REGION=us-west-004    # 任意
export KAGI_OBJECT_PREFIX=kagi/          # 任意
```

この vault の実運用値（2026-08-28 稼働）:

| | |
|---|---|
| bucket | `com-junkawasaki-kagi`（allPrivate、この用途専用。2026-08-28 稼働、restore 検証済み） |
| 鍵の正本 | kagi item **`com-junkawasaki-kagi-b2`**（compartment `gftdcojp`） |
| Keychain ミラー | service `b2:com-junkawasaki-kagi`（launchd 下用） |
| capabilities | `listBuckets,listFiles,readFiles,writeFiles` — **delete を外してある** |

`deleteFiles` を外したのは意図的で、この backend は上書きも削除もせず、
**古い版が残ること自体が HEAD 競合に負けた時の復旧手段**だから。削除できる鍵は
その性質を壊せる。同じ理由で B2 の lifecycle rule も設定していない（1 push ≒ 9.5 MB
で版は増える。保持方針はオーナー判断）。

io-storj は **`:cli` / `:test` alias の extra-dep** であってライブラリの依存ではない。
`kagi.store` / `kagi.sync` は 4 関数を受け取るだけで、どのバケットかを知らない
（配線を持つのは `kagi.object-store` と `bin/kagi` だけ）。

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
> 検証: **238 tests / 874 assertions + 3 browser tests pass**(2026-08-23 実測。KEM 往復・署名 tamper reject・PQC 共有・KDF・
> 台帳改竄検知・CACAO 詐称/改竄 reject・authn 強制)。ブラウザ provider は
> `kagi.crypto.noble`(純 JS `@noble/*`、Rust ではない)、`KotobaStore` は注入式
> `SealedBlockStore` と暗号文E2E contract testを持つ。CLIの既定は local snapshot、
> cloud CLIは暗号化snapshot同期。S3 object store(Storj / B2)は
> `kagi.store/object-sealed-block-store`、IPFS は `kagi.store/ipfs-sealed-block-store`
> (ポインタ層の注入が必須)。
> 秘密鍵は `.kagi/identity.edn`（gitignore）。git に絶対コミットしない。
