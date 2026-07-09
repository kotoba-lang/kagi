(ns kagi.store
  "SSoT 注入境界。コアは backend へ `:db-api` map `{:q :transact! :db :pull :entid}`
  越しにのみ喋る(直呼び禁止)。`MemStore`(in-mem, test) ≡ `KotobaStore`(langchain
  kotoba-db XRPC, CACAO 自己発行) を contract test で等価保証。

  暗号文 blob 自体は kotoba `SealedBlockStore`(B2/IPFS cold)に置き、ここは CID/メタ/
  grant/台帳のみ扱う。"
  (:require [kagi.vault :as vault]))

(defprotocol Store
  (member [s did])
  (put-member! [s member-rec])      ; depth-1 self-mint: actor が自分の公開鍵束を登録
  (item [s id])
  (items-in [s compartment])
  (grants-of [s item-id])
  (ledger [s])
  ;; 副作用ゲート(operation の副作用ノードからのみ呼ぶ)
  (put-item! [s item-rec])          ; :item/create | :item/update | :item/rotate
  (put-grant! [s grant-rec])        ; :share/grant
  (revoke-grant! [s grant-id])      ; :share/revoke
  ;; 暗号文 blob(SealedBlockStore 抽象)
  (block-get [s cid])
  (block-put! [s cid bytes])
  ;; 監査台帳(append-only、ハッシュ鎖)
  (append-ledger! [s fact])
  ;; build-fn: (fn [ledger] entry) -- kagi.ledger/make-entry と同じ形。read
  ;; ledger snapshot -> build entry -> append を一つの原子操作にする。呼び手
  ;; (kagi.operation の :effect/:hold ノード)が (ledger s) を読んでから
  ;; make-entry で :ledger/seq/:ledger/prev-hash/:ledger/hash を計算し、別途
  ;; append-ledger! する2段階だと、2つの並行呼び出しが同じ snapshot から同じ
  ;; seq/prev-hash を計算してしまい、どちらも改竄していないのに verify-chain
  ;; が hash 鎖破損として検知してしまう(実測: MemStore で2並行呼び出しを再現
  ;; したところ両方 :ledger/seq 0 になり verify-chain が :broken-at 1 を返した)。
  (append-chained-ledger! [s build-fn]))

;; ───────── MemStore(依存ゼロ、.cljc 可搬) ─────────

(defrecord MemStore [a]
  Store
  (member [_ did] (get-in @a [:members did]))
  (put-member! [s rec] (swap! a assoc-in [:members (:member/did rec)] rec) s)
  (item [_ id] (get-in @a [:items id]))
  (items-in [_ c] (filterv #(= c (:item/compartment %)) (vals (:items @a))))
  (grants-of [_ item-id] (filterv #(= item-id (:grant/item %)) (vals (:grants @a))))
  (ledger [_] (:ledger @a))
  (put-item! [s rec] (swap! a assoc-in [:items (:item/id rec)] rec) s)
  (put-grant! [s rec] (swap! a assoc-in [:grants (:grant/id rec)] rec) s)
  (revoke-grant! [s gid] (swap! a assoc-in [:grants gid :grant/revoked] true) s)
  (block-get [_ cid] (get-in @a [:blocks cid]))
  (block-put! [s cid bytes] (swap! a assoc-in [:blocks cid] bytes) s)
  ;; entry は kagi.ledger/make-entry が seq/prev-hash/hash/sig を付けた完成形を渡す。
  ;; store は append-only の保管のみ担う(改竄検知のロジックは ledger ns)。
  (append-ledger! [_ entry] (swap! a update :ledger (fnil conj []) entry) entry)
  ;; swap! の再試行セマンティクスで read+build+append を原子化する: 競合して
  ;; f が複数回呼ばれても、実際に CAS が成功した最後の呼び出しは常に「その時点の
  ;; 最新 ledger」から entry を組み立てるので、2並行呼び出しが同じ seq/prev-hash
  ;; を計算することは構造的に起こらない。
  (append-chained-ledger! [_ build-fn]
    (let [captured (volatile! nil)]
      (swap! a (fn [state]
                 (let [entry (build-fn (:ledger state))]
                   (vreset! captured entry)
                   (update state :ledger (fnil conj []) entry))))
      @captured)))

(defn mem-store
  ([] (mem-store {}))
  ([seed] (->MemStore (atom (merge {:members {} :items {} :grants {}
                                    :blocks {} :ledger []}
                                   seed)))))

;; ───────── KotobaStore(:db-api 越し) ─────────
;; backend は `langchain.kotoba-db/kotoba-api`(kotoba-server XRPC) または
;; `langchain.db/api`(in-process Datomic)。conn は CACAO 自己発行(kagi.identity)。
;; schema は `kagi.vault/schema`。ここは shape のみ示す(配線は段階導入)。

(defrecord KotobaStore [db-api conn]
  Store
  (member [_ did] ((:pull db-api) conn '[*] [:member/did did]))
  (put-member! [s rec] ((:transact! db-api) conn [rec]) s)
  (item [_ id] ((:pull db-api) conn '[*] [:item/id id]))
  (items-in [_ c]
    ((:q db-api) '[:find [(pull ?e [*]) ...] :in $ ?c
                   :where [?e :item/compartment ?c]] conn c))
  (grants-of [_ item-id]
    ((:q db-api) '[:find [(pull ?e [*]) ...] :in $ ?i
                   :where [?e :grant/item ?i]] conn item-id))
  (ledger [_]
    ((:q db-api) '[:find [(pull ?e [*]) ...] :where [?e :ledger/seq _]] conn))
  (put-item! [s rec] ((:transact! db-api) conn [rec]) s)
  (put-grant! [s rec] ((:transact! db-api) conn [rec]) s)
  (revoke-grant! [s gid] ((:transact! db-api) conn [{:grant/id gid :grant/revoked true}]) s)
  (block-get [_ _cid] (throw (ex-info "SealedBlockStore 配線は段階導入" {})))
  (block-put! [_ _cid _bytes] (throw (ex-info "SealedBlockStore 配線は段階導入" {})))
  (append-ledger! [_ fact] ((:transact! db-api) conn [fact]) fact)
  ;; best-effort: the abstract :db-api transact! offers no compare-and-swap
  ;; primitive to build this atomically the way MemStore's swap! does, so a
  ;; genuine race between two KotobaStore-backed callers can still corrupt
  ;; the hash chain (same residual limitation already noted elsewhere for
  ;; langchain.db/transact!'s non-atomicity). Closes the race for the
  ;; default, always-available MemStore backend; a real fix here would need
  ;; either a backend-native optimistic-concurrency primitive or an
  ;; application-level serialization point in front of KotobaStore.
  (append-chained-ledger! [s build-fn]
    (let [entry (build-fn (ledger s))]
      ((:transact! db-api) conn [entry])
      entry)))

(defn kotoba-store [db-api conn] (->KotobaStore db-api conn))

;; schema を re-export(配線側が参照)
(def schema vault/schema)
