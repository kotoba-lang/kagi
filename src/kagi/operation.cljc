(ns kagi.operation
  "VaultActor — vault の 1 操作 = 1 supervised run(langgraph-clj StateGraph)。
  知能ノード(:advise)は proposal のみ。AccessGovernor(:govern)と phase gate(:decide)を
  必ず通り、**副作用は :effect / :hold の 2 ノードだけ**。`:advise` から `:effect` へ
  Governor を迂回する辺は無い(単一不変条件をグラフ位相で保証)。

  注入境界(swap, not rewrite):
    - Store    (MemStore | KotobaStore)        — `store` 引数
    - Provider (BouncyCastle | kotoba-crypto)  — :crypto opt
    - Advisor  (mock | LLM/異常検知)            — :advisor opt
    - Phase    (0→3)                            — :phase in ctx

  human-in-the-loop = `interrupt-before #{:request-approval}`。承認者は
  `{:approval {:status :approved}}`(または :rejected)で resume する
  (break-glass / 高価値 reveal / 復旧)。"
  (:require [langgraph.graph :as g]
            [langgraph.checkpoint :as cp]
            [kagi.advisor :as advisor]
            [kagi.governor :as governor]
            [kagi.phase :as phase]
            [kagi.crypto :as crypto]
            [kagi.vault :as vault]
            [kagi.store :as store]))

;; ───────── 台帳 fact ─────────

(defn- commit-fact [request context]
  {:t :committed :op (:op request) :actor (:did context)
   :item (:item-id request) :disposition :commit})

(defn- hold-fact [request context verdict]
  {:t :policy-hold :op (:op request) :actor (:did context)
   :item (:item-id request) :disposition :hold
   :basis (mapv :rule (:violations verdict))})

;; ───────── 副作用(:effect ノードからのみ) ─────────

(defn- do-effect
  "op を実際に実行する。ここだけが store を変更し item を復号開示する。"
  [store* crypto* request context proposal]
  (case (:op request)
    :item/create
    (let [{:keys [item-id compartment plaintext]} request
          vmk (:vmk context)
          aad (vault/item-aad item-id)
          {:keys [dek nonce ciphertext]} (crypto/seal-item crypto* plaintext aad)
          kek (crypto/compartment-key crypto* vmk compartment)
          cid (str "cid:" item-id)]
      (store/block-put! store* cid ciphertext)
      (store/put-item! store* #:item{:id item-id :compartment compartment
                                     :cid cid :nonce nonce :version 1
                                     :wrap (crypto/wrap-dek crypto* kek dek)
                                     :created-by (:did context)})
      {:effect :stored :item item-id})

    :item/reveal
    (let [{:keys [item-id]} request
          it  (store/item store* item-id)
          vmk (:vmk context)
          kek (crypto/compartment-key crypto* vmk (:item/compartment it))
          dek (crypto/unwrap-dek crypto* kek (:item/wrap it))
          pt  (crypto/open-item crypto* dek (:item/nonce it)
                                (store/block-get store* (:item/cid it))
                                (vault/item-aad item-id))]
      {:effect :revealed :item item-id :plaintext pt :purpose (:purpose context)})

    ;; share/rotate は PQC KEM を要する(provider 段階導入)。governor/phase が高価値を
    ;; escalate に回すため、ここに来るのは承認済みケース。
    (throw (ex-info "op の副作用は段階導入" {:op (:op request) :proposal proposal}))))

;; ───────── グラフ ─────────

(defn build
  "VaultActor グラフを store に束ねてコンパイル。"
  [store* & [{:keys [advisor crypto checkpointer]
              :or {advisor      (advisor/mock-advisor)
                   crypto       (crypto/bc-provider)
                   checkpointer (cp/mem-checkpointer)}}]]
  (-> (g/state-graph
       {:channels {:request     {:default nil}
                   :context     {:default nil}
                   :proposal    {:default nil}
                   :verdict     {:default nil}
                   :disposition {:default nil}
                   :result      {:default nil}
                   :approval    {:default nil}
                   :audit       {:reducer into :default []}}})
      (g/add-node :intake (fn [s] s))
      (g/add-node :authn
                  (fn [{:keys [context]}]
                    ;; CACAO/hybrid 署名検証(段階導入)。現状は context の identity を信頼。
                    {:context context}))
      (g/add-node :advise
                  (fn [{:keys [request context]}]
                    (let [p (advisor/-advise advisor request context)]
                      {:proposal p :audit [(advisor/trace request p)]})))
      (g/add-node :govern
                  (fn [{:keys [request context proposal]}]
                    {:verdict (governor/check request context proposal store*)}))
      (g/add-node :decide
                  (fn [{:keys [request context verdict]}]
                    (let [base (governor/verdict->disposition verdict)
                          ph   (:phase context phase/default-phase)
                          {:keys [disposition reason]} (phase/gate ph request base)]
                      (case disposition
                        :hold     {:disposition :hold
                                   :audit [(cond-> (hold-fact request context verdict)
                                             reason (assoc :phase-reason reason))]}
                        :escalate {:disposition :escalate
                                   :audit [{:t :approval-requested :op (:op request)
                                            :actor (:did context)}]}
                        :commit   {:disposition :commit}))))
      (g/add-node :request-approval
                  (fn [{:keys [approval]}]
                    ;; interrupt-before で停止 → 承認者が approval を入れて resume
                    {:disposition (if (= :approved (:status approval)) :commit :hold)}))
      (g/add-node :effect
                  (fn [{:keys [request context proposal]}]
                    (let [r (do-effect store* crypto request context proposal)
                          f (commit-fact request context)]
                      (store/append-ledger! store* f)
                      {:result r :audit [f]})))
      (g/add-node :hold
                  (fn [{:keys [request context verdict audit]}]
                    (let [hf (or (last (filter #(#{:policy-hold} (:t %)) audit))
                                 (hold-fact request context verdict))]
                      (store/append-ledger! store* hf)
                      {:result {:effect :held}})))
      (g/set-entry-point :intake)
      (g/add-edge :intake :authn)
      (g/add-edge :authn :advise)
      (g/add-edge :advise :govern)
      (g/add-edge :govern :decide)
      (g/add-conditional-edges :decide
                               (fn [{:keys [disposition]}]
                                 (case disposition
                                   :commit   :effect
                                   :escalate :request-approval
                                   :hold)))
      (g/add-conditional-edges :request-approval
                               (fn [{:keys [disposition]}]
                                 (if (= :commit disposition) :effect :hold)))
      (g/set-finish-point :effect)
      (g/set-finish-point :hold)
      (g/compile-graph {:checkpointer checkpointer
                        :interrupt-before #{:request-approval}})))
