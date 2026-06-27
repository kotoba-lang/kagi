(ns kagi.governor
  "AccessGovernor — 知能ノードから独立した検閲器。proposal を受け取り verdict を返す。
  knowledge ノード(advisor)は本検査に一切の可視性を持たない。

  hard violation(即 hold): RBAC / purpose / 最小開示 / consent。
  soft escalation(人間承認へ): 低 confidence / 高価値(high-value) / 異常(anomaly)。

  単一不変条件: ここが ok? でない開示/書込/共有/鍵操作を operation は決して副作用に回さない。"
  (:require [kagi.store :as store]))

(def permissions
  "role → 許可される op。"
  {:owner  #{:item/create :item/update :item/rotate :item/reveal :item/list
             :share/grant :share/revoke}
   :member #{:item/reveal :item/list :item/update}
   :viewer #{:item/reveal :item/list}})

;; ───────── hard checks ─────────

(defn- rbac-violations [{:keys [op]} {:keys [role]}]
  (cond-> []
    (not (contains? (get permissions role #{}) op))
    (conj {:rule :rbac :detail (str role " は " op " の権限を持たない")})))

(defn- granted? [st item-id did]
  (some (fn [g] (and (= did (:grant/recipient g))
                     (not (:grant/revoked g))))
        (store/grants-of st item-id)))

(defn- access-violations [{:keys [op item-id]} {:keys [role did]} st]
  (cond-> []
    (and item-id (#{:item/reveal :item/update} op) (not= role :owner)
         (not (granted? st item-id did)))
    (conj {:rule :rbac-subject :detail (str did " は item " item-id " への grant を持たない")})))

(defn- purpose-violations [{:keys [op]} {:keys [purpose]}]
  (cond-> []
    (and (= op :item/reveal) (nil? purpose))
    (conj {:rule :purpose :detail "reveal には用途(purpose)宣言が必要"})))

(defn- consent-violations [{:keys [op]} {:keys [consent?]}]
  (cond-> []
    (and (#{:share/grant} op) (not consent?))
    (conj {:rule :consent :detail "共有には対象者 consent が必要"})))

;; ───────── 検査本体 ─────────

(def ^:const confidence-floor 0.6)

(def high-value
  "高価値カテゴリ: reveal/rotate に人間承認を要求。"
  #{:recovery-code :root-credential :signing-key})

(defn check
  "→ {:ok? :violations :hard? :escalate? :high-value? :confidence}"
  [request context proposal st]
  (let [hard (into [] (concat (rbac-violations request context)
                              (access-violations request context st)
                              (purpose-violations request context)
                              (consent-violations request context)))
        conf (:confidence proposal 1.0)
        low? (< conf confidence-floor)
        hv?  (boolean (some high-value [(:category proposal) (:category request)]))
        anom? (boolean (:anomaly? proposal))
        hard? (boolean (seq hard))]
    {:ok?         (and (not hard?) (not low?) (not hv?) (not anom?))
     :violations  hard
     :confidence  conf
     :hard?       hard?
     :high-value? hv?
     :escalate?   (and (not hard?) (or low? hv? anom?))}))

(defn verdict->disposition [{:keys [hard? escalate?]}]
  (cond hard? :hold escalate? :escalate :else :commit))
