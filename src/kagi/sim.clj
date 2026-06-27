(ns kagi.sim
  "デモドライバ。1 つの VaultActor に複数 op を通し、Governor verdict と台帳を見せる。
  実行: clojure -M:dev:run"
  (:require [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.crypto :as crypto]))

(defn- run-op [actor request context]
  (:state (g/run* actor {:request request :context context}
                  {:thread-id (str (:op request) "-" (:item-id request))})))

(defn -main [& _]
  (let [st     (store/mem-store {:members {"did:key:zOwner" #:member{:did "did:key:zOwner" :role :owner}}})
        crypto (crypto/bc-provider)
        actor  (op/build st {:crypto crypto})
        owner  {:did "did:key:zOwner" :role :owner :phase 1
                :vmk (crypto/rand-bytes crypto 32) :purpose :daily-use}]
    (println "── create(owner, phase 1) ──")
    (let [r (run-op actor {:op :item/create :item-id "gh-token"
                           :compartment "work" :plaintext (.getBytes "ghp_demo_secret" "UTF-8")}
                    owner)]
      (println "  result:" (:result r)))
    (println "── reveal(owner, purpose=daily-use) ──")
    (let [r (run-op actor {:op :item/reveal :item-id "gh-token"} owner)]
      (println "  revealed:" (when-let [pt (get-in r [:result :plaintext])]
                               (String. ^bytes pt "UTF-8"))))
    (println "── reveal(viewer, NO grant) → HOLD ──")
    (let [r (run-op actor {:op :item/reveal :item-id "gh-token"}
                    {:did "did:key:zViewer" :role :viewer :phase 1 :purpose :audit})]
      (println "  disposition:" (:disposition r) "result:" (:result r)))
    (println "── reveal(owner, NO purpose) → HOLD ──")
    (let [r (run-op actor {:op :item/reveal :item-id "gh-token"}
                    {:did "did:key:zOwner" :role :owner :phase 1})]
      (println "  disposition:" (:disposition r)))
    (println "── 監査台帳 ──")
    (doseq [f (store/ledger st)]
      (println "  " (select-keys f [:ledger/seq :t :op :disposition :basis])))))
