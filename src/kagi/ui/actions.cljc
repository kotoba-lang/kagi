(ns kagi.ui.actions
  "The three things the vault window is allowed to do, built over an open
  vault session.

  This is a separate namespace from `kagi.cli` on purpose: it is the whole of
  what a browser can reach, so it is the part that has to be readable in one
  screen and testable against a real vault rather than a description of one
  (`kagi.ui-actions-test` drives these through the real governor graph with a
  memory clipboard).

  `session` is exactly `kagi.vault-read`'s shape — `{:status :open :provider
  :identity :vmk :store}` — so listing and revealing go through that
  namespace's read discipline rather than a second copy of it:

    * listing does not decrypt (`vault-read/items` returns metadata),
    * revealing goes through `kagi.operation`, so the AccessGovernor sees it
      and the hash-chained ledger records it with a purpose.

  Nothing here returns a secret. `copy!` puts the plaintext on the clipboard
  and returns a report; the report does not carry the value, and does not
  carry its length either — the window is rendered from these return values,
  so anything they hold is on a page."
  ;; JVM-only requires, and honestly so: the vault, its governor and its
  ;; unlock envelope all live in the process that holds the JDK's PQC
  ;; primitives. Only `copy-purpose` — the word this writes into the ledger —
  ;; is portable.
  #?(:clj
     (:require [clojure.string :as str]
               [kagi.clipboard :as clipboard]
               [kagi.device :as device]
               [kagi.store :as store]
               [kagi.unlock :as unlock]
               [kagi.vault-read :as vault-read])))

(def copy-purpose
  "What the ledger records for a reveal that came from the window: a human
  clicked Copy on this machine. A script wanting to say something more
  specific has `kagi copy --purpose`, where the flag is required."
  :ui-copy)

#?(:clj
   (defn actions
  "Build the action map `kagi.ui.server/start!` expects.

  * `:session`     — an open `kagi.vault-read` session.
  * `:meta-state`  — atom holding the CURRENT vault meta. Revocation rewrites
                     it, and reading a closed-over copy instead would render a
                     device that was just revoked as still enrolled.
  * `:save!`       — `(fn [meta])`, persists. Injected so a test can watch the
                     write without one happening.
  * `:clipboard`   — a `kagi.clipboard/Clipboard`.
  * `:copy-ttl-sec`— seconds before the clipboard is cleared if unchanged.
  * `:clipboard-copy!` — `(fn [clipboard secret opts])`, defaulting to
                     `kagi.clipboard/copy-secret-with-ttl!`."
  [{:keys [session meta-state save! clipboard copy-ttl-sec clipboard-copy! vault-home]
    :or {copy-ttl-sec 45}}]
  (let [copy-fn (or clipboard-copy! clipboard/copy-secret-with-ttl!)]
    {:snapshot
     (fn []
       {:items (vault-read/items session)
        :clipboard-ttl-sec copy-ttl-sec
        :devices (:devices (device/status @meta-state))
        :vault {:did (:did session)
                :graph (:graph (:identity session))
                :home (vault-read/redact-home (or vault-home (:vault-home session)))
                :unlock (unlock/status @meta-state)}})

     :copy!
     (fn [item-id]
       (cond
         (str/blank? (str item-id))
         {:ok? false :heading "item が指定されていない"}

         ;; Absent and refused are different answers and the window must not
         ;; merge them: one is a typo, the other is the governor saying no.
         (not (store/item (:store session) item-id))
         {:ok? false :heading "そんな item は無い" :detail (str item-id)}

         :else
         (if-let [secret (vault-read/reveal session item-id copy-purpose)]
           (do
             ;; Not blocking: this runs on a request thread inside a process
             ;; that outlives it, so the clearing future survives. `kagi copy`
             ;; blocks because a CLI would exit and kill that thread.
             (copy-fn clipboard secret {:ttl-ms (* copy-ttl-sec 1000)})
             {:ok? true
              :heading (str item-id " を clipboard にコピーした")
              :detail (str copy-ttl-sec " 秒後に、内容が変わっていなければ消える")})
           {:ok? false
            :heading "reveal を governor が拒否した"
            :detail (str item-id)})))

     :revoke!
     (fn [device-id]
       (if (str/blank? (str device-id))
         {:ok? false :heading "device-id が無い"}
         (let [next-meta (device/revoke-device @meta-state device-id)]
           (save! next-meta)
           (reset! meta-state next-meta)
           {:ok? true
            :heading (str device-id " を revoke した")
            :detail (str "これはアクセス一覧の変更であって、その端末が既に得た VMK の"
                         "取り消しではない。紛失端末は vault 侵害として扱い、"
                         "secret 自体を rotate すること")})))})))
