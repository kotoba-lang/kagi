(ns kagi.ui
  "The local vault window: one document, no script, on jp-go-dds.

  ## What this is for

  `bin/kagi` covers everything the vault does, and a list of items is the one
  thing a terminal is genuinely worse at than a window. `kagi.vault-read` says
  so in its own docstring — enumerating your own items is what a password
  manager's list screen *is*, and it stays safe because listing does not
  decrypt. This renders that screen, plus the two other things you cannot see
  at a glance: which devices hold this vault, and how it unlocks.

  ## Why there is no JavaScript

  Every other single-page app in this workspace ships a ClojureScript bundle
  (ADR-2608080100). This one ships none, and that is the point of it: the
  document is served to a browser that is holding a live vault session, so the
  cheapest correct answer to \"what could a script on this page do\" is that
  the page has no script and `Content-Security-Policy: default-src 'none'`
  says so. A reviewer reads the HTML and has read the client.

  What that costs is the mount: an action posts a form and the document is
  rendered again. On a loopback socket that is a few milliseconds, and the
  invariants the SPA rule protects are kept — one document, one shell, one
  stylesheet, and a nav generated from `views` so a view cannot exist without
  being reachable.

  Routing is the browser's: every view is in the document and `:target`
  chooses which one shows. `body:not(:has(…:target))` is how a stylesheet says
  \"nothing is addressed\", which is the fresh-open and the typo'd-fragment
  case at once — the same rule `fragment->view` states for the routers that do
  have a runtime.

  ## What must never appear here

  A decrypted secret. Copying goes vault -> JVM -> clipboard without crossing
  the socket, so this namespace only ever receives metadata, and
  `kagi.ui-test` asserts a plaintext handed to the renderer cannot come back
  out of it."
  (:require [clojure.string :as str]
            [jp-go-dds.core :as dds]
            [jp-go-dds.page :as dds-page]
            [jp-go-dds.tokens :as dds-tokens]))

(def views
  "Every view, in nav order. The first is the default — the one a fresh open
  and an unknown fragment both land on. The nav, the routing CSS and the
  redirect targets are all generated from this, so a view that is not here
  does not exist and a view that is here cannot be unreachable."
  [{:id :items    :fragment "#items"    :label "Items"
    :description "この vault の item。ここに平文は出ない。"}
   {:id :devices  :fragment "#devices"  :label "Devices"
    :description "この vault を開ける端末。"}
   {:id :vault    :fragment "#vault"    :label "Vault"
    :description "unlock の方法と、この端末の identity。"}])

(def default-view (first views))

(defn view-by-id [id] (first (filter #(= id (:id %)) views)))

(defn fragment->view
  "Resolve a fragment to a view. Unknown, empty and nil all land on the
  default: an address bar is user input, and a typo must not blank the app.
  The stylesheet states the same rule for the browser; this states it for the
  server, which needs it to aim a redirect after a POST."
  [fragment]
  (let [f (or fragment "")]
    (or (first (filter #(= (:fragment %) f) views))
        (first (filter #(= (str "#" (name (:id %))) f) views))
        default-view)))

;; ───────── chrome ─────────

(defn nav
  "The view switcher. `dds/button` with `:href` renders an anchor, so these are
  real links — copyable, middle-clickable — while looking like the design
  system's own controls. Which one reads as current is decided in CSS
  (`nav-css`), because a document with no script cannot know."
  []
  (into [:nav {:class "dds-ext-row kagi-nav" :aria-label "Views"}]
        (for [{:keys [fragment label]} views]
          (dds/button label {:type :text :size "sm" :href fragment}))))

(def ^:private routing-css
  "Fragment routing, generated from `views`.

  `:has()` is doing the load-bearing work: `body:not(:has(.kagi-view:target))`
  is the only way a stylesheet can say \"no view is addressed\", which is both
  the fresh open and the mistyped fragment. Baseline since 2023; this document
  is opened by `kagi ui` in the operator's own browser, not shipped to the
  public web."
  (str ".kagi-view{display:none}\n"
       ".kagi-view:target{display:block}\n"
       "body:not(:has(.kagi-view:target)) #" (name (:id default-view)) "{display:block}\n"
       ;; Current-view styling, same source of truth as the nav itself.
       (str/join "\n"
                 (for [{:keys [id fragment]} views]
                   (str "body:has(#" (name id) ":target) .kagi-nav a[href=\"" fragment "\"],\n"
                        "body:not(:has(.kagi-view:target)) .kagi-nav "
                        "a[href=\"" (:fragment default-view) "\"]"
                        "{background:var(--hig-color-fill-tertiary);font-weight:700}")))
       "\n"))

(def app-css
  "`skin-css` first — that is `bridge-css` + `a11y-css`, the two things
  jp-go-dds says an app should actually add, and what makes the `--hig-*`
  tokens below resolve on top of DADS primitives. Nothing here invents a
  colour."
  (str dds-tokens/skin-css
       "\n"
       routing-css
       "
.kagi-shell{max-width:64rem;margin:0 auto;padding:var(--hig-spacing-4)}
.kagi-head{display:flex;flex-wrap:wrap;gap:var(--hig-spacing-3);
           align-items:baseline;justify-content:space-between;
           padding-bottom:var(--hig-spacing-3);
           border-bottom:var(--hig-hairline) solid var(--hig-color-separator)}
.kagi-where{color:var(--hig-color-label-secondary);
            font-size:var(--hig-text-footnote-font-size)}
.kagi-lede{color:var(--hig-color-label-secondary);
           font-size:var(--hig-text-footnote-font-size);
           margin:0 0 var(--hig-spacing-3)}
.kagi-act{display:inline-flex;gap:var(--hig-spacing-2);align-items:center;margin:0}
.kagi-empty{color:var(--hig-color-label-secondary);padding:var(--hig-spacing-4) 0}
.kagi-mono{font-family:var(--hig-font-mono,ui-monospace,SFMono-Regular,Menlo,monospace)}
.kagi-foot{margin-top:var(--hig-spacing-5);padding-top:var(--hig-spacing-3);
           border-top:var(--hig-hairline) solid var(--hig-color-separator);
           color:var(--hig-color-label-secondary);
           font-size:var(--hig-text-footnote-font-size)}
/* A table is the wrong shape below ~40rem; let it scroll rather than crush
   the row it is describing. */
.kagi-scroll{overflow-x:auto}
.kagi-search{display:flex;flex-wrap:wrap;gap:var(--hig-spacing-2);
             align-items:flex-end;margin:0 0 var(--hig-spacing-4)}
.kagi-detail-head{justify-content:space-between}
"))

;; ───────── views ─────────

(defn- hidden [name value] [:input {:type "hidden" :name name :value (str value)}])

(defn- url-encode [s]
  #?(:clj (java.net.URLEncoder/encode (str s) "UTF-8")
     :cljs (js/encodeURIComponent (str s))))

(defn matching-items
  "Filter the item list by a typed query.

  Matches the id, the compartment and the category, case-insensitively, on
  substring — the three things the row shows. Nothing here touches a
  ciphertext, so searching a vault is not a reason to decrypt it: a query
  that would only match on a secret's contents finds nothing, which is the
  correct answer for a list screen that does not open items.

  A blank query matches everything, and does so without a special case:
  every string contains the empty string. There used to be an `if` here
  saying the same thing, which looked like a guard and could not fail — the
  substring rule already produced the identical answer, so breaking the
  branch changed nothing and no test could tell. What it was really there for
  is the behaviour, not the branch: submitting the form with nothing typed
  must show the whole vault, never an empty one."
  [items q]
  (let [q (str/lower-case (str/trim (str q)))]
    (vec (filter (fn [it]
                   (some #(str/includes? (str/lower-case (str %)) q)
                         [(:item/id it)
                          (:item/compartment it)
                          (some-> (:item/category it) name)]))
                 items))))

(defn item-href
  "The address of one item's detail panel, keeping whatever search the reader
  had typed so that closing the panel does not also clear the filter."
  [item-id q]
  (str "/?item=" (url-encode item-id)
       (when-not (str/blank? (str q)) (str "&q=" (url-encode q)))
       (:fragment (view-by-id :items))))

(defn- action-form
  "A POST that carries the session token in the body as well as the cookie.
  The cookie proves the browser is ours; this proves the *page* is ours, so a
  form posted from anywhere else fails even if the browser attaches the
  cookie. Both are checked server-side."
  [{:keys [action token]} & body]
  (into [:form {:method "post" :action action :class "kagi-act"}
         (hidden "token" token)]
        body))

(defn- search-form
  "Filtering is a GET with the query in the address, so a filtered list is a
  URL: reloadable, bookmarkable, and back-buttonable. Nothing about it is a
  state change, which is why it is not a POST."
  [q]
  [:form {:method "get" :action "/" :class "kagi-search" :role "search"}
   (dds/form-field
    {:label "検索" :for "q"}
    (dds/input-text {:id "q" :name "q" :value (str q) :size "md"
                     :placeholder "item / compartment / category"
                     :autocomplete "off"}))
   (dds/button "絞り込む" {:type :outline :size "sm" :submit? true})
   (when-not (str/blank? (str q))
     (dds/button "解除" {:type :text :size "sm"
                         :href (str "/" (:fragment (view-by-id :items)))}))])

(defn- field-row
  "One kagitaba field. A concealed value is shown as SET, not as empty:
  `strip-sensitive` keeps the field and drops the value for exactly this
  reason — 'there is a password' and 'there is no password' are different
  facts, and an empty cell says the second one."
  [f]
  [(str (or (:field/title f) (:field/id f)))
   (str (some-> (:field/type f) name))
   (if (:field/redacted? f)
     (dds/chip-label "設定済み・伏せてある" {:color "gray"})
     [:span {:class "kagi-mono"} (str (or (:field/value f) "—"))])])

(defn- detail-card
  "One item, opened.

  Opening decrypts — through the same governor graph as everything else, with
  its own purpose in the ledger — and then drops every sensitive value before
  the structure gets here. So this shows what an item IS (title, username,
  urls, which fields are set) and never what its secrets ARE. The value only
  ever leaves through Copy, into the clipboard."
  [{:keys [detail token q]}]
  (let [{:keys [status item]} detail
        close (dds/button "閉じる" {:type :text :size "sm"
                                    :href (str "/"
                                               (when-not (str/blank? (str q))
                                                 (str "?q=" (url-encode q)))
                                               (:fragment (view-by-id :items)))})]
    (case status
      :ok
      (dds/card
       [:div {:class "dds-ext-row kagi-detail-head"}
        (dds/heading 3 (str (or (:item/title item) (:item/id item))) {:size "20"})
        (when-let [c (:item/category item)] (dds/chip-label (name c) {:color "blue"}))
        close]
       [:p {:class "kagi-lede"}
        [:span {:class "kagi-mono"} (str (:item/id item))]
        (when-let [u (:item/username item)] (str " · " u))
        (when-let [u (:item/url item)] (str " · " u))]
       (when-let [notes (not-empty (str (:item/notes item)))]
         [:p (str notes)])
       (for [section (:item/sections item)]
         [:div {:class "kagi-scroll"}
          (dds/table
           {:caption (str (or (:section/title section) "fields"))
            :headers ["Field" "Type" "Value"]
            :row-header? true
            :rows (mapv field-row (:section/fields section))})])
       (action-form {:action "/copy" :token token}
                    (hidden "item" (:item/id item))
                    (dds/button "Copy" {:type :solid-fill :size "sm" :submit? true})))

      :raw
      (dds/card
       [:div {:class "dds-ext-row kagi-detail-head"}
        (dds/heading 3 "素の secret" {:size "20"})
        close]
       [:p {:class "kagi-lede"}
        "この item は kagitaba item ではなく、"
        [:code "kagi add"] " で入れた素の値。構造が無いので見せられるものも無い —— "
        "値は clipboard 経由でだけ取り出せる。"]
       (action-form {:action "/copy" :token token}
                    (hidden "item" (:item-id detail))
                    (dds/button "Copy" {:type :solid-fill :size "sm" :submit? true})))

      :denied
      (dds/notification-banner {:type :error :heading "reveal を governor が拒否した"}
                               [:p "この item は開けない。" close])

      (dds/notification-banner {:type :error :heading "そんな item は無い"}
                               [:p close]))))

(defn items-view
  "The list screen. Metadata only — `kagi.vault-read/items` does not decrypt,
  and the Copy button does not put the value on this page either: the JVM
  reveals it through the governor and puts it on the clipboard."
  [{:keys [items token clipboard-ttl-sec q detail] :as data}]
  (let [shown (matching-items items q)
        filtered? (not (str/blank? (str q)))]
    (list
     [:p {:class "kagi-lede"}
      "Copy は governor を通して復号し、値を " [:strong "この端末の clipboard"] " に置く。"
      "ページにも socket にも平文は出ない。clipboard は "
      [:strong (str clipboard-ttl-sec " 秒")] " 後に、内容が変わっていなければ消える。"]
     (search-form q)
     (when detail (detail-card data))
     (cond
       (empty? items)
       [:p {:class "kagi-empty"} "item がまだ無い。" [:code "kagi add <name>"] " で入れる。"]

       ;; A filter that matches nothing is not an empty vault, and the two
       ;; must not be drawn the same way.
       (empty? shown)
       [:p {:class "kagi-empty"}
        (str "\"" q "\" に一致する item は無い（" (count items) " 件中 0 件）。")]

       :else
       [:div {:class "kagi-scroll"}
        (dds/table
         {:caption (if filtered?
                     (str (count shown) " / " (count items) " items")
                     (str (count items) " items"))
          :headers ["Item" "Compartment" "Category" "Version" "Updated" ""]
          :row-header? true
          :rows (for [it shown]
                  [[:a {:href (item-href (:item/id it) q) :class "kagi-mono"}
                    (str (:item/id it))]
                   (str (or (:item/compartment it) "—"))
                   (if-let [c (:item/category it)]
                     (dds/chip-label (name c) {:color "gray"})
                     "—")
                   (str "v" (:item/version it))
                   (str (or (:item/updated-at it) (:item/created-at it) "—"))
                   (action-form {:action "/copy" :token token}
                                (hidden "item" (:item/id it))
                                (dds/button "Copy" {:type :outline :size "sm" :submit? true}))])})]))))

(defn- revoke-control
  "Revoking is one click away from an operator who meant to click the row.

  So the button is a LINK — a GET that changes nothing and re-renders this
  view with the confirmation in place — and only the second control is a POST.
  That also means the dangerous verb never sits behind a bare GET: the link
  asks, the form acts."
  [{:keys [device-id token confirming?]}]
  (if confirming?
    (list
     (action-form {:action "/device/revoke" :token token}
                  (hidden "device-id" device-id)
                  (dds/button "本当に revoke する" {:type :solid-fill :size "sm" :submit? true}))
     (dds/button "やめる" {:type :text :size "sm" :href (str "/" (:fragment (view-by-id :devices)))}))
    (dds/button "Revoke" {:type :outline :size "sm"
                          :href (str "/?confirm=" device-id
                                     (:fragment (view-by-id :devices)))})))

(defn devices-view
  "Which machines can open this vault, and the one control that matters here.

  The warning is not decoration: revoking removes a device from this list and
  from the unlock wraps, and does nothing whatever to the VMK that device
  already holds. Saying so next to the button is the difference between an
  operator who rotates the secrets and one who thinks they already did."
  [{:keys [devices token confirm]}]
  (list
   [:p {:class "kagi-lede"}
    "revoke はアクセス一覧の変更であって、その端末が既に得た VMK の取り消しではない。"
    "紛失端末は vault 侵害として扱い、secret 自体を rotate すること。"]
   (if (empty? devices)
     [:p {:class "kagi-empty"}
      "登録された端末はこの1台だけ。" [:code "kagi device request"] " で増やす。"]
     [:div {:class "kagi-scroll"}
      (dds/table
       {:caption (str (count devices) " devices")
        :headers ["Device" "Label" "Fingerprint" "Enrolled" "Status"]
        :row-header? true
        :rows (for [d devices]
                [[:span {:class "kagi-mono"} (str (:device/id d))]
                 (str (or (:device/label d) "—"))
                 [:span {:class "kagi-mono"} (str (or (:device/fingerprint d) "—"))]
                 (str (or (:device/enrolled-at d) "—"))
                 (if-let [revoked (:device/revoked-at d)]
                   (dds/chip-label (str "revoked " revoked) {:color "gray"})
                   (revoke-control {:device-id (:device/id d) :token token
                                    :confirming? (= confirm (:device/id d))}))])})])))

(defn vault-view
  "How this vault opens, and who it says you are. Refs are redacted upstream
  (`kagi.unlock/status` runs them through `secret-store/redact-ref`); nothing
  here un-redacts them."
  [{:keys [vault]}]
  (let [{:keys [did graph home unlock]} vault]
    (list
     [:p {:class "kagi-lede"} "unlock envelope と identity。鍵そのものは出ない。"]
     (dds/table
      ;; No headers: a two-column key/value table with blank column headings
      ;; draws an empty header row, which reads as a missing label rather than
      ;; as an absent one. `dds/table` omits <thead> entirely for an empty
      ;; header vector.
      {:caption "Identity"
       :headers []
       :row-header? true
       :rows [["did" [:span {:class "kagi-mono"} (str did)]]
              ["graph" [:span {:class "kagi-mono"} (str graph)]]
              ["vault" [:span {:class "kagi-mono"} (str home)]]]})
     (dds/table
      {:caption (str "Unlock — " (:wrap-count unlock) " wraps"
                     (when (:passphrase-recovery? unlock) " + passphrase recovery"))
       :headers ["Method" "Provider" "Ref"]
       :row-header? true
       :rows (if (seq (:methods unlock))
               (for [m (:methods unlock)]
                 [(str (some-> (:method m) name))
                  (str (some-> (:provider m) name))
                  [:span {:class "kagi-mono"} (str (or (:ref m) "—"))]])
               [["passphrase" "argon2id" "—"]])}))))

(def ^:private renderers
  {:items items-view :devices devices-view :vault vault-view})

(defn- flash-banner
  "The result of the last action. `:ok?` decides the type, and the text is
  whatever the action reported — this never composes a success message of its
  own, so a failure cannot be rendered as a success."
  [{:keys [ok? heading detail]}]
  (dds/notification-banner
   {:type (if ok? :success :error)
    :heading (str heading)}
   (when detail [:p (str detail)])))

(defn document
  "The whole app: one HTML string carrying every view.

  `data` is metadata that has already been fetched — this function performs no
  I/O and holds no vault, which is what keeps it testable and keeps a secret
  structurally unable to reach it."
  [{:keys [css flash] :as data}]
  (dds-page/->page
   {:title "kagi"
    :description "kagi — local vault window"
    :lang "ja"
    :css (or css "")
    :app-css app-css
    :head [[:meta {:name "robots" :content "noindex"}]]}
   [:div {:class "kagi-shell"}
    [:header {:class "kagi-head"}
     (dds/heading 1 "kagi" {:size "32"})
     [:span {:class "kagi-where"} "127.0.0.1 · この端末だけ"]]
    (nav)
    (when flash (flash-banner flash))
    (into [:main]
          (for [{:keys [id label description]} views]
            [:section {:id (name id) :class "kagi-view" :aria-label label}
             (dds/heading 2 label {:size "24"})
             [:p {:class "kagi-lede"} description]
             ((get renderers id) data)]))
    [:footer {:class "kagi-foot"}
     "この窓は " [:code "kagi ui"] " が生きている間だけ開いている。"
     "閉じるには端末で Ctrl-C。"]]))
