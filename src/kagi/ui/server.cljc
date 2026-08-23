(ns kagi.ui.server
  "The loopback server behind `kagi ui`.

  ## What it knows about the vault: nothing

  `start!` takes an `:actions` map of functions. This namespace opens no
  vault, holds no VMK and calls no crypto — it binds a socket, decides whether
  a request is ours, and calls one of those functions. That is the same seam
  `kagi.store/object-sealed-block-store` uses (four functions, not a client),
  and it is what lets the whole surface be tested against fakes while the real
  wiring stays in `kagi.cli`, where unlock already lives.

  ## Who is allowed in

  Three independent gates, because each one fails differently:

  1. **The socket is 127.0.0.1.** Nothing off this machine can reach it. This
     is the only gate that is not a check — it is an absence of route.
  2. **A session cookie.** The process mints a 32-byte token, opens the
     browser once at `/?token=…`, and immediately redirects to a bare `/`
     after setting the cookie, so the token does not sit in the address bar,
     the history or a `Referer`. Another local process cannot read the cookie
     jar of the operator's browser; it also cannot guess the token.
  3. **The same token, again, in the body of every POST.** The cookie proves
     the *browser* is the operator's. This proves the *page* is ours. A form
     served by any other page on this machine can make the browser attach the
     cookie, and it cannot make it carry a token it has never seen.

  `Origin` is checked when present and not required when absent: form POSTs
  have not always carried one across browsers, and a gate that is *sometimes*
  enforced would be doing the job the form token already does completely.

  ## Refusals say which gate refused

  Every rejection answers with its own reason string, and the tests assert
  those literals. A guard that returns the same 403 for 'no session', 'wrong
  origin' and 'stale form' can be broken in one of those three ways and go on
  passing its own tests (the workspace rule about checks that cannot say what
  they refused — CLAUDE.md, 'the six questions')."
  ;; `kagi.ui` and `clojure.java.io` are used only by the JVM half below, so
  ;; they are required only there — a `.cljc` that requires what its cljs
  ;; branch never uses is a `.clj` wearing a different extension.
  (:require #?@(:clj [[clojure.java.io :as io]
                      [kagi.ui :as ui]])
            [clojure.string :as str])
  #?(:clj
     (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
              [java.io ByteArrayOutputStream]
              [java.net InetAddress InetSocketAddress URLDecoder]
              [java.nio.charset StandardCharsets]
              [java.security MessageDigest]
              [java.util Base64]
              [java.util.concurrent Executors ThreadFactory TimeUnit])))

;; ── the portable half: what a request says ─────────────────────────────────

(defn- url-decode [s]
  #?(:clj (URLDecoder/decode (str s) "UTF-8")
     :cljs (js/decodeURIComponent (str/replace (str s) "+" " "))))

(defn form-decode
  "`a=1&b=2` -> `{\"a\" \"1\" \"b\" \"2\"}`. Later keys do not overwrite earlier
  ones: a body carrying `token` twice is trying to make the parser and the
  gate disagree about which one is 'the' token, and the first value is the one
  the gate already saw."
  [s]
  (reduce (fn [acc pair]
            (let [[k v] (str/split pair #"=" 2)
                  k* (when-not (str/blank? k) (url-decode k))]
              (if (or (nil? k*) (contains? acc k*))
                acc
                (assoc acc k* (url-decode (or v ""))))))
          {}
          (remove str/blank? (str/split (or s "") #"&"))))

(defn cookie-value
  "Pull one cookie out of a `Cookie:` header, by full name — `kagi_ui_session`
  and `kagi_ui_session_anything` are different cookies. Pure and portable, so
  the shape the session gate rests on can be tested without a socket."
  [header cookie]
  (some->> (str/split (or header "") #";")
           (map str/trim)
           (filter #(str/starts-with? % (str cookie "=")))
           first
           (#(subs % (inc (count cookie))))))

;; ── the JVM half ───────────────────────────────────────────────────────────
;;
;; Everything below binds a socket, and the socket has to be in the process
;; that already holds the open vault — which is the JVM, because the PQC
;; primitives come from the JDK. The parsing above is portable; this is not,
;; and says so rather than pretending.
#?(:clj
   (do

     (def ^:private max-body-bytes
       "A form on this page is a few hundred bytes. Nothing legitimate is near
       this, and an unbounded read on a loopback socket is a way for any local
       process to make this JVM allocate until it dies."
       8192)

     (def ^:private cookie-name "kagi_ui_session")

     (defn dds-css
       "The vendored デジタル庁デザインシステム stylesheet, read off the classpath.

       Throws rather than falling back to `\"\"`. An empty stylesheet renders a
       page that loads, looks broken, and gives no clue why — the failure mode
       this workspace keeps calling out, where not being able to do the thing
       returns the same value as doing it."
       []
       (if-let [resource (io/resource "jp_go_dds/dds.css")]
         (slurp resource)
         (throw (ex-info (str "jp_go_dds/dds.css is not on the classpath — "
                              "is io.github.kotoba-lang/jp-go-digital-design-system "
                              "in deps.edn?")
                         {:resource "jp_go_dds/dds.css"}))))

     (defn- constant-time= [^String a ^String b]
       (and a b
            (MessageDigest/isEqual (.getBytes a StandardCharsets/UTF_8)
                                   (.getBytes b StandardCharsets/UTF_8))))

     (defn- mint-token
       "32 bytes from the vault's own CSPRNG seam, url-safe. `rand-fn` is passed
       in rather than requiring kagi.crypto, so this namespace stays free of the
       provider — and so a test can watch what it does with a known token."
       [rand-fn]
       (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) ^bytes (rand-fn 32)))

     (defn- read-body ^String [^HttpExchange exchange]
       (with-open [in (.getRequestBody exchange)
                   out (ByteArrayOutputStream.)]
         (let [buf (byte-array 4096)]
           (loop [total 0]
             (let [n (.read in buf)]
               (if (neg? n)
                 (.toString out "UTF-8")
                 (let [next-total (+ total n)]
                   (when (> next-total max-body-bytes)
                     (throw (ex-info "kagi ui body too large"
                                     {:max-bytes max-body-bytes})))
                   (.write out buf 0 n)
                   (recur next-total))))))))

     (defn- respond!
       [^HttpExchange exchange status content-type body & {:keys [headers]}]
       (let [bytes (.getBytes ^String (or body "") StandardCharsets/UTF_8)
             out-headers (.getResponseHeaders exchange)]
         (.set out-headers "content-type" content-type)
         (.set out-headers "cache-control" "no-store")
         ;; `same-origin`, NOT `no-referrer`, and the difference is
         ;; load-bearing: a page served with `no-referrer` makes the browser
         ;; send `Origin: null` on its own same-origin form POSTs, so every
         ;; action on this page came back `bad-origin`. Measured in a real
         ;; browser on 2026-08-23; the suite could not see it, because an HTTP
         ;; client sends whatever Origin the test hands it. `kagi.ui-server-test`
         ;; pins this header next to the gate that depends on it.
         (.set out-headers "referrer-policy" "same-origin")
         (.set out-headers "x-content-type-options" "nosniff")
         ;; No script anywhere: `default-src 'none'` covers script-src, so the
         ;; document cannot run one even if something managed to inject it.
         ;; `style-src 'unsafe-inline'` is the design system's stylesheet, which
         ;; jp-go-dds emits as one inline <style>; with no script on the page a
         ;; style is markup, not a way to execute anything.
         (.set out-headers "content-security-policy"
               (str "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"))
         (doseq [[k v] headers] (.add out-headers k v))
         (.sendResponseHeaders exchange status (alength bytes))
         (with-open [os (.getResponseBody exchange)] (.write os bytes))))

     (defn- refuse! [exchange status reason]
       (respond! exchange status "text/plain; charset=utf-8" (str reason "\n")))

     (defn- query-param [^HttpExchange exchange k]
       (get (form-decode (.getQuery (.getRequestURI exchange))) k))

     (defn- page-for
       "`:snapshot` is called on every render; `:detail` only when one item was
       asked for. That ordering is the point: opening an item decrypts it, so
       it happens when the reader names one, and never as part of drawing a
       list."
       [{:keys [actions css token flash confirm query item]}]
       (ui/document (merge {:css css :token token :flash flash :confirm confirm
                            :q query
                            :detail (when-not (str/blank? (str item))
                                      ((:detail actions) item))}
                           ((:snapshot actions)))))

     (defn- redirect! [exchange fragment flash-atom flash]
       (reset! flash-atom flash)
       (respond! exchange 303 "text/plain; charset=utf-8" ""
                 :headers {"location" (str "/" fragment)}))

     (defn- handle-action!
       "Run one action and turn whatever it returns — or throws — into a flash.

       An action that throws is reported as a failure with its message. It is
       not reported as a success with the failure in the detail line, which is
       the shape that lets a refused reveal read as a completed one."
       [exchange {:keys [flash-atom view f]}]
       (let [{:keys [ok? heading detail]}
             (try (f)
                  (catch Exception e
                    {:ok? false :heading "失敗" :detail (or (ex-message e) (str e))}))]
         (redirect! exchange (:fragment (ui/view-by-id view)) flash-atom
                    {:ok? (boolean ok?) :heading heading :detail detail})))

     (defn start!
       "Bind 127.0.0.1 and serve the vault window. Returns
       `{:origin :url :token :port :await :stop}`.

       `:actions` is `{:snapshot fn, :copy! fn, :revoke! fn}`:

         :snapshot  () -> the metadata `kagi.ui/document` renders. Must not
                    decrypt.
         :copy!     (item-id) -> {:ok? :heading :detail}. Reveals through the
                    governor and puts the value on THIS machine's clipboard.
                    The return value is a report; a secret in it would be
                    rendered.
         :revoke!   (device-id) -> {:ok? :heading :detail}.

       `:idle-timeout-seconds` closes the window when nobody is using it, so a
       forgotten tab is not an open vault for the rest of the day."
       [{:keys [actions css rand-fn idle-timeout-seconds]
         :or {idle-timeout-seconds 900}}]
       (let [server (HttpServer/create
                     (InetSocketAddress. (InetAddress/getByName "127.0.0.1") 0) 0)
             port (.getPort (.getAddress server))
             origin (str "http://127.0.0.1:" port)
             token (mint-token rand-fn)
             flash-atom (atom nil)
             last-seen (atom (System/nanoTime))
             executor (Executors/newFixedThreadPool 2)
             stopped? (atom false)
             closed (promise)
             stop (fn []
                    (when (compare-and-set! stopped? false true)
                      (.stop server 0)
                      (.shutdownNow executor)
                      (deliver closed :stopped))
                    @closed)
             take-flash! #(let [f @flash-atom] (reset! flash-atom nil) f)
             session-ok? (fn [^HttpExchange exchange]
                           (constant-time=
                            token
                            (cookie-value (.getFirst (.getRequestHeaders exchange) "Cookie")
                                          cookie-name)))
             origin-ok? (fn [^HttpExchange exchange]
                          ;; Absent is allowed (see the ns docstring); present
                          ;; and wrong is not — and `null`, which is what a
                          ;; sandboxed or cross-site context sends, is wrong.
                          (let [sent (.getFirst (.getRequestHeaders exchange) "Origin")]
                            (or (nil? sent) (= origin sent))))]
         (.setExecutor server executor)
         (.createContext
          server "/"
          (reify HttpHandler
            (handle [_ exchange]
              (reset! last-seen (System/nanoTime))
              (try
                (let [path (.getPath (.getRequestURI exchange))
                      method (.getRequestMethod exchange)]
                  (cond
                    ;; The one request allowed to carry the token in the URL.
                    ;; It hands the browser a cookie and sends it straight to a
                    ;; bare `/`, so the token is not left anywhere a later
                    ;; screenshot, history entry or Referer can pick it up.
                    (and (= "GET" method) (= "/" path) (query-param exchange "token"))
                    (if (constant-time= token (query-param exchange "token"))
                      (respond! exchange 303 "text/plain; charset=utf-8" ""
                                :headers {"location" (str "/" (:fragment ui/default-view))
                                          "set-cookie" (str cookie-name "=" token
                                                            "; Path=/; HttpOnly; SameSite=Strict")})
                      (refuse! exchange 403 "bad-session-token"))

                    (not (session-ok? exchange))
                    (refuse! exchange 403 "no-session")

                    (and (= "GET" method) (= "/" path))
                    (respond! exchange 200 "text/html; charset=utf-8"
                              (page-for {:actions actions :css css :token token
                                         :flash (take-flash!)
                                         ;; Asking is a GET; acting is a POST.
                                         ;; This only chooses which control the
                                         ;; devices view draws — nothing is
                                         ;; decided here.
                                         :confirm (query-param exchange "confirm")
                                         :query (query-param exchange "q")
                                         :item (query-param exchange "item")}))

                    (not= "POST" method)
                    (refuse! exchange 404 "not-found")

                    (not (origin-ok? exchange))
                    (refuse! exchange 403 "bad-origin")

                    :else
                    (let [form (form-decode (read-body exchange))]
                      (cond
                        (not (constant-time= token (get form "token")))
                        (refuse! exchange 403 "bad-form-token")

                        (= "/copy" path)
                        (handle-action! exchange
                                        {:flash-atom flash-atom :view :items
                                         :f #((:copy! actions) (get form "item"))})

                        (= "/device/revoke" path)
                        (handle-action! exchange
                                        {:flash-atom flash-atom :view :devices
                                         :f #((:revoke! actions) (get form "device-id"))})

                        :else (refuse! exchange 404 "not-found")))))
                (catch Exception e
                  ;; The message, not the stack: this is a local operator's
                  ;; browser, and a body large enough to be refused should say so.
                  (refuse! exchange 400 (str "refused: " (ex-message e))))
                (finally (.close exchange))))))
         (.start server)
         (let [watchdog (Executors/newSingleThreadScheduledExecutor
                         (reify ThreadFactory
                           (newThread [_ r]
                             (doto (Thread. ^Runnable r "kagi-ui-idle")
                               (.setDaemon true)))))]
           (.scheduleAtFixedRate
            watchdog
            ^Runnable (fn []
                        (when (> (/ (- (System/nanoTime) @last-seen) 1e9)
                                 idle-timeout-seconds)
                          (stop)
                          (.shutdown watchdog)))
            10 10 TimeUnit/SECONDS))
         {:origin origin
          :url (str origin "/?token=" token)
          :token token
          :port port
          ;; `await` parks until the window closes — the idle watchdog, a
          ;; Ctrl-C through the caller, or `stop` itself. `kagi ui` is a
          ;; foreground command and the vault is open in this process while it
          ;; runs, so the caller needs something to wait on that ends when the
          ;; socket does.
          :await #(deref closed)
          :stop stop}))))
