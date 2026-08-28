(ns kagi.object-store-test
  "The object-store wiring, over a real socket.

  A fake S3 served by an actual HTTP server rather than a stubbed `IHttp`:
  everything between `kagi.sync/object-push!` and the wire — SigV4 signing, URL
  assembly, the JDK transport, and the byte representations on both sides — is
  the production path. `kagi.storj-block-store-test` makes the same argument
  for the sealed-block seam and gives the reason: a fake-only test passes while
  the two sides disagree about what a byte is."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kagi.object-store :as object-store]
            [kagi.persist :as persist]
            [kagi.sync :as sync])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.io ByteArrayOutputStream]
           [java.net InetAddress InetSocketAddress]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(def ^:private bucket "kagi-vault-test")

(defn- tmp-dir []
  (str (.toAbsolutePath (Files/createTempDirectory "kagi-obj-http" (make-array FileAttribute 0)))))

(defn- read-all [^HttpExchange ex]
  (with-open [in (.getRequestBody ex) out (ByteArrayOutputStream.)]
    (let [buf (byte-array 4096)]
      (loop []
        (let [n (.read in buf)]
          (when-not (neg? n) (.write out buf 0 n) (recur))))
      (.toByteArray out))))

(defn- start-fake-s3!
  "Serves `/<bucket>/<key>` for PUT / GET / HEAD. Authorization is NOT checked —
  this proves the wiring reaches S3 correctly shaped, not that S3 authenticates
  (which is Backblaze's job and not reproducible here)."
  [objects]
  (let [server (HttpServer/create (InetSocketAddress. (InetAddress/getByName "127.0.0.1") 0) 0)]
    (.createContext
     server "/"
     (reify HttpHandler
       (handle [_ ex]
         (try
           (let [k (java.net.URLDecoder/decode
                    (str/replace (.getPath (.getRequestURI ex)) (re-pattern (str "^/" bucket "/")) "")
                    "UTF-8")
                 method (.getRequestMethod ex)]
             (case method
               "PUT" (let [body (read-all ex)]
                       (swap! objects assoc k body)
                       (.sendResponseHeaders ex 200 -1))
               "GET" (if-let [b (get @objects k)]
                       (do (.sendResponseHeaders ex 200 (alength ^bytes b))
                           (with-open [os (.getResponseBody ex)] (.write os ^bytes b)))
                       (.sendResponseHeaders ex 404 -1))
               "HEAD" (.sendResponseHeaders ex (if (contains? @objects k) 200 404) -1)
               (.sendResponseHeaders ex 405 -1)))
           (finally (.close ex)))))) 
    (.setExecutor server nil)
    (.start server)
    server))

(defn- config-for [port]
  {:bucket bucket
   :access-key "AKIAIOSFODNN7EXAMPLE"
   :secret-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
   :endpoint (str "http://127.0.0.1:" port)
   :region "us-west-004"
   :allow-any-host? true})

(defn- snapshot! [path payload]
  (persist/save! path {:meta {:marker payload} :items {} :members {}
                       :grants {} :blocks {} :ledger []})
  path)

(deftest push-and-pull-over-a-real-socket
  (let [objects (atom {})
        server (start-fake-s3! objects)]
    (try
      (let [port (.getPort (.getAddress server))
            fns (object-store/store-fns (config-for port))
            did "did:key:zHttpRoundTrip"
            a (snapshot! (str (tmp-dir) "/vault.edn") "the-encrypted-snapshot")
            b (str (tmp-dir) "/vault.edn")
            pushed (sync/object-push! {:fns fns :did did :vault-path a})
            pulled (sync/object-pull! {:fns fns :did did :vault-path b})]
        (is (= 1 (:seq pushed)))
        (is (= 1 (:seq pulled)))
        ;; parsed value, not bytes: pull reassembles from catalog + blocks, so
        ;; the serialization is rebuilt rather than copied
        (is (= "the-encrypted-snapshot"
               (:marker (:meta (persist/<-edn (slurp b)))))
            "本物の署名・HTTP・バイト変換を通して往復する")
        (testing "キーは DID で切られている"
          (is (contains? @objects (str "kagi/" did "/catalog/HEAD")))
          (is (contains? @objects (str "kagi/" did "/catalog/v1.edn")))))
      (finally (.stop server 0)))))

(deftest a-missing-object-is-absent-not-empty
  (testing "未 push の vault は :seq nil であって空 snapshot ではない"
    (let [objects (atom {})
          server (start-fake-s3! objects)]
      (try
        (let [fns (object-store/store-fns (config-for (.getPort (.getAddress server))))
              local (snapshot! (str (tmp-dir) "/vault.edn") "local-only")
              before (slurp local)]
          (is (= {:seq nil} (sync/object-pull! {:fns fns :did "did:key:zNothing"
                                                :vault-path local})))
          (is (= before (slurp local))))
        (finally (.stop server 0))))))

(deftest a-second-push-advances-the-sequence
  (let [objects (atom {})
        server (start-fake-s3! objects)]
    (try
      (let [fns (object-store/store-fns (config-for (.getPort (.getAddress server))))
            did "did:key:zAdvance"
            path (snapshot! (str (tmp-dir) "/vault.edn") "v1")]
        (is (= 1 (:seq (sync/object-push! {:fns fns :did did :vault-path path}))))
        (snapshot! path "v2")
        (is (= 2 (:seq (sync/object-push! {:fns fns :did did :vault-path path}))))
        (is (= 2 (:seq (sync/object-pull! {:fns fns :did did
                                           :vault-path (str (tmp-dir) "/vault.edn")}))))
        (is (contains? @objects (str "kagi/" did "/catalog/v1.edn")) "古い版は消えない"))
      (finally (.stop server 0)))))

(deftest config-from-env-is-absent-rather-than-partial
  (testing "設定されていないことはエラーではなく既定状態"
    ;; No env vars are set in the suite, so this is the unconfigured answer.
    (is (nil? (object-store/config-from-env)))
    (is (nil? (object-store/from-env)))))

(deftest the-help-names-every-variable-it-needs
  (doseq [v ["KAGI_OBJECT_BUCKET" "KAGI_OBJECT_KEY_ID" "KAGI_OBJECT_APP_KEY"
             "KAGI_OBJECT_ENDPOINT"]]
    (is (str/includes? object-store/env-help v))))
