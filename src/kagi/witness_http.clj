(ns kagi.witness-http
  "Small independently deployable transport for signed public checkpoints.
  TLS termination is expected at a reverse proxy; clients reject cleartext
  non-loopback URLs. Every received checkpoint is still cryptographically
  verified by WitnessService before persistence."
  (:require [clojure.string :as str]
            [kagi.persist :as persist]
            [kagi.witness :as witness]
            [kagi.witness-service :as service])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
            HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]))

(def max-request-bytes 1048576)

(defn- reply! [^HttpExchange exchange status value]
  (let [body (.getBytes (persist/->edn value) StandardCharsets/UTF_8)]
    (.set (.getResponseHeaders exchange) "content-type" "application/edn; charset=utf-8")
    (.sendResponseHeaders exchange status (alength body))
    (with-open [out (.getResponseBody exchange)] (.write out body))))

(defn- read-body [^HttpExchange exchange]
  (with-open [in (.getRequestBody exchange)]
    (let [body (.readNBytes in (inc max-request-bytes))]
      (when (> (alength body) max-request-bytes)
        (throw (ex-info "witness request too large" {:max max-request-bytes})))
      (persist/<-edn (String. body StandardCharsets/UTF_8)))))

(defn- handler [witness-service]
  (reify HttpHandler
    (handle [_ exchange]
      (try
        (let [method (.getRequestMethod exchange)
              path (.getPath (.getRequestURI exchange))]
          (cond
            (and (= "GET" method) (= "/v1/checkpoints" path))
            (reply! exchange 200 (service/gossip-snapshot witness-service))

            (and (= "GET" method) (= "/v1/conflicts" path))
            (reply! exchange 200 (service/conflicts witness-service))

            (and (= "POST" method) (= "/v1/checkpoints/submit" path))
            (reply! exchange 200 (service/submit! witness-service (read-body exchange)))

            :else (reply! exchange 404 {:error :not-found})))
        (catch Exception e
          (reply! exchange 400 {:error :invalid-checkpoint
                                :message (.getMessage e)}))
        (finally (.close exchange))))))

(defrecord WitnessHttpServer [^HttpServer server]
  java.io.Closeable
  (close [_] (.stop server 0)))

(defn start!
  "Start on host/port (port 0 chooses an ephemeral port). Bind loopback by
  default so an operator must deliberately expose it through authenticated
  TLS infrastructure."
  ([witness-service] (start! witness-service "127.0.0.1" 0))
  ([witness-service host port]
   (let [server (HttpServer/create (InetSocketAddress. host (int port)) 32)]
     (.createContext server "/" (handler witness-service))
     (.setExecutor server nil)
     (.start server)
     (->WitnessHttpServer server))))

(defn endpoint [^WitnessHttpServer http-server]
  (let [address (.getAddress (:server http-server))]
    (str "http://" (.getHostString address) ":" (.getPort address))))

(defn- secure-endpoint! [base-url]
  (let [uri (URI/create base-url)
        host (.getHost uri)]
    (when-not (or (= "https" (.getScheme uri))
                  (and (= "http" (.getScheme uri))
                       (contains? #{"127.0.0.1" "localhost" "::1"} host)))
      (throw (ex-info "remote witness requires HTTPS" {:endpoint base-url})))
    base-url))

(defn- request-edn [method base-url path body]
  (let [base (str/replace (secure-endpoint! base-url) #"/$" "")
        builder (-> (HttpRequest/newBuilder (URI/create (str base path)))
                    (.header "accept" "application/edn"))
        request (.build (if (= method :post)
                          (-> builder
                              (.header "content-type" "application/edn")
                              (.POST (HttpRequest$BodyPublishers/ofString
                                      (persist/->edn body))))
                          (.GET builder)))
        response (.send (HttpClient/newHttpClient) request
                        (HttpResponse$BodyHandlers/ofString))]
    (when-not (<= 200 (.statusCode response) 299)
      (throw (ex-info "witness HTTP request failed"
                      {:status (.statusCode response) :path path})))
    (persist/<-edn (.body response))))

(defn fetch-checkpoints [base-url]
  (request-edn :get base-url "/v1/checkpoints" nil))

(defn submit-checkpoint! [base-url checkpoint]
  (request-edn :post base-url "/v1/checkpoints/submit" checkpoint))

(defn gossip!
  "Fetch a remote snapshot and submit every checkpoint to the local verified
  service. Returns the merged split-view assessment."
  [local-service remote-url]
  (let [before (service/gossip-snapshot local-service)
        remote (fetch-checkpoints remote-url)]
    (doseq [checkpoint (sort-by (juxt :checkpoint/witness :checkpoint/seq) remote)]
      (service/submit! local-service checkpoint))
    (witness/merge-gossip before remote)))
