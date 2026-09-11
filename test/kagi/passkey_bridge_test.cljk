(ns kagi.passkey-bridge-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.passkey-bridge :as bridge])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
            HttpResponse$BodyHandlers]))

(defn- request [method url headers body]
  (let [builder (HttpRequest/newBuilder (URI/create url))]
    (doseq [[k v] headers] (.header builder k v))
    (.send (HttpClient/newHttpClient)
           (.build (.method builder method
                            (if body (HttpRequest$BodyPublishers/ofString body)
                                (HttpRequest$BodyPublishers/noBody))))
           (HttpResponse$BodyHandlers/ofString))))

(deftest loopback-bridge-is-origin-token-and-replay-bound
  (let [p (crypto/jvm-provider)
        received (atom nil)
        server (bridge/start! p {:timeout-seconds 10
                                 :on-input #(do (reset! received %) {:saved true})})
        endpoint (str (:origin server) "/bridge")]
    (try
      (is (= 200 (.statusCode (request "GET" (:origin server) {} nil))))
      (testing "hostile origin does not consume the one-shot token"
        (is (= 403 (.statusCode (request "POST" endpoint
                                         {"Origin" "https://evil.example"
                                          "X-Kagi-Token" (:token server)} "{}")))))
      (testing "oversized input is bounded and does not burn the token"
        (is (= 400 (.statusCode (request "POST" endpoint
                                         {"Origin" (:origin server)
                                          "X-Kagi-Token" (:token server)}
                                         (str "{\"x\":\"" (apply str (repeat 65537 "x")) "\"}"))))))
      (is (= 200 (.statusCode (request "POST" endpoint
                                       {"Origin" (:origin server)
                                        "X-Kagi-Token" (:token server)
                                        "Content-Type" "application/json"}
                                       "{\"fixture\":true}"))))
      (is (= {:fixture true} @received))
      (is (= {:saved true} ((:await server))))
      (testing "the successful token cannot be replayed"
        (is (= 403 (.statusCode (request "POST" endpoint
                                         {"Origin" (:origin server)
                                          "X-Kagi-Token" (:token server)} "{}")))))
      (finally ((:stop server))))))
