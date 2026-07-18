(ns kagi.witness-http-test
  (:require [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.rotation :as rotation]
            [kagi.witness :as witness]
            [kagi.witness-http :as http]
            [kagi.witness-main :as witness-main]
            [kagi.witness-service :as service]))

(defn- file-service [p public-of suffix]
  (let [dir (doto (java.io.File/createTempFile (str "witness-http-" suffix) ".tmp")
              (.delete) (.mkdirs))]
    (service/file-service (str (java.io.File. dir "state.edn")) p public-of)))

(deftest independent-http-witnesses-exchange-and-verify-checkpoints
  (let [p (crypto/jvm-provider)
        key (crypto/sign-keypair p)
        public-of #(when (= "w1" %) (:public key))
        remote (file-service p public-of "remote")
        local (file-service p public-of "local")
        event (rotation/new-event {:subject "did:o" :purpose :authority
                                   :from-key "a" :to-key "b" :from-epoch 0})
        cp (witness/create-checkpoint p "w1" 1 [(:rotation/id event)] nil
                                      (:secret key))
        server (http/start! remote)]
    (try
      (is (:accepted? (http/submit-checkpoint! (http/endpoint server) cp)))
      (is (= [(:checkpoint/id cp)]
             (mapv :checkpoint/id (http/fetch-checkpoints (http/endpoint server)))))
      (is (false? (:split-view? (http/gossip! local (http/endpoint server)))))
      (is (= (:checkpoint/id cp)
             (:checkpoint/id (first (service/gossip-snapshot local)))))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"requires HTTPS"
                            (http/fetch-checkpoints "http://witness.example")))
      (finally (.close server)))))

(deftest standalone-witness-config-is-loopback-only-and-has-no-private-key
  (let [p (crypto/jvm-provider)
        key (crypto/sign-keypair p)
        dir (doto (java.io.File/createTempFile "witness-main" ".tmp")
              (.delete) (.mkdirs))
        config #:witness{:state-path (str (java.io.File. dir "state.edn"))
                          :public-keys {"w1" (:public key)}
                          :bind "127.0.0.1" :port 0}
        running (witness-main/start-from-config! config)]
    (try
      (is (re-find #"^http://127\.0\.0\.1:" (:endpoint running)))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"loopback"
                            (witness-main/validate-config!
                             (assoc config :witness/bind "0.0.0.0"))))
      (is (nil? (:private-keys running)))
      (finally (.close (:server running))))))
