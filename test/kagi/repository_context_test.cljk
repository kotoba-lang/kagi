(ns kagi.repository-context-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.persist :as persist]
            [kagi.repository-context :as context]
            [kagi.secret-store :as secret-store])
  (:import [java.nio.file Files]
           [java.util Arrays]))

(deftest missing-vault-fails-before-unlock
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo #"vault and identity"
       (context/load-context {:vault-home
                              (str (System/getProperty "java.io.tmpdir")
                                   "/kagi-missing-repository-context")}))))

(deftest repository-runtime-refuses-development-plaintext-identity
  (let [home (.toFile (Files/createTempDirectory
                       "kagi-repository-plaintext-identity"
                       (make-array java.nio.file.attribute.FileAttribute 0)))
        provider (crypto/jvm-provider)
        vmk (crypto/rand-bytes provider 32)]
    (persist/save! (.getPath (io/file home "vault.edn")) {:meta {}})
    (identity/load-or-create-identity!
     (.getPath (io/file home "identity.edn")) provider
     {:allow-plaintext? true})
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"SecretStore-backed"
         (context/load-context
          {:vault-home home :provider provider
           :unlock-vmk-fn (fn [_ _] vmk)})))))

(deftest explicit-host-unlock-builds-repository-context
  (let [home (.toFile (Files/createTempDirectory
                       "kagi-repository-context"
                       (make-array java.nio.file.attribute.FileAttribute 0)))
        provider (crypto/jvm-provider)
        secrets (secret-store/mem-secret-store)
        vmk (crypto/rand-bytes provider 32)]
    (persist/save! (.getPath (io/file home "vault.edn")) {:meta {}})
    (identity/load-or-create-identity!
     (.getPath (io/file home "identity.edn")) provider
     {:secret-store secrets :secret-ref "mem://identity/context"})
    (let [loaded (context/load-context
                  {:vault-home home :provider provider
                   :identity-secret-store secrets
                   :unlock-vmk-fn (fn [_ _] vmk)})]
      (is (Arrays/equals vmk (:vmk loaded)))
      (is (= 1 (:key-epoch loaded)))
      (is (Arrays/equals vmk (get (:vmks loaded) 1)))
      (is (map? (:signing-secret loaded)))
      (is (map? (:signing-public loaded))))))

(deftest repository-vmk-rotation-retains-old-epochs-wrapped
  (let [home (.toFile (Files/createTempDirectory
                       "kagi-repository-keyring"
                       (make-array java.nio.file.attribute.FileAttribute 0)))
        provider (crypto/jvm-provider)
        secrets (secret-store/mem-secret-store)
        root-vmk (crypto/rand-bytes provider 32)
        unlock-fn (fn [_ _] root-vmk)]
    (persist/save! (.getPath (io/file home "vault.edn")) {:meta {}})
    (identity/load-or-create-identity!
     (.getPath (io/file home "identity.edn")) provider
     {:secret-store secrets :secret-ref "mem://identity/keyring"})
    (let [staged (context/prepare-repository-vmk-rotation
                  {:vault-home home :provider provider
                   :repository-id "user-storage-a"
                   :identity-secret-store secrets
                   :unlock-vmk-fn unlock-fn :expected-epoch 1})
          before-admission (context/load-context
                            {:vault-home home :provider provider
                             :repository-id "user-storage-a"
                             :identity-secret-store secrets
                             :unlock-vmk-fn unlock-fn})
          rotated (context/adopt-repository-vmk!
                   {:vault-home home :provider provider
                    :repository-id "user-storage-a"
                    :identity-secret-store secrets
                    :unlock-vmk-fn unlock-fn :key-epoch 2
                    :key-envelope (get (:key-envelopes staged) 2)
                    :rotation-event (:repository-rotation-event staged)})
          reloaded (context/load-context
                    {:vault-home home :provider provider
                     :repository-id "user-storage-a"
                     :identity-secret-store secrets
                     :unlock-vmk-fn unlock-fn})
          old (context/load-context
               {:vault-home home :provider provider
                :repository-id "user-storage-a"
                :identity-secret-store secrets
                :unlock-vmk-fn unlock-fn :key-epoch 1})
          raw-vault (slurp (io/file home "vault.edn"))]
      (is (= 1 (:key-epoch before-admission))
          "a staged rotation does not advance the durable keyring")
      (is (= 2 (:key-epoch rotated) (:key-epoch reloaded)))
      (is (= #{1 2} (set (keys (:vmks reloaded)))))
      (is (map? (get (:key-envelopes reloaded) 2)))
      (is (Arrays/equals root-vmk (:vmk old)))
      (is (Arrays/equals (:vmk rotated) (:vmk reloaded)))
      (is (not (.contains raw-vault
                          (.encodeToString (java.util.Base64/getEncoder)
                                           ^bytes (:vmk rotated)))))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"stale"
           (context/prepare-repository-vmk-rotation
            {:vault-home home :provider provider
             :repository-id "user-storage-a"
             :identity-secret-store secrets
             :unlock-vmk-fn unlock-fn :expected-epoch 1}))))))

(deftest another-device-adopts-a-signed-head-key-envelope
  (let [provider (crypto/jvm-provider)
        root-vmk (crypto/rand-bytes provider 32)
        secrets (secret-store/mem-secret-store)
        unlock-fn (fn [_ _] root-vmk)
        new-home (fn [prefix]
                   (let [home (.toFile (Files/createTempDirectory
                                        prefix
                                        (make-array java.nio.file.attribute.FileAttribute 0)))]
                     (persist/save! (.getPath (io/file home "vault.edn")) {:meta {}})
                     home))
        device-a (new-home "kagi-key-device-a")
        device-b (new-home "kagi-key-device-b")
        _ (identity/load-or-create-identity!
           (.getPath (io/file device-a "identity.edn")) provider
           {:secret-store secrets
            :secret-ref "mem://identity/shared-device"})
        _ (spit (io/file device-b "identity.edn")
                (slurp (io/file device-a "identity.edn")))
        staged (context/prepare-repository-vmk-rotation
                {:vault-home device-a :provider provider
                 :repository-id "shared-user-storage"
                 :identity-secret-store secrets
                 :unlock-vmk-fn unlock-fn :expected-epoch 1})
        adopted (context/adopt-repository-vmk!
                 {:vault-home device-b :provider provider
                  :repository-id "shared-user-storage"
                  :identity-secret-store secrets
                  :unlock-vmk-fn unlock-fn :key-epoch 2
                  :key-envelope (get (:key-envelopes staged) 2)
                  :rotation-event (:repository-rotation-event staged)})]
    (is (= 2 (:current-key-epoch adopted)))
    (is (Arrays/equals (:vmk staged) (:vmk adopted)))))
