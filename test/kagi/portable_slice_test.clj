(ns kagi.portable-slice-test
  "The namespaces the agent API needs on a runtime that is not a JVM must stay
  free of ones that are.

  Asserted structurally rather than by running them under ClojureScript,
  because this repo has no cljs test harness for them yet. That is a weaker
  check and it is the one that would actually have caught the drift: the way
  this breaks is somebody adding a convenient `.clj` require to a `.cljc`
  namespace, and the graph says so immediately."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]))

(def ^:private portable-roots
  "The slice that has to run wherever the API runs. `kagi.agent` itself is NOT
  here: it holds the agent-side session (vault, governor, ledger signing),
  which is JVM work and belongs where the vault is."
  ['kagi.agent-registry 'kagi.agent-protocol 'kagi.agent-client
   'kagi.ledger 'kagi.pubkey 'kagi.b64 'kagi.digest])

(defn- source-file [ns-sym]
  (let [base (-> (name ns-sym) (str/replace "-" "_") (str/replace "." "/"))]
    (some (fn [ext] (let [f (io/file "src" (str base ext))] (when (.exists f) f)))
          [".cljc" ".clj" ".cljs"])))

(defn- required-nses [^java.io.File f]
  (let [src (slurp f)]
    (->> (re-seq #"\[([a-z0-9.\-]+)\s+:as\s" src)
         (map second)
         (map symbol)
         (filter #(str/starts-with? (name %) "kagi."))
         set)))

(defn- closure [roots]
  (loop [seen #{} q (vec roots)]
    (if-let [ns-sym (peek q)]
      (if (contains? seen ns-sym)
        (recur seen (pop q))
        (let [f (source-file ns-sym)]
          (recur (conj seen ns-sym)
                 (into (pop q) (when f (required-nses f))))))
      seen)))

(deftest the-portable-slice-requires-nothing-jvm-only
  (testing "移植対象の推移閉包が全て .cljc であること"
    (let [nses (closure portable-roots)
          offenders (into (sorted-map)
                          (keep (fn [n]
                                  (when-let [f (source-file n)]
                                    (when-not (str/ends-with? (.getName f) ".cljc")
                                      [n (.getPath f)]))))
                          nses)]
      (is (empty? offenders)
          (str "これらは .cljc ではないので、Worker/browser で動く経路に入れられない: "
               (pr-str offenders))))))

(deftest every-portable-root-actually-exists
  (doseq [n portable-roots]
    (is (some? (source-file n)) (str n " のソースが見つからない"))))

(deftest the-did-derivation-agrees-with-the-jvm-one
  (testing "可搬な did 導出が、KeyFactory 経由のものと一致する"
    (let [id ((requiring-resolve 'kagi.identity/generate-identity)
              ((requiring-resolve 'kagi.crypto/jvm-provider)))]
      (is (= (:did id)
             ((requiring-resolve 'kagi.pubkey/did-key-from-spki-b64) (:public-b64 id)))))))

(deftest the-portable-fingerprint-agrees-with-the-device-one
  (testing "読み上げる fingerprint が、raw bytes でも base64 でも同じ値になる"
    (let [p ((requiring-resolve 'kagi.crypto/jvm-provider))
          id ((requiring-resolve 'kagi.identity/generate-identity) p)
          raw ((requiring-resolve 'kagi.identity/kem-public) id)
          b64m (into {} (map (fn [[k v]] [k ((requiring-resolve 'kagi.b64/encode) v)])) raw)
          device-fp ((requiring-resolve 'kagi.device/fingerprint) raw)]
      (is (= device-fp
             ((requiring-resolve 'kagi.pubkey/fingerprint) raw)
             ((requiring-resolve 'kagi.pubkey/fingerprint) b64m))))))
