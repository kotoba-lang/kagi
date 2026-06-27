(ns kagi.persist
  "vault スナップショットの edn 永続化。byte[] は base64 にして edn 安全にする。
  保存されるのは **暗号文 + wrap 済み鍵 + 台帳メタ** のみ(平文・素の VMK は出ない)。"
  (:require [clojure.walk :as walk]
            [clojure.edn :as edn])
  (:import [java.util Base64]))

(defn- enc [x]
  (if (bytes? x) {:kagi/b64 (.encodeToString (Base64/getEncoder) ^bytes x)} x))

(defn- dec* [x]
  (if (and (map? x) (contains? x :kagi/b64))
    (.decode (Base64/getDecoder) ^String (:kagi/b64 x))
    x))

(defn ->edn ^String [data] (pr-str (walk/postwalk enc data)))
(defn <-edn [^String s] (walk/postwalk dec* (edn/read-string s)))

(defn save! [path data]
  (let [f (java.io.File. ^String path)]
    (when-let [p (.getParentFile (.getAbsoluteFile f))] (.mkdirs p))
    (spit f (->edn data))))

(defn load* [path]
  (let [f (java.io.File. ^String path)]
    (when (.exists f) (<-edn (slurp f)))))
