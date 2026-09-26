(ns kagi.local-edn
  "Bounded EDN reader for existing local vault files on the JVM."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io])
  (:import [java.io PushbackReader StringReader]))

(def ^:private max-local-edn-bytes (* 32 1024 1024))
(def ^:private eof (Object.))

(defn- read-one [reader source]
  (let [value (edn/read {:eof eof} reader)]
    (when (identical? value eof)
      (throw (ex-info "local EDN is empty" {:source source})))
    (when-not (identical? (edn/read {:eof eof} reader) eof)
      (throw (ex-info "local EDN has trailing form" {:source source})))
    value))

(defn read-text [text]
  (when (> (count (.getBytes ^String text "UTF-8")) max-local-edn-bytes)
    (throw (ex-info "local EDN exceeds limit" {:limit max-local-edn-bytes})))
  (with-open [reader (PushbackReader. (StringReader. text))]
    (read-one reader :secret-store)))

(defn read-file [path]
  (let [file (io/file path)
        size (.length file)]
    (when (> size max-local-edn-bytes)
      (throw (ex-info "local EDN file exceeds limit"
                      {:bytes size :limit max-local-edn-bytes})))
    (with-open [reader (PushbackReader. (io/reader file))]
      (read-one reader (str path)))))
