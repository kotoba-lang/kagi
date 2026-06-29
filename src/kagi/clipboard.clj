(ns kagi.clipboard
  "Clipboard custody helpers.

  Secret values may enter this namespace, but should not be returned, logged, or
  printed. Public results only contain operational metadata."
  (:require [clojure.java.io :as io]))

(defprotocol Clipboard
  (copy! [clipboard s])
  (paste [clipboard]))

(defrecord MemoryClipboard [state]
  Clipboard
  (copy! [_ s]
    (reset! state (str s))
    true)
  (paste [_]
    @state))

(defn memory-clipboard
  ([] (memory-clipboard ""))
  ([initial] (->MemoryClipboard (atom (str initial)))))

(defn- run-with-stdin! [argv s]
  (let [p (.start (ProcessBuilder. ^java.util.List argv))]
    (with-open [w (io/writer (.getOutputStream p))]
      (.write w (str s)))
    (let [exit (.waitFor p)]
      (when-not (zero? exit)
        (throw (ex-info "clipboard command failed" {:exit exit :argv argv}))))
    true))

(defn- run-stdout [argv]
  (let [p (.start (ProcessBuilder. ^java.util.List argv))
        out (future (slurp (.getInputStream p)))
        _err (future (slurp (.getErrorStream p)))
        exit (.waitFor p)]
    (when-not (zero? exit)
      (throw (ex-info "clipboard command failed" {:exit exit :argv argv})))
    @out))

(defrecord MacClipboard []
  Clipboard
  (copy! [_ s]
    (run-with-stdin! ["/usr/bin/pbcopy"] s))
  (paste [_]
    (run-stdout ["/usr/bin/pbpaste"])))

(defn macos-clipboard []
  (->MacClipboard))

(defn copy-secret-with-ttl!
  "Copy a secret to clipboard and clear it later only if it is still unchanged."
  [clipboard secret {:keys [ttl-ms clear?]
                     :or {ttl-ms 45000 clear? true}}]
  (copy! clipboard secret)
  (when clear?
    (future
      (Thread/sleep ttl-ms)
      (try
        (when (= secret (paste clipboard))
          (copy! clipboard ""))
        (catch Throwable _ nil))))
  {:ok? true
   :copied? true
   :ttl-ms ttl-ms
   :secret? false})
