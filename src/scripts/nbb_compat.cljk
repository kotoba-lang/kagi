(ns scripts.nbb-compat
  "Small synchronous Node.js bridge for the workspace's nbb maintenance scripts."
  (:require [clojure.string :as str]))

(def fs (js/require "node:fs"))
(def path (js/require "node:path"))
(def child-process (js/require "node:child_process"))

(defn file-path [f]
  (cond
    (string? f) f
    (some? f) (.-path f)
    :else ""))

(defn file [x & xs]
  (let [p (.apply (.-resolve path) path (to-array (map file-path (cons x xs))))]
    (js-obj
     "path" p
     "exists" #(try (.existsSync fs p) (catch :default _ false))
     "isFile" #(try (.isFile (.statSync fs p)) (catch :default _ false))
     "isDirectory" #(try (.isDirectory (.statSync fs p)) (catch :default _ false))
     "length" #(try (.-size (.statSync fs p)) (catch :default _ 0))
     "getPath" #(str p)
     "getCanonicalPath" #(str (.realpathSync fs p))
     "getCanonicalFile" #(file (.realpathSync fs p))
     "getName" #(.basename path p)
     "getParent" #(.dirname path p)
     "getParentFile" #(file (.dirname path p))
     "mkdirs" #(do (.mkdirSync fs p #js {:recursive true}) true)
     "listFiles" (fn []
                   (if (.existsSync fs p)
                     (to-array (map (fn [name] (file (.join path p name))) (.readdirSync fs p)))
                     #js []))
     "toPath" #js {"toAbsolutePath" (fn [] #js {"normalize" (fn [] p)})}
     "toURI" #(str "file://" p)
     "toString" (fn [] p))))

(defn slurp [f] (.readFileSync fs (file-path f) "utf8"))
(defn spit [f s] (do (.mkdirSync fs (.dirname path (file-path f)) #js {:recursive true})
                      (.writeFileSync fs (file-path f) (str s))))
(defn spit-append
  "`(spit f s :append true)` の nbb 版。"
  [f s] (do (.mkdirSync fs (.dirname path (file-path f)) #js {:recursive true})
            (.appendFileSync fs (file-path f) (str s))))
(defn read-stdin
  "`(slurp *in*)` の nbb 版。stdin を EOF まで同期読み込みする(fd 0)。"
  [] (try (.readFileSync fs 0 "utf8") (catch :default _ "")))

(defn file-seq [dir]
  (letfn [(walk [f]
            (lazy-seq
             (cons f (when (.isDirectory f)
                       (mapcat walk (seq (.listFiles f)))))))]
    (walk (if (string? dir) (file dir) dir))))

(defn sh [& args]
  (let [options (when (map? (last args)) (last args))
        command (if options (butlast args) args)
        ;; Node's spawnSync default maxBuffer is ~1MB; beyond that it returns
        ;; status:null + truncated output (ENOBUFS in .error) instead of throwing,
        ;; which this fn used to mask as a bare "exit 1" with no diagnostic. Raise
        ;; the cap and surface the real spawn error when one occurred.
        result (.spawnSync child-process (first command) (to-array (rest command))
                           (clj->js (merge {:encoding "utf8" :maxBuffer (* 64 1024 1024)} options)))
        spawn-err (.-error result)
        ;; A child killed by a signal (OOM kill, timeout kill, SIGSEGV) also
        ;; reports status:null, so it lands on the same synthetic exit 1 as a
        ;; real failure — usually with EMPTY stderr, which reads as "it failed
        ;; and said nothing". Report the signal so callers can name the cause.
        signal (.-signal result)]
    {:exit (or (.-status result) 1)
     :signal signal
     :out (or (.-stdout result) "")
     :err (cond-> (or (.-stderr result) "")
            spawn-err (str "\n[nbb-compat/sh] " (.-message spawn-err))
            signal (str "\n[nbb-compat/sh] killed by signal " signal
                        " (exit status は null — 合成した exit 1 です)"))}))

(defn exit [status] (.exit js/process status))
(defn sleep!
  "`(Thread/sleep ms)` の nbb 版。nbb はシングルスレッド同期スクリプトなので
   Atomics.wait でブロッキング待機する(Promise/setTimeout は非同期で
   同期スクリプトの制御フローに割り込めない)。"
  [ms] (js/Atomics.wait (js/Int32Array. (js/SharedArrayBuffer. 4)) 0 0 ms))
(defn getenv [k] (aget (.-env js/process) k))
(defn getenv-all
  "`(System/getenv)`(0-arity)の nbb 版。プロセス環境変数全体を map で返す。
   `js->clj` は process.env(プレーンな JS object ではない)を変換できないため、
   Object.keys で手動収集する。"
  [] (let [env (.-env js/process)]
       (into {} (map (fn [k] [k (aget env k)]) (js/Object.keys env)))))
(defn get-property [k] (when (= k "babashka.file") *file*))
(defn format [template & values]
  ;; matched the whole specifier and substituted (str v) verbatim, discarding any
  ;; width/flag (e.g. "%-18s") — every column-aligned CLI/CI table using this fn
  ;; printed unpadded, ragged output. Now applies width + `-`/`0` padding for real.
  (reduce (fn [s v]
            (if-let [[whole flag width] (re-find #"%([-+0]?)(\d*)[sd]" s)]
              (let [text (str v)
                    w (when (seq width) (js/parseInt width 10))
                    padded (cond
                             (nil? w) text
                             (= flag "-") (.padEnd text w " ")
                             (= flag "0") (.padStart text w "0")
                             :else (.padStart text w " "))]
                (str/replace-first s whole padded))
              s))
          template values))
(defn relative-path [base target]
  (.relative path (file-path base) (file-path target)))
(defn parent-path [f] (.dirname path (file-path f)))
(defn canonical-path [f] (.realpathSync fs (file-path f)))

(set! (.-System js/globalThis)
      #js {"getenv" getenv
           "getProperty" get-property
           "exit" exit})
