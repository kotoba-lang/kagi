(ns kagi.rotation-main
  "Long-running entrypoint for durable scheduled rotation. Each tick invokes
  the normal CLI path, so Governor admission, OS-keystore unlock, job leases,
  atomic vault persistence, retry/backoff, and dead-letter behavior remain the
  single implementation rather than being re-created in a daemon."
  (:require [kagi.cli :as cli])
  (:import [java.time Instant]
           [java.util.concurrent ThreadLocalRandom]))

(def default-interval-seconds 3600)
(def minimum-interval-seconds 60)

(defn interval-seconds [value]
  (let [seconds (if (or (nil? value) (= "" value))
                  default-interval-seconds
                  (try (Long/parseLong value)
                       (catch NumberFormatException _
                         (throw (ex-info "invalid KAGI_ROTATION_INTERVAL_SECONDS"
                                         {:value value})))))]
    (when (< seconds minimum-interval-seconds)
      (throw (ex-info "rotation interval is too short"
                      {:seconds seconds :minimum minimum-interval-seconds})))
    seconds))

(defn run-once! []
  (cli/-main "rotation-run"))

(defn- jittered-millis [seconds]
  ;; Up to 10% positive jitter prevents a fleet of hosts restored from the
  ;; same image from polling their backing stores simultaneously.
  (let [base (* 1000 seconds)
        jitter (.nextLong (ThreadLocalRandom/current) (inc (max 1 (quot base 10))))]
    (+ base jitter)))

(defn -main [& _]
  (let [seconds (interval-seconds (System/getenv "KAGI_ROTATION_INTERVAL_SECONDS"))]
    (binding [*out* *err*]
      (println (pr-str {:service :kagi/rotation-scheduler
                        :status :started :at (str (Instant/now))
                        :interval-seconds seconds})))
    (loop []
      (try
        (run-once!)
        (catch InterruptedException e (throw e))
        (catch Exception e
          ;; The durable job store owns retry/dead-letter state. A failed tick
          ;; must not terminate the supervisor process or erase that evidence.
          (binding [*out* *err*]
            (println (pr-str {:service :kagi/rotation-scheduler
                              :status :tick-failed :at (str (Instant/now))
                              :error (.getMessage e)})))))
      (if (try
            (Thread/sleep (jittered-millis seconds))
            true
            (catch InterruptedException _ false))
        (recur)
        (binding [*out* *err*]
          (println (pr-str {:service :kagi/rotation-scheduler
                            :status :stopped :at (str (Instant/now))})))))))
