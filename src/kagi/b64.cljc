(ns kagi.b64
  "Base64, portably.

  Extracted because three namespaces needed it on both runtimes and each was
  about to grow its own copy: `kagi.ledger` (entry hashes and signatures),
  `kagi.agent-client` (the wire), and anything else that has to put bytes in
  EDN or JSON. Two encodings of the same bytes that disagree by one padding
  character produce a signature that verifies on one runtime and not the
  other, which is the kind of difference that shows up as an authorization
  failure a long way from here.

  Standard alphabet with padding (`+/=`), because that is what the JVM half of
  this repo has always emitted and what is already sitting in vault files and
  ledgers. `url` variants are separate functions rather than a flag, so a
  caller cannot pick the wrong one by passing the wrong boolean."
  ;; `clojure.string` is used only by the :cljs branch — required inside the
  ;; reader conditional so a JVM consumer neither loads it nor gets linted for
  ;; an unused require.
  #?(:cljs (:require [clojure.string :as str]))
  #?(:clj (:import [java.util Base64])))

(defn encode
  "bytes → standard base64 with padding."
  [bs]
  #?(:clj (.encodeToString (Base64/getEncoder) ^bytes bs)
     :cljs (js/btoa (apply str (map js/String.fromCharCode (array-seq bs))))))

(defn decode
  "standard base64 → the runtime's byte container."
  [s]
  #?(:clj (.decode (Base64/getDecoder) ^String s)
     :cljs (let [bin (js/atob s)
                 out (js/Uint8Array. (.-length bin))]
             (dotimes [i (.-length bin)] (aset out i (.charCodeAt bin i)))
             out)))

(defn encode-url
  "bytes → base64url, no padding. For anything that lands in a URL or a token."
  [bs]
  #?(:clj (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) ^bytes bs)
     :cljs (-> (encode bs)
               (str/replace "+" "-")
               (str/replace "/" "_")
               (str/replace #"=+$" ""))))

(defn decode-url
  [s]
  #?(:clj (.decode (Base64/getUrlDecoder) ^String s)
     :cljs (decode (-> s
                       (str/replace "-" "+")
                       (str/replace "_" "/")
                       (as-> t (str t (case (mod (count t) 4) 2 "==" 3 "=" "")))))))
