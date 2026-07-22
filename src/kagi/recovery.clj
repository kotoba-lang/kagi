(ns kagi.recovery
  "Shamir threshold recovery for random VMKs over GF(256). Shares contain no
  usable VMK alone and carry a set id plus SHA-256 digest for mix-up/tamper detection."
  (:require [kagi.crypto :as crypto])
  (:import [java.util UUID]))

(defn- gf-mul [a b]
  (loop [a (bit-and a 0xff) b (bit-and b 0xff) out 0]
    (if (zero? b)
      out
      (recur (bit-and (bit-xor (bit-shift-left a 1)
                               (if (pos? (bit-and a 0x80)) 0x1b 0)) 0xff)
             (unsigned-bit-shift-right b 1)
             (if (odd? b) (bit-xor out a) out)))))

(defn- gf-pow [a n]
  (loop [base a n n out 1]
    (if (zero? n) out
        (recur (gf-mul base base) (unsigned-bit-shift-right n 1)
               (if (odd? n) (gf-mul out base) out)))))

(defn- gf-div [a b]
  (when (zero? b) (throw (ex-info "invalid recovery share denominator" {})))
  (gf-mul a (gf-pow b 254)))

(defn- eval-poly [coeffs x]
  (reduce (fn [out coefficient] (bit-xor (gf-mul out x) coefficient)) 0 coeffs))

(defn split
  "Split secret bytes into n shares requiring threshold k."
  [p ^bytes secret k n]
  (when-not (and (pos-int? k) (<= 2 k n 255))
    (throw (ex-info "invalid recovery threshold" {:threshold k :shares n})))
  (let [set-id (str (UUID/randomUUID))
        digest (crypto/sha256 secret)
        polys (mapv (fn [b]
                      (into [(bit-and b 0xff)]
                            (map #(bit-and % 0xff) (crypto/rand-bytes p (dec k)))))
                    secret)]
    (mapv (fn [x]
            {:recovery/version 1 :recovery/set-id set-id
             :recovery/threshold k :recovery/index x :recovery/digest digest
             :recovery/value (byte-array (map #(eval-poly (reverse %) x) polys))})
          (range 1 (inc n)))))

(defn combine
  "Recover and integrity-check a secret from k or more distinct shares."
  [shares]
  (let [shares (vec shares)
        first-share (first shares)
        k (:recovery/threshold first-share)
        set-id (:recovery/set-id first-share)
        selected (subvec shares 0 (min (count shares) (or k 0)))
        indexes (mapv :recovery/index selected)]
    (when-not (and first-share (>= (count shares) k))
      (throw (ex-info "insufficient recovery shares" {:required k :provided (count shares)})))
    (when-not (and (= (count indexes) (count (set indexes)))
                   (every? #(and (= set-id (:recovery/set-id %))
                                 (= k (:recovery/threshold %))
                                 (= (seq (:recovery/digest first-share))
                                    (seq (:recovery/digest %)))) selected))
      (throw (ex-info "incompatible recovery shares" {})))
    (let [size (alength ^bytes (:recovery/value first-share))
          secret (byte-array
                  (for [offset (range size)]
                    (reduce bit-xor 0
                            (for [{xi :recovery/index value :recovery/value} selected]
                              (let [basis (reduce
                                           (fn [acc xj]
                                             (if (= xi xj) acc
                                                 (gf-mul acc (gf-div xj (bit-xor xj xi)))))
                                           1 indexes)]
                                (gf-mul (bit-and (aget ^bytes value offset) 0xff) basis))))))]
      (when-not (= (seq (crypto/sha256 secret)) (seq (:recovery/digest first-share)))
        (throw (ex-info "recovery share integrity check failed" {})))
      secret)))
