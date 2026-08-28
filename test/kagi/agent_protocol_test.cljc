(ns kagi.agent-protocol-test
  "The wire contract, tested without a socket. `kagi.agent-client/sha256-bytes`
  is the portable digest, so these assertions mean the same thing on whichever
  runtime runs them."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest testing is]]
            [kagi.agent-client :as client]
            [kagi.agent-protocol :as proto]))

(def ^:private sha client/sha256-bytes)

(deftest leading-zero-bits-counts-bits-not-bytes
  (is (= 0 (proto/leading-zero-bits [0xff])))
  (is (= 1 (proto/leading-zero-bits [0x7f])))
  (is (= 7 (proto/leading-zero-bits [0x01])))
  (is (= 8 (proto/leading-zero-bits [0x00 0xff])))
  (is (= 12 (proto/leading-zero-bits [0x00 0x0f])))
  (is (= 16 (proto/leading-zero-bits [0x00 0x00]))))

(deftest solved-work-verifies-and-a-wrong-nonce-does-not
  (testing "solve-pow が返す nonce は pow-satisfies? を満たす"
    (let [nonce (proto/solve-pow sha "test-challenge" 12)]
      (is (some? nonce))
      (is (proto/pow-satisfies? sha "test-challenge" nonce 12))
      (is (not (proto/pow-satisfies? sha "test-challenge" (str nonce "0") 12))
          "nonce を変えれば通らない")
      (is (not (proto/pow-satisfies? sha "other-challenge" nonce 12))
          "challenge を変えれば通らない — 解は challenge に縛られている"))))

(deftest solve-gives-up-instead-of-hanging
  (testing "解けない難易度では nil を返す(無限ループしない)"
    (is (nil? (proto/solve-pow sha "impossible" 64 {:max-attempts 64})))))

(deftest enrollment-without-an-invite-is-refused-however-good-the-work-is
  (testing "PoW が完璧でも invite が無ければ通らない — PoW は認証ではない"
    (let [challenge "c" nonce (proto/solve-pow sha challenge 12)
          errs (proto/enrollment-errors
                {:invite nil :label "x" :pow {:nonce nonce}
                 :public {:kem {:x "a" :pq "b"} :sign {:ed "c" :mldsa "d"}}}
                {:challenge challenge :difficulty-bits 12 :invite-record nil}
                sha)]
      (is (some #{:invite-missing} (map :rule errs))))))

(deftest each-refusal-has-its-own-code
  (let [challenge "c"
        good (proto/solve-pow sha challenge 12)
        base {:invite "kagi_inv_x" :label "x" :pow {:nonce good}
              :public {:kem {:x "a" :pq "b"} :sign {:ed "c" :mldsa "d"}}}
        record #:invite{:id "i" :uses-left 1 :expires-at "2999-01-01T00:00:00Z"}
        ctx {:challenge challenge :difficulty-bits 12 :invite-record record
             :now "2026-08-28T00:00:00Z"}
        rules (fn [req c] (set (map :rule (proto/enrollment-errors req c sha))))]
    (testing "揃っていれば何も出ない"
      (is (empty? (rules base ctx))))
    (testing "使い切った招待"
      (is (contains? (rules base (assoc ctx :invite-record
                                        (assoc record :invite/uses-left 0)))
                     :invite-exhausted)))
    (testing "期限切れの招待"
      (is (contains? (rules base (assoc ctx :invite-record
                                        (assoc record :invite/expires-at
                                               "2020-01-01T00:00:00Z")))
                     :invite-expired)))
    (testing "存在しない招待"
      (is (contains? (rules base (assoc ctx :invite-record nil)) :invite-unknown)))
    (testing "失効した challenge"
      (is (contains? (rules base (assoc ctx :expired? true)) :challenge-expired)))
    (testing "解けていない PoW"
      (is (contains? (rules (assoc base :pow {:nonce "0"}) ctx) :pow-failed)))
    (testing "鍵が揃っていない"
      (is (contains? (rules (assoc base :public {:kem {:x "a"}}) ctx) :incomplete-keys)))
    (testing "label が無い"
      (is (contains? (rules (assoc base :label "") ctx) :label-missing)))))

(deftest tokens-are-stored-as-hashes-and-parsed-as-bearer-credentials
  (testing "token-hash は token を含まない"
    (let [token (str proto/token-prefix "abc123")
          h (proto/token-hash (fn [s] (str "sha:" (hash s))) token)]
      (is (not (str/includes? (str h) "abc123")))))
  (testing "bearer 以外の Authorization は token として扱わない"
    (is (= "abc" (proto/bearer-token "Bearer abc")))
    (is (= "abc" (proto/bearer-token "bearer   abc  ")))
    (is (nil? (proto/bearer-token "Basic YWJjOmRlZg==")))
    (is (nil? (proto/bearer-token "")))
    (is (nil? (proto/bearer-token nil)))))

(deftest default-capabilities-are-read-only
  (testing "既定の招待は書けない"
    (is (= #{:item/reveal :item/list} proto/default-ops))
    (is (empty? (filter #{:item/create :item/update :share/grant} proto/default-ops)))))
