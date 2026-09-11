(ns kagi.ledger-test
  "改竄検知台帳: ハッシュ鎖 + hybrid 署名(Ed25519+ML-DSA-65)の検証。"
  (:require [clojure.test :refer [deftest testing is]]
            [kagi.ledger :as ledger]
            [kagi.identity :as identity]
            [kagi.crypto :as crypto])
  (:import [java.util Base64]))

(defn- build [provider signer facts]
  (reduce (fn [led f] (conj led (ledger/make-entry led f provider signer))) [] facts))

(deftest signed-chain-verifies
  (testing "全 entry に hybrid 署名が付き、正規鎖は verify-chain で ok"
    (let [p  (crypto/jvm-provider)
          id (identity/generate-identity)
          pub-of (constantly (identity/sign-public id))
          led (build p (identity/sign-secret id)
                     [{:t :committed :op :item/create :actor (:did id)}
                      {:t :committed :op :item/reveal :actor (:did id)}
                      {:t :policy-hold :op :share/grant :actor (:did id)}])]
      (is (= [0 1 2] (mapv :ledger/seq led)))
      (is (every? :ledger/sig led))
      (is (:ok? (ledger/verify-chain led p pub-of))))))

(deftest tampered-fact-detected
  (testing "途中 fact を改竄するとその位置で hash 不一致を検知"
    (let [p  (crypto/jvm-provider)
          id (identity/generate-identity)
          pub-of (constantly (identity/sign-public id))
          led (build p (identity/sign-secret id)
                     [{:t :committed :op :item/create :actor (:did id)}
                      {:t :committed :op :item/reveal :actor (:did id)}])
          tampered (assoc-in led [1 :op] :item/rotate)
          r (ledger/verify-chain tampered p pub-of)]
      (is (false? (:ok? r)))
      (is (= 1 (:broken-at r)))
      (is (= :hash (:why r))))))

(deftest broken-signature-detected
  (testing "署名(ML-DSA)を差し替えると sig 検証で弾く"
    (let [p  (crypto/jvm-provider)
          id (identity/generate-identity)
          pub-of (constantly (identity/sign-public id))
          led (build p (identity/sign-secret id)
                     [{:t :committed :op :item/create :actor (:did id)}])
          garbage (.encodeToString (Base64/getEncoder) (byte-array 100))
          broken  (assoc-in led [0 :ledger/sig :mldsa] garbage)
          r (ledger/verify-chain broken p pub-of)]
      (is (false? (:ok? r)))
      (is (= :sig (:why r))))))

(deftest stripped-signature-on-a-signed-entry-is-detected
  (testing "an attacker who dissoc's :ledger/sig from an otherwise-signed
            entry (touching neither fact content nor hash/prev-hash) must
            not slip past verify-chain just because a missing signature is
            tolerated for actors with no registered key"
    (let [p  (crypto/jvm-provider)
          id (identity/generate-identity)
          pub-of (constantly (identity/sign-public id))
          led (build p (identity/sign-secret id)
                     [{:t :committed :op :item/create :actor (:did id)}
                      {:t :committed :op :item/reveal :actor (:did id)}])
          stripped (update led 1 dissoc :ledger/sig)
          r (ledger/verify-chain stripped p pub-of)]
      (is (false? (:ok? r)))
      (is (= 1 (:broken-at r)))
      (is (= :sig (:why r))))))

(deftest unsigned-chain-still-hash-verifies
  (testing "signer 無し(未署名)でもハッシュ鎖は検証できる"
    (let [p (crypto/jvm-provider)
          led (build p nil [{:t :committed :op :item/create}
                            {:t :committed :op :item/reveal}])]
      (is (every? #(nil? (:ledger/sig %)) led))
      (is (:ok? (ledger/verify-chain led p (constantly nil)))))))
