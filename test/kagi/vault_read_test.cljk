(ns kagi.vault-read-test
  (:require [clojure.test :refer [deftest is testing]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.vault-read :as vr]
            [kagitaba.contract :as contract]
            [kagitaba.item :as kitem]
            [langgraph.graph :as g]))

(defn- session
  "テスト用の open session。`open` はディスク上の vault を読むが、この ns の
  読み取り規律（列挙は復号しない / reveal は governor 経由 / 機微値は落とす）は
  ストアの出自に依存しない。"
  []
  (let [cr (crypto/jvm-provider)
        id (identity/generate-identity)
        st (store/mem-store {:members {(:did id) #:member{:did (:did id) :role :owner}}})]
    {:status :open :provider cr :identity id :did (:did id)
     :vmk (crypto/rand-bytes cr 32) :store st :vault-home "/tmp/test-vault"}))

(defn- seed! [{:keys [store provider identity vmk]} item-id compartment category plaintext]
  (let [actor (op/build store {:crypto provider})]
    (g/run* actor
            {:request {:op :item/create :item-id item-id :compartment compartment
                       :category category :plaintext (.getBytes ^String plaintext "UTF-8")}
             :context {:did (:did identity) :role :owner :phase 1 :vmk vmk
                       :purpose :daily-use}}
            {:thread-id (str "seed-" item-id)})))

(def claude-item
  (kitem/item* {:category :membership :title "Claude Pro"
                :sections [{:title "Login"
                            :fields [{:id "username" :title "username"
                                      :type :string :value "jun@example.com"}
                                     {:id "password" :title "password"
                                      :type :concealed :value "hunter2"}]}
                           (contract/section {:plan "Pro" :status :active
                                              :amount-minor 3000 :currency "JPY"
                                              :cycle :monthly
                                              :cancel-proc-id "claude-pro"})]}))

;; ── 開かない vault は「契約 0 件」ではない ──────────────────────────────────

(deftest absent-vault-is-not-an-empty-vault
  (let [s (vr/open "/tmp/kagi-vault-read-test-nonexistent")]
    (is (= :absent (:status s)))
    (is (nil? (vr/items s)) "vault が無いときに空リストを返すと 0 件と区別できない")
    (is (nil? (vr/kagitaba-items s "test")))))

;; ── 列挙は復号しない ────────────────────────────────────────────────────────

(deftest listing-never-decrypts
  (let [s (session)]
    (seed! s "claude-pro" "personal" :membership (pr-str claude-item))
    (seed! s "gh-token" "work" :api-credential "ghp_realtokenvalue")
    (let [ls (vr/items s)]
      (is (= ["claude-pro" "gh-token"] (mapv :item/id ls)))
      (is (= [:membership :api-credential] (mapv :item/category ls)))
      (is (not-any? #(re-find #"hunter2|ghp_realtokenvalue" (pr-str %)) ls)
          "一覧に平文が漏れてはならない"))))

;; ── reveal は governor 経由 ─────────────────────────────────────────────────

(deftest reveal-goes-through-the-governor
  (let [s (session)]
    (seed! s "claude-pro" "personal" :membership (pr-str claude-item))
    (testing "用途を宣言した owner は開ける"
      (is (some? (vr/reveal s "claude-pro" :contract-review))))
    (testing "用途の無い開示は governor が止める（nil であって例外ではない）"
      (is (nil? (vr/reveal s "claude-pro" nil))))
    (testing "存在しない item は nil"
      (is (nil? (vr/reveal s "no-such-item" :contract-review))))))

;; ── 機微値は読み出し口で落ちる ──────────────────────────────────────────────

(deftest sensitive-values-never-leave-the-reader
  (let [s (session)]
    (seed! s "claude-pro" "personal" :membership (pr-str claude-item))
    (let [[it] (vr/kagitaba-items s :contract-review)
          dump (pr-str it)]
      (is (= "Claude Pro" (:item/title it)))
      (is (not (re-find #"hunter2" dump))
          "契約を読むために item を開いたが、パスワードは戻り値に含めない")
      (is (re-find #"username" dump) "非機微 field は残る")
      (let [pw (->> (:item/sections it)
                    (mapcat :section/fields)
                    (filter #(= :concealed (:field/type %)))
                    first)]
        (is (some? pw) "password field 自体は残す — 消すと「未設定」に見える")
        (is (nil? (:field/value pw)))
        (is (true? (:field/redacted? pw)))))))

(deftest contract-survives-the-round-trip
  (let [s (session)]
    (seed! s "claude-pro" "personal" :membership (pr-str claude-item))
    (let [[it] (vr/kagitaba-items s :contract-review)
          c (contract/read-contract it)]
      (is (= "Pro" (:contract/plan c)))
      (is (= 3000 (:contract/amount-minor c)))
      (is (= :monthly (:contract/cycle c)))
      (is (= "claude-pro" (:contract/cancel-proc-id c))
          "解約手順への参照は機微ではない — 落としてはいけない"))))

;; ── 見る必要のない item は開かない ──────────────────────────────────────────

(deftest only-matching-items-are-decrypted
  (let [s (session)]
    (seed! s "claude-pro" "personal" :membership (pr-str claude-item))
    (seed! s "gh-token" "work" :api-credential "ghp_realtokenvalue")
    (let [items (vr/kagitaba-items s :contract-review)]
      (is (= 1 (count items)) "契約画面が vault 全体を復号しない")
      (is (not (re-find #"ghp_realtokenvalue" (pr-str items)))))))

(deftest raw-secrets-are-not-mistaken-for-items
  (let [s (session)]
    (seed! s "note" "personal" :membership "just a string, not an item")
    (is (empty? (vr/kagitaba-items s :contract-review))
        "kagitaba item でない平文は item として返さない")))

;; ── 1 件を開く: 4 つの答えは 4 つとも別物 ───────────────────────────────────

(deftest read-one-distinguishes-its-four-answers
  (let [s (session)]
    (seed! s "claude-pro" "personal" :membership (pr-str claude-item))
    (seed! s "note" "personal" :api-credential "just a string, not an item")
    (testing "kagitaba item は構造を返す。機微値は落ちるが field は残る"
      (let [{:keys [status item]} (vr/read-one s "claude-pro" :contract-review)]
        (is (= :ok status))
        (is (= "Claude Pro" (:item/title item)))
        (is (= "claude-pro" (:item/id item)))
        (is (not (re-find #"hunter2" (pr-str item))))
        (let [pw (->> (:item/sections item) (mapcat :section/fields)
                      (filter #(= :concealed (:field/type %))) first)]
          (is (true? (:field/redacted? pw)))
          (is (nil? (:field/value pw))))))
    (testing "素の secret は :raw。平文は返さない"
      (let [r (vr/read-one s "note" :contract-review)]
        (is (= :raw (:status r)))
        (is (not (re-find #"just a string" (pr-str r)))
            "raw の答えに平文が混ざってはいけない")))
    (testing "governor の拒否は :denied で、:absent とも :raw とも別"
      (is (= :denied (:status (vr/read-one s "claude-pro" nil)))))
    (testing "無い item は :absent"
      (is (= :absent (:status (vr/read-one s "no-such-item" :contract-review)))))
    (testing "開いていない vault は :absent（:denied ではない）"
      (is (= :absent (:status (vr/read-one (vr/open "/tmp/kagi-nonexistent-vault")
                                           "claude-pro" :contract-review)))))))

;; ── 表示 ────────────────────────────────────────────────────────────────────

(deftest home-path-is-redacted-for-display
  (let [home (System/getProperty "user.home")]
    (is (= "~/.kagi" (vr/redact-home (str home "/.kagi"))))
    (is (= "/etc/kagi" (vr/redact-home "/etc/kagi")))))
