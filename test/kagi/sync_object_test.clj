(ns kagi.sync-object-test
  "The object-store sync backend, against a fake store.

  The fake is four functions over an atom because that IS the contract —
  `kagi.store/object-sealed-block-store` takes the same four, and a test that
  needed a real S3 would be testing Backblaze rather than this code."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest testing is]]
            [kagi.crypto :as crypto]
            [kagi.identity :as identity]
            [kagi.operation :as op]
            [kagi.persist :as persist]
            [kagi.store :as store]
            [kagi.sync :as sync]
            [langgraph.graph :as g])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.time Instant]
           [java.time.temporal ChronoUnit]))

(defn- tmp-dir []
  (str (.toAbsolutePath (Files/createTempDirectory "kagi-sync-obj" (make-array FileAttribute 0)))))

(defn- fake-store
  "`{:get-object :put-object :exists?}` over an atom, plus the atom so a test
  can look at what actually landed."
  []
  (let [a (atom {})]
    {:a a
     :fns {:get-object (fn [k] (get @a k))
           :put-object (fn [k v] (swap! a assoc k (vec v)) {:ok? true})
           :exists? (fn [k] (contains? @a k))}}))

(def ^:private did "did:key:zTestVaultOwner")

(defn- shape
  "What must survive a push→pull: every item's cid, and every block's bytes.

  Not a byte compare of the file — `pull` REASSEMBLES the snapshot from a
  catalog and one object per block, so the serialization is rebuilt rather than
  copied. Comparing the bytes of the file would be asserting that `pr-str`
  emits maps in a particular order, which is not a property this system has or
  needs."
  [edn-text]
  (let [d (persist/<-edn edn-text)]
    {:items (into (sorted-map) (map (fn [[k v]] [k (:item/cid v)])) (:items d))
     :blocks (into (sorted-map)
                   (map (fn [[k v]] [k (vec (map #(bit-and % 0xff) v))]))
                   (:blocks d))}))

(defn- vault-with
  "A real encrypted vault snapshot on disk holding one secret."
  [secret]
  (let [p (crypto/jvm-provider)
        dir (tmp-dir)
        path (str dir "/vault.edn")
        owner (identity/generate-identity p)
        vmk (crypto/rand-bytes p 32)
        st (store/mem-store {:members {(:did owner) (identity/member-record owner :owner)}})
        actor (op/build st {:crypto p :signer (identity/sign-secret owner)})]
    (g/run* actor
            {:request {:op :item/create :item-id "k" :compartment "ops"
                       :plaintext (.getBytes ^String secret "UTF-8")}
             :context {:did (:did owner) :role :owner :phase 3 :vmk vmk :purpose :seed
                       :now (str (.truncatedTo (Instant/now) ChronoUnit/SECONDS))
                       :register (identity/member-record owner :owner)}}
            {:thread-id "seed"})
    (persist/save! path (assoc (select-keys @(:a st) [:members :items :grants :blocks :ledger])
                               :meta {}))
    {:path path :dir dir}))

(deftest push-then-pull-round-trips
  (let [{:keys [fns]} (fake-store)
        {:keys [path]} (vault-with "round-trip-secret")
        pushed (sync/object-push! {:fns fns :did did :vault-path path})
        before (slurp path)
        other (str (tmp-dir) "/vault.edn")
        pulled (sync/object-pull! {:fns fns :did did :vault-path other})
        other-text (slurp other)]
    (is (= 1 (:seq pushed)))
    (is (= 0 (:previous-seq pushed)))
    (is (= 1 (:seq pulled)))
    (is (= (shape before) (shape other-text)) "別の機械に同じ暗号文が着地する")))

(deftest the-store-only-ever-holds-ciphertext
  (testing "平文は object store に載らない"
    (let [{:keys [a fns]} (fake-store)
          {:keys [path]} (vault-with "plaintext-that-must-not-appear")]
      (sync/object-push! {:fns fns :did did :vault-path path})
      (let [everything (str/join " " (map (fn [[k v]]
                                            (str k " " (String. (byte-array (map unchecked-byte v))
                                                                "UTF-8")))
                                          @a))]
        (is (not (str/includes? everything "plaintext-that-must-not-appear")))))))

(deftest a-second-writer-does-not-erase-the-first-ones-vault
  (testing "同じ鍵に別のバイト列を書こうとした 2 番目の writer が落ち、1 番目は無傷"
    (let [{:keys [a fns]} (fake-store)
          dev-a (vault-with "device-a")
          dev-b (vault-with "device-b")]
      (is (= 1 (:seq (sync/object-push! {:fns fns :did did :vault-path (:path dev-a)}))))
      (let [block-key (first (filter #(clojure.string/includes? % "/blocks/") (keys @a)))
            a-block (get @a block-key)
            head-key (str "kagi/" did "/catalog/HEAD")
            ;; device B never pulled, so it still believes the remote is empty
            stale-fns (assoc fns :get-object
                             (fn [k] (if (= k head-key) nil ((:get-object fns) k))))]
        ;; The refusal now comes from the BLOCK key rather than the catalog
        ;; version, and that is the more fundamental one: the ciphertext under
        ;; `cid:k:v1` is device A's, and device B's is different.
        (is (thrown? clojure.lang.ExceptionInfo
                     (sync/object-push! {:fns stale-fns :did did :vault-path (:path dev-b)})))
        (is (= a-block (get @a block-key))
            "1 番目の暗号文はそのまま — これが守りたかった性質")))))

(deftest an-identical-retry-is-not-a-conflict
  (testing "部分失敗からの同一バイト列の再 PUT は通る（正当なリトライを詰まらせない）"
    (let [{:keys [fns]} (fake-store)
          {:keys [path]} (vault-with "retry-me")
          head-key (str "kagi/" did "/catalog/HEAD")]
      (sync/object-push! {:fns fns :did did :vault-path path})
      ;; HEAD never landed, so the next push aims at v1 again — with the SAME bytes.
      (let [stale-fns (assoc fns :get-object
                             (fn [k] (if (= k head-key) nil ((:get-object fns) k))))]
        (is (= 1 (:seq (sync/object-push! {:fns stale-fns :did did :vault-path path}))))))))

(deftest expected-seq-guards-an-overwrite
  (testing "pull 後に cloud が動いていたら push しない"
    (let [{:keys [fns]} (fake-store)
          {:keys [path]} (vault-with "x")]
      (sync/object-push! {:fns fns :did did :vault-path path})
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"cloud vault changed since pull"
                            (sync/object-push! {:fns fns :did did :vault-path path
                                                :expected-seq 0}))))))

(deftest an-empty-store-pulls-nothing-rather-than-clobbering
  (let [{:keys [fns]} (fake-store)
        {:keys [path]} (vault-with "local-only")
        before (slurp path)]
    (is (= {:seq nil} (sync/object-pull! {:fns fns :did did :vault-path path})))
    (is (= before (slurp path)) "cloud が空でもローカルは触らない")))

(deftest a-dangling-head-refuses-instead-of-emptying-the-vault
  (testing "HEAD が存在しない version を指していたら、ローカルを消さずに名前付きで落ちる"
    (let [{:keys [a fns]} (fake-store)
          {:keys [path]} (vault-with "keep-me")
          before (slurp path)]
      (sync/object-push! {:fns fns :did did :vault-path path})
      (swap! a dissoc (str "kagi/" did "/catalog/v1.edn"))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"HEAD points at a version"
                            (sync/object-pull! {:fns fns :did did :vault-path path})))
      (is (= before (slurp path)) "失敗しても vault は元のまま"))))

(deftest pull-backs-the-local-file-up-first
  (let [{:keys [fns]} (fake-store)
        remote (vault-with "remote-version")
        local (vault-with "local-version")
        local-before (slurp (:path local))]
    (sync/object-push! {:fns fns :did did :vault-path (:path remote)})
    (sync/object-pull! {:fns fns :did did :vault-path (:path local)})
    ;; `shape`, not bytes: pull REASSEMBLES from catalog + blocks, so the
    ;; serialization is rebuilt and key order differs. The `.bak` IS a byte
    ;; copy of the previous file, so that one compares literally.
    (is (= (shape (slurp (:path remote))) (shape (slurp (:path local)))))
    (is (= local-before (slurp (str (:path local) ".bak"))) "上書き前の版が .bak に残る")))

(deftest versions-accumulate-so-a-lost-head-race-is-recoverable
  (testing "古い版は消えない — HEAD は指すだけで、消すのは誰でもない"
    (let [{:keys [a fns]} (fake-store)
          {:keys [path]} (vault-with "v1")]
      (sync/object-push! {:fns fns :did did :vault-path path})
      (spit path (persist/->edn {:meta {} :items {} :members {} :grants {}
                                 :blocks {} :ledger []}))
      (sync/object-push! {:fns fns :did did :vault-path path})
      (is (contains? @a (str "kagi/" did "/catalog/v1.edn")))
      (is (contains? @a (str "kagi/" did "/catalog/v2.edn")))
      (is (= 2 (:seq (persist/<-edn (String. (byte-array (map unchecked-byte
                                                              (get @a (str "kagi/" did "/catalog/HEAD"))))
                                             "UTF-8"))))))))

(deftest the-prefix-and-did-scope-the-keys
  (testing "DID が tenant 境界 — 別の vault のキーに触らない"
    (let [{:keys [a fns]} (fake-store)
          {:keys [path]} (vault-with "scoped")]
      (sync/object-push! {:fns fns :did did :vault-path path :prefix "custom/"})
      (is (every? #(str/starts-with? % (str "custom/" did "/")) (keys @a))))))

(deftest a-restore-returns-every-block-the-push-uploaded
  (testing "item が指していない旧版の暗号文も戻る — backup が黙って減らない"
    (let [{:keys [fns]} (fake-store)
          {:keys [path]} (vault-with "v1")
          ;; a superseded version: a block no current item points at
          data (persist/load* path)
          orphan-cid "cid:k:v0"
          _ (persist/save! path (assoc-in data [:blocks orphan-cid]
                                          (byte-array [1 2 3 4])))
          _ (sync/object-push! {:fns fns :did did :vault-path path})
          other (str (tmp-dir) "/vault.edn")
          pulled (sync/object-pull! {:fns fns :did did :vault-path other})
          restored (persist/<-edn (slurp other))]
      (is (= 2 (:blocks pulled)))
      (is (contains? (:blocks restored) orphan-cid)
          "どの item も指していない block も復元される")
      (is (= [1 2 3 4] (vec (map #(bit-and % 0xff) (get (:blocks restored) orphan-cid))))))))
