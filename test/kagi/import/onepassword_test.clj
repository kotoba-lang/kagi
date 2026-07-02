(ns kagi.import.onepassword-test
  "1PUX → kagitaba item → kagi vault の end-to-end round-trip。
  実 .1pux ファイルの代わりに、実フォーマットと同じ zip(export.data JSON)を
  テスト内で組み立てる — kagitaba 側の 1PUX shape 検証は kagitaba 自身の
  test で行うので、ここでは kagi 側の glue(plan→:item/create→:item/reveal)
  だけを対象にする。"
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.data.json :as json]
            [langgraph.graph :as g]
            [kagi.operation :as op]
            [kagi.store :as store]
            [kagi.crypto :as crypto]
            [kagi.import.onepassword :as import-1p])
  (:import [java.io File FileOutputStream]
           [java.util.zip ZipOutputStream ZipEntry]))

(def export-data
  {:accounts [{:attrs {:name "jun@example.com"}
              :vaults [{:attrs {:name "Personal"}
                        :items [{:uuid "item-1" :categoryUuid "001" :state "active" :favIndex 0
                                 :overview {:title "GitHub" :tags ["dev"]}
                                 :details {:loginFields [{:name "username" :designation "username" :value "jun"}
                                                         {:name "password" :designation "password" :value "s3cret!"}]
                                          :notesPlain "2FA via app"}}
                                {:uuid "item-2" :categoryUuid "003" :state "archived" :favIndex 0
                                 :overview {:title "Old note"}
                                 :details {:notesPlain "should be skipped by default"}}]}]}]})

(defn- write-1pux! ^File []
  (let [f (File/createTempFile "kagitaba-test-" ".1pux")]
    (.deleteOnExit f)
    (with-open [zos (ZipOutputStream. (FileOutputStream. f))]
      (.putNextEntry zos (ZipEntry. "export.data"))
      (.write zos (.getBytes (json/write-str export-data) "UTF-8"))
      (.closeEntry zos))
    f))

(defn- run [actor req ctx]
  (:state (g/run* actor {:request req :context ctx}
                  {:thread-id (str (:op req) "-" (:item-id req) "-" (:did ctx))})))

(deftest plan-skips-archived-items-by-default
  (let [f (write-1pux! )
        {:keys [entries warnings]} (import-1p/plan (.getPath f))]
    (is (empty? warnings))
    (is (= 1 (count entries)))
    (is (= "github" (:item-id (first entries))))
    (is (= "personal" (:compartment (first entries))))
    (is (= :login (:category (first entries))))))

(deftest plan-include-archived-flag
  (let [f (write-1pux! )
        {:keys [entries]} (import-1p/plan (.getPath f) {:include-archived? true})]
    (is (= 2 (count entries)))
    (is (some #{:secure-note} (map :category entries)))))

(deftest imported-item-roundtrips-through-vault-and-preserves-category
  (testing "kagitaba item(username+password+notes) survives create→reveal unchanged,
           and :item/category is stored as plaintext index metadata"
    (let [f (write-1pux! )
          {:keys [entries]} (import-1p/plan (.getPath f))
          entry (first entries)
          st (store/mem-store {:members {"did:key:zOwner" #:member{:did "did:key:zOwner" :role :owner}}})
          cr (crypto/bc-provider)
          actor (op/build st {:crypto cr})
          owner {:did "did:key:zOwner" :role :owner :phase 1
                :vmk (crypto/rand-bytes cr 32) :purpose :import}
          _ (run actor {:op :item/create :item-id (:item-id entry)
                        :compartment (:compartment entry) :category (:category entry)
                        :plaintext (:plaintext entry)}
                 owner)
          rv (run actor {:op :item/reveal :item-id (:item-id entry)} owner)
          revealed (read-string (String. ^bytes (get-in rv [:result :plaintext]) "UTF-8"))]
      (is (= :revealed (get-in rv [:result :effect])))
      (is (= :login (:item/category revealed)))
      (is (= "jun" (:item/username revealed)))
      (is (= "2FA via app" (:item/notes revealed)))
      (is (= :login (:item/category (store/item st (:item-id entry))))
          "category is readable from the item index without unlocking (like compartment)")
      (let [login-section (first (filter #(= "Login" (:section/title %)) (:item/sections revealed)))
            pw (first (filter #(= :concealed (:field/type %)) (:section/fields login-section)))]
        (is (= "s3cret!" (:field/value pw)))))))
