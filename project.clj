(defproject mobilethreat "0.0.1-SNAPSHOT"
  :description "An ontology for mobilethreat"
  :dependencies [[uk.org.russet/tawny-owl "2.0.0-SNAPSHOT"]
                 [org.clojure/clojure "1.10.1"]]
  :main mobilethreat.mobilethreat

  :profiles
  {:light {:plugins [[nightlight/lein-nightlight "1.9.0"]]}}
  )
