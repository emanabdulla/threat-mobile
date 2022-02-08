(ns mobilethreat.core
  [:use [tawny.owl]]
  [:require [mobilethreat.mobilethreat]])


(defn -main [& args]
  (save-ontology mobilethreat.mobilethreat/mobilethreat "mobilethreat.omn"))
