(ns mobilethreat.mobilethreat
  (:use [tawny owl pattern util])
  (:require [tawny.owl :refer :all]
            [tawny.english]
            [tawny.reasoner :as r]))


(defontology mThreat
  :iri "http://www.russet.org.uk/tawny/mobilethreat/mthreat"
  :comment "An ontology for mobile threat Catalogue (MTC), which describes, identifies, and structures the threats posed to mobile information systems."
  )

(r/reasoner-factory :hermit)

;;OWL CLASSES

(defclass Threat
  :comment "The threat is a potential negative action or event facilitated by a vulnerability that results in an unwanted impact on a computer system, application and mobile devices.")

(deftier ThreatCategory
[  Application
Authentication
Celular
]
)
;(owl-and    (owl-some hasActor entriprise ) (owl-some  hasCountermeasure (owl-or countermeasure1 counter2 )  )               )

;;; annotation properties
(defaproperty id)
(def id (annotator id))
(defaproperty Description)
(def Description  (annotator Description))

;;Application's Threat list
(defclass EavesdroppingOnUnencrytedAppTraffic 
  :super Application
  :annotation
  (id "APP-0")
                                        ;(has-value hasID "APP-0")
  (Description "Transmission of app or device data unencrypted allows any attacker with access to the physical media channel (e.g. proximity to wireless radios) to intercept that data. Even if the data is not directly sensitive, it may in combination with other data, allow an attacker in infer sensitive information or conduct other attacks against the user or device (e.g. geo-physical tracking, social engineering, phishing, watering-hole attacks)" "ddddddd")
                             ;(owl-comment "description: Transmission of.......")
  )


(save-ontology "mobilethreat.omn" :omn)
(save-ontology "mobilethreat.owl" :owl)
