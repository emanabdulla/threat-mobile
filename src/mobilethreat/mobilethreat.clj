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

(defclass ThreatCategory)
(defoproperty hasCategory
  ;:characteristic :transitive
  :domain Threat
  :range ThreatCategory)

(as-disjoint-subclasses
 ThreatCategory
 (defclass Application
   :comment "Threats related to software applications developed for mobile devices")
 (defclass Authentication
   :comment "Threats related to authentication mechanisms.")
 (defclass Cellular
   :comment "Threats related to cellular systems and infrastructure.")
 (defclass Ecosystem
   :comment "Threats related to the greater mobile ecosystem.")
 (defclass EMM
   :comment "Threats related to enterprise mobility management systems.")
 (defclass GPS
   :comment "Threats related to GPS technology.")
 (defclass LAN&PAN
   :comment "Threats related to local and personal area networks.")
 (defclass Payment
   :comment "Threats related to mobile payments.")
 (defclass PhysicalAccess
   :comment "Threats originating from outside of the device")
 (defclass Privacy
   :comment "Threats related to user privacy")
 (defclass Stack
   :comment "Threats related to the hardware, firmware, and software used to host and operate a device")
 (defclass SupplyChain
   :comment "Threats related to the device and component supply chain."))

;; (deftier ThreatCategory
  ;; [  
;   Application :comment "Threats related to software applications developed for mobile devices"
 ;  Authentication :comment "Threats related to authentication mechanisms"
;   Cellular :comment "Threats related to cellular systems and infrastructure."
;   Ecosystem :comment "Threats related to the greater mobile ecosystem."
;   EMM :comment "Threats related to enterprise mobility management systems."
;   GPS :comment "Threats related to GPS technology."
;   LAN&PAN :comment "Threats related to local and personal area networks."
;   Payment :comment "Threats related to mobile payments."
;   PhysicalAccess :comment "Threats originating from outside of the device"
;   Privacy :comment "Threats related to user privacy"
;   Stack :comment "Threats related to the hardware, firmware, and software used to host and operate a device"
;   SupplyChain :comment "Threats related to the device and component supply chain"
 
;; ]
 ; :functional false
  ;; )

;(owl-and    (owl-some hasActor entriprise ) (owl-some  hasCountermeasure (owl-or countermeasure1 counter2 )  )               )




;;; annotation properties
(defaproperty Id)
(def id (annotator id))
(defaproperty Description)
(def Description  (annotator Description))
(defaproperty CVEExamples)
(def CVEExamples (annotator CVEExamples))

;;Application's Threat list
(defclass EavesdroppingOnUnencrytedAppTraffic 
  :super Application
  :annotation
  (annotation Id "APP-0")
  
  ;(has-value hasID "APP-0")
  (Description "Transmission of app or device data unencrypted allows any attacker with access to the physical media channel (e.g. proximity to wireless radios) to intercept that data. Even if the data is not directly sensitive, it may in combination with other data, allow an attacker in infer sensitive information or conduct other attacks against the user or device (e.g. geo-physical tracking, social engineering, phishing, watering-hole attacks)" "ddddddd")
  ;(owl-comment "description: Transmission of.......")
  
(CVEExamples "CVE-2017-2412")
(CVEExamples "CVE-2015-4640")

)


(save-ontology "mobilethreat.omn" :omn)
(save-ontology "mobilethreat.owl" :owl)
