(ns mobilethreat.mobilethreat
  (:use [tawny.owl])
  (:require [tawny.owl :refer :all]
            [tawny.english]
            [tawny.reasoner :as r]))


(defontology mThreat
  :iri "http://www.russet.org.uk/tawny/mobilethreat/mthreat"
  :comment "An ontology for mobile threat Catalogue (MTC), which describes, identifies, and structures the threats posed to mobile information systems."
  )

(r/reasoner-factory :hermit)

;;OWL CLASSES

(defclass threat
  :comment "The threat is a potential negative action or event facilitated by a vulnerability that results in an unwanted impact on a computer system, application and mobile devices.")

(defclass threatCategories)
(defoproperty hasCategory
  :domain threat
  :range threatCategories)

(as-disjoint-subclasses
 threatCategories
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


(save-ontology "mobilethreat.omn" :omn)
(save-ontology "mobilethreat.owl" :owl)
