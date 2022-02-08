(ns mobilethreat.mobilethreat
  (:use [tawny.owl])
  (:require [tawny.owl :refer :all]
            [tawny.english]
            [tawny.reasoner :as r]))


(defontology mobilethreat
  :iri "http://www.russet.org.uk/tawny/mobilethreat/mobilethreat"
  :comment "An ontology for mobile threat Catalogue (MTC), which describes, identifies, and structures the threats posed to mobile information systems."
)

(r/reasoner-factory :hermit)

(defclass threat
:comment "The threat is a potential negative action or event facilitated by a vulnerability that results in an unwanted impact on a computer system, application and mobile devices.")

(defclass threatCategories)
