(ns mobilethreat.mobilethreat-test
    (:use [clojure.test])
    (:require
     [mobilethreat.mobilethreat :as ont]
     [tawny.owl :as o]
     [tawny.reasoner :as r]
     [tawny.fixture :as f]))

(use-fixtures :each (f/reasoner :hermit))

(deftest reasonable
  (is (r/consistent? ont/mThreat))
  (is (r/coherent? ont/mThreat)))
