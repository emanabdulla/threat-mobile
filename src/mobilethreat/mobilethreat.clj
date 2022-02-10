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
 ; :characteristic :transitive
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
(as-disjoint-subclasses
 Application
 (defclass VulnerableApplication
   :comment "This subcategory contains threats relating to discrete software vulnerabilities residing within mobile applications running atop the mobile operating system.")

 (defclass MaliciousOrprivacy-invasiveApplication
   :comment "This subcategory identifies mobile malware based threats, based in part off of Google's mobile classification taxonomy."))


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
  :super   VulnerableApplication
  :annotation
  (annotation Id "APP-0")
  (Description "Transmission of app or device data unencrypted allows any attacker with access to the physical media channel (e.g. proximity to wireless radios) to intercept that data. Even if the data is not directly sensitive, it may in combination with other data, allow an attacker in infer sensitive information or conduct other attacks against the user or device (e.g. geo-physical tracking, social engineering, phishing, watering-hole attacks)" "ddddddd")
(CVEExamples "CVE-2017-2412")
(CVEExamples "CVE-2015-4640")
  ;(owl-comment "description: Transmission of.......")
  ;(has-value hasID "APP-0")
)
(defclass Man-In-The-Middle-AttackOnServerAuthentication 
  :super VulnerableApplication
  :annotation
  (annotation Id "APP-1")  
  (Description "Apps that exchange information with a back-end server should strongly authenticate the server before attemtping to establish a secure connection. If the authentication mechanism used by the app is weak, such as not validating a server certificate, an attacker can readily impersonate the back-end server to the app and achieve a man-in-the-middle (MITM) attack. This would provide an attacker with unauthorized access to all unencrypted transmitted data, including modification of data-in-transit. A successful MITM greatly facilitates further attacks against the client app, the back-end server, and all parties of a compromised session.")
(CVEExamples "CVE-2016-3664")
(CVEExamples "CVE-2014-5618"))

(defclass SensitiveInformationExposure
  :super VulnerableApplication
  :annotation
  (annotation Id "APP-2")  
  (Description "Mobile OS APIs allow apps to share data with other apps, either by exposing specific services to other apps (e.g. Android intents) or by storing it to locations accessible to other apps. Sensitive information stored in commonly-accessible files/locations (e.g. OS-managed contacts list) or openly accessible through intents may be read or potentially modified by apps untrusted by the developer, which may lead to a loss of confidentiality, integrity, or availability of that data.")
(CVEExamples "CVE-2011-1717"))

(defclass SensitiveInformationInSystemLogs
  :super VulnerableApplication
  :annotation
  (annotation Id "APP-3")  
  (Description "Mobile application developers may unintentionally expose sensitive information by storing it in system logs designed to troubleshoot problems. An example would be logging the username and password for a failed user-to-app authentication attempt. An attacker with access to the system log would gain unauthorized access to the information.")
(CVEExamples "CVE-2012-2630")
(CVEExamples "CVE-2014-0647"))

(defclass NeedtoUseAKnownVulnerableAppOrDevice
  :super VulnerableApplication
  :annotation
  (annotation Id "APP-4")  
  (Description "Organizations or individual users may develop and rely upon specific apps or devices to complete necessary work. Knowledge of a serious vulnerability affecting such an app or device increases the risk associated with using it to accomplish that work. However, the impact of being unable to complete the work as a result of abstaining from use of the app or device, may be unacceptable.")
(CVEExamples "CVE-2016-5340")
(CVEExamples "CVE-2016-2059")
(CVEExamples "CVE-2016-2503")
(CVEExamples "CVE-2016-2504")

)

(defclass MaliciousCodeDownloadedViaMaliciousURL
  :super VulnerableApplication
  :annotation
  (annotation Id "APP-5")  
  (Description "A URL can refer to a broad spectrum of resource types, some of which can contain code that is executed by the process that requests it. The malicious code may automatically function in the target context, such as a script that is allowed to execute in a web browser, or it may require the presence of a vulnerability in the app that downloaded it that is exploited during an attempt to process the content, such as a buffer overflow attack.")
(CVEExamples "CVE-2010-1797")
(CVEExamples "CVE-2010-2973"))






;(CVEExamples "")

(save-ontology "mobilethreat.omn" :omn)
(save-ontology "mobilethreat.owl" :owl)
