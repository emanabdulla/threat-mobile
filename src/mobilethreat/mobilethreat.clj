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
 ;; :characteristic :transitive
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

(as-disjoint-subclasses
 Application
 (defclass VulnerableApplications
   :comment "This subcategory contains threats relating to discrete software vulnerabilities residing within mobile applications running atop the mobile operating system.")

 (defclass MaliciousOrprivacy-invasiveApplication
   :comment "This subcategory identifies mobile malware based threats, based in part off of Google's mobile classification taxonomy."))

(defclass Actor
  :comment " is a participant (person or group) in an action or  perform the possible countermeasures")

(as-disjoint-subclasses
 Actor
 (defclass MobileDeviceUser)
 (defclass MobileAppDeveloper)
 (defclass Enterprise))


;;(defdproperty hasID :domain threatCategories :range string)

;;; annotation properties
(defaproperty hasID)
(defaproperty Description)

;;Application's Threat list
(defclass EavesdroppingOnUnencrytedAppTraffic 
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-0")
                                        ;(has-value hasID "APP-0")
  (annotation Description "Transmission of app or device data unencrypted allows any attacker with access to the physical media channel (e.g. proximity to wireless radios) to intercept that data. Even if the data is not directly sensitive, it may in combination with other data, allow an attacker in infer sensitive information or conduct other attacks against the user or device (e.g. geo-physical tracking, social engineering, phishing, watering-hole attacks)")
                             ;(owl-comment "description: Transmission of.......")
  )

(defclass ManInTheMiddleAttackOnServerAuthentication 
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-1")  
  (annotation Description "Apps that exchange information with a back-end server should strongly authenticate the server before attemtping to establish a secure connection. If the authentication mechanism used by the app is weak, such as not validating a server certificate, an attacker can readily impersonate the back-end server to the app and achieve a man-in-the-middle (MITM) attack. This would provide an attacker with unauthorized access to all unencrypted transmitted data, including modification of data-in-transit. A successful MITM greatly facilitates further attacks against the client app, the back-end server, and all parties of a compromised session."))

(defclass SensitiveInformationExposure
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-2")  
  (annotation Description "Mobile OS APIs allow apps to share data with other apps, either by exposing specific services to other apps (e.g. Android intents) or by storing it to locations accessible to other apps. Sensitive information stored in commonly-accessible files/locations (e.g. OS-managed contacts list) or openly accessible through intents may be read or potentially modified by apps untrusted by the developer, which may lead to a loss of confidentiality, integrity, or availability of that data."))

(defclass SensitiveInformationInSystemLogs
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-3")  
  (annotation Description "Mobile application developers may unintentionally expose sensitive information by storing it in system logs designed to troubleshoot problems. An example would be logging the username and password for a failed user-to-app authentication attempt. An attacker with access to the system log would gain unauthorized access to the information."))


(defclass NeedtoUseAKnownVulnerableAppOrDevice
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-4")  
  (annotation Description "Organizations or individual users may develop and rely upon specific apps or devices to complete necessary work. Knowledge of a serious vulnerability affecting such an app or device increases the risk associated with using it to accomplish that work. However, the impact of being unable to complete the work as a result of abstaining from use of the app or device, may be unacceptable."))

(defclass MaliciousCodeDownloadedViaMaliciousURL
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-5")  
  (annotation Description "A URL can refer to a broad spectrum of resource types, some of which can contain code that is executed by the process that requests it. The malicious code may automatically function in the target context, such as a script that is allowed to execute in a web browser, or it may require the presence of a vulnerability in the app that downloaded it that is exploited during an attempt to process the content, such as a buffer overflow attack."))


(defclass VulnerableThird-PartyLibrary
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-6")  
  (annotation Description "A mobile app may not directly contain vulnerabilities in its code, but may make calls to a third-party library that does contain vulnerabilities that are exploitable by a remote attacker."))

(defclass DataOrFuncionalityExposedToUntrustedApps
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-7")  
  (annotation Description "Android apps can be designed to share data with other apps through a variety of mechanisms such as broadcast receivers, services, intents, and content providers. Some of these mechanisms permit the app developer to grant broader permissions to untrusted apps than intended. As a result, a malicious app may gain unauthorized access to sensitive functionality or data. The malicious app may further take advantage of the weak permission to exploit other vulnerabilities in the receiving app by sending it crafted input."))

(defclass WebViewAppVulnerableToBrowser-BasedAttacks
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-8")  
  (annotation Description "A mobile app that implement a WebView, which allows it to render and potentially perform actions available in a web page, may contain vulnerabilities to common browser-based attacks, such as cross-site request forgery, cross-site scripting, and injection of malicious dynamic content (e.g., JavaScript). Further, exploits delivered over web pages may allow remote exploitation of vulnerabilities in other app components, thereby gaining access to data or functionality outside the context of the vulnerable WebView."))


(defclass CompromisedBackendServer
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-9")  
  (annotation Description "If an app exchanges data with a compromised back-end server, it may be vulnerable to exploitation from what may be treated as a trusted system. This may provide an attacker with unauthorized access to sensitive user data or remote control over app behavior or content." ))

(defclass PoorlyImplementedCryptography
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-10")  
  (annotation Description "While still supported by many systems, cryptographic algorithms and ciphers proven to be weak or broken should not be used to protect sensitive data. Weak algorithm/ciphers are those that have been deprecated following advancements in processing speeds and distributed processessing that have made brute-force attacks against them feasible. Broken algorithms, such as MD5, have known vulnerabilities an attacker can exploit to defeat one or more of its security properties. Similarly, the use of novel (e.g. home-grown) cryptographic algorithms should also be avoided. Novel algorithms may not have yet undergone sufficient scrutiny by the cryptologic community at large, and may possess flaws that if discovered, present an attacker with a path of lesser resistance to achieving unauthorized access to any data these cryptographic mechanisms were designed to protect." ))

(defclass UntrustedInputToSensitiveOperations
  :super VulnerableApplications
  :annotation
  (annotation hasID "APP-11")  
  (annotation Description "Applications often have a need to dynamically incorporate input into sensitive operations such as access control decisions (e.g. authentication) or database operations. However, if a sensitive operation acts on untrusted and unsafe input, it may not function as intended. An attacker with control over such input can potentialy craft it to control application or system behavior. Prime examples of exploits include buffer overflow and code injection attacks. Therefore, it is important to evaluate untrusted input for safeness in the context in which it will be processed prior to accepting it."))


(defclass MaliciousDeviceInformationGathering
  :super MaliciousOrprivacy-invasiveApplication
  :annotation
  (annotation hasID "APP-12")  
  (annotation Description "Persistent information that can be used to identify or characterize a specific mobile device in one or more contexts, such as IMEI, IMSI, MAC address, phone number, mobile OS, or installed apps, may be collected by a malicious or privacy-invasive app to facilitate future attacks. These values, particularly in combination, greatly increase potential for geo-physical or behavioral tracking, device fingerprinting, and impersonation attacks against the device or its user."))

(defclass SensitiveInformationDiscoveryViaOSAPIs
  :super MaliciousOrprivacy-invasiveApplication
  :annotation
  (annotation hasID "APP-13")  
  (annotation Description "Apps may be granted permission, by the user or by default, access common data stores provided by the mobile OS. Common stores are contacts lists, call history, calendar, notes, or app clipboard. When apps used in differing personal and enterprise contexts have access to these stores, they may contain co-mingled personal and enterprise data. A malicious or invasive app granted access to these locations can collect any sensitive data stored there, likely with an intent to exfiltrate it to the attacker."))



(defclass MasqueradeAsLegitimateApplication
  :super MaliciousOrprivacy-invasiveApplication
  :annotation
  (annotation hasID "APP-14")  
  (annotation Description "Like well-behaved apps, a trojan app offers some functionality to the user, though a trojan also includes hidden functionality that is malicious or otherwise undesirable. One technique for deploying trojan functionality is to obtain the install packages for a legitimate app, decompile/disassemble it, introduce the trojan, and then generate a new install package. The app will appear to a user to be the legitimate app. Distribution of trojans is commonly achieved by submission to open 3rd party app stores or social engineering attacks claiming to offer users the app with incentives (lower cost, free, extras unlocked, etc.)"))




;;(defclass Distribution of malicious apps by a 3rd party store
 ;;:super MaliciousOrprivacy-invasiveApplication
  ;; :annotation
  ;;(annotation hasID "APP-15")  


 

(defclass PremiumSMSFraud
  :super MaliciousOrprivacy-invasiveApplication
  :annotation
  (annotation hasID "APP-16")  
  (annotation Description "SMS messages were initially charged to a cellular subscriber’s account on a per-message basis. However, some services use SMS messaging as a subscription or one-time payment method. The charge associated with the SMS message is placed on the cellular subscriber’s account and collected along with standard cellular service fees. This model enables malicious app developers to potentially collude with premium SMS service providers to commit fraud against users. The subscriber is held responsible for the fraudulent charges by the cellular carrier. Early forms of this attack exploited the weak OS permission models that allowed apps to send premium SMS messages without user interaction, which prompted improvement by affected OS developers. Contemporary variants must instead exploit vulnerabilities in the mobile OS to send messages without user knowledge and consent."))

(defclass InterceptingSMSMessages
  :super MaliciousOrprivacy-invasiveApplication
  :annotation
  (annotation hasID "APP-17")  
  (annotation Description "Prior to Android 4.4, apps granted permissions to SMS messaging functionality had the ability to listen for and receive incoming SMS messages. If the app was registered as the highest priority listener for messages, it could silently (without notice to the user) intercept, read, and dispose of messages intended for other apps. One serious abuse of this was the interception of one-time passwords (OTP) used for two-factor authentication (2FA) sent over SMS. Newer versions of Android do not permit apps with permission to access SMS messaging to receive or dispose of SMS messages directly. Unlike Android, the iOS security model does not permit apps with access to SMS messaging. Malicious apps may still realize this threat following exploitation of OS vulnerabilities that bypass access control on private SMS messaging APIs or achieve arbitrary code execution."))

;;(defclass Premium Service Fraud
 ;; (annotation hasID "APP-18")  

(defclass AudioOrVideoSurveillance
  :super MaliciousOrprivacy-invasiveApplication
  :annotation
  (annotation hasID "APP-19")  
  (annotation Description " Starting with Android 6.0, access to the microphone or camera is considered a dangerous permission and each recording attempt must be granted permission by the user at runtime. Similarly, the iOS security model only allows apps granted permission by the user to access the camera or microphone while running in the foreground. Therefore, an app operating in these or newer environments cannot abuse public APIs to initiate a recording outside the user’s knowledge. This threat can still be realized following successful exploits of OS vulnerabilities that ultimately provide a malicious app with unauthorized access to those resources (e.g. bypass access control on APIs or direct access to the hardware)."))




(save-ontology "mobilethreat.omn" :omn)
(save-ontology "mobilethreat.owl" :owl)
