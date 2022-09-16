<!-- Open Web Application Security Project (OWASP)  -->

## 1. Injection 
   - Occurs when untrusted data is sent to a server as part of a command or query
   - Data can be stolen, modified or deleted 

&nbsp;

  ### How to prevent? 
   - Reject untrusted/invalid input data
   - Use latest frameworks
   - Typically found by penetration testers / secure code review

---

&nbsp;

## 2. Broken Authentication and Session Management
 
  ### What is it? 
   - Incorrectly build authorization and session management scheme that allows an attacker to impersonate another user

&nbsp;

  ### What is the impact?
   - Attacker can take identity of victim

&nbsp;

  ### How to prevent? 
   - Don't develop your own authentication schemes
   - Use open source frameworks that are actively maintained by the community
   - Use strong passwords
   - Require current credential when sensitive information is requested or changed
   - Multi-factor authentication
   - Log out or expire session after X amount of time
   - Be careful with 'remember me' functionality

---

&nbsp;

## 3. Cross-Site Scripting (XSS)

  ### What is it? 
   - Untrusted user input is interpreted by browser and executed

&nbsp;

  ### What is the impact?
   - Hijack user sessions, deface web sites, change content

&nbsp;

  ### How to prevent?
   - Escape untrusted input data
   - Latest UI framework

---

&nbsp;

## 4. Broken Access Control

  ### What is it?
   - Restrictions on what authenticated users are allowed to do are not properly enforced

&nbsp;

  ### What is the impact?
   - Attackers can assess data, view sensitive files and modify data

&nbsp;

  ### How to prevent? 
   - Application should not solely rely on user input; check access rights on UI level and server level for requests to resources (e.g. data)
   - Deny access by default

---

&nbsp;

## 5. Security Misconfiguration 

  ### What is it? 
   - Human mistake of misconfigurating the system (e.g. providing a user with a default password)
  
&nbsp;

  ### What is the impact? 
   - Depends on the misconfiguration. Worst misconfiguration could result in loss of the system

&nbsp;

  ### How to prevent? 
   - Force change of default credentials
   - Least privilege: turn everything off by default (debugging, admin interface, etc)
   - Static tools that scan code for default settings
   - Keep patching, updating and testing the system
   - Regularly audit system deployment in production

---

&nbsp;

## 6. Sensitive Data Exposure

  ### What is it? 
   - Sensitive data is exposed, e.g. social security numbers, passwords, health records
  
&nbsp;

  ### What is the impact? 
   - Data that are lost, exposed or corrupted can have severe impact on business continuity
  
&nbsp;

  ### How to prevent? 
   - Always obscure data (credit card numbers are almost always obscured)
   - Update cryptographic algorithm (MD5, DES, SHA-0 and SHA-1 are insecure)
   - Use salted encryption on storage of passwords

---

&nbsp;

## 7. Insufficient Attack Protection

  ### What is it? 
   - Applications that are attacked but do not recognize it as an attack, letting the attacker attack again and again

&nbsp;

  ### What is the impact?
   - Leak of data, decrease application availability

&nbsp;

  ### How to prevent?
   - Detect and log normal and abnormal use of application
   - Respond by automatically blocking abnormal users or range of IP addresses
   - Patch abnormal use quickly

---

&nbsp;

## 8. Cross-Site Request Forgery (CSRF)

  ### What is it?
   - An attack that forces a victim to execute unwanted actions on a web application in which they're currently authenticated
  
&nbsp;

  ### What is the impact? 
   - Victim unknowingly executes transactions 

&nbsp;

  ### How to prevent?
  - Reauthenticate for all critical actions (e.g. transfer money)
  - Include hidden token in request
  - Most web frameworks have built-in CSRF protection, but isn't enabled by default

---

&nbsp;

## 9. Using Components with Known Vulnerabilities

  ### What is it?
   - Third-party components that the focal system uses (e.g. authentication frameworks)
  
&nbsp;

  ### What is the impact?
   - Depending on the vulnerability it could range from subtle to seriously bad
  
&nbsp;

  ### How to prevent?
   - Always stay current with third-party components
   - If possible, follow best practice of virtual patching

---

&nbsp;

## 10. Underprotected APIs

  ### What is it? 
   - Applications expose rich connectivity options through APIs, in the browser to a user. These APIs are often unprotected and contain numerous vulnerabilities
  
&nbsp;

  ### What is the impact?
   - Data theft, corruption, unauthorized access, etc

&nbsp;

  ### How to prevent?
   - Ensure secure communication between client browser and server API
   - Reject untrusted/invalid input data
   - Use latest framework
   - Vulnerabilities are typically found by penetration testers and secure code reviewers

---

&nbsp;

## 11. XML External Entities (XXE) 

  ### What is it?
   - Many older or poorly configured XML processors evaluate external entity references within XML documents

&nbsp;

  ### What is the impact?
   - Extraction of data, remote code execution and denial of service attack

&nbsp;

  ### How to prevent?
   - Use JSON, avoiding serialization of sensitive data
   - Patch or upgrade all XML processors and libraries
   - Disable XXE and implement whitelisting
   - Detect, resolve and verify XXE with static application security testing tools

---

&nbsp;

## 12. Insecure Deserialization 
 
  ### What is it? 
   - Error in translations between objects
  
&nbsp;

  ### What is the impact? 
   - Remote code execution, denial of service. Impact depends on type of data on that server

&nbsp;

  ### How to prevent?
   - Validate user input
   - Implement digital signatures on serialized objects to enforce integrity
   - Restrict usage and monitor deserialization and log exceptions and failures

---

&nbsp;

## 13. Insufficient Logging & Monitoring

  ### What is it? 
   - Not able to witness or discover an attack when it happens or happened
  
&nbsp;

  ### What is the impact? 
   - Allows attacker to persist and tamper, extract, or destroy your data without you noticing it

&nbsp;

  ### How to prevent?
   - Log login, access control and server-side input validation failures
   - Ensure logs can be consumed easily, but cannot be tampered with
   - Continuously improve monitoring and alerting process
   - Mitigate impact of breach: Rotate, Repave and Repair

---

&nbsp;

## 14. Cryptographic Failures

  ### What is it?
   - Ineffective execution & configuration of cryptography (e.g. FTP, HTTP, MD5, WEP)

&nbsp;

  ### What is the impact? 
   - Sensitive Data Exposure

&nbsp;

  ### How to prevent?
   - Never roll your own crypto! Use well-known open source libraries
   - Static code analysis tools can discover this issue
   - Key management (creation, destruction, distribution, storage and use)

---

&nbsp;

## 15. Insecure Design

  ### What is it? 
   - A failure to use security by design methods/principles resulting in a weak or insecure design

&nbsp;

  ### What is the impact? 
   - Breach of confidentiality, integrity and availability

&nbsp;

  ### How to prevent?
   - Secure lifecycle (embed security in each phase; requirements, design, development, test, deployment, maintenance and decommissioning)
   - Use manual (e.g. code review, threat modelling) and automated (e.g. SAST and DAST) methods to improve security

---

&nbsp;

## 16. Software and Data Integrity Failures
 
  ### What is it? 
   - E.g. an application that relies on updates from a trusted external source, however the update mechanism is compromised

&nbsp;

  ### What is the impact?
   - Supply chain attack; data exfiltration, ransomware, etc

&nbsp;

  ### How to prevent? 
   - Verify input (in this case software updates with digital signatures)
   - Continuously check for vulnerabilities in dependencies
   - Use Software Bill of materials
   - Unconnected back ups

---

&nbsp;

## 17. Server-Side Request Forgery

  ### What is it?
   - Misuse of prior established trust to access other resources. A web application is fetching a remote resource without validating the user-supplied URL

&nbsp;

  ### What is the impact?
   - Scan and connect to internal services. In some cases the attacker could access sensitive data

&nbsp;

  ### How to prevent?
   - Sanitize and validate all client-supplied input data
   - Segment remote server access functionality in separate networks to reduce the impact
   - Limiting conenctions to specific ports only (e.g. 443 for https)

---

&nbsp;

## Bonus

  1. Defense in depth
  2. STRIDE (basics)
  3. Secure development processes

&nbsp;

## 1. Defense in Depth
 * Data 
      --> Database Security (online storage & backups)
      --> Content Security, Information Rights Management
      --> Message Level Security


 * Application 
      --> Federation (SSO, Identity Propagation, Trust, ...)
      --> Authentication, Authorization, Auditing (AAA)
      --> Security Assurance (coding practices)


 * Host
      --> Platform O/S
      --> Vulnerability Management(patches)
      --> Desktop (malware protection)


 * Internal Network
      --> Transport Layer Security (encryption, identity)
      --> Firewalls, network address translation, denial of service prevention, message parsing and validation, ...


 * Perimeter
      --> Transport Layer Security (encryption, identity)
      --> Firewalls, network address translation, denial of service prevention, message parsing and validation, ...


 * Physical
      --> Fences, walls, guards, locks, keys, badges, ...


 * Policies, Procedures, & Awareness
      --> Data Classification, Password Strengths, Code Reviews, Usage Policies

&nbsp;

## 2. STRIDE - basics

  ### Why? 
   - Examine what can go wrong
   - What are you going to do about it
   - Determine whether you are doing a good job

&nbsp;

  ### STRIDE 
   - Spoofing 
   - Tampering
   - Repudiation
   - Information discloure
   - Denial of service
   - Elevation of privilege

&nbsp;

## 3. Secure Development Processes

  ### Microsoft Security Development Lifecycle (MS SDL)
   * Training
      - Core training

   * Requirements 
      - Define quality gates/bug bar
      - Analyze security and privacy risk

   * Design
      - Attack surface analysis
      - Threat Modelling

  * Implementation
      - Specify tools
      - Enforce banned functions
      - Static analysis

  * Verification
      - Dynamic/Fuzz testing
      - Verify threat models/attack surface

  * Release 
      - Response plan
      - Final security review
      - Release archive

  * Response
      - Response execution

&nbsp;

## Other secure development processes are:
  - Software Assurance Maturity Model (previously called CLASP)
  - Touchpoints for software security

&nbsp;

## 4. What are Insecure Direct Object References
  
  ### What is it? 
   - A reference to a file, database or directory exposed to user via the browser
  
&nbsp;

  ### What is the impact?
   - Any user can navigate to almost any part of the system and attack the system by modifying the URL through the browser

&nbsp;

  ### How to prevent?
   - Check access rights (e.g. proper authorization)
   - Input validation 

---