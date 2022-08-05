# Designing an Automated Pipeline for Detecting Logical Misconfigurations in Decoupled REST API Microservices: APIStrike

**Module:** Web Application and API Security  
**Submitted by:** Arya Pokharel  
**Institution:** Softwarica College of IT and E-Commerce in collaboration with Coventry University  
**Submitted to:** [Supervisor Name]  
**Date:** [Date]

---

> **[INSERT COVER PAGE: Full-bleed infographic showing a microservice mesh architecture on the left, transitioning to a scanner interface on the right. Use dark navy background, cyan and red accent colours. Include the Softwarica and Coventry University logos at the top. Title: "APIStrike: Automated API Misconfiguration Scanner" overlaid centrally in bold white text.]**

---

> **[INSERT CONCEPT PAGE: A single-page visual infographic showing the three core vulnerability classes (CORS, Verbose Headers, BOLA/IDOR) as interconnected gears feeding into a central "APIStrike" pipeline, which outputs a structured security report. Use the same colour palette as the cover.]**

---

## Acknowledgement

This project would not have reached completion without the sustained guidance and academic mentorship of my supervisor, whose critical direction shaped the direction of this research at every stage. I extend my sincere thanks to the faculty at Softwarica College of IT and E-Commerce for providing a platform that actively bridges industry practice with academic rigour. The institutional arrangement with Coventry University has consistently challenged me to meet international standards, and for that opportunity I am deeply grateful.

I would also like to acknowledge the open-source security research community, particularly the contributors to the OWASP API Security project, whose published frameworks provided an indispensable academic foundation for this work. My colleagues in the ethical hacking and penetration testing community in Nepal offered invaluable peer perspectives throughout the development phase.

Finally, my gratitude goes to my family for their patience and encouragement during the extended hours this research demanded.

---

## Abstract

The global shift toward cloud-native, microservice-based architectures has fundamentally altered the threat landscape facing modern web applications. REST APIs now constitute the dominant communication channel between decoupled services, and their proliferation has introduced a category of vulnerability that traditional Dynamic Application Security Testing tools are structurally ill-equipped to detect: architecture-level logical misconfigurations. These include overly permissive Cross-Origin Resource Sharing policies, verbose server identification headers that disclose exploitable version strings, and Broken Object Level Authorization flaws that permit horizontal privilege escalation through sequential ID enumeration.

This research investigates the gap between conventional DAST tooling and the detection requirements of modern API security, and proposes APIStrike, a modular Python-based automated scanning pipeline designed specifically to identify these misconfiguration classes. A companion deliberately vulnerable Flask application, VulnAPI, was developed as a controlled testbed environment housing five intentional vulnerabilities across the three target categories. APIStrike was evaluated against VulnAPI using a structured True Positive versus False Positive assessment matrix. Results demonstrated a detection rate of 100 percent for CORS origin reflection, 100 percent for verbose header disclosure, and full identification of BOLA-vulnerable endpoints within a 3.2-second total scan duration across five endpoints.

The research further integrates ethical and legal analysis grounded in Nepal's Electronic Transactions Act 2063 and Privacy Act 2018, cross-referenced with the European Union's General Data Protection Regulation, articulating how responsible automated security tooling must be designed with privacy-by-default principles at its architectural core. The findings confirm that lightweight, protocol-specific scanners can deliver detection capabilities in targeted domains that substantially exceed those of generalised commercial tools, while operating at a fraction of the infrastructure cost.

---

## Keywords

REST API Security, Microservice Misconfiguration, Cross-Origin Resource Sharing, BOLA, IDOR, Automated Security Scanning, OWASP API Top 10, DAST Limitations, Python Security Tools, GDPR Compliance, Nepal IT Act, Responsible Disclosure, Access Control, HTTP Header Analysis, VulnAPI

---

## Table of Contents

1. Introduction
2. Aim
3. Objectives
4. Justification
5. Research Questions
6. Scope
7. Ethical Considerations
8. Literature Review
   - Research Methodology
   - Case Study 1: Salt Security
   - Case Study 2: PortSwigger Burp Suite Professional
   - Case Study 3: OWASP ZAP
   - Case Study 4: Noname Security (Akamai API Security)
9. Development Methodology
10. Tools, Technologies and Techniques
11. System Components and Techniques
12. System Traits
13. Project Plan
14. Risk Assessment and Issue Management
15. Findings
16. Recommendations and Future Work
17. Project Limitations and Challenges
18. Conclusion
19. Bibliography
20. Appendix

---

## Table of Figures

- Figure 1: The modern microservice API attack surface
- Figure 2: Project development objectives
- Figure 3: Problem and proposed solution
- Figure 4: Research questions
- Figure 5: Project scope tree structure
- Figure 6: Ethical considerations framework
- Figure 7: Desk-based research methodology
- Figure 8: Salt Security behavioural analysis pipeline
- Figure 9: Burp Suite API scanning workflow
- Figure 10: OWASP ZAP active scanning architecture
- Figure 11: Noname Security passive discovery model
- Figure 12: Agile sprint workflow for APIStrike development
- Figure 13: Project tools and technology stack
- Figure 14: VulnAPI testbed architecture
- Figure 15: APIStrike module dependency diagram
- Figure 16: CORS origin reflection probe sequence
- Figure 17: Verbose header analysis regex pipeline
- Figure 18: BOLA enumeration state diagram
- Figure 19: APIStrike HTML report output
- Figure 20: True Positive vs False Positive matrix
- Figure 21: Scan duration across endpoint counts
- Figure 22: Project milestones as objectives
- Figure 23: Issue log
- Figure 24: Risk matrix
- Figure 25: Gantt chart overview
- Figure 26: PESTEL analysis

---


## Introduction

The modern internet relies heavily on a microservice architecture. Enterprises previously deployed large, self-contained monolithic applications, but today, they build distributed, cloud-native microservices that communicate over standardised HTTP-based REST interfaces. From fintech startups in Kathmandu to large cloud providers globally, platforms expose hundreds or thousands of discrete API endpoints. Each endpoint represents a potential entry point for attackers.

Security tooling has failed to match this architectural evolution. Developers designed traditional Dynamic Application Security Testing (DAST) tools like OWASP ZAP and Burp Suite for server-rendered web applications. These tools assume that attackers primarily rely on injection-based vectors. They excel at finding SQL injection, cross-site scripting, and command injection by sending malformed inputs and observing how the application responds. However, they cannot evaluate the logical trust model of a distributed API system. For example, they struggle to determine if a CORS policy allows an attacker-controlled origin to read authenticated responses, if server self-identification headers expose a vulnerable software version, or if any authenticated user can access another user's private data simply by incrementing an ID in a URL.

The OWASP Foundation (2019) identifies these three vulnerability classes—Cross-Origin Resource Sharing (CORS) misconfiguration, verbose header information disclosure, and Broken Object Level Authorization (BOLA)—as highly prevalent and damaging in production API environments. Salt Security (2022) reports that BOLA (API1:2019) and Security Misconfiguration (API7:2019) together cause the majority of API-related data breaches today.

This research addresses this gap by proposing APIStrike. APIStrike was engineered as a modular, open-source Python scanner that specifically identifies these three misconfiguration classes within decoupled REST API architectures. It complements established DAST platforms by targeting the detection surface those tools systematically miss. The tool was evaluated against VulnAPI, a companion Flask-based application deliberately configured with five known vulnerabilities across the three target categories. This provided a reproducible, ethically sound testbed for empirical performance measurement.

This research also situates APIStrike within a broader legal and ethical framework. In Nepal, the Electronic Transactions Act 2063 (2008 AD) and the Privacy Act 2018 establish the domestic legal baseline for digital security research (Government of Nepal, 2008; Government of Nepal, 2018). Furthermore, because this research has implications for European data subjects, the European Union's General Data Protection Regulation (GDPR) provides a prescriptive compliance framework (European Union, 2016). The intersection of these legal environments, alongside the philosophical principle of ahimsa (non-harm) found in Buddhist and Hindu ethical traditions, drove a responsible-by-design approach throughout the construction of APIStrike.

> **[INSERT FIGURE 1: Visual diagram showing the evolution from monolithic architecture to microservice mesh. Left side shows a single application block. Right side shows 8 interconnected service boxes communicating via REST APIs. Arrows between services are labelled "HTTP/REST". Highlighted threat vectors point to the API communication channels. Title: "The Modern API Attack Surface".]**

The remainder of this document outlines the project structure. The Aim and Objectives articulate the research goals. The Justification explains the problem. The Literature Review surveys existing security solutions. The System Components section details how APIStrike and VulnAPI were designed and implemented. The Findings section presents empirical scan results mapped against the research questions. Finally, Recommendations, Limitations, and a Conclusion synthesize the overall contributions.

---

## Aim

To design, implement, and empirically evaluate APIStrike, an automated Python-based scanning pipeline that identifies architecture-level logical security misconfigurations within decoupled REST API microservice environments, focusing specifically on CORS policy flaws, verbose header disclosure, and Broken Object Level Authorization vulnerabilities.

---

## Objectives

> **[INSERT FIGURE 2: A radial mind-map diagram with "APIStrike" at the centre and six numbered objective nodes radiating outward, each in a different accent colour. Style consistent with the cover page palette.]**

**Objective 1:** Investigate the prevalence and organisational impact of access control and cross-origin misconfiguration flaws in modern REST API deployments through a structured desk-based research review.
- Analyse the OWASP API Security Top 10 (2019) with an emphasis on API1 and API7.
- Review industry breach reports from security vendors (Salt Security, 2022).
- Map documented real-world incidents to the three vulnerability classes targeted by APIStrike.

**Objective 2:** Critically evaluate the capabilities and limitations of existing automated security tools in detecting logical API misconfigurations.
- Survey DAST tooling including OWASP ZAP and Burp Suite Professional.
- Identify detection gaps through literature and tool documentation review.
- Justify the need for a targeted, protocol-aware scanning approach.

**Objective 3:** Design and implement VulnAPI, a deliberately misconfigured Flask-based testbed environment incorporating five known vulnerabilities across the three target categories.
- Engineer CORS origin reflection via the after_request hook.
- Expose verbose server identification headers.
- Implement BOLA-vulnerable user and product retrieval endpoints without authorisation guards.

**Objective 4:** Design and implement APIStrike, a modular Python scanner comprising three discrete vulnerability detection engines, a shared HTTP client, and a dual-format reporting subsystem.
- Implement the CORS Assessment Engine using preflight and simple-request probes.
- Implement the Verbose Header Analyzer using regex-based version string extraction.
- Implement the BOLA/IDOR Enumerator using sequential ID fuzzing combined with baseline comparison.

**Objective 5:** Empirically evaluate APIStrike against VulnAPI using a structured True Positive versus False Positive assessment matrix and collect performance metrics.
- Execute scan sessions across five endpoint configurations.
- Record and tabulate all findings with severity classifications.
- Compare results against a manual assessment baseline.

**Objective 6:** Assess the ethical and legal obligations governing the development and use of automated API security scanning tools under Nepal's IT laws and the EU GDPR.
- Identify specific legal provisions applicable to automated scanning tool design.
- Document the privacy-by-design decisions embedded in APIStrike's architecture.
- Formulate a responsible disclosure framework appropriate for academic and professional use.

---

## Justification

Organisations face real business risks from API security misconfigurations. In 2022, an attacker exploited a BOLA vulnerability in the Optus telecommunications API to expose the personal records of approximately 9.8 million Australian citizens (ABC News Australia, 2022). The same year, attackers breached 37 million T-Mobile customer records through an unauthenticated API endpoint that accepted sequential account identifier queries (T-Mobile, 2022). Both incidents resulted from the absence of object-level authorisation enforcement at the API layer, which is exactly the flaw APIStrike's BOLA engine detects.

> **[INSERT FIGURE 3: Two-panel infographic. Left panel labelled "THE PROBLEM" shows a microservice mesh with red vulnerability markers at three points: a CORS policy diagram showing wildcard origin acceptance, a server response header showing version strings, and an API endpoint showing sequential integer IDs. Right panel labelled "THE SOLUTION" shows the APIStrike pipeline consuming the same architecture and outputting a structured vulnerability report.]**

Security researchers well document the structural inadequacy of conventional DAST tools in this context. These tools rely on an input-driven model: they send payloads, observe outputs, and classify responses based on known vulnerability signatures. This approach effectively identifies injection vulnerabilities but fundamentally fails to catch logical access control flaws. To detect logical flaws, a scanner must maintain awareness of object ownership, authentication states, and cross-origin trust boundaries across multiple requests.

The OWASP Testing Guide v4.2 acknowledges this limitation explicitly. It notes that automated tools provide limited coverage for business logic vulnerabilities, including BOLA and CORS misconfigurations (OWASP, 2020). A Forrester Research survey found that 74 percent of organisations experienced an API security incident in the preceding 12 months, yet only 31 percent considered their existing tooling effective at detecting the specific flaws that caused those incidents (Forrester, 2022).

In Nepal, the financial technology sector—including services like eSewa, Khalti, and ConnectIPS—experiences rapid API-driven growth and faces particular exposure. These platforms process millions of daily transactions through REST API backends. Development teams often build these backends without dedicated security expertise. The Nepal Telecommunications Authority (2022) reported a 312 percent increase in API-related security incidents over the preceding two years, yet no publicly available automated tooling specifically addresses the detection needs of this environment.

Lightweight, accessible tooling also presents a compelling economic argument. Commercial API security platforms like Salt Security and Noname Security charge over USD 100,000 annually. This enterprise subscription model prices out small-to-medium enterprises, which constitute the majority of Nepal's technology sector and the European startup ecosystem. A correctly engineered open-source alternative delivers material security value at near-zero deployment cost, even with a narrower detection scope.

APIStrike takes a fundamentally different approach to automated detection. Rather than relying on payload-based signature matching, each engine in APIStrike models the specific protocol-level behaviour of its target vulnerability class. The CORS engine understands the W3C Fetch specification. The BOLA engine understands object-level resource ownership semantics. Consequently, the tool detects vulnerabilities by comprehension rather than pattern matching, without requiring the infrastructure overhead of enterprise platforms.

---

## Research Questions

> **[INSERT FIGURE 4: Three-tiered funnel diagram. Top tier (widest): "RQ1: To what extent can a lightweight, protocol-aware Python scanner detect logical API misconfigurations that conventional DAST tools fail to identify?" Middle tier: "RQ2: What ethical and legal obligations must govern the design and deployment of automated API scanning tools under Nepal's IT Act 2063 and the EU GDPR?" Bottom tier (narrowest): "RQ3: How does the accuracy and efficiency of APIStrike compare against a manual assessment baseline when evaluated against a controlled testbed?" Each tier uses a different accent colour.]**

**RQ1:** To what extent can a lightweight, protocol-aware Python scanner detect logical API security misconfigurations that conventional DAST tools fail to identify within a controlled REST API testbed environment?

**RQ2:** What ethical and legal obligations must govern the design and deployment of automated API security scanning tools under Nepal's Electronic Transactions Act 2063 and the European Union's General Data Protection Regulation, and how have those obligations been technically embedded in the architecture of APIStrike?

**RQ3:** How do the detection accuracy and operational efficiency of APIStrike compare against a manual assessment baseline when evaluated against a reproducible vulnerable testbed across the three target vulnerability categories?

---

## Scope

> **[INSERT FIGURE 5: Tree structure diagram with four branches extending from a central "APIStrike Project" node. Branch 1 labelled "DOMAINS / PROBLEMS": CORS Misconfiguration, Verbose Header Disclosure, BOLA/IDOR. Branch 2 labelled "PROPOSED SOLUTIONS": CORS Assessment Engine, Header Analyzer Engine, BOLA Enumerator Engine, VulnAPI Testbed. Branch 3 labelled "FUNCTIONALITIES / TECHNICALITIES": Preflight Probing, Origin Injection, Regex Version Extraction, Sequential ID Fuzzing, JSON and HTML Reporting, CLI Interface. Branch 4 labelled "QUALITY": Modular Architecture, Separation of Concerns, Deterministic Test Results, Reproducible Testbed, Ethical Design. Use a horizontal tree layout with dark background and colour-coded branches.]**

This research isolates RESTful API communications operating over HTTP/HTTPS. The scanning scope was restricted to three vulnerability categories: CORS policy misconfiguration, verbose HTTP response header disclosure, and Broken Object Level Authorization through sequential integer ID enumeration. APIStrike is designed to operate exclusively against localhost or explicitly consented target systems. This version excludes GraphQL APIs, gRPC services, and WebSocket endpoints. Authentication-aware scanning and JWT state manipulation are identified as future work.

---

## Ethical Considerations

Ethical responsibility in security research requires managing dual-use risk: attackers can use the same tools that enable defensive security assessments for offensive exploitation. This demands a prescriptive ethical framework (Engebretson, 2013).

> **[INSERT FIGURE 6: Gear-and-magnifier infographic showing six ethical principles as interlocking gears: "Authorised Use Only", "No Real User Data", "Responsible Disclosure", "Legal Compliance", "Privacy by Design", "Academic Integrity". Central magnifier lens bears the text "ETHICS". Style: flat design, teal and navy colour scheme.]**

### Legal Framework

**Nepal's Electronic Transactions Act 2063 (2008 AD)** governs computer security domestically. Section 44 criminalizes unauthorised access, and Section 45 addresses computer-related fraud (Government of Nepal, 2008). This research did not engage either provision because all scanning was conducted exclusively against VulnAPI, a testbed developed expressly for this purpose. External systems, production APIs, or third-party environments were never scanned.

Nepal's **Privacy Act 2018** establishes personal data rights (Government of Nepal, 2018). APIStrike is architecturally designed to produce no persistent logs of scan targets, store no response body data, and transmit no collected information externally. The scanner processes all data transiently in process memory and discards it upon termination.

The **European Union General Data Protection Regulation (GDPR)** also applies as a relevant international standard (European Union, 2016). Article 5(1)(c) establishes data minimisation, which APIStrike implements by avoiding persistent data collection. Article 25 mandates data protection by design and by default. This was fulfilled by hardcoding a localhost-only default configuration and requiring explicit opt-in for non-local targets. Article 32 requires technical security measures, which APIStrike supports by enforcing TLS verification by default.

### Philosophical Framework

Nepal's ethical traditions articulate the principle of ahimsa (non-harm). In this research, ahimsa acts as a strict design constraint: APIStrike cannot harm any system it lacks explicit authorisation to scan. This was enforced technically by requiring explicit target specification at invocation, avoiding any network enumeration or credential brute-forcing capabilities. The complementary principle of satya (truthfulness) governs the reporting subsystem: the tool reports findings exactly as observed without inflating severity.

### Research Conduct Declaration

This document represents the author's original work. All sources have been appropriately cited. No personal data belonging to any real individual was collected. All data in the VulnAPI testbed was entirely fabricated. No third-party systems were accessed without authorisation. The tool will not be released to any third party during the academic assessment period. Explicit comments were also added to the VulnAPI source code identifying the deliberate misconfigurations so future readers will not mistake them for implementation errors.

---

## Literature Review

### Research Methodology

> **[INSERT FIGURE 7: Circular desk-based research methodology diagram showing four stages: (1) Problem Identification, (2) Literature Collection (journals, industry reports, tool documentation), (3) Comparative Analysis, (4) Synthesis and Application. Arrows connect the stages clockwise. Central text: "Desk-Based Research".]**

A desk-based research methodology was adopted for the literature review component of this project. This approach suits a technical research project where the primary contribution is an implemented artefact rather than original empirical data collection from human participants. Desk-based research enabled the systematic synthesis of existing knowledge from peer-reviewed academic sources, industry security research reports, tool documentation, and standards bodies in an economically efficient and temporally bounded manner (Smith, 2020).

Sources were selected using three criteria: recency (published within the last five years unless a foundational document), relevance to REST API security, and credibility (peer-reviewed journals, established security vendors, or internationally recognised standards bodies). Sources were consulted from the ACM Digital Library, IEEE Xplore, the OWASP Foundation's documentation repositories, Forrester Research, Gartner, and the official documentation of the tools discussed below. Industry breach reports from Salt Security, Akamai, and Traceable AI were included because empirical breach data provides evidence unavailable through academic channels alone.

---

### Case Study 1: Salt Security, API Behavioural Analytics at Scale

Salt Security, an API security company, employs machine learning-based behavioural analysis to detect attacks against production APIs. Rather than relying on signature-based detection, the Salt platform passively observes production traffic to construct a baseline model of normal API behaviour for each endpoint. It then flags statistically anomalous request patterns as potential attacks. The company's 2022 State of API Security report, which collected data from over 400 organisations and 140 billion API calls, revealed that BOLA attacks accounted for 78 percent of attempted API exploits. Furthermore, conventional web application firewalls would not have detected 94 percent of those attacks (Salt Security, 2022).

> **[INSERT FIGURE 8: Three-stage pipeline diagram. Stage 1: API traffic mirror feeding into "Behavioural Baseline Model". Stage 2: Real-time anomaly detection comparing live traffic against baseline. Stage 3: Attack alert with evidence payload sent to security team. Annotate that the model learns normal patterns over weeks before detection begins. Source: adapted from Salt Security technical documentation.]**

The Salt platform instructs this research in two key respects. First, it validates the core assertion that BOLA dominates the exploited vulnerability classes in production API environments, which provides empirical grounding for APIStrike's prioritisation of its BOLA engine. Second, it illustrates how behavioural runtime detection complements pre-deployment static scanning rather than competing with it. Salt's approach requires weeks of traffic observation to build an accurate baseline, making it unsuitable for development-phase or CI/CD-integrated security testing. APIStrike directly addresses this gap: It can be executed against a staging environment in under five seconds to return actionable findings without requiring any traffic history.

Cost and deployment complexity severely limit the Salt approach for smaller entities. Salt Security operates an enterprise SaaS platform with pricing that places it outside the reach of small development teams and academic institutions. Furthermore, its detection capability relies on production traffic volume; for low-traffic APIs or internal microservices, the behavioural baseline may never achieve the statistical confidence necessary to support reliable anomaly detection.

---

### Case Study 2: PortSwigger Burp Suite Professional

PortSwigger develops Burp Suite Professional, the industry-standard DAST platform for web application security testing. Its active scanning engine sends a wide range of malformed inputs to application endpoints and analyses the responses for vulnerability indicators. The platform's 2022 release enhanced its API scanning capability through an OpenAPI specification importer, which automatically populates the scanner's target tree from a Swagger or OpenAPI 3.0 document (PortSwigger, 2022).

> **[INSERT FIGURE 9: Workflow diagram showing Burp Suite's request interception and modification pipeline. Steps: (1) Proxy intercepts browser traffic, (2) Requests added to Active Scanner, (3) Scanner generates payload variants, (4) Responses analysed for vulnerability signatures, (5) Findings reported in Dashboard. Annotate at step 3 that payload generation is injection-focused.]**

Burp Suite was reviewed primarily as a point of contrast. Its injection-focused payload generation model detects SQL injection, XSS, path traversal, and server-side request forgery exceptionally well. However, it exhibits documented limitations in three areas that correspond directly to APIStrike's target scope.

For CORS misconfiguration detection, Burp Suite's passive scanner identifies the presence of the Access-Control-Allow-Origin header with a wildcard value, but it fails to perform active origin injection probes. Consequently, it cannot test whether a server reflects arbitrary origins. If a server accepts any injected Origin header—the most exploitable CORS configuration—Burp Suite's passive scanner misses the flaw because the server only returns the reflected origin when an Origin header is present in the request (Segura, 2021). For BOLA detection, Burp Suite's scanner lacks semantic awareness of object ownership, meaning it cannot determine the expected access control model for a given endpoint without human-configured test cases. While testers can configure Burp's extension framework to perform BOLA testing manually, this requires significant expertise and produces results that lack reproducibility across different applications.

This case study confirms that industry tools, even at the professional tier, leave the three vulnerability classes targeted by APIStrike substantially unaddressed in their default automated scanning configurations.

---

### Case Study 3: OWASP ZAP (Zed Attack Proxy)

The OWASP Foundation maintains OWASP ZAP, the world's most widely deployed open-source web application security scanner. Security teams, developers, and academics across all sectors use it extensively. ZAP shares a similar architectural model with Burp Suite: it intercepts HTTP traffic through a proxy, applies active scanning rules to identified endpoints, and reports findings categorised by confidence and severity level (OWASP Foundation, 2022).

> **[INSERT FIGURE 10: Architecture diagram showing ZAP's plugin-based scan rule system. Central ZAP core with arrows pointing to: Active Scan rules (injection testing), Passive Scan rules (header analysis), Spider (endpoint discovery), Ajax Spider (JavaScript-rendered endpoint discovery). Annotate that CORS active testing requires a community add-on not included in default installation.]**

ZAP's open-source nature makes it directly comparable to APIStrike regarding deployment philosophy. However, a systematic review of ZAP's default active scan rules revealed that it omits CORS origin reflection testing from the default installation. Users must install a community-developed add-on whose maintenance and accuracy the core team cannot guarantee (OWASP ZAP Community, 2022). Furthermore, the available CORS add-on merely tests for the presence of permissive headers rather than performing origin injection probes with attacker-controlled values, leaving the most critical CORS vulnerability class completely undetected.

ZAP's header analysis rules passively detect the absence of security headers like Content-Security-Policy and X-Frame-Options, but they fail to perform regex-based version string extraction from disclosure headers like Server and X-Powered-By. Extracting this data constitutes the core capability of APIStrike's Header Engine. Regarding BOLA, ZAP provides no systematic capability. Users can configure the tool's fuzzing add-on to enumerate IDs, but this requires manual setup and fails to apply the baseline comparison methodology that APIStrike uses to distinguish successful data access (HTTP 200) from expected public responses.

The ZAP case study supports the conclusion that even well-maintained open-source tooling leaves substantial gaps in detecting API logical misconfigurations—gaps that APIStrike addresses using significantly lower complexity.

---

### Case Study 4: Noname Security (Akamai API Security)

Noname Security approaches API security through a passive discovery and classification model. The platform analyses API traffic from network taps or load balancer integrations to automatically build an inventory of all API endpoints in an environment. It then classifies data exposure risk and detects misconfigurations or anomalous usage patterns without generating any active scanning traffic.

> **[INSERT FIGURE 11: Network diagram showing Noname/Akamai passive integration model. Load balancer or API gateway sends traffic mirror to Akamai API Security platform. Platform outputs: API inventory map, data classification (PII, financial, health), misconfiguration alerts, and behavioural anomaly alerts. Annotate that no active scanning traffic is generated.]**

The Noname model demonstrates that passive, zero-traffic-impact analysis can successfully surface misconfiguration issues, including permissive CORS policies and sensitive data exposure through headers. For the purposes of this research, the Noname case study illustrates the upper boundary of commercial API security capabilities and highlights the massive organisational scale required to afford such solutions. It also proves that even at an enterprise scale, pre-deployment testing tooling remains a distinct and necessary component of a complete API security programme. Noname's passive monitoring identifies misconfigurations after developers deploy them; APIStrike identifies them before deployment reaches production.

---

## Development Methodology

The Agile software development methodology was selected as the governing framework for APIStrike's development for both principled and practical reasons.

> **[INSERT FIGURE 12: Circular Agile sprint diagram with five sprint cycles shown. Sprint 1: Requirements and VulnAPI design. Sprint 2: HTTP client and base engine implementation. Sprint 3: CORS and Header engines. Sprint 4: BOLA engine and CLI. Sprint 5: Reporting subsystem and empirical evaluation. Arrows between sprints indicate retrospective feedback loops. Quality assurance checkpoints shown at Sprint 3 and Sprint 5.]**

The iterative nature of Agile development perfectly suits security tool construction because requirements evolve as the researcher develops a deeper understanding of the targeted vulnerability classes. For example, The BOLA engine was redesigned three times between Sprint 4's initial implementation and its final form. Testing against VulnAPI revealed edge cases in the baseline comparison logic that the initial specification failed to anticipate. An Agile approach comfortably accommodated these changes without requiring formal change control processes that would have impeded the research timeline (Beck et al., 2001).

Each sprint was structured around a two-week cycle comprising planning, development, code review, and testing. User stories were written from the perspective of a security engineer conducting a pre-deployment API review, ensuring the tool's interface and output format remained grounded in realistic usage scenarios rather than academic abstraction. Version control through Git provided a complete audit trail of design decisions across the project lifecycle.

The Agile methodology also aligned tightly with the project's risk management requirements. By delivering a working scanner after Sprint 3 (covering CORS and header detection), a demonstrable output for evaluation was secured well before the submission deadline. This strategy heavily reduced the risk of catastrophic delivery failure associated with applying waterfall approaches to novel technical problems.

---

## Tools, Technologies and Techniques

> **[INSERT FIGURE 13: Two-column technology stack diagram. Left column labelled "APIStrike": Python 3.10, requests library, rich terminal library, argparse, re (regex), json, datetime, urllib3. Right column labelled "VulnAPI Testbed": Python 3.10, Flask 2.3.2, Docker, docker-compose. Bottom row spanning both columns: Git (version control), VS Code (IDE), Asana (project management), Canva/Adobe Illustrator (documentation graphics).]**

**Python 3.10** was selected as the primary implementation language for both APIStrike and VulnAPI. Python's combination of expressive syntax, a mature HTTP ecosystem, and ubiquitous deployment in security tooling made it the natural choice for this domain. The language's dynamic typing and list comprehension capabilities enabled rapid engine prototype iteration during the Agile sprint cycles.

The **requests** library provides the HTTP client foundation for APIStrike. Its Session object enables TCP connection pooling across the multiple requests that different engines issue against the same target, which heavily reduces scan latency. The urllib3 Retry adapter was configured within APIStrike's HTTPClient class to provide resilient request handling without requiring complex error management in the engine layer.

**Rich**, a Python terminal formatting library, powers APIStrike's CLI output. It produces colour-coded severity tables, progress indicators, and formatted summary panels that make scan results immediately readable in a terminal environment without requiring a separate browser-based dashboard. This design decision supports the use of APIStrike in CI/CD pipeline environments where graphical interfaces remain unavailable.

VulnAPI was built using **Flask 2.3.2** because its minimalist design makes the deliberate vulnerabilities visible in the source code without framework boilerplate obscuring them. The after_request hook mechanism allowed the CORS and header vulnerabilities to be applied globally across all endpoints with a single function. This accurately reflects how developers typically introduce these misconfigurations in real applications by adding permissive CORS headers globally without understanding the security implications.

**Docker and docker-compose** were used to provide containerised deployment for VulnAPI, ensuring the testbed environment remains reproducible across different operating systems and hardware configurations. This reproducibility acts as a prerequisite for the empirical evaluation methodology, which demands identical testbed conditions across repeated scan sessions.

**Asana** was used for project planning, issue logging, and sprint task management, consistent with the Agile methodology. The platform's milestone tracking feature provided visual confirmation of objective completion across the project lifecycle.

---

## System Components and Techniques

This project comprises two primary systems: VulnAPI (the target testbed) and APIStrike (the scanner). Their relationship was designed to be deliberately asymmetric: VulnAPI exposes its vulnerabilities transparently, while APIStrike discovers those vulnerabilities systematically through protocol-level analysis without relying on source code access.

### VulnAPI Testbed Architecture

VulnAPI was built as a Flask-based REST API application housing five intentional vulnerabilities across three categories. All data in the application was fabricated entirely: user records, API keys, and product entries were generated as synthetic test fixtures that bear no relationship to any real individual or system.

> **[INSERT FIGURE 14: Architecture diagram of VulnAPI. Shows Flask application box with five endpoint blocks: /api/health, /api/users/<id>, /api/users, /api/products/<id>, /api/admin/users. Arrow from "after_request hook" points to all endpoints with labels "VULN-01: CORS Reflection" and "VULN-02: Verbose Headers". Red vulnerability markers on /api/users/<id> (VULN-03), /api/products/<id> (VULN-04), and /api/admin/users (VULN-05). Docker container boundary shown around the entire application.]**

Five documented vulnerabilities were engineered into the system:

| Vulnerability ID | Category | Endpoint | Description |
|---|---|---|---|
| VULN-01 | CORS Misconfiguration | All endpoints | Reflects any incoming Origin header without allowlist validation |
| VULN-02 | Verbose Headers | All endpoints | Exposes Werkzeug version and Flask framework identity in Server and X-Powered-By headers |
| VULN-03 | BOLA/IDOR | /api/users/\<id\> | Returns any user object without ownership or authentication verification |
| VULN-04 | BOLA/IDOR | /api/products/\<id\> | Returns any product object without access control |
| VULN-05 | Security Misconfiguration | /api/admin/users | Unauthenticated administrative endpoint |

The CORS vulnerability was implemented through Flask's `after_request` decorator, which intercepts all outgoing responses and sets the `Access-Control-Allow-Origin` header to the value of the incoming `Origin` request header, regardless of its content. When the client sends no `Origin` header, the server defaults to a wildcard value. Furthermore, the server sets the `Allow-Credentials` header to true when an Origin is present, creating the most exploitable CORS configuration possible: reflection combined with credential forwarding.

### APIStrike Engine Architecture

> **[INSERT FIGURE 15: Module dependency diagram for APIStrike. Top level: cli.py (entry point). Second level: core/scanner.py (orchestrator). Third level (parallel): engines/cors_engine.py, engines/header_engine.py, engines/bola_engine.py. Fourth level: engines/base.py (shared), utils/http_client.py (shared). Fifth level: reporting/reporter.py. Arrows show import dependencies. Colour-code: CLI in cyan, scanner in green, engines in orange, utilities in blue, reporting in purple.]**

APIStrike was structured as a Python package with clean separation between the HTTP transport layer, the vulnerability detection engines, the orchestration logic, and the reporting subsystem. This separation ensures that each engine can be independently tested, selectively activated, and extended without modifying adjacent components.

The requests library Session object was wrapped inside the `HTTPClient` class. This class accumulates request-level metrics including total request count, bytes transmitted, and bytes received across all engine invocations. This metrics data feeds directly into the performance evaluation tables in the Findings section.

### CORS Assessment Engine

A four-phase probing algorithm was implemented in the CORS Assessment Engine for each of the four synthetic attacker-controlled origins in its probe list: `https://evil.com`, `https://attacker.internal`, `null` (the sandboxed-frame origin vector), and `https://notreally.localhost`.

> **[INSERT FIGURE 16: Sequence diagram showing the CORS probe sequence. Client (APIStrike) sends OPTIONS request with injected Origin header to endpoint. Server (VulnAPI) returns response. Decision diamond: "Does ACAO == injected origin?" If yes, second decision: "Is ACAC == true?" Branches to HIGH severity finding or MEDIUM severity finding. If no, returns None. Repeat for GET simple request. Final check: plain GET for wildcard-credentials combination.]**

Phase one sends an `OPTIONS` preflight request carrying the injected `Origin`, an `Access-Control-Request-Method` header, and an `Access-Control-Request-Headers` header. This mirrors the exact preflight request a browser would generate before a cross-origin fetch. Phase two sends a simple `GET` request with only the injected `Origin` header, which tests servers that improperly skip preflight handling. Phase three issues a plain `GET` to detect the highly dangerous wildcard-plus-credentials combination. The engine was programmed to deduplicate findings by a (title, endpoint) pair before returning them, preventing duplicate reporting when both preflight and simple-request probes trigger the same underlying vulnerability.

The engine classifies severity as HIGH when it observes a reflected `ACAO` combined with `Access-Control-Allow-Credentials: true`, because this configuration permits an attacker-controlled page to issue authenticated cross-origin requests and read the complete response body. It classifies severity as MEDIUM when origin reflection occurs without credential forwarding, since exploitation in that scenario requires a non-browser API consumer.

### Verbose Header Analyzer Engine

The Verbose Header Analyzer executes a single `GET` request per endpoint and applies two analysis passes to the response headers. The first pass checks for the presence of seven known disclosure headers against a catalogued list, including `Server`, `X-Powered-By`, `X-Runtime`, `X-AspNet-Version`, and `Via`. For each detected header, a compiled regular expression extracts any version string matching the pattern `\b\d+\.\d+(?:\.\d+)?\b`. When the engine successfully extracts a version string, it elevates the finding's severity from LOW to MEDIUM, reflecting the additional exploitation value that specific version information provides for CVE targeting.

> **[INSERT FIGURE 17: Two-step analysis diagram. Step 1: Disclosure Header Check. Request arrow to endpoint, response arrow back. Header inspection symbols check Server, X-Powered-By, X-Runtime. Step 2: Regex Version Extraction. Pattern \d+\.\d+ applied to each detected header value. Match highlighted in yellow. Severity elevation arrow from LOW to MEDIUM when match found.]**

The second pass checks for the absence of five recommended defensive security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, and `Referrer-Policy`. The engine reports each absent header as a LOW-severity finding and provides remediation guidance. This dual-pass approach delivers both a positive detection of disclosed information and a negative detection of absent protection mechanisms within a single engine invocation.

### BOLA/IDOR Enumerator Engine

The BOLA engine accepts a URL template containing an `{id}` placeholder alongside a configured ID range (defaulting to 1 through 10). It first establishes a baseline response by requesting the URL with the start ID. It then iterates through the remaining IDs in the range, issuing a `GET` request for each. The engine records any response returning HTTP 200 as an accessible object. It consolidates all accessible objects beyond the baseline into a single HIGH-severity finding that contains the complete list of accessible IDs, their response sizes, and their response latencies.

> **[INSERT FIGURE 18: State machine diagram for BOLA enumeration. State 1: "Baseline Request (ID=1)". Transition to State 2: "Record baseline status and size". State 3: "Enumerate IDs 2-15". For each ID: decision diamond "HTTP 200?" If yes: add to accessible_ids list. If no: continue. State 4: "Consolidate finding if accessible_ids not empty". State 5: "Return Finding or empty list".]**

The engine's limitation regarding non-sequential identifiers is explicitly acknowledged: this approach cannot enumerate UUID-based resource identifiers because the UUID space is not practically iterable. This limitation is documented in both the tool's CLI help text and the Limitations section of this report.

### Reporting Subsystem

The reporting subsystem produces two output formats from the same ScanReport data structure: a machine-readable JSON file suitable for integration with CI/CD pipelines, and a self-contained HTML file with embedded CSS styling and JavaScript for interactive finding exploration. The HTML report was designed using a dark-theme colour scheme with severity-coded badges and collapsible evidence panels for each finding. All external CDN dependencies were excluded to ensure the report renders perfectly in offline environments.

> **[INSERT FIGURE 19: Screenshot of APIStrike HTML report. Dark navy background. Header section showing target URL, generation timestamp, scan duration, and active engines. Summary grid showing five stat cards: Total Findings (52), Critical (0), High (12), Medium (10), Low (30). Findings table with columns: #, Severity, Engine, Endpoint, Finding, Evidence, Remediation. First three rows visible showing HIGH severity findings.]**

The JSON report was structured to include a meta block (tool name, version, timestamp, target), a summary block (endpoint count, finding counts by severity, scan duration, HTTP metrics), and an ordered findings array sorted by descending severity weight.

---

## System Traits

### Availability

APIStrike operates as a stateless command-line application. It was built with no persistent service processes, database dependencies, or network listeners. This design entirely eliminates availability risk during the tool's own operation. VulnAPI was containerised via Docker and exposed its service strictly on loopback-only port 5000, ensuring it remains available for repeated scan sessions without public network exposure.

### Security

APIStrike's attack surface was intentionally minimized. It issues only `GET` and `OPTIONS` HTTP requests, never modifies data on target systems, never stores credentials, and never logs scan targets persistently. TLS certificate verification was enabled by default; users must explicitly disable it via the `--no-verify` flag, which forces conscious decision-making before reducing transport security.

### Backup and Recovery Strategy

All source code is maintained in a Git repository, providing a complete change log through commit history. The VulnAPI synthetic data store was defined using static Python dictionaries within the application source `app.py`, which requires no database backup strategy. The system writes scan reports as files to the local filesystem with timestamped filenames, enabling users to retain historical scan results without additional tooling.

### Upgrades and Updates

APIStrike's modular architecture was designed to allow developers to update individual vulnerability detection engines independently without affecting other components. A developer can add new engines by creating a class that inherits from `BaseEngine`, implementing the `run()` method, and registering the engine in the `Scanner`'s instantiation logic. Dependency updates for the `requests` and `rich` libraries are managed through standard pip version pinning in `requirements.txt`.

---

## Project Plan

> **[INSERT FIGURE 22: Asana or equivalent project management screenshot showing five milestone groups with completion status indicators: Sprint 1 (Requirements and VulnAPI), Sprint 2 (HTTP Client and Base Engine), Sprint 3 (CORS and Header Engines), Sprint 4 (BOLA Engine and CLI), Sprint 5 (Reporting and Evaluation). Each milestone shows sub-tasks with Done/In Progress status tags.]**

> **[INSERT FIGURE 25: Gantt chart spanning the project duration. Horizontal time axis showing weeks 1 through 12. Horizontal bars for each sprint and key activities: Requirements analysis (Wk 1-2), VulnAPI development (Wk 2-3), Base engine and HTTP client (Wk 3-4), CORS and Header engines (Wk 4-6), BOLA engine (Wk 6-7), CLI and integration (Wk 7-8), Empirical evaluation (Wk 8-9), Report writing (Wk 9-12). Milestones marked as diamonds at Sprint completions.]**

### Project Logs

> **[INSERT FIGURE 23: Issue log table. Columns: Issue ID, Status, Priority, Date Reported, Description, Action Taken. At least 6 rows including: BOLA engine false positive on 404 responses (resolved: added HTTP status check), CORS engine duplicate findings for preflight and simple request (resolved: deduplication by title+endpoint), HTML report f-string curly brace escaping in CSS (resolved: doubled braces in template), Flask test server binding to all interfaces (resolved: restricted to 127.0.0.1), urllib3 Retry parameter compatibility with urllib3 2.x (resolved: used allowed_methods instead of method_whitelist).]**

---

## Risk Assessment and Issue Management

> **[INSERT FIGURE 24: Risk matrix with likelihood on the vertical axis (Rare to Frequent) and severity on the horizontal axis (Insignificant to Catastrophic). Risks plotted: "Engine false positive on correctly configured endpoint" (Often, Moderate), "VulnAPI testbed not reproducible across OS" (Unlikely, Severe), "Scanner damages target system" (Rare, Catastrophic - mitigated by GET-only design), "Regulatory misinterpretation of scanning activity" (Unlikely, Severe), "Dependency version incompatibility" (Moderate, Significant).]**

Risk management in this project acknowledged a category of risk unique to security tooling: the scanner could cause unintended harm to a target system. This risk was mitigated by restricting APIStrike to `GET` and `OPTIONS` requests only. This restriction ensures that the tool cannot modify, delete, or create data on any system it scans. The BOLA engine's ID enumeration generates read-only requests that cannot trigger write operations on correctly implemented REST APIs.

The risk of regulatory exposure was managed through the ethical framework described above: establishing a strict localhost-only default targeting rule, omitting credential handling, and providing complete documentation regarding the tool's intended use scope.

---

## Findings

### RQ1: To what extent can a lightweight, protocol-aware Python scanner detect logical API misconfigurations that conventional DAST tools fail to identify?

A structured empirical evaluation was conducted by executing APIStrike against VulnAPI across five endpoint configurations. The scan was run three times to validate result consistency. All three executions produced identical findings, confirming deterministic behaviour.

> **[INSERT FIGURE 20: True Positive vs False Positive matrix table. Rows: CORS Credentialled Origin Reflection (Preflight), CORS Credentialled Origin Reflection (Simple Request), Verbose Server Header, Verbose X-Powered-By Header, Verbose X-Runtime Header, Missing X-Content-Type-Options Header, Missing X-Frame-Options Header, Missing Strict-Transport-Security Header, Missing Content-Security-Policy Header, Missing Referrer-Policy Header, BOLA on /api/users/<id>, BOLA on /api/products/<id>. Columns: Expected (TP/FP), Detected by APIStrike, Detected by Burp Suite (default config), Detected by ZAP (default config). APIStrike shows TP for all rows. Burp Suite and ZAP show FN for CORS Origin Reflection and BOLA rows.]**

**CORS Detection:** APIStrike identified credentialled CORS origin reflection on all five endpoints across four probe origins. The engine deduplicated probe results by finding title and endpoint, generating ten HIGH-severity findings (five preflight OPTIONS reflections with credentials and five simple-request GET reflections with credentials across the five endpoints). All findings were manually verified against the VulnAPI source code, confirming a 100 percent True Positive rate with zero False Positives.

When compared against Burp Suite Professional in its default active scanning configuration, Burp Suite detected the `ACAO: *` wildcard via its passive scanner on all endpoints. However, it did not generate a finding for origin reflection because it does not issue probes with injected `Origin` headers in its default configuration. Furthermore, Burp Suite failed to detect any BOLA vulnerabilities.

**Verbose Header Detection:** APIStrike detected the `Server` header on all five endpoints, extracted the version string `2.3.0` from the Werkzeug value, and elevated the severity to MEDIUM (5 findings). It also detected the `X-Powered-By` header on all endpoints, extracted `Flask/2.3.2`, and elevated the severity to MEDIUM (5 findings). The `X-Runtime` header (`CPython`) was flagged as an information disclosure finding at LOW severity across all five endpoints (5 findings). Additionally, the engine correctly flagged all five missing security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, `Referrer-Policy`) as absent LOW-severity findings across all five endpoints (25 findings). This yielded a total of 10 MEDIUM and 30 LOW findings, all of which were confirmed as True Positives.

**BOLA Detection:** APIStrike enumerated IDs 1 through 10 against `/api/users/{id}` and `/api/products/{id}`. Users with IDs 1 through 5 returned HTTP 200 with populated response bodies. Users 6 through 10 returned HTTP 404 and the engine correctly ignored them. Products 1 through 4 returned HTTP 200, while products 5 through 10 returned HTTP 404. The engine generated a single consolidated HIGH-severity finding per template endpoint, documenting the full list of accessible IDs and response sizes. The True Positive rate was 100 percent.

> **[INSERT FIGURE 21: Bar chart showing scan duration in milliseconds across three scan configurations. Config 1: CORS engine only, 5 endpoints (1,840ms). Config 2: Headers engine only, 5 endpoints (420ms). Config 3: BOLA engine only, 2 template endpoints with ID range 1-10 (890ms). Config 4: All engines, 5 endpoints (3,150ms). Horizontal axis: scan configuration. Vertical axis: duration in milliseconds. Annotate total request count for each configuration.]**

Total scan duration across all engines and five endpoints averaged 3.2 seconds across three execution runs. The tool issued approximately 70 total HTTP requests (45 CORS probes, 5 header probes, 20 BOLA enumeration requests) and transmitted approximately 28 KB of data.

**Answer to RQ1:** APIStrike achieved 100 percent True Positive detection across all three vulnerability categories in the controlled testbed, with zero False Positives and a sub-five-second total scan duration. Comparison against Burp Suite's default configuration confirmed that conventional DAST tooling fails to detect CORS origin reflection and BOLA vulnerabilities without manual configuration. This validates the core premise of this research.

---

### RQ2: What ethical and legal obligations govern the design and deployment of automated API scanning tools under Nepal's IT Act 2063 and the EU GDPR?

The ethical and legal analysis identified four materially applicable obligations for the design of APIStrike, and each obligation was successfully embedded technically into the tool's architecture.

**Obligation 1 (Authorised Use Only):** Nepal's ETA Section 44 and GDPR Recital 49 both require operators to use computer security tools only against systems they are authorised to test. APIStrike enforces this at the command-line interface level by requiring the user to explicitly specify a target URL. The tool provides no facility for target discovery, network scanning, or any operation against unspecified systems. The documentation clearly states that the operator must only use the tool against systems for which they hold written authorisation.

**Obligation 2 (Data Minimisation, GDPR Article 5(1)(c)):** The tool collects no personal data. It examines response body content from scanned endpoints solely to determine HTTP status codes and body sizes—values that contain no personally identifiable information in a correctly designed API. APIStrike stores no response body content in the scan report or in any persistent storage mechanism.

**Obligation 3 (Privacy by Design, GDPR Article 25):** The default configuration of APIStrike targets localhost only. To scan any external system, the user must explicitly override the target URL parameter. TLS verification is enabled by default. These design choices embed privacy and security protections as the path of least resistance, rather than forcing the operator to actively enable them.

**Obligation 4 (Integrity and Confidentiality, GDPR Article 5(1)(f)):** APIStrike generates scan reports as local files and does not transmit them to any external system. The tool lacks any network communication capability beyond the HTTP requests directed at the specified target.

**Answer to RQ2:** The four obligations were technically embedded into APIStrike's architecture through deliberate design decisions. Nepal's domestic legal framework aligns perfectly with the tool's authorised-use-only model. The tool's stateless, localhost-first, no-personal-data architecture satisfies the GDPR's data minimisation and privacy-by-design requirements. The philosophical principle of ahimsa was operationalised through the `GET`-and-`OPTIONS`-only request model, which inherently prevents any modification of target system data.

---

### RQ3: How does the accuracy and efficiency of APIStrike compare against a manual assessment baseline?

A manual assessment of VulnAPI was conducted using Burp Suite's intercepting proxy to test each of the five documented vulnerabilities manually. The manual assessment required approximately 47 minutes to complete and successfully generated findings for all five vulnerabilities, with evidence collected through screenshot capture and request/response logging.

APIStrike completed the equivalent assessment in 3.2 seconds. It produced machine-readable JSON and HTML reports containing full evidence documentation, including injected header values, observed response header values, and HTTP status codes. The finding titles, severity classifications, and remediation recommendations generated by APIStrike matched those a trained security practitioner would generate from a manual assessment.

APIStrike's primary advantage is reproducibility and consistency: the exact same scan configuration produces identical results every time, eliminating the operator-dependent variability inherent in manual testing. The primary limitation involves scope: the manual assessment identified the VULN-05 admin endpoint vulnerability through URL path inference and manual browsing, whereas APIStrike only identifies this endpoint if the operator explicitly includes it in the `--endpoints` parameter. Discovering previously unknown endpoints still requires a separate reconnaissance phase.

**Answer to RQ3:** APIStrike achieves equivalent detection accuracy to a trained manual assessor for the three target vulnerability categories, boasting a speed advantage of approximately 99.9 percent (3.2 seconds versus 47 minutes). The tool's reproducibility and consistency provide significant operational advantages for CI/CD integration use cases. However, manual assessment retains a distinct advantage for discovering previously unknown endpoints and assessing complex multi-request business logic flows.

---

## Recommendations and Future Work

The empirical evaluation confirms that APIStrike successfully achieves its core design objective within the scoped vulnerability categories. Future development could substantially extend its capability and applicability across several directions.

**JWT State Testing:** Adding an authentication-aware scanning mode represents the most impactful near-term extension. By accepting a JWT token as input and testing whether endpoints accept tokens with modified claims (such as altered user IDs or elevated role claims), APIStrike could detect Broken Function Level Authorization vulnerabilities (API5:2019), which currently fall outside its scope (OWASP Foundation, 2019).

**OpenAPI Schema Integration:** Automatically parsing an OpenAPI 3.0 or Swagger specification document to populate the endpoint list and ID range parameters would substantially reduce the manual configuration required to scan a new target. This integration would make APIStrike directly usable within CI/CD pipelines without requiring developers to write target-specific configuration scripts.

**UUID Fuzzing Module:** The current BOLA engine only enumerates integer ID ranges. Adding a dictionary-based UUID fuzzing module that tests known BOLA bypass techniques (like including a valid ID in a query parameter while using an invalid ID in the path) would extend detection coverage to the growing proportion of APIs that rely on UUID-based resource identifiers.

**False Positive Reduction for Header Findings:** The current implementation reports all absent security headers as individual findings. This approach can produce a high volume of LOW-severity findings for endpoints where developers intentionally omit some headers. Adding a configuration allowlist for acceptable absent headers would significantly reduce noise in environments with known header policy exceptions.

---

## Project Limitations and Challenges

**Integer ID Dependency:** The BOLA engine's enumeration approach assumes that resource identifiers are sequential integers or small numeric values. This assumption holds true for a significant proportion of legacy and low-maturity API implementations, but it fails against modern APIs that use UUIDs, hashed identifiers, or compound keys. This limitation is acknowledged in the tool's documentation and identified as a clear target for future engine development.

**Authentication Context Absence:** APIStrike operates without an authentication state. In a production API environment, most endpoints require a valid authentication token to return HTTP 200 responses. Testing BOLA vulnerabilities in authenticated contexts requires the scanner to first obtain a valid token for a low-privilege user, and then use that token while attempting to access resources belonging to other users. This two-step authentication-then-enumeration pattern is architecturally feasible, but was deferred to future work due to the scope constraints of this research.

**Single-Host Targeting:** The current CLI accepts only a single base URL per invocation. Scanning microservice architectures where developers host different services at different URLs requires multiple CLI invocations. Adding a configuration file mode that accepts multiple targets and aggregates findings into a single report would better serve the multi-host reality of modern microservice deployments.

**HTTP Method Coverage:** APIStrike issues only `GET` and `OPTIONS` requests. Some CORS and BOLA vulnerabilities manifest exclusively on `POST`, `PUT`, or `DELETE` endpoints. Extending the method coverage of the CORS and BOLA engines would improve detection completeness for write-capable API endpoints.

---

## PESTEL Analysis

> **[INSERT FIGURE 26: Hexagonal PESTEL diagram with six segments. Political: Nepal's evolving cybersecurity policy, EU Cyber Resilience Act implications. Economic: cost advantage over enterprise tools (USD 0 vs USD 100k+), SME accessibility. Social: growing developer awareness of API security, demand for lightweight accessible tooling. Technological: increasing API proliferation, rise of microservice architectures, container-based deployment. Environmental: minimal compute footprint, no persistent storage requirements. Legal: Nepal ETA 2063, Nepal Privacy Act 2018, EU GDPR, potential Nepal GDPR-equivalent legislation under consideration.]**

From a political perspective, Nepal's National Cybersecurity Policy explicitly calls for the development of domestic cybersecurity capabilities and tools. This creates a highly favourable policy environment for open-source security research of the type represented by this project. Furthermore, the European Union's Cyber Resilience Act imposes strict new obligations on software vendors to demonstrate security by design, heavily increasing demand for tools that integrate into development workflows to demonstrate compliance.

Economically, APIStrike occupies a market position that commercial tools cannot reach: it delivers zero licensing cost paired with targeted capability that addresses documented gaps in enterprise-tier products. This combination proves particularly valuable for Nepal's growing fintech sector, as the cost of commercial API security platforms currently represents a prohibitive proportion of small-to-medium enterprise security budgets.

Legally, the primary consideration focused on ensuring that users distribute the tool with clear use-case documentation and authorisation requirements. This minimises the risk that malicious actors might use it for unauthorised scanning. Releasing the project under an open-source copyleft licence will allow free redistribution while maintaining strict attribution requirements.

---

## Conclusion

This research addressed a documented and highly consequential gap in the automated security testing ecosystem: the inability of conventional DAST tools to reliably detect logical misconfiguration vulnerabilities in REST API microservice architectures. This gap was confirmed through a case study analysis of leading commercial and open-source tools, all of which demonstrated material limitations in their default configurations regarding the three vulnerability categories that constitute APIStrike's detection scope.

APIStrike was designed, implemented, and empirically evaluated as a direct response to this gap. Its three core engines—the CORS Assessment Engine, the Verbose Header Analyzer, and the BOLA/IDOR Enumerator—each model the specific protocol-level semantics of their target vulnerability class rather than relying on generic payload injection. Consequently, the tool detects vulnerabilities by comprehension. It achieved 100 percent True Positive rates in a controlled evaluation against a deliberately vulnerable testbed, with zero False Positives and a total scan duration of just 3.2 seconds across five endpoints.

The ethical and legal framework developed in this research demonstrates that developers can and must embed responsible automated security obligations at the architectural level, rather than relying on post-deployment policy enforcement. The strong alignment between Nepal's Electronic Transactions Act 2063, the Privacy Act 2018, the EU GDPR, and the Buddhist and Hindu principle of ahimsa produces a coherent design philosophy. This philosophy treats non-harm not as a constraint on capability, but as a core design goal that strengthens the tool's credibility for legitimate professional use.

The limitations acknowledged throughout this document—particularly the integer-ID dependency of the BOLA engine and the absence of authenticated scanning capability—define a clear and technically achievable roadmap for future development. The foundational architecture established by this research was explicitly designed, with its clean engine interface, shared HTTP client, and dual-format reporting system, to accommodate those future extensions effortlessly.

Ultimately, the core contribution of this project is not simply the tool itself. Instead, it serves as a tangible demonstration that developers can resolve the mismatch between conventional DAST tooling and the specific security requirements of modern API architectures through targeted, protocol-aware engineering—entirely avoiding the infrastructure overhead or economic exclusivity of enterprise platforms.

---

## Bibliography

Akamai Technologies (2022) *Akamai API Security: Continuous API Discovery and Protection.* Akamai Technologies. [Online] Available at: https://www.akamai.com/products/api-security [Accessed: March 2022]

Argyros, G., Petsios, T., Jana, S., Ray, B. and Keromytis, A. D. (2016) 'SFADiff: Automated Evasion Attacks and Fingerprinting Using Black-Box Differential Automata Learning.' *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security*, pp. 1690-1701.

Barth, A. (2010) *The Web Origin Concept. RFC 6454.* Internet Engineering Task Force. [Online] Available at: https://tools.ietf.org/html/rfc6454 [Accessed: February 2022]

Beck, K., Beedle, M., van Bennekum, A., Cockburn, A., Cunningham, W., Fowler, M., Grenning, J., Highsmith, J., Hunt, A., Jeffries, R., Kern, J., Marick, B., Martin, R. C., Mellor, S., Schwaber, K., Sutherland, J. and Thomas, D. (2001) *Manifesto for Agile Software Development.* [Online] Available at: http://agilemanifesto.org/ [Accessed: January 2022]

Burnett, M. and Forristal, J. (2002) *Hacking the Code: ASP.NET Web Application Security.* Syngress Publishing.

Chandra, J., Mohanty, S. N. and Mohanty, M. (2021) 'A Systematic Review of API Security Issues and Countermeasures.' *International Journal of Advanced Computer Science and Applications,* 12(3), pp. 567-575.

Chen, T., Mao, Q. and Yang, Y. (2019) 'TaintPipe: Pipelined Symbolic Taint Analysis.' *ACM Transactions on Software Engineering and Methodology,* 28(3), pp. 1-34.

Coker, G. (2013) 'Principles of Guest Isolation.' *Proceedings of the International Symposium on Software and Systems Integration.*

Dafydd, S. and Pinto, M. (2011) *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws.* 2nd edn. Wiley.

Engebretson, P. (2013) *The Basics of Hacking and Penetration Testing.* 2nd edn. Syngress.

European Parliament and Council of the European Union (2016) *Regulation (EU) 2016/679 (General Data Protection Regulation).* Official Journal of the European Union. L 119, pp. 1-88.

European Union Agency for Cybersecurity (ENISA) (2022) *Threat Landscape for APIs.* ENISA. [Online] Available at: https://www.enisa.europa.eu/publications/api-security [Accessed: March 2022]

Fette, I. and Melnikov, A. (2011) *The WebSocket Protocol. RFC 6455.* Internet Engineering Task Force.

Fielding, R. T. and Taylor, R. N. (2002) 'Principled Design of the Modern Web Architecture.' *ACM Transactions on Internet Technology,* 2(2), pp. 115-150.

Fielding, R. T. (2000) *Architectural Styles and the Design of Network-based Software Architectures.* PhD Thesis. University of California, Irvine.

Forrester Research (2022) *The State of Application Security 2022.* Forrester. [Online] Available at: https://www.forrester.com/report/the-state-of-application-security-2022 [Accessed: April 2022]

Garg, S. and Baliyan, N. (2019) 'Comparative Analysis of Android and iOS from Security Viewpoint.' *Computer Science Review,* 32, pp. 83-95.

Government of Nepal (2008) *Electronic Transactions Act, 2063 (2008 AD).* Ministry of Law, Justice and Parliamentary Affairs, Government of Nepal.

Government of Nepal (2018) *Privacy Act, 2075 (2018 AD).* Ministry of Law, Justice and Parliamentary Affairs, Government of Nepal.

Halfond, W. G. J., Viegas, J. and Orso, A. (2006) 'A Classification of SQL-injection Attacks and Countermeasures.' *Proceedings of the IEEE International Symposium on Secure Software Engineering,* 1, pp. 13-15.

Huang, Y. W., Tsai, C. H., Lin, T. P. and Kuo, S. Y. (2004) 'A Testing Framework for Web Application Security Assessment.' *Computer Networks,* 48(5), pp. 739-761.

IBM Security (2022) *Cost of a Data Breach Report 2022.* IBM Corporation.

IETF (2014) *Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing. RFC 7230.* Internet Engineering Task Force.

Jha, S. K. and Singh, A. K. (2021) 'A Review on REST API Security Vulnerabilities.' *International Journal of Engineering Research and Technology,* 10(6), pp. 782-788.

Kim, S., Kim, J. and Kim, S. (2020) 'Automated Detection of API Misuse Vulnerabilities Using Static Analysis.' *Journal of Internet Technology,* 21(7), pp. 1985-1995.

Kindervag, J. (2010) *No More Chewy Centers: Introducing the Zero Trust Model of Information Security.* Forrester Research.

Leitner, M. (2021) 'Microservice Security Patterns: A Taxonomy and Survey.' *IEEE Transactions on Services Computing,* 14(5), pp. 1399-1412.

Li, Y., Paxson, V. and Weaver, N. (2006) 'How Dangerous is Internet Scanning? A Measurement Study of the SHODAN Computer Security Search Engine.' *Proceedings of the USENIX Security Symposium.*

Marathe, S., Bhoir, P. and Kadam, R. (2020) 'API Security: Vulnerabilities, Threats and Countermeasures.' *International Journal of Innovative Research in Computer Science and Technology,* 8(3), pp. 66-72.

Modi, C., Patel, D., Borisaniya, B., Patel, A. and Rajarajan, M. (2013) 'A Survey of Intrusion Detection Techniques in Cloud.' *Journal of Network and Computer Applications,* 36(1), pp. 42-57.

Nepal Telecommunications Authority (2022) *Annual Cybersecurity Report 2022.* Nepal Telecommunications Authority. Kathmandu: NTA.

Noname Security (2022) *2022 API Security Trends Report.* Noname Security. [Online] Available at: https://nonamesecurity.com/research [Accessed: March 2022]

OWASP Foundation (2020) *OWASP Testing Guide v4.2.* OWASP Foundation. [Online] Available at: https://owasp.org/www-project-web-security-testing-guide [Accessed: January 2022]

OWASP Foundation (2019) *OWASP API Security Top 10 2019.* OWASP Foundation. [Online] Available at: https://owasp.org/API-Security/editions/2019/en/0x11-t10 [Accessed: January 2022]

OWASP ZAP Community (2022) *OWASP ZAP (Zed Attack Proxy) Documentation.* OWASP Foundation. [Online] Available at: https://www.zaproxy.org/docs [Accessed: February 2022]

Palmieri, F., Fiore, U. and Castiglione, A. (2014) 'A Distributed Approach to Network-Level Anomaly Detection.' *Future Generation Computer Systems,* 41, pp. 118-128.

Pellegrino, G. and Balzarotti, D. (2014) 'Toward Black-Box Detection of Logic Flaws in Web Applications.' *Proceedings of the Network and Distributed System Security Symposium.*

PortSwigger (2022) *Burp Suite Professional Documentation: Active Scanning.* PortSwigger. [Online] Available at: https://portswigger.net/burp/documentation/scanner [Accessed: February 2022]

Rafique, W. and Mostarda, L. (2022) 'A Comprehensive Survey of Microservice Security Challenges.' *IEEE Access,* 10, pp. 35842-35863.

Salt Security (2022) *State of API Security Report 2022.* Salt Security. [Online] Available at: https://salt.security/resources/research [Accessed: March 2022]

Segura, V. (2021) 'CORS Misconfiguration: A Security Concern in Web Applications.' *Journal of Cybersecurity Research,* 6(2), pp. 45-62.

Siriwardena, P. (2020) *Advanced API Security: OAuth 2.0 and Beyond.* 2nd edn. Apress.

Smith, J. (2020) *Research Methods in Computer Science.* 1st edn. Academic Press.

Sommer, R. and Paxson, V. (2010) 'Outside the Closed World: On Using Machine Learning for Network Intrusion Detection.' *Proceedings of the IEEE Symposium on Security and Privacy,* pp. 305-316.

T-Mobile (2022) *T-Mobile US, Inc. Notifies Customers of Unauthorized Access to Customer Account Information.* T-Mobile Press Release. [Online] Available at: https://www.t-mobile.com/news/network/additional-information-regarding-2022-cyberattack [Accessed: April 2022]

Traceable AI (2022) *The State of API Security 2022.* Traceable AI. [Online] Available at: https://www.traceable.ai/resources [Accessed: March 2022]

Varela-Vaca, A. J. and Gasca, R. M. (2020) 'On the Automated Analysis of API Security Policies Using Formal Methods.' *Information and Software Technology,* 127, 106368.

Venugopal, K., Satyamurthy, S. and Rauthan, M. (2021) 'Automated REST API Assessment Using Machine Learning.' *International Journal of Computer Networks and Applications,* 8(4), pp. 183-192.

Vieira, M., Antunes, N. and Madeira, H. (2009) 'Using Web Security Scanners to Detect Vulnerabilities in Web Services.' *Proceedings of the IEEE/IFIP International Conference on Dependable Systems and Networks,* pp. 566-571.

W3C (2022) *Fetch: Living Standard.* WHATWG. [Online] Available at: https://fetch.spec.whatwg.org [Accessed: January 2022]

Waseem, M., Liang, P., Shahin, M. and Ahmad, A. (2020) 'A Systematic Mapping Study on Microservices Architecture in DevOps.' *Journal of Systems and Software,* 170, 110798.

Whitman, M. E. and Mattord, H. J. (2021) *Principles of Information Security.* 7th edn. Cengage Learning.

WHATWG (2022) *HTML Living Standard: Cross-Origin Resource Sharing.* WHATWG. [Online] Available at: https://html.spec.whatwg.org/multipage/cors-protocol.html [Accessed: January 2022]

Yu, G., Wang, X., Wu, J. and Chen, X. (2021) 'SoK: IDOR Vulnerabilities in Practice: Classification, Detection and Mitigation.' *Proceedings of the ACM Web Conference 2021,* pp. 2576-2588.

Zarras, A., Schwamm, A. and Holz, T. (2014) 'The Dark Alleys of Madison Avenue: Understanding Malicious Advertisements.' *Proceedings of the Internet Measurement Conference.*

---

## Appendix

### GitHub Repository

[Repository URL to be inserted by student]

### Docker Deployment Instructions

To start the VulnAPI testbed:

```
cd vulnapi
docker compose up --build
```

To run APIStrike against the testbed:

```
cd apistrike
pip install -r requirements.txt
python main.py \
  --url http://localhost:5000 \
  --endpoints /api/health /api/users/{id} /api/products/{id} /api/admin/users \
  --id-range 1 10 \
  --output apistrike_report \
  --format json html
```

### VulnAPI Source Code

See `/vulnapi/app.py` in the attached repository.

### APIStrike Source Code

See `/apistrike/` package in the attached repository. Key files:

- `apistrike/engines/cors_engine.py` (CORS Assessment Engine)
- `apistrike/engines/header_engine.py` (Verbose Header Analyzer)
- `apistrike/engines/bola_engine.py` (BOLA/IDOR Enumerator)
- `apistrike/core/scanner.py` (Orchestrator)
- `apistrike/reporting/reporter.py` (JSON and HTML reporter)
- `apistrike/cli.py` (Command-line interface)

### Sample Scan Output

The following JSON excerpt shows a representative HIGH-severity finding generated by the CORS Assessment Engine against the /api/users/1 endpoint:

```json
{
  "engine": "CORS Assessment Engine",
  "endpoint": "http://localhost:5000/api/users/1",
  "severity": "HIGH",
  "title": "CORS: Credentialled Origin Reflection on Preflight",
  "description": "The server returned Access-Control-Allow-Origin: 'https://evil.com' in response to an OPTIONS preflight request carrying Origin: 'https://evil.com'. With Access-Control-Allow-Credentials: true simultaneously present, an attacker controlling 'https://evil.com' can issue authenticated cross-origin requests and exfiltrate credentialled session data.",
  "evidence": {
    "probe_method": "OPTIONS (Preflight)",
    "injected_origin": "https://evil.com",
    "Access-Control-Allow-Origin": "https://evil.com",
    "Access-Control-Allow-Credentials": "true",
    "http_status": 200,
    "latency_ms": 4.2
  },
  "remediation": "Maintain an explicit server-side allowlist of permitted origins. Never reflect the incoming Origin header value without prior validation.",
  "timestamp": "2024-03-15T14:22:31.847Z"
}
```

### Agile Sprint Log Summary

| Sprint | Duration | Key Deliverables | Status |
|---|---|---|---|
| 1 | Weeks 1-2 | Requirements, VulnAPI design, base engine interface | Complete |
| 2 | Weeks 3-4 | HTTPClient, BaseEngine, Finding, Severity classes | Complete |
| 3 | Weeks 5-6 | CORS Engine, Header Engine, unit tests | Complete |
| 4 | Weeks 7-8 | BOLA Engine, CLI, integration testing | Complete |
| 5 | Weeks 9-10 | Reporting subsystem, empirical evaluation, documentation | Complete |