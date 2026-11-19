# Project Proposal

## 1. Project Title

**ThreatLens — Network Discovery, Traffic Analysis and Security Assessment Platform.**

## 2. Abstract

This project proposes the design and development of a beginner-friendly Python application for conducting limited, authorized network reconnaissance and basic security configuration checks. The application will validate target IP addresses and hostnames against an explicit allowlist, request user confirmation before assessment, and restrict TCP connection checks to an approved set of ports. It will identify likely services using limited connection evidence and assess HTTP and HTTPS behavior, selected response security headers, and cookie security attributes.

Assessment observations will be classified using a documented, project-specific risk scheme, stored in a dedicated SQLite database at `data/cybersecurity_assessment.db`, and presented in JSON and HTML reports. The project is intended for localhost, isolated laboratory systems, and other explicitly approved targets. It will not attempt exploitation, password attacks, denial-of-service testing, or unrestricted network scanning. Its purpose is educational and diagnostic: results will describe observed conditions and their limitations, not certify a system as secure or prove that a vulnerability is exploitable.

## 3. Introduction

Computers and web applications communicate over networks using protocols and services that may expose information about a system’s configuration. An authorized assessment can help a system owner understand which selected TCP services are reachable and whether a web server presents particular security-related settings. Such observations can support learning and basic defensive review, but they must be collected within a clearly defined scope and interpreted cautiously.

This project will combine basic networking with web response inspection in a small, modular Python tool. It will emphasize safeguards—explicit target approval, a limited port list, conservative timeouts, low-rate connection attempts, and confirmation before network activity—alongside understandable output and reproducible local testing. The approach is consistent with the general assessment lifecycle described in NIST’s guidance on planning and conducting technical security tests, analyzing findings, and considering their limitations [9].

## 4. Background of the Study

Network reconnaissance, in this project’s narrow defensive context, means collecting basic information from explicitly authorized systems. A TCP connection attempt to a selected port can indicate that a service may be reachable, but network filtering, routing, service behavior, and timeouts can affect the observation. Therefore, a connection result is evidence about reachability at a particular time—not a complete inventory or proof of a vulnerability. NIST emphasizes planning, conducting, and analyzing security tests with attention to the techniques’ benefits and limitations [9].

Web servers return status codes, headers, and sometimes cookies along with page content. OWASP documents HTTP response headers that can contribute to browser-side security, while also explaining that their relevance depends on context [7]. Cookie attributes such as `Secure`, `HttpOnly`, and `SameSite` are useful indicators to inspect, particularly for session-related cookies; their presence alone does not establish that an application’s session management is secure [8].

Python provides standard-library modules for IP address handling, socket communication, SQLite database access, and JSON serialization [1][2][5][6]. The Requests library provides an interface for HTTP requests and response inspection [3], and Beautiful Soup can parse HTML when page markup needs structured inspection [4]. These technologies make it possible to implement a small educational tool without requiring a separate database server or a complex scanning framework.

## 5. Problem Statement

Learners need a safe, understandable way to connect foundational networking concepts with practical defensive checks. Unbounded scanning tools can exceed an educational task’s needs and increase the risk of contacting systems without authorization. At the same time, a basic connectivity result or a missing header can be misunderstood if the tool does not explain its scope and limitations.

The problem addressed by this project is the absence, within the project’s defined educational scope, of a simple Python application that combines controlled TCP reachability checks and basic web security configuration observations with explicit target authorization, persistent results, transparent risk labels, and readable reports. The proposed tool will address this need without attempting to exploit systems or replace a professional security assessment.

## 6. Aim of the Project

The aim is to design and develop a modular Python application that safely performs limited network and web security assessments of localhost, isolated laboratory systems, and other explicitly approved targets, then stores and reports its observations.

## 7. Specific Objectives

The project will:

1. Validate IPv4 and IPv6 addresses and validate hostname input before assessment.
2. Enforce an explicit target allowlist and restrict checks to approved TCP ports.
3. Require user confirmation and apply conservative timeouts and a low request rate.
4. Perform controlled TCP connection checks and report observed results without overstating their meaning.
5. Identify likely services using limited evidence and communicate identification uncertainty.
6. Inspect HTTP and HTTPS responses for redirect behavior, selected security headers, and cookie attributes.
7. Classify findings using a documented qualitative scheme that records the observation and its rationale.
8. Store assessment records in the dedicated SQLite database `data/cybersecurity_assessment.db`.
9. Generate JSON and HTML reports from assessment results.
10. Test the application using unit tests and controlled localhost or isolated-lab services, including expected and actual results.

## 8. Significance of the Project

The project has educational, practical, and defensive value:

- **For the student:** It provides a structured exercise in Python modules, input validation, sockets, HTTP, persistence, reporting, and testing.
- **For authorized lab users:** It provides a bounded way to observe selected service reachability and basic web security configuration.
- **For safe security practice:** It makes target approval and scope restrictions part of the assessment workflow rather than treating them as optional.
- **For future development:** Its modular design and documented limitations provide a foundation for learning about assessment methodology without representing the tool as a comprehensive scanner.

## 9. Project Scope

The application will be limited to:

- Single targets entered as IP addresses or hostnames, subject to strict allowlisting and scope checks.
- Localhost, isolated laboratory systems, or other explicitly approved targets. Public targets will not be assessed without explicit authorization and inclusion in the configured scope.
- A fixed, approved list of TCP ports; broad or unrestricted port sweeps are outside the project scope.
- Conservative TCP connection checks and basic, non-exploitative service identification.
- Basic HTTP/HTTPS checks for response behavior, HTTP-to-HTTPS redirection, selected response security headers, and cookie attributes.
- Qualitative classification of observed findings, with supporting evidence and caveats.
- Local storage in `data/cybersecurity_assessment.db` and JSON and HTML report generation.
- Testing against controlled local or isolated-lab services.

For hostname targets, scope control must account for DNS resolution: resolved addresses must be checked against the approved scope, and redirect destinations must not be followed outside that scope. An HTTP-to-HTTPS redirect can be recorded and checked only when the HTTPS destination is itself approved. HTML reports must escape untrusted target and response data before rendering it.

The project explicitly excludes exploitation, credential or password attacks, denial-of-service testing, stealth techniques, unrestricted discovery, vulnerability exploitation, and automated scanning of public targets without explicit authorization. It is not intended to provide a complete vulnerability assessment, penetration test, compliance certification, or guarantee of security.

## 10. Project Limitations

1. **Limited observations:** A TCP connection result does not prove which application is running or whether it is vulnerable. Firewalls and network conditions can produce ambiguous results.
2. **Heuristic service identification:** Service names inferred from a port number or a limited response are estimates; services can use non-standard ports or suppress identifying information.
3. **Partial web review:** A small set of HTTP checks cannot evaluate application logic, authentication, authorization, server-side code, or all deployment settings.
4. **Context-dependent findings:** The security value of a header or cookie attribute depends on the application and response context. A missing item is not automatically proof of an exploitable vulnerability [7][8].
5. **DNS and redirects:** Hostnames can resolve to multiple or changing addresses, and redirects may lead to another host. Every connection destination must remain within the approved scope.
6. **Environment differences:** Results can vary with operating system, network path, name resolution, TLS configuration, and the target’s state at assessment time.
7. **Qualitative risk labels:** The proposed categories are educational prioritization labels, not a standardized severity score or substitute for expert risk analysis.
8. **Authorization cannot be inferred:** The application can enforce a configured allowlist and confirmation step, but it cannot independently verify a user’s legal authority to assess a target.

## 11. Research Methodology

The project will use a staged design-and-implementation methodology:

1. **Requirements analysis:** Translate the instructor’s objectives into functional, technical, usability, and safety requirements.
2. **Research and design:** Consult official Python documentation, OWASP guidance, and NIST security testing guidance. Define the module boundaries, data flow, allowlisting behavior, and database and report requirements before implementation.
3. **Modular implementation:** Develop target validation and scope control, TCP assessment, service identification, web checks, risk classification, database operations, and report generation as separate components. Each assessment operation will be bounded by authorization, approved ports, and conservative connection settings.
4. **Controlled testing:** Test validation, allowlisting, confirmation behavior, TCP outcomes, service-identification limitations, HTTP/HTTPS behavior, headers, cookies, classification, SQLite operations, and JSON/HTML output. Network tests will use localhost or an isolated laboratory environment.
5. **Evaluation and documentation:** Compare expected and actual test results, document failures and limitations, and prepare user and technical documentation. Findings will be reported as observations with evidence rather than claims of proven exploitability.

NIST SP 800-115 is used as general guidance for organizing and interpreting technical security testing; it is not presented as a certification standard for this student project [9].

## 12. Technologies and Libraries with Their Purposes

| Technology or library | Purpose in the project |
|---|---|
| **Python 3** | Main programming language for implementing the application as independent, reusable modules. |
| **`ipaddress`** (standard library) | Parses and validates IPv4/IPv6 addresses and supports address and network scope checks [1]. |
| **`socket`** (standard library) | Provides low-level TCP connections for checks against approved host/port pairs; it supports connection timeouts and basic response-based service clues [2]. |
| **Requests** (third-party) | Sends bounded HTTP/HTTPS requests and exposes response status, headers, and cookies for inspection [3]. Requests must be configured with explicit timeouts; redirects must be constrained to approved destinations. |
| **Beautiful Soup** (third-party) | Parses returned HTML into a navigable structure if page markup must be examined; it is not required merely to inspect response headers [4]. |
| **`sqlite3`** (standard library) | Provides database access for the project’s dedicated SQLite database without requiring a separate database server [5]. |
| **`json`** (standard library) | Serializes assessment data into JSON reports and can load JSON configuration or data where appropriate [6]. |
| **HTML** | Human-readable report format; report generation must escape data originating from targets so response content is not interpreted as report markup. |
| **`unittest`** (standard library) | Proposed test framework for focused automated tests without introducing an additional test dependency. |

Only Requests and Beautiful Soup are anticipated as external runtime packages for the stated features. Beautiful Soup will be included because it is required by the instructor’s technology list, while its use will remain limited to cases requiring HTML parsing.

## 13. Proposed System Functionality

The proposed workflow is:

1. The user supplies a target and selects an assessment scope.
2. The application validates the target and checks it against the configured allowlist. For hostnames, it checks resolved addresses against the approved scope.
3. The application displays the target, approved ports, and planned checks, then requires user confirmation.
4. The TCP assessment component attempts connections only to approved ports, one at a time or at a deliberately low rate, using a conservative timeout.
5. The service identification component reports likely services from limited evidence and labels uncertain identifications accordingly.
6. The web assessment component checks HTTP/HTTPS behavior, including redirects only when each destination remains approved, and records selected security headers and cookie attributes.
7. The risk classification component assigns documented qualitative categories to observations and includes the evidence and caveats supporting each result.
8. The database component saves the assessment and its findings in `data/cybersecurity_assessment.db`.
9. The reporting component creates JSON and HTML reports from the stored assessment data.

If a target is invalid, unapproved, or outside scope, the application must not begin network checks. If a connection or request fails, the result must represent that failure or uncertainty rather than silently treating it as a closed port, a secure configuration, or a successful assessment.

## 14. Expected Outcomes

At the end of the project, the expected deliverables are:

- A modular Python application implementing the approved, bounded assessment workflow.
- Strict allowlisting, approved-port restrictions, confirmation before checks, conservative timeouts, and clear handling of out-of-scope targets.
- Basic TCP reachability and likely-service observations, with limitations stated.
- HTTP/HTTPS observations covering redirects, selected response security headers, and cookie attributes.
- A qualitative and documented classification of findings.
- A project-specific SQLite database at `data/cybersecurity_assessment.db`.
- JSON and HTML reports generated from assessment results.
- Tests covering the required valid and invalid inputs, network outcomes, web observations, database operations, and report generation.
- Documentation explaining setup, use, scope, safety precautions, and interpretation of results.

The expected outcome is a learning and basic assessment aid for authorized environments—not a replacement for a professional security testing process.

## 15. References

1. Python Software Foundation. “`ipaddress` — IPv4/IPv6 manipulation library.” *Python 3 Documentation*. https://docs.python.org/3/library/ipaddress.html (accessed 17 November 2026).
2. Python Software Foundation. “`socket` — Low-level networking interface.” *Python 3 Documentation*. https://docs.python.org/3/library/socket.html (accessed 17 November 2026).
3. Requests Contributors. “Quickstart.” *Requests Documentation*. https://requests.readthedocs.io/en/latest/user/quickstart/ (accessed 17 November 2026).
4. Richardson, Leonard. “Beautiful Soup Documentation.” *Beautiful Soup 4 Documentation*. https://www.crummy.com/software/BeautifulSoup/bs4/doc/ (accessed 17 November 2026).
5. Python Software Foundation. “`sqlite3` — DB-API 2.0 interface for SQLite databases.” *Python 3 Documentation*. https://docs.python.org/3/library/sqlite3.html (accessed 17 November 2026).
6. Python Software Foundation. “`json` — JSON encoder and decoder.” *Python 3 Documentation*. https://docs.python.org/3/library/json.html (accessed 17 November 2026).
7. OWASP Foundation. “HTTP Security Response Headers Cheat Sheet.” *OWASP Cheat Sheet Series*. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html (accessed 17 November 2026).
8. OWASP Foundation. “Session Management Cheat Sheet.” *OWASP Cheat Sheet Series*. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html (accessed 17 November 2026).
9. Scarfone, Karen, Murugiah Souppaya, Amanda Cody, and Angela Orebaugh. *Technical Guide to Information Security Testing and Assessment*. NIST Special Publication 800-115, September 2008. https://doi.org/10.6028/NIST.SP.800-115.
