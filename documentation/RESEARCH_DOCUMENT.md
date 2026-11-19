# Research Document

## ThreatLens — Network Discovery, Traffic Analysis and Security Assessment Platform.

### 1. Purpose

This research document explains the defensive concepts and technologies used in this educational project. The tool is intentionally limited to explicitly approved loopback targets, a small configured port list, one assessment confirmation, and bounded HTTP/HTTPS checks. It is not a general-purpose network scanner or a substitute for a professional assessment.

### 2. Network reconnaissance in a defensive context

Network reconnaissance is the collection of basic information about systems and services. In this project, it is limited to checking reachability on approved TCP ports and observing selected web response properties on a local system. NIST SP 800-115 describes planning, conducting, and analyzing technical security tests, including the need to understand their scope and limitations [1]. A single connection attempt is only a time-specific reachability observation; it does not prove that a port is always reachable, identify the software with certainty, or establish that a vulnerability exists.

### 3. TCP port assessment

TCP connection establishment is used as a conservative reachability test. The application tries each approved address/port sequentially with a bounded timeout. A completed connection is recorded as **open**; an explicit connection refusal is **closed**; timeout or other ambiguous network errors are **filtered/unknown**. An ambiguous timeout is not treated as proof that a port is closed.

The project avoids broad port ranges, retries, parallel scanning, and arbitrary protocol payloads. The configured ports are 80, 443, 8000, and 8080, and the current target policy is loopback-only.

### 4. Service identification

The application associates a small set of conventional port numbers with likely service labels. These labels are explicitly heuristic: a service may use another port, and a conventional port may host a different service. The application does not claim software versions or vulnerabilities from a port number alone. An unknown port remains unidentified rather than being guessed.

### 5. Web security assessment

HTTP responses can expose status codes, response headers, redirect behavior, and `Set-Cookie` attributes. OWASP's HTTP Security Response Headers Cheat Sheet discusses headers that can support browser-side protections, while their correct use depends on the application and deployment context [2]. The project records a limited header set and treats an absent header as an observation, not automatic proof of vulnerability.

Cookie attributes such as `Secure`, `HttpOnly`, and `SameSite` can be useful configuration indicators. OWASP's Session Management Cheat Sheet explains their role and the importance of broader session-management practices [3]. This tool records only cookie names and selected attributes; it does not persist cookie values.

The web assessor uses bounded timeouts, disables ambient proxy discovery, does not automatically follow redirects, and does not disable TLS certificate verification. It connects to a validated IP address while retaining the approved hostname for the HTTP `Host` header and TLS SNI/certificate hostname checks. Every redirect is separately validated against the project allowlist and loopback restriction before it is followed.

### 6. Risk classification

The application uses project-specific qualitative categories: Informational, Low, Medium, and High. They are prioritization labels, not CVSS scores. Confidence is a separate field. An open port is informational by itself; a missing header generally represents a low-priority hardening observation; a directly observed TLS failure or a session-like cookie lacking `Secure` may be Medium within the tool's narrow context. The current checks do not automatically assign High based only on an open port, missing header, inferred service, or timeout.

### 7. Technologies and their purposes

| Technology | Purpose |
|---|---|
| Python 3 | Modular implementation and command-line orchestration. |
| `ipaddress` | Parsing and canonicalizing IPv4/IPv6 values and checking loopback membership [4]. |
| `socket` | Bounded TCP connection checks and hostname address resolution [5]. |
| Requests | HTTP/HTTPS request handling, response inspection, timeouts, and TLS verification [6]. |
| `sqlite3` | Project-local persistence with foreign-key constraints and transactions [7]. |
| `json` | Configuration/report serialization and structured observation storage [8]. |
| `html` and HTML | Standard-library context escaping for safe report rendering and human-readable output. |
| `unittest` | Automated unit tests using the Python standard library. |

Beautiful Soup is not installed in the current implementation because it examines response headers and cookie attributes without needing to parse page HTML. This avoids an unnecessary runtime dependency. If future approved requirements need bounded HTML parsing, Beautiful Soup's documentation describes its parsing interface [9].

### 8. Ethical and legal considerations

Technical access does not imply authorization. The operator must have permission from the system owner before assessment. The allowlist is a technical scope control, not proof of legal authority. For safety, the implementation enforces loopback-only targets independently of configuration, rejects any disallowed DNS answer instead of filtering it, displays the resolved scope before confirmation, and does not make assessment connections before an affirmative response.

The application does not exploit vulnerabilities, attempt passwords, brute-force credentials, conduct denial-of-service tests, or scan external systems. Results should be interpreted as limited observations and handled according to the owner's policies.

### 9. References

1. Scarfone, K., Souppaya, M., Cody, A., and Orebaugh, A. *Technical Guide to Information Security Testing and Assessment*. NIST Special Publication 800-115, September 2008. https://doi.org/10.6028/NIST.SP.800-115.
2. OWASP Foundation. “HTTP Security Response Headers Cheat Sheet.” https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html (accessed 17 November 2026).
3. OWASP Foundation. “Session Management Cheat Sheet.” https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html (accessed 17 November 2026).
4. Python Software Foundation. “`ipaddress` — IPv4/IPv6 manipulation library.” https://docs.python.org/3/library/ipaddress.html (accessed 17 November 2026).
5. Python Software Foundation. “`socket` — Low-level networking interface.” https://docs.python.org/3/library/socket.html (accessed 17 November 2026).
6. Requests Contributors. “Quickstart.” https://requests.readthedocs.io/en/latest/user/quickstart/ (accessed 17 November 2026).
7. Python Software Foundation. “`sqlite3` — DB-API 2.0 interface for SQLite databases.” https://docs.python.org/3/library/sqlite3.html (accessed 17 November 2026).
8. Python Software Foundation. “`json` — JSON encoder and decoder.” https://docs.python.org/3/library/json.html (accessed 17 November 2026).
9. Richardson, L. “Beautiful Soup Documentation.” https://www.crummy.com/software/BeautifulSoup/bs4/doc/ (accessed 17 November 2026).
