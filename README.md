# Python-Based Network Reconnaissance and Vulnerability Assessment Tool

This educational command-line application performs small, conservative checks against targets explicitly allowlisted in this project. **This initial implementation is hard-restricted to loopback addresses (`127.0.0.0/8` and `::1`)**, even if someone edits the configuration. It is not a scanner for university, public, or other network systems.

It checks selected TCP ports, identifies only likely services from conventional port numbers, and makes bounded HTTP/HTTPS requests to inspect selected response headers, redirects, TLS verification, and cookie attributes. Results are saved to the project-local `data/cybersecurity_assessment.db` and exported to JSON and HTML.

## Safety and limitations

- Assess only a local service you own or are authorized to test.
- User confirmation is required for every assessment.
- Only targets in `config/approved_targets.json` and approved ports/methods can be used.
- All resolved addresses and redirect destinations must be approved loopback IPs. Connections use pinned IPs, not an independently resolved hostname.
- TCP checks are sequential, one connection per port/address, with a conservative timeout and pacing.
- HTTPS certificate verification stays enabled. A failed TLS check is recorded; it is not bypassed.
- The tool does not exploit vulnerabilities, submit credentials, brute-force, crawl pages, or perform denial-of-service checks.
- It does not store raw cookie values, credentials, or full response bodies.
- Service names and risk levels are limited observations, not proof of vulnerability or system security.

## Requirements

- Windows with Python 3.12 or newer.
- The project-local `.venv` at `.venv\Scripts\python.exe`.
- Requests, installed only in that virtual environment from `requirements.txt`.

Beautiful Soup is not installed because this version checks response headers and `Set-Cookie` attributes without parsing response HTML. Python's standard library covers IP validation, sockets, SQLite, JSON, HTML escaping, and testing.

## Environment setup

From the project directory in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Or run commands without activation:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The `.venv` is project-local; do not activate or install packages into another project's environment.

## Configuration

The active safe configurations are:

- `config\app_settings.json` — approved ports, web ports, timeouts, pacing, redirect limit, and user agent.
- `config\approved_targets.json` — explicit host-to-loopback-IP mappings, ports, and assessment methods.

Example templates are stored beside them as `app_settings.example.json` and `approved_targets.example.json`. The application validates configuration before network activity and independently rejects any non-loopback target or DNS answer.

## Running an assessment

Use the project-local interpreter:

```powershell
.\.venv\Scripts\python.exe -m src.cyber_assessment --help
.\.venv\Scripts\python.exe -m src.cyber_assessment localhost
```

The CLI validates and resolves the allowlisted target before displaying the original/canonical target, every resolved IP address, selected methods, approved ports, and scope restrictions. It requires typing `yes` before any TCP or HTTP/HTTPS assessment connection. By default it checks the configured TCP ports and HTTP/HTTPS web ports. Choose one module:

```powershell
.\.venv\Scripts\python.exe -m src.cyber_assessment localhost --tcp-only
.\.venv\Scripts\python.exe -m src.cyber_assessment localhost --web-only
```

The web module sends one bounded GET per configured scheme/port/address and follows at most three redirects manually. Each redirect is checked against the same project-local allowlist and loopback restriction before it is followed.

## Data and reports

- SQLite database: `data\cybersecurity_assessment.db` (created on first confirmed run).
- JSON and HTML reports: `reports\assessment-<id>.json` and `.html`.

Use `--reports-dir PATH` only for an output directory inside this project. HTML values are escaped at render time; stored observation validation is not treated as output encoding.
Open the generated `.html` report in a browser to review the human-readable results. JSON output can be opened in an editor or parsed by another local tool.

## Project documentation

- [Project proposal](documentation/PROJECT_PROPOSAL.md)
- [System architecture](documentation/SYSTEM_ARCHITECTURE.md)
- [Research document](documentation/RESEARCH_DOCUMENT.md)
- [Technical report](documentation/TECHNICAL_REPORT.md)
- [User guide](documentation/USER_GUIDE.md)
- [Test results](documentation/TEST_RESULTS.md)

The controlled assessment of `127.0.0.1` completed with status `partial` after the verified local test server was restarted. Port 8000 was open and returned HTTP 200; three TCP ports remained filtered/unknown and three web checks failed or timed out. See the [technical report](documentation/TECHNICAL_REPORT.md), [test results](documentation/TEST_RESULTS.md), and actual [JSON](reports/assessment-5a3010c1-d971-498f-b3c4-cb273aefb93d.json) and [HTML](reports/assessment-5a3010c1-d971-498f-b3c4-cb273aefb93d.html) reports. These are limited observations, not proof of vulnerability.

## Tests

Tests use the standard-library `unittest` and local loopback services only:

```powershell
$env:PYTHONPATH = ".\src"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

No test contacts a public or third-party system. The tests use temporary test databases; the application itself uses only the dedicated project database path above.
