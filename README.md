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
- Requests and Flask, installed only in that virtual environment from `requirements.txt`.
- Gunicorn is included for the Linux-hosted Render demo; it is not used by the local Windows launcher.

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

After cloning the public repository, create local-only active configuration files from the examples:

```powershell
Copy-Item config\app_settings.example.json config\app_settings.json
Copy-Item config\approved_targets.example.json config\approved_targets.json
```

The active files are ignored by Git and are not required by the hosted demonstration.

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

## Local web application

The Flask interface is a separate presentation layer over the existing scope validation, assessment workflow, database, and reporting modules. It does not replace the CLI or add assessment methods.

Install the project's requirements in the existing virtual environment when Flask is not installed yet:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start the application from the project root:

```powershell
.\run_web.ps1
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in Chrome. The server binds only to `127.0.0.1`; it does not bind to `0.0.0.0`. Press `Ctrl+C` in the PowerShell window to stop it.

If PowerShell's execution policy prevents running the launcher, start the same loopback-only entry point directly:

```powershell
$env:PYTHONPATH = ".\src"
.\.venv\Scripts\python.exe -m cyber_assessment.web
```

The dashboard, history, findings, and report pages are read-only. Starting an assessment requires a POST form submission, validation against the existing target allowlist, and a separate review page that displays the original target, resolved approved IPs, methods, ports, and restrictions. The confirmation is one-time, expires after five minutes, and passes the already validated scope to the existing CLI assessment workflow. TLS verification, redirect scope checks, and loopback-only rules remain unchanged.

The local interface uses CSRF tokens, loopback client checks, trusted local hostnames, context-escaped Jinja templates, and a sandboxed HTML report preview. It does not expose database file paths, arbitrary file reads, credentials, raw cookie values, or response bodies.

## Public demonstration on Render

The Render deployment is a **read-only demonstration**, separate from the local assessment application:

- It displays fixed, synthetic examples marked as sample data; they are not real findings or assessment history.
- It does not load the project configuration, SQLite database, local reports, or environment files.
- Assessment POST routes and all report-view/download routes are disabled in hosted mode.
- The target-validation and assessment workflow remains available only in the local application and retains its loopback-only restrictions.
- The hosted service listens on `0.0.0.0:$PORT` behind Render's service boundary. Do not use the Gunicorn command to expose a local assessment instance.

The repository includes [`render.yaml`](render.yaml). In Render, create a new Blueprint from this repository and review the service settings before applying them. The blueprint sets hosted-demo mode, generates a session secret, and configures `/healthz` as the health check. Render must report a successful deployment before the application can be considered live.

Render build command:

```text
python -m pip install -r requirements.txt
```

Render start command:

```text
gunicorn --chdir src --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 30 cyber_assessment.web.wsgi:app
```

## Local data and reports

- SQLite database: `data\cybersecurity_assessment.db` (created on first confirmed local run).
- JSON and HTML reports: `reports\assessment-<id>.json` and `.html` (local only).

Use `--reports-dir PATH` only for an output directory inside this project. HTML values are escaped at render time; stored observation validation is not treated as output encoding.
Open a locally generated `.html` report in a browser to review the human-readable results. The database, generated reports, active configuration, and real assessment history are excluded from Git and are never loaded by the hosted demo.

## Tests

Tests use the standard-library `unittest` and local loopback services only:

```powershell
$env:PYTHONPATH = ".\src"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

No test contacts a public or third-party system. The tests use temporary test databases; the application itself uses only the dedicated project database path above.
