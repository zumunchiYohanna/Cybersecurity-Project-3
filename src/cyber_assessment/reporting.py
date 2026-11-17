"""Versioned JSON and HTML report writers with safe output encoding."""

from __future__ import annotations

import html
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .errors import AssessmentError


def _safe_report_dir(output_dir: Path) -> Path:
    directory = Path(output_dir).resolve()
    try:
        directory.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise AssessmentError("Reports must be written inside this project.") from exc
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _atomic_write(path: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            file.write(content)
        os.replace(temporary_path, path)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise AssessmentError(f"Could not write report {path.name}: {exc}") from exc


def _assessment_payload(data: dict[str, Any]) -> dict[str, Any]:
    assessment = dict(data["assessment"])
    assessment["scope"] = data["scope"]
    assessment.pop("scope_snapshot_json", None)
    payload = {
        "schema_version": "1.0",
        "assessment": assessment,
        "module_runs": data["module_runs"],
        "resolved_addresses": data["resolved_addresses"],
        "port_results": data["port_results"],
        "web_results": data["web_results"],
        "findings": data["findings"],
        "limitations": [
            "This assessment covers only the configured checks against loopback addresses.",
            "Results are observations, not proof of vulnerability or overall security.",
        ],
    }
    return payload


def render_html(payload: dict[str, Any]) -> str:
    """Render report data as escaped text; never treat observations as markup."""
    assessment = payload["assessment"]
    escape = lambda value: html.escape(str(value if value is not None else ""), quote=True)
    lines = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Cybersecurity Assessment Report</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.45rem;text-align:left}"
        ".notice{padding:.8rem;background:#fff3cd}</style></head><body>",
        "<h1>Cybersecurity Assessment Report</h1>",
        "<p class=\"notice\">Authorized localhost-only assessment. Findings are limited observations.</p>",
        "<h2>Assessment</h2><dl>",
    ]
    for label, key in (
        ("Assessment ID", "assessment_id"),
        ("Target", "requested_target"),
        ("Status", "status"),
        ("Started", "started_at"),
        ("Finished", "finished_at"),
    ):
        lines.append(f"<dt>{escape(label)}</dt><dd>{escape(assessment.get(key))}</dd>")
    lines.append("</dl><h2>Module status</h2><table><thead><tr><th>Module</th><th>Status</th><th>Error</th></tr></thead><tbody>")
    for module in payload["module_runs"]:
        lines.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(module.get("module_name")),
                escape(module.get("status")),
                escape(module.get("error_detail") or module.get("error_code")),
            )
        )
    lines.append("</tbody></table><h2>TCP results</h2><table><thead><tr><th>Address</th><th>Port</th><th>State</th><th>Likely service</th></tr></thead><tbody>")
    for result in payload["port_results"]:
        lines.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(result.get("ip_address")),
                escape(result.get("port")),
                escape(result.get("state")),
                escape(result.get("service_name")),
            )
        )
    lines.append("</tbody></table><h2>Web results</h2><table><thead><tr><th>Scheme / host</th><th>Connected IP</th><th>Status</th><th>TLS</th><th>Error</th></tr></thead><tbody>")
    for result in payload["web_results"]:
        lines.append(
            "<tr><td>{}://{}:{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(result.get("requested_scheme")),
                escape(result.get("requested_host")),
                escape(result.get("port")),
                escape(result.get("connected_ip")),
                escape(result.get("http_status")),
                escape(result.get("tls_status")),
                escape(result.get("error_code")),
            )
        )
    lines.append("</tbody></table><h2>Findings</h2>")
    for finding in payload["findings"]:
        lines.append(
            "<section><h3>{} — {}</h3><p>{}</p><p><strong>Confidence:</strong> {}</p>"
            "<p><strong>Recommendation:</strong> {}</p></section>".format(
                escape(finding.get("severity")),
                escape(finding.get("title")),
                escape(finding.get("description")),
                escape(finding.get("confidence")),
                escape(finding.get("recommendation")),
            )
        )
    lines.append("<h2>Limitations</h2><ul>")
    for limitation in payload.get("limitations", []):
        lines.append(f"<li>{escape(limitation)}</li>")
    lines.append("</ul></body></html>")
    return "\n".join(lines)


def write_reports(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    directory = _safe_report_dir(output_dir)
    assessment_id = str(data["assessment"]["assessment_id"])
    if not re.fullmatch(r"[a-fA-F0-9-]{36}", assessment_id):
        raise AssessmentError("Assessment ID is not a valid report filename.")
    payload = _assessment_payload(data)
    json_path = directory / f"assessment-{assessment_id}.json"
    html_path = directory / f"assessment-{assessment_id}.html"
    _atomic_write(json_path, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")
    _atomic_write(html_path, render_html(payload))
    return json_path, html_path
