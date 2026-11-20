"""Loopback-only Flask interface for the existing assessment workflow."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from .. import cli
from ..config import CONFIG_DIR, PROJECT_ROOT, AppSettings, load_allowlist, load_settings
from ..database import AssessmentDatabase
from ..errors import (
    AssessmentError,
    AssessmentNotFoundError,
    PersistenceError,
)
from ..models import AssessmentScope, TargetRule
from ..scope import match_target_rule, resolve_scope, validated_rules

_ASSESSMENT_ID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_REPORT_NAME = re.compile(
    r"^assessment-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.(json|html)$"
)
_METHOD_ORDER = ("tcp", "http", "https")
_SEVERITIES = ("informational", "low", "medium", "high")
_PENDING_SECONDS = 300
_DEMO_ASSESSMENT_ID = "00000000-0000-4000-8000-000000000001"

AssessmentRunner = Callable[
    [AssessmentScope, tuple[TargetRule, ...], AppSettings, tuple[str, ...], Path],
    tuple[str, Path, Path],
]


@dataclass(frozen=True)
class _PendingAssessment:
    scope: AssessmentScope
    methods: tuple[str, ...]
    expires_at: float


def _reports_directory(value: str | Path) -> Path:
    directory = Path(value).resolve()
    try:
        directory.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise ValueError("The web application may only access reports inside this project.") from exc
    return directory


def _report_path(directory: Path, assessment_id: str, extension: str) -> Path:
    if not _ASSESSMENT_ID.fullmatch(assessment_id) or extension not in {"json", "html"}:
        abort(404)
    root = directory.resolve()
    path = (root / f"assessment-{assessment_id}.{extension}").resolve()
    if path.parent != root or not path.is_file():
        abort(404)
    return path


def _existing_reports(directory: Path) -> list[dict[str, object]]:
    root = directory.resolve()
    if not root.is_dir():
        return []
    reports: dict[str, set[str]] = {}
    try:
        for path in root.iterdir():
            match = _REPORT_NAME.fullmatch(path.name)
            if match is None or not path.is_file() or path.resolve().parent != root:
                continue
            assessment_id, extension = match.groups()
            reports.setdefault(assessment_id, set()).add(extension)
    except OSError as exc:
        raise PersistenceError("Stored reports could not be listed.") from exc
    return [
        {"assessment_id": assessment_id, "formats": tuple(sorted(formats))}
        for assessment_id, formats in sorted(reports.items(), reverse=True)
    ]


def _method_selection(mode: str, rule: TargetRule) -> tuple[str, ...]:
    if mode == "all":
        requested = set(_METHOD_ORDER)
    elif mode == "tcp":
        requested = {"tcp"}
    elif mode == "web":
        requested = {"http", "https"}
    else:
        raise AssessmentError("Choose one of the displayed assessment method options.")
    methods = tuple(method for method in _METHOD_ORDER if method in requested and method in rule.methods)
    if not methods:
        raise AssessmentError("The selected assessment method is not approved for this target.")
    return methods


def _demo_findings() -> list[dict[str, object]]:
    return [
        {
            "assessment_id": _DEMO_ASSESSMENT_ID,
            "requested_target": "demo.local",
            "severity": "informational",
            "confidence": "high",
            "category": "sample_observation",
            "title": "Sample observation: approved TCP port responded",
            "description": "Illustrative finding only; no connection was made to a target.",
            "recommendation": "Review the scope and evidence in a real, authorized local assessment.",
            "created_at": "SAMPLE DATA",
            "evidence": {"notice": "Synthetic demonstration value; not an observed result."},
        },
        {
            "assessment_id": _DEMO_ASSESSMENT_ID,
            "requested_target": "demo.local",
            "severity": "low",
            "confidence": "medium",
            "category": "sample_web_header",
            "title": "Sample observation: security header not shown",
            "description": "This sample illustrates a possible web configuration observation.",
            "recommendation": "Evaluate security headers in the context of the application.",
            "created_at": "SAMPLE DATA",
            "evidence": {"notice": "Synthetic demonstration value; not an observed result."},
        },
    ]


def _demo_assessment_summary() -> dict[str, object]:
    assessment = {
        "assessment_id": _DEMO_ASSESSMENT_ID,
        "requested_target": "demo.local",
        "canonical_target": "demo.local",
        "target_kind": "hostname",
        "started_at": "SAMPLE DATA",
        "finished_at": "SAMPLE DATA",
        "status": "completed",
    }
    return {
        "total_assessments": 1,
        "latest_assessment": assessment,
        "findings_by_severity": {
            "informational": 1,
            "low": 1,
            "medium": 0,
            "high": 0,
        },
    }


def _demo_assessment_result() -> dict[str, object]:
    findings = _demo_findings()
    return {
        "assessment": {
            "assessment_id": _DEMO_ASSESSMENT_ID,
            "requested_target": "demo.local",
            "canonical_target": "demo.local",
            "target_kind": "hostname",
            "started_at": "SAMPLE DATA",
            "finished_at": "SAMPLE DATA",
            "status": "completed",
        },
        "scope": {"approved_ports": (80, 443)},
        "resolved_addresses": [{"ip_address": "127.0.0.1"}],
        "module_runs": [
            {
                "module_name": "tcp_assessment",
                "status": "succeeded",
                "observations_count": 1,
                "error_code": None,
            },
            {
                "module_name": "web_assessment",
                "status": "succeeded",
                "observations_count": 1,
                "error_code": None,
            },
        ],
        "port_results": [
            {
                "ip_address": "127.0.0.1",
                "port": 443,
                "state": "open",
                "service_name": "https",
                "error_code": "sample_only",
                "identification_basis": None,
            },
        ],
        "web_results": [
            {
                "requested_scheme": "https",
                "requested_host": "demo.local",
                "connected_ip": "127.0.0.1",
                "port": 443,
                "http_status": 200,
                "tls_status": "verified",
                "error_code": None,
                "headers": (("strict-transport-security", "sample-only"),),
                "cookies": (),
            },
        ],
        "findings": findings,
    }


def create_app(
    test_config: dict[str, object] | None = None,
    *,
    database: AssessmentDatabase | None = None,
    assessment_runner: AssessmentRunner | None = None,
) -> Flask:
    """Create the local app or an isolated, read-only hosted demonstration."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    hosted_demo_env = os.environ.get("CYBER_ASSESSMENT_HOSTED_DEMO", "").strip().lower() in {
        "1",
        "true",
    }
    configured_secret = os.environ.get("CYBER_ASSESSMENT_SECRET_KEY")
    if hosted_demo_env and (
        not configured_secret or not configured_secret.strip()
    ):
        raise RuntimeError("Hosted demo mode requires CYBER_ASSESSMENT_SECRET_KEY.")
    app.config.from_mapping(
        SECRET_KEY=configured_secret or secrets.token_urlsafe(32),
        HOSTED_DEMO=hosted_demo_env,
        MAX_CONTENT_LENGTH=16 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        REPORTS_DIR=PROJECT_ROOT / "reports",
    )
    if test_config:
        app.config.update(test_config)
    hosted_demo = app.config["HOSTED_DEMO"]
    if type(hosted_demo) is not bool:
        raise ValueError("HOSTED_DEMO must be a boolean.")
    secret_key = app.config["SECRET_KEY"]
    if hosted_demo and (
        not isinstance(secret_key, str) or not secret_key.strip()
    ):
        raise RuntimeError("Hosted demo mode requires a non-empty session secret.")
    if hosted_demo:
        app.config["SESSION_COOKIE_SECURE"] = True

    if hosted_demo:
        app.config.pop("REPORTS_DIR", None)
        settings = None
        rules: tuple[TargetRule, ...] = ()
        repository = None
    else:
        app.config["REPORTS_DIR"] = _reports_directory(app.config["REPORTS_DIR"])
        settings = load_settings(CONFIG_DIR)
        rules = validated_rules(load_allowlist(CONFIG_DIR), settings.approved_ports)
        repository = database or AssessmentDatabase()
        repository.initialize()
        app.extensions["cyber_assessment.database"] = repository
        app.extensions["cyber_assessment.assessment_runner"] = assessment_runner or cli._assess

    pending: dict[str, _PendingAssessment] = {}
    pending_lock = threading.Lock()

    @app.context_processor
    def inject_display_mode():
        def static_asset_url(filename: str) -> str:
            if hosted_demo:
                return f"/{filename.lstrip('/')}"
            return url_for("static", filename=filename)

        return {
            "hosted_demo": hosted_demo,
            "static_asset_url": static_asset_url,
        }

    def csrf_token() -> str:
        token = session.get("_csrf_token")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def discard_expired_pending() -> None:
        now = time.monotonic()
        expired = [token for token, item in pending.items() if item.expires_at <= now]
        for token in expired:
            pending.pop(token, None)

    def get_pending(token: str, *, consume: bool) -> _PendingAssessment | None:
        with pending_lock:
            discard_expired_pending()
            item = pending.get(token)
            if item is not None and consume:
                pending.pop(token, None)
            return item

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def enforce_local_access_and_csrf():
        if not hosted_demo:
            try:
                host_parts = urlsplit(f"//{request.host}")
                host_name = host_parts.hostname
                host_parts.port
            except ValueError:
                abort(400)
            if host_name not in {"127.0.0.1", "localhost"}:
                abort(400)
            try:
                remote_address = ipaddress.ip_address(request.remote_addr or "")
            except ValueError:
                abort(403)
            if not remote_address.is_loopback:
                abort(403)
        elif request.endpoint in {
            "preview_assessment",
            "confirm_assessment",
            "cancel_assessment",
        }:
            abort(404)
        if request.method == "POST":
            expected = session.get("_csrf_token", "")
            supplied = request.form.get("csrf_token", "")
            if not isinstance(expected, str) or not supplied or not secrets.compare_digest(expected, supplied):
                abort(400)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "sandbox; default-src 'none'; style-src 'unsafe-inline'; "
            "frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
            if request.endpoint == "view_html_report"
            else (
                "default-src 'self'; style-src 'self'; script-src 'self'; "
                "frame-src 'self'; object-src 'none'; base-uri 'self'; "
                "form-action 'self'; frame-ancestors 'none'"
            )
        )
        return response

    @app.errorhandler(PersistenceError)
    def persistence_error(_error: PersistenceError):
        current_app.logger.error("Assessment database operation failed.")
        return render_template(
            "error.html",
            title="Assessment data unavailable",
            message="The local assessment database could not complete this request.",
            status_code=503,
        ), 503

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html",
            title="Page not found",
            message="The requested assessment or report is not available.",
            status_code=404,
        ), 404

    @app.errorhandler(400)
    def bad_request(_error):
        return render_template(
            "error.html",
            title="Request not accepted",
            message="The form could not be verified. Reload the page and try again.",
            status_code=400,
        ), 400

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template(
            "error.html",
            title="Local access only",
            message="The local application accepts browser requests from loopback only.",
            status_code=403,
        ), 403

    @app.get("/healthz")
    def health_check():
        return jsonify(status="ok", mode="demo" if hosted_demo else "local")

    @app.get("/")
    def dashboard():
        if hosted_demo:
            summary = _demo_assessment_summary()
            recent = [_demo_assessment_result()["assessment"]]
        else:
            assert repository is not None
            summary = repository.get_dashboard_summary()
            recent = repository.list_assessments(limit=8)
        return render_template("dashboard.html", summary=summary, recent=recent)

    @app.get("/assessments/new")
    def new_assessment():
        return render_template(
            "new_assessment.html",
            targets=rules,
            error=None,
            target_value="",
            hosted_demo=hosted_demo,
        )

    @app.post("/assessments/preview")
    def preview_assessment():
        if hosted_demo:
            abort(404)
        assert settings is not None
        target = request.form.get("target", "")
        mode = request.form.get("method_mode", "all")
        try:
            _, _, rule = match_target_rule(target, rules, settings.approved_ports)
            methods = _method_selection(mode, rule)
            ports = tuple(port for port in rule.ports if port in settings.approved_ports)
            scope = resolve_scope(
                target,
                rules,
                settings.approved_ports,
                requested_methods=methods,
                requested_ports=ports,
            )
        except (AssessmentError, ValueError) as exc:
            return render_template(
                "new_assessment.html",
                targets=rules,
                error=str(exc),
                target_value=target[:253],
            ), 400

        pending_token = secrets.token_urlsafe(32)
        with pending_lock:
            discard_expired_pending()
            pending[pending_token] = _PendingAssessment(
                scope=scope,
                methods=methods,
                expires_at=time.monotonic() + _PENDING_SECONDS,
            )
        return render_template(
            "confirm_assessment.html",
            scope=scope,
            methods=methods,
            pending_token=pending_token,
            expires_minutes=_PENDING_SECONDS // 60,
            error=None,
        )

    @app.post("/assessments/<pending_token>/confirm")
    def confirm_assessment(pending_token: str):
        if hosted_demo:
            abort(404)
        assert settings is not None
        item = get_pending(pending_token, consume=False)
        if item is None:
            abort(404)
        if request.form.get("acknowledged") != "yes" or request.form.get("confirmation") != "yes":
            return render_template(
                "confirm_assessment.html",
                scope=item.scope,
                methods=item.methods,
                pending_token=pending_token,
                expires_minutes=_PENDING_SECONDS // 60,
                error="Tick the authorization acknowledgement and type yes to start.",
            ), 400

        item = get_pending(pending_token, consume=True)
        if item is None:
            abort(404)
        reports_dir = Path(current_app.config["REPORTS_DIR"])
        runner: AssessmentRunner = current_app.extensions["cyber_assessment.assessment_runner"]
        try:
            status, json_path, _html_path = runner(
                item.scope,
                rules,
                settings,
                item.methods,
                reports_dir,
            )
        except (AssessmentError, OSError) as exc:
            current_app.logger.error("Assessment could not be completed: %s", type(exc).__name__)
            flash("Assessment could not be completed. Review the local application log.", "error")
            return redirect(url_for("new_assessment"))

        report_match = _REPORT_NAME.fullmatch(Path(json_path).name)
        if report_match is None or report_match.group(2) != "json":
            raise PersistenceError("Assessment workflow returned an invalid report reference.")
        assessment_id = report_match.group(1)
        if status not in {"completed", "partial", "failed"}:
            raise PersistenceError("Assessment workflow returned an unknown status.")
        flash(
            f"Assessment run recorded with status {status}. Review its observations.",
            "error" if status == "failed" else "success",
        )
        return redirect(url_for("assessment_result", assessment_id=assessment_id))

    @app.post("/assessments/<pending_token>/cancel")
    def cancel_assessment(pending_token: str):
        if hosted_demo:
            abort(404)
        get_pending(pending_token, consume=True)
        flash("Assessment cancelled; no assessment connections were started.", "info")
        return redirect(url_for("new_assessment"))

    @app.get("/assessments/<assessment_id>")
    def assessment_result(assessment_id: str):
        if not _ASSESSMENT_ID.fullmatch(assessment_id):
            abort(404)
        if hosted_demo:
            if assessment_id != _DEMO_ASSESSMENT_ID:
                abort(404)
            data = _demo_assessment_result()
        else:
            assert repository is not None
            try:
                data = repository.get_assessment(assessment_id)
            except AssessmentNotFoundError:
                abort(404)
        return render_template("assessment_result.html", data=data)

    @app.get("/findings")
    def findings():
        severity = request.args.get("severity")
        if severity not in {None, "", *_SEVERITIES}:
            abort(400)
        selected_severity = severity or None
        if hosted_demo:
            items = [
                item for item in _demo_findings()
                if selected_severity is None or item["severity"] == selected_severity
            ]
        else:
            assert repository is not None
            items = repository.list_findings(severity=selected_severity)
        return render_template(
            "findings.html",
            findings=items,
            severities=_SEVERITIES,
            selected_severity=selected_severity,
        )

    @app.get("/history")
    def history():
        if hosted_demo:
            assessments = [_demo_assessment_result()["assessment"]]
        else:
            assert repository is not None
            assessments = repository.list_assessments(limit=200)
        return render_template("history.html", assessments=assessments)

    @app.get("/reports")
    def reports():
        existing = (
            []
            if hosted_demo
            else _existing_reports(Path(current_app.config["REPORTS_DIR"]))
        )
        return render_template("reports.html", reports=existing, hosted_demo=hosted_demo)

    @app.get("/reports/<assessment_id>/view")
    def report_view(assessment_id: str):
        if hosted_demo:
            abort(404)
        if not _ASSESSMENT_ID.fullmatch(assessment_id):
            abort(404)
        report = next(
            (item for item in _existing_reports(Path(current_app.config["REPORTS_DIR"]))
             if item["assessment_id"] == assessment_id),
            None,
        )
        if report is None:
            abort(404)
        formats = set(report["formats"])
        return render_template(
            "report_view.html",
            assessment_id=assessment_id,
            has_json="json" in formats,
            has_html="html" in formats,
        )

    @app.get("/reports/<assessment_id>/view/json")
    def view_json_report(assessment_id: str):
        if hosted_demo:
            abort(404)
        path = _report_path(Path(current_app.config["REPORTS_DIR"]), assessment_id, "json")
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            current_app.logger.error("Stored JSON report is unavailable or invalid: %s", type(exc).__name__)
            raise PersistenceError("Stored JSON report could not be read.") from exc
        return render_template("report_json.html", assessment_id=assessment_id, report_text=json.dumps(report, indent=2))

    @app.get("/reports/<assessment_id>/view/html")
    def view_html_report(assessment_id: str):
        if hosted_demo:
            abort(404)
        path = _report_path(Path(current_app.config["REPORTS_DIR"]), assessment_id, "html")
        response = send_file(
            path,
            mimetype="text/html",
            as_attachment=False,
            download_name=path.name,
            conditional=False,
        )
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    @app.get("/reports/<assessment_id>/download/<extension>")
    def download_report(assessment_id: str, extension: str):
        if hosted_demo:
            abort(404)
        path = _report_path(Path(current_app.config["REPORTS_DIR"]), assessment_id, extension)
        mimetype = "application/json" if extension == "json" else "text/html"
        return send_file(path, mimetype=mimetype, as_attachment=True, download_name=path.name)

    return app
