"""Command-line orchestration, confirmation, and user-facing errors."""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

from . import __version__
from .config import CONFIG_DIR, PROJECT_ROOT, load_allowlist, load_settings
from .database import AssessmentDatabase
from .errors import AssessmentError
from .models import AssessmentScope, ModuleRunResult, utc_now
from .scope import match_target_rule, resolve_scope
from .tcp_assessor import assess_tcp
from .web_assessor import assess_web
from .reporting import write_reports


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cyber-assessment",
        description="Conservative, localhost-only network and web checks.",
    )
    parser.add_argument("target", nargs="?", help="allowlisted IP address or hostname (default: prompt)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--tcp-only", action="store_true", help="run TCP checks only")
    modes.add_argument("--web-only", action="store_true", help="run HTTP/HTTPS checks only")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=PROJECT_ROOT / "reports",
        help="report output directory inside the project",
    )
    return parser.parse_args(argv)


def _methods(args: argparse.Namespace) -> tuple[str, ...]:
    if args.tcp_only:
        return ("tcp",)
    if args.web_only:
        return ("http", "https")
    return ("tcp", "http", "https")


def _failed_module(module_name: str, module_run_id: int, exc: Exception) -> ModuleRunResult:
    return ModuleRunResult(
        module_name=module_name,  # type: ignore[arg-type]
        status="failed",
        module_run_id=module_run_id,
        error_code="module_error",
        error_detail=f"{type(exc).__name__}: {str(exc)[:400]}",
        started_at=utc_now(),
        finished_at=utc_now(),
    )


def _mark_skipped(database: AssessmentDatabase, module_name: str, module_run_id: int) -> None:
    database.complete_module(
        ModuleRunResult(
            module_name=module_name,  # type: ignore[arg-type]
            status="skipped",
            module_run_id=module_run_id,
        )
    )


def _assess(
    scope: AssessmentScope,
    rules,
    settings,
    methods: tuple[str, ...],
    reports_dir: Path,
) -> tuple[str, Path, Path]:
    assessment_id = str(uuid.uuid4())
    database = AssessmentDatabase()
    module_ids = database.create_assessment(scope, assessment_id, utc_now())

    tasks = (
        ("tcp_assessment", "tcp", lambda: assess_tcp(scope, assessment_id, module_ids["tcp_assessment"], settings)),
        (
            "web_assessment",
            "web",
            lambda: assess_web(scope, rules, settings, assessment_id, module_ids["web_assessment"]),
        ),
    )
    for module_name, feature, run in tasks:
        module_run_id = module_ids[module_name]
        if feature == "tcp" and "tcp" not in methods:
            _mark_skipped(database, module_name, module_run_id)
            continue
        if feature == "web" and not {"http", "https"}.intersection(methods):
            _mark_skipped(database, module_name, module_run_id)
            continue
        database.mark_module_running(module_run_id)
        try:
            result = run()
        except Exception as exc:
            # Keep the independent module runnable while recording this failure explicitly.
            print(f"{module_name} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            result = _failed_module(module_name, module_run_id, exc)
        database.complete_module(result)
        if result.status in {"partial", "failed"}:
            print(
                f"{module_name} status: {result.status}"
                + (f" ({result.error_detail})" if result.error_detail else ""),
                file=sys.stderr,
            )

    final_status = database.finalize_assessment(assessment_id)
    report_data = database.get_assessment(assessment_id)
    json_path, html_path = write_reports(report_data, reports_dir)
    return final_status, json_path, html_path


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    try:
        settings = load_settings(CONFIG_DIR)
        rules = load_allowlist(CONFIG_DIR)
        target = args.target if args.target is not None else input("Target [localhost]: ").strip() or "localhost"
        canonical, _, rule = match_target_rule(target, rules, settings.approved_ports)
        methods = _methods(args)
        if not set(methods).issubset(set(rule.methods)):
            raise AssessmentError("Selected assessment method is not approved for this target.")
        selected_ports = tuple(
            port for port in rule.ports if port in settings.approved_ports
        )
        scope = resolve_scope(
            target,
            rules,
            settings.approved_ports,
            requested_methods=methods,
            requested_ports=selected_ports,
        )
        print(f"Original target: {scope.original_target}")
        print(f"Canonical target: {scope.canonical_target}")
        print(f"Resolved IP addresses: {', '.join(scope.approved_ips)}")
        print(f"Approved ports: {', '.join(str(port) for port in selected_ports)}")
        print(f"Assessment methods: {', '.join(methods)}")
        print("Restriction: loopback addresses only; redirects must also be allowlisted and loopback.")
        confirmation = input("Type 'yes' to confirm this authorized local assessment: ").strip().lower()
        if confirmation != "yes":
            print("Assessment cancelled; no network connections were made.")
            return 1

        reports_dir = args.reports_dir
        if not reports_dir.is_absolute():
            reports_dir = PROJECT_ROOT / reports_dir
        status, json_path, html_path = _assess(scope, rules, settings, methods, reports_dir)
        print(f"Assessment {status}.")
        print(f"JSON report: {json_path}")
        print(f"HTML report: {html_path}")
        print(f"Database: {PROJECT_ROOT / 'data' / 'cybersecurity_assessment.db'}")
        return 0 if status in {"completed", "partial"} else 2
    except (AssessmentError, OSError, EOFError) as exc:
        print(f"Assessment could not be completed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
