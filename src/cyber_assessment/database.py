"""SQLite schema and persistence for this project's dedicated database."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from .config import PROJECT_ROOT
from .errors import PersistenceError, ScopeDeniedError
from .models import (
    AssessmentScope,
    Finding,
    ModuleRunResult,
    PortResult,
    WebResult,
    utc_now,
)
from .risk import classify_port, classify_web

DB_PATH = PROJECT_ROOT / "data" / "cybersecurity_assessment.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    requested_target TEXT NOT NULL,
    canonical_target TEXT NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('ip', 'hostname')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'partial', 'aborted', 'failed')),
    confirmation_at TEXT NOT NULL,
    scope_snapshot_json TEXT NOT NULL,
    tool_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS module_runs (
    module_run_id INTEGER PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    module_name TEXT NOT NULL CHECK (module_name IN ('tcp_assessment', 'web_assessment')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'partial', 'failed', 'skipped')),
    started_at TEXT,
    finished_at TEXT,
    error_code TEXT,
    error_detail TEXT,
    observations_count INTEGER NOT NULL DEFAULT 0 CHECK (observations_count >= 0),
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    UNIQUE (assessment_id, module_name),
    UNIQUE (module_run_id, assessment_id, module_name)
);

CREATE TABLE IF NOT EXISTS resolved_addresses (
    resolved_address_id INTEGER PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    hostname TEXT,
    ip_address TEXT NOT NULL,
    address_family INTEGER NOT NULL CHECK (address_family IN (4, 6)),
    approved INTEGER NOT NULL CHECK (approved = 1),
    approved_rule_id TEXT NOT NULL,
    resolved_at TEXT NOT NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    UNIQUE (assessment_id, ip_address),
    UNIQUE (assessment_id, ip_address, approved)
);

CREATE TABLE IF NOT EXISTS port_results (
    port_result_id INTEGER PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    module_run_id INTEGER NOT NULL,
    module_name TEXT NOT NULL DEFAULT 'tcp_assessment' CHECK (module_name = 'tcp_assessment'),
    ip_address TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 1 CHECK (approved = 1),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'TCP' CHECK (protocol = 'TCP'),
    state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'filtered_unknown')),
    service_name TEXT,
    identification_basis TEXT,
    latency_ms REAL CHECK (latency_ms IS NULL OR latency_ms >= 0),
    error_code TEXT,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id, ip_address, approved)
        REFERENCES resolved_addresses(assessment_id, ip_address, approved),
    FOREIGN KEY (module_run_id, assessment_id, module_name)
        REFERENCES module_runs(module_run_id, assessment_id, module_name),
    UNIQUE (assessment_id, ip_address, port, protocol),
    UNIQUE (port_result_id, assessment_id)
);

CREATE TABLE IF NOT EXISTS web_results (
    web_result_id INTEGER PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    module_run_id INTEGER NOT NULL,
    module_name TEXT NOT NULL DEFAULT 'web_assessment' CHECK (module_name = 'web_assessment'),
    requested_scheme TEXT NOT NULL CHECK (requested_scheme IN ('http', 'https')),
    requested_host TEXT NOT NULL,
    connected_ip TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 1 CHECK (approved = 1),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    redirect_chain_json TEXT NOT NULL,
    tls_status TEXT NOT NULL CHECK (tls_status IN ('verified', 'failed', 'not_applicable', 'not_checked')),
    headers_json TEXT NOT NULL,
    cookie_attributes_json TEXT NOT NULL,
    error_code TEXT,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id, connected_ip, approved)
        REFERENCES resolved_addresses(assessment_id, ip_address, approved),
    FOREIGN KEY (module_run_id, assessment_id, module_name)
        REFERENCES module_runs(module_run_id, assessment_id, module_name),
    UNIQUE (web_result_id, assessment_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    port_result_id INTEGER,
    web_result_id INTEGER,
    severity TEXT NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high')),
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (port_result_id, assessment_id)
        REFERENCES port_results(port_result_id, assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (web_result_id, assessment_id)
        REFERENCES web_results(web_result_id, assessment_id) ON DELETE CASCADE,
    CHECK (NOT (port_result_id IS NOT NULL AND web_result_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_assessments_started ON assessments(started_at);
CREATE INDEX IF NOT EXISTS idx_module_runs_assessment ON module_runs(assessment_id);
CREATE INDEX IF NOT EXISTS idx_port_results_assessment ON port_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_web_results_assessment ON web_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
"""


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _clean_text(value: str | None, limit: int = 1000) -> str | None:
    if value is None:
        return None
    return "".join(char for char in str(value) if char >= " " and char != "\x7f")[:limit]


class AssessmentDatabase:
    """Project SQLite repository. Production defaults to the fixed dedicated DB path."""

    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        try:
            if str(self.path) != ":memory:":
                self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(self.path), timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        except sqlite3.Error as exc:
            raise PersistenceError(f"Could not open the project assessment database: {exc}") from exc

    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Connection, None, None]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        try:
            with self._transaction() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise PersistenceError(f"Could not initialize the project assessment database: {exc}") from exc

    def create_assessment(self, scope: AssessmentScope, assessment_id: str, confirmation_at: str) -> dict[str, int]:
        """Create a running assessment, approved IP rows, and its two module runs."""
        self.initialize()
        module_ids: dict[str, int] = {}
        snapshot = {
            "approved_ports": list(scope.approved_ports),
            "permitted_methods": sorted(scope.permitted_methods),
            "resolved_addresses": list(scope.approved_ips),
        }
        try:
            with self._transaction() as connection:
                connection.execute(
                    """INSERT INTO assessments
                    (assessment_id, requested_target, canonical_target, target_kind,
                     started_at, finished_at, status, confirmation_at, scope_snapshot_json, tool_version)
                    VALUES (?, ?, ?, ?, ?, NULL, 'running', ?, ?, ?)""",
                    (
                        assessment_id,
                        _clean_text(scope.original_target, 253),
                        scope.canonical_target,
                        scope.target_kind,
                        utc_now(),
                        confirmation_at,
                        _json(snapshot),
                        "0.1.0",
                    ),
                )
                for address in scope.approved_addresses:
                    ip_obj = ipaddress.ip_address(address.ip_address)
                    if not ip_obj.is_loopback:
                        raise ScopeDeniedError("Refusing to store a non-loopback resolved address.")
                    connection.execute(
                        """INSERT INTO resolved_addresses
                        (assessment_id, hostname, ip_address, address_family, approved,
                         approved_rule_id, resolved_at)
                        VALUES (?, ?, ?, ?, 1, ?, ?)""",
                        (
                            assessment_id,
                            address.hostname,
                            str(ip_obj),
                            ip_obj.version,
                            address.approved_rule_id,
                            address.resolved_at,
                        ),
                    )
                for module_name in ("tcp_assessment", "web_assessment"):
                    cursor = connection.execute(
                        """INSERT INTO module_runs
                        (assessment_id, module_name, status, observations_count)
                        VALUES (?, ?, 'pending', 0)""",
                        (assessment_id, module_name),
                    )
                    module_ids[module_name] = int(cursor.lastrowid)
        except (sqlite3.Error, ScopeDeniedError) as exc:
            if isinstance(exc, ScopeDeniedError):
                raise
            raise PersistenceError(f"Could not create assessment records: {exc}") from exc
        return module_ids

    def mark_module_running(self, module_run_id: int) -> None:
        try:
            with self._transaction() as connection:
                connection.execute(
                    "UPDATE module_runs SET status='running', started_at=? WHERE module_run_id=? AND status='pending'",
                    (utc_now(), module_run_id),
                )
                if connection.total_changes != 1:
                    raise PersistenceError("Module run was not in the pending state.")
        except sqlite3.Error as exc:
            raise PersistenceError(f"Could not start module run: {exc}") from exc

    def complete_module(self, result: ModuleRunResult) -> None:
        """Commit one module's observations and status independently from other modules."""
        observations = [*result.port_results, *result.web_results]
        run_id = result.module_run_id
        try:
            with self._transaction() as connection:
                module_row = connection.execute(
                    "SELECT assessment_id, module_name FROM module_runs WHERE module_run_id=?",
                    (run_id,),
                ).fetchone()
                if module_row is None or module_row["module_name"] != result.module_name:
                    raise PersistenceError("Module result does not match a registered module run.")
                assessment_id = module_row["assessment_id"]
                for port_result in result.port_results:
                    self._validate_port_result(port_result, assessment_id, run_id)
                    cursor = connection.execute(
                        """INSERT INTO port_results
                        (assessment_id, module_run_id, module_name, ip_address, approved, port,
                         state, service_name, identification_basis, latency_ms, error_code, observed_at)
                        VALUES (?, ?, 'tcp_assessment', ?, 1, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            assessment_id, run_id, port_result.ip_address, port_result.port,
                            port_result.state, port_result.service_name,
                            port_result.identification_basis, port_result.latency_ms,
                            port_result.error_code, port_result.observed_at,
                        ),
                    )
                    finding = classify_port(port_result)
                    if finding is not None:
                        self._insert_finding(
                            connection,
                            assessment_id,
                            finding,
                            port_result_id=int(cursor.lastrowid),
                        )
                for web_result in result.web_results:
                    self._validate_web_result(web_result, assessment_id, run_id)
                    for ip_text in web_result.approved_hop_ips:
                        ip_obj = ipaddress.ip_address(ip_text)
                        if not ip_obj.is_loopback:
                            raise ScopeDeniedError("Refusing to persist a non-loopback redirect address.")
                        connection.execute(
                            """INSERT OR IGNORE INTO resolved_addresses
                            (assessment_id, hostname, ip_address, address_family, approved,
                             approved_rule_id, resolved_at)
                            VALUES (?, ?, ?, ?, 1, 'validated-redirect', ?)""",
                            (
                                assessment_id, web_result.requested_host, str(ip_obj),
                                ip_obj.version, web_result.observed_at,
                            ),
                        )
                    cursor = connection.execute(
                        """INSERT INTO web_results
                        (assessment_id, module_run_id, module_name, requested_scheme, requested_host,
                         connected_ip, approved, port, http_status, redirect_chain_json, tls_status,
                         headers_json, cookie_attributes_json, error_code, observed_at)
                        VALUES (?, ?, 'web_assessment', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            assessment_id, run_id, web_result.requested_scheme,
                            _clean_text(web_result.requested_host, 253),
                            web_result.connected_ip, web_result.port, web_result.http_status,
                            _json(web_result.redirect_chain), web_result.tls_status,
                            _json(web_result.headers),
                            _json([cookie.__dict__ for cookie in web_result.cookies]),
                            web_result.error_code, web_result.observed_at,
                        ),
                    )
                    for finding in classify_web(web_result):
                        self._insert_finding(
                            connection,
                            assessment_id,
                            finding,
                            web_result_id=int(cursor.lastrowid),
                        )
                connection.execute(
                    """UPDATE module_runs
                    SET status=?, started_at=COALESCE(started_at, ?), finished_at=?,
                        error_code=?, error_detail=?, observations_count=?
                    WHERE module_run_id=?""",
                    (
                        result.status,
                        result.started_at,
                        result.finished_at,
                        _clean_text(result.error_code, 100),
                        _clean_text(result.error_detail, 500),
                        len(observations),
                        run_id,
                    ),
                )
        except (sqlite3.Error, ValueError, ScopeDeniedError, PersistenceError) as exc:
            if isinstance(exc, (ScopeDeniedError, PersistenceError)):
                raise
            raise PersistenceError(f"Could not persist {result.module_name} results: {exc}") from exc

    @staticmethod
    def _validate_port_result(result: PortResult, assessment_id: str, run_id: int) -> None:
        if result.assessment_id != assessment_id or result.module_run_id != run_id:
            raise PersistenceError("TCP result references the wrong assessment or module run.")
        if not ipaddress.ip_address(result.ip_address).is_loopback:
            raise ScopeDeniedError("TCP result destination is not loopback.")

    @staticmethod
    def _validate_web_result(result: WebResult, assessment_id: str, run_id: int) -> None:
        if result.assessment_id != assessment_id or result.module_run_id != run_id:
            raise PersistenceError("Web result references the wrong assessment or module run.")
        if result.connected_ip is not None and not ipaddress.ip_address(result.connected_ip).is_loopback:
            raise ScopeDeniedError("Web result destination is not loopback.")
        if result.connected_ip is not None and result.connected_ip not in result.approved_hop_ips:
            raise ScopeDeniedError("Web result IP is missing from its approved redirect chain.")

    @staticmethod
    def _insert_finding(
        connection: sqlite3.Connection,
        assessment_id: str,
        finding: Finding,
        port_result_id: int | None = None,
        web_result_id: int | None = None,
    ) -> None:
        connection.execute(
            """INSERT INTO findings
            (assessment_id, port_result_id, web_result_id, severity, confidence, category,
             title, description, evidence_json, recommendation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                assessment_id, port_result_id, web_result_id, finding.severity,
                finding.confidence, finding.category, _clean_text(finding.title, 180),
                _clean_text(finding.description, 1000), _json(finding.evidence),
                _clean_text(finding.recommendation, 1000), finding.created_at,
            ),
        )

    def finalize_assessment(self, assessment_id: str) -> str:
        try:
            with self._transaction() as connection:
                rows = connection.execute(
                    "SELECT status, observations_count FROM module_runs WHERE assessment_id=?",
                    (assessment_id,),
                ).fetchall()
                applicable = [row for row in rows if row["status"] != "skipped"]
                if not applicable:
                    final_status = "failed"
                elif all(row["status"] == "succeeded" for row in applicable):
                    final_status = "completed"
                elif any(
                    row["status"] in {"succeeded", "partial"} and row["observations_count"] > 0
                    for row in applicable
                ):
                    final_status = "partial"
                else:
                    final_status = "failed"
                connection.execute(
                    "UPDATE assessments SET status=?, finished_at=? WHERE assessment_id=?",
                    (final_status, utc_now(), assessment_id),
                )
                return final_status
        except sqlite3.Error as exc:
            raise PersistenceError(f"Could not finalize assessment: {exc}") from exc

    def get_assessment(self, assessment_id: str) -> dict[str, object]:
        try:
            with self._transaction() as connection:
                assessment = connection.execute(
                    "SELECT * FROM assessments WHERE assessment_id=?", (assessment_id,)
                ).fetchone()
                if assessment is None:
                    raise PersistenceError("Assessment does not exist.")
                modules = connection.execute(
                    "SELECT * FROM module_runs WHERE assessment_id=? ORDER BY module_name",
                    (assessment_id,),
                ).fetchall()
                addresses = connection.execute(
                    "SELECT * FROM resolved_addresses WHERE assessment_id=? ORDER BY ip_address",
                    (assessment_id,),
                ).fetchall()
                ports = connection.execute(
                    "SELECT * FROM port_results WHERE assessment_id=? ORDER BY ip_address, port",
                    (assessment_id,),
                ).fetchall()
                web = connection.execute(
                    "SELECT * FROM web_results WHERE assessment_id=? ORDER BY web_result_id",
                    (assessment_id,),
                ).fetchall()
                findings = connection.execute(
                    "SELECT * FROM findings WHERE assessment_id=? ORDER BY finding_id",
                    (assessment_id,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Could not load assessment report data: {exc}") from exc

        return {
            "assessment": dict(assessment),
            "scope": json.loads(assessment["scope_snapshot_json"]),
            "resolved_addresses": [dict(row) for row in addresses],
            "module_runs": [dict(row) for row in modules],
            "port_results": [dict(row) for row in ports],
            "web_results": [
                {
                    **dict(row),
                    "redirect_chain": json.loads(row["redirect_chain_json"]),
                    "headers": json.loads(row["headers_json"]),
                    "cookies": json.loads(row["cookie_attributes_json"]),
                }
                for row in web
            ],
            "findings": [
                {
                    **dict(row),
                    "evidence": json.loads(row["evidence_json"]),
                }
                for row in findings
            ],
        }
