"""Typed data structures shared by the assessment modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

AssessmentStatus = Literal["running", "completed", "partial", "aborted", "failed"]
ModuleStatus = Literal["pending", "running", "succeeded", "partial", "failed", "skipped"]
PortState = Literal["open", "closed", "filtered_unknown"]
Severity = Literal["informational", "low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
ModuleName = Literal["tcp_assessment", "web_assessment"]


def utc_now() -> str:
    """Return a timezone-aware ISO-8601 timestamp in UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class TargetRule:
    """One project-local allowlist rule."""

    rule_id: str
    host: str
    approved_ips: tuple[str, ...]
    ports: tuple[int, ...]
    methods: tuple[str, ...]


@dataclass(frozen=True)
class ResolvedAddress:
    """An IP address checked against the allowlist and loopback restriction."""

    hostname: str | None
    ip_address: str
    address_family: int
    approved_rule_id: str
    resolved_at: str


@dataclass(frozen=True)
class AssessmentScope:
    """Immutable, validated destination and operation limits for one assessment."""

    original_target: str
    canonical_target: str
    target_kind: Literal["ip", "hostname"]
    approved_addresses: tuple[ResolvedAddress, ...]
    hostname_to_ips: tuple[tuple[str, tuple[str, ...]], ...]
    approved_ports: tuple[int, ...]
    permitted_methods: frozenset[str]

    @property
    def approved_ips(self) -> tuple[str, ...]:
        return tuple(address.ip_address for address in self.approved_addresses)

    def ips_for_hostname(self, hostname: str) -> tuple[str, ...]:
        """Return only the already-validated IPs mapped to a hostname."""
        for mapped_hostname, addresses in self.hostname_to_ips:
            if mapped_hostname == hostname:
                return addresses
        if self.target_kind == "ip" and hostname == self.canonical_target:
            return self.approved_ips
        return ()


@dataclass(frozen=True)
class PortResult:
    assessment_id: str
    module_run_id: int
    ip_address: str
    port: int
    state: PortState
    service_name: str | None
    identification_basis: str | None
    latency_ms: float | None
    error_code: str | None
    observed_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class CookieAttributes:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None


@dataclass(frozen=True)
class WebResult:
    assessment_id: str
    module_run_id: int
    requested_scheme: str
    requested_host: str
    connected_ip: str | None
    port: int
    http_status: int | None
    redirect_chain: tuple[str, ...]
    tls_status: str
    headers: tuple[tuple[str, str], ...]
    cookies: tuple[CookieAttributes, ...]
    approved_hop_ips: tuple[str, ...]
    error_code: str | None
    observed_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Finding:
    assessment_id: str
    severity: Severity
    confidence: Confidence
    category: str
    title: str
    description: str
    evidence: dict[str, object]
    recommendation: str
    port_result_id: int | None = None
    web_result_id: int | None = None
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ModuleRunResult:
    module_name: ModuleName
    status: ModuleStatus
    module_run_id: int
    port_results: tuple[PortResult, ...] = ()
    web_results: tuple[WebResult, ...] = ()
    error_code: str | None = None
    error_detail: str | None = None
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class AssessmentResult:
    assessment_id: str
    requested_target: str
    canonical_target: str
    target_kind: str
    status: AssessmentStatus
    started_at: str
    finished_at: str | None
    approved_ports: tuple[int, ...]
    resolved_addresses: tuple[str, ...]
    module_runs: tuple[dict[str, object], ...]
    port_results: tuple[dict[str, object], ...]
    web_results: tuple[dict[str, object], ...]
    findings: tuple[dict[str, object], ...]
