"""Sequential TCP connection checks for approved loopback addresses only."""

from __future__ import annotations

import ipaddress
import socket
import time

from .config import AppSettings
from .errors import ScopeDeniedError
from .models import AssessmentScope, ModuleRunResult, PortResult, utc_now
from .service_id import identify_service


def assess_tcp(
    scope: AssessmentScope,
    assessment_id: str,
    module_run_id: int,
    settings: AppSettings,
) -> ModuleRunResult:
    """Check each approved address/port once, classifying ambiguity as unknown."""
    started_at = utc_now()
    if "tcp" not in scope.permitted_methods:
        raise ScopeDeniedError("TCP assessment is not permitted by this scope.")
    results: list[PortResult] = []
    for ip_text in scope.approved_ips:
        address = ipaddress.ip_address(ip_text)
        if not address.is_loopback:
            raise ScopeDeniedError("TCP assessor received a non-loopback destination.")
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        for port_index, port in enumerate(scope.approved_ports):
            started = time.monotonic()
            state = "filtered_unknown"
            error_code: str | None = None
            try:
                with socket.socket(family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(settings.connect_timeout_seconds)
                    sockaddr = (ip_text, port, 0, 0) if address.version == 6 else (ip_text, port)
                    connection.connect(sockaddr)
                    state = "open"
            except ConnectionRefusedError:
                state = "closed"
                error_code = "connection_refused"
            except (socket.timeout, TimeoutError):
                error_code = "timeout"
            except OSError:
                error_code = "network_error"
            latency = (time.monotonic() - started) * 1000
            result = PortResult(
                assessment_id=assessment_id,
                module_run_id=module_run_id,
                ip_address=ip_text,
                port=port,
                state=state,  # type: ignore[arg-type]
                service_name=None,
                identification_basis=None,
                latency_ms=round(latency, 2),
                error_code=error_code,
            )
            results.append(identify_service(result))
            if port_index < len(scope.approved_ports) - 1 or ip_text != scope.approved_ips[-1]:
                time.sleep(settings.minimum_delay_seconds)
    return ModuleRunResult(
        module_name="tcp_assessment",
        status="succeeded",
        module_run_id=module_run_id,
        port_results=tuple(results),
        started_at=started_at,
        finished_at=utc_now(),
    )
