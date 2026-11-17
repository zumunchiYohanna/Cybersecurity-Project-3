"""Cautious service-name hints based on conventional TCP ports."""

from __future__ import annotations

from .models import PortResult

_KNOWN_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    8000: "http-alt",
    8080: "http-alt",
}


def identify_service(port_result: PortResult) -> PortResult:
    """Attach a low-confidence conventional port label; never claim verification."""
    if port_result.state != "open":
        return port_result
    service = _KNOWN_PORTS.get(port_result.port)
    if service is None:
        return port_result
    from dataclasses import replace

    return replace(
        port_result,
        service_name=service,
        identification_basis="well_known_port",
    )
