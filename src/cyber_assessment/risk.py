"""Qualitative, conservative risk classification for collected observations."""

from __future__ import annotations

import re

from .models import Finding, PortResult, WebResult


def classify_port(result: PortResult) -> Finding | None:
    if result.state == "open":
        return Finding(
            assessment_id=result.assessment_id,
            severity="informational",
            confidence="medium" if result.identification_basis else "high",
            category="network_exposure",
            title=f"TCP port {result.port} is open",
            description="A TCP connection to this approved loopback port succeeded. This does not establish a vulnerability.",
            evidence={"ip_address": result.ip_address, "port": result.port, "service": result.service_name},
            recommendation="Confirm that the local service is required and configured appropriately.",
        )
    return None


def classify_web(result: WebResult) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    headers = {name.lower(): value for name, value in result.headers}
    if result.error_code == "tls_error":
        findings.append(
            Finding(
                assessment_id=result.assessment_id,
                severity="medium",
                confidence="high",
                category="transport",
                title="TLS certificate verification failed",
                description="The local HTTPS endpoint did not pass the client's certificate verification.",
                evidence={"host": result.requested_host, "port": result.port},
                recommendation="Use a trusted certificate whose name matches the hostname.",
            )
        )
    if result.error_code is not None and result.http_status is None:
        return tuple(findings)
    checks = (
        ("x-content-type-options", "X-Content-Type-Options", "low"),
        ("content-security-policy", "Content-Security-Policy", "low"),
        ("referrer-policy", "Referrer-Policy", "low"),
    )
    if result.requested_scheme == "https" and result.tls_status == "verified":
        checks += (("strict-transport-security", "Strict-Transport-Security", "low"),)
    for key, label, severity in checks:
        if key not in headers:
            findings.append(
                Finding(
                    assessment_id=result.assessment_id,
                    severity=severity,  # type: ignore[arg-type]
                    confidence="medium",
                    category="header",
                    title=f"{label} response header not observed",
                    description="The header was absent from this response; application context may change its significance.",
                    evidence={"scheme": result.requested_scheme, "port": result.port},
                    recommendation=f"Review whether {label} is appropriate for this endpoint.",
                )
            )
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        findings.append(
            Finding(
                assessment_id=result.assessment_id,
                severity="low",
                confidence="medium",
                category="header",
                title="Frame embedding protection not observed",
                description="Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
                evidence={"scheme": result.requested_scheme, "port": result.port},
                recommendation="Review clickjacking protections for this page.",
            )
        )
    if result.requested_scheme == "https":
        for cookie in result.cookies:
            if re.search(r"(session|sess|auth|token|^sid$)", cookie.name, re.IGNORECASE):
                if not cookie.secure:
                    findings.append(
                        Finding(
                            assessment_id=result.assessment_id,
                            severity="medium",
                            confidence="medium",
                            category="cookie",
                            title="Likely session cookie lacks Secure attribute",
                            description="A cookie with a session-like name was observed without the Secure attribute.",
                            evidence={"cookie_name": cookie.name, "port": result.port},
                            recommendation="Review whether this cookie should be marked Secure.",
                        )
                    )
                if not cookie.httponly:
                    findings.append(
                        Finding(
                            assessment_id=result.assessment_id,
                            severity="low",
                            confidence="medium",
                            category="cookie",
                            title="Likely session cookie lacks HttpOnly attribute",
                            description="A cookie with a session-like name was observed without the HttpOnly attribute.",
                            evidence={"cookie_name": cookie.name, "port": result.port},
                            recommendation="Review whether this cookie should be marked HttpOnly.",
                        )
                    )
    return tuple(findings)
