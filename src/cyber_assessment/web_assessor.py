"""HTTP/HTTPS checks that connect to pinned, allowlisted loopback IPs."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util.connection import create_connection

from .config import AppSettings
from .errors import ScopeDeniedError
from .models import (
    AssessmentScope,
    CookieAttributes,
    ModuleRunResult,
    TargetRule,
    WebResult,
    utc_now,
)
from .scope import validate_redirect

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


class _PinnedHTTPConnection(HTTPConnection):
    """HTTP connection that refuses hostnames and connects only to a literal IP."""

    def _new_conn(self) -> socket.socket:
        address = ipaddress.ip_address(self.host)
        if not address.is_loopback:
            raise ScopeDeniedError("HTTP connection refused: destination is not loopback.")
        return create_connection(
            (str(address), self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )


class _PinnedHTTPSConnection(HTTPSConnection):
    """HTTPS connection; the pool IP is pinned while TLS checks the original name."""

    def _new_conn(self) -> socket.socket:
        address = ipaddress.ip_address(self.host)
        if not address.is_loopback:
            raise ScopeDeniedError("HTTPS connection refused: destination is not loopback.")
        return create_connection(
            (str(address), self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class PinnedHTTPAdapter(HTTPAdapter):
    """Requests adapter whose connection pool host is an approved literal IP."""

    def __init__(
        self,
        approved_ip: str,
        expected_hostname: str,
        timeout_seconds: float,
    ) -> None:
        self.approved_ip = str(ipaddress.ip_address(approved_ip))
        if not ipaddress.ip_address(self.approved_ip).is_loopback:
            raise ScopeDeniedError("Pinned HTTP adapter accepts loopback IP addresses only.")
        self.expected_hostname = expected_hostname
        self.timeout_seconds = timeout_seconds
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if verify is not True:
            raise ScopeDeniedError("HTTPS certificate verification cannot be disabled or overridden.")
        if cert is not None:
            raise ScopeDeniedError("Client certificates are not used by this assessment tool.")
        if proxies:
            raise ScopeDeniedError("Proxy use is disabled for pinned assessments.")
        parsed = urlsplit(request.url)
        if parsed.hostname != self.expected_hostname:
            raise ScopeDeniedError("Request hostname does not match the validated target.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "https":
            # The pool's host is an IP literal, avoiding a second DNS lookup.
            # TLS SNI and certificate matching remain the original hostname.
            return _PinnedHTTPSConnectionPool(
                host=self.approved_ip,
                port=port,
                timeout=self.timeout_seconds,
                maxsize=1,
                block=True,
                retries=False,
                server_hostname=self.expected_hostname,
                assert_hostname=self.expected_hostname,
            )
        if parsed.scheme == "http":
            return _PinnedHTTPConnectionPool(
                host=self.approved_ip,
                port=port,
                timeout=self.timeout_seconds,
                maxsize=1,
                block=True,
                retries=False,
            )
        raise ScopeDeniedError("Only HTTP and HTTPS are supported.")


def _host_header(hostname: str, port: int, scheme: str) -> str:
    try:
        address = ipaddress.ip_address(hostname)
        rendered = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        rendered = hostname
    default_port = 443 if scheme == "https" else 80
    return rendered if port == default_port else f"{rendered}:{port}"


def _url_for(hostname: str, scheme: str, port: int) -> str:
    host = _host_header(hostname, port, scheme)
    return urlunsplit((scheme, host, "/", "", ""))


def _header_values(response: requests.Response) -> tuple[tuple[str, str], ...]:
    observed: list[tuple[str, str]] = []
    for name in _SECURITY_HEADERS:
        value = response.headers.get(name)
        if value is not None:
            safe_value = "".join(char for char in value if char >= " " and char != "\x7f")[:1024]
            observed.append((name, safe_value))
    return tuple(observed)


def _cookie_attributes(response: requests.Response) -> tuple[CookieAttributes, ...]:
    raw_headers = getattr(response.raw, "headers", None)
    get_all = getattr(raw_headers, "getlist", None)
    set_cookie_headers = get_all("Set-Cookie") if get_all else []
    cookies: list[CookieAttributes] = []
    for header in set_cookie_headers:
        parts = [part.strip() for part in header.split(";")]
        first = parts[0] if parts else ""
        name = first.split("=", 1)[0].strip()[:100]
        if not name:
            continue
        attributes = {part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip()
                      for part in parts[1:] if "=" in part}
        flags = {part.strip().lower() for part in parts[1:] if "=" not in part}
        same_site = attributes.get("samesite")
        cookies.append(
            CookieAttributes(
                name=name,
                secure="secure" in flags,
                httponly="httponly" in flags,
                samesite=same_site[:40] if same_site else None,
            )
        )
    return tuple(cookies)


def _result(
    assessment_id: str,
    module_run_id: int,
    scheme: str,
    hostname: str,
    port: int,
    connected_ip: str | None,
    status: int | None,
    redirects: list[str],
    tls_status: str,
    headers: tuple[tuple[str, str], ...],
    cookies: tuple[CookieAttributes, ...],
    approved_hop_ips: set[str],
    error_code: str | None,
) -> WebResult:
    return WebResult(
        assessment_id=assessment_id,
        module_run_id=module_run_id,
        requested_scheme=scheme,
        requested_host=hostname,
        connected_ip=connected_ip,
        port=port,
        http_status=status,
        redirect_chain=tuple(redirects),
        tls_status=tls_status,
        headers=headers,
        cookies=cookies,
        approved_hop_ips=tuple(sorted(approved_hop_ips)),
        error_code=error_code,
        observed_at=utc_now(),
    )


def _assess_one(
    scope: AssessmentScope,
    rules: tuple[TargetRule, ...],
    settings: AppSettings,
    assessment_id: str,
    module_run_id: int,
    scheme: str,
    initial_port: int,
    initial_ip: str,
) -> WebResult:
    current_ip = initial_ip
    current_host = scope.canonical_target
    current_scheme = scheme
    current_port = initial_port
    current_url = _url_for(current_host, scheme, current_port)
    redirects: list[str] = []
    approved_hop_ips = {initial_ip}
    last_status: int | None = None
    last_headers: tuple[tuple[str, str], ...] = ()
    all_cookies: list[CookieAttributes] = []
    tls_status = "not_applicable" if scheme == "http" else "not_checked"

    for redirect_number in range(settings.max_redirects + 1):
        adapter = PinnedHTTPAdapter(current_ip, current_host, settings.request_timeout_seconds)
        try:
            with requests.Session() as session:
                session.trust_env = False
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                response = session.get(
                    current_url,
                    headers={
                        "Host": _host_header(current_host, current_port, current_scheme),
                        "User-Agent": settings.user_agent,
                        "Connection": "close",
                    },
                    timeout=(settings.connect_timeout_seconds, settings.request_timeout_seconds),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )
                try:
                    last_status = response.status_code
                    last_headers = _header_values(response)
                    all_cookies.extend(_cookie_attributes(response))
                    if current_scheme == "https":
                        tls_status = "verified"
                    location = response.headers.get("Location")
                    if response.is_redirect and location:
                        if redirect_number >= settings.max_redirects:
                            return _result(
                                assessment_id, module_run_id, scheme, current_host,
                                initial_port, current_ip, last_status, redirects, tls_status,
                                last_headers, tuple(all_cookies), approved_hop_ips, "redirect_limit",
                            )
                        try:
                            next_url, next_scope = validate_redirect(
                                location,
                                current_url,
                                rules,
                                settings.approved_ports,
                                scope,
                            )
                        except (ScopeDeniedError, ValueError):
                            return _result(
                                assessment_id, module_run_id, scheme, current_host,
                                initial_port, current_ip, last_status, redirects, tls_status,
                                last_headers, tuple(all_cookies), approved_hop_ips,
                                "redirect_out_of_scope",
                            )
                        next_parts = urlsplit(next_url)
                        next_host = next_scope.canonical_target
                        next_port = next_parts.port or (443 if next_parts.scheme == "https" else 80)
                        next_ips = next_scope.ips_for_hostname(next_host)
                        if not next_ips:
                            return _result(
                                assessment_id, module_run_id, scheme, current_host,
                                initial_port, current_ip, last_status, redirects, tls_status,
                                last_headers, tuple(all_cookies), approved_hop_ips,
                                "redirect_out_of_scope",
                            )
                        redirects.append(f"{next_parts.scheme}://{_host_header(next_host, next_port, next_parts.scheme)}")
                        current_url = next_url
                        current_host = next_host
                        current_scheme = next_parts.scheme
                        current_port = next_port
                        current_ip = next_ips[0]
                        approved_hop_ips.update(next_ips)
                        if next_parts.scheme == "https":
                            tls_status = "not_checked"
                        else:
                            tls_status = "not_applicable"
                        continue
                    return _result(
                        assessment_id, module_run_id, scheme, current_host,
                        initial_port, current_ip, last_status, redirects, tls_status,
                        last_headers, tuple(all_cookies), approved_hop_ips, None,
                    )
                finally:
                    response.close()
        except requests.exceptions.SSLError:
            return _result(
                assessment_id, module_run_id, scheme, current_host, initial_port,
                current_ip, last_status, redirects, "failed" if current_scheme == "https" else tls_status,
                last_headers, tuple(all_cookies), approved_hop_ips, "tls_error",
            )
        except requests.exceptions.Timeout:
            return _result(
                assessment_id, module_run_id, scheme, current_host, initial_port,
                current_ip, last_status, redirects, tls_status, last_headers,
                tuple(all_cookies), approved_hop_ips, "timeout",
            )
        except (requests.exceptions.RequestException, OSError):
            return _result(
                assessment_id, module_run_id, scheme, current_host, initial_port,
                current_ip, last_status, redirects, tls_status, last_headers,
                tuple(all_cookies), approved_hop_ips, "transport_error",
            )
        finally:
            adapter.close()
    return _result(
        assessment_id, module_run_id, scheme, current_host, initial_port, current_ip,
        last_status, redirects, tls_status, last_headers, tuple(all_cookies),
        approved_hop_ips, "redirect_limit",
    )


def assess_web(
    scope: AssessmentScope,
    rules: tuple[TargetRule, ...],
    settings: AppSettings,
    assessment_id: str,
    module_run_id: int,
) -> ModuleRunResult:
    """Inspect configured local web ports without using ambient DNS or proxies."""
    started_at = utc_now()
    results: list[WebResult] = []
    attempted = 0
    for scheme in ("http", "https"):
        if scheme not in scope.permitted_methods:
            continue
        for port in settings.ports_for_scheme(scheme):
            if port not in scope.approved_ports:
                continue
            for ip_address in scope.approved_ips:
                if not ipaddress.ip_address(ip_address).is_loopback:
                    raise ScopeDeniedError("Web assessor received a non-loopback destination.")
                attempted += 1
                results.append(
                    _assess_one(
                        scope, rules, settings, assessment_id, module_run_id,
                        scheme, port, ip_address,
                    )
                )
    if attempted == 0:
        raise ScopeDeniedError("No configured web checks are permitted by this scope.")
    failures = sum(result.error_code is not None for result in results)
    successes = sum(result.http_status is not None for result in results)
    if failures and successes:
        status = "partial"
    elif failures:
        status = "failed"
    else:
        status = "succeeded"
    return ModuleRunResult(
        module_name="web_assessment",
        status=status,  # type: ignore[arg-type]
        module_run_id=module_run_id,
        web_results=tuple(results),
        error_code="web_checks_failed" if failures else None,
        error_detail=f"{failures} of {attempted} web checks failed." if failures else None,
        started_at=started_at,
        finished_at=utc_now(),
    )
