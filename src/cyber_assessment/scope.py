"""Validate targets and create immutable, loopback-only connection scopes."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Literal
from urllib.parse import urlsplit

from .errors import InvalidTargetError, ResolutionError, ScopeDeniedError
from .models import AssessmentScope, ResolvedAddress, TargetRule, utc_now

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_host(value: str) -> tuple[str, Literal["ip", "hostname"]]:
    """Return canonical host and kind, rejecting URL-like or ambiguous input."""
    if not isinstance(value, str) or not value or len(value) > 253:
        raise InvalidTargetError("Enter one IP address or hostname (up to 253 characters).")
    if value != value.strip() or any(character in value for character in "/\\@?#") or "%" in value:
        raise InvalidTargetError("Enter a host only, without URL paths, credentials, or zone IDs.")
    try:
        address = ipaddress.ip_address(value)
        return str(address), "ip"
    except ValueError:
        pass

    candidate = value[:-1] if value.endswith(".") else value
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidTargetError("Hostname is not valid IDNA text.") from exc
    if not hostname or len(hostname) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in hostname.split(".")):
        raise InvalidTargetError("Hostname contains an invalid label.")
    return hostname, "hostname"


def validated_rules(rules: tuple[TargetRule, ...], global_ports: tuple[int, ...]) -> tuple[TargetRule, ...]:
    """Validate allowlist entries; configuration cannot authorize non-loopback IPs."""
    checked: list[TargetRule] = []
    for rule in rules:
        canonical_host, _ = normalize_host(rule.host)
        if canonical_host != rule.host.lower().rstrip("."):
            # IP addresses are already canonicalized by ipaddress; hostnames must be normalized.
            if canonical_host != rule.host.lower():
                raise ScopeDeniedError(f"Allowlist host {rule.host!r} is not canonical.")
        approved_ips: list[str] = []
        for configured_ip in rule.approved_ips:
            try:
                address = ipaddress.ip_address(configured_ip)
            except ValueError as exc:
                raise ScopeDeniedError(f"Allowlist rule {rule.rule_id} has an invalid IP.") from exc
            if not address.is_loopback:
                raise ScopeDeniedError("This implementation allows loopback addresses only.")
            approved_ips.append(str(address))
        if not set(rule.ports).issubset(global_ports):
            raise ScopeDeniedError(f"Allowlist rule {rule.rule_id} includes a port not globally approved.")
        checked.append(
            TargetRule(
                rule_id=rule.rule_id,
                host=canonical_host,
                approved_ips=tuple(dict.fromkeys(approved_ips)),
                ports=rule.ports,
                methods=rule.methods,
            )
        )
    return tuple(checked)


def match_target_rule(
    target: str,
    rules: tuple[TargetRule, ...],
    global_ports: tuple[int, ...],
) -> tuple[str, str, TargetRule]:
    """Validate target syntax and require an exact project-local allowlist rule."""
    canonical, kind = normalize_host(target)
    checked_rules = validated_rules(rules, global_ports)
    for rule in checked_rules:
        if rule.host == canonical:
            if kind == "ip" and canonical not in rule.approved_ips:
                continue
            return canonical, kind, rule
    raise ScopeDeniedError("Target is not present in the project-local allowlist.")


def _resolve_addresses(host: str) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolutionError(f"Could not resolve approved hostname {host!r}.") from exc
    addresses = tuple(dict.fromkeys(record[4][0].split("%", 1)[0] for record in records))
    if not addresses:
        raise ResolutionError(f"Approved hostname {host!r} returned no addresses.")
    return addresses


def resolve_scope(
    original_target: str,
    rules: tuple[TargetRule, ...],
    global_ports: tuple[int, ...],
    requested_methods: tuple[str, ...] = ("tcp", "http", "https"),
    requested_ports: tuple[int, ...] | None = None,
) -> AssessmentScope:
    """Resolve and pin an allowlisted target; reject every non-loopback DNS answer."""
    canonical, kind, rule = match_target_rule(original_target, rules, global_ports)
    ports = tuple(requested_ports or rule.ports)
    methods = frozenset(requested_methods)
    if not ports or not set(ports).issubset(rule.ports) or not set(ports).issubset(global_ports):
        raise ScopeDeniedError("Requested ports exceed the target's approved port list.")
    if not methods or not methods.issubset(set(rule.methods)):
        raise ScopeDeniedError("Requested assessment methods exceed the target's approved methods.")

    raw_addresses = (canonical,) if kind == "ip" else _resolve_addresses(canonical)
    parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_ip in raw_addresses:
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise ResolutionError("Resolver returned an invalid IP address.") from exc
        if not address.is_loopback:
            raise ScopeDeniedError("Hostname resolved outside loopback; no assessment connection was made.")
        if str(address) not in rule.approved_ips:
            raise ScopeDeniedError("Hostname resolved to an IP not approved by its allowlist rule.")
        parsed_addresses.append(address)

    timestamp = utc_now()
    resolved = tuple(
        ResolvedAddress(
            hostname=canonical if kind == "hostname" else None,
            ip_address=str(address),
            address_family=4 if address.version == 4 else 6,
            approved_rule_id=rule.rule_id,
            resolved_at=timestamp,
        )
        for address in parsed_addresses
    )
    mapping = ((canonical, tuple(item.ip_address for item in resolved)),)
    return AssessmentScope(
        original_target=original_target,
        canonical_target=canonical,
        target_kind=kind,
        approved_addresses=resolved,
        hostname_to_ips=mapping,
        approved_ports=ports,
        permitted_methods=methods,
    )


def validate_redirect(
    location: str,
    current_url: str,
    rules: tuple[TargetRule, ...],
    global_ports: tuple[int, ...],
    source_scope: AssessmentScope,
) -> tuple[str, AssessmentScope]:
    """Resolve and authorize one redirect before any request follows it."""
    from urllib.parse import urljoin

    absolute_url = urljoin(current_url, location)
    parsed = urlsplit(absolute_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScopeDeniedError("Redirect uses an unsupported scheme or embedded credentials.")
    canonical, _ = normalize_host(parsed.hostname)
    port = parsed.port or (443 if scheme == "https" else 80)
    method = scheme
    if method not in source_scope.permitted_methods:
        raise ScopeDeniedError("Redirect method is not permitted by the assessment scope.")
    redirect_scope = resolve_scope(
        canonical,
        rules,
        global_ports,
        requested_methods=(method,),
        requested_ports=(port,),
    )
    return absolute_url, redirect_scope
