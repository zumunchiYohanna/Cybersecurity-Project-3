"""Load and validate configuration stored inside this project."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .models import TargetRule

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"


@dataclass(frozen=True)
class AppSettings:
    approved_ports: tuple[int, ...]
    web_ports: tuple[tuple[str, tuple[int, ...]], ...]
    connect_timeout_seconds: float
    request_timeout_seconds: float
    minimum_delay_seconds: float
    max_redirects: int
    user_agent: str

    def ports_for_scheme(self, scheme: str) -> tuple[int, ...]:
        for configured_scheme, ports in self.web_ports:
            if configured_scheme == scheme:
                return ports
        return ()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            value = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read project configuration {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"{path.name} must contain a JSON object.")
    return value


def _valid_port_list(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError(f"{label} must be a non-empty list of TCP ports.")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in value):
        raise ConfigurationError(f"{label} may contain only integer ports from 1 to 65535.")
    if len(set(value)) != len(value):
        raise ConfigurationError(f"{label} cannot contain duplicate ports.")
    return tuple(value)


def load_settings(config_dir: Path = CONFIG_DIR) -> AppSettings:
    data = _read_json(config_dir / "app_settings.json")
    approved_ports = _valid_port_list(data.get("approved_ports"), "approved_ports")

    web_data = data.get("web_ports")
    if not isinstance(web_data, dict) or set(web_data) != {"http", "https"}:
        raise ConfigurationError("web_ports must define exactly the http and https port lists.")
    web_ports = tuple(
        (scheme, _valid_port_list(web_data[scheme], f"web_ports.{scheme}"))
        for scheme in ("http", "https")
    )
    if any(port not in approved_ports for _, ports in web_ports for port in ports):
        raise ConfigurationError("Every web port must also appear in approved_ports.")

    connect_timeout = data.get("connect_timeout_seconds")
    request_timeout = data.get("request_timeout_seconds")
    delay = data.get("minimum_delay_seconds")
    max_redirects = data.get("max_redirects")
    user_agent = data.get("user_agent")
    if type(connect_timeout) not in (int, float) or not 0 < connect_timeout <= 3:
        raise ConfigurationError("connect_timeout_seconds must be greater than 0 and at most 3.")
    if type(request_timeout) not in (int, float) or not 0 < request_timeout <= 5:
        raise ConfigurationError("request_timeout_seconds must be greater than 0 and at most 5.")
    if type(delay) not in (int, float) or not 0.1 <= delay <= 2:
        raise ConfigurationError("minimum_delay_seconds must be between 0.1 and 2.")
    if type(max_redirects) is not int or not 0 <= max_redirects <= 3:
        raise ConfigurationError("max_redirects must be an integer from 0 to 3.")
    if not isinstance(user_agent, str) or not user_agent.strip() or len(user_agent) > 120:
        raise ConfigurationError("user_agent must be a non-empty string of at most 120 characters.")

    return AppSettings(
        approved_ports=approved_ports,
        web_ports=web_ports,
        connect_timeout_seconds=float(connect_timeout),
        request_timeout_seconds=float(request_timeout),
        minimum_delay_seconds=float(delay),
        max_redirects=max_redirects,
        user_agent=user_agent.strip(),
    )


def load_allowlist(config_dir: Path = CONFIG_DIR) -> tuple[TargetRule, ...]:
    data = _read_json(config_dir / "approved_targets.json")
    entries = data.get("targets")
    if not isinstance(entries, list) or not entries:
        raise ConfigurationError("approved_targets.json must contain a non-empty targets list.")

    rules: list[TargetRule] = []
    seen_hosts: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigurationError(f"targets[{index}] must be a JSON object.")
        rule_id = entry.get("rule_id")
        host = entry.get("host")
        ips = entry.get("approved_ips")
        methods = entry.get("methods")
        if not isinstance(rule_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", rule_id):
            raise ConfigurationError(f"targets[{index}].rule_id is invalid.")
        if not isinstance(host, str) or not host.strip():
            raise ConfigurationError(f"targets[{index}].host must be a non-empty string.")
        if host.lower() in seen_hosts:
            raise ConfigurationError(f"Duplicate target rule for {host}.")
        seen_hosts.add(host.lower())
        if not isinstance(ips, list) or not ips or any(not isinstance(ip, str) for ip in ips):
            raise ConfigurationError(f"targets[{index}].approved_ips must be a non-empty string list.")
        ports = _valid_port_list(entry.get("ports"), f"targets[{index}].ports")
        if not isinstance(methods, list) or not methods:
            raise ConfigurationError(f"targets[{index}].methods must be a non-empty list.")
        if any(method not in {"tcp", "http", "https"} for method in methods):
            raise ConfigurationError(f"targets[{index}].methods contains an unsupported method.")
        rules.append(
            TargetRule(
                rule_id=rule_id,
                host=host.strip(),
                approved_ips=tuple(ips),
                ports=ports,
                methods=tuple(dict.fromkeys(methods)),
            )
        )
    return tuple(rules)
