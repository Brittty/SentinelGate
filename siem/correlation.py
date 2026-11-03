"""Correlation engine for SentinelGate SIEM.

Analyzes recent events to detect multi-request patterns: brute force,
scanning (404 bursts), injection bursts, and multi-stage attacks.
Produces alert dicts that are written to the alerts table via Store.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any

import yaml

CORRELATION_PATH = "siem/correlation.yaml"


def _load_rules() -> list[dict]:
    try:
        with open(CORRELATION_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data.get("rules", [])
    except (OSError, yaml.YAMLError):
        return []


def _window_start(seconds: int, now: float) -> str:
    dt = datetime.fromtimestamp(now, tz=UTC) - timedelta(seconds=seconds)
    return dt.isoformat()


def correlate(
    events: list[dict], store: Any, now: float | None = None
) -> list[dict]:
    """Run correlation rules against *events*.

    Returns a list of alert dicts. De-duplicates repeated alerts within a
    time window by checking existing alerts in *store*.
    """
    if now is None:
        now = datetime.now(tz=UTC).timestamp()

    alerts: list[dict] = []
    rules = _load_rules()
    if not rules:
        return alerts

    # Index events by source_ip
    by_ip: dict[str, list[dict]] = {}
    for ev in events:
        by_ip.setdefault(ev.get("source_ip", "unknown"), []).append(ev)

    detectors = {
        "brute_force": _bruteforce_count,
        "scan": _scan_path_count,
        "injection_burst": _injection_count,
    }

    for rule in rules:
        detector = detectors.get(rule["id"])
        if detector is None:
            continue
        window = rule.get("window_seconds", 60)
        threshold = rule.get("threshold", 5)
        start_iso = _window_start(window, now)

        for ip, ip_events in by_ip.items():
            window_events = [
                ev for ev in ip_events if ev.get("timestamp", "") >= start_iso
            ]
            count = detector(window_events)
            if count >= threshold:
                alerts.append(_make_alert(ip, rule, count, window_events, now))

    # Multi-stage: scan then injection within window
    ms_rule = next((r for r in rules if r["id"] == "multi_stage"), None)
    if ms_rule:
        window = ms_rule.get("window_seconds", 600)
        start_iso = _window_start(window, now)
        for ip, ip_events in by_ip.items():
            window_events = [
                ev for ev in ip_events if ev.get("timestamp", "") >= start_iso
            ]
            has_scan = any(
                ev.get("status") == HTTPStatus.NOT_FOUND for ev in window_events
            )
            has_injection = any(
                ev.get("attack_type")
                in ("sqli", "xss", "command_injection", "ssrf")
                for ev in window_events
            )
            if has_scan and has_injection:
                alerts.append(
                    _make_alert(ip, ms_rule, 2, window_events, now)
                )

    # De-duplicate against existing alerts
    existing = {
        (a.get("rule"), a.get("ip")) for a in store.get_alerts(limit=1000)
    }
    unique: list[dict] = []
    for alert in alerts:
        key = (alert["rule"], alert["ip"])
        if key not in existing:
            unique.append(alert)
    return unique


def _bruteforce_count(events: list[dict]) -> int:
    """Count failed logins against /login."""
    return sum(
        1
        for ev in events
        if ev.get("status") in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN)
        and "/login" in ev.get("path", "")
    )


def _scan_path_count(events: list[dict]) -> int:
    """Count distinct 404 paths (scanning behavior)."""
    return len(
        {
            ev.get("path", "")
            for ev in events
            if ev.get("status") == HTTPStatus.NOT_FOUND
        }
    )


INJECTION_TYPES = ("sqli", "xss", "command_injection", "ssrf")


def _injection_count(events: list[dict]) -> int:
    """Count events tagged as injection attempts."""
    return sum(1 for ev in events if ev.get("attack_type") in INJECTION_TYPES)


def _make_alert(ip: str, rule: dict, count: int, events: list[dict], now: float) -> dict:
    created = datetime.fromtimestamp(now, tz=UTC).isoformat()
    evidence = {
        "count": count,
        "window_seconds": rule.get("window_seconds", 0),
        "sample_events": events[:5],
    }

    return {
        "alert_id": f"{rule['id']}-{ip}-{int(now)}",
        "ip": ip,
        "rule": rule["name"],
        "severity": rule["severity"],
        "status": "new",
        "mitre_id": rule.get("mitre_id", ""),
        "evidence": json.dumps(evidence),
        "created_at": created,
    }
