"""Correlation engine for SentinelGate SIEM.

Analyzes recent events to detect multi-request patterns: brute force,
scanning (404 bursts), injection bursts, and multi-stage attacks.
Produces alert dicts that are written to the alerts table via Store.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
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
    dt = datetime.fromtimestamp(now, tz=timezone.utc) - timedelta(seconds=seconds)
    return dt.isoformat()


def correlate(
    events: list[dict], store: Any, now: float | None = None
) -> list[dict]:
    """Run correlation rules against *events*.

    Returns a list of alert dicts. De-duplicates repeated alerts within a
    time window by checking existing alerts in *store*.
    """
    if now is None:
        now = datetime.now(tz=timezone.utc).timestamp()

    alerts: list[dict] = []
    rules = _load_rules()
    if not rules:
        return alerts

    # Index events by source_ip
    by_ip: dict[str, list[dict]] = {}
    for ev in events:
        by_ip.setdefault(ev.get("source_ip", "unknown"), []).append(ev)

    for rule in rules:
        rid = rule["id"]
        window = rule.get("window_seconds", 60)
        threshold = rule.get("threshold", 5)
        start_iso = _window_start(window, now)

        for ip, ip_events in by_ip.items():
            window_events = [
                ev for ev in ip_events if ev.get("timestamp", "") >= start_iso
            ]

            if rid == "brute_force":
                count = sum(
                    1
                    for ev in window_events
                    if ev.get("status") in (401, 403)
                    and "/login" in ev.get("path", "")
                )
                if count >= threshold:
                    alerts.append(
                        _make_alert(
                            rid, ip, rule, count, window_events, now
                        )
                    )

            elif rid == "scan":
                paths = {
                    ev.get("path", "")
                    for ev in window_events
                    if ev.get("status") == 404
                }
                if len(paths) >= threshold:
                    alerts.append(
                        _make_alert(
                            rid, ip, rule, len(paths), window_events, now
                        )
                    )

            elif rid == "injection_burst":
                count = sum(
                    1
                    for ev in window_events
                    if ev.get("attack_type")
                    in ("sqli", "xss", "command_injection", "ssrf")
                )
                if count >= threshold:
                    alerts.append(
                        _make_alert(
                            rid, ip, rule, count, window_events, now
                        )
                    )

    # Multi-stage: scan then injection within window
    ms_rule = next((r for r in rules if r["id"] == "multi_stage"), None)
    if ms_rule:
        window = ms_rule.get("window_seconds", 600)
        start_iso = _window_start(window, now)
        for ip, ip_events in by_ip.items():
            window_events = [
                ev for ev in ip_events if ev.get("timestamp", "") >= start_iso
            ]
            has_scan = any(ev.get("status") == 404 for ev in window_events)
            has_injection = any(
                ev.get("attack_type")
                in ("sqli", "xss", "command_injection", "ssrf")
                for ev in window_events
            )
            if has_scan and has_injection:
                alerts.append(
                    _make_alert(
                        "multi_stage", ip, ms_rule, 2, window_events, now
                    )
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


def _make_alert(
    rule_id: str, ip: str, rule: dict, count: int, events: list[dict], now: float
) -> dict:
    created = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    evidence = {
        "count": count,
        "window_seconds": rule.get("window_seconds", 0),
        "sample_events": events[:5],
    }
    import json

    return {
        "alert_id": f"{rule_id}-{ip}-{int(now)}",
        "ip": ip,
        "rule": rule["name"],
        "severity": rule["severity"],
        "status": "new",
        "mitre_id": rule.get("mitre_id", ""),
        "evidence": json.dumps(evidence),
        "created_at": created,
    }
