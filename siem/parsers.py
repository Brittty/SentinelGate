"""Log parsers for SentinelGate SIEM.

Parses Linux auth.log and nginx combined log format into Event-shaped dicts.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

_AUTH_FAILED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\S+):\s+Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_AUTH_INVALID_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\S+):\s+Invalid user (?P<user>\S+) from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def _month_num(mon: str) -> int:
    try:
        return datetime.strptime(mon, "%b").month
    except ValueError:
        return 1


def _auth_log_timestamp(month: str, day: str, time_str: str, year: int) -> str:
    dt = datetime(year, _month_num(month), int(day), tzinfo=UTC)
    h, m, s = map(int, time_str.split(":"))
    dt = dt.replace(hour=h, minute=m, second=s)
    return dt.isoformat()


def parse_auth_log(text: str, year: int | None = None) -> list[dict[str, Any]]:
    """Parse Linux auth.log lines for Failed password / Invalid user events."""
    if year is None:
        year = datetime.now(tz=UTC).year
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = _AUTH_FAILED_RE.search(line) or _AUTH_INVALID_RE.search(line)
        if not m:
            continue
        ip = m.group("ip")
        ts = _auth_log_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
        events.append(
            {
                "timestamp": ts,
                "source_ip": ip,
                "method": "POST",
                "path": "/login",
                "query": "",
                "status": 401,
                "user_agent": "",
                "latency_ms": 0.0,
                "rule_hit": "",
                "attack_type": "brute_force",
                "ml_score": 0.0,
                "cvss_score": 0.0,
                "risk_score": 0.0,
                "action": "block",
                "source": "siem",
            }
        )
    return events


def parse_nginx_combined(text: str) -> list[dict[str, Any]]:
    """Parse nginx combined log format into Event dicts."""
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = _NGINX_RE.search(line)
        if not m:
            continue
        status = int(m.group("status"))
        action = "allow"
        if status >= HTTPStatus.BAD_REQUEST:
            action = (
                "throttle" if status == HTTPStatus.TOO_MANY_REQUESTS else "block"
            )
        events.append(
            {
                "timestamp": _parse_nginx_time(m.group("time")),
                "source_ip": m.group("ip"),
                "method": m.group("method"),
                "path": m.group("path"),
                "query": "",
                "status": status,
                "user_agent": m.group("ua"),
                "latency_ms": 0.0,
                "rule_hit": "",
                "attack_type": "",
                "ml_score": 0.0,
                "cvss_score": 0.0,
                "risk_score": 0.0,
                "action": action,
                "source": "siem",
            }
        )
    return events


def _parse_nginx_time(time_str: str) -> str:
    # Format: 10/Oct/2000:13:55:36 -0700
    try:
        dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        return datetime.now(tz=UTC).isoformat()
