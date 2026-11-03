"""Data access functions for dashboard.

All SQL queries are here, not in the UI code.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime


def get_kpi(conn: sqlite3.Connection) -> dict:
    """Calculate KPIs for overview page."""
    # Requests per minute (last 5 minutes)
    cursor = conn.execute(
        """
        SELECT COUNT(*) FROM events
        WHERE timestamp >= datetime('now', '-5 minutes')
        """
    )
    recent_count = cursor.fetchone()[0]
    requests_per_min = recent_count / 5.0

    # Blocked count
    cursor = conn.execute(
        "SELECT COUNT(*) FROM events WHERE action = 'block'"
    )
    blocked = cursor.fetchone()[0]

    # Active bans
    now = datetime.now(tz=UTC).timestamp()
    cursor = conn.execute(
        "SELECT COUNT(*) FROM blocklist WHERE banned_until > ?", (now,)
    )
    active_bans = cursor.fetchone()[0]

    # Open alerts
    cursor = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE status = 'new'"
    )
    open_alerts = cursor.fetchone()[0]

    # Average risk score (last 100 events)
    cursor = conn.execute(
        "SELECT AVG(risk_score) FROM (SELECT risk_score FROM events ORDER BY id DESC LIMIT 100)"
    )
    avg_risk = cursor.fetchone()[0] or 0.0

    return {
        "requests_per_min": requests_per_min,
        "blocked": blocked,
        "active_bans": active_bans,
        "open_alerts": open_alerts,
        "avg_risk": avg_risk,
    }


def get_alert_counts(conn: sqlite3.Connection) -> dict:
    """Count alerts by severity."""
    cursor = conn.execute(
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
    )
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for row in cursor:
        severity, count = row
        counts[severity] = count
    return counts


def get_alerts(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    """Fetch recent alerts."""
    cursor = conn.execute(
        """
        SELECT alert_id, ip, rule, severity, status, mitre_id, evidence, created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]


def get_recent_events(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    """Fetch recent events."""
    cursor = conn.execute(
        """
        SELECT timestamp, source_ip, method, path, query, status, user_agent,
               latency_ms, rule_hit, attack_type, ml_score, cvss_score,
               risk_score, action, source
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]


def get_top_attackers(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    """Get top attackers by request count and risk."""
    cursor = conn.execute(
        """
        SELECT source_ip,
               COUNT(*) as request_count,
               AVG(risk_score) as avg_risk,
               MAX(risk_score) as max_risk
        FROM events
        WHERE risk_score > 0
        GROUP BY source_ip
        ORDER BY max_risk DESC, request_count DESC
        LIMIT ?
        """,
        (limit,),
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]


def get_blocklist(conn: sqlite3.Connection) -> list[dict]:
    """Fetch current blocklist."""
    now = datetime.now(tz=UTC).timestamp()
    cursor = conn.execute(
        """
        SELECT ip, banned_until, reason, created_at
        FROM blocklist
        WHERE banned_until > ?
        ORDER BY banned_until DESC
        """,
        (now,),
    )
    columns = [d[0] for d in cursor.description]
    return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]
