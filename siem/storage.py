"""SIEM storage layer — SQLite in WAL mode.

Tables: events, alerts, blocklist, kv. Indexes on source_ip and timestamp.
All queries are parameterized.
"""

from __future__ import annotations

import sqlite3
from typing import Any


class Store:
    """Wrapper around a SQLite connection in WAL mode."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query TEXT DEFAULT '',
                status INTEGER DEFAULT 200,
                user_agent TEXT DEFAULT '',
                latency_ms REAL DEFAULT 0.0,
                rule_hit TEXT DEFAULT '',
                attack_type TEXT DEFAULT '',
                ml_score REAL DEFAULT 0.0,
                cvss_score REAL DEFAULT 0.0,
                risk_score REAL DEFAULT 0.0,
                action TEXT DEFAULT 'allow',
                source TEXT DEFAULT 'gateway'
            );
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL UNIQUE,
                ip TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'new',
                mitre_id TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE TABLE IF NOT EXISTS blocklist (
                ip TEXT PRIMARY KEY,
                banned_until REAL NOT NULL,
                reason TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    # -- events -----------------------------------------------------------

    def insert_event(self, event: dict[str, Any]) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO events
            (timestamp, source_ip, method, path, query, status, user_agent,
             latency_ms, rule_hit, attack_type, ml_score, cvss_score,
             risk_score, action, source)
            VALUES (:timestamp, :source_ip, :method, :path, :query, :status,
                    :user_agent, :latency_ms, :rule_hit, :attack_type,
                    :ml_score, :cvss_score, :risk_score, :action, :source)
            """,
            event,
        )
        self.conn.commit()
        return cur.lastrowid

    def recent_events(
        self, source_ip: str | None = None, limit: int = 1000
    ) -> list[dict]:
        if source_ip:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE source_ip=? ORDER BY id DESC LIMIT ?",
                (source_ip, limit),
            )
        else:
            rows = self.conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            )
        return self._rows_to_dicts(rows)

    @staticmethod
    def _rows_to_dicts(rows) -> list[dict]:
        return [dict(zip([d[0] for d in rows.description], row)) for row in rows.fetchall()]

    # -- alerts -----------------------------------------------------------

    def insert_alert(self, alert: dict[str, Any]) -> int:
        cur = self.conn.execute(
            """
            INSERT OR IGNORE INTO alerts
            (alert_id, ip, rule, severity, status, mitre_id, evidence, created_at)
            VALUES (:alert_id, :ip, :rule, :severity, :status,
                    :mitre_id, :evidence, :created_at)
            """,
            alert,
        )
        self.conn.commit()
        return cur.lastrowid

    def get_alerts(self, status: str | None = None, limit: int = 100) -> list[dict]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self.conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        return self._rows_to_dicts(rows)

    def update_alert_status(self, alert_id: str, status: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id)
        )
        self.conn.commit()

    # -- blocklist --------------------------------------------------------

    def upsert_blocklist(
        self, ip: str, banned_until: float, reason: str, created_at: str
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO blocklist (ip, banned_until, reason, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                banned_until=excluded.banned_until,
                reason=excluded.reason,
                created_at=excluded.created_at
            """,
            (ip, banned_until, reason, created_at),
        )
        self.conn.commit()

    def get_blocklist(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM blocklist ORDER BY banned_until DESC"
        )
        return self._rows_to_dicts(rows)

    def is_blocked(self, ip: str, now: float) -> bool:
        row = self.conn.execute(
            "SELECT banned_until FROM blocklist WHERE ip=? AND banned_until>?",
            (ip, now),
        ).fetchone()
        return row is not None

    # -- kv ---------------------------------------------------------------

    def get_kv(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_kv(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    # -- retention --------------------------------------------------------

    def purge_retention(self, days: int) -> int:
        cur = self.conn.execute(
            "DELETE FROM events WHERE timestamp < datetime('now', ?)",
            (f"-{days} days",),
        )
        deleted = cur.rowcount
        self.conn.execute(
            "DELETE FROM alerts WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        deleted += cur.rowcount
        self.conn.commit()
        return deleted
