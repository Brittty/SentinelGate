"""Case management for SentinelGate SOC workflow.

Creates cases from alerts, tracks status, assignees, notes, and timeline.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any


class CaseManager:
    """SOC case management backed by SQLite."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                assignee TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);

            CREATE TABLE IF NOT EXISTS case_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                entry TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_case ON case_timeline(case_id);
            """
        )
        self.conn.commit()

    def create_case(
        self,
        title: str,
        severity: str,
        alert_id: str | None = None,
        assignee: str = "",
    ) -> str:
        """Create a new case and return its ID."""
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(tz=timezone.utc).isoformat()

        self.conn.execute(
            """
            INSERT INTO cases (id, title, severity, status, assignee, created_at, updated_at)
            VALUES (?, ?, ?, 'open', ?, ?, ?)
            """,
            (case_id, title, severity, assignee, now, now),
        )
        self.conn.commit()

        # Add creation to timeline
        entry = f"Case created"
        if alert_id:
            entry += f" from alert {alert_id}"
        self.add_timeline_entry(case_id, entry, "system")

        return case_id

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """Get case by ID."""
        row = self.conn.execute(
            "SELECT * FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if not row:
            return None
        columns = ["id", "title", "severity", "status", "assignee", "notes", "created_at", "updated_at"]
        return dict(zip(columns, row))

    def list_cases(self, status: str | None = None, limit: int = 100) -> list[dict]:
        """List cases, optionally filtered by status."""
        if status:
            rows = self.conn.execute(
                "SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self.conn.execute(
                "SELECT * FROM cases ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        columns = ["id", "title", "severity", "status", "assignee", "notes", "created_at", "updated_at"]
        return [dict(zip(columns, row)) for row in rows.fetchall()]

    def update_case(
        self,
        case_id: str,
        status: str | None = None,
        assignee: str | None = None,
        notes: str | None = None,
        actor: str = "system",
    ) -> bool:
        """Update case fields and add timeline entry."""
        case = self.get_case(case_id)
        if not case:
            return False

        now = datetime.now(tz=timezone.utc).isoformat()
        updates = []
        values = []
        timeline_entries = []

        if status is not None and status != case["status"]:
            updates.append("status = ?")
            values.append(status)
            timeline_entries.append(f"Status changed to {status}")

        if assignee is not None and assignee != case["assignee"]:
            updates.append("assignee = ?")
            values.append(assignee)
            timeline_entries.append(f"Assigned to {assignee}" if assignee else "Unassigned")

        if notes is not None:
            updates.append("notes = ?")
            values.append(notes)
            timeline_entries.append("Notes updated")

        if not updates:
            return True

        updates.append("updated_at = ?")
        values.append(now)
        values.append(case_id)

        self.conn.execute(
            f"UPDATE cases SET {', '.join(updates)} WHERE id = ?",
            values,
        )
        self.conn.commit()

        for entry in timeline_entries:
            self.add_timeline_entry(case_id, entry, actor)

        return True

    def add_timeline_entry(self, case_id: str, entry: str, actor: str) -> None:
        """Add an entry to the case timeline."""
        now = datetime.now(tz=timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO case_timeline (case_id, entry, actor, created_at) VALUES (?, ?, ?, ?)",
            (case_id, entry, actor, now),
        )
        self.conn.commit()

    def get_timeline(self, case_id: str) -> list[dict]:
        """Get timeline for a case."""
        rows = self.conn.execute(
            """
            SELECT entry, actor, created_at
            FROM case_timeline
            WHERE case_id = ?
            ORDER BY created_at ASC
            """,
            (case_id,),
        )
        columns = ["entry", "actor", "created_at"]
        return [dict(zip(columns, row)) for row in rows.fetchall()]
