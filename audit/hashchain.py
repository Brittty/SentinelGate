"""Tamper-evident hash chain for audit log.

Each entry stores sha256(prev_hash + canonical_json(entry)).
Verification detects any tampering and returns the first tampered index.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any


class HashChain:
    """Append-only hash-chained audit log backed by SQLite."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_hash TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def append(self, entry: dict[str, Any]) -> str:
        """Append an entry to the chain and return its hash."""
        # Get the last hash
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else "0" * 64

        # Canonical JSON
        entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))

        # Compute hash
        entry_hash = hashlib.sha256(
            (prev_hash + entry_json).encode("utf-8")
        ).hexdigest()

        created_at = datetime.now(tz=UTC).isoformat()

        self.conn.execute(
            "INSERT INTO audit_chain"
            " (prev_hash, entry_json, entry_hash, created_at)"
            " VALUES (?, ?, ?, ?)",
            (prev_hash, entry_json, entry_hash, created_at),
        )
        self.conn.commit()

        return entry_hash

    def verify(self) -> tuple[bool, int | None]:
        """Verify the entire chain.

        Returns (ok, first_tampered_index). If ok is True, first_tampered_index is None.
        """
        rows = self.conn.execute(
            "SELECT id, prev_hash, entry_json, entry_hash FROM audit_chain ORDER BY id ASC"
        ).fetchall()

        if not rows:
            return True, None

        expected_prev = "0" * 64

        for row in rows:
            row_id, prev_hash, entry_json, entry_hash = row

            if prev_hash != expected_prev:
                return False, row_id

            computed = hashlib.sha256(
                (prev_hash + entry_json).encode("utf-8")
            ).hexdigest()

            if computed != entry_hash:
                return False, row_id

            expected_prev = entry_hash

        return True, None

    def get_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent entries as dicts."""
        rows = self.conn.execute(
            "SELECT id, entry_json, entry_hash, created_at FROM audit_chain"
            " ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            row_id, entry_json, entry_hash, created_at = row
            entry = json.loads(entry_json)
            entry["_id"] = row_id
            entry["_hash"] = entry_hash
            entry["_created_at"] = created_at
            result.append(entry)
        return result
