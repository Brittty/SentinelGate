"""Shared pytest fixtures for SentinelGate.

Provides a temporary SQLite database in WAL mode and a controllable fake
clock (float seconds since epoch) used by rate limiting, ML windows,
correlation windows, and bans.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest


@pytest.fixture
def tmp_db():
    """A temporary SQLite database in WAL mode, torn down after the test."""
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    yield conn
    conn.close()
    os.unlink(path)


@pytest.fixture
def fake_clock():
    """A controllable clock returning seconds (float) since epoch.

    ``clock.advance(seconds)`` moves time forward for deterministic tests.
    """
    state = {"now": 1704110400.0}  # 2024-01-01 12:00:00 UTC

    def clock() -> float:
        return state["now"]

    def advance(seconds: float) -> None:
        state["now"] += float(seconds)

    clock.advance = advance  # type: ignore[attr-defined]
    return clock
