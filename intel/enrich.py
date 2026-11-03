"""IP reputation enrichment via AbuseIPDB.

Queries AbuseIPDB API for IP reputation scores and caches results.
"""

from __future__ import annotations

import os
import sqlite3
import time
from http import HTTPStatus

import requests

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL = 86400  # 24 hours
TIMEOUT = 5.0


class ReputationClient:
    """AbuseIPDB client with SQLite cache."""

    def __init__(self, conn: sqlite3.Connection, api_key: str | None = None):
        self.conn = conn
        self.api_key = api_key or ABUSEIPDB_KEY
        self._init_cache()

    def _init_cache(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                reputation REAL NOT NULL,
                abuse_score INTEGER DEFAULT 0,
                is_public INTEGER DEFAULT 1,
                cached_at REAL NOT NULL
            )
            """
        )
        self.conn.commit()

    def lookup(self, ip: str) -> float:
        """Look up IP reputation (0.0=good, 1.0=bad).

        Returns reputation score 0-1. Returns 0.0 if unconfigured or error.
        """
        # Check cache
        now = time.time()
        row = self.conn.execute(
            "SELECT reputation, cached_at FROM ip_reputation WHERE ip = ?", (ip,)
        ).fetchone()
        if row:
            reputation, cached_at = row
            if now - cached_at < CACHE_TTL:
                return reputation

        # Check if API key is configured
        if not self.api_key:
            return 0.0

        # Query AbuseIPDB
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            resp = requests.get(
                ABUSEIPDB_URL, headers=headers, params=params, timeout=TIMEOUT
            )
            if resp.status_code == HTTPStatus.OK:
                data = resp.json()
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                is_public = data.get("data", {}).get("isPublic", True)

                # Normalize abuse_score (0-100) to reputation (0-1)
                reputation = abuse_score / 100.0

                # Cache it
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO ip_reputation
                    (ip, reputation, abuse_score, is_public, cached_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (ip, reputation, abuse_score, 1 if is_public else 0, now),
                )
                self.conn.commit()

                return reputation
        except (requests.RequestException, ValueError, KeyError):
            pass

        # Offline fallback: assume neutral
        return 0.0

    def bulk_lookup(self, ips: list[str]) -> dict[str, float]:
        """Look up multiple IPs and return {ip: reputation} dict."""
        results = {}
        for ip in ips:
            results[ip] = self.lookup(ip)
        return results
