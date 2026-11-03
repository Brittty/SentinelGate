"""NVD API 2.0 client with SQLite cache and offline fallback.

Looks up CVE details from the National Vulnerability Database.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 10.0
CACHE_TTL = 86400 * 7  # 7 days


class NVDClient:
    """NVD API 2.0 client with local SQLite cache."""

    def __init__(self, conn: sqlite3.Connection, api_key: str | None = None):
        self.conn = conn
        self.api_key = api_key
        self._init_cache()

    def _init_cache(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nvd_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                cached_at REAL NOT NULL
            )
            """
        )
        self.conn.commit()

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        """Lookup CVE by ID. Returns dict or None if not found.

        Checks cache first; falls back to API with exponential backoff.
        """
        # Check cache
        now = time.time()
        row = self.conn.execute(
            "SELECT data, cached_at FROM nvd_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row:
            data, cached_at = row
            if now - cached_at < CACHE_TTL:
                import json

                return json.loads(data)

        # Fetch from API
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {"cveId": cve_id}

        for attempt in range(3):
            try:
                resp = requests.get(
                    NVD_API_URL, params=params, headers=headers, timeout=TIMEOUT
                )
                if resp.status_code == 200:
                    result = resp.json()
                    vulnerabilities = result.get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_data = vulnerabilities[0]
                        # Cache it
                        import json

                        self.conn.execute(
                            "INSERT OR REPLACE INTO nvd_cache (cve_id, data, cached_at) VALUES (?, ?, ?)",
                            (cve_id, json.dumps(cve_data), now),
                        )
                        self.conn.commit()
                        return cve_data
                    return None
                elif resp.status_code == 404:
                    return None
                else:
                    # Rate limit or server error; retry with backoff
                    time.sleep(2**attempt)
            except (requests.RequestException, ValueError):
                time.sleep(2**attempt)

        # Offline fallback
        return None
