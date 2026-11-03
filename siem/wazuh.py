"""Wazuh integration for SentinelGate SIEM.

Polls Wazuh API or indexer for alerts and converts to Event schema.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from argparse import ArgumentParser
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import requests

from siem.storage import Store

WAZUH_URL = os.getenv("WAZUH_URL", "https://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
TIMEOUT = 10.0
# Wazuh commonly runs with a self-signed certificate in labs. Verification stays
# on unless the operator explicitly opts out.
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "true").lower() not in (
    "false",
    "0",
    "no",
)


def _authenticate(base_url: str, username: str, password: str) -> str | None:
    """Authenticate to Wazuh API and return JWT token."""
    try:
        resp = requests.post(
            f"{base_url}/security/user/authenticate",
            auth=(username, password),
            timeout=TIMEOUT,
            verify=WAZUH_VERIFY_TLS,
        )
        if resp.status_code == HTTPStatus.OK:
            data = resp.json()
            return data.get("data", {}).get("token")
    except (requests.RequestException, ValueError, KeyError):
        pass
    return None


def parse_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Parse a Wazuh alert into Event schema."""
    timestamp = alert.get("timestamp", datetime.now(tz=UTC).isoformat())
    src_ip = alert.get("data", {}).get("srcip", "unknown")
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    return {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "method": "UNKNOWN",
        "path": agent.get("name", ""),
        "query": "",
        "status": 0,
        "user_agent": "",
        "latency_ms": 0.0,
        "rule_hit": rule.get("description", ""),
        "attack_type": rule.get("groups", [""])[0] if rule.get("groups") else "",
        "ml_score": 0.0,
        "cvss_score": 0.0,
        "risk_score": 0.0,
        "action": "allow",
        "source": "wazuh",
    }


def poll_wazuh(
    base_url: str,
    username: str,
    password: str,
    store: Store,
    last_id_key: str = "wazuh_last_id",
) -> int:
    """Poll Wazuh API for new alerts and insert into store.

    Returns the number of events inserted.
    """
    if not username or not password:
        return 0

    # Authenticate
    token = _authenticate(base_url, username, password)
    if not token:
        return 0

    headers = {"Authorization": f"Bearer {token}"}

    # Get last processed alert ID
    last_id = store.get_kv(last_id_key)
    last_id = int(last_id) if last_id else 0

    # Fetch alerts
    params = {"offset": last_id, "limit": 500, "sort": "+id"}
    try:
        resp = requests.get(
            f"{base_url}/alerts",
            headers=headers,
            params=params,
            timeout=TIMEOUT,
            verify=WAZUH_VERIFY_TLS,
        )
        if resp.status_code != HTTPStatus.OK:
            return 0

        data = resp.json()
        alerts = data.get("data", {}).get("affected_items", [])

        count = 0
        max_id = last_id
        for alert in alerts:
            event = parse_wazuh_alert(alert)
            store.insert_event(event)
            count += 1
            alert_id = alert.get("id", 0)
            max_id = max(max_id, alert_id)

        if max_id > last_id:
            store.set_kv(last_id_key, str(max_id))

        return count

    except (requests.RequestException, ValueError, KeyError):
        return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for Wazuh collector."""
    parser = ArgumentParser(description="SentinelGate Wazuh collector")
    parser.add_argument("--url", default=WAZUH_URL, help="Wazuh API URL")
    parser.add_argument("--user", default=WAZUH_USER, help="Wazuh username")
    parser.add_argument("--password", default=WAZUH_PASSWORD, help="Wazuh password")
    parser.add_argument("--db", default="logs/siem.db", help="Path to SQLite DB")
    parser.add_argument("--interval", type=int, default=60, help="Poll interval (seconds)")
    parser.add_argument("--follow", action="store_true", help="Poll continuously")
    args = parser.parse_args(argv)

    if not args.user or not args.password:
        print("ERROR: Wazuh credentials required (--user and --password)", file=sys.stderr)
        return 1

    conn = sqlite3.connect(args.db)
    store = Store(conn)

    try:
        if args.follow:
            while True:
                count = poll_wazuh(args.url, args.user, args.password, store)
                if count > 0:
                    print(f"Inserted {count} Wazuh alerts.", file=sys.stderr)
                time.sleep(args.interval)
        else:
            count = poll_wazuh(args.url, args.user, args.password, store)
            print(f"Inserted {count} Wazuh alerts.", file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
