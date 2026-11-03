"""Suricata eve.json parser for SentinelGate SIEM.

Tails Suricata's eve.json file and converts alerts to Event schema.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from argparse import ArgumentParser
from datetime import UTC, datetime
from typing import Any

from siem.storage import Store

DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"


def parse_suricata_event(line: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a Suricata eve.json line into Event schema.

    Returns Event dict or None if not an alert.
    """
    event_type = line.get("event_type")
    if event_type != "alert":
        return None

    alert = line.get("alert", {})
    src_ip = line.get("src_ip", "unknown")
    dest_ip = line.get("dest_ip", "")
    timestamp = line.get("timestamp", datetime.now(tz=UTC).isoformat())

    # Map Suricata alert to our Event schema
    return {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "method": "UNKNOWN",  # Suricata doesn't track HTTP method in alerts
        "path": dest_ip,  # Use dest_ip as path
        "query": "",
        "status": 0,
        "user_agent": "",
        "latency_ms": 0.0,
        "rule_hit": alert.get("signature", ""),
        "attack_type": alert.get("category", ""),
        "ml_score": 0.0,
        "cvss_score": 0.0,
        "risk_score": 0.0,
        "action": "block" if alert.get("action") == "blocked" else "allow",
        "source": "suricata",
    }


def tail_suricata(
    eve_path: str,
    store: Store,
    offset_key: str = "suricata_offset",
    follow: bool = False,
) -> int:
    """Tail Suricata eve.json and insert alerts into store.

    Returns the number of events inserted.
    """
    if not os.path.isfile(eve_path):
        return 0

    # Resume from stored offset
    offset_str = store.get_kv(offset_key)
    offset = int(offset_str) if offset_str else 0

    count = 0
    with open(eve_path, "rb") as fh:
        fh.seek(offset)
        while True:
            line = fh.readline()
            if not line:
                if follow:
                    time.sleep(0.5)
                    continue
                break

            try:
                data = json.loads(line)
                event = parse_suricata_event(data)
                if event:
                    store.insert_event(event)
                    count += 1
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

            offset = fh.tell()
            store.set_kv(offset_key, str(offset))

    return count


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for Suricata collector."""
    parser = ArgumentParser(description="SentinelGate Suricata collector")
    parser.add_argument("--eve", default=DEFAULT_EVE_PATH, help="Path to eve.json")
    parser.add_argument("--db", default="logs/siem.db", help="Path to SQLite DB")
    parser.add_argument("--follow", action="store_true", help="Tail mode")
    args = parser.parse_args(argv)

    conn = sqlite3.connect(args.db)
    store = Store(conn)

    try:
        count = tail_suricata(args.eve, store, follow=args.follow)
        if not args.follow:
            print(f"Inserted {count} Suricata alerts.", file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
