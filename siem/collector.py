"""SIEM collector — tails logs/requests.jsonl and inserts into SQLite.

CLI:  python -m siem.collector [--follow]

Tracks byte offset in kv store to resume after restart.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from argparse import ArgumentParser
from typing import Any

from siem.storage import Store

DEFAULT_LOG = "logs/requests.jsonl"
DEFAULT_DB = "logs/siem.db"
OFFSET_KEY = "collector_offset"


def collect(store: Store, log_path: str, follow: bool = False) -> int:
    """Tail *log_path* and insert events into *store*.

    Returns the number of events inserted.
    """
    if not os.path.isfile(log_path):
        return 0

    offset_str = store.get_kv(OFFSET_KEY)
    offset = int(offset_str) if offset_str else 0

    count = 0
    with open(log_path, "rb") as fh:
        fh.seek(offset)
        while True:
            line = fh.readline()
            if not line:
                if follow:
                    time.sleep(0.5)
                    continue
                break
            try:
                event = json.loads(line)
                store.insert_event(event)
                count += 1
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
            offset = fh.tell()
            store.set_kv(OFFSET_KEY, str(offset))
    return count


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="SentinelGate SIEM collector")
    parser.add_argument("--log", default=DEFAULT_LOG, help="Path to requests.jsonl")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to SQLite DB")
    parser.add_argument("--follow", action="store_true", help="Tail mode")
    args = parser.parse_args(argv)

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    conn = sqlite3.connect(args.db)
    store = Store(conn)

    try:
        count = collect(store, args.log, follow=args.follow)
        if not args.follow:
            print(f"Inserted {count} events.", file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
