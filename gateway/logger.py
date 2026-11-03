"""Append one JSON line per request to logs/requests.jsonl.

Each line is an Event-shaped dict (see siem/schema.py). String fields are
sanitized (control characters and newlines removed, length capped) to prevent
log injection. The log is append-only; the collector (Phase 4) tails it.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from typing import Any

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NEWLINE_RE = re.compile(r"[\r\n]+")
MAX_FIELD = 2048


def _sanitize(value: str, max_len: int = MAX_FIELD) -> str:
    """Remove control characters/newlines and cap length."""
    value = _NEWLINE_RE.sub(" ", value)
    value = CONTROL_CHARS_RE.sub("", value)
    return value[:max_len]


def log_event(log_path: str, event: dict[str, Any]) -> None:
    """Append *event* as a single sanitized JSON line to *log_path*."""
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    cleaned: dict[str, Any] = {}
    for key, value in event.items():
        if isinstance(value, str):
            cleaned[key] = _sanitize(value)
        elif isinstance(value, datetime):
            cleaned[key] = value.astimezone(UTC).isoformat()
        else:
            cleaned[key] = value
    line = json.dumps(cleaned, separators=(",", ":"), default=str)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
