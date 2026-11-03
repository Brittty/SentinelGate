"""Feature extraction for ML anomaly detection.

Computes per-IP features over a sliding 60-second window:
- requests/min, unique paths, unique-path ratio
- 4xx and 5xx ratio
- avg and max payload length
- Shannon entropy of query/body
- special-character count
- mean inter-request gap
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any


def extract_features(events: list[dict[str, Any]]) -> dict[str, float]:
    """Extract features from a list of events (one IP, 60s window).

    Returns a dict with 10 feature keys. Returns zeros if events is empty.
    """
    if not events:
        return {
            "requests_per_min": 0.0,
            "unique_paths": 0.0,
            "unique_path_ratio": 0.0,
            "error_4xx_ratio": 0.0,
            "error_5xx_ratio": 0.0,
            "avg_payload_length": 0.0,
            "max_payload_length": 0.0,
            "query_entropy": 0.0,
            "special_char_count": 0.0,
            "mean_inter_request_gap": 0.0,
        }

    n = len(events)
    paths = [ev.get("path", "") for ev in events]
    unique = len(set(paths))
    unique_ratio = unique / n if n > 0 else 0.0

    status_codes = [ev.get("status", 200) for ev in events]
    error_4xx = sum(1 for s in status_codes if 400 <= s < 500) / n
    error_5xx = sum(1 for s in status_codes if 500 <= s < 600) / n

    queries = [ev.get("query", "") for ev in events]
    lengths = [len(q) for q in queries]
    avg_len = sum(lengths) / n if n > 0 else 0.0
    max_len = max(lengths) if lengths else 0.0

    combined = "".join(queries)
    entropy = _shannon_entropy(combined) if combined else 0.0

    special_count = sum(
        1 for c in combined if not c.isalnum() and not c.isspace()
    ) / max(len(combined), 1)

    # Inter-request gap: compute from timestamps if present
    timestamps = []
    for ev in events:
        ts_str = ev.get("timestamp", "")
        if ts_str:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(ts_str)
                timestamps.append(dt.timestamp())
            except (ValueError, TypeError):
                pass

    mean_gap = 0.0
    if len(timestamps) > 1:
        timestamps.sort()
        gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        mean_gap = sum(gaps) / len(gaps) if gaps else 0.0

    return {
        "requests_per_min": n,  # Already a 60s window
        "unique_paths": float(unique),
        "unique_path_ratio": unique_ratio,
        "error_4xx_ratio": error_4xx,
        "error_5xx_ratio": error_5xx,
        "avg_payload_length": avg_len,
        "max_payload_length": max_len,
        "query_entropy": entropy,
        "special_char_count": special_count,
        "mean_inter_request_gap": mean_gap,
    }


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy
