"""Train ML anomaly detection model.

Usage:
    python -m ml.train [--input logs/requests.jsonl] [--output models/iforest.joblib]

Trains an IsolationForest on normal traffic from the input log, or generates
a synthetic baseline if the log is small. Saves the model plus metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from argparse import ArgumentParser
from datetime import datetime, timezone

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


from ml.features import extract_features


def load_events(log_path: str, limit: int = 10000) -> list[dict]:
    """Load events from JSONL log."""
    if not os.path.isfile(log_path):
        return []
    events = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            if len(events) >= limit:
                break
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def generate_synthetic_baseline(n: int = 500) -> list[dict]:
    """Generate synthetic normal traffic events."""
    import random
    from datetime import timedelta

    base = datetime.now(tz=timezone.utc)
    events = []
    for i in range(n):
        dt = base + timedelta(seconds=i * 0.1)
        events.append({
            "timestamp": dt.isoformat(),
            "source_ip": f"192.0.2.{random.randint(1, 10)}",
            "path": random.choice(["/", "/about", "/contact", "/api/status"]),
            "query": "",
            "status": 200,
        })
    return events


def train_model(events: list[dict], output_path: str) -> None:
    """Train IsolationForest and save to output_path."""
    if not ML_AVAILABLE:
        print("ERROR: scikit-learn not available. Cannot train model.", file=sys.stderr)
        return

    # Group by IP and extract features
    by_ip: dict[str, list[dict]] = {}
    for ev in events:
        by_ip.setdefault(ev.get("source_ip", "unknown"), []).append(ev)

    feature_rows = []
    feature_names = [
        "requests_per_min",
        "unique_paths",
        "unique_path_ratio",
        "error_4xx_ratio",
        "error_5xx_ratio",
        "avg_payload_length",
        "max_payload_length",
        "query_entropy",
        "special_char_count",
        "mean_inter_request_gap",
    ]

    for ip_events in by_ip.values():
        features = extract_features(ip_events)
        row = [features[k] for k in feature_names]
        feature_rows.append(row)

    if not feature_rows:
        print("ERROR: No features extracted from events.", file=sys.stderr)
        return

    X = np.array(feature_rows)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    # Save model
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(model, output_path)

    # Compute SHA-256
    with open(output_path, "rb") as fh:
        model_hash = hashlib.sha256(fh.read()).hexdigest()

    # Save metadata
    meta_path = output_path.replace(".joblib", ".json")
    metadata = {
        "version": "1.0",
        "model_type": "IsolationForest",
        "feature_names": feature_names,
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "training_samples": len(feature_rows),
        "sha256": model_hash,
    }
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"Model trained and saved to {output_path}", file=sys.stderr)
    print(f"Metadata: {meta_path}", file=sys.stderr)
    print(f"SHA-256: {model_hash}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Train ML anomaly detection model")
    parser.add_argument("--input", default="logs/requests.jsonl", help="Input JSONL log")
    parser.add_argument("--output", default="models/iforest.joblib", help="Output model path")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic baseline")
    args = parser.parse_args(argv)

    if not ML_AVAILABLE:
        print("ERROR: scikit-learn is not installed. Cannot train model.", file=sys.stderr)
        return 1

    if args.synthetic:
        events = generate_synthetic_baseline(500)
    else:
        events = load_events(args.input, limit=10000)
        if len(events) < 50:
            print(f"WARNING: Only {len(events)} events in log. Using synthetic baseline.", file=sys.stderr)
            events = generate_synthetic_baseline(500)

    train_model(events, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
