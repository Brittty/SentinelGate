"""Evaluate ML model on a labeled sample and write report."""

from __future__ import annotations

import sys
from argparse import ArgumentParser

try:
    import numpy as np
    from sklearn.metrics import classification_report, precision_recall_fscore_support

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from ml.live_detector import LiveDetector


def evaluate(detector: LiveDetector, normal_events: list[list[dict]], attack_events: list[list[dict]]) -> dict:
    """Evaluate detector on labeled windows.

    normal_events: list of normal windows (each window is a list of events)
    attack_events: list of attack windows

    Returns a dict with precision, recall, f1.
    """
    if not ML_AVAILABLE:
        return {"error": "scikit-learn not available"}

    if not detector.model_available:
        return {"error": "Model not loaded"}

    y_true = []
    y_pred = []

    threshold = 0.5

    for window in normal_events:
        score, _ = detector.score(window)
        y_true.append(0)
        y_pred.append(1 if score >= threshold else 0)

    for window in attack_events:
        score, _ = detector.score(window)
        y_true.append(1)
        y_pred.append(1 if score >= threshold else 0)

    if not y_true:
        return {"error": "No samples"}

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "samples": len(y_true),
    }


def write_report(results: dict, output_path: str) -> None:
    """Write evaluation results to a markdown file."""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("# ML Model Evaluation\n\n")
        if "error" in results:
            fh.write(f"**Error:** {results['error']}\n")
            return
        fh.write(f"- **Precision:** {results['precision']:.3f}\n")
        fh.write(f"- **Recall:** {results['recall']:.3f}\n")
        fh.write(f"- **F1 Score:** {results['f1']:.3f}\n")
        fh.write(f"- **Samples:** {results['samples']}\n")
        fh.write("\n## Notes\n\n")
        fh.write("Evaluated on synthetic or hand-built windows. "
                 "For production use, validate on real attack traffic.\n")


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Evaluate ML model")
    parser.add_argument("--output", default="docs/ml-evaluation.md", help="Output markdown path")
    args = parser.parse_args(argv)

    if not ML_AVAILABLE:
        print("ERROR: scikit-learn not available.", file=sys.stderr)
        return 1

    detector = LiveDetector()
    if not detector.model_available:
        print("ERROR: Model not loaded. Train a model first with ml.train.", file=sys.stderr)
        return 1

    # Hand-built sample windows for smoke test
    normal_window = [
        {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.1", "path": "/", "query": "", "status": 200},
        {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.1", "path": "/about", "query": "", "status": 200},
    ]
    attack_window = [
        {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.2", "path": "/", "query": "id=1' OR '1'='1", "status": 200},
        {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.2", "path": "/admin", "query": "id=1 UNION SELECT", "status": 200},
        {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.2", "path": "/test", "query": "q=<script>", "status": 200},
        {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.2", "path": "/api", "query": "cmd=sleep(5)", "status": 200},
    ]

    results = evaluate(detector, [normal_window], [attack_window])

    import os
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    write_report(results, args.output)
    print(f"Evaluation report written to {args.output}", file=sys.stderr)
    print(f"Results: {results}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
