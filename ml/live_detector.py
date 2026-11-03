"""Live ML anomaly detector for SentinelGate.

Loads a trained IsolationForest model and scores per-IP windows.
Returns ml_score 0-1 and top contributing features.
Gracefully degrades if model is missing or scikit-learn unavailable.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

try:
    import joblib
    import numpy as np

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from ml.features import extract_features

DEFAULT_MODEL = "models/iforest.joblib"
DEFAULT_META = "models/iforest.json"


class LiveDetector:
    """Anomaly detector that loads a model and scores windows."""

    def __init__(self, model_path: str = DEFAULT_MODEL, meta_path: str = DEFAULT_META):
        self.model = None
        self.feature_names = []
        self.model_available = False

        if not ML_AVAILABLE:
            return

        if not os.path.isfile(model_path) or not os.path.isfile(meta_path):
            return

        # Verify hash
        try:
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
            expected_hash = meta.get("sha256", "")
            with open(model_path, "rb") as fh:
                actual_hash = hashlib.sha256(fh.read()).hexdigest()
            if expected_hash and actual_hash != expected_hash:
                return

            self.feature_names = meta.get("feature_names", [])
            self.model = joblib.load(model_path)
            self.model_available = True
        except (OSError, json.JSONDecodeError, ValueError, KeyError):
            pass

    def score(self, events: list[dict[str, Any]]) -> tuple[float, list[str]]:
        """Score a per-IP window and return (ml_score, top_features).

        ml_score is 0-1, where 1 is most anomalous.
        top_features is a list of feature names contributing most to the score.
        Returns (0.0, []) if model unavailable.
        """
        if not self.model_available or not events:
            return 0.0, []

        features = extract_features(events)
        row = np.array([[features[k] for k in self.feature_names]])

        # IsolationForest score_samples returns negative values; more negative = more anomalous
        score = self.model.score_samples(row)[0]
        # Normalize to 0-1: typical range is [-0.5, 0.5], cap and scale
        normalized = max(0.0, min(1.0, 0.5 - score))

        # Top features: return names of highest-value features as a heuristic
        top = sorted(
            self.feature_names,
            key=lambda k: features[k],
            reverse=True,
        )[:3]

        return normalized, top


# Singleton
_detector: LiveDetector | None = None


def get_detector() -> LiveDetector:
    """Return the singleton detector instance."""
    global _detector  # noqa: PLW0603
    if _detector is None:
        _detector = LiveDetector()
    return _detector
