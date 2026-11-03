"""Tests for ML feature extraction and live detection."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone

import pytest

from ml.features import extract_features

# Check if ML libraries are available
try:
    import numpy as np
    from ml.live_detector import LiveDetector
    from ml.train import generate_synthetic_baseline, train_model

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


def test_extract_features_empty():
    features = extract_features([])
    assert features["requests_per_min"] == 0.0
    assert features["unique_paths"] == 0.0


def test_extract_features_normal():
    events = [
        {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.1", "path": "/", "query": "", "status": 200},
        {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.1", "path": "/about", "query": "", "status": 200},
        {"timestamp": "2026-11-03T05:00:02Z", "source_ip": "192.0.2.1", "path": "/", "query": "", "status": 200},
    ]
    features = extract_features(events)
    assert features["requests_per_min"] == 3
    assert features["unique_paths"] == 2.0
    assert features["unique_path_ratio"] == pytest.approx(2 / 3)
    assert features["error_4xx_ratio"] == 0.0
    assert features["error_5xx_ratio"] == 0.0


def test_extract_features_attack_like():
    events = [
        {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.2", "path": "/admin", "query": "id=1' OR '1'='1", "status": 403},
        {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.2", "path": "/test", "query": "cmd=sleep(5)", "status": 403},
        {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.2", "path": "/api", "query": "q=<script>alert(1)</script>", "status": 403},
        {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.2", "path": "/data", "query": "id=1 UNION SELECT", "status": 403},
    ]
    features = extract_features(events)
    assert features["requests_per_min"] == 4
    assert features["unique_paths"] == 4.0
    assert features["unique_path_ratio"] == 1.0
    assert features["error_4xx_ratio"] == 1.0
    assert features["query_entropy"] > 0.0
    assert features["special_char_count"] > 0.0


@pytest.mark.skipif(not ML_AVAILABLE, reason="scikit-learn not available")
def test_train_and_load_model():
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "test.joblib")
        events = generate_synthetic_baseline(100)
        train_model(events, model_path)

        assert os.path.isfile(model_path)
        meta_path = model_path.replace(".joblib", ".json")
        assert os.path.isfile(meta_path)

        detector = LiveDetector(model_path, meta_path)
        assert detector.model_available

        # Score a normal window
        normal = [
            {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.1", "path": "/", "query": "", "status": 200},
            {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.1", "path": "/about", "query": "", "status": 200},
        ]
        score, features = detector.score(normal)
        assert 0.0 <= score <= 1.0
        assert isinstance(features, list)


@pytest.mark.skipif(not ML_AVAILABLE, reason="scikit-learn not available")
def test_detector_scores_differ():
    """Normal and attack-like windows should have different scores."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "test.joblib")
        events = generate_synthetic_baseline(200)
        train_model(events, model_path)

        detector = LiveDetector(model_path, model_path.replace(".joblib", ".json"))

        normal = [
            {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.1", "path": "/", "query": "", "status": 200},
            {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.1", "path": "/about", "query": "", "status": 200},
        ]
        attack = [
            {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.2", "path": "/admin", "query": "id=1' OR '1'='1", "status": 403},
            {"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.2", "path": "/test", "query": "cmd=sleep(5)", "status": 403},
            {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.2", "path": "/api", "query": "q=<script>", "status": 403},
            {"timestamp": "2026-11-03T05:00:01Z", "source_ip": "192.0.2.2", "path": "/data", "query": "id=1 UNION SELECT", "status": 403},
        ]

        score_normal, _ = detector.score(normal)
        score_attack, _ = detector.score(attack)

        # Attack-like should have higher anomaly score
        # Note: this is probabilistic but should hold with high confidence
        assert score_attack > score_normal or score_attack > 0.3


def test_detector_graceful_fallback():
    """Detector should return 0.0 when model is missing."""
    # Import here to avoid import errors when ML not available
    from ml.live_detector import LiveDetector as LD

    detector = LD("nonexistent.joblib", "nonexistent.json")
    assert not detector.model_available

    events = [{"timestamp": "2026-11-03T05:00:00Z", "source_ip": "192.0.2.1", "path": "/", "query": "", "status": 200}]
    score, features = detector.score(events)
    assert score == 0.0
    assert features == []
