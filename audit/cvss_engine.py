"""CVSS v3.1 scoring engine for SentinelGate.

Maps attack types and security findings to CVSS vectors, computes base scores.
"""

from __future__ import annotations

import yaml

try:
    from cvss import CVSS3

    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False

VECTORS_PATH = "audit/vectors.yaml"


def _load_vectors() -> dict:
    """Load CVSS vectors from vectors.yaml."""
    try:
        with open(VECTORS_PATH, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return {}


def score_attack(attack_type: str) -> tuple[float, str, str]:
    """Return (score, severity, vector) for an attack type.

    Returns (0.0, "none", "") if attack_type not found or cvss unavailable.
    """
    if not CVSS_AVAILABLE:
        return 0.0, "none", ""

    vectors = _load_vectors()
    attack_types = vectors.get("attack_types", {})
    entry = attack_types.get(attack_type)
    if not entry:
        return 0.0, "none", ""

    vector_str = entry.get("vector", "")
    if not vector_str:
        return 0.0, "none", ""

    try:
        c = CVSS3(vector_str)
        score = c.scores()[0]  # base_score
        severity = c.severities()[0]  # None, Low, Medium, High, Critical
        return score, severity.lower() if severity else "none", vector_str
    except Exception:
        return 0.0, "none", ""


def score_finding(finding_type: str) -> tuple[float, str, str]:
    """Return (score, severity, vector) for a security finding.

    Returns (0.0, "none", "") if finding_type not found or cvss unavailable.
    """
    if not CVSS_AVAILABLE:
        return 0.0, "none", ""

    vectors = _load_vectors()
    findings = vectors.get("findings", {})
    entry = findings.get(finding_type)
    if not entry:
        return 0.0, "none", ""

    vector_str = entry.get("vector", "")
    if not vector_str:
        return 0.0, "none", ""

    try:
        c = CVSS3(vector_str)
        score = c.scores()[0]
        severity = c.severities()[0]
        return score, severity.lower() if severity else "none", vector_str
    except Exception:
        return 0.0, "none", ""
