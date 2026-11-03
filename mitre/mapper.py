"""MITRE ATT&CK mapping helper for SentinelGate.

Tags detections with MITRE tactics and techniques.
"""

from __future__ import annotations

import yaml
from typing import Any

MAPPING_PATH = "mitre/mapping.yaml"


def _load_mappings() -> dict:
    """Load MITRE mappings from YAML."""
    try:
        with open(MAPPING_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data.get("mappings", {})
    except (OSError, yaml.YAMLError):
        return {}


def get_mitre_info(technique_id: str) -> dict[str, Any]:
    """Get MITRE ATT&CK info for a technique ID.

    Returns dict with name, tactic, description, severity.
    Returns empty dict if not found.
    """
    mappings = _load_mappings()
    return mappings.get(technique_id, {})


def tag_rule(rule_name: str) -> str:
    """Find MITRE technique ID for a rule name.

    Returns technique ID (e.g., "T1110") or empty string if not found.
    """
    mappings = _load_mappings()
    for technique_id, info in mappings.items():
        detection_rules = info.get("detection_rules", [])
        if rule_name in detection_rules:
            return technique_id
    return ""


def get_all_techniques() -> list[dict]:
    """Get all MITRE techniques as a list of dicts."""
    mappings = _load_mappings()
    result = []
    for technique_id, info in mappings.items():
        result.append(
            {
                "id": technique_id,
                "name": info.get("name", ""),
                "tactic": info.get("tactic", ""),
                "description": info.get("description", ""),
                "severity": info.get("severity", "medium"),
                "detection_rules": info.get("detection_rules", []),
            }
        )
    return result
