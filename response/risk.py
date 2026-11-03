"""Risk scoring engine for SentinelGate.

Combines ML anomaly score, rule severity, IP reputation, and CVSS impact
into a 0-100 risk score with configurable thresholds.
"""

from __future__ import annotations

import time
from typing import Any

# Risk formula: risk = 100 * (0.3*ml_score + 0.3*rule_score + 0.2*reputation + 0.2*cvss/10)
ALERT_THRESHOLD = 40.0
THROTTLE_THRESHOLD = 60.0
BLOCK_THRESHOLD = 80.0


def calculate_risk(
    ml_score: float = 0.0,
    rule_severity: str = "",
    reputation: float = 0.0,
    cvss_score: float = 0.0,
    decay_factor: float = 1.0,
) -> dict[str, Any]:
    """Calculate risk score and return breakdown.

    Args:
        ml_score: ML anomaly score 0-1
        rule_severity: low/medium/high/critical or empty
        reputation: IP reputation 0-1 (0=good, 1=bad)
        cvss_score: CVSS base score 0-10
        decay_factor: Time-based decay 0-1 (1=no decay)

    Returns:
        {
            "risk_score": float 0-100,
            "action": "allow" | "alert" | "throttle" | "block",
            "breakdown": {...},
            "threshold_met": str,
        }
    """
    # Map rule severity to 0-1 score
    severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
    rule_score = severity_map.get(rule_severity.lower(), 0.0)

    # Apply decay to rule score (recent hits matter more)
    rule_score *= decay_factor

    # Calculate weighted risk
    risk = 100.0 * (
        0.3 * ml_score + 0.3 * rule_score + 0.2 * reputation + 0.2 * (cvss_score / 10.0)
    )
    risk = max(0.0, min(100.0, risk))

    # Determine action based on thresholds
    action = "allow"
    threshold_met = "none"
    if risk >= BLOCK_THRESHOLD:
        action = "block"
        threshold_met = "block"
    elif risk >= THROTTLE_THRESHOLD:
        action = "throttle"
        threshold_met = "throttle"
    elif risk >= ALERT_THRESHOLD:
        action = "alert"
        threshold_met = "alert"

    return {
        "risk_score": round(risk, 2),
        "action": action,
        "threshold_met": threshold_met,
        "breakdown": {
            "ml_score": ml_score,
            "rule_score": rule_score,
            "reputation": reputation,
            "cvss_score": cvss_score,
            "decay_factor": decay_factor,
        },
    }


def decay_since(timestamp: float, now: float | None = None, half_life: float = 3600.0) -> float:
    """Calculate decay factor based on time elapsed.

    Args:
        timestamp: Unix timestamp of the event
        now: Current time (defaults to time.time())
        half_life: Time in seconds for score to decay to 0.5

    Returns:
        Decay factor 0-1
    """
    if now is None:
        now = time.time()
    elapsed = now - timestamp
    if elapsed <= 0:
        return 1.0
    return 0.5 ** (elapsed / half_life)
