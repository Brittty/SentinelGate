"""Telegram alert integration for SentinelGate.

Sends high/critical alerts to a configured Telegram bot. Rate-limited
and no-op when TELEGRAM_TOKEN is unset.
"""

from __future__ import annotations

import os
import time
from http import HTTPStatus
from typing import Any

import requests

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Rate limiting: max 1 alert per 60 seconds
_last_alert_time = 0.0
RATE_LIMIT = 60.0


def send_alert(severity: str, title: str, details: dict[str, Any]) -> bool:
    """Send an alert to Telegram if configured and rate limit permits.

    Args:
        severity: low/medium/high/critical
        title: Short alert title
        details: Dict with ip, risk_score, attack_type, etc.

    Returns:
        True if sent, False if skipped (unconfigured, rate-limited, or error)
    """
    global _last_alert_time  # noqa: PLW0603

    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    # Only send high and critical alerts
    if severity.lower() not in ("high", "critical"):
        return False

    # Rate limit
    now = time.time()
    if now - _last_alert_time < RATE_LIMIT:
        return False

    # Format message
    message = f"🚨 **{severity.upper()}**: {title}\n\n"
    for key, value in details.items():
        message += f"• {key}: {value}\n"

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=5.0)
        if resp.status_code == HTTPStatus.OK:
            _last_alert_time = now
            return True
    except requests.RequestException:
        pass

    return False
