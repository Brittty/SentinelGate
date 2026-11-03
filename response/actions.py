"""Automated response actions for SentinelGate.

throttle, temp_ban, permanent_block, unblock. All actions are written
to the audit hash chain with actor, reason, and risk breakdown.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from audit.hashchain import HashChain
from siem.storage import Store

ALLOWLIST = os.getenv("ALLOWLIST", "").split(",")
ALLOWLIST = [ip.strip() for ip in ALLOWLIST if ip.strip()]

# Ban durations (seconds)
THROTTLE_BAN = 900  # 15 minutes
TEMP_BAN = 86400  # 24 hours
PERMANENT_BAN = 86400 * 365 * 10  # 10 years


def is_allowlisted(ip: str) -> bool:
    """Check if IP is in the allowlist."""
    return ip in ALLOWLIST or ip in ("127.0.0.1", "localhost", "::1")


def throttle(
    ip: str,
    reason: str,
    risk_breakdown: dict,
    store: Store,
    chain: HashChain,
    actor: str = "system",
) -> dict[str, Any]:
    """Throttle an IP for 15 minutes.

    Returns action dict with success and message.
    """
    if is_allowlisted(ip):
        return {"success": False, "message": f"IP {ip} is allowlisted"}

    now = datetime.now(tz=timezone.utc)
    banned_until = now.timestamp() + THROTTLE_BAN

    store.upsert_blocklist(ip, banned_until, f"throttle: {reason}", now.isoformat())

    # Audit
    chain.append(
        {
            "action": "throttle",
            "ip": ip,
            "reason": reason,
            "duration_seconds": THROTTLE_BAN,
            "actor": actor,
            "risk_breakdown": risk_breakdown,
            "timestamp": now.isoformat(),
        }
    )

    return {"success": True, "message": f"IP {ip} throttled for 15 minutes"}


def temp_ban(
    ip: str,
    reason: str,
    risk_breakdown: dict,
    store: Store,
    chain: HashChain,
    actor: str = "system",
) -> dict[str, Any]:
    """Ban an IP for 24 hours."""
    if is_allowlisted(ip):
        return {"success": False, "message": f"IP {ip} is allowlisted"}

    now = datetime.now(tz=timezone.utc)
    banned_until = now.timestamp() + TEMP_BAN

    store.upsert_blocklist(ip, banned_until, f"temp_ban: {reason}", now.isoformat())

    chain.append(
        {
            "action": "temp_ban",
            "ip": ip,
            "reason": reason,
            "duration_seconds": TEMP_BAN,
            "actor": actor,
            "risk_breakdown": risk_breakdown,
            "timestamp": now.isoformat(),
        }
    )

    return {"success": True, "message": f"IP {ip} banned for 24 hours"}


def permanent_block(
    ip: str,
    reason: str,
    risk_breakdown: dict,
    store: Store,
    chain: HashChain,
    actor: str = "system",
) -> dict[str, Any]:
    """Permanently block an IP."""
    if is_allowlisted(ip):
        return {"success": False, "message": f"IP {ip} is allowlisted"}

    now = datetime.now(tz=timezone.utc)
    banned_until = now.timestamp() + PERMANENT_BAN

    store.upsert_blocklist(ip, banned_until, f"permanent: {reason}", now.isoformat())

    chain.append(
        {
            "action": "permanent_block",
            "ip": ip,
            "reason": reason,
            "duration_seconds": PERMANENT_BAN,
            "actor": actor,
            "risk_breakdown": risk_breakdown,
            "timestamp": now.isoformat(),
        }
    )

    return {"success": True, "message": f"IP {ip} permanently blocked"}


def unblock(
    ip: str,
    reason: str,
    store: Store,
    chain: HashChain,
    actor: str = "admin",
) -> dict[str, Any]:
    """Unblock an IP by removing it from the blocklist."""
    now = datetime.now(tz=timezone.utc)

    # Set banned_until to now (expired)
    store.upsert_blocklist(ip, now.timestamp(), f"unblocked: {reason}", now.isoformat())

    chain.append(
        {
            "action": "unblock",
            "ip": ip,
            "reason": reason,
            "actor": actor,
            "timestamp": now.isoformat(),
        }
    )

    return {"success": True, "message": f"IP {ip} unblocked"}


def escalate_action(
    ip: str,
    current_action: str,
    risk_score: float,
    risk_breakdown: dict,
    store: Store,
    chain: HashChain,
) -> dict[str, Any]:
    """Escalate action based on repeated violations.

    Ladder: throttle -> temp_ban -> permanent_block
    """
    if current_action == "allow" and risk_score >= 60.0:
        return throttle(ip, f"risk {risk_score}", risk_breakdown, store, chain)
    elif current_action == "throttle" and risk_score >= 70.0:
        return temp_ban(ip, f"escalated from throttle, risk {risk_score}", risk_breakdown, store, chain)
    elif current_action == "temp_ban" and risk_score >= 85.0:
        return permanent_block(ip, f"escalated from temp_ban, risk {risk_score}", risk_breakdown, store, chain)
    else:
        return {"success": False, "message": "No escalation needed"}
