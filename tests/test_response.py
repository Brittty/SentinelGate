"""Tests for response: risk engine, actions, telegram."""

from __future__ import annotations

import sqlite3
import time

import pytest

from audit.hashchain import HashChain
from response.actions import escalate_action, permanent_block, temp_ban, throttle, unblock
from response.risk import calculate_risk, decay_since
from siem.storage import Store


@pytest.fixture
def store() -> Store:
    conn = sqlite3.connect(":memory:")
    return Store(conn)


@pytest.fixture
def chain() -> HashChain:
    conn = sqlite3.connect(":memory:")
    return HashChain(conn)


def test_calculate_risk_low():
    result = calculate_risk(ml_score=0.1, rule_severity="low", reputation=0.0, cvss_score=2.0)
    assert result["risk_score"] < 40.0
    assert result["action"] == "allow"
    assert result["threshold_met"] == "none"


def test_calculate_risk_medium():
    result = calculate_risk(ml_score=0.5, rule_severity="medium", reputation=0.3, cvss_score=5.0)
    assert 40.0 <= result["risk_score"] < 60.0
    assert result["action"] == "alert"
    assert result["threshold_met"] == "alert"


def test_calculate_risk_high():
    result = calculate_risk(ml_score=0.7, rule_severity="high", reputation=0.5, cvss_score=7.0)
    assert 60.0 <= result["risk_score"] < 80.0
    assert result["action"] == "throttle"
    assert result["threshold_met"] == "throttle"


def test_calculate_risk_critical():
    result = calculate_risk(ml_score=0.9, rule_severity="critical", reputation=0.8, cvss_score=9.8)
    assert result["risk_score"] >= 80.0
    assert result["action"] == "block"
    assert result["threshold_met"] == "block"


def test_decay_since():
    now = time.time()
    # No decay (same time)
    assert decay_since(now, now) == 1.0

    # Half-life decay
    past = now - 3600.0
    decay = decay_since(past, now, half_life=3600.0)
    assert 0.49 <= decay <= 0.51

    # Full decay (10 half-lives)
    very_past = now - 36000.0
    decay = decay_since(very_past, now, half_life=3600.0)
    assert decay < 0.01


def test_throttle_action(store: Store, chain: HashChain):
    result = throttle("192.0.2.1", "test", {}, store, chain)
    assert result["success"]
    assert "throttled" in result["message"]

    # Check blocklist
    blocklist = store.get_blocklist()
    assert len(blocklist) == 1
    assert blocklist[0]["ip"] == "192.0.2.1"

    # Check audit chain
    entries = chain.get_entries(limit=10)
    assert len(entries) == 1
    assert entries[0]["action"] == "throttle"


def test_temp_ban_action(store: Store, chain: HashChain):
    result = temp_ban("192.0.2.2", "brute_force", {}, store, chain)
    assert result["success"]
    assert "24 hours" in result["message"]

    entries = chain.get_entries(limit=10)
    assert len(entries) == 1
    assert entries[0]["action"] == "temp_ban"


def test_permanent_block_action(store: Store, chain: HashChain):
    result = permanent_block("192.0.2.3", "repeated_attacks", {}, store, chain)
    assert result["success"]
    assert "permanently blocked" in result["message"]

    entries = chain.get_entries(limit=10)
    assert len(entries) == 1
    assert entries[0]["action"] == "permanent_block"


def test_unblock_action(store: Store, chain: HashChain):
    # Block first
    throttle("192.0.2.1", "test", {}, store, chain)

    # Unblock
    result = unblock("192.0.2.1", "false_positive", store, chain, actor="admin")
    assert result["success"]
    assert "unblocked" in result["message"]

    entries = chain.get_entries(limit=10)
    assert len(entries) == 2
    assert entries[0]["action"] == "unblock"


def test_allowlist_protection(store: Store, chain: HashChain):
    result = throttle("127.0.0.1", "test", {}, store, chain)
    assert not result["success"]
    assert "allowlisted" in result["message"]

    # No entry in blocklist
    blocklist = store.get_blocklist()
    assert len(blocklist) == 0


def test_escalate_action(store: Store, chain: HashChain):
    # Start with throttle
    risk_breakdown = {"ml_score": 0.7, "rule_score": 0.8}
    result = escalate_action("192.0.2.1", "allow", 65.0, risk_breakdown, store, chain)
    assert result["success"]
    assert "throttled" in result["message"]

    # Escalate to temp_ban
    result = escalate_action("192.0.2.1", "throttle", 75.0, risk_breakdown, store, chain)
    assert result["success"]
    assert "24 hours" in result["message"]

    # Escalate to permanent
    result = escalate_action("192.0.2.1", "temp_ban", 90.0, risk_breakdown, store, chain)
    assert result["success"]
    assert "permanently" in result["message"]

    # Check audit chain
    entries = chain.get_entries(limit=10)
    assert len(entries) == 3


def test_telegram_unconfigured():
    # Without TELEGRAM_TOKEN set, should return False without error
    from response.telegram import send_alert

    result = send_alert("high", "Test", {"ip": "192.0.2.1"})
    assert result is False
