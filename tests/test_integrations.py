"""Tests for Suricata and Wazuh integrations."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from siem.storage import Store
from siem.suricata import parse_suricata_event, tail_suricata
from siem.wazuh import parse_wazuh_alert


@pytest.fixture
def store() -> Store:
    conn = sqlite3.connect(":memory:")
    return Store(conn)


def test_parse_suricata_alert():
    line = {
        "timestamp": "2026-11-03T05:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.0.2.1",
        "dest_ip": "10.0.0.1",
        "alert": {
            "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
            "category": "Attempted Information Leak",
            "action": "allowed",
        },
    }
    event = parse_suricata_event(line)
    assert event is not None
    assert event["source_ip"] == "192.0.2.1"
    assert event["source"] == "suricata"
    assert "Nmap" in event["rule_hit"]
    assert event["action"] == "allow"


def test_parse_suricata_blocked():
    line = {
        "timestamp": "2026-11-03T05:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.0.2.2",
        "dest_ip": "10.0.0.1",
        "alert": {
            "signature": "SQL Injection Attempt",
            "category": "Web Application Attack",
            "action": "blocked",
        },
    }
    event = parse_suricata_event(line)
    assert event is not None
    assert event["action"] == "block"


def test_parse_suricata_non_alert():
    line = {
        "timestamp": "2026-11-03T05:00:00.000000+0000",
        "event_type": "stats",
        "stats": {},
    }
    event = parse_suricata_event(line)
    assert event is None


def test_tail_suricata(store: Store):
    # Create temp eve.json
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        eve_path = f.name
        for i in range(3):
            line = {
                "timestamp": f"2026-11-03T05:00:{i:02d}.000000+0000",
                "event_type": "alert",
                "src_ip": f"192.0.2.{i}",
                "dest_ip": "10.0.0.1",
                "alert": {
                    "signature": f"Test Alert {i}",
                    "category": "Test",
                    "action": "allowed",
                },
            }
            f.write(json.dumps(line) + "\n")

    try:
        count = tail_suricata(eve_path, store, offset_key="test_offset", follow=False)
        assert count == 3

        events = store.recent_events(limit=10)
        assert len(events) == 3
        assert all(e["source"] == "suricata" for e in events)

        # Test resume
        with open(eve_path, "a") as f:
            line = {
                "timestamp": "2026-11-03T05:00:03.000000+0000",
                "event_type": "alert",
                "src_ip": "192.0.2.3",
                "dest_ip": "10.0.0.1",
                "alert": {
                    "signature": "Test Alert 3",
                    "category": "Test",
                    "action": "allowed",
                },
            }
            f.write(json.dumps(line) + "\n")

        count2 = tail_suricata(eve_path, store, offset_key="test_offset", follow=False)
        assert count2 == 1

        events = store.recent_events(limit=10)
        assert len(events) == 4
    finally:
        Path(eve_path).unlink()


def test_parse_wazuh_alert():
    alert = {
        "timestamp": "2026-11-03T05:00:00+00:00",
        "rule": {
            "level": 5,
            "description": "sshd: authentication failed",
            "id": "5710",
            "groups": ["authentication_failed", "syslog", "sshd"],
        },
        "agent": {"id": "001", "name": "web-server"},
        "data": {"srcip": "192.0.2.1", "srcport": "12345"},
    }
    event = parse_wazuh_alert(alert)
    assert event["source_ip"] == "192.0.2.1"
    assert event["source"] == "wazuh"
    assert "authentication failed" in event["rule_hit"]
    assert event["attack_type"] == "authentication_failed"


def test_suricata_missing_file(store: Store):
    count = tail_suricata("/nonexistent/eve.json", store, follow=False)
    assert count == 0
