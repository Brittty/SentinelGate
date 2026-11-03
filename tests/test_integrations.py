"""Tests for Suricata and Wazuh integrations."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from siem import wazuh
from siem.storage import Store
from siem.suricata import parse_suricata_event, tail_suricata
from siem.wazuh import parse_wazuh_alert, poll_wazuh


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


# -- Wazuh polling -------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_wazuh_requires_credentials(store: Store):
    assert poll_wazuh("https://wazuh", "", "", store) == 0


def test_wazuh_auth_failure(store: Store, monkeypatch):
    monkeypatch.setattr(
        wazuh.requests, "post", lambda *a, **k: _FakeResponse({}, status_code=401)
    )
    assert poll_wazuh("https://wazuh", "user", "pass", store) == 0


def test_wazuh_poll_inserts_and_tracks_offset(store: Store, monkeypatch):
    alerts = {
        "data": {
            "affected_items": [
                {
                    "id": 7,
                    "timestamp": "2026-11-03T05:00:00+00:00",
                    "rule": {"description": "auth failed", "groups": ["auth"]},
                    "agent": {"name": "web"},
                    "data": {"srcip": "192.0.2.9"},
                }
            ]
        }
    }
    monkeypatch.setattr(
        wazuh.requests,
        "post",
        lambda *a, **k: _FakeResponse({"data": {"token": "jwt"}}),
    )
    monkeypatch.setattr(
        wazuh.requests, "get", lambda *a, **k: _FakeResponse(alerts)
    )

    assert poll_wazuh("https://wazuh", "user", "pass", store) == 1
    events = store.recent_events(limit=10)
    assert len(events) == 1
    assert events[0]["source"] == "wazuh"
    assert store.get_kv("wazuh_last_id") == "7"


def test_wazuh_poll_api_error(store: Store, monkeypatch):
    monkeypatch.setattr(
        wazuh.requests,
        "post",
        lambda *a, **k: _FakeResponse({"data": {"token": "jwt"}}),
    )
    monkeypatch.setattr(
        wazuh.requests, "get", lambda *a, **k: _FakeResponse({}, status_code=500)
    )
    assert poll_wazuh("https://wazuh", "user", "pass", store) == 0


def test_wazuh_poll_exception(store: Store, monkeypatch):
    def boom(*args, **kwargs):
        raise wazuh.requests.RequestException("offline")

    monkeypatch.setattr(wazuh.requests, "post", boom)
    assert poll_wazuh("https://wazuh", "user", "pass", store) == 0


# -- collector -----------------------------------------------------------


def test_collector_resumes_after_offset(tmp_path):
    from siem.collector import collect

    conn = sqlite3.connect(":memory:")
    store = Store(conn)
    log = tmp_path / "requests.jsonl"
    log.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-03T05:00:00Z",
                "source_ip": "192.0.2.1",
                "method": "GET",
                "path": "/",
                "query": "",
                "status": 200,
                "user_agent": "",
                "latency_ms": 1.0,
                "rule_hit": "",
                "attack_type": "",
                "ml_score": 0.0,
                "cvss_score": 0.0,
                "risk_score": 0.0,
                "action": "allow",
                "source": "gateway",
            }
        )
        + "\nnot json\n",
        encoding="utf-8",
    )

    assert collect(store, str(log)) == 1
    assert collect(store, str(log)) == 0
    assert collect(store, str(tmp_path / "missing.jsonl")) == 0

    with log.open("a", encoding="utf-8") as fh:
        fh.write(log.read_text(encoding="utf-8").splitlines()[0] + "\n")
    assert collect(store, str(log)) == 1
