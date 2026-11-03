"""Tests for SIEM: storage, parsers, correlation, collector."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

import pytest

from siem.collector import collect
from siem.correlation import correlate
from siem.parsers import parse_auth_log, parse_nginx_combined
from siem.storage import Store


# --- Storage ---


@pytest.fixture
def store() -> Store:
    conn = sqlite3.connect(":memory:")
    return Store(conn)


def test_insert_event(store: Store):
    event = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "source_ip": "192.0.2.1",
        "method": "GET",
        "path": "/test",
        "query": "",
        "status": 200,
        "user_agent": "test",
        "latency_ms": 10.5,
        "rule_hit": "",
        "attack_type": "",
        "ml_score": 0.0,
        "cvss_score": 0.0,
        "risk_score": 0.0,
        "action": "allow",
        "source": "gateway",
    }
    row_id = store.insert_event(event)
    assert row_id > 0
    events = store.recent_events()
    assert len(events) == 1
    assert events[0]["source_ip"] == "192.0.2.1"


def test_insert_alert(store: Store):
    alert = {
        "alert_id": "test-123",
        "ip": "192.0.2.1",
        "rule": "brute_force",
        "severity": "high",
        "status": "new",
        "mitre_id": "T1110",
        "evidence": "{}",
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    store.insert_alert(alert)
    alerts = store.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "brute_force"


def test_blocklist(store: Store):
    now = datetime.now(tz=timezone.utc).timestamp()
    future = now + 3600
    store.upsert_blocklist("192.0.2.1", future, "test", datetime.now(tz=timezone.utc).isoformat())
    assert store.is_blocked("192.0.2.1", now)
    assert not store.is_blocked("192.0.2.1", future + 10)


def test_kv(store: Store):
    assert store.get_kv("missing") is None
    store.set_kv("key", "value")
    assert store.get_kv("key") == "value"
    store.set_kv("key", "updated")
    assert store.get_kv("key") == "updated"


# --- Parsers ---


def test_parse_auth_log():
    text = """
Oct 15 10:22:33 host sshd[1234]: Failed password for admin from 203.0.113.5 port 22
Oct 15 10:22:35 host sshd[1235]: Invalid user test from 203.0.113.6 port 22
"""
    events = parse_auth_log(text, year=2026)
    assert len(events) == 2
    assert events[0]["source_ip"] == "203.0.113.5"
    assert events[0]["attack_type"] == "brute_force"
    assert events[1]["source_ip"] == "203.0.113.6"


def test_parse_nginx_combined():
    text = """
192.0.2.1 - - [10/Oct/2000:13:55:36 -0700] "GET /test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.0.2.2 - - [10/Oct/2000:13:55:40 -0700] "POST /login HTTP/1.1" 401 0 "-" "curl/7.68.0"
"""
    events = parse_nginx_combined(text)
    assert len(events) == 2
    assert events[0]["source_ip"] == "192.0.2.1"
    assert events[0]["status"] == 200
    assert events[1]["status"] == 401


# --- Correlation ---


def test_brute_force_correlation(store: Store):
    now = datetime.now(tz=timezone.utc).timestamp()
    now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    events = [
        {
            "timestamp": now_iso,
            "source_ip": "192.0.2.1",
            "path": "/login",
            "status": 401,
        }
        for _ in range(6)
    ]
    alerts = correlate(events, store, now)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Brute force login attempts"
    assert alerts[0]["severity"] == "high"


def test_scan_correlation(store: Store):
    now = datetime.now(tz=timezone.utc).timestamp()
    now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    events = [
        {
            "timestamp": now_iso,
            "source_ip": "192.0.2.1",
            "path": f"/path{i}",
            "status": 404,
        }
        for i in range(12)
    ]
    alerts = correlate(events, store, now)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Active scanning / 404 burst"


def test_injection_burst_correlation(store: Store):
    now = datetime.now(tz=timezone.utc).timestamp()
    now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    events = [
        {
            "timestamp": now_iso,
            "source_ip": "192.0.2.1",
            "path": "/test",
            "attack_type": "sqli",
        }
        for _ in range(6)
    ]
    alerts = correlate(events, store, now)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Injection burst"


def test_multi_stage_correlation(store: Store):
    now = datetime.now(tz=timezone.utc).timestamp()
    now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    events = [
        {
            "timestamp": now_iso,
            "source_ip": "192.0.2.1",
            "path": "/scan",
            "status": 404,
        },
        {
            "timestamp": now_iso,
            "source_ip": "192.0.2.1",
            "path": "/test",
            "attack_type": "sqli",
        },
    ]
    alerts = correlate(events, store, now)
    # Should trigger multi_stage
    multi = [a for a in alerts if a["rule"] == "Multi-stage attack (scan then injection)"]
    assert len(multi) == 1
    assert multi[0]["severity"] == "critical"


def test_deduplication(store: Store):
    now = datetime.now(tz=timezone.utc).timestamp()
    now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    events = [
        {
            "timestamp": now_iso,
            "source_ip": "192.0.2.1",
            "path": "/login",
            "status": 401,
        }
        for _ in range(6)
    ]
    alerts1 = correlate(events, store, now)
    assert len(alerts1) == 1
    # Insert the alert
    store.insert_alert(alerts1[0])
    # Run correlation again — should deduplicate
    alerts2 = correlate(events, store, now)
    assert len(alerts2) == 0


# --- Collector ---


def test_collector():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "test.jsonl")
        db_path = os.path.join(tmpdir, "test.db")

        # Write sample events
        with open(log_path, "w", encoding="utf-8") as fh:
            for i in range(3):
                event = {
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "source_ip": f"192.0.2.{i}",
                    "method": "GET",
                    "path": "/test",
                    "query": "",
                    "status": 200,
                    "user_agent": "",
                    "latency_ms": 0.0,
                    "rule_hit": "",
                    "attack_type": "",
                    "ml_score": 0.0,
                    "cvss_score": 0.0,
                    "risk_score": 0.0,
                    "action": "allow",
                    "source": "gateway",
                }
                fh.write(json.dumps(event) + "\n")

        conn = sqlite3.connect(db_path)
        store = Store(conn)
        count = collect(store, log_path, follow=False)
        assert count == 3

        events = store.recent_events()
        assert len(events) == 3

        # Resume: append one more line
        with open(log_path, "a", encoding="utf-8") as fh:
            event = {
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "source_ip": "192.0.2.100",
                "method": "POST",
                "path": "/new",
                "query": "",
                "status": 201,
                "user_agent": "",
                "latency_ms": 0.0,
                "rule_hit": "",
                "attack_type": "",
                "ml_score": 0.0,
                "cvss_score": 0.0,
                "risk_score": 0.0,
                "action": "allow",
                "source": "gateway",
            }
            fh.write(json.dumps(event) + "\n")

        count2 = collect(store, log_path, follow=False)
        assert count2 == 1

        events = store.recent_events()
        assert len(events) == 4

        conn.close()
