"""Tests for the Telegram alert integration."""

from __future__ import annotations

import time

import pytest

from response import telegram


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    """Start each test with a configured, un-rate-limited client."""
    monkeypatch.setattr(telegram, "TELEGRAM_TOKEN", "token")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "chat")
    monkeypatch.setattr(telegram, "_last_alert_time", 0.0)


def test_unconfigured_returns_false(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_TOKEN", "")
    assert telegram.send_alert("critical", "title", {"ip": "192.0.2.1"}) is False


def test_low_severity_is_ignored():
    assert telegram.send_alert("medium", "title", {"ip": "192.0.2.1"}) is False


def test_high_severity_sends(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["payload"] = json
        return type("R", (), {"status_code": 200})()

    monkeypatch.setattr(telegram.requests, "post", fake_post)
    assert telegram.send_alert("high", "Brute force", {"ip": "192.0.2.1"}) is True
    assert captured["url"].endswith("/bottoken/sendMessage")
    assert captured["payload"]["chat_id"] == "chat"
    assert "Brute force" in captured["payload"]["text"]


def test_rate_limited(monkeypatch):
    monkeypatch.setattr(telegram, "_last_alert_time", time.time())
    assert telegram.send_alert("critical", "title", {}) is False


def test_api_failure_returns_false(monkeypatch):
    monkeypatch.setattr(
        telegram.requests,
        "post",
        lambda *a, **k: type("R", (), {"status_code": 500})(),
    )
    assert telegram.send_alert("critical", "title", {}) is False


def test_network_error_returns_false(monkeypatch):
    def boom(*args, **kwargs):
        raise telegram.requests.RequestException("offline")

    monkeypatch.setattr(telegram.requests, "post", boom)
    assert telegram.send_alert("critical", "title", {}) is False
