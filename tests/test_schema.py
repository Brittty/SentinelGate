"""Tests for the shared Event schema (siem/schema.py)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from siem.schema import Event


def test_valid_event():
    event = Event(
        timestamp="2024-01-01T12:00:00Z",
        source_ip="127.0.0.1",
        method="GET",
        path="/search",
        query="q=hello",
        status=200,
        user_agent="Mozilla/5.0",
        latency_ms=12.5,
        rule_hit="",
        attack_type="",
        ml_score=0.0,
        cvss_score=0.0,
        risk_score=10.0,
        action="allow",
        source="gateway",
    )
    assert event.source_ip == "127.0.0.1"
    assert event.method == "GET"
    assert event.action == "allow"
    assert event.source == "gateway"
    assert event.risk_score == 10.0  # noqa: PLR2004


def test_defaults():
    event = Event(
        timestamp="2024-01-01T12:00:00Z",
        source_ip="127.0.0.1",
        method="POST",
        path="/login",
    )
    assert event.status == 200  # noqa: PLR2004
    assert event.query == ""
    assert event.action == "allow"
    assert event.source == "gateway"
    assert event.ml_score == 0.0


def test_sanitizes_newlines_and_control_chars():
    event = Event(
        timestamp="2024-01-01T12:00:00Z",
        source_ip="127.0.0.1",
        method="GET",
        path="/search",
        user_agent="bad\u0000ua\r\ninjected",
    )
    assert "\n" not in event.user_agent
    assert "\r" not in event.user_agent
    assert "\x00" not in event.user_agent
    assert "badua injected" == event.user_agent


def test_rejects_bad_status():
    with pytest.raises(ValidationError):
        Event(
            timestamp="2024-01-01T12:00:00Z",
            source_ip="127.0.0.1",
            method="GET",
            path="/",
            status=999,
        )


def test_rejects_ml_score_out_of_range():
    with pytest.raises(ValidationError):
        Event(
            timestamp="2024-01-01T12:00:00Z",
            source_ip="127.0.0.1",
            method="GET",
            path="/",
            ml_score=1.5,
        )


def test_rejects_invalid_action():
    with pytest.raises(ValidationError):
        Event(
            timestamp="2024-01-01T12:00:00Z",
            source_ip="127.0.0.1",
            method="GET",
            path="/",
            action="drop",  # type: ignore[arg-type]
        )


def test_missing_required_field():
    with pytest.raises(ValidationError):
        Event(
            timestamp="2024-01-01T12:00:00Z",
            source_ip="127.0.0.1",
            method="GET",
        )  # path is required