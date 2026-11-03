"""Tests for attack simulator."""

from __future__ import annotations

import pytest

from simulator.run import validate_target


def test_validate_target_localhost():
    assert validate_target("http://127.0.0.1:8000")
    assert validate_target("http://localhost:8000")
    assert validate_target("http://[::1]:8000")


def test_validate_target_refuses_external():
    assert not validate_target("http://example.com")
    assert not validate_target("http://192.0.2.1")
    assert not validate_target("https://evil.com")


def test_validate_target_allowed_list(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "testlab.local,192.168.1.100")
    # Need to reload the module to pick up the env var
    import importlib
    import simulator.run

    importlib.reload(simulator.run)

    assert simulator.run.validate_target("http://testlab.local")
    assert simulator.run.validate_target("http://192.168.1.100")
    assert not simulator.run.validate_target("http://other.com")
