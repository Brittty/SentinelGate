"""Tests for audit: CVSS, hashchain, scanners."""

from __future__ import annotations

import sqlite3

import pytest

from audit.hashchain import HashChain

# CVSS engine tests
try:
    from audit.cvss_engine import score_attack, score_finding

    CVSS_AVAILABLE = True
except ImportError:
    CVSS_AVAILABLE = False


@pytest.fixture
def chain() -> HashChain:
    conn = sqlite3.connect(":memory:")
    return HashChain(conn)


def test_hashchain_append(chain: HashChain):
    entry1 = {"action": "block", "ip": "192.0.2.1", "reason": "brute_force"}
    hash1 = chain.append(entry1)
    assert len(hash1) == 64

    entry2 = {"action": "unblock", "ip": "192.0.2.1", "reason": "false_positive"}
    hash2 = chain.append(entry2)
    assert hash2 != hash1

    entries = chain.get_entries(limit=10)
    assert len(entries) == 2


def test_hashchain_verify_clean(chain: HashChain):
    chain.append({"action": "block", "ip": "192.0.2.1"})
    chain.append({"action": "throttle", "ip": "192.0.2.2"})

    ok, idx = chain.verify()
    assert ok
    assert idx is None


def test_hashchain_verify_tampered(chain: HashChain):
    chain.append({"action": "block", "ip": "192.0.2.1"})
    chain.append({"action": "throttle", "ip": "192.0.2.2"})

    # Tamper with the second entry
    chain.conn.execute(
        "UPDATE audit_chain SET entry_json = ? WHERE id = 2",
        ('{"action":"allow","ip":"192.0.2.2"}',),
    )
    chain.conn.commit()

    ok, idx = chain.verify()
    assert not ok
    assert idx == 2


@pytest.mark.skipif(not CVSS_AVAILABLE, reason="cvss library not available")
def test_score_attack_sqli():
    score, severity, vector = score_attack("sqli")
    assert score > 9.0  # Critical
    assert severity == "critical"
    assert "CVSS:3.1" in vector


@pytest.mark.skipif(not CVSS_AVAILABLE, reason="cvss library not available")
def test_score_attack_xss():
    score, severity, vector = score_attack("xss")
    assert 4.0 <= score < 7.0  # Medium
    assert severity in ("medium", "low")
    assert "CVSS:3.1" in vector


@pytest.mark.skipif(not CVSS_AVAILABLE, reason="cvss library not available")
def test_score_finding_missing_hsts():
    score, severity, vector = score_finding("missing_hsts")
    assert 0.0 < score < 7.0
    assert severity in ("low", "medium")
    assert "CVSS:3.1" in vector


def test_score_attack_unknown():
    score, severity, vector = score_attack("nonexistent_attack")
    assert score == 0.0
    assert severity == "none"
    assert vector == ""


# Scanner tests (integration-level smoke tests)


def test_headers_scanner_missing_target():
    from audit.scanners.headers import scan_headers

    findings = scan_headers("http://nonexistent.invalid", timeout=1.0)
    assert len(findings) > 0
    assert findings[0]["type"] == "connection_error"


def test_ports_scanner_refuses_non_local():
    from audit.scanners.ports import scan_ports

    findings = scan_ports("http://example.com", timeout=1.0)
    assert len(findings) > 0
    assert findings[0]["type"] == "refused"


def test_tls_scanner_http_target():
    from audit.scanners.tls import scan_tls

    findings = scan_tls("http://localhost", timeout=1.0)
    assert len(findings) > 0
    assert findings[0]["type"] == "no_tls"


def test_code_scanner_smoke():
    from audit.scanners.code import scan_code

    # This may return tool_unavailable or findings
    findings = scan_code(".", timeout=10.0)
    assert isinstance(findings, list)


def test_deps_scanner_smoke():
    from audit.scanners.deps import scan_dependencies

    # This may return tool_unavailable or findings
    findings = scan_dependencies(timeout=10.0)
    assert isinstance(findings, list)
