"""Tests for audit scanners and the NVD client with mocked I/O."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import time

import pytest

from audit import nvd_client
from audit.nvd_client import NVDClient
from audit.scanners import code, deps, headers, ports, tls


class _Response:
    """Minimal requests.Response stand-in."""

    def __init__(self, payload=None, status_code=200, headers=None, text=""):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _Completed:
    """Minimal subprocess.CompletedProcess stand-in."""

    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# -- headers -------------------------------------------------------------


def test_headers_all_missing(monkeypatch):
    monkeypatch.setattr(headers.requests, "get", lambda *a, **k: _Response())
    findings = headers.scan_headers("http://localhost")
    types = {f["type"] for f in findings}
    assert types == {
        "missing_hsts",
        "missing_csp",
        "missing_x_frame",
        "missing_x_content_type",
        "missing_referrer_policy",
    }


def test_headers_all_present(monkeypatch):
    response = _Response(
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
    )
    monkeypatch.setattr(headers.requests, "get", lambda *a, **k: response)
    assert headers.scan_headers("http://localhost") == []


def test_headers_insecure_cookie(monkeypatch):
    response = _Response(headers={"Set-Cookie": "session=abc; Path=/"})
    monkeypatch.setattr(headers.requests, "get", lambda *a, **k: response)
    findings = headers.scan_headers("http://localhost")
    cookie_findings = [f for f in findings if f["type"] == "insecure_cookie"]
    assert len(cookie_findings) == 2
    assert all("session=abc" in f["evidence"] for f in cookie_findings)


def test_headers_connection_error(monkeypatch):
    def fail(*args, **kwargs):
        raise headers.requests.RequestException("boom")

    monkeypatch.setattr(headers.requests, "get", fail)
    findings = headers.scan_headers("http://localhost")
    assert findings[0]["type"] == "connection_error"


# -- TLS -----------------------------------------------------------------


class _Socket:
    def __init__(self, cert=None, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384",)):
        self._cert = cert or {}
        self._version = version
        self._cipher = cipher

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getpeercert(self):
        return self._cert

    def cipher(self):
        return self._cipher

    def version(self):
        return self._version


class _Context:
    def __init__(self, sock):
        self._sock = sock

    def wrap_socket(self, sock, server_hostname=None):
        return self._sock


def _patch_tls(monkeypatch, sock):
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: _Context(sock))
    monkeypatch.setattr(tls.socket, "create_connection", lambda addr, timeout: sock)


def test_tls_non_https():
    findings = tls.scan_tls("http://localhost")
    assert findings[0]["type"] == "no_tls"


def test_tls_clean_https(monkeypatch):
    _patch_tls(monkeypatch, _Socket())
    assert tls.scan_tls("https://localhost") == []


def test_tls_weak_cert_and_cipher(monkeypatch):
    sock = _Socket(
        cert={"notAfter": "Jan 01 00:00:00 2020 GMT"},
        version="TLSv1.1",
        cipher=("RC4-SHA", "TLSv1.1", 128),
    )
    _patch_tls(monkeypatch, sock)
    types = {f["type"] for f in tls.scan_tls("https://localhost")}
    assert {"expired_cert", "weak_tls", "weak_cipher"} <= types


def test_tls_handshake_error(monkeypatch):
    def fail(addr, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(tls.socket, "create_connection", fail)
    findings = tls.scan_tls("https://localhost")
    assert findings[0]["type"] == "tls_error"


# -- ports ---------------------------------------------------------------


def test_ports_refuses_non_local():
    findings = ports.scan_ports("http://example.com")
    assert findings[0]["type"] == "refused"


def test_ports_nmap_missing(monkeypatch):
    monkeypatch.setattr(ports.shutil, "which", lambda name: None)
    findings = ports.scan_ports("http://127.0.0.1")
    assert findings[0]["type"] == "tool_unavailable"


def test_ports_reports_unexpected_ports(monkeypatch):
    monkeypatch.setattr(ports.shutil, "which", lambda name: "nmap")
    output = (
        "PORT     STATE SERVICE\n"
        "22/tcp   open  ssh\n"
        "80/tcp   open  http\n"
        "5000/tcp open  http-alt\n"
    )
    monkeypatch.setattr(
        ports.subprocess, "run", lambda *a, **k: _Completed(stdout=output)
    )
    findings = ports.scan_ports("http://127.0.0.1")
    assert [f["title"] for f in findings] == ["Unexpected open port 22"]


def _nmap_then(monkeypatch, outcome):
    """Let the version probe succeed, then make the scan raise *outcome*."""
    calls = {"count": 0}

    def run(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return _Completed(stdout="Nmap version 7.94")
        raise outcome

    monkeypatch.setattr(ports.shutil, "which", lambda name: "nmap")
    monkeypatch.setattr(ports.subprocess, "run", run)


def test_ports_timeout_and_error(monkeypatch):
    _nmap_then(monkeypatch, subprocess.TimeoutExpired("nmap", 1))
    assert ports.scan_ports("http://127.0.0.1")[0]["type"] == "scan_timeout"

    _nmap_then(monkeypatch, RuntimeError("bad"))
    assert ports.scan_ports("http://127.0.0.1")[0]["type"] == "scan_error"


# -- dependency and code scanners ---------------------------------------


def test_deps_reports_vulnerabilities(monkeypatch):
    payload = {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.0.0",
                "vulns": [
                    {"id": "CVE-2020-1", "description": "bad", "fix_versions": ["2.1.0"]}
                ],
            }
        ]
    }
    monkeypatch.setattr(deps.shutil, "which", lambda name: "pip-audit")
    monkeypatch.setattr(
        deps.subprocess, "run", lambda *a, **k: _Completed(stdout=json.dumps(payload))
    )
    findings = deps.scan_dependencies()
    assert len(findings) == 1
    assert "Upgrade to 2.1.0" in findings[0]["remediation"]


def test_deps_unavailable_and_bad_output(monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda name: None)
    assert deps.scan_dependencies()[0]["type"] == "tool_unavailable"

    monkeypatch.setattr(deps.shutil, "which", lambda name: "pip-audit")
    monkeypatch.setattr(
        deps.subprocess, "run", lambda *a, **k: _Completed(stdout="not json")
    )
    assert deps.scan_dependencies()[0]["type"] == "parse_error"


def test_deps_timeout_and_failure(monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda name: "pip-audit")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("pip-audit", 1)

    monkeypatch.setattr(deps.subprocess, "run", timeout)
    assert deps.scan_dependencies()[0]["type"] == "scan_timeout"

    monkeypatch.setattr(
        deps.subprocess,
        "run",
        lambda *a, **k: _Completed(stdout="", stderr="boom", returncode=2),
    )
    assert deps.scan_dependencies()[0]["type"] == "scan_error"


def test_code_reports_findings(monkeypatch):
    payload = {
        "results": [
            {
                "test_id": "B602",
                "issue_text": "subprocess call with shell=True",
                "filename": "app.py",
                "line_number": 12,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
            },
            {
                "test_id": "B101",
                "issue_text": "assert used",
                "filename": "app.py",
                "line_number": 7,
                "issue_severity": "low",
                "issue_confidence": "low",
            },
        ]
    }
    monkeypatch.setattr(code.shutil, "which", lambda name: "bandit")
    monkeypatch.setattr(
        code.subprocess, "run", lambda *a, **k: _Completed(stdout=json.dumps(payload))
    )
    findings = code.scan_code()
    assert len(findings) == 1
    assert "B602" in findings[0]["title"]


def test_code_unavailable_timeout_and_parse_error(monkeypatch):
    monkeypatch.setattr(code.shutil, "which", lambda name: None)
    assert code.scan_code()[0]["type"] == "tool_unavailable"

    monkeypatch.setattr(code.shutil, "which", lambda name: "bandit")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("bandit", 1)

    monkeypatch.setattr(code.subprocess, "run", timeout)
    assert code.scan_code()[0]["type"] == "scan_timeout"

    monkeypatch.setattr(
        code.subprocess, "run", lambda *a, **k: _Completed(stdout="nope")
    )
    assert code.scan_code()[0]["type"] == "parse_error"


# -- NVD client ----------------------------------------------------------


@pytest.fixture
def nvd(tmp_db):
    return NVDClient(tmp_db)


def test_nvd_cache_hit(nvd, monkeypatch):
    nvd.conn.execute(
        "INSERT INTO nvd_cache (cve_id, data, cached_at) VALUES (?, ?, ?)",
        ("CVE-2020-1", json.dumps({"id": "CVE-2020-1"}), time.time()),
    )
    nvd.conn.commit()
    assert nvd.lookup("CVE-2020-1") == {"id": "CVE-2020-1"}


def test_nvd_api_success_caches(nvd, monkeypatch):
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-2020-2"}}]}
    monkeypatch.setattr(
        nvd_client.requests, "get", lambda *a, **k: _Response(payload=payload)
    )
    result = nvd.lookup("CVE-2020-2")
    assert result == {"cve": {"id": "CVE-2020-2"}}
    row = nvd.conn.execute(
        "SELECT data FROM nvd_cache WHERE cve_id = ?", ("CVE-2020-2",)
    ).fetchone()
    assert row is not None


def test_nvd_not_found(nvd, monkeypatch):
    monkeypatch.setattr(
        nvd_client.requests, "get", lambda *a, **k: _Response(status_code=404)
    )
    assert nvd.lookup("CVE-2020-3") is None


def test_nvd_retries_then_gives_up(nvd, monkeypatch):
    monkeypatch.setattr(nvd_client.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        nvd_client.requests, "get", lambda *a, **k: _Response(status_code=500)
    )
    assert nvd.lookup("CVE-2020-4") is None


def test_nvd_exception_returns_none(nvd, monkeypatch):
    def boom(*args, **kwargs):
        raise nvd_client.requests.RequestException("offline")

    monkeypatch.setattr(nvd_client.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(nvd_client.requests, "get", boom)
    assert nvd.lookup("CVE-2020-5") is None
