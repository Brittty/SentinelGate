"""Tests for gateway.main using a mocked upstream (httpx.MockTransport)."""

from __future__ import annotations

import sqlite3

import httpx
from fastapi.testclient import TestClient

import gateway.main as gw


def _upstream_handler(request: httpx.Request) -> httpx.Response:
    body = request.content or b""
    return httpx.Response(
        200,
        text=f"echo:{body.decode(errors='replace')}",
        headers={"content-type": "text/plain"},
    )


def test_proxy_200_passthrough(monkeypatch):
    transport = httpx.MockTransport(_upstream_handler)
    monkeypatch.setattr(gw, "_client", httpx.AsyncClient(transport=transport))

    client = TestClient(gw.app)
    response = client.get("/search?q=hello", headers={"user-agent": "test-agent"})

    assert response.status_code == 200  # noqa: PLR2004
    assert "echo:" in response.text
    assert response.headers.get("x-request-id") is not None


def test_proxy_forwards_body(monkeypatch):
    transport = httpx.MockTransport(_upstream_handler)
    monkeypatch.setattr(gw, "_client", httpx.AsyncClient(transport=transport))

    client = TestClient(gw.app)
    response = client.post("/login", data={"username": "alice", "password": "pw"})

    assert response.status_code == 200  # noqa: PLR2004
    assert "alice" in response.text


def test_health_endpoint():
    client = TestClient(gw.app)
    response = client.get("/health")
    assert response.status_code == 200  # noqa: PLR2004
    assert response.json() == {"status": "ok"}


def test_proxy_connect_error_returns_502(monkeypatch):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, text="x"))
    )

    async def _failing_request(*args, **kwargs):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(client, "request", _failing_request)
    monkeypatch.setattr(gw, "_client", client)

    tc = TestClient(gw.app)
    response = tc.get("/anything")
    assert response.status_code == 502  # noqa: PLR2004


def test_proxy_timeout_returns_504(monkeypatch):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, text="x"))
    )

    async def _failing_request(*args, **kwargs):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(client, "request", _failing_request)
    monkeypatch.setattr(gw, "_client", client)

    tc = TestClient(gw.app)
    response = tc.get("/anything")
    assert response.status_code == 504  # noqa: PLR2004


def test_record_block_allowlisted_writes_audit_only(tmp_path, monkeypatch):
    from audit.hashchain import HashChain
    from gateway import main

    db_path = tmp_path / "gateway.db"
    monkeypatch.setattr(main, "DB_PATH", str(db_path))

    main._record_block("127.0.0.1", "IDPS high: xss_script", {}, "high")

    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0] == 0
    ok, _ = HashChain(conn).verify()
    assert ok
    conn.close()


def test_record_block_bans_external_ip(tmp_path, monkeypatch):
    from gateway import main

    db_path = tmp_path / "gateway.db"
    monkeypatch.setattr(main, "DB_PATH", str(db_path))

    main._record_block("203.0.113.7", "IDPS critical: sqli", {}, "critical")

    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0] == 1
    conn.close()
