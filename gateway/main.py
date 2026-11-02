"""SentinelGate gateway — FastAPI reverse proxy.

Forwards incoming requests (method, path, query, headers minus hop-by-hop,
body) to TARGET_URL via a shared httpx.AsyncClient. Returns the upstream
status, headers, and body. Emits one JSONL event per request via
gateway.logger.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from gateway.logger import log_event
from gateway.ratelimit import rate_limit_middleware
from idps.engine import Engine

TARGET_URL = "http://127.0.0.1:5000"
LOG_PATH = "logs/requests.jsonl"
REQUEST_TIMEOUT = 10.0

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_client: httpx.AsyncClient | None = None
_idps: Engine | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client, _idps  # noqa: PLW0603
    _client = httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT))
    _idps = Engine()
    yield
    await _client.aclose()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    return await rate_limit_middleware(request, call_next)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy(request: Request, path: str):
    """Proxy the request to TARGET_URL and return the upstream response."""
    assert _client is not None
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    url = f"{TARGET_URL}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
    }
    headers["X-Request-ID"] = request_id

    body = await request.body()

    source_ip = request.client.host if request.client else "unknown"
    user_agent = headers.get("user-agent", "")
    query = str(request.url.query)

    # --- IDPS inspection ---
    rule_hit = ""
    attack_type = ""
    action = "allow"
    if _idps is not None:
        hits = _idps.inspect(
            method=request.method,
            path=f"/{path}",
            query=query,
            headers=dict(request.headers),
            body=body.decode(errors="replace"),
        )
        if hits:
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            max_severity = max(
                hits, key=lambda h: severity_order.get(h["severity"], 0)
            )["severity"]
            rule_hit = ",".join(h["id"] for h in hits)
            attack_type = hits[0]["attack_type"]
            if max_severity in ("critical", "high"):
                action = "block"
                latency_ms = (time.perf_counter() - start) * 1000.0
                log_event(
                    LOG_PATH,
                    {
                        "timestamp": datetime.now().astimezone().isoformat(),
                        "source_ip": source_ip,
                        "method": request.method,
                        "path": f"/{path}",
                        "query": query,
                        "status": 403,
                        "user_agent": user_agent,
                        "latency_ms": round(latency_ms, 3),
                        "rule_hit": rule_hit,
                        "attack_type": attack_type,
                        "ml_score": 0.0,
                        "cvss_score": 0.0,
                        "risk_score": 0.0,
                        "action": "block",
                        "source": "gateway",
                    },
                )
                return Response(
                    status_code=403,
                    content="blocked by IDPS",
                    headers={"X-Request-ID": request_id},
                )

    status = 200
    upstream_content = b""
    upstream = None
    try:
        upstream = await _client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )
        status = upstream.status_code
        upstream_content = upstream.content
    except httpx.ConnectError:
        status = 502
        upstream_content = b"upstream unreachable"
    except httpx.TimeoutException:
        status = 504
        upstream_content = b"upstream timeout"

    latency_ms = (time.perf_counter() - start) * 1000.0

    event: dict[str, Any] = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "source_ip": source_ip,
        "method": request.method,
        "path": f"/{path}",
        "query": query,
        "status": status,
        "user_agent": user_agent,
        "latency_ms": round(latency_ms, 3),
        "rule_hit": rule_hit,
        "attack_type": attack_type,
        "ml_score": 0.0,
        "cvss_score": 0.0,
        "risk_score": 0.0,
        "action": action,
        "source": "gateway",
    }
    log_event(LOG_PATH, event)

    response_headers = {
        k: v
        for k, v in (upstream.headers if upstream else {}).items()
        if k.lower() not in HOP_BY_HOP
    }
    response_headers["X-Request-ID"] = request_id

    return Response(
        content=upstream_content,
        status_code=status,
        headers=response_headers,
        media_type=(upstream.headers.get("content-type") if upstream else None),
    )