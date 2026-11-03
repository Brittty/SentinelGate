"""Rate limiting for the SentinelGate gateway.

Implements a per-IP token bucket with an LRU-evicted bucket cache, temporary
bans with expiry, and an allowlist. The :class:`RateLimiter` ABC lets the
backend be swapped (e.g. Redis in Phase 14) without changing callers.

All time-dependent behaviour uses an injectable ``clock`` callable (default
``time.time``) so tests can freeze time.
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Callable

from fastapi import Request
from fastapi.responses import Response

from gateway.logger import log_event


class RateLimiter(ABC):
    """Interface for per-IP rate limiting and banning."""

    @abstractmethod
    def allow(self, ip: str) -> tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)`` for *ip*."""

    @abstractmethod
    def is_banned(self, ip: str) -> bool:
        """Return True if *ip* is currently banned."""

    @abstractmethod
    def retry_after(self, ip: str) -> float:
        """Seconds remaining on *ip*'s ban (0 if not banned)."""

    @abstractmethod
    def ban(self, ip: str, duration_seconds: float) -> None:
        """Ban *ip* for *duration_seconds*."""

    @abstractmethod
    def unban(self, ip: str) -> None:
        """Lift any ban on *ip*."""

    @abstractmethod
    def is_allowlisted(self, ip: str) -> bool:
        ...

    @abstractmethod
    def allowlist(self, ip: str) -> None:
        ...

    @abstractmethod
    def remove_allowlist(self, ip: str) -> None:
        ...


class InMemoryTokenBucket(RateLimiter):
    """Token bucket rate limiter stored in memory with LRU eviction."""

    def __init__(
        self,
        rate_per_sec: float,
        burst: int,
        clock: Callable[[], float] = time.time,
        max_buckets: int = 10_000,
    ):
        self.rate = rate_per_sec
        self.burst = burst
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._bans: dict[str, float] = {}
        self._allowlist: set[str] = set()

    def _now(self) -> float:
        return self._clock()

    def _bucket(self, ip: str) -> tuple[float, float]:
        now = self._now()
        if ip in self._buckets:
            tokens, last = self._buckets[ip]
            elapsed = max(0.0, now - last)
            tokens = min(float(self.burst), tokens + elapsed * self.rate)
            self._buckets[ip] = (tokens, now)
            self._buckets.move_to_end(ip)
            return tokens, now
        if len(self._buckets) >= self._max_buckets:
            self._buckets.popitem(last=False)
        tokens = float(self.burst)
        self._buckets[ip] = (tokens, now)
        return tokens, now

    def allow(self, ip: str) -> tuple[bool, float]:
        if ip in self._allowlist:
            return True, 0.0
        if self.is_banned(ip):
            return False, self.retry_after(ip)
        tokens, _ = self._bucket(ip)
        if tokens >= 1.0:
            cur_tokens, _ = self._buckets[ip]
            self._buckets[ip] = (cur_tokens - 1.0, self._now())
            return True, 0.0
        retry_after = (1.0 - tokens) / self.rate if self.rate > 0 else 0.0
        return False, max(0.0, retry_after)

    def is_banned(self, ip: str) -> bool:
        expiry = self._bans.get(ip)
        if expiry is None:
            return False
        if self._now() < expiry:
            return True
        del self._bans[ip]
        return False

    def retry_after(self, ip: str) -> float:
        expiry = self._bans.get(ip)
        if expiry is None:
            return 0.0
        return max(0.0, expiry - self._now())

    def ban(self, ip: str, duration_seconds: float) -> None:
        self._bans[ip] = self._now() + float(duration_seconds)

    def unban(self, ip: str) -> None:
        self._bans.pop(ip, None)

    def is_allowlisted(self, ip: str) -> bool:
        return ip in self._allowlist

    def allowlist(self, ip: str) -> None:
        self._allowlist.add(ip)

    def remove_allowlist(self, ip: str) -> None:
        self._allowlist.discard(ip)


LOG_PATH = "logs/requests.jsonl"

RATE_LIMIT_PER_MIN = float(os.environ.get("RATE_LIMIT", "60"))
RATE_BURST = int(os.environ.get("RATE_BURST", "20"))
TRUST_PROXY = os.environ.get("TRUST_PROXY", "false").lower() == "true"

rate_limiter = InMemoryTokenBucket(
    rate_per_sec=RATE_LIMIT_PER_MIN / 60.0,
    burst=RATE_BURST,
)


def client_ip(request: Request, trust_proxy: bool = TRUST_PROXY) -> str:
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def rate_limit_middleware(request: Request, call_next):
    ip = client_ip(request, trust_proxy=TRUST_PROXY)

    if not rate_limiter.is_allowlisted(ip):
        if rate_limiter.is_banned(ip):
            retry = int(rate_limiter.retry_after(ip)) + 1
            _log_throttle(ip, request)
            return Response(
                status_code=429, headers={"Retry-After": str(retry)},
                content="rate limited",
            )
        allowed, retry = rate_limiter.allow(ip)
        if not allowed:
            _log_throttle(ip, request)
            return Response(
                status_code=429, headers={"Retry-After": str(int(retry) + 1)},
                content="rate limited",
            )

    return await call_next(request)


def _log_throttle(ip: str, request: Request) -> None:
    log_event(
        LOG_PATH,
        {
            "timestamp": time.time(),
            "source_ip": ip,
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "status": 429,
            "user_agent": request.headers.get("user-agent", ""),
            "latency_ms": 0.0,
            "rule_hit": "",
            "attack_type": "",
            "ml_score": 0.0,
            "cvss_score": 0.0,
            "risk_score": 0.0,
            "action": "throttle",
            "source": "gateway",
        },
    )
