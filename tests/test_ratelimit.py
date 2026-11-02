"""Tests for gateway.ratelimit (token bucket, bans, allowlist, eviction)."""

from __future__ import annotations

from gateway.ratelimit import InMemoryTokenBucket, client_ip


class FakeRequest:
    """Minimal stand-in for a FastAPI Request for client_ip tests."""

    def __init__(self, host: str, headers: dict | None = None):
        self.client = type("C", (), {"host": host})() if host else None
        self.headers = headers or {}


BUCKET_COUNT = 3


def test_refill(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=1.0, burst=2, clock=fake_clock)
    assert limiter.allow("1.2.3.4")[0] is True
    assert limiter.allow("1.2.3.4")[0] is True
    assert limiter.allow("1.2.3.4")[0] is False  # burst exhausted
    fake_clock.advance(1.0)  # refill 1 token
    assert limiter.allow("1.2.3.4")[0] is True


def test_burst(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=0.5, burst=3, clock=fake_clock)
    results = [limiter.allow("1.2.3.4")[0] for _ in range(4)]
    assert results == [True, True, True, False]


def test_429_retry_after(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=1.0, burst=1, clock=fake_clock)
    assert limiter.allow("1.2.3.4")[0] is True
    allowed, retry = limiter.allow("1.2.3.4")
    assert allowed is False
    assert retry > 0


def test_ban_expiry(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=1.0, burst=5, clock=fake_clock)
    limiter.ban("1.2.3.4", 10.0)
    assert limiter.is_banned("1.2.3.4") is True
    assert limiter.retry_after("1.2.3.4") > 0
    fake_clock.advance(11.0)
    assert limiter.is_banned("1.2.3.4") is False
    assert limiter.retry_after("1.2.3.4") == 0.0


def test_allowlist_never_blocked(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=0.1, burst=1, clock=fake_clock)
    limiter.allowlist("1.2.3.4")
    assert limiter.is_allowlisted("1.2.3.4") is True
    # Exhaust the bucket, then ban — allowlisted IP still allowed.
    for _ in range(20):
        limiter.allow("1.2.3.4")
    limiter.ban("1.2.3.4", 60.0)
    allowed, _ = limiter.allow("1.2.3.4")
    assert allowed is True


def test_lru_eviction(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=1.0, burst=1, clock=fake_clock, max_buckets=3)
    for ip in ["1.0.0.1", "1.0.0.2", "1.0.0.3"]:
        limiter.allow(ip)
    assert len(limiter._buckets) == BUCKET_COUNT  # noqa: SLF001
    limiter.allow("1.0.0.4")  # evicts LRU (1.0.0.1)
    assert len(limiter._buckets) == BUCKET_COUNT  # noqa: SLF001
    assert "1.0.0.1" not in limiter._buckets  # noqa: SLF001


def test_client_ip_socket_peername():
    req = FakeRequest(host="10.0.0.1")
    assert client_ip(req, trust_proxy=False) == "10.0.0.1"


def test_client_ip_trust_proxy_xff():
    req = FakeRequest(host="10.0.0.1", headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"})
    assert client_ip(req, trust_proxy=True) == "203.0.113.7"


def test_client_ip_no_proxy_when_untrusted():
    req = FakeRequest(host="10.0.0.1", headers={"x-forwarded-for": "203.0.113.7"})
    assert client_ip(req, trust_proxy=False) == "10.0.0.1"


def test_ban_then_unban(fake_clock):
    limiter = InMemoryTokenBucket(rate_per_sec=1.0, burst=5, clock=fake_clock)
    limiter.ban("1.2.3.4", 60.0)
    assert limiter.is_banned("1.2.3.4")
    limiter.unban("1.2.3.4")
    assert limiter.is_banned("1.2.3.4") is False