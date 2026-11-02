# SentinelGate — Progress Log

## Environment (decisions recorded)
- OS: Windows 11; shell: PowerShell 5.1 (`powershell.exe`; `pwsh` not on PATH)
- Python: 3.14.7 (target 3.12+); venv at `.venv` (active)
- git: 2.55.0; Docker Desktop available (optional, off by default)
- nmap: NOT installed — port scanner/integrations degrade gracefully
- Network: PyPI reachable but intermittent DNS; scikit-learn has no cp314 wheel (builds fail from source) — ML (Phase 5) will degrade gracefully if unavailable
- CLAUDE.md: created (project instruction file)

## Phase 0: Foundation — DONE
- Files: CLAUDE.md, .gitignore, pyproject.toml, pytest.ini, requirements.txt; package __init__.py for all modules; siem/schema.py (Event model); tests/conftest.py; tests/test_schema.py
- Test result: 7 passed; ruff clean
- Commit: "Phase 0: Foundation"

## Phase 2: Rate limiting — DONE
- Files:
  - gateway/ratelimit.py — `RateLimiter` ABC; `InMemoryTokenBucket` (rate/burst from .env RATE_LIMIT/RATE_BURST, defaults 60/min, burst 20); per-IP buckets in OrderedDict with LRU eviction (max 10k); BanStore with expiry; allowlist; `client_ip()` (socket peername; XFF first entry only if TRUST_PROXY=true); `rate_limit_middleware` (allowlist/ban check → token bucket → 429 with Retry-After, logs action=throttle)
  - gateway/main.py — added `@app.middleware("http")` calling rate_limit_middleware before routing
  - tests/test_ratelimit.py — 9 tests: refill, burst, 429+retry_after, ban expiry, allowlist never blocked, LRU eviction, client IP (socket/XFF/trust proxy), ban/unban
- Hook: middleware runs before IDPS/proxy; throttled requests return 429 + Retry-After and log action=throttle
- Test result: 24 passed (16 phase 1 + 8 phase 2); ruff clean
- Commit: "Phase 2: Rate limiting"

## Notes / blockers
- requirements.txt pins (fastapi<0.116, uvicorn<0.33, scikit-learn<1.7) too strict for Python 3.14; newer versions installed. Will loosen pins when rewriting requirements.txt after dependency survey.
- scikit-learn 1.6.1 fails to build from source on cp314 (no wheel); ML (Phase 5) will degrade gracefully if unavailable.
