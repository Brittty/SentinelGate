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

## Phase 1: Test app and gateway proxy — DONE
- Files:
  - testapp/app.py — Flask on port 5000: /, /search?q= (reflects), /login POST (no lockout), /file?name= (reads ./testapp/files), /admin; "DELIBERATELY VULNERABLE" banner; testapp/files/sample.txt
  - gateway/main.py — FastAPI catch-all proxy to TARGET_URL via shared httpx.AsyncClient (lifespan-managed); forwards method/path/query/headers (minus hop-by-hop)+body; returns upstream status/headers/body; 502 on ConnectError, 504 on TimeoutException; /health; X-Request-ID header; logs one JSONL event per request
  - gateway/logger.py — append_jsonl to logs/requests.jsonl; sanitizes control chars/newlines; per-field cap (MAX_FIELD=2048); creates directories
  - tests/test_gateway.py — 200 passthrough, body forwarding, /health, 502 on connect error, 504 on timeout (httpx.MockTransport)
  - tests/test_logger.py — JSON line format, sanitization, field cap, directory creation
- Test result: 16 passed (7 schema + 4 logger + 5 gateway); ruff clean
- Commit: "Phase 1: Test app and gateway proxy"

## Notes / blockers
- requirements.txt pins (fastapi<0.116, uvicorn<0.33, scikit-learn<1.7) too strict for Python 3.14; newer versions installed. Will loosen pins when rewriting requirements.txt after dependency survey.
- scikit-learn 1.6.1 fails to build from source on cp314 (no wheel); ML (Phase 5) will degrade gracefully if unavailable.
