# SentinelGate — Progress Log

## Environment (decisions recorded)
- OS: Windows 11; shell: PowerShell 5.1 (`powershell.exe`; `pwsh` not on PATH)
- Python: 3.14.7 (target 3.12+); venv at `.venv` (active)
- git: 2.55.0; Docker Desktop available (optional, off by default)
- nmap: NOT installed — port scanner/integrations degrade gracefully
- Network: PyPI reachable but intermittent DNS; scikit-learn has no cp314 wheel (builds fail from source) — deferred to Phase 5 with optional/graceful ML
- CLAUDE.md: created (project instruction file)

## Phase 0: Foundation — DONE
- Files created:
  - CLAUDE.md, .gitignore, pyproject.toml (ruff + pytest config), pytest.ini, requirements.txt
  - Package __init__.py for: siem, gateway, idps, ml, audit, audit/scanners, response, cases, mitre, intel, playbooks, reports, dashboard, simulator, testapp, prompts, tests
  - siem/schema.py — Pydantic v2 `Event` model with string sanitization (control chars/newlines removed, length capped)
  - tests/conftest.py — `tmp_db` (SQLite WAL) and `fake_clock` (float seconds) fixtures
  - tests/test_schema.py — 7 tests (valid event, defaults, sanitization, field validation)
- Test result: 7 passed, 0 failed
- Ruff: all checks passed
- Commit: `git add . ; git commit -m "Phase 0: Foundation"`

## Notes / blockers
- requirements.txt pins (fastapi<0.116, uvicorn<0.33, scikit-learn<1.7) are too strict for Python 3.14; newer versions installed instead. Will loosen pins when rewriting requirements.txt after dependency survey.
- scikit-learn 1.6.1 fails to build from source on cp314 (no wheel); ML (Phase 5) will degrade gracefully if unavailable.
