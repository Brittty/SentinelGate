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

## Phase 3: IDPS signature engine — DONE
- Files:
  - idps/rules.yaml — 34 rules across SQLi (7), XSS (4), path traversal (4), command injection (5), SSRF (3), bad user agents (6), scanner paths (5); each with id, name, attack_type, pattern, targets, severity, mitre_id
  - idps/engine.py — Engine class: loads/compiles rules, _normalize (URL-decode up to 2 passes, lowercase, null byte→space), per-request 5ms time budget, never raises, returns hits list
  - gateway/main.py — IDPS integrated before proxy: critical/high → 403 blocked; medium/low → tag and allow with rule_hit/attack_type in event
  - tests/test_idps.py — 32 tests: 3+ malicious + 3+ benign per category incl. encoded evasions; false-positive check; null byte stripping; engine never raises
- Hook: IDPS runs after rate limiting, before proxy; blocks critical/high with 403
- Test result: 48 passed total; ruff clean
- Commit: "Phase 3: IDPS signature engine"

## Notes / blockers
- requirements.txt pins (fastapi<0.116, uvicorn<0.33, scikit-learn<1.7) too strict for Python 3.14; newer versions installed. Will loosen pins when rewriting requirements.txt after dependency survey.
- scikit-learn 1.6.1 fails to build from source on cp314 (no wheel); ML (Phase 5) will degrade gracefully if unavailable.
