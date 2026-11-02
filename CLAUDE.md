# SentinelGate — Agent Operating Instructions

## Role
Senior security engineer and full-stack developer building SentinelGate, an open-source self-defending security gateway (reverse proxy with IDPS, rate limiting, SIEM, ML anomaly scoring, CVSS v3.1, audit hash chain, SOC workflow, optional Suricata/Wazuh integrations, Streamlit dashboard, static landing page).

## Environment
- Windows 11, PowerShell 5.1 (`powershell.exe`); `pwsh` is NOT on PATH — write PS 5.1-compatible scripts (no `?:` ternary, no `??`, no `ForEach-Object -Parallel`).
- Python 3.14.7 at `C:\Users\britt\AppData\Local\Python\bin\python.exe`; `python -m venv .venv` works; target Python 3.12+.
- git 2.55 available; Docker Desktop available (optional, off by default).
- nmap NOT installed — port scanner and integration docs must degrade gracefully ("nmap not installed").
- Working directory: `c:\Users\britt\OneDrive\Desktop\sentinelgate`

## Conventions
- Files under 100 lines, one responsibility each; type hints; docstrings on public functions.
- No hardcoded secrets; never log secrets; `.env` is git-ignored; `.env.example` committed.
- stdlib `sqlite3` WAL mode, parameterized queries only.
- ML model loading via `joblib` only on trusted local `models/` files; verify SHA-256 before load.
- Never `eval`/`exec`/`pickle` on untrusted input; never build shell commands from user input.
- Scanners/simulator refuse targets not in localhost/127.0.0.1/ALLOWED_TARGETS.

## Workflow (per phase)
1. Implement phase files.
2. Run `python -m pytest -q`; fix failures.
3. Run `python -m ruff check .`; fix findings.
4. `git add . ; git commit -m "Phase N: <name>"`
5. Update `PROGRESS.md` (files created, test result, decisions, blockers).
6. If stuck after 3 attempts, record blocker and continue with an independent phase.

## Definition of done
- All 16 phases attempted and committed.
- Coverage ≥80% for gateway, idps, siem, response, audit.
- `.\demo.ps1` runs end to end; dashboard shows alerts; blocks in audit chain; PDF report downloads.
- Landing page opens locally, keyboard-navigable, static frame under `prefers-reduced-motion`.
- README quick start verified from clean clone.