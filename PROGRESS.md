# SentinelGate â€” Progress Log

## Environment (decisions recorded)

- OS: Windows 11; shell: PowerShell 5.1 (`powershell.exe`; `pwsh` not on PATH)
- Python: 3.14.7; venv at `.venv`; project targets 3.12+
- git 2.55; Docker Desktop available (optional)
- nmap: NOT installed â€” the port scanner returns a `tool_unavailable` finding
- ML stack: installed and working on cp314 (scikit-learn 1.9.1, numpy 2.5.4,
  joblib 1.6.0). Dependency bounds were relaxed so a clean install resolves
  current wheels instead of the old `<1.7` pins that had no cp314 wheel.

## Status: all 16 phases complete

| Phase | Result | Key artifacts |
| ----- | ------ | ------------- |
| 0 Foundation | Done | `CLAUDE.md`, `pyproject.toml`, `siem/schema.py`, fixtures |
| 1 Gateway + test app | Done | `gateway/main.py`, `testapp/app.py` |
| 2 Rate limiting | Done | `gateway/ratelimit.py` (token bucket, bans, allowlist) |
| 3 IDPS | Done | `idps/rules.yaml` (34 rules), `idps/engine.py` |
| 4 SIEM | Done | `siem/storage.py`, `parsers.py`, `correlation.py`, `collector.py` |
| 5 ML detection | Done | `ml/features.py`, `train.py`, `live_detector.py`, `evaluate.py` |
| 6 CVSS + audit | Done | `audit/cvss_engine.py`, `hashchain.py`, 5 scanners |
| 7 Risk + response | Done | `response/risk.py`, `actions.py`, `telegram.py` |
| 8 SOC | Done | `cases/manager.py`, `mitre/mapper.py`, `intel/enrich.py`, playbooks |
| 9 Dashboard | Done | `dashboard/app.py`, `dashboard/data.py` |
| 10 Simulator | Done | `simulator/run.py` (7 scenarios), `demo.ps1` |
| 11 Integrations | Done | `siem/suricata.py`, `siem/wazuh.py`, `docs/integrations.md` |
| 12 PDF reports | Done | `reports/incident.py`, `reports/audit_report.py` |
| 13 Landing page | Done | `web/index.html`, `app.js`, `particles.js`, `styles.css`, `nginx.conf` |
| 14 Docker/CI | Done | `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`, `tasks.ps1` |
| 15 Documentation | Done | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, deployment docs |
| 16 Security review | Done | `docs/security-review.md`, auth/TLS hardening |

## Verification (last run)

- `python -m pytest -q` â€” **184 passed, 0 skipped**
- Coverage for required packages â€” **88% total**
  (gateway 87%, idps 83%, siem 84%, response 97%, audit 93%)
- `python -m ruff check .` â€” **0 findings**
- `python -m bandit -r <packages> -q` â€” **0 open findings**
  (14 justified `# nosec` markers; see the security review)
- `python -m pip_audit` â€” **no known vulnerabilities**
- Landing page: anchors and relative links validated; skip link, focus styles,
  mobile nav with `aria-expanded`, and `prefers-reduced-motion` handling present
- Docker Compose web service serves the repo at port 8080 and redirects to `/web/`
- End-to-end run (headless, 2026-11-03): test app 200, gateway 200, collector
  ingested 64 events, simulator sent 60 mixed requests (2 blocked by IDPS, 34
  throttled), correlation raised a critical multi-stage alert, audit chain held
  2 verified block entries, dashboard health 200, both PDF reports generated,
  and all landing-page assets/docs returned 200

## Fixes made in the final pass

- **Lint**: removed 260 ruff findings (line length, unused imports, `zip(strict=)`,
  magic numbers â†’ named constants, lazy imports, subprocess handling).
- **Coverage**: added `tests/test_scanners.py`, `tests/test_telegram.py`, and
  Wazuh/collector/storage cases in the integration and SIEM suites.
- **Security**: dashboard login fails closed without `DASHBOARD_PASSWORD` and
  uses `hmac.compare_digest`; Wazuh TLS verification defaults on; scanner
  binaries resolved via `shutil.which`; proxy `assert` replaced with a runtime
  check; ML test gating now uses installed packages rather than a bare import.
- **Docs**: README roadmap/tree, CHANGELOG, deployment notes, and this log now
  match the code. Added `SECURITY.md`, `CONTRIBUTING.md`, `docs/security-review.md`.

## Known limitations

- `nmap` is not installed here, so port scanning reports `tool_unavailable`.
- The gateway does not terminate TLS itself; deploy behind a TLS proxy.
- Rate limiting is in-process; Redis-backed distribution remains roadmap work.
- Docker Compose was written and CI builds it, but the full container stack
  was not started in this environment (services were run natively).
- The demo's local traffic is allowlisted, so blocks are recorded in the audit
  chain but no IP is banned; bans apply to non-local sources.

## Future work (not part of the 16 phases)

- Sigma rule import
- Redis distributed rate limiting / storage
- REST API and webhook notifications (Slack, PagerDuty)
- Architecture and rules guides (`docs/architecture.md`, `docs/rules-guide.md`)

## README Rewrite — DONE
- Files: README.md (rewritten, 383 lines)
- Clean emojis (no mojibake), no null bytes, well-formed markdown
- Sections: Badges, Features table, Architecture (Mermaid), Quick Start, Configuration table, Project Structure, Testing, Attack Simulator, Running Components, Security Scans, Development, Responsible Use, Documentation links, Roadmap table, Contributing, License, Credits, Contact
- Test result: N/A (documentation only)
- Ruff: N/A
- Commit: "Rewrite README.md — proper documentation with all sections"

