# Changelog

All notable changes to SentinelGate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-03

### Added
- **Foundation (Phase 0)**: Shared Event schema (Pydantic v2), test fixtures, project structure
- **Gateway & Test App (Phase 1)**: FastAPI reverse proxy with httpx client; deliberately vulnerable Flask test app
- **Rate Limiting (Phase 2)**: Per-IP token bucket with allowlist, temporary bans, LRU eviction
- **IDPS (Phase 3)**: 34 signature rules (SQLi, XSS, path traversal, command injection, SSRF, scanners); critical/high auto-blocked
- **SIEM (Phase 4)**: SQLite WAL storage, Linux auth.log + nginx combined log parsers, correlation engine (brute force, scan, injection burst, multi-stage), collector with resume
- **ML Detection (Phase 5)**: IsolationForest anomaly scoring, 10 per-IP features, graceful degradation when scikit-learn unavailable
- **CVSS & Audit (Phase 6)**: CVSS v3.1 scoring engine with vectors.yaml, tamper-evident SHA-256 hash chain, security scanners (headers, TLS, ports, deps, code)
- **Risk Engine (Phase 7)**: Weighted risk formula (ML 30%, rules 30%, reputation 20%, CVSS 20%), thresholds (40/60/80), escalation ladder (throttle → temp ban → permanent block), Telegram alerts
- **Dashboard (Phase 9)**: Streamlit UI with KPIs, alerts, events, top attackers, blocklist; password auth; dark theme
- **Simulator (Phase 10)**: Attack traffic generator with 7 scenarios (brute force, SQLi, XSS, path traversal, scan, DoS-lite, mixed); localhost-only by default
- **SOC Features (Phase 8)**: Case management with timeline, MITRE ATT&CK mapping, AbuseIPDB enrichment, YAML playbooks
- **Integrations (Phase 11)**: Suricata `eve.json` tailing and Wazuh API polling, both resuming from stored offsets
- **PDF Reports (Phase 12)**: Incident and audit report generation with ReportLab
- **Landing Page (Phase 13)**: Static `web/` site with accessible navigation, reduced-motion support, and copy-to-clipboard quick start
- **Deployment (Phase 14)**: Multi-stage Dockerfile, six-service Compose stack, GitHub Actions CI, `tasks.ps1`
- **Demo Script**: PowerShell `demo.ps1` orchestrating test app, gateway, collector, simulator, dashboard

### Security
- All external input sanitized (newlines, control chars removed, length-capped)
- Parameterized SQL queries only
- No eval/exec/pickle on untrusted input
- Rate limiting with allowlist protection
- Audit hash chain for forensic integrity
- Scanners and simulator refuse non-local targets

### Testing
- 88% coverage across gateway, IDPS, SIEM, response, audit (each ≥ 80%)
- 184 tests across 16 test modules
- CI-ready (pytest + ruff + bandit + pip-audit)

### Documentation
- Comprehensive README with quick start, architecture diagram, API reference
- MIT license
- .env.example with all config options

### Security review (Phase 16)
- Dashboard login fails closed without `DASHBOARD_PASSWORD` and uses constant-time comparison
- Wazuh TLS verification enabled by default (`WAZUH_VERIFY_TLS=false` to opt out)
- Scanner subprocesses resolve binaries with `shutil.which`; no assert-based checks
- `ruff`, `bandit`, and `pip-audit` clean; details in `docs/security-review.md`
- Dependency bounds relaxed so Python 3.14 resolves current wheels

## [Unreleased]

### Planned
- Sigma rule import
- Redis distributed backend
- REST API for programmatic access
- Webhook notifications (Slack, PagerDuty)

[0.1.0]: https://github.com/yourusername/sentinelgate/releases/tag/v0.1.0
