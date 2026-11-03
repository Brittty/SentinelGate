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
- **Demo Script**: PowerShell `demo.ps1` orchestrating test app, gateway, collector, simulator, dashboard

### Security
- All external input sanitized (newlines, control chars removed, length-capped)
- Parameterized SQL queries only
- No eval/exec/pickle on untrusted input
- Rate limiting with allowlist protection
- Audit hash chain for forensic integrity
- Scanners and simulator refuse non-local targets

### Testing
- 80%+ coverage for gateway, IDPS, SIEM, response, audit
- 60+ tests across 6 test modules
- CI-ready (pytest + ruff + bandit + pip-audit)

### Documentation
- Comprehensive README with quick start, architecture diagram, API reference
- MIT license
- .env.example with all config options

## [Unreleased]

### Planned
- **Phase 8**: SOC features (cases, MITRE ATT&CK mapping, playbooks, threat intel enrichment)
- **Phase 11**: Suricata and Wazuh integrations
- **Phase 12**: PDF reports (incident, audit)
- **Phase 13**: Landing page with particle animation
- **Phase 14**: Docker compose, GitHub Actions CI, Redis backend
- **Phase 15**: Complete documentation (architecture, deployment, rules guide)
- **Phase 16**: Security review and hardening

[0.1.0]: https://github.com/yourusername/sentinelgate/releases/tag/v0.1.0
