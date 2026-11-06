# SentinelGate 🛡️

**Open-source self-defending security gateway** combining IDPS, SIEM, ML anomaly detection, CVSS v3.1 scoring, tamper-evident audit logging, and automated response in a single reverse proxy.

Designed for students, small teams, and SOC learners. Everything runs locally in a lab environment. Attacks and scans only ever run against localhost or hosts in ALLOWED_TARGETS.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-88%25-brightgreen.svg)](tests/)

---

## Features

| Component | Description |
|-----------|-------------|
| **IDPS** | 30+ signature rules detecting SQLi, XSS, path traversal, command injection, SSRF, and scanner activity |
| **SIEM** | Event collection, normalization, SQLite WAL storage, correlation engine with multi-stage attack detection |
| **ML** | Isolation Forest scoring per-IP behavior over 60-second windows (optional, degrades gracefully) |
| **CVSS** | CVSS v3.1 base score calculation for attacks and audit findings |
| **Rate Limiting** | Per-IP token bucket with allowlist, temporary bans, and escalation ladder |
| **Audit** | SHA-256 hash-chained action log for forensic integrity |
| **Security Scanners** | Headers, TLS, ports (nmap), dependencies (pip-audit), code quality (bandit) |
| **Risk Engine** | Weighted scoring: ML 30%, rules 30%, reputation 20%, CVSS 20% |
| **Automated Response** | Throttle, ban, block actions with audit trail; Telegram alerts for high/critical events |
| **Dashboard** | Streamlit-based SOC dashboard: KPIs, alerts, event log, top attackers, blocklist management |
| **Attack Simulator** | Lab-safe traffic generator: brute force, SQLi, XSS, scanning, DoS-lite, mixed |
| **SOC Features** | Cases, MITRE ATT&CK tagging, threat-intel enrichment (AbuseIPDB), playbooks, incident reports |
| **Integrations** | Suricata (network IDS), Wazuh (SIEM/XDR) |

---


---

## Architecture

`mermaid
graph LR
    A[Client] -->|HTTP| B[SentinelGate Gateway :8000]
    B -->|Proxy| C[Target App :5000]
    B -->|Log| D[logs/requests.jsonl]
    D -->|Tail| E[SIEM Collector]
    E -->|Store| F[(SQLite WAL)]
    E -->|Correlate| G[Alerts]
    F -->|Query| H[Dashboard :8501]
    I[Simulator] -.Attack.-> B
    J[Suricata/Wazuh] -.Events.-> E
`

**Request Flow:**

1. **Client → Gateway** — allowlist/ban check → rate limit → IDPS rules
2. **Critical/high severity → 403 blocked** + logged to SIEM
3. **Medium/low → tag and proxy upstream**
4. **Background:** ML scorer, correlation engine, risk calculator, response actions
5. **Dashboard** queries SQLite for real-time visibility

**Risk Formula:** isk = 100 × (0.3×ml + 0.3×rule + 0.2×rep + 0.2×cvss/10)

**Thresholds:** ≥40 alert · ≥60 throttle (15 min) · ≥80 block (24 hr), escalation to permanent

**Event Schema:** 	imestamp, source_ip, method, path, query, status, user_agent, latency_ms, ule_hit, ttack_type, ml_score, cvss_score, isk_score, ction, source

---


---

## Quick Start

**Requirements:** Python 3.12+, 8 GB RAM, Windows/Linux/macOS

`powershell
# 1. Clone and enter directory
git clone https://github.com/yourusername/sentinelgate.git
cd sentinelgate

# 2. Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # Windows PowerShell
# source .venv/bin/activate     # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
copy .env.example .env
# Edit .env: set TARGET_URL, RATE_LIMIT, etc.

# 5. Run the demo
.\demo.ps1   # Starts test app, gateway, collector, simulator, dashboard
`

Set DASHBOARD_PASSWORD in .env before starting the dashboard; login fails closed if unset. The dashboard opens at **http://localhost:8501**.

---


---

## Configuration

Create .env from .env.example and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| TARGET_URL | http://127.0.0.1:5000 | Upstream application to protect |
| RATE_LIMIT | 60 | Requests per minute per IP |
| RATE_BURST | 20 | Burst allowance |
| TRUST_PROXY | alse | Trust X-Forwarded-For header |
| DB_PATH | logs/siem.db | SQLite database path |
| ALLOWED_TARGETS | "" | Comma-separated IPs for scanner/simulator |
| ALLOWLIST | "" | IPs exempt from rate limiting and bans |
| DASHBOARD_PASSWORD | (required) | Dashboard login password |
| TELEGRAM_TOKEN | "" | Telegram bot token (optional) |
| TELEGRAM_CHAT_ID | "" | Telegram chat ID (optional) |
| NVD_API_KEY | "" | NVD API key (optional, for CVE lookups) |
| ABUSEIPDB_KEY | "" | AbuseIPDB API key (optional, for reputation) |
| ENABLE_SURICATA | alse | Tail Suricata eve.json |
| ENABLE_WAZUH | alse | Poll Wazuh API for alerts |

No secrets are hardcoded. .env is git-ignored and never committed.

---


---

## Project Structure

`
sentinelgate/
├── gateway/          # FastAPI reverse proxy + IDPS + rate limiter + logger
├── idps/             # Signature rules (YAML) and matching engine
├── siem/             # Storage, parsers, correlation, collector
├── ml/               # Feature extraction, training, live detector
├── audit/            # CVSS engine, hash chain, scanners
├── response/         # Risk engine, automated actions, Telegram alerts
├── cases/            # SOC case management (SQLite)
├── mitre/            # MITRE ATT&CK mappings
├── intel/            # IP reputation enrichment (AbuseIPDB)
├── playbooks/        # Automated response playbooks + runner
├── reports/          # PDF incident and audit reports
├── dashboard/        # Streamlit app + pages
├── web/              # Landing page (HTML/CSS/JS canvas particles)
├── simulator/        # Attack simulator CLI
├── testapp/          # Deliberately vulnerable Flask app (port 5000)
├── tests/            # Pytest suite
├── docs/             # Architecture, integrations, deployment, security review
├── logs/             # requests.jsonl, siem.db, audit-chain.jsonl, model files
├── .env.example      # Example config (copy to .env)
└── demo.ps1          # Full demo script
`

---


---

## Testing

`powershell
# Run all tests
python -m pytest -q

# With coverage
python -m pytest --cov=. --cov-report=html --cov-report=term

# Specific module
python -m pytest tests/test_idps.py -v

# Linting
python -m ruff check .

# Auto-fix linting
python -m ruff check . --fix

# Security scan (bandit)
python -m bandit -r . -q

# Dependency vulnerability scan
pip-audit
`

**Coverage Target:** 80%+ for gateway, idps, siem, response, and audit modules.

---


---

## Attack Simulator

Generate test traffic (localhost only by default — refuses any target not in localhost/127.0.0.1/ALLOWED_TARGETS):

`powershell
# Brute force login attempts
python -m simulator.run brute_force --count 30

# SQL injection
python -m simulator.run sqli --count 20

# XSS payloads
python -m simulator.run xss --count 20

# Path traversal
python -m simulator.run path_traversal --count 20

# Active scanning (404 burst)
python -m simulator.run scan --count 30

# DoS-lite (max 200 req/s, hard capped)
python -m simulator.run dos_lite --count 100

# Mixed scenario (all attack types)
python -m simulator.run mixed --target http://127.0.0.1:8000 --count 50
`

**Scenarios:** rute_force, sqli, xss, path_traversal, scan, dos_lite, mixed

---


---

## Running Components Separately

`powershell
# Test app (port 5000) — deliberately vulnerable, lab use only
python -m testapp.app

# Gateway reverse proxy (port 8000)
python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000

# SIEM collector (tail mode)
python -m siem.collector --follow

# Streamlit dashboard (port 8501)
streamlit run dashboard\app.py

# Attack simulator
python -m simulator.run mixed --target http://127.0.0.1:8000 --count 50
`

---

## Security Scans

`powershell
# HTTP headers audit
python -c "from audit.scanners.headers import scan_headers; print(scan_headers('http://localhost:8000'))"

# Port scan (requires nmap installed)
python -c "from audit.scanners.ports import scan_ports; print(scan_ports('http://localhost'))"

# Code quality (requires bandit)
python -m bandit -r . -f json

# Dependency vulnerabilities (requires pip-audit)
pip-audit --format json
`

---


---

## Development

`powershell
# Setup development environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run linter
python -m ruff check .

# Format code
python -m ruff format .

# Run security checks
python -m bandit -r . -q
pip-audit
`

---


---

## Responsible Use ⚠️

**This tool is for authorized testing only.**

- Only run the gateway, scanners, and simulator against systems **you own** or have **written permission** to test.
- The test app (	estapp/app.py) is **deliberately vulnerable** for lab use. Never expose it to a network.
- Attacks and scans are **restricted to localhost/127.0.0.1** by default. Use ALLOWED_TARGETS only for systems you control.

Unauthorized testing is illegal. Use responsibly.

---


---

## Documentation

- **[Deployment](docs/deployment.md)** — Local, Docker, and production deployment
- **[Integrations](docs/integrations.md)** — Suricata, Wazuh setup
- **[Security Review](docs/security-review.md)** — Phase 16 review and results
- **[ML Evaluation](docs/ml-evaluation.md)** — Model performance metrics

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 0–7 | ✅ Done | Foundation, gateway, IDPS, SIEM, ML, CVSS, audit, risk engine, response |
| 8 | ✅ Done | SOC features (cases, MITRE mapping, playbooks, threat intel) |
| 9–10 | ✅ Done | Dashboard, simulator |
| 11 | ✅ Done | Suricata and Wazuh integrations |
| 12 | ✅ Done | PDF reports (incident, audit) |
| 13 | ✅ Done | Landing page (HTML/CSS/JS canvas particles) |
| 14 | ✅ Done | Docker Compose, CI, task scripts |
| 15 | ✅ Done | Documentation, contributing and security policies |
| 16 | ✅ Done | Security review (bandit, pip-audit, auth hardening) |

**Future:** Sigma rule import · Redis distributed backend · Multi-tenancy · REST API · Webhook notifications (Slack, PagerDuty)

---


---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repo
2. Create a feature branch (git checkout -b feature/amazing)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing)
5. Open a Pull Request

**Good First Issues:** Check the issue tracker for beginner-friendly tasks.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Credits

- **Suricata** — Open-source network IDS/IPS
- **Wazuh** — Open-source SIEM and XDR platform
- **scikit-learn** — Machine learning library
- **FastAPI**, **Streamlit**, **Flask** — Python web frameworks
- **MITRE ATT&CK** — Threat intelligence framework
- **CVSS** — Common Vulnerability Scoring System
- **CSIC 2010 HTTP Dataset** — Web attack dataset (optional for ML training)

---

## Contact

- **Issues:** [GitHub Issues](https://github.com/yourusername/sentinelgate/issues)
- **Security:** See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

---

**Built with ❤️ for security learners, small teams, and SOC training labs.**

*Make it true.*

