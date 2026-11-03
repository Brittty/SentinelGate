# Security Policy

SentinelGate is a security tool, so vulnerabilities in it matter. Please report
them privately rather than opening a public issue.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Use GitHub's **private vulnerability reporting** (Security tab → "Report a
vulnerability") on the repository. Include:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal request or script.
- The version/commit and Python version you tested.

You can expect an acknowledgement within 7 days. Please do not include real
customer data, credentials, or live third-party targets in a report.

## Scope

In scope:

- The gateway proxy, IDPS engine, rate limiter, and audit hash chain.
- SIEM storage, parsers, correlation, and the Suricata/Wazuh integrations.
- Dashboard authentication and the report generators.
- The landing page under `web/`.

Out of scope:

- Findings that require running the attack simulator or scanners against
  systems you do not own.
- Denial of service from intentionally unbounded local test traffic.
- Missing hardening that is already documented as optional (TLS termination,
  Redis, external WAF).

## Security Design Notes

- No secrets are committed; configuration comes from `.env` (git-ignored).
- All SQL uses parameterized queries against SQLite in WAL mode.
- ML models are loaded with `joblib` only from local `models/` files whose
  SHA-256 is verified first.
- No `eval`/`exec`/`pickle` on untrusted input, and no shell commands are built
  from request data.
- Scanners and the simulator refuse targets outside localhost/`ALLOWED_TARGETS`.
- Dashboard access requires a password (`DASHBOARD_PASSWORD`); change the
  default before exposing it beyond localhost.

## Responsible Use

Attack simulation, scanning, and blocking are for systems you own or have
written permission to test. See the notice in `README.md`.
