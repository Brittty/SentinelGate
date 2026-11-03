# Security Review (Phase 16)

Date: 2026-11-03
Scope: all first-party Python packages (`gateway`, `idps`, `siem`, `ml`, `audit`,
`response`, `cases`, `mitre`, `intel`, `playbooks`, `reports`, `simulator`,
`testapp`, `dashboard`) plus the static site in `web/`.

## Method

| Check | Command | Result |
| ----- | ------- | ------ |
| Lint / bug patterns | `python -m ruff check .` | 0 findings |
| SAST | `python -m bandit -r gateway idps siem response audit cases mitre intel playbooks ml reports simulator testapp dashboard` | 0 open findings |
| Dependencies | `python -m pip_audit` | No known vulnerabilities |
| Tests | `python -m pytest -q` | 184 passed, 0 skipped |
| Coverage | `pytest --cov=gateway --cov=idps --cov=siem --cov=response --cov=audit` | 88% total; every required package ≥ 80% |
| Secret scan | `grep` for assigned tokens/passwords in first-party code | No secrets committed |

Bandit suppressions are limited to calls that take locally resolved binaries and
fixed arguments (`subprocess` in the scanners), lab-only pseudorandom payload
selection in the simulator, synthetic training data, and the parameterized
dynamic `UPDATE` in `cases/manager.py` whose column fragments are fixed literals.

## Fixes Applied

- **Dashboard authentication fails closed.** `DASHBOARD_PASSWORD` has no default
  and the login page refuses access when it is unset; comparisons use
  `hmac.compare_digest`. `.env` is loaded by the dashboard process.
- **Wazuh TLS verification is on by default.** `WAZUH_VERIFY_TLS=false` is an
  explicit opt-out for self-signed lab certificates.
- **Scanner binaries are resolved with `shutil.which`** before execution, so a
  partial path can no longer be used; arguments remain fixed and never include
  request data.
- **Removed `assert` from the proxy hot path** (`gateway/main.py`), replacing it
  with an explicit runtime check that survives `python -O`.
- **CLI failures degrade cleanly** — missing `nmap`, `bandit`, or `pip-audit`
  return a `tool_unavailable` finding instead of raising.

## Verified Design Properties

- Reverse-proxy upstream is a fixed `TARGET_URL`; user input cannot change it.
- IDPS normalizes (URL-decode, lower-case, null-byte strip) before matching and
  never raises on malformed input.
- All SQL uses bound parameters; SQLite runs in WAL mode with per-IP/time indexes.
- ML models load only from local `models/` files and require a matching SHA-256.
- No `eval`, `exec`, `pickle`, or shell command construction from request data.
- Scanners and the simulator reject targets outside localhost/`ALLOWED_TARGETS`.
- Request logs strip control characters and newlines and cap field length.
- Every response action appends to the SHA-256 audit chain, which verifies
  tamper-evident on read.
- The landing page is static: no cookies, storage, analytics, or third-party
  scripts; it honors `prefers-reduced-motion` and exposes a skip link.

## Residual Risks

| Risk | Mitigation |
| ---- | ---------- |
| Gateway itself terminates no TLS | Run behind a TLS-terminating proxy; `TRUST_PROXY` is off by default |
| In-memory rate limiter is per-process | Single-node default; Redis backend remains roadmap work |
| SQLite is a single-node store | Adequate for the documented lab/small-team scope |
| Telegram/NVD/AbuseIPDB keys live in `.env` | `.env` is git-ignored; never log secrets |
| Optional integrations parse external logs | Parsers tolerate malformed input and extract only known fields |

## Re-running

```powershell
python -m ruff check .
python -m bandit -r <packages> -q
python -m pip_audit
python -m pytest -q --cov=gateway --cov=idps --cov=siem --cov=response --cov=audit
```
