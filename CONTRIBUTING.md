# Contributing to SentinelGate

Thanks for helping improve SentinelGate. This project is a defensive security
tool; changes should keep it safe by default.

## Development Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e ".[dev]"
copy .env.example .env
```

`nmap`, Docker, Redis, Suricata, and Wazuh are optional; features that use them
must degrade gracefully when they are absent.

## Before You Open a Pull Request

```powershell
python -m pytest -q
python -m ruff check .
```

Both must pass. Coverage for `gateway`, `idps`, `siem`, `response`, and `audit`
should stay at or above 80%.

## Code Conventions

- Python 3.12+, type hints, docstrings on public functions.
- Keep modules focused and small; one responsibility per file.
- Use `sqlite3` parameterized queries only; never build SQL from input.
- Never log secrets, tokens, passwords, or full request bodies.
- Never use `eval`, `exec`, or `pickle` on untrusted input, and never build
  shell commands from request data.
- Scanners and the simulator must validate targets against localhost and
  `ALLOWED_TARGETS`.
- New IDPS or correlation rules need both a malicious and a benign test case so
  false positives stay visible.

## Adding Detection Rules

1. Add the rule to `idps/rules.yaml` (or the SIEM correlation YAML) with an
   `id`, `attack_type`, `severity`, and, where relevant, a MITRE ATT&CK id.
2. Add tests to `tests/test_idps.py` or `tests/test_siem.py`.
3. Run the suite and confirm the rule never raises on malformed input.

## Pull Requests

- Keep each pull request to one logical change.
- Describe the motivation and the behavior change; link related issues.
- Include tests for new behavior and note any manual verification you ran.
- Do not include generated secrets, `.env` files, databases, or `logs/`.

## Reporting Security Issues

Do not open a public issue for a vulnerability. Follow `SECURITY.md`.
