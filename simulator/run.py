"""Attack simulator for SentinelGate lab testing.

Usage: python -m simulator.run [scenario]

Scenarios: brute_force, sqli, xss, path_traversal, scan, dos_lite, mixed

ONLY runs against localhost/127.0.0.1 or targets in ALLOWED_TARGETS.
"""

from __future__ import annotations

import os
import random
import sys
import time
from argparse import ArgumentParser
from urllib.parse import urlparse

import requests

ALLOWED_TARGETS = os.getenv("ALLOWED_TARGETS", "").split(",")
ALLOWED_TARGETS = [t.strip() for t in ALLOWED_TARGETS if t.strip()]

WARNING = """
╔════════════════════════════════════════════════════════════════╗
║  WARNING: ATTACK SIMULATOR - LAB USE ONLY                      ║
║  This tool generates malicious traffic for testing purposes.   ║
║  Only run against systems you own or have permission to test.  ║
╚════════════════════════════════════════════════════════════════╝
"""


def validate_target(url: str) -> bool:
    """Return True if target is localhost or in ALLOWED_TARGETS."""
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    if hostname in ALLOWED_TARGETS:
        return True
    return False


def run_scenario(scenario: str, target: str, count: int = 20) -> dict:
    """Run a scenario and return summary stats."""
    if not validate_target(target):
        print(f"ERROR: Target {target} not allowed. Must be localhost or in ALLOWED_TARGETS.", file=sys.stderr)
        return {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}

    print(WARNING)
    print(f"[*] Running scenario: {scenario}")
    print(f"[*] Target: {target}")
    print(f"[*] Count: {count}\n")

    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}

    if scenario == "brute_force":
        stats = _brute_force(target, count)
    elif scenario == "sqli":
        stats = _sqli(target, count)
    elif scenario == "xss":
        stats = _xss(target, count)
    elif scenario == "path_traversal":
        stats = _path_traversal(target, count)
    elif scenario == "scan":
        stats = _scan(target, count)
    elif scenario == "dos_lite":
        stats = _dos_lite(target, count)
    elif scenario == "mixed":
        stats = _mixed(target, count)
    else:
        print(f"ERROR: Unknown scenario '{scenario}'", file=sys.stderr)

    print(f"\n[✓] Summary:")
    print(f"    Sent:      {stats['sent']}")
    print(f"    Allowed:   {stats['allowed']}")
    print(f"    Throttled: {stats['throttled']}")
    print(f"    Blocked:   {stats['blocked']}")
    print(f"    Errors:    {stats['errors']}")

    return stats


def _brute_force(target: str, count: int) -> dict:
    """Simulate brute force login attempts."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    for i in range(count):
        try:
            resp = requests.post(
                f"{target}/login",
                data={"username": f"admin{i}", "password": "wrong"},
                timeout=2.0,
            )
            stats["sent"] += 1
            if resp.status_code == 403:
                stats["blocked"] += 1
            elif resp.status_code == 429:
                stats["throttled"] += 1
            else:
                stats["allowed"] += 1
        except requests.RequestException:
            stats["errors"] += 1
        time.sleep(0.1)
    return stats


def _sqli(target: str, count: int) -> dict:
    """Simulate SQL injection attempts."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND 1=1--",
        "admin'--",
        "1' OR '1'='1' /*",
        "1; SELECT * FROM users",
    ]
    for i in range(count):
        payload = random.choice(payloads)
        try:
            resp = requests.get(f"{target}/search", params={"q": payload}, timeout=2.0)
            stats["sent"] += 1
            if resp.status_code == 403:
                stats["blocked"] += 1
            elif resp.status_code == 429:
                stats["throttled"] += 1
            else:
                stats["allowed"] += 1
        except requests.RequestException:
            stats["errors"] += 1
        time.sleep(0.1)
    return stats


def _xss(target: str, count: int) -> dict:
    """Simulate XSS attempts."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
    ]
    for i in range(count):
        payload = random.choice(payloads)
        try:
            resp = requests.get(f"{target}/search", params={"q": payload}, timeout=2.0)
            stats["sent"] += 1
            if resp.status_code == 403:
                stats["blocked"] += 1
            elif resp.status_code == 429:
                stats["throttled"] += 1
            else:
                stats["allowed"] += 1
        except requests.RequestException:
            stats["errors"] += 1
        time.sleep(0.1)
    return stats


def _path_traversal(target: str, count: int) -> dict:
    """Simulate path traversal attempts."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ]
    for i in range(count):
        payload = random.choice(payloads)
        try:
            resp = requests.get(f"{target}/file", params={"name": payload}, timeout=2.0)
            stats["sent"] += 1
            if resp.status_code == 403:
                stats["blocked"] += 1
            elif resp.status_code == 429:
                stats["throttled"] += 1
            else:
                stats["allowed"] += 1
        except requests.RequestException:
            stats["errors"] += 1
        time.sleep(0.1)
    return stats


def _scan(target: str, count: int) -> dict:
    """Simulate active scanning (404 burst)."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    paths = [
        "/.env", "/.git/config", "/wp-admin", "/admin", "/phpmyadmin",
        "/config.php", "/.svn", "/backup.sql", "/db.sql", "/.DS_Store",
    ]
    for i in range(count):
        path = random.choice(paths) + str(i)
        try:
            resp = requests.get(f"{target}{path}", timeout=2.0)
            stats["sent"] += 1
            if resp.status_code == 403:
                stats["blocked"] += 1
            elif resp.status_code == 429:
                stats["throttled"] += 1
            else:
                stats["allowed"] += 1
        except requests.RequestException:
            stats["errors"] += 1
        time.sleep(0.05)
    return stats


def _dos_lite(target: str, count: int) -> dict:
    """Simulate light DoS (rate limit test, max 200 req/s)."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    count = min(count, 200)  # Hard cap
    print(f"[!] DoS lite capped at {count} requests")
    for i in range(count):
        try:
            resp = requests.get(f"{target}/", timeout=0.5)
            stats["sent"] += 1
            if resp.status_code == 403:
                stats["blocked"] += 1
            elif resp.status_code == 429:
                stats["throttled"] += 1
            else:
                stats["allowed"] += 1
        except requests.RequestException:
            stats["errors"] += 1
        time.sleep(0.005)  # 200 req/s
    return stats


def _mixed(target: str, count: int) -> dict:
    """Run a mixed scenario with all attack types."""
    stats = {"sent": 0, "blocked": 0, "throttled": 0, "allowed": 0, "errors": 0}
    scenarios = [_brute_force, _sqli, _xss, _path_traversal, _scan]
    per_scenario = count // len(scenarios)

    for scenario in scenarios:
        result = scenario(target, per_scenario)
        for key in stats:
            stats[key] += result[key]

    return stats


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="SentinelGate attack simulator (LAB USE ONLY)")
    parser.add_argument(
        "scenario",
        choices=["brute_force", "sqli", "xss", "path_traversal", "scan", "dos_lite", "mixed"],
        help="Attack scenario to run",
    )
    parser.add_argument("--target", default="http://127.0.0.1:8000", help="Target URL (default: localhost:8000)")
    parser.add_argument("--count", type=int, default=20, help="Number of requests (default: 20)")
    args = parser.parse_args(argv)

    run_scenario(args.scenario, args.target, args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
