"""Code quality scanner using Bandit.

Runs bandit in JSON mode and returns findings.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def scan_code(path: str = ".", timeout: float = 60.0) -> list[dict[str, Any]]:
    """Run bandit on *path* and return security findings.

    Returns a list of finding dicts or an error dict if bandit unavailable.
    """
    findings = []

    try:
        result = subprocess.run(
            ["bandit", "-r", path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return [
            {
                "type": "tool_unavailable",
                "title": "bandit not installed",
                "evidence": "bandit binary not found",
                "remediation": "Install bandit: pip install bandit",
            }
        ]
    except subprocess.TimeoutExpired:
        return [
            {
                "type": "scan_timeout",
                "title": "bandit timed out",
                "evidence": f"Scan exceeded {timeout}s",
                "remediation": "Reduce scan scope or increase timeout",
            }
        ]

    # Bandit returns exit code 1 if issues found; parse output anyway
    if not result.stdout:
        return [
            {
                "type": "scan_error",
                "title": "bandit failed",
                "evidence": result.stderr[:200],
                "remediation": "Check bandit installation",
            }
        ]

    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [
            {
                "type": "parse_error",
                "title": "Could not parse bandit output",
                "evidence": result.stdout[:200],
                "remediation": "Check bandit version",
            }
        ]

    # Extract results
    results = data.get("results", [])
    for issue in results:
        test_id = issue.get("test_id", "")
        issue_text = issue.get("issue_text", "")
        filename = issue.get("filename", "")
        line_number = issue.get("line_number", 0)
        severity = issue.get("issue_severity", "low").lower()
        confidence = issue.get("issue_confidence", "").lower()

        # Only report medium+ severity or high confidence
        if severity in ("medium", "high") or confidence == "high":
            findings.append(
                {
                    "type": "code_quality",
                    "title": f"{test_id}: {issue_text[:50]}",
                    "evidence": f"{filename}:{line_number} - {issue_text}",
                    "remediation": "Review and fix the code quality issue",
                }
            )

    return findings
