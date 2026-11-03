"""Dependency vulnerability scanner using pip-audit.

Runs pip-audit in JSON mode and returns findings.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from typing import Any


def scan_dependencies(timeout: float = 60.0) -> list[dict[str, Any]]:
    """Run pip-audit and return vulnerability findings.

    Returns a list of finding dicts or an error dict if pip-audit unavailable.
    """
    findings = []
    pip_audit = shutil.which("pip-audit")
    if pip_audit is None:
        return [
            {
                "type": "tool_unavailable",
                "title": "pip-audit not installed",
                "evidence": "pip-audit binary not found",
                "remediation": "Install pip-audit: pip install pip-audit",
            }
        ]

    try:
        # Arguments are fixed flags; nothing is shell-expanded.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [pip_audit, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return [
            {
                "type": "tool_unavailable",
                "title": "pip-audit not installed",
                "evidence": "pip-audit binary not found",
                "remediation": "Install pip-audit: pip install pip-audit",
            }
        ]
    except subprocess.TimeoutExpired:
        return [
            {
                "type": "scan_timeout",
                "title": "pip-audit timed out",
                "evidence": f"Scan exceeded {timeout}s",
                "remediation": "Check network or reduce scan scope",
            }
        ]

    if result.returncode != 0 and not result.stdout:
        return [
            {
                "type": "scan_error",
                "title": "pip-audit failed",
                "evidence": result.stderr[:200],
                "remediation": "Check pip-audit installation",
            }
        ]

    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [
            {
                "type": "parse_error",
                "title": "Could not parse pip-audit output",
                "evidence": result.stdout[:200],
                "remediation": "Check pip-audit version",
            }
        ]

    # Extract vulnerabilities
    dependencies = data.get("dependencies", [])
    for dep in dependencies:
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        vulns = dep.get("vulns", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            description = vuln.get("description", "No description")
            fixed_versions = vuln.get("fix_versions", [])

            findings.append(
                {
                    "type": "vulnerable_dependency",
                    "title": f"{name} {version} - {vuln_id}",
                    "evidence": description[:200],
                    "remediation": (
                        f"Upgrade to {', '.join(fixed_versions)}"
                        if fixed_versions
                        else "No fix available"
                    ),
                }
            )

    return findings
