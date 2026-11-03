"""Port scanner using subprocess nmap.

Only scans localhost or targets in ALLOWED_TARGETS.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from typing import Any
from urllib.parse import urlparse

ALLOWED_TARGETS = os.getenv("ALLOWED_TARGETS", "").split(",")
ALLOWED_TARGETS = [t.strip() for t in ALLOWED_TARGETS if t.strip()]

# nmap splits a port line into "22/tcp open ssh"; index 2 holds the service.
SERVICE_INDEX = 2
MIN_SERVICE_FIELDS = SERVICE_INDEX + 1


def scan_ports(target_url: str, timeout: float = 30.0) -> list[dict[str, Any]]:
    """Scan open ports on *target_url* using nmap.

    Refuses to scan targets not in localhost/127.0.0.1/ALLOWED_TARGETS.
    Returns a list of finding dicts or an error dict if nmap not installed.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or parsed.netloc

    # Security: only scan allowed targets
    if hostname not in ("localhost", "127.0.0.1") and hostname not in ALLOWED_TARGETS:
        return [
            {
                "type": "refused",
                "title": "Port scan refused",
                "evidence": f"Target {hostname} not in allowed list",
                "remediation": "Add target to ALLOWED_TARGETS env var",
            }
        ]

    # Check if nmap is available
    nmap = shutil.which("nmap")
    if nmap is None:
        return [
            {
                "type": "tool_unavailable",
                "title": "nmap not installed",
                "evidence": "nmap binary not found on PATH",
                "remediation": "Install nmap to enable port scanning",
            }
        ]

    try:
        subprocess.run(  # noqa: S603  # nosec B603
            [nmap, "--version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [
            {
                "type": "tool_unavailable",
                "title": "nmap not installed",
                "evidence": "nmap binary not found on PATH",
                "remediation": "Install nmap to enable port scanning",
            }
        ]

    # Run nmap
    findings = []
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [nmap, "-p", "1-1024", "--open", hostname],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = result.stdout

        # Parse output for open ports
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port_info = parts[0]  # e.g., "22/tcp"
                port_num = port_info.split("/")[0]
                service = parts[SERVICE_INDEX] if len(parts) >= MIN_SERVICE_FIELDS else "unknown"

                # Flag unexpected ports (anything except 80, 443, 5000)
                if port_num not in ("80", "443", "5000"):
                    findings.append(
                        {
                            "type": "open_port",
                            "title": f"Unexpected open port {port_num}",
                            "evidence": f"Port {port_num}/tcp open ({service})",
                            "remediation": f"Close port {port_num} or justify its exposure",
                        }
                    )

    except subprocess.TimeoutExpired:
        findings.append(
            {
                "type": "scan_timeout",
                "title": "Port scan timed out",
                "evidence": f"Scan exceeded {timeout}s",
                "remediation": "Check network or reduce scan scope",
            }
        )
    except Exception as e:
        findings.append(
            {
                "type": "scan_error",
                "title": "Port scan failed",
                "evidence": str(e),
                "remediation": "Check nmap installation and permissions",
            }
        )

    return findings
