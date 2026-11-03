"""TLS/SSL scanner.

Checks protocol version, certificate expiry, and weak cipher detection.
"""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse


def scan_tls(target_url: str, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Scan *target_url* for TLS/SSL issues.

    Returns a list of finding dicts: {type, title, evidence, remediation}.
    """
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return [
            {
                "type": "no_tls",
                "title": "Target not using HTTPS",
                "evidence": f"Scheme: {parsed.scheme}",
                "remediation": "Use HTTPS for all traffic",
            }
        ]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Check certificate expiry
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=UTC)
                        now = datetime.now(tz=UTC)
                        if expiry < now:
                            findings.append(
                                {
                                    "type": "expired_cert",
                                    "title": "Expired SSL/TLS certificate",
                                    "evidence": f"Expired on {not_after}",
                                    "remediation": "Renew the certificate immediately",
                                }
                            )

                # Check protocol version
                if version and version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(
                        {
                            "type": "weak_tls",
                            "title": "Weak TLS protocol version",
                            "evidence": f"Protocol: {version}",
                            "remediation": "Upgrade to TLS 1.2 or 1.3",
                        }
                    )

                # Check cipher
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ["DES", "RC4", "MD5", "NULL", "EXPORT", "anon"]
                    if any(w in cipher_name.upper() for w in weak_ciphers):
                        findings.append(
                            {
                                "type": "weak_cipher",
                                "title": "Weak cipher suite detected",
                                "evidence": f"Cipher: {cipher_name}",
                                "remediation": (
                                    "Disable weak ciphers; use AEAD ciphers "
                                    "(AES-GCM, ChaCha20)"
                                ),
                            }
                        )

    except (OSError, ssl.SSLError, ValueError) as e:
        findings.append(
            {
                "type": "tls_error",
                "title": "TLS handshake failed",
                "evidence": str(e),
                "remediation": "Check server TLS configuration",
            }
        )

    return findings
