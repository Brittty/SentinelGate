"""Security headers scanner.

Checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, and secure cookie flags.
"""

from __future__ import annotations

import requests
from typing import Any


def scan_headers(target_url: str, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Scan *target_url* for missing or weak security headers.

    Returns a list of finding dicts: {type, title, evidence, remediation}.
    """
    findings = []

    try:
        resp = requests.get(target_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return [
            {
                "type": "connection_error",
                "title": "Could not connect to target",
                "evidence": str(e),
                "remediation": "Ensure target is reachable",
            }
        ]

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # HSTS
    if "strict-transport-security" not in headers:
        findings.append(
            {
                "type": "missing_hsts",
                "title": "Missing HSTS header",
                "evidence": "No Strict-Transport-Security header found",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
            }
        )

    # CSP
    if "content-security-policy" not in headers:
        findings.append(
            {
                "type": "missing_csp",
                "title": "Missing Content-Security-Policy",
                "evidence": "No CSP header found",
                "remediation": "Add a strict Content-Security-Policy header",
            }
        )

    # X-Frame-Options
    if "x-frame-options" not in headers:
        findings.append(
            {
                "type": "missing_x_frame",
                "title": "Missing X-Frame-Options",
                "evidence": "No X-Frame-Options header (clickjacking risk)",
                "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
            }
        )

    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append(
            {
                "type": "missing_x_content_type",
                "title": "Missing X-Content-Type-Options",
                "evidence": "No X-Content-Type-Options header",
                "remediation": "Add 'X-Content-Type-Options: nosniff'",
            }
        )

    # Referrer-Policy
    if "referrer-policy" not in headers:
        findings.append(
            {
                "type": "missing_referrer_policy",
                "title": "Missing Referrer-Policy",
                "evidence": "No Referrer-Policy header",
                "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter",
            }
        )

    # Cookie flags (check Set-Cookie headers)
    set_cookies = resp.headers.get_list("Set-Cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies:
        raw = resp.headers.get("Set-Cookie", "")
        if raw:
            set_cookies = [raw]

    for cookie in set_cookies:
        cookie_lower = cookie.lower()
        if "secure" not in cookie_lower:
            findings.append(
                {
                    "type": "insecure_cookie",
                    "title": "Cookie without Secure flag",
                    "evidence": f"Cookie: {cookie[:50]}...",
                    "remediation": "Set Secure flag on all cookies served over HTTPS",
                }
            )
        if "httponly" not in cookie_lower:
            findings.append(
                {
                    "type": "insecure_cookie",
                    "title": "Cookie without HttpOnly flag",
                    "evidence": f"Cookie: {cookie[:50]}...",
                    "remediation": "Set HttpOnly flag to protect against XSS",
                }
            )

    return findings
