"""Tests for PDF report generation."""

from __future__ import annotations

import os
import tempfile

import pytest

try:
    from reports.audit_report import calculate_audit_score, generate_audit_report
    from reports.incident import generate_incident_report

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


@pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="reportlab not available")
def test_audit_score_calculation():
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
    ]
    score = calculate_audit_score(findings)
    assert score == 100 - 20 - 10 - 5 - 2
    assert score == 63


@pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="reportlab not available")
def test_audit_score_floor():
    findings = [{"severity": "critical"} for _ in range(10)]
    score = calculate_audit_score(findings)
    assert score == 0.0


@pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="reportlab not available")
def test_generate_audit_report():
    findings = [
        {
            "type": "missing_hsts",
            "title": "Missing HSTS header",
            "severity": "medium",
            "cvss_score": 4.3,
            "evidence": "No Strict-Transport-Security header found",
            "remediation": "Add HSTS header",
        },
        {
            "type": "missing_csp",
            "title": "Missing CSP",
            "severity": "medium",
            "cvss_score": 5.3,
            "evidence": "No Content-Security-Policy found",
            "remediation": "Add CSP header",
        },
    ]
    metadata = {
        "target": "http://localhost:8000",
        "scan_date": "2026-11-03",
        "scanners_used": ["headers", "tls"],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "audit.pdf")
        result = generate_audit_report(findings, metadata, output_path)
        assert result is True
        assert os.path.isfile(output_path)
        assert os.path.getsize(output_path) > 0


@pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="reportlab not available")
def test_generate_incident_report():
    case = {
        "id": "CASE-12345678",
        "title": "SQL injection attack",
        "severity": "critical",
        "status": "investigating",
        "created_at": "2026-11-03T05:00:00Z",
    }
    timeline = [
        {"entry": "Case created", "actor": "system", "created_at": "2026-11-03T05:00:00Z"},
        {"entry": "Evidence collected", "actor": "analyst1", "created_at": "2026-11-03T05:10:00Z"},
    ]
    affected_ips = ["192.0.2.1", "192.0.2.2"]
    attack_types = {"sqli": 15, "xss": 3}
    mitre_techniques = [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ]
    actions = [
        {"action": "permanent_block", "ip": "192.0.2.1", "reason": "SQL injection"},
    ]
    recommendations = [
        "Patch application vulnerabilities",
        "Review WAF rules",
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "incident.pdf")
        result = generate_incident_report(
            case, timeline, affected_ips, attack_types, mitre_techniques, actions, recommendations, output_path
        )
        assert result is True
        assert os.path.isfile(output_path)
        assert os.path.getsize(output_path) > 0
