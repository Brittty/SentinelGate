"""PDF audit report generation using ReportLab.

Generates security audit reports with findings, CVSS scores, and recommendations.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def calculate_audit_score(findings: list[dict]) -> float:
    """Calculate overall audit score 0-100 based on findings.

    Deducts points based on severity: critical -20, high -10, medium -5, low -2
    """
    score = 100.0
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity == "critical":
            score -= 20
        elif severity == "high":
            score -= 10
        elif severity == "medium":
            score -= 5
        elif severity == "low":
            score -= 2
    return max(0.0, score)


def generate_audit_report(
    findings: list[dict],
    scan_metadata: dict[str, Any],
    output_path: str,
) -> bool:
    """Generate a PDF audit report.

    Args:
        findings: List of finding dicts with type, title, severity, cvss_score, evidence, remediation
        scan_metadata: Dict with target, scan_date, scanners_used
        output_path: Path to save PDF

    Returns:
        True if successful, False otherwise
    """
    if not REPORTLAB_AVAILABLE:
        return False

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#05060C'),
        spaceAfter=30,
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#11122B'),
        spaceAfter=12,
    )

    # Title
    story.append(Paragraph("Security Audit Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    # Metadata
    story.append(Paragraph("Audit Summary", heading_style))
    metadata_data = [
        ["Target:", scan_metadata.get("target", "")],
        ["Scan Date:", scan_metadata.get("scan_date", "")],
        ["Scanners:", ", ".join(scan_metadata.get("scanners_used", []))],
        ["Report Generated:", datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    metadata_table = Table(metadata_data, colWidths=[2 * inch, 4 * inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#EEF2FF')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 0.3 * inch))

    # Audit score
    audit_score = calculate_audit_score(findings)
    story.append(Paragraph(f"Overall Audit Score: {audit_score:.1f}/100", heading_style))

    score_color = colors.green
    if audit_score < 50:
        score_color = colors.red
    elif audit_score < 75:
        score_color = colors.orange

    story.append(Paragraph(
        f"<font color='{score_color.hexval()}'>{'Excellent' if audit_score >= 90 else 'Good' if audit_score >= 75 else 'Fair' if audit_score >= 50 else 'Poor'}</font>",
        styles['Normal']
    ))
    story.append(Spacer(1, 0.3 * inch))

    # Severity breakdown
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in severity_counts:
            severity_counts[severity] += 1

    story.append(Paragraph("Findings by Severity", heading_style))
    severity_data = [["Severity", "Count"]]
    for severity, count in severity_counts.items():
        severity_data.append([severity.capitalize(), str(count)])
    severity_table = Table(severity_data, colWidths=[3 * inch, 2 * inch])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#11122B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(severity_table)
    story.append(Spacer(1, 0.4 * inch))

    # Findings (sorted by CVSS score descending)
    story.append(Paragraph("Detailed Findings", heading_style))
    sorted_findings = sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)

    for i, finding in enumerate(sorted_findings, 1):
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "low")
        cvss = finding.get("cvss_score", 0.0)
        evidence = finding.get("evidence", "")[:200]
        remediation = finding.get("remediation", "")

        # Finding header
        story.append(Paragraph(
            f"<b>{i}. {title}</b> [<font color='red'>{severity.upper()}</font>] CVSS: {cvss:.1f}",
            styles['Normal']
        ))
        story.append(Spacer(1, 0.1 * inch))

        # Evidence
        story.append(Paragraph(f"<i>Evidence:</i> {evidence}", styles['Normal']))
        story.append(Spacer(1, 0.05 * inch))

        # Remediation
        story.append(Paragraph(f"<i>Remediation:</i> {remediation}", styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))

    # Footer
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "This audit report was generated by SentinelGate. Review findings and apply recommended remediations.",
        styles['Normal']
    ))

    # Build PDF
    try:
        doc.build(story)
        return True
    except Exception:
        return False
