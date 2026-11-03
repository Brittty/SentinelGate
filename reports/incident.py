"""PDF incident report generation using ReportLab.

Generates comprehensive incident reports with timeline, evidence, and recommendations.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

MAX_LISTED_IPS = 20


def generate_incident_report(
    case: dict[str, Any],
    timeline: list[dict],
    affected_ips: list[str],
    attack_types: dict[str, int],
    mitre_techniques: list[dict],
    actions: list[dict],
    recommendations: list[str],
    output_path: str,
) -> bool:
    """Generate a PDF incident report.

    Args:
        case: Case dict with id, title, severity, status
        timeline: List of timeline entries
        affected_ips: List of attacker IPs
        attack_types: Dict of {attack_type: count}
        mitre_techniques: List of MITRE techniques involved
        actions: List of response actions taken
        recommendations: List of remediation recommendations
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
    story.append(Paragraph("Security Incident Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    # Case summary
    story.append(Paragraph("Incident Summary", heading_style))
    summary_data = [
        ["Case ID:", case.get("id", "")],
        ["Title:", case.get("title", "")],
        ["Severity:", case.get("severity", "").upper()],
        ["Status:", case.get("status", "").upper()],
        ["Created:", case.get("created_at", "")[:19]],
        ["Report Generated:", datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    summary_table = Table(summary_data, colWidths=[2 * inch, 4 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#EEF2FF')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    # Affected IPs
    story.append(Paragraph("Affected IP Addresses", heading_style))
    story.append(Paragraph(", ".join(affected_ips[:MAX_LISTED_IPS]), styles['Normal']))
    if len(affected_ips) > MAX_LISTED_IPS:
        remaining = len(affected_ips) - MAX_LISTED_IPS
        story.append(Paragraph(f"...and {remaining} more", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # Attack types
    story.append(Paragraph("Attack Types Detected", heading_style))
    attack_data = [["Attack Type", "Count"]]
    for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
        attack_data.append([attack_type or "Unknown", str(count)])
    attack_table = Table(attack_data, colWidths=[4 * inch, 2 * inch])
    attack_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#11122B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(attack_table)
    story.append(Spacer(1, 0.3 * inch))

    # MITRE ATT&CK
    story.append(Paragraph("MITRE ATT&CK Techniques", heading_style))
    mitre_data = [["ID", "Name", "Tactic"]]
    for technique in mitre_techniques[:10]:
        mitre_data.append([
            technique.get("id", ""),
            technique.get("name", "")[:40],
            technique.get("tactic", ""),
        ])
    mitre_table = Table(mitre_data, colWidths=[1 * inch, 3 * inch, 2 * inch])
    mitre_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#11122B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(mitre_table)
    story.append(Spacer(1, 0.3 * inch))

    # Timeline
    story.append(PageBreak())
    story.append(Paragraph("Incident Timeline", heading_style))
    for entry in timeline[-20:]:  # Last 20 entries
        ts = entry.get("created_at", "")[:19]
        actor = entry.get("actor", "")
        text = entry.get("entry", "")
        story.append(Paragraph(f"<b>{ts}</b> [{actor}] {text}", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))

    # Response actions
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Response Actions Taken", heading_style))
    action_data = [["Action", "IP", "Reason"]]
    for action in actions[-15:]:
        action_data.append([
            action.get("action", "")[:20],
            action.get("ip", "")[:20],
            action.get("reason", "")[:40],
        ])
    action_table = Table(action_data, colWidths=[1.5 * inch, 2 * inch, 2.5 * inch])
    action_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#11122B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(action_table)
    story.append(Spacer(1, 0.3 * inch))

    # Recommendations
    story.append(Paragraph("Recommendations", heading_style))
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))

    # Footer
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "This report was generated by SentinelGate. For questions, contact your security team.",
        styles['Normal']
    ))

    # Build PDF
    try:
        doc.build(story)
        return True
    except Exception:
        return False
