"""PDF Evidence Report Generator for PhishLens Investigations.

Generates a professional PDF report from a stored investigation record.
Uses ReportLab for pure-Python PDF generation with no external dependencies.
"""

import json
import textwrap
from datetime import datetime
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)


DEFAULT_DB_PATH = "instance/phishlens.db"


def generate_report(investigation_record, output_path):
    """Generate a PDF evidence report from an investigation record.

    Args:
        investigation_record: Dict with keys id, created_at, url, risk_score, risk_level, result
        output_path: Path to write the PDF file

    Returns:
        True on success, False on failure
    """
    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title=f"PhishLens Investigation Report - {investigation_record['id'][:8]}",
            author="PhishLens",
            subject="Phishing Investigation Evidence Report",
            keywords=["phishing", "security", "investigation", "evidence"],
        )

        styles = getSampleStyleSheet()
        story = []

        _add_header(story, styles, investigation_record)
        _add_metadata(story, styles, investigation_record)
        _add_observed_evidence(story, styles, investigation_record)
        _add_inferred_risk(story, styles, investigation_record)
        _add_score_breakdown(story, styles, investigation_record)
        _add_recommendations(story, styles, investigation_record)
        _add_disclaimer(story, styles)

        doc.build(story)
        return True
    except Exception:
        return False


def _add_header(story, styles, record):
    """Add report header with title and branding."""
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#06b9d4"),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#94a3b8"),
        spaceAfter=18,
        alignment=TA_CENTER,
        fontName="Helvetica",
    )
    story.append(Paragraph("PhishLens", title_style))
    story.append(Paragraph("Cyber Intelligence — Investigation Evidence Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#06b9d4"), spaceAfter=12))


def _add_metadata(story, styles, record):
    """Add investigation metadata section."""
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#f1f5f9"),
        spaceBefore=12,
        spaceAfter=8,
        fontName="Helvetica-Bold",
        borderWidth=0,
        borderPadding=0,
    )
    label_style = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        fontName="Helvetica-Bold",
    )
    value_style = ParagraphStyle(
        "MetaValue",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#f1f5f9"),
        fontName="Helvetica",
    )

    story.append(Paragraph("Investigation Metadata", section_style))

    created_at = record.get("created_at", "")
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        formatted_date = created_at

    url_display = _redact_url_for_display(record.get("url", ""))
    risk_score = record.get("risk_score", 0)
    risk_level = record.get("risk_level", "unknown").upper()

    meta_data = [
        ["Investigation ID:", record.get("id", "N/A")],
        ["Date/Time (UTC):", formatted_date],
        ["Analyzed URL:", url_display],
        ["Risk Score:", f"{risk_score}/100"],
        ["Risk Level:", risk_level],
    ]

    table = Table(meta_data, colWidths=[1.8 * inch, 5.2 * inch])
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#f1f5f9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))


def _add_observed_evidence(story, styles, record):
    """Add observed evidence section (indicators with evidence)."""
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#f1f5f9"),
        spaceBefore=12,
        spaceAfter=8,
        fontName="Helvetica-Bold",
    )
    story.append(Paragraph("Observed Evidence", section_style))

    result = record.get("result", {})
    indicators = result.get("indicators", [])

    if not indicators:
        empty_style = ParagraphStyle(
            "EmptyState",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#94a3b8"),
            fontName="Helvetica-Oblique",
        )
        story.append(Paragraph(
            "No risk indicators were identified by the current heuristic checks. "
            "This does not guarantee the URL is safe — the analyzer only checks a fixed "
            "set of heuristic patterns and never contacts the URL.",
            empty_style
        ))
        story.append(Spacer(1, 12))
        return

    for ind in indicators:
        name = xml_escape(str(ind.get("name", "Indicator")))
        detail = xml_escape(str(ind.get("detail", "")))
        evidence = xml_escape(str(ind.get("evidence", "")))
        severity = str(ind.get("severity", "unknown")).lower()
        points = ind.get("points", 0)
        explanation = xml_escape(str(ind.get("explanation", "")))

        sev_colors = {
            "high": colors.HexColor("#FF496C"),
            "medium": colors.HexColor("#fbbf24"),
            "low": colors.HexColor("#4ade80"),
            "unknown": colors.HexColor("#94a3b8"),
        }
        sev_color = sev_colors.get(severity, colors.HexColor("#94a3b8"))

        ind_style = ParagraphStyle(
            f"Indicator_{id(ind)}",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#f1f5f9"),
            fontName="Helvetica",
            spaceAfter=6,
        )
        evidence_style = ParagraphStyle(
            "Evidence",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748b"),
            fontName="Courier",
            leftIndent=12,
            spaceAfter=4,
        )
        detail_style = ParagraphStyle(
            "Detail",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#cbd5e1"),
            fontName="Helvetica",
            leftIndent=12,
            spaceAfter=4,
        )
        explanation_style = ParagraphStyle(
            "Explanation",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#94a3b8"),
            fontName="Helvetica-Oblique",
            leftIndent=12,
            spaceAfter=8,
        )

        header_text = f"<b>{name}</b>  <font color='#{sev_color.hexval()[2:]}'><b>{severity.upper()}</b></font>  (+{points} pts)"
        story.append(Paragraph(header_text, ind_style))
        if detail:
            story.append(Paragraph(f"Detail: {detail}", detail_style))
        if evidence:
            story.append(Paragraph(f"Evidence: {evidence}", evidence_style))
        if explanation:
            story.append(Paragraph(f"Explanation: {explanation}", explanation_style))

    story.append(Spacer(1, 8))


def _add_inferred_risk(story, styles, record):
    """Add inferred risk section."""
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#f1f5f9"),
        spaceBefore=12,
        spaceAfter=8,
        fontName="Helvetica-Bold",
    )
    story.append(Paragraph("Inferred Risk Assessment", section_style))

    result = record.get("result", {})
    risk_score = record.get("risk_score", 0)
    risk_level = record.get("risk_level", "unknown").lower()

    level_map = {
        "minimal": ("MINIMAL", colors.HexColor("#4ade80"), "No significant phishing indicators detected."),
        "low": ("LOW", colors.HexColor("#4ade80"), "Some suspicious patterns; remain vigilant."),
        "medium": ("MEDIUM", colors.HexColor("#fbbf24"), "Multiple indicators; exercise caution, verify independently."),
        "high": ("HIGH", colors.HexColor("#FF496C"), "Strong indicators of phishing; do not visit."),
        "error": ("ERROR", colors.HexColor("#FF496C"), "Analysis could not be completed."),
    }
    level_label, level_color, level_desc = level_map.get(risk_level, ("UNKNOWN", colors.HexColor("#94a3b8"), "Risk level unknown."))

    risk_text = (
        f"Based on the observed evidence, the analyzer assigns a <b>Risk Score of {risk_score}/100</b> "
        f"with a <font color='#{level_color.hexval()[2:]}'><b>{level_label} RISK</b></font> classification. "
        f"{level_desc}"
    )

    body_style = ParagraphStyle(
        "RiskBody",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#f1f5f9"),
        fontName="Helvetica",
        alignment=TA_JUSTIFY,
        spaceAfter=12,
    )
    story.append(Paragraph(risk_text, body_style))
    story.append(Spacer(1, 4))


def _add_score_breakdown(story, styles, record):
    """Add score breakdown table."""
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#f1f5f9"),
        spaceBefore=12,
        spaceAfter=8,
        fontName="Helvetica-Bold",
    )
    story.append(Paragraph("Score Breakdown", section_style))

    result = record.get("result", {})
    breakdown = result.get("score_breakdown", {})
    raw_total = breakdown.get("raw_total", 0)
    cap = breakdown.get("cap", 100)
    final_score = breakdown.get("final_score", 0)
    capped = breakdown.get("capped", False)
    contributions = breakdown.get("contributions", [])

    summary_data = [
        ["Metric", "Value"],
        ["Raw Total", str(raw_total)],
        ["Score Cap", str(cap)],
        ["Final Score", str(final_score)],
        ["Capped", "Yes" if capped else "No"],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 4.5 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#06b9d4")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0a0f1a"), colors.HexColor("#111827")]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    if contributions:
        story.append(Paragraph("Per-Indicator Contributions", ParagraphStyle(
            "ContribTitle", parent=styles["Heading3"], fontSize=11, leading=14,
            textColor=colors.HexColor("#cbd5e1"), fontName="Helvetica-Bold", spaceAfter=6
        )))

        contrib_data = [["Indicator", "Severity", "Points", "Explanation"]]
        for c in contributions:
            contrib_data.append([
                xml_escape(str(c.get("name", ""))),
                xml_escape(str(c.get("severity", "unknown")).upper()),
                str(c.get("points", 0)),
                xml_escape(str(c.get("explanation", ""))),
            ])

        contrib_table = Table(contrib_data, colWidths=[1.5 * inch, 0.7 * inch, 0.5 * inch, 4.3 * inch])
        contrib_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#06b9d4")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0a0f1a"), colors.HexColor("#111827")]),
        ]))
        story.append(contrib_table)

    story.append(Spacer(1, 12))


def _add_recommendations(story, styles, record):
    """Add recommendations section."""
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#f1f5f9"),
        spaceBefore=12,
        spaceAfter=8,
        fontName="Helvetica-Bold",
    )
    story.append(Paragraph("Recommendations", section_style))

    result = record.get("result", {})
    recommendations = result.get("recommendations", [])

    if not recommendations:
        empty_style = ParagraphStyle(
            "EmptyState",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#94a3b8"),
            fontName="Helvetica-Oblique",
        )
        story.append(Paragraph("No specific recommendations available.", empty_style))
        story.append(Spacer(1, 12))
        return

    rec_style = ParagraphStyle(
        "Recommendation",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#f1f5f9"),
        fontName="Helvetica",
        leftIndent=20,
        spaceAfter=6,
        bulletIndent=8,
        bulletFontName="Helvetica",
        bulletFontSize=10,
    )
    for rec in recommendations:
        story.append(Paragraph(xml_escape(str(rec)), rec_style, bulletText="•"))
    story.append(Spacer(1, 12))


def _add_disclaimer(story, styles):
    """Add heuristic disclaimer at the end."""
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#fbbf24"),
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        borderWidth=1,
        borderColor=colors.HexColor("#fbbf24"),
        borderPadding=8,
        spaceBefore=20,
    )
    story.append(Paragraph(
        "HEURISTIC ESTIMATE — Scores and indicators are statistical signals, "
        "not proof that a URL is malicious or safe. "
        "PhishLens performs static analysis only and never fetches or executes the target URL.",
        disclaimer_style
    ))


def _redact_url_for_display(url):
    """Redact embedded credentials from URL for safe display."""
    if not isinstance(url, str) or "@" not in url:
        return url
    try:
        parsed = urlparse(url)
        if parsed.username is None and parsed.password is None:
            return url
        host_part = parsed.netloc.rsplit("@", 1)[1] if "@" in parsed.netloc else parsed.netloc
        from urllib.parse import urlunparse
        redacted = parsed._replace(netloc="[redacted]@" + host_part)
        return urlunparse(redacted)
    except Exception:
        return url


def generate_report_from_id(investigation_id, db_path=None, output_path=None):
    """Convenience function to generate report directly from investigation ID.

    Args:
        investigation_id: UUID string
        db_path: Optional database path
        output_path: Optional output path (defaults to /tmp/phishlens_<id>.pdf)

    Returns:
        (success: bool, output_path: str|None, error_msg: str|None)
    """
    from investigations import get_investigation, is_valid_id

    if not is_valid_id(investigation_id):
        return False, None, "Invalid investigation ID"

    record = get_investigation(investigation_id, db_path)
    if not record:
        return False, None, "Investigation not found"

    if output_path is None:
        import tempfile
        output_path = f"{tempfile.gettempdir()}/phishlens_{investigation_id[:8]}.pdf"

    success = generate_report(record, output_path)
    if success:
        return True, output_path, None
    return False, None, "Report generation failed"