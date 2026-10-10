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
    KeepTogether,
    HRFlowable,
    PageBreak,
)
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate
from reportlab.platypus.frames import Frame


DEFAULT_DB_PATH = "instance/phishlens.db"


PAGE_WIDTH, PAGE_HEIGHT = letter
LEFT_MARGIN = 0.75 * inch
RIGHT_MARGIN = 0.75 * inch
TOP_MARGIN = 0.75 * inch
BOTTOM_MARGIN = 0.75 * inch
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN


SEVERITY_COLORS = {
    "high": colors.HexColor("#DC2626"),      # Red-600 - readable on white
    "medium": colors.HexColor("#D97706"),    # Amber-600 - readable on white
    "low": colors.HexColor("#16A34A"),       # Green-600 - readable on white
    "unknown": colors.HexColor("#64748B"),   # Slate-500 - readable on white
}


RISK_LEVEL_MAP = {
    "minimal": ("MINIMAL", colors.HexColor("#16A34A"), "No significant phishing indicators detected."),
    "low": ("LOW", colors.HexColor("#16A34A"), "Some suspicious patterns; remain vigilant."),
    "medium": ("MEDIUM", colors.HexColor("#D97706"), "Multiple indicators; exercise caution, verify independently."),
    "high": ("HIGH", colors.HexColor("#DC2626"), "Strong indicators of phishing; do not visit."),
    "error": ("ERROR", colors.HexColor("#DC2626"), "Analysis could not be completed."),
}


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
            rightMargin=RIGHT_MARGIN,
            leftMargin=LEFT_MARGIN,
            topMargin=TOP_MARGIN,
            bottomMargin=BOTTOM_MARGIN,
            title=f"PhishLens Investigation Report - {investigation_record['id'][:8]}",
            author="PhishLens",
            subject="Phishing Investigation Evidence Report",
            keywords=["phishing", "security", "investigation", "evidence"],
        )

        styles = _build_styles()
        story = []

        _add_header(story, styles, investigation_record)
        _add_metadata(story, styles, investigation_record)
        _add_observed_evidence(story, styles, investigation_record)
        _add_inferred_risk(story, styles, investigation_record)
        _add_score_breakdown(story, styles, investigation_record)
        _add_recommendations(story, styles, investigation_record)
        _add_disclaimer(story, styles)

        doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
        return True
    except Exception:
        return False


def _build_styles():
    """Build and return a dictionary of paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),       # Near-black - readable on white
        spaceAfter=4,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#64748b"),       # Slate-500 - readable on white
        spaceAfter=14,
        alignment=TA_CENTER,
        fontName="Helvetica",
    ))

    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1e293b"),       # Slate-800 - readable on white
        spaceBefore=14,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        borderWidth=0,
        borderPadding=0,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="SubSectionTitle",
        parent=styles["Heading3"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#334155"),       # Slate-700 - readable on white
        spaceBefore=8,
        spaceAfter=4,
        fontName="Helvetica-Bold",
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="MetaLabel",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),       # Slate-700 - readable on white
        fontName="Helvetica-Bold",
    ))

    styles.add(ParagraphStyle(
        name="MetaValue",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a"),       # Near-black - readable on white
        fontName="Helvetica",
    ))

    styles.add(ParagraphStyle(
        name="BodyText2",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1e293b"),       # Slate-800 - readable on white
        fontName="Helvetica",
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="IndicatorHeader",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=12,
        textColor=colors.HexColor("#0f172a"),       # Near-black - readable on white
        fontName="Helvetica",
        spaceAfter=3,
    ))

    styles.add(ParagraphStyle(
        name="IndicatorDetail",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155"),       # Slate-700 - readable on white
        fontName="Helvetica",
        leftIndent=14,
        spaceAfter=3,
    ))

    styles.add(ParagraphStyle(
        name="IndicatorEvidence",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),       # Slate-600 - readable on white
        fontName="Courier",
        leftIndent=14,
        spaceAfter=3,
    ))

    styles.add(ParagraphStyle(
        name="IndicatorExplanation",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#64748b"),       # Slate-500 - readable on white
        fontName="Helvetica-Oblique",
        leftIndent=14,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="RiskBody",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1e293b"),       # Slate-800 - readable on white
        fontName="Helvetica",
        alignment=TA_JUSTIFY,
        spaceAfter=10,
    ))

    styles.add(ParagraphStyle(
        name="Recommendation",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1e293b"),       # Slate-800 - readable on white
        fontName="Helvetica",
        leftIndent=18,
        spaceAfter=5,
        bulletIndent=6,
        bulletFontName="Helvetica",
        bulletFontSize=9.5,
    ))

    styles.add(ParagraphStyle(
        name="Disclaimer",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#D97706"),       # Amber-600 - readable on white
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        borderWidth=1,
        borderColor=colors.HexColor("#D97706"),
        borderPadding=8,
        spaceBefore=18,
    ))

    styles.add(ParagraphStyle(
        name="EmptyState",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#64748b"),       # Slate-500 - readable on white
        fontName="Helvetica-Oblique",
        alignment=TA_CENTER,
        spaceAfter=8,
    ))

    return styles


def _add_page_number(canvas, doc):
    """Add page number to bottom center of each page."""
    canvas.saveState()
    page_num = doc.page
    text = f"Page {page_num}"
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#64748b"))  # Slate-500 - readable on white
    canvas.drawCentredString(PAGE_WIDTH / 2, 0.45 * inch, text)
    canvas.restoreState()


def _add_header(story, styles, record):
    """Add report header with title and branding."""
    story.append(Paragraph("PhishLens", styles["ReportTitle"]))
    story.append(Paragraph("Cyber Intelligence — Investigation Evidence Report", styles["ReportSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#06b9d4"), spaceAfter=14))


def _add_metadata(story, styles, record):
    """Add investigation metadata section with clean two-column table."""
    story.append(Paragraph("Investigation Metadata", styles["SectionTitle"]))

    created_at = record.get("created_at", "")
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        formatted_date = created_at

    url_display = _redact_url_for_display(record.get("url", ""))
    risk_score = record.get("risk_score", 0)
    risk_level = record.get("risk_level", "unknown").upper()

    level_label, level_color, _ = RISK_LEVEL_MAP.get(record.get("risk_level", "unknown").lower(),
                                                      ("UNKNOWN", colors.HexColor("#64748b"), ""))

    meta_data = [
        [Paragraph("<b>Investigation ID:</b>", styles["MetaLabel"]),
         Paragraph(xml_escape(record.get("id", "N/A")), styles["MetaValue"])],
        [Paragraph("<b>Date/Time (UTC):</b>", styles["MetaLabel"]),
         Paragraph(xml_escape(formatted_date), styles["MetaValue"])],
        [Paragraph("<b>Analyzed URL:</b>", styles["MetaLabel"]),
         Paragraph(xml_escape(url_display), ParagraphStyle(
             "URLValue", parent=styles["MetaValue"], fontName="Courier", wordWrap="CJK"
         ))],
        [Paragraph("<b>Risk Score:</b>", styles["MetaLabel"]),
         Paragraph(f"<b>{risk_score}/100</b>", styles["MetaValue"])],
        [Paragraph("<b>Risk Level:</b>", styles["MetaLabel"]),
         Paragraph(f'<font color="#{level_color.hexval()[2:]}"><b>{level_label}</b></font>', styles["MetaValue"])],
    ]

    table = Table(meta_data, colWidths=[1.6 * inch, CONTENT_WIDTH - 1.6 * inch])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))


def _add_observed_evidence(story, styles, record):
    """Add observed evidence section (indicators with evidence)."""
    story.append(Paragraph("Observed Evidence", styles["SectionTitle"]))

    result = record.get("result", {})
    indicators = result.get("indicators", [])

    if not indicators:
        story.append(Paragraph(
            "No risk indicators were identified by the current heuristic checks. "
            "This does not guarantee the URL is safe — the analyzer only checks a fixed "
            "set of heuristic patterns and never contacts the URL.",
            styles["EmptyState"]
        ))
        story.append(Spacer(1, 10))
        return

    for ind in indicators:
        name = xml_escape(str(ind.get("name", "Indicator")))
        detail = xml_escape(str(ind.get("detail", "")))
        evidence = xml_escape(str(ind.get("evidence", "")))
        severity = str(ind.get("severity", "unknown")).lower()
        points = ind.get("points", 0)
        explanation = xml_escape(str(ind.get("explanation", "")))

        sev_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])

        ind_elements = []

        header_text = (
            f"<b>{name}</b>  "
            f'<font color="#{sev_color.hexval()[2:]}"><b>{severity.upper()}</b></font>  '
            f"(+{points} pts)"
        )
        ind_elements.append(Paragraph(header_text, styles["IndicatorHeader"]))

        if detail:
            ind_elements.append(Paragraph(f"Detail: {detail}", styles["IndicatorDetail"]))
        if evidence:
            ind_elements.append(Paragraph(f"Evidence: {evidence}", styles["IndicatorEvidence"]))
        if explanation:
            ind_elements.append(Paragraph(f"Explanation: {explanation}", styles["IndicatorExplanation"]))

        story.append(KeepTogether(ind_elements))

    story.append(Spacer(1, 6))


def _add_inferred_risk(story, styles, record):
    """Add inferred risk section."""
    story.append(Paragraph("Inferred Risk Assessment", styles["SectionTitle"]))

    result = record.get("result", {})
    risk_score = record.get("risk_score", 0)
    risk_level = record.get("risk_level", "unknown").lower()

    level_label, level_color, level_desc = RISK_LEVEL_MAP.get(risk_level,
        ("UNKNOWN", colors.HexColor("#94a3b8"), "Risk level unknown."))

    risk_text = (
        f"Based on the observed evidence, the analyzer assigns a <b>Risk Score of {risk_score}/100</b> "
        f"with a <font color='#{level_color.hexval()[2:]}'><b>{level_label} RISK</b></font> classification. "
        f"{level_desc}"
    )

    story.append(Paragraph(risk_text, styles["RiskBody"]))
    story.append(Spacer(1, 4))


def _add_score_breakdown(story, styles, record):
    """Add score breakdown table."""
    story.append(Paragraph("Score Breakdown", styles["SectionTitle"]))

    result = record.get("result", {})
    breakdown = result.get("score_breakdown", {})
    raw_total = breakdown.get("raw_total", 0)
    cap = breakdown.get("cap", 100)
    final_score = breakdown.get("final_score", 0)
    capped = breakdown.get("capped", False)
    contributions = breakdown.get("contributions", [])

    summary_data = [
        [Paragraph("<b>Metric</b>", styles["MetaLabel"]), Paragraph("<b>Value</b>", styles["MetaLabel"])],
        [Paragraph("Raw Total", styles["MetaLabel"]), Paragraph(str(raw_total), styles["MetaValue"])],
        [Paragraph("Score Cap", styles["MetaLabel"]), Paragraph(str(cap), styles["MetaValue"])],
        [Paragraph("Final Score", styles["MetaLabel"]), Paragraph(str(final_score), styles["MetaValue"])],
        [Paragraph("Capped", styles["MetaLabel"]), Paragraph("Yes" if capped else "No", styles["MetaValue"])],
    ]
    summary_table = Table(summary_data, colWidths=[2.2 * inch, CONTENT_WIDTH - 2.2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),      # Slate-200 - light header bg
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),        # Near-black header text
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#1e293b")),       # Slate-800 body text
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),       # Slate-300 grid
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),  # White / Slate-50
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    if contributions:
        story.append(Paragraph("Per-Indicator Contributions", styles["SubSectionTitle"]))

        contrib_data = [
            [Paragraph("<b>Indicator</b>", styles["MetaLabel"]),
             Paragraph("<b>Severity</b>", styles["MetaLabel"]),
             Paragraph("<b>Points</b>", styles["MetaLabel"]),
             Paragraph("<b>Explanation</b>", styles["MetaLabel"])]
        ]
        for c in contributions:
            sev = xml_escape(str(c.get("severity", "unknown")).upper())
            sev_color = SEVERITY_COLORS.get(c.get("severity", "unknown").lower(), SEVERITY_COLORS["unknown"])
            contrib_data.append([
                Paragraph(xml_escape(str(c.get("name", ""))), styles["MetaValue"]),
                Paragraph(f'<font color="#{sev_color.hexval()[2:]}"><b>{sev}</b></font>', styles["MetaValue"]),
                Paragraph(str(c.get("points", 0)), styles["MetaValue"]),
                Paragraph(xml_escape(str(c.get("explanation", ""))), styles["MetaValue"]),
            ])

        col_widths = [1.4 * inch, 0.6 * inch, 0.45 * inch, CONTENT_WIDTH - 2.45 * inch]
        contrib_table = Table(contrib_data, colWidths=col_widths, repeatRows=1)
        contrib_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),      # Slate-200 - light header bg
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),        # Near-black header text
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#1e293b")),       # Slate-800 body text
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),       # Slate-300 grid
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),  # White / Slate-50
        ]))
        story.append(contrib_table)

    story.append(Spacer(1, 10))


def _add_recommendations(story, styles, record):
    """Add recommendations section."""
    story.append(Paragraph("Recommendations", styles["SectionTitle"]))

    result = record.get("result", {})
    recommendations = result.get("recommendations", [])

    if not recommendations:
        story.append(Paragraph("No specific recommendations available.", styles["EmptyState"]))
        story.append(Spacer(1, 10))
        return

    for rec in recommendations:
        story.append(Paragraph(xml_escape(str(rec)), styles["Recommendation"], bulletText="•"))
    story.append(Spacer(1, 10))


def _add_disclaimer(story, styles):
    """Add heuristic disclaimer at the end."""
    story.append(Paragraph(
        "HEURISTIC ESTIMATE — Scores and indicators are statistical signals, "
        "not proof that a URL is malicious or safe. "
        "PhishLens performs static analysis only and never fetches or executes the target URL.",
        styles["Disclaimer"]
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