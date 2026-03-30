"""
report.py — Output Layer
CipherAudit | TLS & PKI Certificate Compliance Scanner

Technology: ReportLab (PDF generation)

Output PDF contains:
  1. Cover page with scan metadata and severity summary
  2. Executive summary table — all domains with severity
  3. Per-domain detail section — full certificate fields
  4. Compliance reference appendix — NIST SP 800-52 & PCI-DSS v4.0 clauses
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
    KeepTogether,
)
from reportlab.platypus.tableofcontents import TableOfContents

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent / "output"

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLOUR_CRITICAL = colors.HexColor("#C0392B")
COLOUR_HIGH     = colors.HexColor("#E67E22")
COLOUR_MEDIUM   = colors.HexColor("#F1C40F")
COLOUR_LOW      = colors.HexColor("#27AE60")
COLOUR_UNKNOWN  = colors.HexColor("#95A5A6")
COLOUR_HEADER   = colors.HexColor("#1A252F")
COLOUR_ACCENT   = colors.HexColor("#2980B9")
COLOUR_ROW_ALT  = colors.HexColor("#F5F8FA")
COLOUR_WHITE    = colors.white
COLOUR_BLACK    = colors.black

SEVERITY_COLOURS = {
    "CRITICAL": COLOUR_CRITICAL,
    "HIGH":     COLOUR_HIGH,
    "MEDIUM":   COLOUR_MEDIUM,
    "LOW":      COLOUR_LOW,
    "UNKNOWN":  COLOUR_UNKNOWN,
}


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "CoverTitle",
            fontSize=28, leading=34, alignment=TA_CENTER,
            textColor=COLOUR_WHITE, fontName="Helvetica-Bold",
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "CoverSubtitle",
            fontSize=13, leading=18, alignment=TA_CENTER,
            textColor=colors.HexColor("#BDC3C7"), fontName="Helvetica",
            spaceAfter=4,
        ),
        "meta": ParagraphStyle(
            "CoverMeta",
            fontSize=10, leading=14, alignment=TA_CENTER,
            textColor=colors.HexColor("#ECF0F1"), fontName="Helvetica",
        ),
        "h1": ParagraphStyle(
            "H1",
            fontSize=16, leading=20, spaceBefore=18, spaceAfter=8,
            textColor=COLOUR_HEADER, fontName="Helvetica-Bold",
            borderPad=(0, 0, 4, 0),
        ),
        "h2": ParagraphStyle(
            "H2",
            fontSize=12, leading=16, spaceBefore=12, spaceAfter=6,
            textColor=COLOUR_ACCENT, fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "Body",
            fontSize=9, leading=13, spaceBefore=2, spaceAfter=2,
            textColor=COLOUR_BLACK, fontName="Helvetica",
        ),
        "body_small": ParagraphStyle(
            "BodySmall",
            fontSize=8, leading=11,
            textColor=colors.HexColor("#555555"), fontName="Helvetica",
        ),
        "label": ParagraphStyle(
            "Label",
            fontSize=8, leading=11,
            textColor=colors.HexColor("#7F8C8D"), fontName="Helvetica-Bold",
        ),
        "value": ParagraphStyle(
            "Value",
            fontSize=9, leading=12,
            textColor=COLOUR_BLACK, fontName="Helvetica",
        ),
        "severity_badge": ParagraphStyle(
            "SeverityBadge",
            fontSize=9, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
        "footer": ParagraphStyle(
            "Footer",
            fontSize=7, alignment=TA_CENTER,
            textColor=colors.HexColor("#95A5A6"), fontName="Helvetica",
        ),
        "compliance_ref": ParagraphStyle(
            "ComplianceRef",
            fontSize=8, leading=12, leftIndent=12,
            textColor=colors.HexColor("#2C3E50"), fontName="Helvetica",
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# Page template with header/footer
# ---------------------------------------------------------------------------

class _ReportDoc(BaseDocTemplate):
    """Custom doc template that adds page header and footer on every page."""

    def __init__(self, path: str, scan_date: str, **kwargs):
        super().__init__(path, **kwargs)
        self.scan_date = scan_date
        self._page_styles = _build_styles()

        frame = Frame(
            self.leftMargin, self.bottomMargin,
            self.width, self.height,
            id="main",
        )
        template = PageTemplate(id="main", frames=[frame], onPage=self._draw_page)
        self.addPageTemplates([template])

    def _draw_page(self, canvas, doc):
        canvas.saveState()

        # Header bar (skip cover page)
        if doc.page > 1:
            canvas.setFillColor(COLOUR_HEADER)
            canvas.rect(
                doc.leftMargin - 0.5 * cm, doc.height + doc.bottomMargin + 0.3 * cm,
                doc.width + 1 * cm, 0.6 * cm,
                fill=1, stroke=0,
            )
            canvas.setFillColor(COLOUR_WHITE)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(
                doc.leftMargin, doc.height + doc.bottomMargin + 0.55 * cm,
                "CipherAudit — TLS & PKI Certificate Compliance Report",
            )
            canvas.setFont("Helvetica", 8)
            canvas.drawRightString(
                doc.leftMargin + doc.width,
                doc.height + doc.bottomMargin + 0.55 * cm,
                f"Scan Date: {self.scan_date}",
            )

        # Footer
        canvas.setFillColor(colors.HexColor("#95A5A6"))
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(
            doc.leftMargin + doc.width / 2,
            doc.bottomMargin - 0.4 * cm,
            f"Page {doc.page}  |  CONFIDENTIAL — Internal Use Only  |  "
            f"Standards: NIST SP 800-52 · PCI-DSS v4.0",
        )

        canvas.restoreState()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(rows: list[dict], summary: dict, output_dir: Path = OUTPUT_DIR) -> Path:
    """
    Generate a PDF compliance report from scan results.

    Args:
        rows:       List of dicts from database.get_latest_scan()
        summary:    Dict from database.get_severity_summary()
        output_dir: Directory to write the PDF into

    Returns:
        Path to the generated PDF file
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    filename  = f"CipherAudit_Report_{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path  = output_dir / filename

    styles = _build_styles()
    story  = []

    # 1. Cover page
    story += _build_cover(styles, scan_date, summary, len(rows))

    # 2. Executive summary table
    story.append(PageBreak())
    story += _build_executive_summary(styles, rows, summary)

    # 3. Per-domain details
    story.append(PageBreak())
    story += _build_domain_details(styles, rows)

    # 4. Compliance appendix
    story.append(PageBreak())
    story += _build_appendix(styles)

    doc = _ReportDoc(
        str(pdf_path),
        scan_date=scan_date,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=2.2 * cm,
        bottomMargin=1.8 * cm,
    )
    doc.build(story)

    logger.info("PDF report generated: %s", pdf_path)
    return pdf_path


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_cover(styles, scan_date: str, summary: dict, total_domains: int) -> list:
    """Dark cover page with summary counts."""
    story = []

    # Dark background rectangle drawn via a custom Flowable
    story.append(_CoverBackground())
    story.append(Spacer(1, 3 * cm))

    story.append(Paragraph("CipherAudit", styles["title"]))
    story.append(Paragraph("TLS &amp; PKI Certificate Compliance Report", styles["subtitle"]))
    story.append(Spacer(1, 0.6 * cm))
    story.append(HRFlowable(width="60%", thickness=1, color=COLOUR_ACCENT, spaceAfter=12))

    story.append(Paragraph(f"Scan Date: {scan_date}", styles["meta"]))
    story.append(Paragraph(f"Domains Scanned: {total_domains}", styles["meta"]))
    story.append(Paragraph("Standards: NIST SP 800-52 · PCI-DSS v4.0", styles["meta"]))
    story.append(Spacer(1, 1.5 * cm))

    # Severity summary boxes
    story.append(_build_cover_severity_table(summary))
    story.append(Spacer(1, 2 * cm))

    story.append(Paragraph("CONFIDENTIAL — Internal Use Only", styles["meta"]))
    story.append(Paragraph(
        "This report contains sensitive compliance findings. "
        "Do not distribute outside the security team.",
        styles["meta"],
    ))

    return story


def _build_cover_severity_table(summary: dict) -> Table:
    """Five-column severity summary strip for the cover page."""
    data = [[
        _severity_cell(label, summary.get(label, 0))
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    ]]
    t = Table(data, colWidths=[3.2 * cm] * 5, rowHeights=[2.5 * cm])
    t.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [4]),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _severity_cell(label: str, count: int) -> Table:
    """Single severity box used on the cover page."""
    colour = SEVERITY_COLOURS.get(label, COLOUR_UNKNOWN)
    inner  = Table(
        [[Paragraph(str(count), ParagraphStyle("sc_count", fontSize=22, alignment=TA_CENTER,
                                               fontName="Helvetica-Bold", textColor=COLOUR_WHITE))],
         [Paragraph(label, ParagraphStyle("sc_label", fontSize=7, alignment=TA_CENTER,
                                          fontName="Helvetica-Bold", textColor=COLOUR_WHITE))]],
        colWidths=[2.8 * cm],
    )
    inner.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), colour),
        ("ROUNDEDCORNERS", [4]),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return inner


def _build_executive_summary(styles, rows: list[dict], summary: dict) -> list:
    """Full-width table listing every domain with its severity."""
    story = []
    story.append(Paragraph("1. Executive Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_ACCENT, spaceAfter=8))
    story.append(Paragraph(
        "The table below presents the compliance status for all scanned domains. "
        "Findings are ordered by severity (CRITICAL first). "
        "Immediate remediation is required for any domain rated CRITICAL or HIGH.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.4 * cm))

    # Summary counts paragraph
    story.append(Paragraph(
        f"<b>Total Domains:</b> {len(rows)}  &nbsp;&nbsp; "
        f"<font color='#C0392B'><b>CRITICAL: {summary.get('CRITICAL', 0)}</b></font>  &nbsp;&nbsp; "
        f"<font color='#E67E22'><b>HIGH: {summary.get('HIGH', 0)}</b></font>  &nbsp;&nbsp; "
        f"MEDIUM: {summary.get('MEDIUM', 0)}  &nbsp;&nbsp; "
        f"<font color='#27AE60'>LOW: {summary.get('LOW', 0)}</font>",
        styles["body"],
    ))
    story.append(Spacer(1, 0.4 * cm))

    # Table
    header = ["#", "Domain", "Severity", "Days Left", "TLS Version", "Issuer"]
    table_data = [header]

    for i, row in enumerate(rows, start=1):
        severity  = row.get("severity", "UNKNOWN")
        days      = row.get("days_left")
        days_str  = str(days) if days is not None else "—"
        table_data.append([
            str(i),
            row.get("hostname", ""),
            severity,
            days_str,
            row.get("tls_version") or "—",
            (row.get("issuer") or "—")[:30],
        ])

    col_widths = [1 * cm, 5.5 * cm, 2.2 * cm, 2 * cm, 2.5 * cm, 4.3 * cm]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        # Header row
        ("BACKGROUND",    (0, 0), (-1, 0), COLOUR_HEADER),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COLOUR_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        # Data rows
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("ALIGN",         (0, 1), (0, -1), "CENTER"),   # row #
        ("ALIGN",         (2, 1), (2, -1), "CENTER"),   # severity
        ("ALIGN",         (3, 1), (3, -1), "RIGHT"),    # days
        ("ALIGN",         (4, 1), (4, -1), "CENTER"),   # TLS
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOUR_WHITE, COLOUR_ROW_ALT]),
    ]

    # Colour-code severity column per row
    for row_idx, row in enumerate(rows, start=1):
        sev = row.get("severity", "UNKNOWN")
        c   = SEVERITY_COLOURS.get(sev, COLOUR_UNKNOWN)
        style_cmds += [
            ("TEXTCOLOR",  (2, row_idx), (2, row_idx), c),
            ("FONTNAME",   (2, row_idx), (2, row_idx), "Helvetica-Bold"),
        ]
        if sev == "CRITICAL":
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#FDECEA")))
        elif sev == "HIGH":
            style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#FEF5E7")))

    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    return story


def _build_domain_details(styles, rows: list[dict]) -> list:
    """Per-domain detail cards — one card per host."""
    story = []
    story.append(Paragraph("2. Per-Domain Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_ACCENT, spaceAfter=8))
    story.append(Paragraph(
        "Each domain is presented with its full certificate metadata, "
        "TLS configuration details, compliance flags, and recommended actions.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.4 * cm))

    for row in rows:
        story.append(KeepTogether(_build_domain_card(styles, row)))
        story.append(Spacer(1, 0.3 * cm))

    return story


def _build_domain_card(styles, row: dict) -> list:
    """Single domain detail card."""
    severity = row.get("severity", "UNKNOWN")
    colour   = SEVERITY_COLOURS.get(severity, COLOUR_UNKNOWN)

    card = []

    # Domain header bar
    header_data = [[
        Paragraph(
            f"<font color='white'><b>{row.get('hostname', 'N/A')}</b></font>",
            ParagraphStyle("dh", fontSize=10, fontName="Helvetica-Bold",
                           textColor=COLOUR_WHITE, leading=14)
        ),
        Paragraph(
            f"<font color='white'><b>{severity}</b></font>",
            ParagraphStyle("ds", fontSize=10, fontName="Helvetica-Bold",
                           textColor=COLOUR_WHITE, alignment=TA_RIGHT, leading=14)
        ),
    ]]
    header_t = Table(header_data, colWidths=[12 * cm, 5.5 * cm])
    header_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colour),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    card.append(header_t)

    # Detail fields in a 2-column grid
    fields = [
        ("Issuer",        row.get("issuer") or "—"),
        ("Subject CN",    row.get("subject_cn") or "—"),
        ("Expiry Date",   row.get("expiry_date") or "—"),
        ("Days Remaining", str(row.get("days_left", "—"))),
        ("TLS Version",   row.get("tls_version") or "—"),
        ("Cipher Suite",  row.get("cipher_suite") or "—"),
        ("Serial Number", row.get("serial_number") or "—"),
        ("Severity",      severity),
    ]

    detail_data = []
    for i in range(0, len(fields), 2):
        row_cells = []
        for label, value in fields[i:i + 2]:
            row_cells.append(Paragraph(label, styles["label"]))
            row_cells.append(Paragraph(str(value)[:60], styles["value"]))
        if len(row_cells) < 4:
            row_cells += ["", ""]
        detail_data.append(row_cells)

    detail_t = Table(detail_data, colWidths=[2.5 * cm, 6 * cm, 2.5 * cm, 6.5 * cm])
    detail_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FAFAFA")),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#E0E0E0")),
    ]))
    card.append(detail_t)

    # Notes row
    notes = row.get("notes") or "No notes."
    notes_data = [[Paragraph("<b>Finding:</b> " + notes, styles["body_small"])]]
    notes_t = Table(notes_data, colWidths=[17.5 * cm])
    notes_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#F0F3F4")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    card.append(notes_t)

    return card


def _build_appendix(styles) -> list:
    """Compliance reference appendix with NIST SP 800-52 and PCI-DSS v4.0 citations."""
    story = []
    story.append(Paragraph("Appendix — Compliance Reference", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_ACCENT, spaceAfter=8))

    story.append(Paragraph("A. NIST SP 800-52 Rev 2 — Guidelines for TLS Implementations", styles["h2"]))

    nist_refs = [
        ("Section 3.1",    "TLS 1.2 is the minimum acceptable version for federal systems. "
                           "TLS 1.3 is strongly recommended."),
        ("Section 3.3.1",  "Cipher suites using RC4, DES, 3DES, NULL, EXPORT, or anonymous "
                           "key exchange are prohibited."),
        ("Section 3.4",    "Certificates must use RSA 2048-bit or ECDSA P-256 minimum key lengths."),
        ("Section 4.1",    "Certificates nearing expiry (< 30 days) must be renewed immediately "
                           "to avoid service disruption."),
        ("Section 4.2",    "Certificate issuers (CAs) must be from the approved CA list. "
                           "Self-signed certificates are prohibited in production."),
    ]

    for ref, desc in nist_refs:
        story.append(Paragraph(
            f"<b>{ref}</b> — {desc}",
            styles["compliance_ref"],
        ))
        story.append(Spacer(1, 0.2 * cm))

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("B. PCI-DSS v4.0 — Payment Card Industry Data Security Standard", styles["h2"]))

    pci_refs = [
        ("Requirement 4.2.1",
         "Strong cryptography must be used to safeguard PAN in transit. "
         "TLS 1.0 and 1.1 do not meet this requirement and must be disabled."),
        ("Requirement 4.2.1 (bullet 2)",
         "Only trusted keys and certificates must be accepted. "
         "Certificate expiry monitoring must be in place."),
        ("Requirement 6.3.3",
         "All software components must be protected from known vulnerabilities. "
         "Deprecated cipher suites constitute known vulnerabilities."),
        ("Requirement 12.3.3",
         "Cryptographic cipher suites must be reviewed at least annually "
         "and documented in the cryptographic inventory."),
        ("Requirement 12.3.4",
         "Hardware and software technologies must be reviewed annually to confirm "
         "they continue to receive security fixes from the vendor."),
    ]

    for ref, desc in pci_refs:
        story.append(Paragraph(
            f"<b>{ref}</b> — {desc}",
            styles["compliance_ref"],
        ))
        story.append(Spacer(1, 0.2 * cm))

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("C. Severity Classification Matrix", styles["h2"]))

    matrix_data = [
        ["Severity", "Condition", "Recommended Action", "SLA"],
        ["CRITICAL", "Certificate expired OR weak cipher in use",
         "Immediate remediation — escalate to security team", "24 hours"],
        ["HIGH", "Expires in < 30 days OR TLS 1.0/1.1 in use",
         "Urgent renewal or TLS upgrade required", "7 days"],
        ["MEDIUM", "Expires in 30–90 days",
         "Schedule certificate renewal", "30 days"],
        ["LOW", "Valid cert, TLS 1.2+, strong cipher",
         "No action required — monitor at next scan cycle", "N/A"],
    ]

    matrix_t = Table(matrix_data, colWidths=[2 * cm, 5.5 * cm, 6.5 * cm, 2 * cm])
    sev_colours_bg = {
        "CRITICAL": colors.HexColor("#FDECEA"),
        "HIGH":     colors.HexColor("#FEF5E7"),
        "MEDIUM":   colors.HexColor("#FEFDE7"),
        "LOW":      colors.HexColor("#EAFAF1"),
    }
    sev_text_col = {
        "CRITICAL": COLOUR_CRITICAL,
        "HIGH":     COLOUR_HIGH,
        "MEDIUM":   colors.HexColor("#B7950B"),
        "LOW":      COLOUR_LOW,
    }
    matrix_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), COLOUR_HEADER),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COLOUR_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
    ]
    for i, label in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"], start=1):
        matrix_cmds += [
            ("BACKGROUND", (0, i), (-1, i), sev_colours_bg[label]),
            ("TEXTCOLOR",  (0, i), (0,  i), sev_text_col[label]),
            ("FONTNAME",   (0, i), (0,  i), "Helvetica-Bold"),
        ]

    matrix_t.setStyle(TableStyle(matrix_cmds))
    story.append(matrix_t)

    return story


# ---------------------------------------------------------------------------
# Custom flowable — solid dark cover background
# ---------------------------------------------------------------------------

from reportlab.platypus import Flowable


class _CoverBackground(Flowable):
    """Draws the full dark background for the cover page."""

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(COLOUR_HEADER)
        # Fill entire page
        c.rect(-2 * cm, -2 * cm, 25 * cm, 32 * cm, fill=1, stroke=0)
        # Accent stripe
        c.setFillColor(COLOUR_ACCENT)
        c.rect(-2 * cm, 10.5 * cm, 25 * cm, 0.3 * cm, fill=1, stroke=0)
        c.restoreState()

    def wrap(self, available_width, available_height):
        return 0, 0


# ---------------------------------------------------------------------------
# Quick standalone test — run: python report.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    sample_rows = [
        {"hostname": "jpmorganchase.com",  "severity": "LOW",      "days_left": 210,
         "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
         "issuer": "DigiCert Inc", "subject_cn": "jpmorganchase.com",
         "expiry_date": "2026-10-01T00:00:00+00:00", "serial_number": "0A1B2C3D",
         "notes": "Valid certificate, TLS 1.3, strong cipher — compliant"},
        {"hostname": "expired.badssl.com", "severity": "CRITICAL", "days_left": -15,
         "tls_version": "TLSv1.2", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
         "issuer": "BadSSL", "subject_cn": "*.badssl.com",
         "expiry_date": "2024-01-01T00:00:00+00:00", "serial_number": "DEADBEEF",
         "notes": "Certificate has EXPIRED | Weak/deprecated cipher: 3DES"},
        {"hostname": "hsbc.com",            "severity": "MEDIUM",   "days_left": 45,
         "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
         "issuer": "GlobalSign", "subject_cn": "hsbc.com",
         "expiry_date": "2025-05-15T00:00:00+00:00", "serial_number": "11223344",
         "notes": "Certificate expires in 45 days — schedule renewal"},
        {"hostname": "oldbank.example.com", "severity": "HIGH",     "days_left": 120,
         "tls_version": "TLSv1.1", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
         "issuer": "Sectigo", "subject_cn": "oldbank.example.com",
         "expiry_date": "2025-08-01T00:00:00+00:00", "serial_number": "AABBCCDD",
         "notes": "Deprecated TLS version in use: TLSv1.1 (PCI-DSS requires TLS 1.2+)"},
    ]

    sample_summary = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0}

    pdf_path = generate_report(sample_rows, sample_summary)
    print(f"Test report generated: {pdf_path}")
