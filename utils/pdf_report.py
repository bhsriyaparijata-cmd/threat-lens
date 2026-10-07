
"""
pdf_report.py
--------------
Builds the downloadable "Forensic Report" PDF using ReportLab.

The report is generated from the combined analysis dictionary produced by
analyzer.run_full_analysis().

The report includes:
- Threat score
- Threat type
- AI classification
- Final verdict explanation
- Score explanation
- Multi-signal correlation
- URL intelligence
- Sender identity analysis
- SPF / DKIM / DMARC
- IP / GeoIP intelligence
- Attachment analysis
- Investigation recommendations
"""

from __future__ import annotations

import io
from datetime import datetime
from html import escape
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


DISCLAIMER = (
    "This report provides automated analysis and intelligence indicators. "
    "Results should be reviewed by a qualified security analyst before "
    "taking action."
)


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _styles():
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="H1Custom",
            parent=styles["Heading1"],
            textColor=colors.HexColor("#0B3D91"),
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="H2Custom",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#0B3D91"),
            spaceBefore=8,
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Evidence",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
        )
    )

    return styles


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe(value: Any) -> str:
    """
    Safely convert values to PDF-friendly text.
    """

    if value is None:
        return "-"

    text = str(value)

    if not text.strip():
        return "-"

    return escape(text)


def _kv_table(pairs, styles):
    data = [
        [
            Paragraph(
                f"<b>{_safe(k)}</b>",
                styles["BodySmall"],
            ),
            Paragraph(
                _safe(v),
                styles["BodySmall"],
            ),
        ]
        for k, v in pairs
    ]

    table = Table(
        data,
        colWidths=[
            4.5 * cm,
            11 * cm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#CCCCCC"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F0F4FA"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    return table


def _bullet_list(items, styles):
    """
    Create a safe bullet list.
    """

    if not items:
        return None

    return ListFlowable(
        [
            ListItem(
                Paragraph(
                    _safe(item),
                    styles["BodySmall"],
                )
            )
            for item in items
        ],
        bulletType="bullet",
    )


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

def build_pdf_report(result: Dict[str, Any]) -> bytes:

    styles = _styles()

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
    )

    story = []

    # -----------------------------------------------------------------------
    # Extract results
    # -----------------------------------------------------------------------

    record = result.get(
        "record",
        {},
    )

    ml = result.get(
        "ml_result",
        {},
    )

    threat = result.get(
        "threat",
        {},
    )

    sender = result.get(
        "sender_result",
        {},
    )

    auth = result.get(
        "auth_result",
        {},
    )

    url_results = result.get(
        "url_results",
        [],
    )

    geo_results = result.get(
        "geo_results",
        [],
    )

    attachment_results = result.get(
        "attachment_results",
        [],
    )

    # -----------------------------------------------------------------------
    # Title
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "AI-Powered Email Threat Detection, Geolocation and",
            styles["H1Custom"],
        )
    )

    story.append(
        Paragraph(
            "Forensic Intelligence Platform - Forensic Report",
            styles["H1Custom"],
        )
    )

    story.append(
        Paragraph(
            f"Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["BodySmall"],
        )
    )

    story.append(
        Spacer(
            1,
            0.5 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Executive threat summary
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Executive Threat Summary",
            styles["H2Custom"],
        )
    )

    threat_score = threat.get(
        "score",
        0,
    )

    risk_level = threat.get(
        "risk_level",
        "UNKNOWN",
    )

    threat_type = threat.get(
        "threat_type",
        "UNKNOWN",
    )

    story.append(
        _kv_table(
            [
                (
                    "Threat Score",
                    f"{threat_score} / 100",
                ),
                (
                    "Risk Level",
                    risk_level,
                ),
                (
                    "Threat Type",
                    threat_type,
                ),
                (
                    "Phishing Correlation",
                    "Detected"
                    if threat.get(
                        "phishing_detected",
                        False,
                    )
                    else "Not detected",
                ),
                (
                    "BEC / Impersonation Correlation",
                    "Detected"
                    if threat.get(
                        "bec_detected",
                        False,
                    )
                    else "Not detected",
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            0.2 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Explainable score breakdown
    # -----------------------------------------------------------------------

    score_breakdown = threat.get(
        "score_breakdown",
        [],
    )

    if score_breakdown:
        story.append(
            Paragraph(
                "Threat Score Breakdown",
                styles["H2Custom"],
            )
        )

        breakdown_rows = [
            [
                Paragraph("<b>Signal</b>", styles["BodySmall"]),
                Paragraph("<b>Points</b>", styles["BodySmall"]),
                Paragraph("<b>Reason</b>", styles["BodySmall"]),
            ]
        ]

        for item in score_breakdown:
            breakdown_rows.append(
                [
                    Paragraph(
                        _safe(item.get("signal", "Unknown")),
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f"+{_safe(item.get('points', 0))}",
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        _safe(item.get("reason", "")),
                        styles["BodySmall"],
                    ),
                ]
            )

        breakdown_table = Table(
            breakdown_rows,
            colWidths=[
                4.2 * cm,
                2.0 * cm,
                9.3 * cm,
            ],
        )

        breakdown_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0F4FA")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        story.append(breakdown_table)

        story.append(
            Paragraph(
                f"<b>Total Threat Score: {threat_score}/100</b>",
                styles["BodySmall"],
            )
        )

        story.append(
            Spacer(
                1,
                0.4 * cm,
            )
        )

    # -----------------------------------------------------------------------
    # Email metadata
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Email Metadata",
            styles["H2Custom"],
        )
    )

    story.append(
        _kv_table(
            [
                (
                    "Subject",
                    record.get(
                        "subject",
                        "",
                    ),
                ),
                (
                    "From",
                    record.get(
                        "from",
                        "",
                    ),
                ),
                (
                    "Display Name",
                    record.get(
                        "from_display_name",
                        "",
                    ),
                ),
                (
                    "To",
                    record.get(
                        "to",
                        "",
                    ),
                ),
                (
                    "Date",
                    record.get(
                        "date",
                        "",
                    ),
                ),
                (
                    "Reply-To",
                    record.get(
                        "reply_to",
                        "",
                    ),
                ),
                (
                    "Return-Path",
                    record.get(
                        "return_path",
                        "",
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # AI classification
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "AI Email Classification",
            styles["H2Custom"],
        )
    )

    story.append(
        _kv_table(
            [
                (
                    "Prediction",
                    ml.get(
                        "prediction",
                        "UNKNOWN",
                    ),
                ),
                (
                    "Confidence",
                    f"{ml.get('confidence', 0)}%",
                ),
                (
                    "Method",
                    "TF-IDF features + Multinomial "
                    "Naive Bayes (trained on SpamAssassin "
                    "Public Corpus)",
                ),
                (
                    "Note",
                    ml.get(
                        "note",
                        "",
                    )
                    or "-",
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Final verdict explanation
    # -----------------------------------------------------------------------

    verdict_explanation = threat.get(
        "verdict_explanation",
        "",
    )

    if verdict_explanation:

        story.append(
            Paragraph(
                "Final Verdict Explanation",
                styles["H2Custom"],
            )
        )

        story.append(
            Paragraph(
                _safe(verdict_explanation),
                styles["BodySmall"],
            )
        )

        story.append(
            Spacer(
                1,
                0.4 * cm,
            )
        )

    # -----------------------------------------------------------------------
    # URL analysis
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "URL Threat Intelligence",
            styles["H2Custom"],
        )
    )

    if url_results:

        for u in url_results:

            story.append(
                Paragraph(
                    f"<b>{_safe(u.get('url', ''))}</b>",
                    styles["BodySmall"],
                )
            )

            story.append(
                _kv_table(
                    [
                        (
                            "Domain",
                            u.get(
                                "domain",
                                "",
                            ),
                        ),
                        (
                            "Risk",
                            u.get(
                                "risk",
                                "Unknown",
                            ),
                        ),
                        (
                            "HTTPS",
                            u.get(
                                "https",
                                False,
                            ),
                        ),
                        (
                            "IP Based",
                            u.get(
                                "ip_based",
                                False,
                            ),
                        ),
                        (
                            "Threat Intelligence",
                            u.get(
                                "threat_intel",
                                "N/A",
                            ),
                        ),
                        (
                            "Typosquat Brand",
                            u.get(
                                "typosquat_brand",
                                None,
                            )
                            or "None detected",
                        ),
                        (
                            "Brand Impersonation",
                            u.get(
                                "impersonated_brand",
                                None,
                            )
                            or "None detected",
                        ),
                        (
                            "Redirect Parameters",
                            u.get(
                                "has_redirect_parameters",
                                False,
                            ),
                        ),
                        (
                            "Credential Parameters",
                            u.get(
                                "has_credential_parameters",
                                False,
                            ),
                        ),
                    ],
                    styles,
                )
            )

            indicators = u.get(
                "indicators",
                [],
            )

            if indicators:

                story.append(
                    Paragraph(
                        "<b>Indicators</b>",
                        styles["BodySmall"],
                    )
                )

                bullet_block = _bullet_list(
                    indicators,
                    styles,
                )

                if bullet_block:
                    story.append(
                        bullet_block
                    )

            url_evidence = u.get(
                "evidence",
                [],
            )

            if url_evidence:

                story.append(
                    Paragraph(
                        "<b>URL Evidence</b>",
                        styles["BodySmall"],
                    )
                )

                bullet_block = _bullet_list(
                    url_evidence,
                    styles,
                )

                if bullet_block:
                    story.append(
                        bullet_block
                    )

            story.append(
                Spacer(
                    1,
                    0.25 * cm,
                )
            )

    else:

        story.append(
            Paragraph(
                "No URLs were detected in this email.",
                styles["BodySmall"],
            )
        )

    story.append(
        Spacer(
            1,
            0.3 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Sender analysis
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Sender Identity Analysis",
            styles["H2Custom"],
        )
    )

    story.append(
        _kv_table(
            [
                (
                    "Sender Risk",
                    sender.get(
                        "risk",
                        "Unknown",
                    ),
                ),
                (
                    "Identity Type",
                    sender.get(
                        "identity_type",
                        "Unknown",
                    ),
                ),
                (
                    "From Domain",
                    sender.get(
                        "from_domain",
                        "",
                    ),
                ),
                (
                    "Reply-To",
                    sender.get(
                        "reply_to",
                        "",
                    ),
                ),
                (
                    "Return-Path",
                    sender.get(
                        "return_path",
                        "",
                    ),
                ),
                (
                    "Free Email Provider",
                    "Yes"
                    if sender.get(
                        "is_free_email_provider",
                        False,
                    )
                    else "No",
                ),
            ],
            styles,
        )
    )

    sender_reasons = sender.get(
        "reasons",
        [],
    )

    if sender_reasons:

        story.append(
            Paragraph(
                "<b>Sender Indicators</b>",
                styles["BodySmall"],
            )
        )

        bullet_block = _bullet_list(
            sender_reasons,
            styles,
        )

        if bullet_block:
            story.append(
                bullet_block
            )

    sender_evidence = sender.get(
        "evidence",
        [],
    )

    if sender_evidence:

        story.append(
            Paragraph(
                "<b>Identity Evidence</b>",
                styles["BodySmall"],
            )
        )

        bullet_block = _bullet_list(
            sender_evidence,
            styles,
        )

        if bullet_block:
            story.append(
                bullet_block
            )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "SPF / DKIM / DMARC",
            styles["H2Custom"],
        )
    )

    story.append(
        _kv_table(
            [
                (
                    "SPF",
                    auth.get(
                        "spf",
                        "UNKNOWN",
                    ),
                ),
                (
                    "DKIM",
                    auth.get(
                        "dkim",
                        "UNKNOWN",
                    ),
                ),
                (
                    "DMARC",
                    auth.get(
                        "dmarc",
                        "UNKNOWN",
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # IP / GeoIP
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "IP / Network Intelligence",
            styles["H2Custom"],
        )
    )

    if geo_results:

        for g in geo_results:

            story.append(
                Paragraph(
                    f"{_safe(g.get('ip', ''))} - "
                    f"{_safe(g.get('city', ''))}, "
                    f"{_safe(g.get('region', ''))}, "
                    f"{_safe(g.get('country', ''))} "
                    f"(ISP: {_safe(g.get('isp', ''))}, "
                    f"ASN: {_safe(g.get('asn', ''))}) "
                    f"[{_safe(g.get('source', ''))}]",
                    styles["BodySmall"],
                )
            )

    else:

        story.append(
            Paragraph(
                "No public IP addresses were found in "
                "the Received headers.",
                styles["BodySmall"],
            )
        )

    story.append(
        Spacer(
            1,
            0.15 * cm,
        )
    )

    story.append(
        Paragraph(
            "IP geolocation provides approximate network/location "
            "information and does not identify the attacker's exact "
            "physical location.",
            styles["BodySmall"],
        )
    )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Attachments
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Attachment Analysis",
            styles["H2Custom"],
        )
    )

    if attachment_results:

        for a in attachment_results:

            vt = a.get(
                "virustotal",
                {},
            )

            story.append(
                Paragraph(
                    f"<b>{_safe(a.get('filename', 'Unknown'))}</b> "
                    f"({_safe(a.get('size_human', ''))}, "
                    f"{_safe(a.get('content_type', ''))}) "
                    f"- Risk: {_safe(a.get('risk', 'Unknown'))}<br/>"
                    f"SHA-256: {_safe(a.get('sha256', ''))}<br/>"
                    f"VirusTotal: "
                    f"{_safe(vt.get('verdict', 'N/A'))}",
                    styles["BodySmall"],
                )
            )

            attachment_indicators = a.get(
                "indicators",
                [],
            )

            if attachment_indicators:

                bullet_block = _bullet_list(
                    attachment_indicators,
                    styles,
                )

                if bullet_block:
                    story.append(
                        bullet_block
                    )

    else:

        story.append(
            Paragraph(
                "No attachments were found in this email.",
                styles["BodySmall"],
            )
        )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Multi-signal correlation
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Multi-Signal Threat Correlation",
            styles["H2Custom"],
        )
    )

    phishing_detected = threat.get(
        "phishing_detected",
        False,
    )

    bec_detected = threat.get(
        "bec_detected",
        False,
    )

    correlation_status = []

    if phishing_detected:
        correlation_status.append(
            "PHISHING correlation detected"
        )

    if bec_detected:
        correlation_status.append(
            "BEC / impersonation correlation detected"
        )

    if not correlation_status:
        correlation_status.append(
            "No strong multi-signal correlation detected"
        )

    story.append(
        _kv_table(
            [
                (
                    "Correlation Result",
                    " | ".join(
                        correlation_status
                    ),
                ),
            ],
            styles,
        )
    )

    phishing_evidence = threat.get(
        "phishing_evidence",
        [],
    )

    if phishing_evidence:

        story.append(
            Paragraph(
                "<b>Phishing Correlation Evidence</b>",
                styles["BodySmall"],
            )
        )

        bullet_block = _bullet_list(
            phishing_evidence,
            styles,
        )

        if bullet_block:
            story.append(
                bullet_block
            )

    bec_evidence = threat.get(
        "bec_evidence",
        [],
    )

    if bec_evidence:

        story.append(
            Paragraph(
                "<b>BEC / Impersonation Evidence</b>",
                styles["BodySmall"],
            )
        )

        bullet_block = _bullet_list(
            bec_evidence,
            styles,
        )

        if bullet_block:
            story.append(
                bullet_block
            )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Threat score explanation
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Threat Score Evidence",
            styles["H2Custom"],
        )
    )

    reasons = threat.get(
        "reasons",
        [],
    )

    if reasons:

        bullet_block = _bullet_list(
            reasons,
            styles,
        )

        if bullet_block:
            story.append(
                bullet_block
            )

    else:

        story.append(
            Paragraph(
                "No significant scoring reasons were recorded.",
                styles["BodySmall"],
            )
        )

    # -----------------------------------------------------------------------
    # Investigation recommendations
    # -----------------------------------------------------------------------

    investigate = threat.get(
        "investigate_further",
        [],
    )

    if investigate:

        story.append(
            Paragraph(
                "Recommended Further Investigation",
                styles["H2Custom"],
            )
        )

        bullet_block = _bullet_list(
            investigate,
            styles,
        )

        if bullet_block:
            story.append(
                bullet_block
            )

    story.append(
        Spacer(
            1,
            0.5 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Final analyst summary
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Analyst Summary",
            styles["H2Custom"],
        )
    )

    summary = (
        f"The analysis produced a threat score of "
        f"{threat_score}/100 with a risk classification of "
        f"{risk_level}. The final automated threat assessment is "
        f"{threat_type}. This conclusion is based on multiple "
        f"available signals including email content, sender identity, "
        f"URLs, authentication results, attachments and threat "
        f"intelligence where available."
    )

    story.append(
        Paragraph(
            summary,
            styles["BodySmall"],
        )
    )

    story.append(
        Spacer(
            1,
            0.4 * cm,
        )
    )

    # -----------------------------------------------------------------------
    # Disclaimer
    # -----------------------------------------------------------------------

    story.append(
        Paragraph(
            "Disclaimer",
            styles["H2Custom"],
        )
    )

    story.append(
        Paragraph(
            DISCLAIMER,
            styles["BodySmall"],
        )
    )

    # -----------------------------------------------------------------------
    # Build PDF
    # -----------------------------------------------------------------------

    doc.build(
        story
    )

    buffer.seek(0)

    return buffer.read()
