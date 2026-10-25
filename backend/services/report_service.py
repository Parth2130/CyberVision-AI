"""
CyberVision AI – Report Generation Service
Produces downloadable CSV, JSON, and professional PDF summary reports using ReportLab.
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime
from typing import Any, Dict

import pandas as pd

logger = logging.getLogger("cybervision.report_service")


def generate_csv(df: pd.DataFrame, filtered: bool = False) -> bytes:
    """
    Generate CSV file bytes from a DataFrame.
    """
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    return buffer.getvalue().encode("utf-8")


def generate_json(analysis_data: Dict[str, Any]) -> str:
    """
    Serialize analysis data to formatted JSON string.
    """
    return json.dumps(analysis_data, indent=2, default=str)


def generate_pdf(analysis_data: Dict[str, Any], include_charts: bool = True) -> bytes:
    """
    Generate a professional multi-page cybersecurity analytics PDF report using ReportLab.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import inch

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        # Custom palette colors
        primary_blue = colors.HexColor("#4776E6")
        secondary_purple = colors.HexColor("#8B5CF6")
        text_navy = colors.HexColor("#23345D")
        bg_light = colors.HexColor("#F4F8FF")

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=primary_blue,
        )

        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#64748B"),
        )

        heading2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=text_navy,
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=text_navy,
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("CyberVision AI 🛡️", title_style))
        story.append(Paragraph("Automated Cybersecurity Analytics & Threat Report", subtitle_style))
        story.append(Spacer(1, 4))
        gen_time = datetime.now().strftime("%B %d, %Y - %H:%M:%S")
        story.append(Paragraph(f"Generated on: <b>{gen_time}</b> | Status: <b>Analysis Complete</b>", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=2, color=primary_blue, spaceBefore=0, spaceAfter=14))

        # 2. Executive Summary Metrics
        story.append(Paragraph("Executive Summary & Core Metrics", heading2_style))
        summary = analysis_data.get("summary", {})
        total_recs = summary.get("total_records", 0)
        normal_recs = summary.get("normal_records", 0)
        attack_recs = summary.get("attack_records", 0)
        anomalies = summary.get("potential_anomalies", 0)
        categories_count = summary.get("unique_categories", 0)

        summary_table_data = [
            ["Metric", "Count", "Percentage / Details"],
            ["Total Records Analyzed", f"{total_recs:,}", "100.0%"],
            ["Normal / Legitimate Records", f"{normal_recs:,}", f"{(normal_recs / total_recs * 100 if total_recs else 0):.1f}%"],
            ["Identified Attack Records", f"{attack_recs:,}", f"{(attack_recs / total_recs * 100 if total_recs else 0):.1f}%"],
            ["Potential Anomalies Flagged", f"{anomalies:,}", f"{(anomalies / total_recs * 100 if total_recs else 0):.1f}% of dataset"],
            ["Distinct Threat Categories", str(categories_count), "Identified event signatures"],
        ]

        t_summary = Table(summary_table_data, colWidths=[200, 140, 200])
        t_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), primary_blue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("BACKGROUND", (0, 1), (-1, -1), bg_light),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 15))

        # 3. Category Breakdown
        story.append(Paragraph("Threat Category Breakdown", heading2_style))
        categories = analysis_data.get("categories", {}).get("distribution", {})
        cat_rows = [["Attack / Event Category", "Occurrences", "Percentage Share"]]
        for cat, cnt in list(categories.items())[:8]:
            pct = (cnt / total_recs * 100) if total_recs else 0
            cat_rows.append([str(cat), f"{cnt:,}", f"{pct:.2f}%"])

        t_cat = Table(cat_rows, colWidths=[240, 150, 150])
        t_cat.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), secondary_purple),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ]))
        story.append(t_cat)
        story.append(Spacer(1, 15))

        # 4. Severity Distribution
        story.append(Paragraph("Severity Profile", heading2_style))
        sev_dist = analysis_data.get("severity", {}).get("distribution", {})
        sev_rows = [
            ["Severity Level", "Record Count", "Risk Assessment"],
            ["Critical", f"{sev_dist.get('Critical', 0):,}", "Immediate remediation required"],
            ["High", f"{sev_dist.get('High', 0):,}", "Active threat investigation priority"],
            ["Medium", f"{sev_dist.get('Medium', 0):,}", "Routine review & perimeter check"],
            ["Low", f"{sev_dist.get('Low', 0):,}", "Informational / Standard activity"],
        ]
        t_sev = Table(sev_rows, colWidths=[140, 160, 240])
        t_sev.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), text_navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ]))
        story.append(t_sev)
        story.append(Spacer(1, 15))

        # 5. Top Source Addresses
        story.append(Paragraph("Top Threat Origin Addresses (Source IPs)", heading2_style))
        top_ips = analysis_data.get("source_ips", {}).get("top_10", [])[:5]
        ip_rows = [["Source IP Address", "Observed Events", "Activity Density"]]
        for item in top_ips:
            ip = item.get("ip", "N/A")
            cnt = item.get("count", 0)
            density = f"{(cnt / total_recs * 100):.1f}% of total" if total_recs else "N/A"
            ip_rows.append([ip, f"{cnt:,}", density])

        t_ip = Table(ip_rows, colWidths=[200, 160, 180])
        t_ip.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#22C7D9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), text_navy),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ]))
        story.append(t_ip)
        story.append(Spacer(1, 20))

        # Footer note
        story.append(Paragraph(
            "<b>Disclaimer:</b> CyberVision AI analyzes uploaded offline datasets and does not directly monitor production infrastructure. Anomalies represent deviations from baseline statistical patterns.",
            subtitle_style,
        ))

        doc.build(story)
        return buffer.getvalue()

    except Exception as exc:
        logger.error("Failed to build PDF with ReportLab: %s, falling back to minimal PDF", exc)
        return _fallback_minimal_pdf(analysis_data)


def _fallback_minimal_pdf(analysis_data: Dict[str, Any]) -> bytes:
    """Generate a minimal ASCII PDF in case reportlab is unavailable."""
    summary = analysis_data.get("summary", {})
    text = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 200 >> stream
BT
/F1 16 Tf
50 720 Td (CyberVision AI - Cybersecurity Report) Tj
/F1 12 Tf
0 -30 Td (Total Records: {summary.get('total_records', 0)}) Tj
0 -20 Td (Normal Records: {summary.get('normal_records', 0)}) Tj
0 -20 Td (Attack Records: {summary.get('attack_records', 0)}) Tj
0 -20 Td (Potential Anomalies: {summary.get('potential_anomalies', 0)}) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000495 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
570
%%EOF"""
    return text.encode("utf-8")
