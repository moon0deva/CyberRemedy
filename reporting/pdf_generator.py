"""
CyberRemedy — PDF Report Generator
====================================
Generates professional PDF reports using ReportLab (free, no API keys).
Install: pip install reportlab --break-system-packages

Exports:
  - Executive Summary PDF
  - Threat Intelligence Report
  - Compliance Assessment PDF
  - Incident Report PDF
  - Vulnerability Report PDF
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("cyberremedy.reporting.pdf")

_REPORTLAB_OK = False
try:
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib.colors import (
        HexColor, Color, black, white, red, green, orange
    )
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    _REPORTLAB_OK = True
except ImportError:
    logger.warning(
        "[PDF] reportlab not installed — PDF export disabled. "
        "Fix: pip install reportlab --break-system-packages"
    )

# ── Colour palette ─────────────────────────────────────────────────────────────
C_DARK     = HexColor("#0a0e1a") if _REPORTLAB_OK else None
C_BLUE     = HexColor("#00e5ff") if _REPORTLAB_OK else None
C_GREEN    = HexColor("#39ff14") if _REPORTLAB_OK else None
C_RED      = HexColor("#ff1744") if _REPORTLAB_OK else None
C_ORANGE   = HexColor("#ff9800") if _REPORTLAB_OK else None
C_YELLOW   = HexColor("#ffeb3b") if _REPORTLAB_OK else None
C_GREY     = HexColor("#78909c") if _REPORTLAB_OK else None
C_LIGHTBG  = HexColor("#0d1729") if _REPORTLAB_OK else None
C_HEADER   = HexColor("#001233") if _REPORTLAB_OK else None

REPORT_DIR = Path("data/reports")


def _severity_color(sev: str):
    if not _REPORTLAB_OK:
        return None
    s = sev.upper()
    return {
        "CRITICAL": C_RED, "HIGH": C_ORANGE,
        "MEDIUM": C_YELLOW, "LOW": C_GREEN,
    }.get(s, C_GREY)


def _get_styles():
    styles = getSampleStyleSheet()
    custom = {
        "title": ParagraphStyle("CRTitle", parent=styles["Normal"],
            fontSize=24, fontName="Helvetica-Bold",
            textColor=C_BLUE, spaceAfter=6, alignment=TA_CENTER),
        "subtitle": ParagraphStyle("CRSubtitle", parent=styles["Normal"],
            fontSize=12, fontName="Helvetica",
            textColor=C_GREY, spaceAfter=20, alignment=TA_CENTER),
        "h1": ParagraphStyle("CRH1", parent=styles["Normal"],
            fontSize=16, fontName="Helvetica-Bold",
            textColor=C_BLUE, spaceBefore=16, spaceAfter=8),
        "h2": ParagraphStyle("CRH2", parent=styles["Normal"],
            fontSize=12, fontName="Helvetica-Bold",
            textColor=C_BLUE, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("CRBody", parent=styles["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=black, spaceAfter=4, leading=14),
        "mono": ParagraphStyle("CRMono", parent=styles["Normal"],
            fontSize=8, fontName="Courier",
            textColor=HexColor("#1a237e") if _REPORTLAB_OK else black,
            spaceAfter=2),
        "kv_label": ParagraphStyle("CRKVLabel", parent=styles["Normal"],
            fontSize=9, fontName="Helvetica-Bold",
            textColor=C_GREY, spaceAfter=2),
        "kv_value": ParagraphStyle("CRKVValue", parent=styles["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=black, spaceAfter=4),
        "footer": ParagraphStyle("CRFooter", parent=styles["Normal"],
            fontSize=7, fontName="Helvetica",
            textColor=C_GREY, alignment=TA_CENTER),
    }
    return custom


def _table_style(header_color=None):
    hc = header_color or C_HEADER
    return TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), hc),
        ("TEXTCOLOR",   (0,0), (-1,0), C_BLUE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,0), 9),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,1), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, HexColor("#f5f5f5")]),
        ("GRID",        (0,0), (-1,-1), 0.3, C_GREY),
        ("ALIGN",       (0,0), (-1,-1), "LEFT"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
    ])


LOGO_PATH = Path("static/logo.png")


def _header_footer(canvas, doc, title: str, generated: str):
    """Draw page header and footer on every page."""
    canvas.saveState()
    w, h = A4
    # Header bar
    canvas.setFillColor(C_HEADER)
    canvas.rect(0, h-40, w, 40, fill=1, stroke=0)
    # Draw custom logo if available, else use text
    logo_x = 12
    if LOGO_PATH.exists():
        try:
            from reportlab.lib.utils import ImageReader
            logo_img = ImageReader(str(LOGO_PATH))
            canvas.drawImage(logo_img, logo_x, h-34, width=24, height=24,
                             preserveAspectRatio=True, mask="auto")
            logo_x = 42
        except Exception:
            pass
    canvas.setFillColor(C_BLUE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(logo_x, h-25, "CyberRemedy SOC Platform")
    canvas.setFillColor(C_GREY)
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(w-30, h-25, title)

    # Footer
    canvas.setFillColor(C_HEADER)
    canvas.rect(0, 0, w, 25, fill=1, stroke=0)
    canvas.setFillColor(C_GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(30, 8, f"Generated: {generated}  |  CONFIDENTIAL — FOR AUTHORIZED USE ONLY")
    canvas.drawRightString(w-30, 8, f"Page {doc.page}")
    canvas.restoreState()


# ── Executive Summary ──────────────────────────────────────────────────────────

def generate_executive_summary(
    alerts: List[dict],
    cases: List[dict],
    blocked: List[dict],
    pipeline_state: dict,
    output_path: Path = None,
) -> Path:
    """Generate a 1-2 page executive summary PDF."""
    if not _REPORTLAB_OK:
        raise RuntimeError("reportlab not installed — run: pip install reportlab --break-system-packages")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORT_DIR / f"executive_summary_{ts}.pdf"

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    styles = _get_styles()

    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=1.8*cm, bottomMargin=1.5*cm)

    story = []

    # Cover
    story.append(Spacer(1, 30))
    story.append(Paragraph("CyberRemedy SOC Platform", styles["title"]))
    story.append(Paragraph("Executive Security Summary", styles["subtitle"]))
    story.append(Paragraph(f"Generated: {generated}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=20))

    # KPI tiles
    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for a in alerts:
        sev_counts[a.get("severity","LOW")] = sev_counts.get(a.get("severity","LOW"),0) + 1

    kpi_data = [
        ["Total Alerts", "Critical", "High", "Cases", "Blocked IPs"],
        [
            str(len(alerts)),
            str(sev_counts.get("CRITICAL",0)),
            str(sev_counts.get("HIGH",0)),
            str(len(cases)),
            str(len(blocked)),
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[3.2*cm]*5)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_HEADER),
        ("TEXTCOLOR",     (0,0), (-1,0), C_GREY),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 8),
        ("BACKGROUND",    (0,1), (0,1), HexColor("#e3f2fd")),
        ("BACKGROUND",    (1,1), (1,1), HexColor("#ffebee")),
        ("BACKGROUND",    (2,1), (2,1), HexColor("#fff3e0")),
        ("BACKGROUND",    (3,1), (3,1), HexColor("#e8f5e9")),
        ("BACKGROUND",    (4,1), (4,1), HexColor("#fce4ec")),
        ("FONTNAME",      (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,1), (-1,1), 18),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,1), (-1,1), 12),
        ("BOTTOMPADDING", (0,1), (-1,1), 12),
        ("GRID",          (0,0), (-1,-1), 0.5, C_GREY),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 20))

    # Alert severity breakdown
    story.append(Paragraph("Alert Severity Distribution", styles["h1"]))
    sev_table_data = [["Severity", "Count", "% of Total"]]
    total_alerts = max(len(alerts), 1)
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        cnt = sev_counts.get(sev, 0)
        sev_table_data.append([sev, str(cnt), f"{cnt/total_alerts*100:.1f}%"])
    sev_table = Table(sev_table_data, colWidths=[5*cm, 3*cm, 4*cm])
    sev_table.setStyle(_table_style())
    story.append(sev_table)
    story.append(Spacer(1, 12))

    # Recent high-severity alerts
    story.append(Paragraph("Recent High-Severity Alerts (Top 10)", styles["h1"]))
    recent = sorted([a for a in alerts if a.get("severity") in ("CRITICAL","HIGH")],
                    key=lambda x: x.get("timestamp",""), reverse=True)[:10]
    if recent:
        alert_data = [["Time", "Severity", "Type", "Source IP", "MITRE"]]
        for a in recent:
            ts_short = (a.get("timestamp","")[:16]).replace("T"," ")
            alert_data.append([
                ts_short,
                a.get("severity","?"),
                (a.get("type","?"))[:30],
                a.get("src_ip","?"),
                a.get("mitre_id","—"),
            ])
        alert_table = Table(alert_data, colWidths=[3*cm, 2*cm, 5*cm, 3.5*cm, 2.5*cm])
        alert_table.setStyle(_table_style())
        story.append(alert_table)
    else:
        story.append(Paragraph("No high-severity alerts in this period.", styles["body"]))
    story.append(Spacer(1, 12))

    # Pipeline status
    story.append(Paragraph("Detection Pipeline Status", styles["h1"]))
    status_data = [
        ["Component", "Status"],
        ["Live Capture", "● ACTIVE" if pipeline_state.get("running") else "○ STOPPED"],
        ["Packets Processed", f"{pipeline_state.get('packets_processed',0):,}"],
        ["Flows Analyzed", f"{pipeline_state.get('flows_analyzed',0):,}"],
        ["Total Alerts Generated", f"{pipeline_state.get('alerts_total',0):,}"],
        ["Cases Created", str(len(cases))],
        ["IPs Blocked", str(len(blocked))],
    ]
    status_table = Table(status_data, colWidths=[8*cm, 8*cm])
    status_table.setStyle(_table_style())
    story.append(status_table)

    def _header_footer_fn(canvas, doc):
        _header_footer(canvas, doc, "Executive Summary", generated)

    doc.build(story, onFirstPage=_header_footer_fn, onLaterPages=_header_footer_fn)
    logger.info(f"Executive summary PDF: {output_path}")
    return output_path


# ── Threat Intelligence Report ─────────────────────────────────────────────────

def generate_threat_intel_report(
    ioc_stats: dict,
    feed_status: List[dict],
    top_iocs: List[dict],
    output_path: Path = None,
) -> Path:
    if not _REPORTLAB_OK:
        raise RuntimeError("reportlab not installed")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORT_DIR / f"threat_intel_{ts}.pdf"

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    styles = _get_styles()
    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=1.8*cm, bottomMargin=1.5*cm)
    story = []

    story.append(Spacer(1, 20))
    story.append(Paragraph("Threat Intelligence Report", styles["title"]))
    story.append(Paragraph(f"Generated: {generated}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=20))

    # IOC counts
    story.append(Paragraph("IOC Database Summary", styles["h1"]))
    ioc_data = [
        ["Type", "Count"],
        ["Malicious IPs",     str(ioc_stats.get("ips",0))],
        ["Malicious Domains",  str(ioc_stats.get("domains",0))],
        ["Malicious Hashes",   str(ioc_stats.get("hashes",0))],
        ["Malicious URLs",     str(ioc_stats.get("urls",0))],
        ["Total IOCs",         str(ioc_stats.get("total",0))],
    ]
    t = Table(ioc_data, colWidths=[8*cm, 8*cm])
    t.setStyle(_table_style())
    story.append(t)
    story.append(Spacer(1, 12))

    # Feed status
    if feed_status:
        story.append(Paragraph("Threat Feed Status", styles["h1"]))
        feed_data = [["Feed Name", "Status", "Last Updated"]]
        for f in feed_status[:20]:
            feed_data.append([
                f.get("name","?")[:30],
                "✓ OK" if f.get("ok") else "✗ FAILED",
                (f.get("last_updated","never"))[:16],
            ])
        ft = Table(feed_data, colWidths=[8*cm, 3*cm, 5*cm])
        ft.setStyle(_table_style())
        story.append(ft)
        story.append(Spacer(1, 12))

    # Top IOCs
    if top_iocs:
        story.append(Paragraph("Recent High-Confidence IOCs", styles["h1"]))
        ioc_header = [["Type", "Value", "Severity", "Tags"]]
        rows = []
        for ioc in top_iocs[:25]:
            rows.append([
                ioc.get("ioc_type","?"),
                (ioc.get("value",""))[:35],
                ioc.get("severity","?"),
                ", ".join(ioc.get("tags",[]))[:30],
            ])
        ioc_table_data = ioc_header + rows
        it = Table(ioc_table_data, colWidths=[2*cm, 6*cm, 2.5*cm, 5.5*cm])
        it.setStyle(_table_style())
        story.append(it)

    def _hf(canvas, doc):
        _header_footer(canvas, doc, "Threat Intelligence Report", generated)

    doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
    logger.info(f"Threat intel PDF: {output_path}")
    return output_path


# ── Vulnerability Report ───────────────────────────────────────────────────────

def generate_vuln_report(
    findings: List[dict],
    stats: dict,
    output_path: Path = None,
) -> Path:
    if not _REPORTLAB_OK:
        raise RuntimeError("reportlab not installed")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORT_DIR / f"vuln_report_{ts}.pdf"

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    styles = _get_styles()
    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=1.8*cm, bottomMargin=1.5*cm)
    story = []

    story.append(Spacer(1, 20))
    story.append(Paragraph("Vulnerability Assessment Report", styles["title"]))
    story.append(Paragraph(f"Generated: {generated}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=20))

    story.append(Paragraph("Summary", styles["h1"]))
    sev = stats.get("by_severity", {})
    sum_data = [
        ["Metric", "Value"],
        ["Total CVEs in Database", str(stats.get("total_cves",0))],
        ["Findings (across assets)", str(stats.get("total_findings",0))],
        ["Assets Scanned", str(stats.get("assets_scanned",0))],
        ["Critical Findings", str(sev.get("CRITICAL",0))],
        ["High Findings", str(sev.get("HIGH",0))],
    ]
    st = Table(sum_data, colWidths=[8*cm, 8*cm])
    st.setStyle(_table_style())
    story.append(st)
    story.append(Spacer(1, 12))

    if findings:
        story.append(Paragraph("Top Vulnerability Findings", styles["h1"]))
        f_header = [["CVE ID", "CVSS", "Severity", "Asset IP", "Matched Software"]]
        rows = []
        for f in sorted(findings, key=lambda x: x.get("cvss_score",0), reverse=True)[:30]:
            rows.append([
                f.get("cve_id","?"),
                str(f.get("cvss_score","?")),
                f.get("severity","?"),
                f.get("asset_ip","?"),
                (f.get("matched_software","?"))[:25],
            ])
        ft = Table(f_header + rows, colWidths=[3*cm, 1.5*cm, 2*cm, 3.5*cm, 6*cm])
        ft.setStyle(_table_style())
        story.append(ft)

    def _hf(canvas, doc):
        _header_footer(canvas, doc, "Vulnerability Report", generated)

    doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
    logger.info(f"Vuln report PDF: {output_path}")
    return output_path


# ── Compliance Report ──────────────────────────────────────────────────────────

def generate_compliance_report(
    framework_results: dict,
    output_path: Path = None,
) -> Path:
    if not _REPORTLAB_OK:
        raise RuntimeError("reportlab not installed")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORT_DIR / f"compliance_report_{ts}.pdf"

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    styles = _get_styles()
    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=1.8*cm, bottomMargin=1.5*cm)
    story = []

    story.append(Spacer(1, 20))
    story.append(Paragraph("Compliance Assessment Report", styles["title"]))
    story.append(Paragraph(f"Generated: {generated}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=20))

    # Framework summary table
    story.append(Paragraph("Framework Compliance Overview", styles["h1"]))
    fw_data = [["Framework", "Score", "Pass", "Fail", "Status"]]
    for fw_id, result in framework_results.items():
        score = result.get("score", 0)
        passed = result.get("passed_controls", 0)
        failed = result.get("failed_controls", 0)
        status = "✓ COMPLIANT" if score >= 80 else "⚠ PARTIAL" if score >= 50 else "✗ NON-COMPLIANT"
        fw_data.append([
            result.get("framework_name", fw_id)[:30],
            f"{score}%",
            str(passed),
            str(failed),
            status,
        ])
    fw_table = Table(fw_data, colWidths=[5*cm, 2*cm, 2*cm, 2*cm, 5*cm])
    fw_table.setStyle(_table_style())
    story.append(fw_table)
    story.append(Spacer(1, 12))

    # Per-framework detail
    for fw_id, result in list(framework_results.items())[:4]:
        story.append(Paragraph(f"{result.get('framework_name', fw_id)} — Detail", styles["h2"]))
        controls = result.get("control_results", [])
        if controls:
            ctrl_data = [["Control ID", "Title", "Pass", "Detail"]]
            for ctrl in controls[:15]:
                ctrl_data.append([
                    ctrl.get("id","")[:10],
                    ctrl.get("title","")[:35],
                    "✓" if ctrl.get("passed") else "✗",
                    ctrl.get("detail","")[:40],
                ])
            ct = Table(ctrl_data, colWidths=[2.5*cm, 7*cm, 1.5*cm, 5*cm])
            ct.setStyle(_table_style())
            story.append(ct)
        story.append(Spacer(1, 8))

    def _hf(canvas, doc):
        _header_footer(canvas, doc, "Compliance Assessment Report", generated)

    doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
    logger.info(f"Compliance report PDF: {output_path}")
    return output_path


# ── API endpoints helper ───────────────────────────────────────────────────────

def is_available() -> bool:
    """Live check — works even if reportlab was installed after server started."""
    if _REPORTLAB_OK:
        return True
    try:
        import importlib
        importlib.import_module("reportlab")
        return True
    except ImportError:
        return False

def install_hint() -> str:
    return "pip install reportlab --break-system-packages"
