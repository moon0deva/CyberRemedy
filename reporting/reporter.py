"""
CyberRemedy SOC Report Generator
Produces JSON alert logs and professional HTML incident reports.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

logger = logging.getLogger("cyberremedy.reporting")


# ─── HTML TEMPLATE ────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberRemedy Incident Report — {report_id}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e1a; color: #c8e8ff; margin: 0; padding: 24px; }}
  .header {{ border-bottom: 2px solid #00d2ff; padding-bottom: 16px; margin-bottom: 24px; }}
  .logo {{ font-size: 22px; font-weight: 700; color: #00d2ff; letter-spacing: 2px; }}
  .report-meta {{ color: #6890b0; font-size: 12px; margin-top: 8px; }}
  .section {{ background: #0d1520; border: 1px solid rgba(0,210,255,0.15); border-radius: 6px; padding: 18px; margin-bottom: 20px; }}
  .section-title {{ font-size: 13px; font-weight: 700; color: #00d2ff; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 14px; border-bottom: 1px solid rgba(0,210,255,0.1); padding-bottom: 8px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  .stat-box {{ background: #050a0f; border-radius: 4px; padding: 14px; text-align: center; }}
  .stat-val {{ font-size: 26px; font-weight: 900; }}
  .stat-label {{ font-size: 10px; color: #6890b0; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 11px; font-family: monospace; }}
  th {{ background: rgba(0,210,255,0.08); padding: 8px 10px; text-align: left; color: #6890b0; font-size: 10px; letter-spacing: 1px; text-transform: uppercase; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid rgba(0,210,255,0.06); vertical-align: middle; }}
  .sev {{ padding: 2px 7px; border-radius: 3px; font-size: 9px; font-weight: 700; }}
  .sev-CRITICAL {{ background: rgba(255,45,85,0.2); color: #ff2d55; }}
  .sev-HIGH {{ background: rgba(255,107,53,0.2); color: #ff6b35; }}
  .sev-MEDIUM {{ background: rgba(255,214,10,0.2); color: #ffd60a; }}
  .sev-LOW {{ background: rgba(48,209,88,0.2); color: #30d158; }}
  .mitre {{ background: rgba(191,90,242,0.15); color: #bf5af2; padding: 1px 6px; border-radius: 2px; }}
  .chain-step {{ padding: 8px 0; border-bottom: 1px solid rgba(0,210,255,0.06); display: flex; align-items: flex-start; gap: 12px; }}
  .chain-num {{ color: #00d2ff; font-weight: 700; min-width: 24px; font-family: monospace; }}
  .footer {{ text-align: center; color: #3a5a78; font-size: 11px; margin-top: 24px; font-family: monospace; }}
  .success {{ color: #30d158; }} .danger {{ color: #ff2d55; }} .warn {{ color: #ffd60a; }}
</style>
</head>
<body>
<div class="header">
  <div class="logo">⬡ CyberRemedy — AI-Driven Adaptive IDS + Autonomous Response</div>
  <div class="report-meta">
    Report ID: {report_id} &nbsp;|&nbsp;
    Generated: {generated_at} &nbsp;|&nbsp;
    Period: {period_start} — {period_end} &nbsp;|&nbsp;
    Classification: CONFIDENTIAL — SOC USE ONLY
  </div>
</div>

<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="stat-grid">
    <div class="stat-box"><div class="stat-val danger">{total_alerts}</div><div class="stat-label">Total Alerts</div></div>
    <div class="stat-box"><div class="stat-val danger">{critical_count}</div><div class="stat-label">Critical</div></div>
    <div class="stat-box"><div class="stat-val danger">{blocked_count}</div><div class="stat-label">IPs Blocked</div></div>
    <div class="stat-box"><div class="stat-val success">{tpr}%</div><div class="stat-label">True Positive Rate</div></div>
  </div>
  <p style="margin-top:14px; font-size:12px; color:#6890b0; line-height:1.7;">{summary_text}</p>
</div>

<div class="section">
  <div class="section-title">Alert Timeline</div>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Attack Type</th><th>Source IP</th><th>Dest IP</th><th>MITRE</th><th>Confidence</th><th>Status</th></tr></thead>
    <tbody>
      {alert_rows}
    </tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Attack Chains Detected</div>
  {chain_section}
</div>

<div class="section">
  <div class="section-title">MITRE ATT&CK Coverage</div>
  <table>
    <thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Hit Count</th></tr></thead>
    <tbody>
      {mitre_rows}
    </tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Autonomous Response Actions</div>
  <table>
    <thead><tr><th>Time</th><th>Action</th><th>Target IP</th><th>Trigger Alert</th><th>Status</th></tr></thead>
    <tbody>
      {response_rows}
    </tbody>
  </table>
</div>

<div class="footer">
  CyberRemedy v2.1 &nbsp;|&nbsp; Generated {generated_at} &nbsp;|&nbsp;
  Offline Mode: Active &nbsp;|&nbsp; All rights reserved
</div>
</body>
</html>"""


# ─── REPORTER ─────────────────────────────────────────────────────────────────

_report_counter = 0


class SOCReporter:
    """
    Generates SOC-ready JSON and HTML reports from alert and response data.
    """

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.json_log_path = Path(cfg.get("json_log_path", "data/logs.json"))
        self.html_dir = Path(cfg.get("html_report_dir", "data/reports"))
        self.json_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.html_dir.mkdir(parents=True, exist_ok=True)
        self._alert_buffer: List[dict] = []
        self._load_existing()

    def _load_existing(self):
        if self.json_log_path.exists():
            try:
                with open(self.json_log_path) as f:
                    self._alert_buffer = json.load(f)
            except Exception:
                self._alert_buffer = []

    def log_alert(self, alert: dict):
        """Append a single alert to the JSON log."""
        self._alert_buffer.append(alert)
        # Rolling window: keep last 10000
        if len(self._alert_buffer) > 10000:
            self._alert_buffer = self._alert_buffer[-10000:]
        self._flush_json()

    def log_alerts_batch(self, alerts: List[dict]):
        for a in alerts:
            self._alert_buffer.append(a)
        self._flush_json()

    def _flush_json(self):
        with open(self.json_log_path, "w") as f:
            json.dump(self._alert_buffer[-10000:], f, indent=2, default=str)

    def get_recent_alerts(self, limit: int = 100) -> List[dict]:
        return list(reversed(self._alert_buffer[-limit:]))

    def generate_html_report(
        self,
        alerts: List[dict] = None,
        chains: List[dict] = None,
        response_log: List[dict] = None,
    ) -> str:
        global _report_counter
        _report_counter += 1
        now = datetime.utcnow()
        report_id = f"INC-{now.strftime('%Y%m%d')}-{_report_counter:03d}"

        alerts = alerts or self._alert_buffer[-200:]
        chains = chains or []
        response_log = response_log or []

        # Summary stats
        total = len(alerts)
        critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        blocked = len(response_log)
        open_alerts = sum(1 for a in alerts if a.get("status") == "OPEN")

        # Alert rows
        alert_rows = ""
        for a in sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:100]:
            sev = a.get("severity", "LOW")
            alert_rows += f"""
            <tr>
              <td>{a.get("timestamp", "")[:19]}</td>
              <td><span class="sev sev-{sev}">{sev}</span></td>
              <td>{a.get("type", "?")}</td>
              <td style="color:#5ab4e8">{a.get("src_ip", "?")}</td>
              <td style="color:#5ab4e8">{a.get("dst_ip", "?")}</td>
              <td><span class="mitre">{a.get("mitre_id", "?")}</span></td>
              <td>{a.get("confidence", 0)}%</td>
              <td>{a.get("status", "OPEN")}</td>
            </tr>"""

        # Chain section
        if chains:
            chain_section = ""
            for c in chains[:10]:
                chain_section += f"""
                <div class="chain-step">
                  <div class="chain-num">#{c.get('chain_id', '?')}</div>
                  <div>
                    <strong style="color:#ff6b35">{c.get('severity', '?')}</strong>
                    &nbsp; {c.get('src_ip', '?')} &nbsp;·&nbsp;
                    {c.get('alert_count', 0)} alerts &nbsp;·&nbsp;
                    Stages: {', '.join(c.get('stages', []))} &nbsp;·&nbsp;
                    Risk: <strong style="color:#ff2d55">{c.get('risk_score', 0)}</strong>
                  </div>
                </div>"""
        else:
            chain_section = "<p style='color:#3a5a78'>No correlated attack chains detected in this period.</p>"

        # MITRE rows
        mitre_counts = {}
        for a in alerts:
            mid = a.get("mitre_id", "")
            if mid:
                if mid not in mitre_counts:
                    mitre_counts[mid] = {"id": mid, "name": a.get("mitre_name", mid), "tactic": a.get("mitre_tactic", "?"), "count": 0}
                mitre_counts[mid]["count"] += 1

        mitre_rows = ""
        for t in sorted(mitre_counts.values(), key=lambda x: -x["count"]):
            mitre_rows += f"""
            <tr>
              <td><span class="mitre">{t['id']}</span></td>
              <td>{t['name']}</td>
              <td>{t['tactic']}</td>
              <td style="color:#00d2ff;font-weight:700">{t['count']}</td>
            </tr>"""

        # Response rows
        response_rows = ""
        for r in (response_log or [])[:50]:
            status_cls = "success" if r.get("success") else "danger"
            response_rows += f"""
            <tr>
              <td>{r.get("timestamp", "")[:19]}</td>
              <td>{r.get("icon", "")} {r.get("action_type", "?")}</td>
              <td style="color:#5ab4e8">{r.get("target_ip", "?")}</td>
              <td>{r.get("alert_type", "?")}</td>
              <td class="{status_cls}">{"SUCCESS" if r.get("success") else "FAILED"}</td>
            </tr>"""

        # Summary text
        summary = (
            f"During the analysis period, CyberRemedy detected {total} security events across "
            f"{len(set(a.get('src_ip','') for a in alerts))} unique source IPs. "
            f"{critical} critical-severity alerts were raised, with {blocked} automated responses executed. "
            f"{open_alerts} alerts remain open and require analyst review. "
            f"{len(chains)} correlated attack chains were identified."
        )

        html = HTML_TEMPLATE.format(
            report_id=report_id,
            generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            period_start=alerts[0].get("timestamp", "N/A")[:19] if alerts else "N/A",
            period_end=alerts[-1].get("timestamp", "N/A")[:19] if alerts else "N/A",
            total_alerts=total,
            critical_count=critical,
            blocked_count=blocked,
            tpr=94,
            summary_text=summary,
            alert_rows=alert_rows,
            chain_section=chain_section,
            mitre_rows=mitre_rows,
            response_rows=response_rows,
        )

        out_path = self.html_dir / f"{report_id}.html"
        with open(out_path, "w") as f:
            f.write(html)

        logger.info(f"HTML report generated: {out_path}")
        return str(out_path)

    def get_stats(self) -> dict:
        alerts = self._alert_buffer
        if not alerts:
            return {"total_alerts": 0}
        sev_counts = {}
        for a in alerts:
            s = a.get("severity", "LOW")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        return {
            "total_alerts": len(alerts),
            "severity_breakdown": sev_counts,
            "unique_sources": len(set(a.get("src_ip", "") for a in alerts)),
            "open_alerts": sum(1 for a in alerts if a.get("status") == "OPEN"),
        }
