"""
AID-ARS v4.0 — Report Scheduler + Email Alerting
Sends scheduled HTML reports via SMTP and real-time alerts via email/Slack/Discord/Telegram.
"""
import json, smtplib, threading, time, logging as _logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, Callable

logger = _logging.getLogger("aidars.notify")


class EmailNotifier:
    """Send alerts and reports via SMTP. Works with Gmail, Office 365, etc."""
    def __init__(self, config: dict):
        cfg = config.get("notifications", {}).get("email", {})
        self.enabled  = cfg.get("enabled", False)
        self.smtp     = cfg.get("smtp_host", "smtp.gmail.com")
        self.port     = int(cfg.get("smtp_port", 587))
        self.user     = cfg.get("smtp_user", "")
        self.password = cfg.get("smtp_password", "")
        self.from_    = cfg.get("from_addr", self.user)
        self.to       = cfg.get("to_addrs", [])
        self.severities = cfg.get("alert_severities", ["CRITICAL", "HIGH"])

    def send(self, subject: str, body_html: str, to: list = None) -> bool:
        if not self.enabled or not self.user: return False
        recipients = to or self.to
        if not recipients: return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = self.from_
            msg["To"]      = ", ".join(recipients)
            msg.attach(MIMEText(body_html, "html"))
            with smtplib.SMTP(self.smtp, self.port) as s:
                s.starttls()
                s.login(self.user, self.password)
                s.sendmail(self.from_, recipients, msg.as_string())
            logger.info(f"Email sent: {subject}")
            return True
        except Exception as e:
            logger.warning(f"Email send failed: {e}")
            return False

    def send_alert(self, alert: dict) -> bool:
        if alert.get("severity","") not in self.severities: return False
        body = f"""
        <html><body style="font-family:monospace;background:#111;color:#eee;padding:20px">
        <h2 style="color:#ff4757">🚨 AID-ARS Alert: {alert.get('type','Unknown')}</h2>
        <table>
        <tr><td><b>Severity:</b></td><td style="color:#ff4757">{alert.get('severity')}</td></tr>
        <tr><td><b>Source IP:</b></td><td>{alert.get('src_ip','?')}</td></tr>
        <tr><td><b>Time:</b></td><td>{alert.get('timestamp','?')}</td></tr>
        <tr><td><b>MITRE:</b></td><td>{alert.get('mitre_id','?')} — {alert.get('mitre_tactic','?')}</td></tr>
        <tr><td><b>Risk Score:</b></td><td>{alert.get('risk_score','?')}</td></tr>
        <tr><td><b>Detail:</b></td><td>{alert.get('detail','?')}</td></tr>
        </table>
        </body></html>"""
        return self.send(f"[AID-ARS] {alert.get('severity')} — {alert.get('type')}", body)


class WebhookNotifier:
    """Slack / Discord / Telegram / custom webhook notifications."""
    def __init__(self, config: dict):
        cfg = config.get("notifications", {})
        self.slack_url    = cfg.get("slack_webhook","") if cfg.get("slack_enabled") else ""
        self.discord_url  = cfg.get("discord_webhook","") if cfg.get("discord_enabled") else ""
        self.tg_token     = cfg.get("telegram_bot_token","") if cfg.get("telegram_enabled") else ""
        self.tg_chat      = cfg.get("telegram_chat_id","")
        self.severities   = cfg.get("notify_severities", ["CRITICAL","HIGH"])

    def _post(self, url: str, payload: dict):
        try:
            import urllib.request, json as _j
            data = _j.dumps(payload).encode()
            req = urllib.request.Request(url, data=data,
                                          headers={"Content-Type":"application/json"})
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.debug(f"Webhook post failed: {e}")
            return False

    def send_alert(self, alert: dict):
        if alert.get("severity","") not in self.severities: return
        sev   = alert.get("severity","?")
        atype = alert.get("type","?")
        ip    = alert.get("src_ip","?")
        score = alert.get("risk_score","?")
        emoji = {"CRITICAL":"🚨","HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}.get(sev,"⚠️")
        text  = f"{emoji} *{sev} — {atype}*\nSrc: `{ip}` | Score: `{score}`"

        if self.slack_url:
            self._post(self.slack_url, {"text": text})
        if self.discord_url:
            self._post(self.discord_url, {"content": text})
        if self.tg_token and self.tg_chat:
            try:
                import urllib.request as _ur
                url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
                data = f"chat_id={self.tg_chat}&text={text}&parse_mode=Markdown"
                _ur.urlopen(url, data.encode(), timeout=5)
            except Exception as e:
                logger.debug(f"Telegram: {e}")


class ReportScheduler:
    """Runs scheduled reports: daily summary, weekly digest."""
    def __init__(self, config: dict, get_stats_fn: Callable,
                 get_alerts_fn: Callable, reporter_fn: Callable):
        cfg = config.get("reporting", {})
        self.enabled       = cfg.get("scheduled_reports", False)
        self.daily_hour    = int(cfg.get("daily_report_hour", 8))  # 08:00 daily
        self.report_dir    = Path(cfg.get("html_report_dir", "data/reports"))
        self._get_stats    = get_stats_fn
        self._get_alerts   = get_alerts_fn
        self._reporter     = reporter_fn
        self._email        = EmailNotifier(config)
        self._lock         = threading.Lock()
        if self.enabled:
            threading.Thread(target=self._loop, daemon=True, name="report-sched").start()
            logger.info(f"Report scheduler: daily at {self.daily_hour:02d}:00")

    def _loop(self):
        while True:
            now = datetime.now()
            # Sleep until next scheduled time
            next_run = now.replace(hour=self.daily_hour, minute=0, second=0, microsecond=0)
            if next_run <= now: next_run += timedelta(days=1)
            time.sleep((next_run - now).total_seconds())
            try: self.run_daily()
            except Exception as e: logger.error(f"Scheduled report: {e}")

    def run_daily(self):
        stats  = self._get_stats()
        alerts = self._get_alerts()
        fname  = self.report_dir / f"daily-{datetime.now().strftime('%Y-%m-%d')}.html"
        html   = self._build_html(stats, alerts, "Daily Summary")
        fname.write_text(html)
        logger.info(f"Daily report saved: {fname}")
        self._email.send(
            f"[AID-ARS] Daily Security Summary — {datetime.now().strftime('%Y-%m-%d')}",
            html
        )
        return str(fname)

    def _build_html(self, stats: dict, alerts: list, title: str) -> str:
        crit = sum(1 for a in alerts if a.get("severity")=="CRITICAL")
        high = sum(1 for a in alerts if a.get("severity")=="HIGH")
        rows = ""
        for a in alerts[:20]:
            rows += f"<tr><td>{a.get('timestamp','?')[:19]}</td><td>{a.get('type','?')}</td><td>{a.get('severity','?')}</td><td>{a.get('src_ip','?')}</td></tr>"
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>{title}</title>
        <style>body{{font-family:monospace;background:#111;color:#eee;padding:20px}}
        h1{{color:#00d2d3}}table{{border-collapse:collapse;width:100%}}
        th,td{{border:1px solid #333;padding:8px;text-align:left}}
        th{{background:#222}}.crit{{color:#ff4757}}.high{{color:#ffa502}}</style></head>
        <body><h1>🛡 AID-ARS — {title}</h1>
        <p>Generated: {datetime.now().isoformat()[:19]}</p>
        <h2>Summary</h2>
        <table><tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Alerts</td><td>{stats.get('total_alerts',0)}</td></tr>
        <tr><td class="crit">CRITICAL</td><td class="crit">{crit}</td></tr>
        <tr><td class="high">HIGH</td><td class="high">{high}</td></tr>
        <tr><td>Cases Open</td><td>{stats.get('cases',{}).get('open',0)}</td></tr>
        <tr><td>Blocked IPs</td><td>{stats.get('responder',{}).get('blocked_ips',0)}</td></tr>
        </table>
        <h2>Recent Alerts (top 20)</h2>
        <table><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source</th></tr>
        {rows}</table></body></html>"""
