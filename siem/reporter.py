"""
CyberRemedy SIEM — WiFi Session Reporter
==========================================
Generates supplemental JSON + HTML reports for monitor-mode WiFi sessions.

Relationship to reporting/reporter.py (SOCReporter):
  SOCReporter generates the main CyberRemedy SOC reports from the full
  alert / response / chain database.

  SIEMReporter generates focused WiFi-session reports that include:
    • All devices detected on the wireless network (from DeviceRegistry)
    • WiFi-specific anomalies (new devices, port hits, spikes)
    • Raw traffic log for the session

  Reports are saved to data/reports/siem_wifi_<ts>.{json,html}
  which means the existing /api/report/list and /api/report/{filename}
  endpoints in api/server.py serve them automatically — no new routes needed.
"""
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("cyberremedy.siem.reporter")

_REPORT_DIR = Path("data/reports")

# ─── Jinja2 HTML template ─────────────────────────────────────────────────────
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CyberRemedy SIEM — WiFi Report {{ generated_at }}</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#04080f;--bg2:#070e17;--bg3:#0d1a26;
      --bd:#0d1a26;--bd2:#1a2a3a;
      --tx1:#c8dde8;--tx2:#8ba8b8;--tx3:#4a6a7a;
      --blue:#00c2ff;--red:#ff3b5c;--orange:#ff6b35;
      --yellow:#ffd60a;--green:#30d158;
      --mono:'JetBrains Mono','Consolas',monospace;
      --sans:'Segoe UI',Arial,sans-serif;
    }
    body{background:var(--bg);color:var(--tx1);font-family:var(--sans)}
    header{background:var(--bg2);border-bottom:2px solid var(--blue);padding:18px 32px}
    header h1{color:var(--blue);font-size:1.4rem;font-weight:800}
    header p{color:var(--tx2);font-size:.8rem;margin-top:4px}
    main{max-width:1400px;margin:0 auto;padding:28px 32px}
    h2{color:var(--blue);font-size:.9rem;font-weight:700;letter-spacing:1.5px;
       text-transform:uppercase;border-left:3px solid var(--blue);
       padding-left:10px;margin:32px 0 14px}
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}
    .card{background:var(--bg2);border:1px solid var(--bd2);border-radius:8px;
          padding:18px;text-align:center;border-top:2px solid var(--blue)}
    .card .n{font-size:2.2rem;font-weight:800;color:var(--blue);font-family:var(--mono)}
    .card .l{font-size:.7rem;color:var(--tx3);margin-top:6px;letter-spacing:1px;text-transform:uppercase}
    table{width:100%;border-collapse:collapse;font-size:.78rem}
    thead th{background:var(--bg3);color:var(--tx2);text-align:left;
             padding:9px 12px;font-size:.7rem;letter-spacing:1px;
             text-transform:uppercase;border-bottom:1px solid var(--bd2)}
    tbody tr:nth-child(odd){background:var(--bg2)}
    tbody tr:nth-child(even){background:var(--bg)}
    tbody td{padding:8px 12px;border-bottom:1px solid var(--bd)}
    .b{display:inline-block;padding:2px 9px;border-radius:3px;
       font-size:.68rem;font-weight:700;letter-spacing:1px;
       text-transform:uppercase;font-family:var(--mono)}
    .crit{background:rgba(255,59,92,.15);color:#ff3b5c}
    .high{background:rgba(255,107,53,.12);color:#ff6b35}
    .med{background:rgba(255,214,10,.11);color:#ffd60a}
    .low{background:rgba(48,209,88,.1);color:#30d158}
    .info{background:rgba(0,194,255,.1);color:#00c2ff}
    .mono{font-family:var(--mono);color:var(--tx2)}
    .empty{text-align:center;color:var(--tx3);padding:24px}
  </style>
</head>
<body>
<header>
  <h1>🛡 CyberRemedy — SIEM WiFi Monitor Report</h1>
  <p>Generated: {{ generated_at }} &nbsp;|&nbsp; Interface: {{ interface }} &nbsp;|&nbsp; Session start: {{ session_start }}</p>
</header>
<main>
  <div class="grid">
    <div class="card"><div class="n">{{ stats.total_devices }}</div><div class="l">Devices Seen</div></div>
    <div class="card"><div class="n">{{ stats.unknown_devices }}</div><div class="l">Unknown Devices</div></div>
    <div class="card"><div class="n">{{ stats.total_packets }}</div><div class="l">Packets Logged</div></div>
    <div class="card"><div class="n">{{ stats.total_anomalies }}</div><div class="l">Anomalies</div></div>
  </div>

  <h2>Devices Detected ({{ devices|length }})</h2>
  <table>
    <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>First Seen</th><th>Last Seen</th><th>Source</th><th>Status</th></tr></thead>
    <tbody>
    {% if devices %}{% for d in devices %}
    <tr>
      <td class="mono">{{ d.ip or '—' }}</td>
      <td class="mono">{{ d.mac or '—' }}</td>
      <td>{{ d.vendor or '—' }}</td>
      <td>{{ d.hostname or '—' }}</td>
      <td class="mono">{{ d.first_seen }}</td>
      <td class="mono">{{ d.last_seen }}</td>
      <td><span class="b info">{{ d.source or 'monitor' }}</span></td>
      <td>{% if not d.is_known %}<span class="b med">UNKNOWN</span>{% else %}<span class="b low">KNOWN</span>{% endif %}</td>
    </tr>
    {% endfor %}{% else %}<tr><td colspan="8" class="empty">No devices recorded</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Anomalies ({{ anomalies|length }})</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source IP</th><th>MITRE</th><th>Detail</th></tr></thead>
    <tbody>
    {% if anomalies %}{% for a in anomalies %}
    {% set sev=(a.severity or '')|lower %}
    {% set cls='crit' if sev=='critical' else ('high' if sev=='high' else ('med' if sev=='medium' else 'low')) %}
    <tr>
      <td class="mono">{{ a.timestamp }}</td>
      <td>{{ a.type }}</td>
      <td><span class="b {{ cls }}">{{ a.severity }}</span></td>
      <td class="mono">{{ a.src_ip or '—' }}</td>
      <td class="mono">{{ a.mitre_id or '—' }}</td>
      <td>{{ a.detail }}</td>
    </tr>
    {% endfor %}{% else %}<tr><td colspan="6" class="empty">No anomalies detected</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Traffic Sample ({{ traffic|length }} packets)</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Src Port</th><th>Dst Port</th><th>Size (B)</th><th>TTL</th></tr></thead>
    <tbody>
    {% if traffic %}{% for t in traffic %}
    <tr>
      <td class="mono">{{ t.timestamp }}</td>
      <td class="mono">{{ t.src_ip }}</td>
      <td class="mono">{{ t.dst_ip }}</td>
      <td><span class="b info">{{ t.protocol }}</span></td>
      <td class="mono">{{ t.src_port or '—' }}</td>
      <td class="mono">{{ t.dst_port or '—' }}</td>
      <td class="mono">{{ t.length or '—' }}</td>
      <td class="mono">{{ t.ttl or '—' }}</td>
    </tr>
    {% endfor %}{% else %}<tr><td colspan="8" class="empty">No traffic logged</td></tr>{% endif %}
    </tbody>
  </table>
</main>
</body>
</html>
"""


class SIEMReporter:
    """
    Accumulates packets + alerts in memory and generates reports on demand.

    Reports land in data/reports/ so the existing /api/report/list and
    /api/report/{filename} endpoints serve them automatically.
    """

    _MAX_TRAFFIC  = 2000   # max packets kept in RAM per session
    _MAX_ANOMALIES = 500

    def __init__(self, registry, monitor_iface: str, session_start: str = ""):
        self._registry      = registry
        self._iface         = monitor_iface
        self._session_start = session_start or datetime.now().isoformat()
        self._traffic: list  = []
        self._anomalies: list = []
        _REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ─── called by SIEMManager ────────────────────────────────────────────────

    def record_packet(self, pkt: dict) -> None:
        if len(self._traffic) < self._MAX_TRAFFIC:
            self._traffic.append(pkt)

    def record_anomaly(self, alert: dict) -> None:
        if len(self._anomalies) < self._MAX_ANOMALIES:
            self._anomalies.append(alert)

    # ─── public ───────────────────────────────────────────────────────────────

    def generate(self) -> tuple:
        """
        Build and save JSON + HTML reports.
        Returns (json_path, html_path) as Path objects.
        """
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        devices   = self._registry.all_devices()
        traffic   = self._traffic[-500:]
        anomalies = self._anomalies[-200:]
        gen_at    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        stats = {
            "total_devices":   len(devices),
            "unknown_devices": sum(1 for d in devices if not d.get("is_known")),
            "total_packets":   len(self._traffic),
            "total_anomalies": len(self._anomalies),
        }

        # ── JSON ──────────────────────────────────────────────────────────────
        json_path = _REPORT_DIR / f"siem_wifi_{ts}.json"
        json_path.write_text(json.dumps({
            "generated_at":  gen_at,
            "session_start": self._session_start,
            "interface":     self._iface,
            "stats":         stats,
            "devices":       _ser(devices),
            "anomalies":     _ser(anomalies),
            "traffic":       _ser(traffic),
        }, indent=2, default=str))
        logger.info(f"[SIEM] JSON report → {json_path}")

        # ── HTML ──────────────────────────────────────────────────────────────
        html_path = _REPORT_DIR / f"siem_wifi_{ts}.html"
        try:
            from jinja2 import Environment, BaseLoader
            tpl  = Environment(loader=BaseLoader()).from_string(_HTML)
            html = tpl.render(
                generated_at  = gen_at,
                session_start = self._session_start,
                interface     = self._iface,
                stats         = stats,
                devices       = _ser(devices),
                anomalies     = _ser(anomalies),
                traffic       = _ser(traffic),
            )
        except ImportError:
            html = "<p>jinja2 not installed — HTML report unavailable. pip install jinja2</p>"
        html_path.write_text(html)
        logger.info(f"[SIEM] HTML report → {html_path}")

        return json_path, html_path


def _ser(rows: list) -> list:
    """Stringify non-JSON-serialisable values (datetime, Path, etc.)."""
    return [
        {k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
         for k, v in row.items()}
        for row in rows
    ]
