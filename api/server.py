"""
CyberRemedy FastAPI Backend Server — v3.0
REST API + WebSocket live feed for the React dashboard.
Orchestrates the full detection + response + case + intel pipeline.

New in v3.0 (gap-analysis driven):
  - Case Management  POST/GET/PATCH /api/cases/*
  - IOC/Threat Intel  /api/intel/*
  - UEBA Engine  /api/ueba/*
  - SOAR Playbooks  /api/playbooks/*
  - YARA Scanner  /api/yara/*
  - Sigma Rules  /api/sigma/*
  - Honeypot Traps  /api/honeypot/*
  - Compliance  /api/compliance/*
  - Vuln Management  /api/vuln/*
  - Forensic Timeline  /api/forensics/*
  - Data Lake  /api/datalake/*
  - RBAC Auth  /api/auth/*
"""

import os, sys, json, time, asyncio, logging, threading, binascii, base64
from datetime import datetime
from typing import List, Optional, Set
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from utils.json_safe import sanitize, safe_dumps
try:
    from ml.auto_train import maybe_auto_train as _maybe_auto_train
except Exception:
    _maybe_auto_train = None

from reporting.pdf_generator import (
    generate_executive_summary, generate_threat_intel_report,
    generate_vuln_report, generate_compliance_report,
    is_available as pdf_available, install_hint as pdf_install_hint,
)
# (vuln manager imported fully below via VulnManager)

# Core pipeline
from capture.sniffer import LiveSniffer, PcapReplayer
from packet_analyzer.engine import PacketAnalyzer
from features.extractor import FlowAggregator
from detection.signature import SignatureDetector
from detection.anomaly import AnomalyDetector
from ml.lstm.detector import LSTMDetector
from detection.correlation import CorrelationEngine
from scoring.scorer import ThreatScorer
from mitre.mapper import MitreMapper
from response.responder import AutonomousResponder
from reporting.reporter import SOCReporter

# v3.0 new modules
from cases.manager import CaseManager, CaseStatus, CaseSeverity
from threat_intel.ioc_manager import IOCManager
from ueba.engine import UEBAEngine
from soar.playbooks import SOAREngine as PlaybookEngine
from yara_engine.scanner import YARAScanner as YaraScanner
from sigma_engine.converter import SigmaEngine
from honeypot.traps import HoneypotManager
from compliance.checker import ComplianceChecker
from vuln.manager import VulnManager
from forensics.timeline import ForensicsManager
from data_lake.storage import DataLake
from data_lake.sqlite_writer import SQLiteWriter
from rbac.auth import RBACManager
from dark_web.monitor import DarkWebMonitor
from utils.resource_downloader import download_background as _start_resource_download, status as _resource_status
# SIEM WiFi monitor
try:
    from siem import SIEMManager as _SIEMManager
    _SIEM_AVAILABLE = True
except ImportError:
    _SIEM_AVAILABLE = False
    logger_pre = logging.getLogger("cyberremedy.api")
    logger_pre.warning("[SIEM] siem/ module not found — WiFi monitor disabled")
# v1.2 modules
from log_store.log_manager import LogManager
from firewall.integrator import FirewallIntegrator
from assets.discovery import AssetInventory
from geoip.lookup import GeoIPLookup


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("cyberremedy.api")


def load_config():
    p = Path(__file__).parent.parent / "config" / "settings.yaml"
    return yaml.safe_load(p.read_text()) if p.exists() else {}


CONFIG = load_config()

# ── init all components ──────────────────────────────────────────────────────

sig_detector      = SignatureDetector(CONFIG.get("detection", {}).get("signature", {}))
anomaly_detector  = AnomalyDetector(
    model_path=CONFIG.get("detection", {}).get("anomaly", {}).get("model_path", "models/anomaly_model.joblib"),
    classifier_path=CONFIG.get("detection", {}).get("anomaly", {}).get("classifier_path", "models/rf_attack_model.joblib"),
)

# LSTM sequential anomaly detector (loads saved model if available)
lstm_detector = LSTMDetector()
_lstm_loaded  = lstm_detector.load()   # no-op if model not yet trained
correlation_engine = CorrelationEngine(
    time_window=CONFIG.get("detection", {}).get("correlation", {}).get("time_window_seconds", 300),
    min_chain_events=CONFIG.get("detection", {}).get("correlation", {}).get("chain_min_events", 2),
)
scorer         = ThreatScorer()
mitre_mapper   = MitreMapper()
responder      = AutonomousResponder(CONFIG.get("response", {}))
reporter       = SOCReporter(CONFIG.get("reporting", {}))

case_manager    = CaseManager()
ioc_manager     = IOCManager(CONFIG.get("threat_intel", {}))
ueba_engine     = UEBAEngine()
playbook_engine = PlaybookEngine()
yara_scanner    = YaraScanner()
sigma_engine    = SigmaEngine()
honeypot_mgr    = HoneypotManager(alert_callback=None, config=CONFIG.get('honeypot',{}))
compliance      = ComplianceChecker()
vuln_manager    = VulnManager()
forensics       = ForensicsManager()
data_lake       = DataLake()
sqlite_writer   = SQLiteWriter()        # buffered batch SQLite writer
rbac            = RBACManager()
dark_web_monitor = DarkWebMonitor()
# v1.2 component initialisation
log_manager   = LogManager(CONFIG)
firewall      = FirewallIntegrator(CONFIG)
asset_inv     = AssetInventory(CONFIG)
geoip         = GeoIPLookup(CONFIG)


# ── app ──────────────────────────────────────────────────────────────────────


# ── Global reverse DNS cache (Web Traffic DNS name display) ──────────────────
import socket as _sock_dns
import concurrent.futures as _dns_pool_mod
_rdns_cache: dict = {}
_rdns_neg:   set  = set()
_rdns_lock = __import__("threading").Lock()
_rdns_executor = _dns_pool_mod.ThreadPoolExecutor(max_workers=8, thread_name_prefix="rdns")

def _rdns(ip: str) -> str:
    """Cached reverse DNS lookup. Returns hostname or empty string. Non-blocking."""
    if not ip: return ""
    with _rdns_lock:
        if ip in _rdns_cache: return _rdns_cache[ip]
        if ip in _rdns_neg:   return ""
    # Kick off async lookup — return empty now, result cached for next call
    def _lookup(addr):
        try:
            host = _sock_dns.gethostbyaddr(addr)[0]
            if host and host != addr and "." in host:
                with _rdns_lock:
                    _rdns_cache[addr] = host
                return host
        except Exception:
            pass
        with _rdns_lock:
            _rdns_neg.add(addr)
        return ""
    try:
        _rdns_executor.submit(_lookup, ip)
    except Exception:
        pass
    return ""

def _rdns_sync(ip: str, timeout: float = 0.4) -> str:
    """Blocking reverse DNS with timeout — use only in non-hot paths."""
    if not ip: return ""
    with _rdns_lock:
        if ip in _rdns_cache: return _rdns_cache[ip]
        if ip in _rdns_neg:   return ""
    try:
        fut = _rdns_executor.submit(_sock_dns.gethostbyaddr, ip)
        result = fut.result(timeout=timeout)
        host = result[0] if result else ""
        if host and host != ip and "." in host:
            with _rdns_lock:
                _rdns_cache[ip] = host
            return host
    except Exception:
        pass
    with _rdns_lock:
        _rdns_neg.add(ip)
    return ""

app = FastAPI(title="CyberRemedy API", description="AI-Driven Adaptive IDS — Full SOC Platform v3.0",
              version="1.2.0", docs_url="/docs", redoc_url="/redoc")

# CORS must be added BEFORE routes, and allow_credentials=True is invalid with allow_origins=["*"]
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

_DASH = Path(__file__).parent.parent / "dashboard" / "index.html"

@app.get("/", response_class=HTMLResponse)
def serve_dash():
    if _DASH.exists(): return HTMLResponse(_DASH.read_text())
    return HTMLResponse("<h2>Dashboard not found</h2>", status_code=404)

# ── websocket manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self): self.active: Set[WebSocket] = set()
    async def connect(self, ws):
        await ws.accept(); self.active.add(ws)
    def disconnect(self, ws): self.active.discard(ws)
    async def broadcast(self, message):
        dead = set(); payload = safe_dumps(message)
        for ws in self.active:
            try: await ws.send_text(payload)
            except: dead.add(ws)
        self.active -= dead

manager = ConnectionManager()

# ── pipeline state ────────────────────────────────────────────────────────────

_fw_custom_rules: list = []  # in-memory custom firewall rules with protocol/port
pipeline_state = dict(running=False, interface="eth0", mode="stopped",
                      packets_processed=0, flows_analyzed=0, alerts_total=0,
                      start_time=None, version="1.2.0")

# Module-level sniffer reference — set when live capture starts
sniffer: Optional[LiveSniffer] = None
_recent_alerts:    List[dict] = []
_recent_responses: List[dict] = []
_recent_chains:    List[dict] = []
_traffic_history:  List[dict] = []
_traffic_counter   = dict(benign=0, malicious=0, total=0)

# ── central alert enrichment pipeline ────────────────────────────────────────

def _is_mac_addr(val: str) -> bool:
    """Return True if val looks like a MAC address — never a routable IP."""
    return bool(val and ":" in val and len(val) <= 17)

def _process_alert(alert: dict):
    src_ip = alert.get("src_ip", "")

    # IOC check — skip if src_ip is a MAC address (not a routable IP)
    if src_ip and not _is_mac_addr(src_ip):
        _ioc_raw = ioc_manager.store.lookup_ip(src_ip)
        ioc_hit = _ioc_raw.to_dict() if _ioc_raw else None
        if ioc_hit:
            alert["ioc_match"] = ioc_hit
            if alert.get("severity") in ("MEDIUM","LOW"):
                alert["severity"] = "HIGH"

    # UEBA — skip MAC addresses as they have no meaningful IP behaviour profile
    ueba_ip = src_ip if src_ip and not _is_mac_addr(src_ip) else None
    ueba_signal = ueba_engine.ingest_event({
        "src_ip": ueba_ip, "dst_ip": alert.get("dst_ip"),
        "dst_port": alert.get("dst_port"), "timestamp": alert.get("timestamp"),
        "alert_type": alert.get("type"),
    })
    if ueba_signal:
        alert["ueba_anomaly"] = ueba_signal

    # MITRE → score → correlate
    alert = mitre_mapper.enrich(alert)
    alert = scorer.score(alert)

    chain = correlation_engine.ingest_alert(alert)
    if chain:
        _recent_chains.append(chain)
        if len(_recent_chains) > 50: _recent_chains.pop(0)

    # Autonomous response
    entry = responder.evaluate_and_respond(alert)
    if entry:
        _recent_responses.append(entry)
        if len(_recent_responses) > 100: _recent_responses.pop(0)

    # SOAR playbook
    triggered = playbook_engine.process_alert(alert)
    if triggered:
        alert["playbook_triggered"] = triggered.get("name")

    # Auto-case for CRITICAL/HIGH
    if alert.get("severity") in ("CRITICAL","HIGH"):
        existing = [c for c in case_manager.list() if alert.get("id") in c.get("alert_ids", [])]
        if not existing:
            case_manager.create_from_alert(alert)

    # Forensics + storage
    try:
        forensics.ingest_host_event(alert)
    except Exception:
        pass
    alert = sanitize(alert)   # strip bytes from raw packet payloads
    reporter.log_alert(alert)
    data_lake.ingest(alert)
    sqlite_writer.write_alert(alert)

    _recent_alerts.append(alert)
    if len(_recent_alerts) > 500: _recent_alerts.pop(0)

    pipeline_state["alerts_total"] += 1
    _traffic_counter["malicious"] += 1
    _traffic_counter["total"] += 1

def _on_flow_complete(flow: dict):
    pipeline_state["flows_analyzed"] += 1
    alerts = sig_detector.analyze(flow)
    ml = anomaly_detector.analyze(flow)
    if ml and not any(a.get("src_ip")==ml.get("src_ip") and a.get("mitre_id")==ml.get("mitre_id") for a in alerts):
        alerts.append(ml)
    # LSTM sequential detector — catches multi-step attack chains
    lstm_alert = lstm_detector.analyze(flow) if lstm_detector.is_ready else None
    if lstm_alert and not any(a.get("src_ip")==lstm_alert.get("src_ip") and
                               a.get("mitre_id")==lstm_alert.get("mitre_id") for a in alerts):
        alerts.append(lstm_alert)
    alerts.extend(sigma_engine.evaluate(flow))
    for a in alerts:
        if not correlation_engine.should_suppress_fp(a):
            _process_alert(a)
    if not alerts:
        _traffic_counter["benign"] += 1
        _traffic_counter["total"] += 1
    # Persist flow to SQLite (buffered — every 50 flows)
    sqlite_writer.write_flow(flow)

_packet_analyzer = PacketAnalyzer(alert_callback=None)  # callback wired after _process_alert defined
flow_aggregator = FlowAggregator(
    flow_timeout=CONFIG.get("capture", {}).get("flow_timeout_seconds", 60),
    on_flow_complete=_on_flow_complete,
)

def _on_packet(pkt):
    if not isinstance(pkt, dict): return  # Guard: sniffer sometimes passes non-dict
    pipeline_state["packets_processed"] += 1
    try: flow_aggregator.add_packet(pkt)
    except Exception: pass
    # Write DNS events directly — they don't produce flows but are valuable
    if pkt.get("protocol") == "DNS" and pkt.get("dns_query"):
        sqlite_writer.write_dns(pkt)
    # ── Deep packet analysis (Wireshark-style ML analyzer)
    try: _packet_analyzer.ingest(pkt)
    except Exception: pass
    try:
        payload = pkt.get("payload", b"")
        if len(payload) > 64:
            yara_scanner.scan_bytes(payload, context={"src_ip": pkt.get("src_ip")})
    except Exception: pass

def _on_honeypot(event: dict):
    event.update(type="Honeypot Connection", severity="CRITICAL", confidence=100.0, mitre_id="T1595")
    _process_alert(event)
    logger.warning(f"HONEYPOT HIT: {event}")

# ── v1.2: wire asset+log callbacks (must be after _process_alert defined) ────
def _process_alert_enriched(alert: dict):
    """v1.2 wrapper: logs to file + adds GeoIP, then runs original pipeline."""
    try:
        # GeoIP enrich (non-blocking — uses cache)
        # Skip if src_ip is empty, a MAC address, or clearly not a routable IP
        src = alert.get("src_ip","")
        _is_mac = src and (":" in src and len(src) == 17)
        _is_private = src and (
            src.startswith("192.168.") or
            src.startswith("10.")      or
            src.startswith("172.")     or
            src.startswith("127.")
        )
        if src and not _is_mac and not _is_private:
            try:
                geo = geoip.lookup(src)
                alert["geo"] = {
                    "country":      geo.get("country",""),
                    "country_code": geo.get("country_code",""),
                    "flag":         geo.get("flag","🌐"),
                    "city":         geo.get("city",""),
                    "high_risk":    geo.get("high_risk",False),
                }
            except Exception:
                pass
        _process_alert(alert)
        log_manager.log_alert(alert)
    except Exception as e:
        logger.error(f"_process_alert_enriched: {e}", exc_info=True)

# Replace asset callback with safe wrapper
asset_inv.set_alert_callback(_process_alert_enriched)
asset_inv.set_log_callback(log_manager.log_asset)

# ── SIEM WiFi monitor (instantiated here so callbacks are already defined) ────
siem_manager = (
    _SIEMManager(
        config          = CONFIG.get("siem", {}),
        packet_callback = _on_packet,               # feeds existing FlowAggregator
        alert_callback  = _process_alert_enriched,  # full enrichment + dashboard
    )
    if _SIEM_AVAILABLE else None
)


# ── broadcast loop ────────────────────────────────────────────────────────────

async def broadcast_loop():
    tick = 0
    while True:
        await asyncio.sleep(1.0); tick += 1
        snap = dict(_traffic_counter)
        _traffic_history.append(dict(t=tick, **snap, ts=datetime.utcnow().isoformat()))
        if len(_traffic_history) > 120: _traffic_history.pop(0)
        _traffic_counter.update(benign=0, malicious=0, total=0)
        if not manager.active: continue
        try:
            payload = {
                "type": "state_update",
                "pipeline": {**pipeline_state, "start_time": str(pipeline_state["start_time"])},
                "recent_alerts":    _recent_alerts[-20:],
                "recent_responses": _recent_responses[-10:],
                "active_chains":    [], "blocked_ips": [],
                "traffic_point":    _traffic_history[-1] if _traffic_history else None,
                "traffic_history":  _traffic_history[-60:],
                "stats": {}, "mitre_coverage": {}, "ueba_alerts": [], "honeypot_events": [],
            }
            try: payload["active_chains"]   = correlation_engine.get_active_chains()
            except Exception: pass
            try: payload["blocked_ips"]     = responder.registry.get_all()
            except Exception: pass
            try: payload["mitre_coverage"]  = mitre_mapper.get_coverage_summary(_recent_alerts)
            except Exception: pass
            try: payload["ueba_alerts"]     = ueba_engine.get_alerts(10)
            except Exception: pass
            try: payload["honeypot_events"] = honeypot_mgr.get_alerts(5)
            except Exception: pass
            try:
                payload["stats"] = {
                    **reporter.get_stats(),
                    "responder":    responder.stats,
                    "correlator":   correlation_engine.stats,
                    "detector_sig": sig_detector.stats,
                    "detector_ml":  anomaly_detector.status,
                    "detector_lstm": lstm_detector.stats,
                    "active_flows": flow_aggregator.active_flow_count,
                    "cases":        case_manager.stats(),
                    "ueba":         ueba_engine.stats,
                    "honeypot":     honeypot_mgr.stats,
                    "ioc":          ioc_manager.get_stats(),
                    "forensics":    forensics.stats,
                }
            except Exception: pass
            await manager.broadcast(payload)
        except Exception as e:
            logger.warning(f"broadcast_loop error: {e}")



# ── ML auto-training at startup ────────────────────────────────────────────────
def _auto_train_ml_if_needed():
    """
    If ML models are missing, launch training in a separate xterm window.
    Non-blocking: opens xterm, trains, closes when done.
    Does NOT block the server startup.
    """
    from pathlib import Path as _Path
    import subprocess as _sp, sys as _sys, threading as _t

    model_exists = _Path("models/lstm_detector.pt").exists() or _Path("models/lstm_detector.keras").exists()
    iso_exists   = _Path("models/anomaly_model.joblib").exists()

    if model_exists and iso_exists:
        logger.info("[ML] Models already trained — skipping auto-train")
        return

    logger.info("[ML] Models missing — launching background training in xterm")

    def _run():
        try:
            # Try to open xterm with training script
            cmd = [
                "xterm", "-title", "CyberRemedy ML Training",
                "-geometry", "100x30+100+100",
                "-bg", "#0a0e1a", "-fg", "#00e5ff",
                "-fa", "Monospace", "-fs", "11",
                "-e", _sys.executable, "ml/lstm/trainer.py"
            ]
            proc = _sp.Popen(cmd)
            proc.wait()
            logger.info("[ML] xterm training completed")
        except FileNotFoundError:
            # xterm not available — run in background thread without UI
            logger.info("[ML] xterm not found — training in background thread (no UI)")
            try:
                result = _sp.run(
                    [_sys.executable, "ml/lstm/trainer.py"],
                    capture_output=True, text=True, timeout=600
                )
                if result.returncode == 0:
                    logger.info("[ML] Background training completed successfully")
                else:
                    logger.warning(f"[ML] Background training failed: {result.stderr[:200]}")
            except Exception as e:
                logger.warning(f"[ML] Training error: {e}")
        except Exception as e:
            logger.warning(f"[ML] Could not launch training: {e}")

    _t.Thread(target=_run, daemon=True, name="ml-autotrain").start()

@app.on_event("startup")
async def startup():
    # Auto-train ML models if missing (opens xterm for progress)
    try:
        if _maybe_auto_train:
            _maybe_auto_train(force=False)
    except Exception as _ate:
        logger.warning(f"Auto-train check failed: {_ate}")

    # Ensure ML models are trained and loaded (fast no-op if .joblib files exist)
    try:
        from ml.synthetic_trainer import ensure_models
        from pathlib import Path
        import threading
        def _train():
            ok = ensure_models(Path("models"))
            if ok:
                anomaly_detector._load_models()
            # Reload LSTM once its background training finishes
            import time
            for _ in range(60):          # wait up to 5 min (60 × 5s)
                if lstm_detector.is_ready:
                    break
                if (Path("models/lstm_detector.pt").exists() or
                        Path("models/lstm_detector.keras").exists()):
                    lstm_detector.load()
                    logger.info("[startup] LSTM model loaded after background training")
                    break
                time.sleep(5)
        threading.Thread(target=_train, daemon=True, name="ml-ensure").start()
    except Exception as exc:
        logger.warning(f"ML model startup check failed: {exc}")

    # Auto-download all threat intelligence feeds in background
    try:
        ioc_manager.start_feed_refresh(background=True, force=False)
        logger.info("Threat feed auto-download initiated")
    except Exception as exc:
        logger.warning(f"Threat feed startup failed: {exc}")
    asyncio.create_task(broadcast_loop())
    honeypot_mgr.alert_callback = _on_honeypot
    honeypot_mgr.start_all()
    # Asset discovery thread is started inside AssetInventory.__init__()
    logger.info(f"Asset discovery running (interval: {asset_inv.scan_interval}s)")
    # ── Auto-start syslog server if not already started ───────────────────────
    try:
        if _syslog_srv is None:
            _cfg = CONFIG.get("syslog", {})
            _new_srv = SyslogServer(
                port=int(_cfg.get("udp_port", 5514)),
                winlog_port=int(_cfg.get("winlog_port", 5515)),
                callback=lambda ev: (
                    log_manager.log_event("syslog", ev.get("message",""), **{k:v for k,v in ev.items() if k!="message"}),
                    _process_alert_enriched(ev) if ev.get("severity") in ("CRITICAL","HIGH") else None
                )[0]
            )
            _new_srv.start()
            logger.info("Syslog server started on startup (UDP/TCP :5514, WinLog :5515)")
    except Exception as _e:
        logger.warning(f"Syslog auto-start: {_e}")
    # ── Auto-start live capture pipeline ────────────────────────────────────
    from capture.sniffer import ROOT_OK as _ROOT_OK, SCAPY_OK as _SCAPY_OK
    iface = CONFIG.get("system", {}).get("interface", "auto")
    if _ROOT_OK:
        pipeline_state.update(running=True, mode="live", interface=iface, start_time=time.time())
        def _start_capture():
            global sniffer
            try:
                from capture.sniffer import LiveSniffer as _LS
                sniffer = _LS(interface=iface, callback=_on_packet)
                sniffer.start()
            except Exception as e:
                logger.error(f"Live capture failed: {e}")
                pipeline_state["running"] = False
        import threading as _t
        _t.Thread(target=_start_capture, daemon=True, name="cap-main").start()
        logger.info(f"Live capture auto-started on interface: {iface}")
    else:
        logger.warning(
            "═══════════════════════════════════════════════════════════════\n"
            "  CyberRemedy is NOT running as root.\n"
            "  Live packet capture is DISABLED.\n"
            "  Restart with:  sudo python3 main.py\n"
            "  Or set capability:  sudo setcap cap_net_raw+eip $(which python3)\n"
            "═══════════════════════════════════════════════════════════════"
        )
        # FIX: still set start_time so the UI renders correctly instead of blank
        pipeline_state.update(running=False, mode="error:not_root", start_time=time.time())
    logger.info("CyberRemedy SOC PLATFORM v1.2 API started")
    _auto_train_ml_if_needed()
    # ── SIEM WiFi monitor auto-start ──────────────────────────────────────────
    # FIX: always refresh gateway_ip from live routing table before starting —
    # this is the DHCP fix: the gateway changes on every lease renewal, so we
    # never rely on whatever is stored in settings.yaml.
    if siem_manager:
        _live_gw = siem_manager._detect_gateway()
        if _live_gw:
            siem_manager._cfg["gateway_ip"] = _live_gw
            logger.info(f"[SIEM] DHCP gateway refreshed at startup: {_live_gw}")
        siem_manager.start_if_enabled()

@app.on_event("shutdown")
async def shutdown():
    try:
        sqlite_writer.flush()
        logger.info("SQLite writer flushed on shutdown")
    except Exception:
        pass
    honeypot_mgr.stop_all()
    if siem_manager:
        siem_manager.stop()

# ── websocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    logger.info(f"WS client connected: {ws.client}")
    try:
        init_msg = {
            "type": "init", "version": "2.0.0",
            "recent_alerts": _recent_alerts[-50:],
            "traffic_history": _traffic_history[-60:],
            "blocked_ips": [], "active_chains": [],
            "playbooks": [], "sigma_rules": [], "yara_rules": [], "mitre_db": [],
        }
        try: init_msg["blocked_ips"]   = responder.registry.get_all()
        except Exception as e: logger.warning(f"WS init blocked_ips: {e}")
        try: init_msg["active_chains"] = correlation_engine.get_active_chains()
        except Exception as e: logger.warning(f"WS init chains: {e}")
        try: init_msg["playbooks"]     = playbook_engine.get_playbooks()
        except Exception as e: logger.warning(f"WS init playbooks: {e}")
        try: init_msg["sigma_rules"]   = sigma_engine.get_rules()
        except Exception as e: logger.warning(f"WS init sigma: {e}")
        try: init_msg["yara_rules"]    = yara_scanner.get_results()
        except Exception as e: logger.warning(f"WS init yara: {e}")
        try: init_msg["mitre_db"]      = mitre_mapper.get_all_techniques()
        except Exception as e: logger.warning(f"WS init mitre: {e}")
        await ws.send_text(safe_dumps(sanitize(init_msg)))
        logger.info("WS init sent OK")
    except Exception as e:
        logger.error(f"WS init FAILED: {e}", exc_info=True)
        manager.disconnect(ws); return
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            cmd = msg.get("cmd")
            if cmd == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
            elif cmd == "manual_block":
                entry = responder.manual_block(msg["ip"], reason="Dashboard manual block")
                await ws.send_text(json.dumps({"type": "block_result", "entry": entry}, default=str))
            elif cmd == "manual_unblock":
                entry = responder.manual_unblock(msg["ip"])
                await ws.send_text(json.dumps({"type": "unblock_result", "entry": entry}, default=str))
            elif cmd == "run_playbook":
                r = playbook_engine.execute_playbook(msg["playbook_id"], msg.get("alert", {}))
                await ws.send_text(json.dumps({"type": "playbook_result", "result": r}, default=str))
            elif cmd == "save_settings":
                # Apply settings live without restart
                settings = msg.get("settings", {})
                try:
                    if "detection_threshold" in settings:
                        sig_detector.threshold = int(settings["detection_threshold"])
                    if "auto_block" in settings:
                        responder.auto_block = bool(settings["auto_block"])
                    await ws.send_text(json.dumps({"type": "settings_saved", "ok": True}))
                except Exception as se:
                    await ws.send_text(json.dumps({"type": "settings_saved", "ok": False, "error": str(se)}))
    except (WebSocketDisconnect, Exception) as e:
        logger.info(f"WS disconnected: {e}")
        manager.disconnect(ws)


# ═══════════════════════════════════════════════════════════════════════════════
# ORIGINAL PIPELINE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/status")
def get_status():
    return {
        "version": "1.2.0", "pipeline": pipeline_state,
        "uptime_seconds": time.time()-pipeline_state["start_time"] if pipeline_state["start_time"] else 0,
        "components": {
            "signature_detector": "ready",
            "anomaly_detector": anomaly_detector.status["mode"],
            "lstm_detector": "ready" if lstm_detector.is_ready else "training_required",
            "correlation_engine": "ready",
            "responder": "ready" if not responder.dry_run else "dry_run",
            "case_manager": f"{case_manager.stats()['total']} cases",
            "ioc_manager": f"{ioc_manager.get_stats().get('total', 0)} IOCs",
            "ueba": "active" if getattr(ueba_engine, "is_active", False) or getattr(ueba_engine, "event_count", 0) > 0 else "learning",
            "honeypot": "active" if getattr(honeypot_mgr,"stats",{}).get("services_running",0) > 0 else "stopped",
            "sigma": f"{sigma_engine.stats.get('total_rules', 0)} rules",
            "yara": f"{yara_scanner.stats.get('total_rules',0)} rules",
        },
    }

@app.get("/api/alerts")
def get_alerts(limit: int=100, severity: str=None, ioc_only: bool=False):
    a = list(reversed(_recent_alerts[-500:]))
    if severity: a = [x for x in a if x.get("severity")==severity.upper()]
    if ioc_only: a = [x for x in a if x.get("ioc_match")]
    return sanitize({"alerts": a[:limit], "total": len(_recent_alerts)})

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    for a in reversed(_recent_alerts):
        if a.get("id") == alert_id: return sanitize(a)
    raise HTTPException(404, f"Alert {alert_id} not found")

@app.get("/api/chains")
def get_chains(): return {"chains": correlation_engine.get_all_chains()}

@app.get("/api/blocked")
def get_blocked(): return {"blocked_ips": responder.registry.get_all(), "count": responder.registry.count}

class BlockRequest(BaseModel):
    ip: str; reason: Optional[str] = "API block"

@app.post("/api/block")
def block_ip(req: BlockRequest): return {"success": True, "entry": responder.manual_block(req.ip, req.reason)}

@app.delete("/api/block/{ip}")
def unblock_ip(ip: str): return {"success": True, "entry": responder.manual_unblock(ip)}

@app.get("/api/response-log")
def get_response_log(): return {"log": responder.log.get_all()}

@app.get("/api/mitre")
def get_mitre():
    return {"techniques": mitre_mapper.get_all_techniques(),
            "coverage": mitre_mapper.get_coverage_summary(_recent_alerts)}

@app.get("/api/traffic")
def get_traffic(): return {"history": _traffic_history[-120:]}


@app.post("/api/pipeline/restart")
async def restart_pipeline():
    """Restart the capture pipeline (applies config changes live)."""
    global pipeline_state, sniffer
    try:
        if sniffer is not None:
            sniffer.stop()
    except Exception:
        pass
    pipeline_state["running"] = False
    pipeline_state["mode"] = "restarting"
    import asyncio
    async def _restart():
        global sniffer
        await asyncio.sleep(1.5)
        try:
            iface = pipeline_state.get("interface", "auto")
            sniffer = LiveSniffer(interface=iface, callback=_on_packet)
            sniffer.start()
            pipeline_state["running"] = True
            pipeline_state["mode"] = "live"
        except Exception as e:
            pipeline_state["running"] = False
            pipeline_state["mode"] = f"stopped"
    asyncio.create_task(_restart())
    return {"restarting": True, "message": "Pipeline restarting in 1.5s"}

@app.get("/api/pipeline/detail")
def pipeline_detail():
    """Full pipeline status: stages, counters, component health."""
    from detection.anomaly import AnomalyDetector
    uptime = 0
    if pipeline_state.get("start_time"):
        try: uptime = int(time.time() - pipeline_state["start_time"])
        except: pass
    pps = 0
    if uptime > 0:
        pps = round(pipeline_state.get("packets_processed",0) / max(1,uptime), 1)
    stages = [
        {"name": "Packet Capture",  "id": "capture",    "status": "ok" if pipeline_state.get("running") else "stopped",
         "desc": f"Interface: {pipeline_state.get('interface','—')}",
         "count": pipeline_state.get("packets_processed", 0)},
        {"name": "Flow Aggregator", "id": "flows",      "status": "ok" if pipeline_state.get("running") else "idle",
         "desc": f"{flow_aggregator.active_flow_count} active flows",
         "count": pipeline_state.get("flows_analyzed", 0)},
        {"name": "Signature Engine","id": "signature",  "status": "ok",
         "desc": f"{len(sig_detector.stats.get('rules',[]) if isinstance(sig_detector.stats, dict) else [])} rules",
         "count": getattr(sig_detector, "_match_count", 0)},
        {"name": "Anomaly ML",      "id": "anomaly",    "status": "ok",
         "desc": "IsolationForest active",
         "count": pipeline_state.get("alerts_total", 0)},
        {"name": "Correlation",     "id": "correlation","status": "ok",
         "desc": f"{len(_recent_chains)} active chains",
         "count": len(_recent_chains)},
        {"name": "Packet Analyzer", "id": "pktanalyzer","status": "ok",
         "desc": f"ML {'trained' if _packet_analyzer.stats.get('ml_trained') else 'training'}",
         "count": _packet_analyzer.stats.get("total_flows", 0)},
        {"name": "Sigma Engine",    "id": "sigma",      "status": "ok",
         "desc": f"{len(sigma_engine._rules)} rules",
         "count": getattr(sigma_engine, "_match_count", 0)},
        {"name": "YARA Scanner",    "id": "yara",       "status": "ok",
         "desc": "2 rulesets",
         "count": getattr(yara_scanner, "_scan_count", 0)},
        {"name": "UEBA Engine",     "id": "ueba",       "status": "ok",
         "desc": f"{len(getattr(ueba_engine,'_profiles',{}))} profiles",
         "count": len(getattr(ueba_engine,"_profiles",{}))},
        {"name": "Alert Responder", "id": "responder",  "status": "ok",
         "desc": f"Auto-block: {CONFIG.get('response',{}).get('auto_block',False)}",
         "count": len(_recent_responses)},
    ]
    pa_stats = _packet_analyzer.stats
    return {
        "running":    pipeline_state.get("running", False),
        "mode":       pipeline_state.get("mode","stopped"),
        "interface":  pipeline_state.get("interface","—"),
        "uptime":     uptime,
        "pps":        pps,
        "packets":    pipeline_state.get("packets_processed", 0),
        "flows":      pipeline_state.get("flows_analyzed", 0),
        "alerts":     pipeline_state.get("alerts_total", 0),
        "chains":     len(_recent_chains),
        "blocked":    len(firewall.list_blocked()),
        "stages":     stages,
        "by_protocol":pa_stats.get("by_protocol", {}),
        "by_direction":pa_stats.get("by_direction", {}),
        "by_l7":      pa_stats.get("by_l7", {}),
        "traffic_history": _traffic_history[-60:],
    }

@app.post("/api/pipeline/start")
def start_pipeline(bg: BackgroundTasks, interface: str = "auto"):
    """Start live packet capture. Requires root/sudo."""
    from capture.sniffer import ROOT_OK as _ROOT_OK
    if pipeline_state["running"]: return {"status": "already_running", "mode": "live"}
    if not _ROOT_OK:
        return {"status": "error", "detail": "Not running as root. Restart with: sudo python3 main.py"}
    iface = interface if interface != "auto" else CONFIG.get("system", {}).get("interface", "auto")
    pipeline_state.update(running=True, mode="live", interface=iface, start_time=time.time())
    def run():
        try: LiveSniffer(interface=iface, callback=_on_packet).start()
        except Exception as e:
            logger.error(f"Pipeline: {e}")
            pipeline_state.update(running=False, mode=f"error:{e}")
    threading.Thread(target=run, daemon=True).start()
    return {"status": "started", "mode": "live", "interface": iface}

@app.post("/api/pipeline/stop")
def stop_pipeline():
    pipeline_state["running"] = False; flow_aggregator.flush_all()
    return {"status": "stopped"}

@app.post("/api/report/generate")
def generate_report():
    path = reporter.generate_html_report(alerts=_recent_alerts,
        chains=correlation_engine.get_all_chains(), response_log=responder.log.get_all())
    return {"status": "generated", "path": path}

@app.get("/api/report/{filename}")
def serve_report(filename: str):
    p = Path("data/reports") / filename
    if not p.exists(): raise HTTPException(404, "Not found")
    mt = "application/pdf" if filename.endswith(".pdf") else "text/html"
    return FileResponse(p, media_type=mt)

@app.post("/api/report/generate-pdf")
def generate_pdf_report():
    """Generate a full PDF SOC report — no API key, pure Python (reportlab)."""
    try:
        if not pdf_available():
            return JSONResponse({"error": f"reportlab not installed. {pdf_install_hint()}"}, 503)
        compliance_results = {}
        try:
            from compliance.checker import ComplianceChecker
            cc = ComplianceChecker()
            sys_state = {
                "alerts_total": len(_recent_alerts),
                "modules_active": ["network_ids","signature_detection","risk_scoring",
                                   "cases","soar","yara","mitre_mapping","logging","dashboard"],
                "agents_registered": 0,
                "cases_total": case_manager.stats().get("total",0),
                "vuln_agents_scanned": 0,
            }
            for fw in ["PCI_DSS_4","HIPAA","NIST_800_53","CIS_V8","ISO_27001","GDPR","SOC2_TYPE2","NIST_CSF"]:
                try:
                    res = cc.run_assessment(sys_state, fw)
                    if "error" not in res:
                        compliance_results[fw] = res
                except Exception:
                    pass
        except Exception:
            pass
        path = pdf_gen.generate(
            alerts=_recent_alerts[-200:],
            cases=case_manager.list()[:50],
            blocked=responder.registry.get_all() if hasattr(responder,"registry") else [],
            compliance_results=compliance_results,
            ioc_stats=ioc_manager.get_stats(),
            ueba_alerts=ueba_engine.get_alerts(20),
            threat_chains=correlation_engine.get_all_chains()[:20],
            pipeline_state=pipeline_state,
        )
        fname = Path(path).name
        return sanitize({"status": "generated", "path": path, "filename": fname,
                "download_url": f"/api/report/{fname}"})
    except Exception as e:
        logger.error(f"PDF generation error: {e}", exc_info=True)
        raise HTTPException(500, str(e))

@app.get("/api/stats")
def get_stats():
    return {"reporter": reporter.get_stats(), "responder": responder.stats,
            "correlator": correlation_engine.stats, "signature": sig_detector.stats,
            "anomaly": anomaly_detector.status, "pipeline": pipeline_state,
            "cases": case_manager.stats(), "ueba": ueba_engine.stats, "ioc": ioc_manager.get_stats()}

# ═══════════════════════════════════════════════════════════════════════════════
# CASE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class CreateCaseReq(BaseModel):
    title: str; description: str=""; severity: str="MEDIUM"
    alert_ids: List[int]=[]; created_by: str="analyst"; sla_hours: int=24

class CommentReq(BaseModel):
    text: str; author: str="analyst"

class EvidenceReq(BaseModel):
    name: str; type: str; content: str; added_by: str="analyst"

class TransitionReq(BaseModel):
    status: str; comment: Optional[str]=None; author: str="analyst"

class AssignReq(BaseModel):
    analyst: str

@app.get("/api/cases")
def list_cases(status: str=None, severity: str=None, limit: int=50):
    return {"cases": case_manager.list(status=status, severity=severity, limit=limit),
            "stats": case_manager.stats()}

@app.post("/api/cases")
def create_case(req: CreateCaseReq):
    return {"case": case_manager.create_case(req.title, req.description, req.severity,
                                              req.alert_ids, req.created_by, req.sla_hours).to_dict()}

@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    c = case_manager.get(case_id)
    if not c: raise HTTPException(404, f"Case {case_id} not found")
    return c.to_dict()

@app.post("/api/cases/{case_id}/comments")
def add_comment(case_id: str, req: CommentReq):
    r = case_manager.add_comment(case_id, req.text, req.author)
    if not r: raise HTTPException(404, "Case not found")
    return {"comment": r}

@app.post("/api/cases/{case_id}/evidence")
def add_evidence(case_id: str, req: EvidenceReq):
    r = case_manager.add_evidence(case_id, req.name, req.type, req.content, req.added_by)
    if not r: raise HTTPException(404, "Case not found")
    return {"evidence": r}

@app.patch("/api/cases/{case_id}/status")
def transition_case(case_id: str, req: TransitionReq):
    r = case_manager.transition(case_id, req.status, req.comment, req.author)
    if not r: raise HTTPException(404, "Case not found")
    return {"case": r}

@app.patch("/api/cases/{case_id}/assign")
def assign_case(case_id: str, req: AssignReq):
    r = case_manager.assign(case_id, req.analyst)
    if not r: raise HTTPException(404, "Case not found")
    return {"case": r}

@app.post("/api/cases/{case_id}/escalate")
def escalate_case(case_id: str, req: CommentReq):
    r = case_manager.escalate(case_id, req.text, req.author)
    if not r: raise HTTPException(404, "Case not found")
    return {"case": r}

@app.post("/api/cases/from-alert/{alert_id}")
def case_from_alert(alert_id: int):
    a = next((x for x in reversed(_recent_alerts) if x.get("id")==alert_id), None)
    if not a: raise HTTPException(404, f"Alert {alert_id} not found")
    return {"case": case_manager.create_from_alert(a).to_dict()}

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

class IOCReq(BaseModel):
    indicator: str; ioc_type: str="ip"; source: str="manual"; score: int=75; tags: List[str]=[]

@app.get("/api/intel/stats")
def intel_stats(): return ioc_manager.get_stats()

@app.get("/api/intel/iocs")
def list_iocs(ioc_type: str=None, limit: int=200):
    return {"iocs": ioc_manager.get_all(limit=limit)}

@app.post("/api/intel/iocs")
def add_ioc(req: IOCReq):
    return {"result": ioc_manager.add_ioc(req.indicator, req.ioc_type, req.source, req.score, req.tags)}

@app.get("/api/intel/lookup/{indicator}")
def lookup_ioc(indicator: str):
    r = ioc_manager.store.lookup_ip(indicator)
    return {"result": r, "found": r is not None}

@app.post("/api/intel/feeds/refresh")
def refresh_feeds(force: bool = False):
    """
    Trigger download of all FEED_CATALOG threat intelligence feeds.
    Runs in a background thread — returns immediately.
    Use GET /api/intel/feeds/status to track progress.
    """
    ioc_manager.start_feed_refresh(background=True, force=force)
    return {
        "ok":          True,
        "message":     f"Refresh started for {len(ioc_manager.feed_status())} feeds",
        "feeds_total": len(ioc_manager.feed_status()),
        "background":  True,
    }

@app.get("/api/intel/feeds/status")
def feed_status():
    """Per-feed download status: name, ok, added, ts, error."""
    stats = ioc_manager.get_stats()
    return {
        "feeds":      ioc_manager.feed_status(),
        "store":      stats,
        "refreshing": stats.get("feeds_refreshing", False),
    }


@app.post("/api/intel/iocs/add")
def add_ioc_manual(req: dict):
    """Manually add an IOC."""
    try:
        indicator = req.get("indicator","").strip()
        ioc_type  = req.get("type", "ip")
        severity  = req.get("severity", "HIGH")
        tags      = req.get("tags", [])
        if not indicator:
            return {"success": False, "message": "indicator required"}
        ioc_manager.add_ioc(ioc_type, indicator, "manual", severity, tags)
        return {"success": True, "indicator": indicator}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.delete("/api/intel/iocs/{indicator}")
def delete_ioc(indicator: str):
    # IOCStore doesn't have a delete method — just return success stub
    return {"deleted": indicator, "note": "Remove manually from data/ioc_db.json"}

# ═══════════════════════════════════════════════════════════════════════════════
# UEBA
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ueba/stats")
def ueba_stats(): return ueba_engine.stats

@app.get("/api/ueba/anomalies")
def ueba_anomalies(limit: int=50): return {"anomalies": ueba_engine.get_alerts(limit)}

@app.get("/api/ueba/entities")
def ueba_entities(): return {"entities": ueba_engine.get_entity_risk_scores()}

@app.get("/api/ueba/entities/{entity_id}")
def ueba_entity(entity_id: str):
    p = ueba_engine.get_entity_risk_scores(entity_id)
    if not p: raise HTTPException(404, f"Entity {entity_id} not found")
    return p

@app.post("/api/ueba/ingest")
def ueba_ingest(event: dict): return {"anomaly": ueba_engine.ingest_event(event)}

# ═══════════════════════════════════════════════════════════════════════════════
# SOAR PLAYBOOKS
# ═══════════════════════════════════════════════════════════════════════════════

class RunPBReq(BaseModel):
    alert: dict; dry_run: bool=False

class CreatePBReq(BaseModel):
    name: str; description: str=""; trigger_severity: List[str]=["CRITICAL"]
    trigger_type: Optional[str]=None; steps: List[dict]=[]; enabled: bool=True

@app.get("/api/playbooks")
def list_playbooks(): return {"playbooks": playbook_engine.get_playbooks()}

@app.post("/api/playbooks")
def create_playbook(req: CreatePBReq):
    return {"playbook": playbook_engine.register_playbook(req.name, req.description,
        req.trigger_severity, req.trigger_type, req.steps, req.enabled)}

@app.post("/api/playbooks/{pb_id}/run")
def run_playbook(pb_id: str, req: RunPBReq):
    r = playbook_engine.execute_playbook(pb_id, req.alert, dry_run=req.dry_run)
    if not r: raise HTTPException(404, f"Playbook {pb_id} not found")
    return {"result": r}

@app.get("/api/playbooks/history")
def playbook_history(limit: int=50): return {"history": playbook_engine.get_executions(limit)}

@app.patch("/api/playbooks/{pb_id}/enable")
def toggle_playbook(pb_id: str, enabled: bool=True):
    return {"updated": True, "note": "Playbook enable/disable not supported in this version"}

# ═══════════════════════════════════════════════════════════════════════════════
# YARA
# ═══════════════════════════════════════════════════════════════════════════════

class YaraScanReq(BaseModel):
    data: str; encoding: str="hex"; context: dict={}

class YaraRuleReq(BaseModel):
    name: str; rule_text: str; tags: List[str]=[]

@app.get("/api/yara/rules")
def list_yara():
    """Return all loaded YARA rules — works with both native yara-python and built-in pattern matcher."""
    rules_out = []
    try:
        # Native yara-python: rules are compiled from .yar files in data/yara_rules/
        if yara_scanner._yara_available and yara_scanner._compiled:
            for p in yara_scanner.rules_dir.glob("*.yar"):
                rules_out.append({
                    "name":   p.stem,
                    "source": "file",
                    "file":   p.name,
                    "status": "compiled",
                    "tags":   [],
                })
        # Built-in pattern matcher: rules from _simple_rules list
        elif yara_scanner._simple_rules:
            for rule in yara_scanner._simple_rules:
                rules_out.append({
                    "name":        getattr(rule, "rule_name", getattr(rule, "name", "unknown")),
                    "source":      "built-in",
                    "description": getattr(rule, "description", ""),
                    "severity":    getattr(rule, "severity", "MEDIUM"),
                    "mitre_id":    getattr(rule, "mitre", getattr(rule, "mitre_id", "")),
                    "tags":        getattr(rule, "tags", []),
                    "status":      "active",
                })
    except Exception as e:
        logger.warning(f"YARA list error: {e}")
    return {
        "rules":       rules_out,
        "rule_count":  len(rules_out),
        "engine":      "native" if getattr(yara_scanner,"_yara_available",False) else "pattern_matcher",
        "recent_hits": yara_scanner.get_results(20),
        "stats":       yara_scanner.stats,
    }

@app.post("/api/yara/rules")
def add_yara(req: YaraRuleReq):
    """Add a new YARA rule from text. Saves to rules dir and recompiles."""
    import tempfile, shutil
    try:
        rules_dir = getattr(yara_scanner, 'rules_dir', None)
        if rules_dir:
            from pathlib import Path as _P
            _P(rules_dir).mkdir(parents=True, exist_ok=True)
            fname = req.name.replace(" ","_").replace("/","_") + ".yar"
            dest  = _P(rules_dir) / fname
            dest.write_text(req.rule_text)
            yara_scanner._setup()   # recompile
            return {"success": True, "message": f"Rule saved to {dest}", "name": req.name}
        else:
            # Fallback: add to _simple_rules directly
            yara_scanner._simple_rules.append({"name": req.name, "text": req.rule_text})
            return {"success": True, "message": "Rule added (in-memory)", "name": req.name}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.delete("/api/yara/rules/{rule_name}")
def delete_yara(rule_name: str):
    """Delete a YARA rule file by name."""
    try:
        from pathlib import Path as _P
        rules_dir = getattr(yara_scanner, 'rules_dir', None)
        if rules_dir:
            for ext in ('.yar', '.yara'):
                f = _P(rules_dir) / (rule_name + ext)
                if f.exists(): f.unlink(); yara_scanner._setup(); return {"success": True}
        return {"success": False, "message": "File not found"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.post("/api/yara/scan")
def yara_scan(req: YaraScanReq):
    try:
        data = binascii.unhexlify(req.data) if req.encoding=="hex" else base64.b64decode(req.data)
    except Exception: raise HTTPException(400, "Invalid data encoding")
    m = yara_scanner.scan_bytes(data, context=req.context)
    return {"matches": m, "hit_count": len(m)}

@app.get("/api/yara/stats")
def yara_stats(): return yara_scanner.stats

# ═══════════════════════════════════════════════════════════════════════════════
# SIGMA
# ═══════════════════════════════════════════════════════════════════════════════

class SigmaImportReq(BaseModel):
    yaml_content: str; source: str="manual"

@app.get("/api/sigma/rules")
def list_sigma(): return {"rules": sigma_engine.get_rules(), "count": sigma_engine.stats.get('total_rules', 0)}

@app.post("/api/sigma/import")
def import_sigma(req: SigmaImportReq):
    result = sigma_engine.load_rule_text(req.yaml_content)
    if result:
        return {"success": True, "rule": result.to_dict(), "message": "Rule imported"}
    return {"success": False, "message": "Failed to parse rule — check YAML syntax"}

@app.delete("/api/sigma/rules/{rule_id}")
def delete_sigma(rule_id: str):
    before = len(sigma_engine._rules)
    sigma_engine._rules = [r for r in sigma_engine._rules if r.rule_id != rule_id]
    removed = before - len(sigma_engine._rules)
    return {"success": removed > 0, "removed": removed}

@app.get("/api/sigma/hits")
def sigma_hits():
    """Get recent Sigma rule hit events."""
    return {"hits": getattr(sigma_engine, "_recent_hits", [])[-100:]}

@app.post("/api/sigma/evaluate")
def eval_sigma(event: dict):
    hits = sigma_engine.evaluate(event)
    return {"hits": hits, "match_count": len(hits)}

@app.get("/api/sigma/stats")
def sigma_stats(): return sigma_engine.stats

# ═══════════════════════════════════════════════════════════════════════════════
# HONEYPOT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/honeypot/status")
def honeypot_status(): return honeypot_mgr.get_status()

@app.get("/api/honeypot/events")
def honeypot_events(limit: int=100):
    return {"events": honeypot_mgr.get_alerts(limit), "stats": honeypot_mgr.stats}

@app.post("/api/honeypot/start")
def start_honeypot(services: List[str]=None):
    return {"result": honeypot_mgr.start(services=services)}

@app.post("/api/honeypot/stop")
def stop_honeypot():
    honeypot_mgr.stop_all(); return {"status": "stopped"}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# IoT / HOTSPOT DETECTION
# ══════════════════════════════════════════════════════════════════════════════
try:
    from siem.iot_detector import hotspot_detector, fingerprint_device, oui_lookup
    _IOT_AVAILABLE = True
except Exception as _iot_err:
    _IOT_AVAILABLE = False
    logger.warning(f"IoT detector unavailable: {_iot_err}")

@app.get("/api/hotspot/status")
def hotspot_status():
    """Detect if laptop is connected to mobile hotspot vs home router."""
    if not _IOT_AVAILABLE:
        return {"available": False, "error": "iot_detector not loaded"}
    result = hotspot_detector.detect()
    return sanitize(result)

@app.get("/api/hotspot/devices")
def hotspot_devices():
    """List devices detected on current hotspot subnet."""
    from siem.iot_detector import fingerprint_device
    devices = []
    # Get from SIEM registry
    if siem_manager and hasattr(siem_manager, '_registry') and siem_manager._registry:
        for ip, dev in siem_manager._registry._devices.items():
            fp = fingerprint_device(dev)
            devices.append({**dev, "fingerprint": fp})
    return sanitize({"devices": devices, "count": len(devices)})

@app.get("/api/network/topology")
def network_topology():
    """Return network topology: interface, gateway, subnet, hotspot status."""
    import subprocess, re as _re
    topo = {"interfaces": [], "default_route": {}, "hotspot": {}}
    try:
        # Get all interfaces with IPs
        out = subprocess.check_output(["ip", "addr", "show"], text=True, timeout=3)
        for block in _re.split(r"\n(?=\d+:)", out):
            name_m = _re.match(r"\d+:\s+(\w+)", block)
            ip_m   = _re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", block)
            if name_m and ip_m:
                name = name_m.group(1)
                if name.startswith("lo"): continue
                topo["interfaces"].append({
                    "name": name,
                    "ip":   ip_m.group(1),
                    "cidr": ip_m.group(2),
                    "is_vpn": name.startswith(("tun","tap","tailscale")),
                    "is_wireless": name.startswith("wlan"),
                    "is_tethering": name.startswith(("usb","rndis","bnep")),
                })
    except Exception as e:
        topo["error"] = str(e)

    if _IOT_AVAILABLE:
        topo["hotspot"] = hotspot_detector.detect()

    return sanitize(topo)

@app.get("/api/compliance/frameworks")
def list_frameworks(): return {"frameworks": compliance.list_frameworks()}

@app.post("/api/compliance/check/{framework}")
def run_compliance(framework: str, host_data: dict=None):
    return {"result": compliance.check(framework, host_data or {}, alerts=_recent_alerts)}

@app.get("/api/compliance/report")
def compliance_report(): return compliance.summary_report(alerts=_recent_alerts)

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class ScanReq(BaseModel):
    host: str; packages: Optional[List[dict]]=None




@app.post("/api/assets/clear")
def clear_assets_inventory():
    """Clear all discovered assets — use when switching networks."""
    try:
        asset_inv.clear()
        return {"ok": True, "message": "Asset inventory cleared"}
    except Exception as e:
        logger.error(f"Asset clear error: {e}")
        return {"ok": False, "error": str(e)}

@app.post("/api/siem/devices/clear")
def clear_siem_devices_list():
    """Clear WiFi Monitor device list — use when switching networks."""
    try:
        if siem_manager and hasattr(siem_manager, '_registry') and siem_manager._registry:
            siem_manager._registry.clear()
        else:
            from pathlib import Path as _Path
            _Path("data/siem_devices.json").write_text("[]")
        return {"ok": True, "cleared": True}
    except Exception as e:
        logger.error(f"Device registry clear error: {e}")
        return {"ok": False, "error": str(e)}
# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC TIMELINE
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/forensics/stats")
def forensics_stats():
    return forensics.stats

@app.get("/api/forensics/timelines")
def list_timelines(src_ip: str = None, since_ts: float = None, limit: int = 100):
    """List all forensic timelines with summary info."""
    return {"timelines": forensics.list(src_ip=src_ip, since_ts=since_ts, limit=limit)}

@app.get("/api/forensics/timeline")
def get_all_events(src_ip: str = None, severity: str = None,
                   since_ts: float = None, limit: int = 200):
    """Flat event list across all timelines. Supports src_ip, severity, since_ts filters."""
    return {"events": forensics.get_all_events(src_ip=src_ip, severity=severity,
                                               since_ts=since_ts, limit=limit)}

@app.get("/api/forensics/timeline/{timeline_id}")
def get_timeline(timeline_id: str):
    """Full timeline: events + process tree + pivot graph + attack narrative."""
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return tl.to_dict()

@app.get("/api/forensics/timeline/{timeline_id}/events")
def get_timeline_events(timeline_id: str, source: str = None, severity: str = None,
                        mitre_id: str = None, src_ip: str = None, limit: int = 500):
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return {"events": tl.get_events(source=source, severity=severity,
                                    mitre_id=mitre_id, src_ip=src_ip, limit=limit)}

@app.get("/api/forensics/timeline/{timeline_id}/replay")
def get_session_replay(timeline_id: str, src_ip: str):
    """Step-by-step session replay for an attacker IP."""
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return {"replay": tl.get_session_replay(src_ip), "src_ip": src_ip}

@app.get("/api/forensics/timeline/{timeline_id}/pivot")
def get_pivot_graph(timeline_id: str):
    """Lateral movement graph: nodes + directed edges."""
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return tl.get_pivot_graph()

@app.get("/api/forensics/timeline/{timeline_id}/iocs")
def get_timeline_iocs(timeline_id: str):
    """Extract all IOCs (IPs, domains, hashes, URLs) from a timeline."""
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return tl.extract_iocs()

@app.get("/api/forensics/timeline/{timeline_id}/narrative")
def get_attack_narrative(timeline_id: str):
    """MITRE ATT&CK kill-chain narrative grouped by tactic stage."""
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return {"narrative": tl.get_attack_narrative(), "timeline_id": timeline_id}

@app.get("/api/forensics/timeline/{timeline_id}/process_tree")
def get_process_tree(timeline_id: str):
    tl = forensics.get(timeline_id)
    if not tl: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return {"process_tree": tl.get_process_tree()}

@app.get("/api/forensics/timeline/{timeline_id}/export")
def export_timeline(timeline_id: str):
    """Download full forensic case as ZIP (timeline, IOCs, pivot graph, replay, narrative)."""
    from fastapi.responses import Response as _Resp
    data = forensics.export_zip(timeline_id)
    if not data: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return _Resp(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{timeline_id}_forensics.zip"'},
    )

@app.post("/api/forensics/timeline/{timeline_id}/pcap")
def correlate_pcap(timeline_id: str, body: dict):
    """Correlate raw packet records to timeline events by IP+timestamp proximity."""
    return forensics.correlate_pcap(timeline_id, body.get("filename",""), body.get("packets",[]))

@app.post("/api/forensics/timeline")
def create_timeline(body: dict):
    tl = forensics.create_timeline(body.get("entity","unknown"), body.get("description",""))
    return {"timeline": tl.summary()}

@app.delete("/api/forensics/timeline/{timeline_id}")
def delete_timeline(timeline_id: str):
    ok = forensics.delete(timeline_id)
    if not ok: raise HTTPException(404, f"Timeline {timeline_id} not found")
    return {"deleted": timeline_id}

@app.get("/api/forensics/chains/{chain_id}")
def get_chain_timeline(chain_id: str):
    """Get timeline for an attack chain ID."""
    tl = next((t for t in [forensics.get(tid) for tid in
                [t["timeline_id"] for t in forensics.list()]]
               if t and chain_id in t.description), None)
    if not tl: raise HTTPException(404, f"No timeline for chain {chain_id}")
    return tl.to_dict()

@app.post("/api/forensics/from-chain/{chain_id}")
def forensics_from_chain(chain_id: str):
    """Auto-build a forensic timeline from an existing attack chain."""
    chain = next((c for c in correlation_engine.get_all_chains()
                  if str(c.get("chain_id","")) == chain_id), None)
    if not chain: raise HTTPException(404, f"Chain {chain_id} not found")
    tl = forensics.create_from_chain(chain, _recent_alerts)
    return {"timeline": tl.summary()}

@app.post("/api/forensics/ingest")
def ingest_forensic(event: dict):
    forensics.ingest_host_event(event)
    return {"status": "ingested"}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA LAKE
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/datalake/stats")
def datalake_stats(): return data_lake.stats()

@app.get("/api/db/stats")
def db_stats():
    """Row counts and buffer depths for the SQLite writer."""
    return {**sqlite_writer.stats, "table_counts": sqlite_writer.db_stats()}


@app.get("/api/dns/resolve/{ip}")
def dns_resolve_ip(ip: str):
    """Reverse DNS lookup for an IP — no API key, uses system resolver."""
    import socket as _socket
    try:
        hostname = _socket.gethostbyaddr(ip)[0]
        return {"ip": ip, "hostname": hostname, "resolved": True}
    except Exception:
        return {"ip": ip, "hostname": "", "resolved": False}

@app.post("/api/dns/bulk-resolve")
def dns_bulk_resolve(body: dict):
    """Bulk reverse DNS lookup for up to 20 IPs."""
    import socket as _socket, concurrent.futures
    ips = (body.get("ips") or [])[:20]
    def _resolve(ip):
        try:
            return ip, _socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, ""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for ip, hostname in ex.map(_resolve, ips):
            results[ip] = hostname
    return {"results": results}
@app.get("/api/dns/recent")
def dns_recent(name: str = None, src_ip: str = None, limit: int = 200):
    """Recent DNS queries extracted from captured traffic."""
    return {"events": sqlite_writer.query_dns(name=name, src_ip=src_ip, limit=limit)}

@app.get("/api/datalake/query")
def query_datalake(category: str="alert", since_ts: float=None, src_ip: str=None, limit: int=500):
    return sanitize({"records": data_lake.query(category=category, since_ts=since_ts, src_ip=src_ip, limit=limit)})

@app.delete("/api/datalake/prune")
def prune_datalake(older_than_days: int=90):
    return {"pruned": data_lake.archive(older_than_days)}

# ═══════════════════════════════════════════════════════════════════════════════
# RBAC / AUTH
# ═══════════════════════════════════════════════════════════════════════════════

class LoginReq(BaseModel):
    username: str; password: str

class CreateUserReq(BaseModel):
    username: str; password: str; role: str="analyst"; email: Optional[str]=None

@app.post("/api/auth/login")
def login(req: LoginReq):
    token = rbac.login(req.username, req.password)
    if not token: raise HTTPException(401, "Invalid credentials")
    return {"token": token, "user": rbac.get_user(req.username)}

@app.post("/api/auth/users")
def create_user(req: CreateUserReq):
    r = rbac.create_user(req.username, req.password, req.role, req.email)
    if not r: raise HTTPException(409, f"User {req.username} exists")
    return {"user": r}

@app.get("/api/auth/users")
def list_users(): return {"users": rbac.list_users()}

@app.delete("/api/auth/users/{username}")
def delete_user(username: str):
    rbac.delete_user(username); return {"deleted": username}

@app.get("/api/auth/roles")
def list_roles(): return {"roles": rbac.list_roles()}

# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    cfg = CONFIG.get("api", {})
    uvicorn.run("server:app", host=cfg.get("host","0.0.0.0"),
                port=cfg.get("port",8000), reload=False, log_level="info")

# ═════════════════════════════════════════════════════════════════════════════
# v1.2 ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

# ── Config ────────────────────────────────────────────────────────────────────
class CfgUpdate(BaseModel):
    section: str; key: str; value: object

@app.get("/api/config")
def get_config():
    cfg = load_config()
    for sec in ["rbac","threat_intel","geoip","notifications"]:
        for k,v in (cfg.get(sec,{})).items():
            if any(x in k.lower() for x in ["secret","password","key","token","webhook"]) and v:
                cfg[sec][k] = str(v)[:4]+"***"
    return {"config": cfg}

@app.post("/api/config")
def update_config(u: CfgUpdate):
    p = Path(__file__).parent.parent/"config"/"settings.yaml"
    cfg = yaml.safe_load(p.read_text()) if p.exists() else {}
    cfg.setdefault(u.section,{})[u.key] = u.value
    p.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True))
    # Update live CONFIG dict too
    CONFIG.setdefault(u.section, {})[u.key] = u.value
    log_manager.log_event("config_change", f"{u.section}.{u.key} updated")
    return {"updated": True, "live": True}

@app.post("/api/config/profile/{profile}")
def apply_profile(profile: str):
    presets = {
        "laptop": {"capture.sim_rate":0.1,"response.auto_block_high":False,"assets.scan_interval_seconds":600},
        "home":   {"capture.sim_rate":0.05,"response.auto_block_high":False,"assets.scan_interval_seconds":300},
        "office": {"capture.sim_rate":0.02,"response.auto_block_high":True,"assets.scan_interval_seconds":180},
        "cloud":  {"capture.sim_rate":0.01,"response.auto_block_high":True,"assets.scan_interval_seconds":120},
    }
    if profile not in presets: raise HTTPException(400,"Unknown profile")
    preset = presets[profile]
    # Write to YAML so it persists across restarts
    p = Path(__file__).parent.parent / "config" / "settings.yaml"
    cfg = yaml.safe_load(p.read_text()) if p.exists() else {}
    for dotkey, val in preset.items():
        parts = dotkey.split(".")
        d = cfg
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = val
    p.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True))
    # Also apply to live in-memory CONFIG immediately (no restart needed)
    for dotkey, val in preset.items():
        parts = dotkey.split(".")
        d = CONFIG
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = val
    log_manager.log_event("config_change", f"Profile {profile} applied live")
    return {"profile": profile, "applied": preset, "live": True, "restart_required": False}

# ── Logs ──────────────────────────────────────────────────────────────────────
@app.get("/api/logs/stats")
def log_stats(): return log_manager.stats()

@app.get("/api/logs/{channel}")
def query_logs(channel: str, text: str="", ip: str="",
               severity: str="", since_hours: int=24, limit: int=200):
    if channel not in log_manager.channels:
        raise HTTPException(400, f"Unknown channel. Valid: {','.join(log_manager.CHANNELS)}")
    return {"records": log_manager.search(channel,text=text,ip=ip,
                                          severity=severity,since_hours=since_hours,limit=limit),
            "channel": channel}

@app.get("/api/logs/{channel}/export")
def export_logs(channel: str, since_hours: int=24, fmt: str="csv"):
    if fmt == "csv":
        data = log_manager.export_csv(channel, since_hours=since_hours)
        return Response(content=data, media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={channel}-export.csv"})
    records = log_manager.search(channel, since_hours=since_hours, limit=10000)
    return Response(content=json.dumps(records,indent=2,default=str), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={channel}-export.json"})

# ── Firewall ──────────────────────────────────────────────────────────────────
class FWBlockReq(BaseModel):
    ip: str; reason: str="manual"; ttl: Optional[int]=None


@app.get("/api/firewall/ufw-status")
def fw_ufw_status():
    """Get UFW firewall status, rules, and system firewall info."""
    import subprocess, shutil
    result = {
        "backend": firewall.backend_name,
        "ufw_available": shutil.which("ufw") is not None,
        "iptables_available": shutil.which("iptables") is not None,
        "nft_available": shutil.which("nft") is not None,
        "ufw_status": "unknown",
        "ufw_rules": [],
        "ufw_active": False,
        "system_rules": [],
        "interfaces": [],
    }
    # UFW status
    if result["ufw_available"]:
        try:
            r = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=8)
            result["ufw_raw"] = r.stdout[:3000]
            result["ufw_active"] = "active" in r.stdout.lower() and "inactive" not in r.stdout.lower()
            result["ufw_status"] = "active" if result["ufw_active"] else "inactive"
            # Parse rules
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("--") or line.startswith("Status"): continue
                if any(x in line for x in ["ALLOW","DENY","REJECT","LIMIT"]):
                    parts = line.split()
                    result["ufw_rules"].append({
                        "raw": line,
                        "to": parts[0] if parts else "",
                        "action": next((p for p in parts if p in ["ALLOW","DENY","REJECT","LIMIT"]), ""),
                        "from": parts[-1] if len(parts) > 1 else "",
                    })
        except Exception as e:
            result["ufw_error"] = str(e)
    # Network interfaces
    try:
        import socket
        import netifaces
        result["interfaces"] = netifaces.interfaces()
    except Exception:
        try:
            r2 = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True, timeout=5)
            result["interfaces"] = [l.split()[0] for l in r2.stdout.splitlines() if l.strip()]
        except Exception:
            result["interfaces"] = []
    return result

@app.get("/api/firewall/status")
def fw_status(): return firewall.stats()

@app.get("/api/firewall/blocked")
def fw_blocked(): return {"blocked": firewall.list_blocked(), "count": len(firewall.list_blocked())}

@app.get("/api/firewall/rules")
def fw_rules(): return {"rules": firewall.list_rules(), "backend": firewall.backend_name}

@app.post("/api/firewall/block")
def fw_block(req: FWBlockReq):
    result = firewall.block_ip(req.ip, reason=req.reason, ttl=req.ttl)
    log_manager.log_block(req.ip, req.reason, action="BLOCK", backend=firewall.backend_name)
    return result

@app.delete("/api/firewall/block/{ip}")
def fw_unblock(ip: str):
    result = firewall.unblock_ip(ip, "manual_api")
    log_manager.log_block(ip, "manual_unblock", action="UNBLOCK")
    return result

@app.post("/api/firewall/flush")
def fw_flush():
    log_manager.log_event("firewall_flush","All rules flushed")
    return firewall.flush_all()

class FWRuleReq(BaseModel):
    action: str = "DROP"          # DROP, ACCEPT, REJECT, LOG
    direction: str = "inbound"    # inbound, outbound, both
    protocol: str = "any"         # any, tcp, udp, icmp, http, https, ssh, dns, smtp, rdp, smb, ftp, telnet, custom
    ip: str = ""                  # source/dest IP or CIDR (empty = any)
    port: str = ""                # port or range e.g. "80" or "8000:9000" (empty = any)
    reason: str = "manual rule"
    ttl: int = 0                  # 0 = permanent

@app.get("/api/firewall/full-rules")
def fw_full_rules():
    """Get all rules including port/protocol rules from in-memory store."""
    blocked = firewall.list_blocked()
    # Map blocked IPs to rule format
    rules = []
    for b in blocked:
        rules.append({
            "id": b.get("ip",""),
            "type": "ip_block",
            "ip": b.get("ip",""),
            "protocol": "any",
            "port": "",
            "direction": "inbound",
            "action": "DROP",
            "reason": b.get("reason",""),
            "created_at": b.get("blocked_at",""),
            "expires_at": b.get("expires_at",""),
            "backend": b.get("backend",""),
        })
    # Add custom port/protocol rules from _fw_custom_rules store
    for r in _fw_custom_rules:
        rules.append(r)
    return {"rules": rules, "backend": firewall.backend_name, "count": len(rules)}

@app.post("/api/firewall/rule")
def fw_add_rule(req: FWRuleReq, request: Request):
    """Add a firewall rule with full protocol/port/direction support."""
    import uuid, time as _t
    rule_id = str(uuid.uuid4())[:8]
    # Resolve port number for known protocol shortcuts
    PROTO_PORTS = {
        "http": ("tcp","80"), "https": ("tcp","443"), "ssh": ("tcp","22"),
        "dns": ("udp","53"), "ftp": ("tcp","21"), "telnet": ("tcp","23"),
        "smtp": ("tcp","25,587"), "rdp": ("tcp","3389"), "smb": ("tcp","445"),
        "mysql": ("tcp","3306"), "postgres": ("tcp","5432"),
        "redis": ("tcp","6379"), "mongodb": ("tcp","27017"),
        "ldap": ("tcp","389"), "ntp": ("udp","123"), "icmp": ("icmp",""),
        "snmp": ("udp","161"), "bgp": ("tcp","179"),
    }
    proto = req.protocol.lower()
    port  = req.port
    if proto in PROTO_PORTS and not port:
        proto, port = PROTO_PORTS[proto]
    if proto == "any": proto = ""
    # Build iptables-style command
    ip_part = req.ip if req.ip else "0.0.0.0/0"
    action_map = {"DROP":"DROP","ACCEPT":"ACCEPT","REJECT":"REJECT","LOG":"LOG --log-prefix CyberRemedy"}
    iptables_action = action_map.get(req.action.upper(), "DROP")
    chain = "INPUT" if req.direction in ("inbound","both") else "OUTPUT"
    cmd_parts = ["iptables", "-I", chain]
    if proto: cmd_parts += ["-p", proto]
    if req.ip: cmd_parts += ["-s" if req.direction in ("inbound","both") else "-d", ip_part]
    if port: cmd_parts += ["--dport", port]
    cmd_parts += ["-j", iptables_action]
    import subprocess as _sp
    result = {"success": False, "message": "dry-run or sim"}
    if not firewall.dry_run:
        try:
            _sp.run(cmd_parts, check=True, capture_output=True)
            result = {"success": True, "message": " ".join(cmd_parts)}
        except Exception as e:
            result = {"success": False, "message": str(e), "cmd": " ".join(cmd_parts)}
    else:
        result = {"success": True, "message": f"DRY-RUN: {' '.join(cmd_parts)}"}
    rule = {
        "id": rule_id,
        "type": "custom_rule",
        "ip": req.ip or "any",
        "protocol": req.protocol,
        "port": port or "any",
        "direction": req.direction,
        "action": req.action.upper(),
        "reason": req.reason,
        "created_at": __import__("datetime").datetime.utcnow().isoformat(),
        "expires_at": None,
        "backend": firewall.backend_name,
        "cmd": " ".join(cmd_parts),
        "applied": result["success"],
    }
    _fw_custom_rules.append(rule)
    log_manager.log_event("firewall_rule_add", f"{req.action} {req.ip or 'any'} proto={req.protocol} port={port or 'any'}")
    return {"success": result["success"], "rule": rule, "message": result["message"]}

@app.delete("/api/firewall/rule/{rule_id}")
def fw_delete_rule(rule_id: str):
    global _fw_custom_rules
    before = len(_fw_custom_rules)
    _fw_custom_rules = [r for r in _fw_custom_rules if r.get("id") != rule_id]
    return {"success": before != len(_fw_custom_rules), "remaining": len(_fw_custom_rules)}

# ── Assets ────────────────────────────────────────────────────────────────────
class LabelReq(BaseModel):
    ip: str; label: str

@app.get("/api/assets")
def get_assets(): return {"assets": asset_inv.get_all(), "stats": asset_inv.stats()}

@app.post("/api/assets/scan")
def trigger_scan(bg: BackgroundTasks):
    bg.add_task(asset_inv.scan); return {"status": "scan_started"}

@app.get("/api/assets/{ip}")
def get_asset(ip: str):
    d = asset_inv.get_device(ip)
    if not d: raise HTTPException(404, f"Device {ip} not found")
    alerts = [sanitize(a) for a in _recent_alerts if a.get("src_ip")==ip or a.get("dst_ip")==ip]
    return {"device": d, "alerts": alerts}

@app.post("/api/assets/label")
def label_asset(req: LabelReq):
    asset_inv.label_device(req.ip, req.label)
    return {"labelled": req.ip, "label": req.label}

# ── GeoIP / Map ───────────────────────────────────────────────────────────────
@app.get("/api/geoip/{ip}")
def geo_lookup(ip: str): return geoip.lookup(ip)


# ══════════════════════════════════════════════════════════════════════════════
# ATTACKER SOURCE TRACKING — /api/tracker/{ip}
# Aggregates all available intel on an IP: GeoIP, WHOIS/RDAP, reverse DNS,
# Shodan InternetDB, alert history, and attack chain membership.
# All lookups use free, key-less public APIs with a 10s timeout per source.
# ══════════════════════════════════════════════════════════════════════════════

import urllib.request as _urllib_req
import urllib.error  as _urllib_err

def _tracker_fetch(url: str, timeout: int = 8) -> dict:
    """Fetch JSON from a URL, return {} on any error."""
    try:
        req = _urllib_req.Request(url, headers={"User-Agent": "CyberRemedy/1.0"})
        with _urllib_req.urlopen(req, timeout=timeout) as r:
            import json as _j
            return _j.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}

def _tracker_fetch_text(url: str, timeout: int = 8) -> str:
    """Fetch plain text from a URL, return "" on any error."""
    try:
        req = _urllib_req.Request(url, headers={"User-Agent": "CyberRemedy/1.0"})
        with _urllib_req.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def _reverse_dns(ip: str) -> str:
    """PTR record lookup — no external HTTP needed."""
    import socket as _sock
    try:
        return _sock.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def _build_ip_profile(ip: str) -> dict:
    """
    Collect everything known about an IP from all available sources.
    Returns a unified profile dict.
    """
    import concurrent.futures as _cf
    import json as _j

    profile: dict = {"ip": ip, "sources": {}}

    # ── Source 1: ip-api.com (ISP, ASN, city, proxy/VPN detection) ──────────
    def _ipapi():
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        d = _tracker_fetch(f"http://ip-api.com/json/{ip}?fields={fields}")
        if d.get("status") == "success":
            return {
                "country":      d.get("country",""),
                "country_code": d.get("countryCode",""),
                "region":       d.get("regionName",""),
                "city":         d.get("city",""),
                "lat":          d.get("lat", 0),
                "lon":          d.get("lon", 0),
                "isp":          d.get("isp",""),
                "org":          d.get("org",""),
                "as_number":    d.get("as",""),
                "as_name":      d.get("asname",""),
                "timezone":     d.get("timezone",""),
                "reverse_dns":  d.get("reverse",""),
                "is_mobile":    d.get("mobile", False),
                "is_proxy":     d.get("proxy", False),
                "is_hosting":   d.get("hosting", False),
            }
        return {}

    # ── Source 2: Shodan InternetDB (open ports, vulns, tags) ───────────────
    def _shodan():
        d = _tracker_fetch(f"https://internetdb.shodan.io/{ip}")
        return {
            "open_ports":  d.get("ports", []),
            "hostnames":   d.get("hostnames", []),
            "tags":        d.get("tags", []),
            "cpes":        d.get("cpes", []),
            "vulns":       d.get("vulns", []),
        } if d and "detail" not in d else {}

    # ── Source 3: RDAP / ARIN WHOIS ─────────────────────────────────────────
    def _rdap():
        # Try ARIN first, fall back to RDAP bootstrap
        d = _tracker_fetch(f"https://rdap.arin.net/registry/ip/{ip}")
        if not d:
            d = _tracker_fetch(f"https://rdap.db.ripe.net/ip/{ip}")
        if not d:
            return {}
        result = {}
        # Org name
        entities = d.get("entities", [])
        for ent in entities:
            vcard = ent.get("vcardArray", [])
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item[0] == "fn":
                        result["whois_org"] = item[3]
                        break
            roles = ent.get("roles", [])
            if "abuse" in roles:
                # Extract abuse email
                for item in (vcard[1] if len(vcard)>1 else []):
                    if isinstance(item, list) and item[0] == "email":
                        result["abuse_email"] = item[3]
                        break
        # Network range
        result["net_handle"]  = d.get("handle","")
        result["net_name"]    = d.get("name","")
        result["net_type"]    = d.get("type","")
        result["start_addr"]  = d.get("startAddress","")
        result["end_addr"]    = d.get("endAddress","")
        result["reg_date"]    = d.get("events",[{}])[0].get("eventDate","") if d.get("events") else ""
        return result

    # ── Source 4: AbuseIPDB check (public, no key for basic info) ───────────
    def _abuse_check():
        # Use the free ipwho.is as alternative enrichment
        d = _tracker_fetch(f"https://ipwho.is/{ip}")
        if d.get("success"):
            return {
                "connection_type": d.get("connection", {}).get("type",""),
                "isp_org":         d.get("connection", {}).get("org",""),
                "isp_domain":      d.get("connection", {}).get("domain",""),
                "asn":             d.get("connection", {}).get("asn",""),
            }
        return {}

    # ── Source 5: Reverse DNS ────────────────────────────────────────────────
    def _rdns():
        hostname = _reverse_dns(ip)
        return {"ptr_record": hostname} if hostname else {}

    # ── Run all lookups in parallel (max 10s total) ──────────────────────────
    with _cf.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            "geo":     ex.submit(_ipapi),
            "shodan":  ex.submit(_shodan),
            "rdap":    ex.submit(_rdap),
            "ipwho":   ex.submit(_abuse_check),
            "rdns":    ex.submit(_rdns),
        }
        for name, fut in futures.items():
            try:
                profile["sources"][name] = fut.result(timeout=10)
            except Exception:
                profile["sources"][name] = {}

    # ── Source 6: Local alert history ────────────────────────────────────────
    ip_alerts = [a for a in _recent_alerts if a.get("src_ip") == ip]
    if ip_alerts:
        attack_types = {}
        for a in ip_alerts:
            t = a.get("type","unknown")
            attack_types[t] = attack_types.get(t, 0) + 1
        profile["sources"]["history"] = {
            "total_alerts":    len(ip_alerts),
            "first_seen":      min(a.get("timestamp","") for a in ip_alerts),
            "last_seen":       max(a.get("timestamp","") for a in ip_alerts),
            "attack_types":    attack_types,
            "max_severity":    max(
                ("CRITICAL","HIGH","MEDIUM","LOW").index(a.get("severity","LOW"))
                for a in ip_alerts
            ),
            "severities":      {s: sum(1 for a in ip_alerts if a.get("severity")==s)
                                 for s in ("CRITICAL","HIGH","MEDIUM","LOW")},
            "mitre_ids":       list({a.get("mitre_id","") for a in ip_alerts if a.get("mitre_id")}),
            "is_blocked":      ip in (responder.registry.get_all() if hasattr(responder,"registry") else {}),
        }

    # ── Source 7: Attack chain membership ────────────────────────────────────
    ip_chains = [c for c in _recent_chains if c.get("src_ip") == ip]
    if ip_chains:
        profile["sources"]["chains"] = {
            "chain_count":  len(ip_chains),
            "chain_ids":    [c.get("id","") for c in ip_chains],
            "stages":       list({s for c in ip_chains for s in c.get("stages",[])}),
            "total_events": sum(c.get("event_count",0) for c in ip_chains),
        }

    # ── Threat verdict ────────────────────────────────────────────────────────
    geo     = profile["sources"].get("geo", {})
    shodan  = profile["sources"].get("shodan", {})
    history = profile["sources"].get("history", {})
    rdap    = profile["sources"].get("rdap", {})

    threat_score = 0
    threat_reasons = []

    if geo.get("is_proxy"):
        threat_score += 30; threat_reasons.append("VPN/Proxy detected")
    if geo.get("is_hosting"):
        threat_score += 20; threat_reasons.append("Hosting/datacenter IP")
    if geo.get("country_code","") in CONFIG.get("geoip",{}).get("high_risk_countries",["CN","RU","KP","IR"]):
        threat_score += 25; threat_reasons.append(f"High-risk country ({geo.get('country','')})")
    if shodan.get("vulns"):
        threat_score += 20; threat_reasons.append(f"{len(shodan['vulns'])} known CVEs on this host")
    if history.get("total_alerts",0) > 5:
        threat_score += 15; threat_reasons.append(f"{history['total_alerts']} alerts in session")
    if history.get("attack_types",{}):
        types = list(history["attack_types"].keys())
        if len(types) > 2:
            threat_score += 10; threat_reasons.append("Multiple attack types used")
    if ip_chains:
        threat_score += 20; threat_reasons.append("Part of multi-stage attack chain")
    if shodan.get("tags") and any(t in ["tor","vpn","scanner","malware"] for t in shodan["tags"]):
        threat_score += 35; threat_reasons.append(f"Shodan tags: {shodan['tags']}")
    if shodan.get("open_ports"):
        if any(p in [22,23,3389,445,1433] for p in shodan.get("open_ports",[])):
            threat_score += 10; threat_reasons.append("Attack-capable services on attacker host")

    threat_score = min(100, threat_score)
    if threat_score >= 70:   verdict = "CONFIRMED THREAT"
    elif threat_score >= 45: verdict = "LIKELY THREAT"
    elif threat_score >= 20: verdict = "SUSPICIOUS"
    else:                    verdict = "UNKNOWN / LOW CONFIDENCE"

    profile["verdict"] = {
        "score":   threat_score,
        "label":   verdict,
        "reasons": threat_reasons,
    }

    # ── Flat summary for quick display ───────────────────────────────────────
    profile["summary"] = {
        "ip":          ip,
        "flag":        geoip.lookup(ip).get("flag","🌐") if ip else "🌐",
        "country":     geo.get("country","Unknown"),
        "city":        geo.get("city",""),
        "isp":         geo.get("isp","") or geo.get("org",""),
        "org":         rdap.get("whois_org","") or geo.get("org",""),
        "asn":         geo.get("as_number",""),
        "ptr":         profile["sources"].get("rdns",{}).get("ptr_record",""),
        "is_proxy":    geo.get("is_proxy", False),
        "is_hosting":  geo.get("is_hosting", False),
        "open_ports":  shodan.get("open_ports",[]),
        "vulns":       shodan.get("vulns",[]),
        "tags":        shodan.get("tags",[]),
        "net_range":   f"{rdap.get('start_addr','')} – {rdap.get('end_addr','')}",
        "abuse_email": rdap.get("abuse_email",""),
        "total_alerts":history.get("total_alerts",0),
        "verdict":     verdict,
        "verdict_score": threat_score,
    }

    return profile


@app.get("/api/tracker/{ip}")
async def track_ip(ip: str):
    """
    Full attacker source profile for a given IP.
    Queries ip-api.com, Shodan InternetDB, RDAP/WHOIS, reverse DNS,
    local alert history, and attack chains in parallel.
    Returns within ~10 seconds.
    """
    import re as _re
    # Validate IP format
    if not _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return _build_ip_profile(ip)


@app.get("/api/tracker/{ip}/quick")
async def track_ip_quick(ip: str):
    """Returns only local data (no external API calls) — instant response."""
    ip_alerts = [a for a in _recent_alerts if a.get("src_ip") == ip]
    ip_chains  = [c for c in _recent_chains if c.get("src_ip") == ip]
    geo        = geoip.lookup(ip) if ip else {}
    return {
        "ip":          ip,
        "geo":         geo,
        "alert_count": len(ip_alerts),
        "chain_count": len(ip_chains),
        "is_blocked":  ip in (responder.registry.get_all() if hasattr(responder,"registry") else {}),
        "attack_types": list({a.get("type","") for a in ip_alerts}),
        "mitre_ids":    list({a.get("mitre_id","") for a in ip_alerts if a.get("mitre_id")}),
    }

@app.get("/api/map")
def get_map(limit: int=200):
    """Geo map with private IP coordinate estimation and public IP lookup."""
    points = geoip.get_map_data(_recent_alerts, limit=limit)
    country_stats = geoip.country_stats(_recent_alerts)

    # Also include alerts from tracker for private IPs (with estimated coords)
    # Private IPs get assigned to the server's country via the public IP fallback
    if len(points) < 5:
        seen_ips = {p["ip"] for p in points}
        # Try online lookup for any IPs not yet resolved
        for a in _recent_alerts[:200]:
            ip = a.get("src_ip","")
            if not ip or ip in seen_ips: continue
            try:
                import urllib.request, json as _j
                req = urllib.request.Request(
                    f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org",
                    headers={"User-Agent":"CyberRemedy/2.0"})
                with urllib.request.urlopen(req, timeout=3) as r:
                    d = _j.loads(r.read().decode())
                if d.get("status")=="success" and d.get("lat") and d.get("lon"):
                    points.append({"ip":ip,"lat":d["lat"],"lon":d["lon"],
                        "country":d.get("country","?"),"country_code":d.get("countryCode","??"),
                        "city":d.get("city",""),"org":d.get("org",""),
                        "alert_count":1,"severity":a.get("severity","LOW"),"flag":"🌐"})
                    seen_ips.add(ip)
                    if len(points) >= limit: break
            except Exception:
                pass

    return {"points": points, "country_stats": country_stats, "total": len(points)}

# ── PCAP ──────────────────────────────────────────────────────────────────────
@app.get("/api/pcap/list")
def pcap_list():
    d = Path("data/pcap")
    if not d.exists(): return {"files":[]}
    return {"files": [{"name":f.name,
                        "size_mb":round(f.stat().st_size/1_048_576,2),
                        "modified":datetime.fromtimestamp(f.stat().st_mtime).isoformat()}
                       for f in sorted(d.glob("*.pcap*"),reverse=True)]}

@app.get("/api/pcap/stats")
def pcap_stats():
    d = Path("data/pcap")
    if not d.exists(): return {"total_files":0,"total_size_mb":0}
    files = list(d.glob("*.pcap*"))
    total = sum(f.stat().st_size for f in files)
    return {"total_files":len(files), "total_size_mb":round(total/1_048_576,2)}

@app.delete("/api/pcap/{filename}")
def pcap_delete(filename: str):
    d = Path("data/pcap"); t = d/filename
    if not t.exists(): raise HTTPException(404,"Not found")
    t.unlink(); return {"deleted": filename}

# ═════════════════════════════════════════════════════════════════════════════
# v4.1 ENDPOINTS — Syslog, Reports, Email, Swagger docs
# ═════════════════════════════════════════════════════════════════════════════

# ── Syslog ingestion ──────────────────────────────────────────────────────────
try:
    from agent.syslog_server import SyslogServer, AgentReceiver
    _syslog_cfg = CONFIG.get("syslog", {})
    _syslog_srv  = SyslogServer(
        port=int(_syslog_cfg.get("udp_port", 5514)),
        winlog_port=int(_syslog_cfg.get("winlog_port", 5515)),
        callback=lambda ev: (log_manager.log_event("syslog", ev.get("message",""), **{k:v for k,v in ev.items() if k!="message"}), _process_alert_enriched(ev) if ev.get("severity") in ("CRITICAL","HIGH") else None)
    )
    _agent_recv = AgentReceiver(
        port=int(_syslog_cfg.get("agent_port", 5516)),
        callback=lambda ev: log_manager.log_event("agent", str(ev), **ev)
    )
    _syslog_srv.start()
    _agent_recv.start()
    logger.info("Syslog server started (UDP/TCP :5514, WinLog :5515, Agent :5516)")
except Exception as _e:
    logger.warning(f"Syslog server init: {_e}")
    _syslog_srv = None

@app.get("/api/syslog/stats")
def syslog_stats():
    import socket as _sock, subprocess as _sp
    # Get all real non-loopback IPs
    all_ips = []
    try:
        # Try to get IPs from all interfaces
        result = _sp.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            all_ips = [ip.strip() for ip in result.stdout.split() if ip.strip() and not ip.startswith("127.") and not ip.startswith("::")]
    except Exception:
        pass
    if not all_ips:
        try:
            # Fallback: connect to external to get primary IP
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            all_ips = [s.getsockname()[0]]
            s.close()
        except Exception:
            all_ips = ["127.0.0.1"]
    server_ip = all_ips[0] if all_ips else "127.0.0.1"
    base = {"running": _syslog_srv is not None, "server_ip": server_ip, "all_ips": all_ips,
            "udp_port": 5514, "winlog_port": 5515, "agent_port": 5516}
    if _syslog_srv:
        try:
            s = _syslog_srv.get_stats() if hasattr(_syslog_srv, "get_stats") else {}
            base.update(s)
        except Exception:
            base["total"] = getattr(_syslog_srv, "count", 0)
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET ANALYZER  — Wireshark-style deep packet analysis with ML
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/packets/flows")
def get_analyzed_flows(
    limit: int = 200,
    severity: str = "",
    protocol: str = "",
    direction: str = "",
    threat_only: bool = False
):
    """Get analyzed network flows with ML classification."""
    return {
        "flows": _packet_analyzer.get_flows(
            limit=limit,
            severity_filter=severity or None,
            protocol_filter=protocol or None,
            direction_filter=direction or None,
            threat_only=threat_only,
        )
    }

@app.get("/api/packets/active")
def get_active_flows(limit: int = 100):
    """Get currently active (incomplete) flows — real-time view."""
    return {"flows": _packet_analyzer.get_active_flows(limit=limit)}

@app.get("/api/packets/stats")
def get_packet_stats():
    """Get packet analyzer statistics + ML training status."""
    return _packet_analyzer.stats

@app.get("/api/packets/summary")
def get_packet_summary():
    """Get high-level summary for dashboard cards."""
    s = _packet_analyzer.stats
    completed = _packet_analyzer.get_flows(limit=500)
    top_talkers = {}
    top_services = {}
    for f in completed:
        ip = f.get('src_ip','')
        if ip: top_talkers[ip] = top_talkers.get(ip, 0) + f.get('byte_count', 0)
        svc = f.get('service','OTHER')
        top_services[svc] = top_services.get(svc, 0) + 1
    top_talkers_list = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
    top_services_list = sorted(top_services.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total_packets":  s.get('total_packets', 0),
        "total_bytes":    s.get('total_bytes', 0),
        "total_flows":    s.get('total_flows', 0),
        "active_flows":   s.get('active_flows', 0),
        "threats":        s.get('threats', 0),
        "anomalies":      s.get('anomalies', 0),
        "ml_trained":     s.get('ml_trained', False),
        "training_progress": min(100, int(s.get('training_samples', 0) / 2)),
        "by_protocol":    s.get('by_protocol', {}),
        "by_direction":   s.get('by_direction', {}),
        "by_l7":          s.get('by_l7', {}),
        "top_talkers":    [{"ip": ip, "bytes": b} for ip, b in top_talkers_list],
        "top_services":   [{"service": sv, "count": ct} for sv, ct in top_services_list],
    }

@app.get("/api/web-traffic")
def get_web_traffic(limit: int = 500, direction: str = ""):
    """Return HTTP/HTTPS flows for web traffic monitor.
    Includes both active and completed flows, and matches on l7, service,
    or destination port (80/443/8080/8443) so data appears even before
    flows complete.
    """
    WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
    WEB_L7    = {"HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt"}

    flows = _packet_analyzer.get_flows(limit=limit, protocol_filter=None, include_active=True)
    web = [
        f for f in flows
        if (f.get("l7") in WEB_L7)
        or (f.get("service") in WEB_L7)
        or (f.get("dst_port") in WEB_PORTS)
        or (f.get("src_port") in WEB_PORTS)
    ]
    if direction:
        web = [f for f in web if f.get("direction") == direction]
    # Summarise top talkers
    dst_bytes, src_bytes = {}, {}
    for f in web:
        if f.get("direction") == "outgoing":
            dst_bytes[f["dst_ip"]] = dst_bytes.get(f["dst_ip"],0) + f.get("byte_count",0)
        else:
            src_bytes[f["src_ip"]] = src_bytes.get(f["src_ip"],0) + f.get("byte_count",0)
    top_dst = sorted(dst_bytes.items(), key=lambda x:x[1], reverse=True)[:10]
    top_src = sorted(src_bytes.items(), key=lambda x:x[1], reverse=True)[:10]
    # Enrich flows with reverse DNS (non-blocking, cached)
    LOCAL_PREFIXES = ("192.168.","10.","172.16.","172.17.","172.18.","172.19.",
                      "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
                      "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","127.")
    enriched = []
    for f in web:
        fd = dict(f)
        remote_ip = fd.get("dst_ip","") if fd.get("direction","")=="outgoing" else fd.get("src_ip","")
        if remote_ip and not any(remote_ip.startswith(p) for p in LOCAL_PREFIXES):
            hn = _rdns(remote_ip)
            if hn:
                fd["dns_name"] = hn
        enriched.append(fd)
    return {
        "flows": [sanitize(f) for f in enriched],
        "count": len(enriched),
        "top_destinations": [{"ip":ip,"bytes":b} for ip,b in top_dst],
        "top_sources":      [{"ip":ip,"bytes":b} for ip,b in top_src],
    }

# ── Reports list ──────────────────────────────────────────────────────────────
@app.get("/api/report/list")
def report_list():
    rdir = Path("data/reports")
    if not rdir.exists(): return {"reports": []}
    files = sorted(rdir.glob("*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
    return {"reports": [{"name": f.name, "size_kb": round(f.stat().st_size/1024,1),
                          "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()} for f in files]}

@app.post("/api/report/test-email")
def test_email():
    try:
        from reporting.scheduler import EmailNotifier
        en = EmailNotifier(CONFIG)
        sent = en.send("[CyberRemedy] Test Email", "<h2>Test email from CyberRemedy SOC PLATFORM v1.2</h2><p>Email is configured correctly.</p>")
        return {"sent": sent}
    except Exception as e:
        return {"sent": False, "error": str(e)}

# ── API Docs redirect ─────────────────────────────────────────────────────────
@app.get("/api/settings")
def get_settings():
    import yaml
    cfg_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    try:
        with open(cfg_path) as f: cfg = yaml.safe_load(f) or {}
    except Exception: cfg = {}
    return {
        "capture_interface": cfg.get("capture", {}).get("interface", "auto"),
        "detection_threshold": cfg.get("detection", {}).get("threshold", 70),
        "auto_block": cfg.get("response", {}).get("auto_block", False),
        "auto_block_threshold": cfg.get("response", {}).get("auto_block_threshold", 85),
        "syslog_port": cfg.get("syslog", {}).get("port", 5514),
        "alert_email": cfg.get("notifications", {}).get("email", ""),
        "interfaces": _get_interfaces(),
        "pipeline": pipeline_state,
    }

def _get_interfaces():
    import subprocess, re as _re
    ifaces = ["auto"]
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], text=True, timeout=3)
        for m in _re.finditer(r"\d+: ([\w@.-]+):", out):
            i = m.group(1).split("@")[0]
            if i not in ("lo", "docker0") and not i.startswith(("veth","br-")):
                ifaces.append(i)
    except Exception: pass
    return ifaces

@app.post("/api/settings")
async def save_settings(req: Request):
    import yaml
    body = await req.json()
    cfg_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    try:
        with open(cfg_path) as f: cfg = yaml.safe_load(f) or {}
    except Exception: cfg = {}
    # Apply live (no restart needed for these)
    if "detection_threshold" in body:
        try: sig_detector.threshold = int(body["detection_threshold"])
        except Exception: pass
    if "auto_block" in body:
        try: responder.auto_block = bool(body["auto_block"])
        except Exception: pass
    # Save to disk
    cfg.setdefault("detection", {})["threshold"] = body.get("detection_threshold", 70)
    cfg.setdefault("response", {})["auto_block"] = body.get("auto_block", False)
    cfg.setdefault("response", {})["auto_block_threshold"] = body.get("auto_block_threshold", 85)
    cfg.setdefault("capture", {})["interface"] = body.get("capture_interface", "auto")
    cfg.setdefault("notifications", {})["email"] = body.get("alert_email", "")
    try:
        with open(cfg_path, "w") as f: yaml.dump(cfg, f)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "message": "Settings saved. Interface changes require restart."}



# ═══ MISSING ROUTES ADDED ════════════════════════════════════════════════════

# /api/response/block  /api/response/unblock  /api/response/log
@app.post("/api/response/block")
def resp_block(req: BlockRequest):
    """Block IP — alias used by dashboard blockIP() function."""
    return {"success": True, "entry": responder.manual_block(req.ip, req.reason or "Dashboard")}

@app.post("/api/response/unblock")
def resp_unblock(req: BlockRequest):
    """Unblock IP — alias used by dashboard."""
    return {"success": True, "entry": responder.manual_unblock(req.ip)}

@app.get("/api/response/log")
def resp_log(limit: int = 100):
    """Response action log — alias for /api/response-log."""
    return {"responses": _recent_responses[-limit:], "count": len(_recent_responses)}

# /api/intel/iocs?limit=  (already exists but add query param support)
# Already handled by /api/intel/iocs — no change needed

# /api/packets/flows?limit&protocol  (already exists, params already supported)
# Already handled — no change needed

# /api/restart
@app.post("/api/restart")
def api_restart():
    """Soft restart signal — logs restart request (actual restart requires OS-level action)."""
    import threading
    def _do(): import time; time.sleep(1); import os; os.execv(__import__('sys').executable, [__import__('sys').executable] + __import__('sys').argv)
    threading.Thread(target=_do, daemon=True).start()
    return {"ok": True, "message": "Restart initiated"}

# /api/config/profile  (already exists as /api/config/profile/{profile} — add non-path variant)
@app.post("/api/config/profile")
def set_profile_body(body: dict):
    """Apply profile from request body {profile: 'laptop'|'office'|'server'|'aggressive'}"""
    profile = body.get("profile","office")
    profiles = {
        "laptop":     {"detection_threshold":60,"auto_block":False,"auto_block_threshold":90},
        "office":     {"detection_threshold":70,"auto_block":False,"auto_block_threshold":85},
        "server":     {"detection_threshold":80,"auto_block":True, "auto_block_threshold":80},
        "aggressive": {"detection_threshold":50,"auto_block":True, "auto_block_threshold":70},
    }
    cfg = profiles.get(profile, profiles["office"])
    try: sig_detector.threshold = cfg["detection_threshold"]
    except: pass
    try: responder.auto_block = cfg["auto_block"]
    except: pass
    return {"ok": True, "profile": profile, "applied": cfg}

# /api/services   (service status + manual start from doc)
_service_status = {
    "sniffer":       {"running": False, "error": None, "label": "Packet Sniffer"},
    "syslog":        {"running": False, "error": None, "label": "Syslog Server"},
    "agent_server":  {"running": False, "error": None, "label": "Agent Receiver"},
    "honeypot":      {"running": False, "error": None, "label": "Honeypot Services"},
    "packet_analyzer":{"running": False, "error": None, "label": "Packet Analyzer ML"},
}

@app.get("/api/services")
def get_services():
    """Service health status for dashboard."""
    try: _service_status["sniffer"]["running"]    = pipeline_state.get("running", False)
    except: pass
    try: _service_status["honeypot"]["running"]   = any(s.get("running") for s in (honeypot_mgr.get_status() or {}).values()) if hasattr(honeypot_mgr,"get_status") else False
    except: _service_status["honeypot"]["running"] = True
    try: _service_status["syslog"]["running"]     = _syslog_srv is not None
    except: pass
    try: _service_status["packet_analyzer"]["running"] = _packet_analyzer is not None
    except: pass
    try: _service_status["agent_server"]["running"] = _syslog_srv is not None
    except: pass
    return _service_status

@app.post("/api/services/start/{service_name}")
def start_service(service_name: str):
    """Manually start a service from dashboard."""
    if service_name not in _service_status:
        raise HTTPException(status_code=404, detail=f"Unknown service: {service_name}")
    try:
        if service_name == "sniffer":
            # Re-trigger capture
            global sniffer
            iface = pipeline_state.get("interface","auto")
            sniffer = LiveSniffer(interface=iface, callback=_on_packet)
            import threading as _st
            _st.Thread(target=sniffer.start, daemon=True, name="cap-restart").start()
            pipeline_state["running"] = True
            _service_status["sniffer"]["running"] = True
            _service_status["sniffer"]["error"] = None
        elif service_name == "honeypot":
            honeypot_mgr.start_all()
            _service_status["honeypot"]["running"] = True
            _service_status["honeypot"]["error"] = None
        else:
            _service_status[service_name]["running"] = True
            _service_status[service_name]["error"] = None
        return {"ok": True, "service": service_name, "status": _service_status[service_name]}
    except Exception as e:
        _service_status[service_name]["error"] = str(e)
        return {"ok": False, "service": service_name, "error": str(e)}

# /api/monitoring/status   (Grafana metrics summary)
@app.get("/api/monitoring/status")
def monitoring_status():
    """Live metrics for Grafana monitoring page."""
    import time
    uptime_s = 0
    if pipeline_state.get("start_time"):
        try:
            import time as _time
            st = pipeline_state["start_time"]
            if st:
                uptime_s = int(_time.time() - st) if isinstance(st, (int, float)) else 0
        except: pass
    h, r = uptime_s // 3600, uptime_s % 3600
    m, s = r // 60, r % 60
    uptime_fmt = f"{h}h {m}m {s}s" if h else f"{m}m {s}s"
    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for a in _recent_alerts: sev_counts[a.get("severity","LOW")] = sev_counts.get(a.get("severity","LOW"),0)+1
    pa = _packet_analyzer.stats if _packet_analyzer else {}
    return {
        "packets_total":    pipeline_state.get("packets_processed",0),
        "flows_total":      pipeline_state.get("flows_analyzed",0),
        "alerts_total":     len(_recent_alerts),
        "blocked_total":    len(blockedIPs_snapshot()),
        "uptime_seconds":   uptime_s,
        "uptime_formatted": uptime_fmt,
        "pipeline_running": pipeline_state.get("running",False),
        "interface":        pipeline_state.get("interface","—"),
        "alerts_by_severity": sev_counts,
        "ml_trained":       pa.get("training_complete",False),
        "ml_flows_seen":    pa.get("total_flows",0),
        "pps":              _traffic_history[-1].get("total",0) if _traffic_history else 0,
        "traffic_history":  _traffic_history[-60:],
        "services":         _service_status,
    }

def blockedIPs_snapshot():
    try: return responder.registry.get_all()
    except: return []

# /metrics  (Prometheus text format)
@app.get("/metrics")
def prometheus_metrics():
    """Prometheus-compatible text metrics for Grafana scraping."""
    pa = _packet_analyzer.stats if _packet_analyzer else {}
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for a in _recent_alerts: sev[a.get("severity","LOW")] = sev.get(a.get("severity","LOW"),0)+1
    lines = [
        "# HELP cyberremedy_packets_total Total packets processed",
        "# TYPE cyberremedy_packets_total counter",
        f"cyberremedy_packets_total {pipeline_state.get('packets_processed',0)}",
        "# HELP cyberremedy_alerts_total Total alerts generated",
        "# TYPE cyberremedy_alerts_total counter",
        f"cyberremedy_alerts_total {len(_recent_alerts)}",
        "# HELP cyberremedy_flows_total Total flows analyzed",
        "# TYPE cyberremedy_flows_total counter",
        f"cyberremedy_flows_total {pipeline_state.get('flows_analyzed',0)}",
        "# HELP cyberremedy_blocked_ips_total Total blocked IPs",
        "# TYPE cyberremedy_blocked_ips_total gauge",
        f"cyberremedy_blocked_ips_total {len(blockedIPs_snapshot())}",
        "# HELP cyberremedy_pipeline_running Is pipeline running",
        "# TYPE cyberremedy_pipeline_running gauge",
        f"cyberremedy_pipeline_running {1 if pipeline_state.get('running') else 0}",
        "# HELP cyberremedy_alerts_critical Critical severity alerts",
        "# TYPE cyberremedy_alerts_critical gauge",
        f"cyberremedy_alerts_critical {sev['CRITICAL']}",
        "# HELP cyberremedy_alerts_high High severity alerts",
        "# TYPE cyberremedy_alerts_high gauge",
        f"cyberremedy_alerts_high {sev['HIGH']}",
        "# HELP cyberremedy_ml_flows ML model training flows seen",
        "# TYPE cyberremedy_ml_flows gauge",
        f"cyberremedy_ml_flows {pa.get('total_flows',0)}",
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

# /api/logs/search  (log search endpoint)
@app.get("/api/logs/search")
def search_logs(q: str = "", type: str = "all", limit: int = 100):
    """Full-text search across recent logs and alerts."""
    results = []
    q_lower = q.lower()
    # Search alerts
    if type in ("all","alerts"):
        for a in _recent_alerts:
            if not q_lower or q_lower in json.dumps(a).lower():
                results.append({**a, "_source": "alert"})
    # Search responses
    if type in ("all","responses"):
        for r in _recent_responses:
            if not q_lower or q_lower in json.dumps(r).lower():
                results.append({**r, "_source": "response"})
    return {"results": results[:limit], "count": len(results), "query": q}

@app.get("/docs/api")
def api_docs_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/docs")


# ══════════════════════════════════════════════════════════════════════════════
# SIEM WiFi Monitor Routes  (/api/siem/*)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/siem/status")
def siem_status():
    """Current state of the WiFi monitor-mode subsystem."""
    if not siem_manager:
        return {"available": False, "reason": "siem/ module not installed"}
    return {"available": True, **siem_manager.status()}

@app.post("/api/siem/start")
def siem_start():
    """Enable monitor mode and start passive WiFi capture."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    # FIX: refresh DHCP gateway from live routing table every time we start.
    # On a DHCP network the gateway IP changes; we never hardcode it.
    _live_gw = siem_manager._detect_gateway()
    if _live_gw:
        siem_manager._cfg["gateway_ip"] = _live_gw
        logger.info(f"[SIEM] DHCP gateway refreshed on /api/siem/start: {_live_gw}")
    # Also ensure enabled flag is set so start_if_enabled() doesn't skip it
    siem_manager._cfg["enabled"] = True
    siem_manager.start()
    return {"status": "starting", "message": "Monitor mode starting in background",
            "gateway_ip": _live_gw or "auto-detect"}

@app.post("/api/siem/stop")
def siem_stop():
    """Stop monitor mode capture and restore normal WiFi."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    siem_manager.stop()
    return {"status": "stopped"}

@app.post("/api/siem/report")
def siem_report():
    """Generate a WiFi session report (JSON + HTML saved to data/reports/)."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    result = siem_manager.generate_report()
    if "error" in result:
        raise HTTPException(500, result["error"])
    return result

@app.get("/api/siem/devices")
def siem_devices():
    """List all devices detected on the wireless network this session."""
    if not siem_manager:
        return {"devices": []}
    return {"devices": siem_manager.devices()}

@app.post("/api/siem/channel")
def siem_set_channel(body: dict):
    """Manually lock the monitor adapter to a specific WiFi channel."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    ch = int(body.get("channel", 0))
    if ch < 1 or ch > 177:
        raise HTTPException(400, "channel must be 1–177")
    result = siem_manager.set_channel(ch)
    if not result.get("ok"):
        raise HTTPException(500, f"Channel lock failed")
    return result

@app.post("/api/siem/devices/{ip}/mark_known")
def siem_mark_known(ip: str):
    """Mark a device as trusted so it no longer triggers new-device alerts."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    ok = siem_manager.mark_known(ip)
    if not ok:
        raise HTTPException(404, f"Device {ip} not found in registry")
    return {"marked_known": ip}

# ── Per-device traffic ─────────────────────────────────────────────────────────

@app.get("/api/siem/devices/{ip}/traffic")
def siem_device_traffic(ip: str, type: str = "normal", limit: int = 100):
    """
    Get traffic for a specific device.
    ?type=normal  → regular traffic packets
    ?type=vpn     → VPN tunnel traffic packets
    ?type=summary → stats overview (no packet list)
    """
    if not siem_manager:
        if type == "summary":
            return {"ip": ip, "normal_count": 0, "vpn_count": 0,
                    "total_bytes": 0, "vpn_bytes": 0,
                    "first_seen": "", "last_seen": "",
                    "top_dsts": [], "protocols": {}}
        return {"ip": ip, "type": type, "packets": []}
    if type == "vpn":
        return sanitize({"ip": ip, "type": "vpn",
                "packets": siem_manager.device_traffic_vpn(ip, limit)})
    if type == "summary":
        return sanitize(siem_manager.device_traffic_summary(ip))
    return sanitize({"ip": ip, "type": "normal",
            "packets": siem_manager.device_traffic_normal(ip, limit)})

@app.get("/api/siem/devices/{ip}/vpn")
def siem_vpn_identify(ip: str):
    """Identify VPN provider/protocol for a device."""
    if not siem_manager:
        return {"ip": ip, "is_vpn": False, "protocol": "Unknown",
                "provider": "Unknown", "confidence": 0,
                "signals": [], "packet_count": 0,
                "traffic_stats": {"total_bytes": 0, "udp_bytes": 0,
                                  "dst_count": 0, "top_dst": ""}}
    return siem_manager.vpn_analyse(ip)

# ── MITM ───────────────────────────────────────────────────────────────────────

@app.post("/api/siem/mitm/start")
def siem_mitm_start(body: dict):
    """
    Start ARP poisoning MITM against a target device.
    Body: {"target_ip": "192.168.1.x"}
    WARNING: Only use on networks you own.
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    target_ip = body.get("target_ip", "")
    if not target_ip:
        raise HTTPException(400, "target_ip required")
    result = siem_manager.mitm_start(target_ip)
    if not result.get("ok"):
        raise HTTPException(500, result.get("error", "MITM start failed"))
    return result

@app.post("/api/siem/mitm/stop")
def siem_mitm_stop(body: dict):
    """Stop MITM session for a target device."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not installed")
    target_ip = body.get("target_ip", "")
    if not target_ip:
        raise HTTPException(400, "target_ip required")
    result = siem_manager.mitm_stop(target_ip)
    if not result.get("ok"):
        raise HTTPException(404, result.get("error", "Session not found"))
    return result

@app.get("/api/siem/mitm/status")
def siem_mitm_all():
    """List all active MITM sessions."""
    if not siem_manager:
        return {"sessions": []}
    return {"sessions": siem_manager.mitm_all_sessions()}

@app.get("/api/siem/mitm/{ip}/status")
def siem_mitm_status(ip: str):
    """Get MITM session status for a specific device."""
    if not siem_manager:
        return {"running": False}
    return siem_manager.mitm_status(ip)

@app.get("/api/siem/mitm/{ip}/packets")
def siem_mitm_packets(ip: str, limit: int = 100):
    """Get intercepted packets from an active MITM session, with DNS hostnames."""
    if not siem_manager:
        return {"ip": ip, "packets": []}
    raw_pkts = siem_manager.mitm_packets(ip, limit)
    # Enrich each packet with reverse-DNS hostnames for src and dst
    for pkt in raw_pkts:
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        if src and "src_host" not in pkt:
            h = _rdns(src)
            if h: pkt["src_host"] = h
        if dst and "dst_host" not in pkt:
            h = _rdns(dst)
            if h: pkt["dst_host"] = h
    return sanitize({"ip": ip, "packets": raw_pkts, "count": len(raw_pkts)})

@app.get("/api/dns/resolve")
def dns_resolve_batch(ips: str = ""):
    """Resolve a comma-separated list of IPs to hostnames. Used by frontend for bulk DNS."""
    result = {}
    for ip in (ips or "").split(","):
        ip = ip.strip()
        if ip:
            result[ip] = _rdns_sync(ip, timeout=0.5) or ip
    return result

# ══════════════════════════════════════════════════════════════════════════════
# ACTIVE CAPTURE ROUTES  (/api/siem/active/*)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/siem/active/status")
def active_capture_status():
    """Status of the active capture engine (method, targets, packet count)."""
    if not siem_manager:
        return {"running": False, "error": "SIEM not running"}
    return siem_manager.active_capture_status()

@app.post("/api/siem/active/target/add")
def active_add_target(body: dict):
    """
    Add a device to active MITM capture at runtime.
    Body: {"ip": "192.168.1.x"}
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not running")
    ip = body.get("ip", "").strip()
    if not ip:
        raise HTTPException(400, "ip required")
    result = siem_manager.add_active_target(ip)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "Failed"))
    return result

@app.delete("/api/siem/active/target/{ip}")
def active_remove_target(ip: str):
    """
    Remove a device from active MITM capture and restore its ARP cache.
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not running")
    result = siem_manager.remove_active_target(ip)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "Failed"))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# AGENTLESS MONITOR TOOLS  (/api/monitor/*)
# Two fallback capture strategies when monitor-mode passive sniffing fails.
# Neither requires an agent on the target device (Laptop B / Windows 10).
# ══════════════════════════════════════════════════════════════════════════════

# ── in-memory state for the monitor-mode sniffer instance ─────────────────────
_monitor_sniffer   = None          # LiveSniffer running with monitor_mode=True
_monitor_packets: List[dict] = []  # rolling capture buffer (last 500)
_dns_leak_log:    List[dict] = []  # DNS packets going to unexpected resolvers

def _on_monitor_packet(pkt: dict):
    """Callback for the agentless monitor sniffer — feeds main pipeline + local buffers."""
    global _monitor_packets, _dns_leak_log

    # Feed into main detection pipeline (FlowAggregator → SignatureDetector …)
    _on_packet(pkt)

    # Keep a rolling buffer for the /api/monitor/packets endpoint
    _monitor_packets.append(pkt)
    if len(_monitor_packets) > 500:
        _monitor_packets.pop(0)

    # DNS leak detection — flag any DNS leaving to a non-LAN resolver
    if pkt.get("protocol") == "DNS" and pkt.get("dst_port") == 53:
        dst = pkt.get("dst_ip", "")
        expected = set(CONFIG.get("detection", {}).get("signature", {}).get("expected_dns_servers", []))
        def _is_private(ip):
            return any(ip.startswith(p) for p in ("192.168.","10.","172.","127."))
        PUBLIC_DNS = {"8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9",
                      "149.112.112.112","208.67.222.222","208.67.220.220"}
        if dst and not _is_private(dst):
            severity = "MEDIUM" if dst in PUBLIC_DNS else "LOW"
            entry = {**pkt, "leak_type": "known_public" if dst in PUBLIC_DNS else "unknown_external",
                     "severity": severity}
            _dns_leak_log.append(entry)
            if len(_dns_leak_log) > 200:
                _dns_leak_log.pop(0)


@app.get("/api/monitor/status")
def monitor_status():
    """
    Status of the agentless monitor capture (monitor_mode=True sniffer).
    Reports which capture method is active and packet counts.
    """
    global _monitor_sniffer
    if not _monitor_sniffer:
        return {
            "running": False,
            "mode": "idle",
            "packet_count": 0,
            "buffered_packets": len(_monitor_packets),
            "dns_leaks_detected": len(_dns_leak_log),
        }
    return {
        "running": _monitor_sniffer.is_running,
        "mode":    _monitor_sniffer.mode,
        "packet_count":       _monitor_sniffer.packet_count,
        "buffered_packets":   len(_monitor_packets),
        "dns_leaks_detected": len(_dns_leak_log),
    }


@app.post("/api/monitor/start")
def monitor_start(body: dict = {}):
    """
    Start agentless monitor-mode capture on Laptop A.
    Captures ALL traffic on the interface (not just Laptop A's own packets).
    Requires root + either scapy, AF_PACKET socket, or tcpdump.

    Body (all optional):
      { "interface": "wlan0", "target_ip": "192.168.1.105" }

    When target_ip is provided only that device's traffic is buffered in
    /api/monitor/packets — but all traffic still feeds the detection pipeline.
    """
    global _monitor_sniffer
    if _monitor_sniffer and _monitor_sniffer.is_running:
        return {"ok": False, "error": "Monitor already running — stop it first"}

    from capture.sniffer import LiveSniffer, ROOT_OK
    if not ROOT_OK:
        raise HTTPException(403, "Monitor mode requires root — restart with sudo python3 main.py")

    iface      = body.get("interface", CONFIG.get("system", {}).get("interface", "auto"))
    target_ip  = body.get("target_ip", "")

    def _cb(pkt: dict):
        # Optional per-device filter
        if target_ip:
            if pkt.get("src_ip") != target_ip and pkt.get("dst_ip") != target_ip:
                return
        _on_monitor_packet(pkt)

    try:
        _monitor_sniffer = LiveSniffer(
            interface    = iface,
            callback     = _cb,
            monitor_mode = True,        # ← captures Laptop B traffic (our sniffer.py fix)
        )
        _monitor_sniffer.start()
        logger.info(f"[Monitor] Agentless capture started on {iface}, target={target_ip or 'all'}")
        return {
            "ok": True,
            "interface":  iface,
            "target_ip":  target_ip or "all",
            "mode":       _monitor_sniffer.mode,
            "message":    "Monitor-mode capture active — no agent required on target device",
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/monitor/stop")
def monitor_stop():
    """Stop agentless monitor-mode capture."""
    global _monitor_sniffer
    if not _monitor_sniffer or not _monitor_sniffer.is_running:
        return {"ok": False, "error": "Monitor not running"}
    _monitor_sniffer.stop()
    return {"ok": True, "packets_captured": _monitor_sniffer.packet_count}


@app.get("/api/monitor/packets")
def monitor_packets(limit: int = 100):
    """
    Return the most recent packets from the monitor-mode buffer.
    Includes direction tag (monitored / incoming / outgoing / internal).
    """
    return {
        "packets": _monitor_packets[-limit:],
        "total_buffered": len(_monitor_packets),
    }


# ── Option 2: ARP MITM fallback  ──────────────────────────────────────────────
# (Endpoints already exist at /api/siem/mitm/* — these are convenience aliases
#  so the Monitor Tools panel can reach them without needing SIEM module)

@app.post("/api/monitor/mitm/start")
def monitor_mitm_start(body: dict):
    """
    Fallback Option 2: Start ARP-poisoning MITM against target device.
    Redirects all of Laptop B's traffic through Laptop A without any agent.
    Works even when Wi-Fi monitor mode fails (uses wired/switched Ethernet).

    Body: { "target_ip": "192.168.1.105", "gateway_ip": "192.168.1.1" }
    WARNING: Only use on networks you own and have permission to test.
    """
    if siem_manager:
        # Prefer the full SIEM MITM engine
        target_ip = body.get("target_ip", "")
        if not target_ip:
            raise HTTPException(400, "target_ip required")
        # Override gateway if explicitly provided
        gw = body.get("gateway_ip", "")
        if gw:
            if hasattr(siem_manager, "_mitm") and siem_manager._mitm: siem_manager._mitm.set_gateway(gw)
        result = siem_manager.mitm_start(target_ip)
        if not result.get("ok"):
            raise HTTPException(500, result.get("error", "MITM start failed"))
        return {**result, "method": "arp_mitm", "note": "All traffic from target now flows through this machine"}

    # Fallback: standalone MITMSession (no full SIEM required)
    from siem.mitm import MITMSession
    target_ip  = body.get("target_ip", "")
    gateway_ip = body.get("gateway_ip", "")
    iface      = body.get("interface", CONFIG.get("system", {}).get("interface", "eth0"))
    if not target_ip or not gateway_ip:
        raise HTTPException(400, "target_ip and gateway_ip are required")
    try:
        session = MITMSession(
            target_ip       = target_ip,
            gateway_ip      = gateway_ip,
            iface           = iface,
            packet_callback = _on_monitor_packet,
        )
        session.start()
        return {
            "ok": True, "method": "arp_mitm",
            "target_ip": target_ip, "gateway_ip": gateway_ip,
            "note": "ARP poisoning active — Laptop B traffic routed through Laptop A",
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/monitor/mitm/stop")
def monitor_mitm_stop(body: dict):
    """Stop ARP MITM fallback session. Restores Laptop B's ARP cache."""
    target_ip = body.get("target_ip", "")
    if not target_ip:
        raise HTTPException(400, "target_ip required")
    if siem_manager:
        result = siem_manager.mitm_stop(target_ip)
        if not result.get("ok"):
            raise HTTPException(404, result.get("error", "Session not found"))
        return result
    return {"ok": False, "error": "No active MITM session found"}


@app.get("/api/monitor/mitm/status")
def monitor_mitm_status():
    """List all active MITM sessions (used by Monitor Tools panel)."""
    if siem_manager:
        return {"sessions": siem_manager.mitm_all_sessions()}
    return {"sessions": []}


# ── DNS Leak detection results ─────────────────────────────────────────────────

@app.get("/api/monitor/dns/leaks")
def monitor_dns_leaks(limit: int = 100):
    """
    Return DNS queries captured going to unexpected / public resolvers.
    These indicate VPN misconfiguration or deliberate bypass (T1071).
    Each entry includes: src_ip, dst_ip (resolver), dns_query, severity, leak_type.
    """
    return {
        "leaks":  _dns_leak_log[-limit:],
        "total":  len(_dns_leak_log),
        "summary": {
            "known_public":      sum(1 for e in _dns_leak_log if e.get("leak_type") == "known_public"),
            "unknown_external":  sum(1 for e in _dns_leak_log if e.get("leak_type") == "unknown_external"),
            "unique_sources":    len({e.get("src_ip") for e in _dns_leak_log}),
            "unique_resolvers":  len({e.get("dst_ip") for e in _dns_leak_log}),
        }
    }


@app.delete("/api/monitor/dns/leaks")
def monitor_dns_leaks_clear():
    """Clear the DNS leak log."""
    global _dns_leak_log
    count = len(_dns_leak_log)
    _dns_leak_log = []
    return {"cleared": count}


@app.get("/api/siem/active/ipv6/scan")
async def active_ipv6_scan():
    """
    Run an active IPv6 NDP scan (ICMPv6 ff02::1 multicast + kernel neigh table).
    Returns all IPv6 devices found on the network, including those not visible
    via IPv4 ARP (e.g. IPv6-only hosts, or devices on the 2a02:.../64 prefix).
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not running")
    import asyncio
    loop = asyncio.get_event_loop()
    neighbours = await loop.run_in_executor(None, siem_manager.scan_ipv6_neighbours)
    return {"neighbours": neighbours, "count": len(neighbours)}


# ══════════════════════════════════════════════════════════════════════════════
# TLS / HTTPS INTERCEPTION  (/api/siem/tls/*)
# Agentless HTTPS decryption — WPAD auto-proxy + iptables REDIRECT + mitmproxy
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/siem/tls/start")
def siem_tls_start(body: dict):
    """
    Start agentless TLS/HTTPS interception.
    Body: { "target_ips": ["192.168.1.x", ...], "mode": "transparent"|"wpad" }

    Two delivery modes (both agentless):
      transparent — iptables REDIRECT TCP/443→proxy (needs root + MITM active)
      wpad        — DHCP WPAD auto-proxy; target browser auto-configures itself

    On first HTTPS connect the browser shows one cert warning (click Proceed).
    After that, all HTTPS flows are fully decrypted with URL, headers, and body.
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    target_ips = body.get("target_ips", [])
    config     = body.get("config", {})
    if body.get("mode"):
        config["mode"] = body["mode"]
    result = siem_manager.start_tls_intercept(target_ips=target_ips, config=config)
    return result

@app.post("/api/siem/tls/stop")
def siem_tls_stop():
    """Stop TLS interception and remove iptables rules."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.stop_tls_intercept()

@app.get("/api/siem/tls/status")
def siem_tls_status():
    """TLS intercept engine status — running, proxy port, WPAD URL, flow count."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.tls_status()

@app.get("/api/siem/tls/flows")
def siem_tls_flows(limit: int = 100, client_ip: str = ""):
    """
    Get decrypted HTTPS flows. Each flow includes:
      url, method, status_code, req_headers, req_body, resp_body,
      tls (version/cipher/sni), sensitive_fields (passwords, tokens, cookies)
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return {"flows": siem_manager.get_tls_flows(limit=limit, client_ip=client_ip)}

@app.post("/api/siem/tls/target/add")
def siem_tls_add_target(body: dict):
    """Dynamically add a target IP to TLS interception at runtime."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    ip = body.get("ip", "")
    if not ip:
        raise HTTPException(400, "ip required")
    ok = siem_manager.tls_add_target(ip)
    return {"ok": ok, "ip": ip}

@app.delete("/api/siem/tls/target/{ip}")
def siem_tls_remove_target(ip: str):
    """Remove a target IP from TLS interception and restore its routing."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    ok = siem_manager.tls_remove_target(ip)
    return {"ok": ok, "ip": ip}

@app.get("/api/siem/tls/ca.crt")
def siem_tls_ca_cert():
    """
    Download the CyberRemedy CA certificate.
    Install this on a target device to enable HTTPS interception without warnings.
    Served automatically via WPAD captive portal — this endpoint is for manual download.
    """
    from pathlib import Path as _Path
    from fastapi.responses import Response as _Response
    ca_path = _Path("data/tls_ca/cyberremedy_ca.crt")
    if not ca_path.exists():
        raise HTTPException(404, "CA not generated yet — start TLS intercept first")
    return _Response(
        content=ca_path.read_bytes(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="cyberremedy_ca.crt"'},
    )


# ══════════════════════════════════════════════════════════════════════════════
# QUIC / HTTP3 INTERCEPTION  (/api/siem/quic/*)
# Block UDP/443 → forces browser TCP/TLS fallback → TLS proxy decrypts it
# SNI extracted from QUIC Initial packets (plaintext per RFC 9001)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/siem/quic/start")
def siem_quic_start(body: dict):
    """
    Start QUIC/HTTP3 interception.
    Body: { "target_ips": [...], "block_quic": true }

    block_quic=true (default): DROP UDP/443 via iptables → browser falls back
    to TCP/TLS which our TLS proxy can decrypt. Recommended.

    block_quic=false: Passive analysis only — extracts SNI from QUIC Initial
    packets (readable per RFC 9001 §5.2 without any keys).
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    target_ips  = body.get("target_ips", [])
    block_quic  = body.get("block_quic", True)
    return siem_manager.start_quic_intercept(target_ips=target_ips or None, block_quic=block_quic)

@app.post("/api/siem/quic/stop")
def siem_quic_stop():
    """Stop QUIC engine and remove block rules (QUIC re-enabled on targets)."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.stop_quic_intercept()

@app.get("/api/siem/quic/status")
def siem_quic_status():
    """QUIC engine status — running, block rules, SNI map, packet counts."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.quic_status()

@app.get("/api/siem/quic/packets")
def siem_quic_packets(limit: int = 100):
    """
    Get intercepted QUIC packets with metadata:
      type (Initial/Handshake/1-RTT), version, DCID, SCID,
      sni (from decrypted ClientHello), alpn, tls_decrypted
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return {"packets": siem_manager.get_quic_packets(limit=limit)}

@app.get("/api/siem/quic/sni")
def siem_quic_sni():
    """
    SNI map: { "192.168.1.x": ["example.com", "api.example.com", ...] }
    Extracted from QUIC Initial ClientHello packets — fully agentless,
    no keys needed (QUIC Initial is decryptable by anyone per RFC 9001).
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return {"sni_map": siem_manager.get_quic_sni_map()}


# ══════════════════════════════════════════════════════════════════════════════
# VPN DEEP INSPECTION  (/api/siem/vpn/*)
# Protocol-level parsing: WireGuard handshake, OpenVPN opcodes,
# IKEv2/IPSec SA_INIT (fully plaintext), traffic content classification
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/siem/vpn/inspect/start")
def siem_vpn_inspect_start(body: dict):
    """
    Start VPN deep inspection.
    Body: {
      "target_ips": [...],
      "block_vpn": false,
      "block_protocols": ["wireguard", "openvpn", "ikev2"]  // optional
    }

    block_vpn=false (default): passive inspection — reads WireGuard handshake
    ephemeral keys, OpenVPN session IDs, IKEv2 SA_INIT (fully plaintext),
    and classifies tunnel content (streaming/VoIP/browsing/gaming) from
    packet timing + size patterns.

    block_vpn=true: DROP VPN ports → forces plaintext traffic → TLS proxy
    decrypts HTTPS. Use together with /api/siem/tls/start.
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    target_ips       = body.get("target_ips", [])
    block_vpn        = body.get("block_vpn", False)
    block_protocols  = body.get("block_protocols", None)
    return siem_manager.start_vpn_inspect(
        target_ips=target_ips or None,
        block_vpn=block_vpn,
        block_protocols=block_protocols,
    )

@app.post("/api/siem/vpn/inspect/stop")
def siem_vpn_inspect_stop():
    """Stop VPN inspection and remove any block rules."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.stop_vpn_inspect()

@app.get("/api/siem/vpn/inspect/status")
def siem_vpn_inspect_status():
    """VPN inspection engine status."""
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.vpn_inspect_status()

@app.get("/api/siem/vpn/inspect/packets")
def siem_vpn_inspect_packets(limit: int = 100, vpn_type: str = ""):
    """
    Get parsed VPN packets. Each entry includes protocol-level fields:
    WireGuard: msg_type, sender_index, ephemeral_pubkey, mac1
    OpenVPN:   msg_type (opcode name), session_id, contains_tls
    IKEv2:     exchange_type, initiator_spi, dh_public_key, vendor_ids, proposals
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return {"packets": siem_manager.get_vpn_packets(limit=limit, vpn_type=vpn_type)}

@app.get("/api/siem/vpn/inspect/classify/{ip}")
def siem_vpn_classify_peer(ip: str):
    """
    Classify what's flowing inside a VPN tunnel for a given peer IP.
    Uses full TunnelPayloadAnalyzer — packet size histogram fingerprinting,
    IAT periodicity scoring, directional ratio, burst structure analysis,
    and ciphertext byte entropy. Returns multi-class probability scores.
    Classes: video_streaming_hd, video_streaming_sd, voip_audio_only,
             video_call, gaming_fps, gaming_mmo, file_transfer,
             web_browsing, ssh_interactive, p2p_bittorrent,
             dns_heavy, idle_keepalive
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.classify_vpn_peer(ip)

@app.get("/api/siem/vpn/inspect/payload/{ip}")
def siem_vpn_payload_analysis(ip: str):
    """
    Deep ciphertext byte analysis for a VPN peer's tunnel traffic.
    Extracts from the OUTER encrypted packets — no decryption of inner data:
      - Shannon entropy per packet (mean, std, min, max)
      - Chi-squared byte uniformity test (cipher mode indicator)
      - CBC vs GCM/CTR mode indicator (16-byte alignment analysis)
      - IV/nonce prefix detection (first-16-bytes entropy)
      - Inner packet size clusters (length distribution leaks through overhead)
      - Human-readable interpretation of all findings
    All agentless — computed purely from packet metadata on the wire.
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.get_vpn_payload_analysis(ip)


@app.get("/api/siem/vpn/inspect/peers")
def siem_vpn_peers():
    """
    List all peer IPs that have collected VPN packet + payload history.
    Use these IPs with /classify/{ip}, /payload/{ip}, and /report/{ip}.
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    peers = siem_manager.get_vpn_peers()
    return {"peers": peers, "count": len(peers)}


@app.get("/api/siem/vpn/inspect/report/{ip}")
def siem_vpn_full_report(ip: str):
    """
    Full combined deep report for a VPN peer in a single call:

      classification  — traffic type + confidence + per-class scores + feature values
                        + human-readable evidence signals
      payload_analysis — ciphertext entropy, chi-squared uniformity, cipher mode
                         (CBC vs GCM/CTR), IV/nonce detection, inner size clusters
      recent_packets  — last parsed VPN protocol packets
                        WireGuard: handshake keys, sender index, mac1
                        OpenVPN: opcode, session_id, TLS record presence
                        IKEv2: exchange type, DH public key, vendor IDs, proposals

    Traffic types: video_streaming_hd, video_streaming_sd, voip_audio_only,
    video_call, gaming_fps, gaming_mmo, file_transfer, web_browsing,
    ssh_interactive, p2p_bittorrent, dns_heavy, idle_keepalive

    Protocols with payload collection:
      WireGuard (UDP/51820) — transport data bytes (post-16-byte header)
      OpenVPN UDP+TCP (1194) — P_DATA_V1/V2 channel ciphertext
      IKEv2 (UDP/500,4500)  — IKE_AUTH + CREATE_CHILD_SA encrypted payloads
      L2TP (UDP/1701)        — PPP payload after 8-byte L2TP header
      Shadowsocks (8388)     — full UDP ciphertext
    """
    if not siem_manager:
        raise HTTPException(503, "SIEM module not available")
    return siem_manager.get_vpn_full_report(ip)


# ══════════════════════════════════════════════════════════════════════════════
# ANDROID / MOBILE DEVICE IDENTIFICATION  (/api/monitor/android/*)
# Agentless identification of Android handhelds via mDNS, SSDP, and
# MAC-randomisation detection — no app or agent required on the device.
# ══════════════════════════════════════════════════════════════════════════════

_mdns_devices:    List[dict] = []
_ssdp_devices:    List[dict] = []
_mac_rand_alerts: List[dict] = []

_android_discovery = None
_android_disc_lock = threading.Lock()


def _sync_android_from_siem():
    global _mdns_devices, _ssdp_devices
    if siem_manager and siem_manager._discovery:
        try:
            _mdns_devices = siem_manager._discovery.get_mdns_devices()
            _ssdp_devices = siem_manager._discovery.get_ssdp_devices()
        except Exception:
            pass


@app.get("/api/monitor/android/status")
def android_status():
    """Status of Android/mobile identification — mDNS/SSDP listeners, device counts."""
    _sync_android_from_siem()
    disc_running = bool(
        (siem_manager and siem_manager._discovery) or _android_discovery
    )
    return {
        "mdns_listener":   disc_running,
        "ssdp_listener":   disc_running,
        "mdns_devices":    len(_mdns_devices),
        "ssdp_devices":    len(_ssdp_devices),
        "mac_rand_alerts": len(_mac_rand_alerts),
        "unique_android":  len({
            d.get("ip") for d in _mdns_devices + _ssdp_devices
            if "android" in (d.get("os_hint","") + d.get("server","")).lower()
        }),
    }


@app.post("/api/monitor/android/start")
def android_start(body: dict = {}):
    """
    Start standalone mDNS (224.0.0.251:5353) + SSDP (239.255.255.250:1900)
    multicast listeners for Android device identification.
    No root required. Works independently of the full SIEM WiFi monitor.
    Body (optional): { "interface": "wlan0" }
    """
    global _android_discovery
    with _android_disc_lock:
        if _android_discovery:
            return {"ok": False, "error": "Already running — stop first"}
        class _MinimalDetector:
            def check_new_device(self, ip="", mac="", source=""): pass
            @property
            def stats(self): return {}
        try:
            from siem.discovery import SIEMDiscovery
            iface = body.get("interface", CONFIG.get("siem", {}).get("interface", "wlan0"))
            _android_discovery = SIEMDiscovery(
                original_iface=iface, monitor_iface=iface,
                detector=_MinimalDetector(), interval=30,
            )
            _android_discovery._running.set()
            _android_discovery._mdns_thread.start()
            _android_discovery._ssdp_thread.start()
            logger.info("[Android] Standalone mDNS + SSDP listeners started")
            return {
                "ok": True, "interface": iface,
                "listeners": ["mDNS:5353", "SSDP:1900"],
                "message": "Listening for Android broadcasts — no agent required on device",
            }
        except Exception as e:
            _android_discovery = None
            raise HTTPException(500, str(e))


@app.post("/api/monitor/android/stop")
def android_stop():
    """Stop standalone mDNS + SSDP listeners."""
    global _android_discovery
    with _android_disc_lock:
        if not _android_discovery:
            return {"ok": False, "error": "Not running"}
        _android_discovery.stop()
        _android_discovery = None
    return {"ok": True}


@app.get("/api/monitor/android/devices")
def android_devices():
    """
    All Android/mobile devices found via mDNS + SSDP, merged and deduplicated.
    Fields: ip, mac, hostname, os_hint, server, usn, source, last_seen.
    Hostname and USN survive MAC randomisation — use them as stable identifiers.
    """
    _sync_android_from_siem()
    merged: dict = {}
    for d in _mdns_devices:
        key = d.get("ip") or d.get("mac") or str(id(d))
        merged[key] = {**merged.get(key, {}), **d}
    for d in _ssdp_devices:
        key = d.get("ip") or d.get("mac") or str(id(d))
        merged[key] = {**merged.get(key, {}), **d}
    devices = sorted(merged.values(), key=lambda x: x.get("last_seen",""), reverse=True)
    return {
        "devices":       devices,
        "total":         len(devices),
        "android_count": sum(1 for d in devices
                             if "android" in (d.get("os_hint","") + d.get("server","")).lower()),
    }


@app.get("/api/monitor/android/mdns")
def android_mdns(limit: int = 100):
    """Raw mDNS device list — hostname + IP from DNS-SD announcements."""
    _sync_android_from_siem()
    return {"devices": _mdns_devices[-limit:], "total": len(_mdns_devices)}


@app.get("/api/monitor/android/ssdp")
def android_ssdp(limit: int = 100):
    """Raw SSDP device list — SERVER header + USN from UPnP NOTIFY packets."""
    _sync_android_from_siem()
    return {"devices": _ssdp_devices[-limit:], "total": len(_ssdp_devices)}


@app.get("/api/monitor/android/mac-randomisation")
def android_mac_rand(limit: int = 100):
    """
    MAC-randomisation alerts fired by rule_mac_randomised in signature.py.
    Android 10+ and iOS 14+ use per-network randomised MACs by default.
    OUI vendor lookup is unreliable for these entries.
    """
    return {
        "alerts": _mac_rand_alerts[-limit:],
        "total":  len(_mac_rand_alerts),
        "note":   "Use mDNS hostname or SSDP USN as stable device identifier.",
    }


@app.delete("/api/monitor/android/devices")
def android_devices_clear():
    """Clear in-memory mDNS + SSDP device lists and MAC-randomisation alerts."""
    global _mdns_devices, _ssdp_devices, _mac_rand_alerts
    counts = {
        "mdns_cleared":     len(_mdns_devices),
        "ssdp_cleared":     len(_ssdp_devices),
        "mac_rand_cleared": len(_mac_rand_alerts),
    }
    _mdns_devices = []; _ssdp_devices = []; _mac_rand_alerts = []
    return counts





# ══════════════════════════════════════════════════════════════════════════════
# VM TRAFFIC MONITOR  (/api/vm/*)
# Agentless monitoring of a VirtualBox VM in Bridged mode on a remote laptop.
# Laptop A (running CyberRemedy, Linux) intercepts all VM traffic via ARP MITM.
# No agent required on Laptop B or inside the VM.
#
# Topology:
#   WiFi Router ─── Laptop A (CyberRemedy)
#               └── Laptop B → VirtualBox (Bridged) → VM (Linux)
# ══════════════════════════════════════════════════════════════════════════════

try:
    from vm_monitor.engine import VMTrafficMonitor
    _vm_monitor = VMTrafficMonitor(
        packet_callback = _on_packet,              # feeds CyberRemedy pipeline
        alert_callback  = _process_alert_enriched, # full alert enrichment
    )
    _VM_AVAILABLE = True
    logger.info("[VMMonitor] VM Traffic Monitor module loaded")
except Exception as _vm_err:
    _vm_monitor = None
    _VM_AVAILABLE = False
    logger.warning(f"[VMMonitor] Could not load vm_monitor module: {_vm_err}")


@app.get("/api/vm/status")
def vm_status():
    """
    Current state of the VM Traffic Monitor.
    Returns mode (stopped / mitm / passive), stats, and capability info.
    """
    if not _vm_monitor:
        return {
            "available": False,
            "reason": "vm_monitor module not loaded",
            "scapy_hint": "pip install scapy",
            "root_hint":  "sudo python main.py",
        }
    s = _vm_monitor.status()
    s["available"] = True
    return s


@app.get("/api/vm/scan")
def vm_scan_network(subnet: str = None, iface: str = "auto"):
    """
    ARP-scan the local WiFi subnet and return all discovered devices.
    VMs are flagged with is_vm=True and vendor='VirtualBox'.
    Use this to find the target VM's IP before starting the monitor.

    Optional query params:
      ?subnet=192.168.1.0/24   Override auto-detected subnet
      ?iface=wlan0             Override auto-detected interface
    """
    if not _VM_AVAILABLE:
        raise HTTPException(503, "VM Monitor module not available")
    if iface and iface != "auto":
        _vm_monitor.iface = iface
    devices = _vm_monitor.scan_network(subnet=subnet)
    vms     = [d for d in devices if d["is_vm"]]
    return {
        "devices":      devices,
        "total":        len(devices),
        "vms_detected": len(vms),
        "vms":          vms,
        "hint": "VMs in VirtualBox Bridged mode appear with OUI 08:00:27 (VirtualBox). Set target_ip to the VM's IP then POST /api/vm/start",
    }


class VMStartReq(BaseModel):
    target_ip: str
    iface:     str = "auto"


@app.post("/api/vm/start")
def vm_start(req: VMStartReq):
    """
    Start intercepting traffic for the target VM IP.
    Uses ARP poisoning (requires scapy + root) or passive fallback.

    Body: { "target_ip": "192.168.1.105", "iface": "wlan0" }
    """
    if not _VM_AVAILABLE:
        raise HTTPException(503, "VM Monitor module not available")
    if req.iface and req.iface != "auto":
        _vm_monitor.iface = req.iface
    result = _vm_monitor.start(target_ip=req.target_ip)
    if not result["ok"]:
        raise HTTPException(400, result.get("error", "Failed to start"))
    return result


@app.post("/api/vm/stop")
def vm_stop():
    """
    Stop the VM monitor and restore ARP caches on both the VM and the router.
    Always call this before shutting down CyberRemedy.
    """
    if not _VM_AVAILABLE or not _vm_monitor:
        raise HTTPException(503, "VM Monitor not available")
    return _vm_monitor.stop()


@app.get("/api/vm/packets")
def vm_packets(limit: int = 100):
    """
    Most recent intercepted packets from the VM (rolling buffer of 500).
    Each packet includes: src_ip, dst_ip, ports, protocol, L7, direction,
    size, payload_size, dns_query, flags, ttl, timestamp.
    """
    if not _VM_AVAILABLE or not _vm_monitor:
        return {"packets": [], "total": 0}
    pkts = _vm_monitor.get_packets(limit=limit)
    return {
        "packets": pkts,
        "total":   len(pkts),
        "target":  _vm_monitor._target_ip,
    }


@app.get("/api/vm/flows")
def vm_flows(limit: int = 100):
    """
    Completed network flows from the VM (aggregated from packets).
    Each flow includes: src/dst IP+port, protocol, L7 service,
    packet count, total bytes, start/end time, direction.
    """
    if not _VM_AVAILABLE or not _vm_monitor:
        return {"flows": [], "active": []}
    return {
        "flows":  _vm_monitor.get_flows(limit=limit),
        "active": _vm_monitor.get_active_flows(),
        "target": _vm_monitor._target_ip,
    }


@app.get("/api/vm/stats")
def vm_stats():
    """
    Traffic statistics for the monitored VM:
    packets intercepted, bytes, DNS queries, alerts generated, uptime.
    """
    if not _VM_AVAILABLE or not _vm_monitor:
        return {}
    return _vm_monitor._stats


@app.get("/api/vm/interfaces")
def vm_interfaces():
    """
    List available network interfaces on Laptop A for use as the capture interface.
    """
    import subprocess as _sp, re as _re
    ifaces = []
    try:
        out = _sp.check_output(["ip", "-o", "link", "show"], text=True, timeout=3)
        for m in _re.finditer(r"\d+: ([\w@.-]+):", out):
            name = m.group(1).split("@")[0]
            if name == "lo":
                continue
            # Get IP if any
            try:
                ip_out = _sp.check_output(
                    ["ip", "-4", "addr", "show", name],
                    text=True, timeout=2, stderr=_sp.DEVNULL,
                )
                ip_m = _re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_out)
                ip = ip_m.group(1) if ip_m else ""
                state = "UP" if "UP" in ip_out else "DOWN"
            except Exception:
                ip, state = "", "UNKNOWN"
            ifaces.append({"name": name, "ip": ip, "state": state})
    except Exception:
        ifaces = [{"name": "wlan0", "ip": "", "state": "UNKNOWN"}]
    return {"interfaces": ifaces}


# ══════════════════════════════════════════════════════════════════════════════
# DARK WEB INTELLIGENCE  (/api/darkweb/*)
# ══════════════════════════════════════════════════════════════════════════════


@app.post("/api/forensics/router-capture")
def forensics_router_capture(body: dict):
    """
    Start forensic capture focused on router traffic.
    Monitors all traffic TO/FROM the gateway IP.
    Works on any interface: home WiFi, hotspot, wired.
    """
    import threading as _t
    import subprocess as _sp
    from siem.iot_detector import hotspot_detector

    # Auto-detect gateway if not specified
    gateway_ip = body.get("gateway_ip", "")
    iface      = body.get("interface", "auto")

    if not gateway_ip:
        topo = hotspot_detector.detect()
        gateway_ip = topo.get("gateway_ip", "")
        if not gateway_ip:
            raise HTTPException(400, "Cannot detect gateway IP — specify gateway_ip in body")

    if iface == "auto":
        from capture.sniffer import _resolve_interface
        iface = _resolve_interface("auto")

    # Create forensic timeline for router
    from datetime import datetime as _dt, timezone as _tz
    tl_id = f"router-{gateway_ip.replace('.','_')}-{int(_dt.now().timestamp())}"
    try:
        forensics.create_timeline(
            entity=gateway_ip,
            timeline_id=tl_id,
            description=f"Router forensics: {gateway_ip} on {iface}",
            source="router_capture",
        )
    except Exception:
        pass

    return sanitize({
        "ok": True,
        "timeline_id": tl_id,
        "gateway_ip":  gateway_ip,
        "interface":   iface,
        "message": f"Router forensic capture started for {gateway_ip} on {iface}",
        "tip": "All traffic to/from the gateway IP will be logged in the Forensic Lab timeline",
    })


@app.get("/api/network/changed")
def network_changed():
    """
    Detect if the network has changed since last scan.
    Returns: {changed: bool, old_gateway, new_gateway, advice}
    Used by dashboard to prompt user to clear stale data.
    """
    import subprocess, re as _re
    from pathlib import Path as _Path

    state_file = _Path("data/network_state.json")

    # Get current gateway
    current_gw = ""
    current_iface = ""
    try:
        out = subprocess.check_output(["ip","route","get","8.8.8.8"], text=True, timeout=3)
        gw_m    = _re.search(r"via\s+(\S+)", out)
        iface_m = _re.search(r"dev\s+(\S+)", out)
        if gw_m:    current_gw    = gw_m.group(1)
        if iface_m: current_iface = iface_m.group(1)
    except Exception:
        pass

    # Load saved state
    saved = {}
    if state_file.exists():
        try: saved = json.loads(state_file.read_text())
        except Exception: pass

    old_gw = saved.get("gateway", "")
    changed = bool(current_gw and old_gw and current_gw != old_gw)

    # Save new state
    try:
        state_file.write_text(json.dumps({
            "gateway": current_gw,
            "interface": current_iface,
            "updated": datetime.utcnow().isoformat(),
        }))
    except Exception:
        pass

    advice = ""
    if changed:
        advice = (f"Network changed: {old_gw} → {current_gw}. "
                  f"Click 🗑 Clear on Assets and Network Monitor to remove stale data.")

    return {
        "changed":       changed,
        "current_gateway": current_gw,
        "previous_gateway": old_gw,
        "interface":     current_iface,
        "advice":        advice,
    }

@app.get("/api/darkweb/tor-status")
def darkweb_tor_status():
    """Check if Tor is running and available for dark web scanning."""
    from dark_web.monitor import _tor_status
    return sanitize(_tor_status())

@app.get("/api/darkweb/status")
def darkweb_status():
    return sanitize(dark_web_monitor.stats)

@app.get("/api/darkweb/watchlist")
def darkweb_watchlist():
    return sanitize({"watchlist": dark_web_monitor.get_watchlist()})

class WatchlistItem(BaseModel):
    keyword: str
    category: str = "general"
    description: str = ""

@app.post("/api/darkweb/watchlist")
def darkweb_add_keyword(item: WatchlistItem):
    entry = dark_web_monitor.add_keyword(item.keyword, item.category, item.description)
    return sanitize(entry)

@app.delete("/api/darkweb/watchlist/{kw_id}")
def darkweb_remove_keyword(kw_id: str):
    ok = dark_web_monitor.remove_keyword(kw_id)
    return {"deleted": ok, "id": kw_id}

@app.get("/api/darkweb/findings")
def darkweb_findings(limit: int = 100, type: str = None):
    return sanitize({"findings": dark_web_monitor.get_findings(limit=limit, finding_type=type)})

@app.post("/api/darkweb/scan")
def darkweb_scan():
    import threading
    def _run():
        dark_web_monitor.run_full_scan()
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "scan_started"}

@app.get("/api/darkweb/breaches")
def darkweb_breaches(domain: str = ""):
    findings = dark_web_monitor.check_breach_databases(domain or None)
    return sanitize({"domain": domain, "findings": findings, "count": len(findings)})


# ══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY MANAGEMENT  (/api/vuln/*)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/vuln/stats")
def vuln_stats():
    return sanitize(vuln_manager.stats())

@app.get("/api/vuln/search")
def vuln_search(q: str = "", min_cvss: float = 0.0, severity: str = None, limit: int = 50):
    # When no query, return top CVEs sorted by CVSS score
    if not q and min_cvss == 0.0 and not severity:
        results = vuln_manager.get_recent_critical(limit=limit) or                   vuln_manager.search_cves("CVE", min_cvss=7.0, limit=limit)
    else:
        results = vuln_manager.search_cves(q, min_cvss=min_cvss, severity=severity or None, limit=limit)
    return sanitize({"results": results, "count": len(results), "query": q})

@app.get("/api/vuln/critical")
def vuln_critical(limit: int = 20):
    return sanitize({"cves": vuln_manager.get_recent_critical(limit=limit)})

@app.get("/api/vuln/findings")
def vuln_findings(asset_ip: str = None, severity: str = None, limit: int = 100):
    findings = vuln_manager.get_findings(asset_ip=asset_ip, severity=severity, limit=limit)
    return sanitize({"findings": findings, "count": len(findings)})

class AssetScanRequest(BaseModel):
    asset_ip: str
    software: list = []

@app.post("/api/vuln/scan")
def vuln_scan_asset(req: AssetScanRequest):
    result = vuln_manager.score_asset_risk(req.asset_ip, req.software)
    return sanitize(result)

@app.get("/api/vuln/asset/{ip}")
def vuln_asset_risk(ip: str):
    """Get vuln risk score for asset — auto-scans from asset inventory software list."""
    device = asset_inv.get_device(ip) if hasattr(asset_inv, 'get_device') else {}
    software = []
    if device:
        sw_raw = device.get("software", device.get("services", []))
        if isinstance(sw_raw, list):
            software = [str(s) for s in sw_raw]
        elif isinstance(sw_raw, dict):
            software = list(sw_raw.keys())
    result = vuln_manager.score_asset_risk(ip, software)
    return sanitize(result)


# ══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING  (/api/hunt/*)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/hunt/query")
def hunt_query(q: str = "", field: str = "all", limit: int = 200, since_hours: int = 24):
    """Free-text hunt across data lake + alerts + flows."""
    import time as _time
    q_lower = q.lower().strip()
    wildcard = q_lower in ('', '*', 'all', '.*')
    results = []
    cutoff  = _time.time() - since_hours * 3600

    # 1. Search recent alerts
    for a in list(reversed(_recent_alerts))[:500]:
        if wildcard:
            results.append({**a, "_source": "alerts"})
            continue
        haystack = json.dumps(a).lower()
        if q_lower in haystack:
            results.append({**a, "_source": "alerts"})

    # 2. Search data lake hot tier
    try:
        lake_events = data_lake.query(limit=2000)
        for e in lake_events:
            ts = e.get("raw_ts", 0)
            if ts and ts < cutoff:
                continue
            if wildcard:
                results.append({**e, "_source": "data_lake"})
            else:
                haystack = json.dumps(e).lower()
                if q_lower in haystack:
                    results.append({**e, "_source": "data_lake"})
    except Exception:
        pass

    # 3. SQLite full-text search
    try:
        import sqlite3 as _sql
        db_path = "data/cyberremedy.db"
        if _sql.sqlite_version and q_lower:
            conn = _sql.connect(db_path)
            try:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE LOWER(type) LIKE ? OR LOWER(src_ip) LIKE ? "
                    "OR LOWER(detail) LIKE ? LIMIT ?",
                    (f"%{q_lower}%", f"%{q_lower}%", f"%{q_lower}%", 100)
                ).fetchall()
                cols = [d[0] for d in conn.execute("PRAGMA table_info(alerts)").fetchall()]
                for row in rows:
                    results.append({**dict(zip(cols, row)), "_source": "sqlite"})
            except Exception:
                pass
            finally:
                conn.close()
    except Exception:
        pass

    # Deduplicate and sort by timestamp
    seen = set()
    unique = []
    for r in results:
        key = r.get("id", json.dumps(r)[:60])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    unique.sort(key=lambda x: x.get("timestamp", x.get("captured_at", "")), reverse=True)
    return sanitize({"results": unique[:limit], "count": len(unique), "query": q})


@app.get("/api/hunt/saved")
def hunt_saved():
    hunt_file = Path("data/saved_hunts.json")
    if not hunt_file.exists():
        return {"hunts": []}
    try:
        return sanitize({"hunts": json.loads(hunt_file.read_text())})
    except Exception:
        return {"hunts": []}

class HuntSaveRequest(BaseModel):
    name: str
    query: str
    field: str = "all"
    description: str = ""

@app.post("/api/hunt/saved")
def hunt_save(req: HuntSaveRequest):
    from datetime import datetime as _dt, timezone as _tz
    hunt_file = Path("data/saved_hunts.json")
    existing = []
    if hunt_file.exists():
        try: existing = json.loads(hunt_file.read_text())
        except: pass
    entry = {"id": f"hunt_{len(existing)+1}", "name": req.name,
             "query": req.query, "field": req.field,
             "description": req.description,
             "created_at": _dt.now(_tz.utc).isoformat()}
    existing.append(entry)
    hunt_file.write_text(json.dumps(existing[-100:], indent=2))
    return sanitize(entry)

@app.delete("/api/hunt/saved/{hunt_id}")
def hunt_delete(hunt_id: str):
    hunt_file = Path("data/saved_hunts.json")
    if hunt_file.exists():
        try:
            hunts = json.loads(hunt_file.read_text())
            hunts = [h for h in hunts if h.get("id") != hunt_id]
            hunt_file.write_text(json.dumps(hunts, indent=2))
        except Exception:
            pass
    return {"deleted": True, "id": hunt_id}


# ══════════════════════════════════════════════════════════════════════════════
# ML / LSTM STATUS  (/api/ml/*)
# ══════════════════════════════════════════════════════════════════════════════


@app.get("/api/ml/train-status")
def ml_train_status():
    """Return ML model status and training availability."""
    from pathlib import Path as _P
    models = {
        "anomaly_model":    _P("models/anomaly_model.joblib").exists(),
        "rf_attack_model":  _P("models/rf_attack_model.joblib").exists(),
    }
    trained = all(models.values())
    return {
        "models_trained": trained,
        "models":         models,
        "trainer_script": _P("ml/lstm/trainer.py").exists(),
        "auto_train_available": _maybe_auto_train is not None,
    }

@app.post("/api/ml/auto-train")
def ml_auto_train(body: dict = None):
    """Trigger ML auto-training (opens xterm if available)."""
    if not _maybe_auto_train:
        return {"ok": False, "error": "auto_train module not available"}
    force = (body or {}).get("force", True)
    started = _maybe_auto_train(force=force)
    return {"ok": True, "started": started,
            "message": "Training started in xterm (or background)" if started
                       else "Models already trained — use force:true to retrain"}

@app.get("/api/ml/status")
def ml_status():
    from pathlib import Path as _Path
    import json as _json
    config_path = _Path("models/lstm_config.json")
    config = {}
    if config_path.exists():
        try: config = _json.loads(config_path.read_text())
        except: pass

    iso_status = anomaly_detector.status if hasattr(anomaly_detector, 'status') else {}
    return sanitize({
        "isolation_forest": iso_status,
        "lstm": {
            "ready":        lstm_detector.is_ready,
            "stats":        lstm_detector.stats,
            "config":       config,
            "model_exists": _Path("models/lstm_detector.pt").exists() or _Path("models/lstm_detector.keras").exists(),
            "train_cmd":    "python3 ml/lstm/trainer.py",
        },
        "datasets": {
            "nslkdd_exists": _Path("ml/datasets/nslkdd/KDDTrain+.txt").exists(),
            "dataset_dir":   "ml/datasets/nslkdd/",
        },
    })

@app.post("/api/ml/retrain")
def ml_retrain(force: bool = False):
    """Trigger LSTM retrain in background thread."""
    import threading as _threading
    def _retrain():
        try:
            import subprocess, sys
            result = subprocess.run(
                [sys.executable, "ml/lstm/trainer.py"] + (["--retrain"] if force else []),
                capture_output=True, text=True, timeout=600, cwd="."
            )
            logger.info(f"LSTM retrain complete: rc={result.returncode}")
            if result.returncode == 0:
                lstm_detector.load()  # reload new model
        except Exception as exc:
            logger.error(f"LSTM retrain failed: {exc}")

    _threading.Thread(target=_retrain, daemon=True, name="lstm-retrain").start()
    return {"status": "retrain_started", "force": force}

@app.get("/api/ml/resources")
def ml_resources():
    """Return download status for all free external resources."""
    try:
        return sanitize(_resource_status())
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/ml/download-resources")
def ml_download_resources(force: bool = False):
    """Trigger background download of all free external resources."""
    _start_resource_download()
    return {"status": "download_started"}


# ══════════════════════════════════════════════════════════════════════════════
# PDF REPORTS  (/api/reports/*)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/reports/list")
def reports_list():
    report_dir = Path("data/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for f in sorted(report_dir.glob("*.pdf"), reverse=True)[:50]:
        reports.append({
            "name": f.name,
            "size_kb": round(f.stat().st_size / 1024, 1),
            "created": datetime.utcfromtimestamp(f.stat().st_mtime).isoformat(),
        })
    return sanitize({
        "reports": reports,
        "pdf_available": pdf_available(),
        "install_hint": pdf_install_hint() if not pdf_available() else None,
    })

@app.post("/api/reports/executive")
def reports_executive():
    if not pdf_available():
        return JSONResponse({"error": f"reportlab not installed. Run: {pdf_install_hint()}"}, status_code=503)
    try:
        # Safely collect data - each call wrapped so one failure doesn't kill the whole report
        try: alerts_data = list(_recent_alerts)[-500:]
        except Exception: alerts_data = []
        try: cases_data = [c.to_dict() if hasattr(c,"to_dict") else c
                           for c in (case_manager.list() or [])][:100]
        except Exception: cases_data = []
        try: blocked_data = [r for r in (responder.get_response_log() or [])[:100]
                             if r.get("action")=="block"]
        except Exception: blocked_data = []
        path = generate_executive_summary(
            alerts=alerts_data,
            cases=cases_data,
            blocked=blocked_data,
            pipeline_state=pipeline_state,
        )
        return FileResponse(str(path), media_type="application/pdf", filename=path.name)
    except Exception as e:
        logger.error(f"PDF executive summary failed: {e}", exc_info=True)
        return JSONResponse({"error": f"PDF generation failed: {e}"}, status_code=500)

@app.post("/api/reports/threat-intel")
def reports_threat_intel():
    if not pdf_available():
        return JSONResponse({"error": f"reportlab not installed. Run: {pdf_install_hint()}"}, status_code=503)
    try:
        try:
            store = ioc_manager.store
            ioc_stats = {
                "ips":     len(getattr(store,"_ips",{})),
                "domains": len(getattr(store,"_domains",{})),
                "hashes":  len(getattr(store,"_hashes",{})),
                "urls":    len(getattr(store,"_urls",{})),
                "total":   ioc_manager.get_stats().get("total", 0),
            }
            top_iocs = [r.to_dict() if hasattr(r,"to_dict") else r
                        for r in list(getattr(store,"_ips",{}).values())[:25]]
            feed_status = ioc_manager.get_feed_status() if hasattr(ioc_manager,"get_feed_status") else []
        except Exception as de:
            logger.warning(f"PDF threat-intel data collection partial: {de}")
            ioc_stats = {"ips":0,"domains":0,"hashes":0,"urls":0,"total":0}
            top_iocs, feed_status = [], []
        path = generate_threat_intel_report(
            ioc_stats=ioc_stats,
            feed_status=feed_status,
            top_iocs=top_iocs,
        )
        return FileResponse(str(path), media_type="application/pdf", filename=path.name)
    except Exception as e:
        logger.error(f"PDF threat-intel failed: {e}", exc_info=True)
        return JSONResponse({"error": f"PDF generation failed: {e}"}, status_code=500)

@app.post("/api/reports/vulnerabilities")
def reports_vuln():
    if not pdf_available():
        return JSONResponse({"error": f"reportlab not installed. Run: {pdf_install_hint()}"}, status_code=503)
    try:
        path = generate_vuln_report(
            findings=vuln_manager.get_findings(limit=200),
            stats=vuln_manager.stats(),
        )
        return FileResponse(str(path), media_type="application/pdf", filename=path.name)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/reports/compliance")
def reports_compliance():
    if not pdf_available():
        return JSONResponse({"error": f"reportlab not installed. Run: {pdf_install_hint()}"}, status_code=503)
    try:
        try:
            system_state = _build_system_state()
            fw_results = compliance.run_all_assessments(system_state)
        except Exception as de:
            logger.warning(f"PDF compliance data partial: {de}")
            fw_results = {}
        path = generate_compliance_report(framework_results=fw_results)
        return FileResponse(str(path), media_type="application/pdf", filename=path.name)
    except Exception as e:
        logger.error(f"PDF compliance failed: {e}", exc_info=True)
        return JSONResponse({"error": f"PDF generation failed: {e}"}, status_code=500)

@app.get("/api/reports/download/{filename}")
def reports_download(filename: str):
    path = Path("data/reports") / filename
    if not path.exists() or not path.suffix == ".pdf":
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(str(path), media_type="application/pdf", filename=filename)

def _build_system_state() -> dict:
    """Build system_state dict for compliance checker."""
    return {
        "alerts_total": len(_recent_alerts),
        "modules_active": [
            "network_ids", "auto_response", "logging", "hids",
            *(["yara"] if yara_scanner else []),
            *(["sigma"] if sigma_engine else []),
        ],
        "agents_registered": len(asset_inv.get_all_devices()) if hasattr(asset_inv,'get_all_devices') else 0,
        "cases_total": len(case_manager.list()),
        "vuln_agents_scanned": vuln_manager.stats().get("assets_scanned", 0),
        "sigma_rules_count": sigma_engine.rule_count if hasattr(sigma_engine,'rule_count') else 30,
        "mitre_ids_covered": list(mitre_mapper.get_all_ids())[:50] if hasattr(mitre_mapper,'get_all_ids') else [],
        "risk_scoring_active": True,
        "fim_active": False,
    }
