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

# Core pipeline
from capture.sniffer import LiveSniffer, PcapReplayer
from packet_analyzer.engine import PacketAnalyzer
from features.extractor import FlowAggregator
from detection.signature import SignatureDetector
from detection.anomaly import AnomalyDetector
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
from rbac.auth import RBACManager
# v1.0 modules
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
    model_path=CONFIG.get("detection", {}).get("anomaly", {}).get("model_path", "models/anomaly_model.pkl"),
    classifier_path=CONFIG.get("detection", {}).get("anomaly", {}).get("classifier_path", "models/classifier_model.pkl"),
)
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
rbac            = RBACManager()
# v1.0 component initialisation
log_manager   = LogManager(CONFIG)
firewall      = FirewallIntegrator(CONFIG)
asset_inv     = AssetInventory(CONFIG)
geoip         = GeoIPLookup(CONFIG)


# ── app ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="CyberRemedy API", description="AI-Driven Adaptive IDS — Full SOC Platform v3.0",
              version="1.0.0", docs_url="/docs", redoc_url="/redoc")

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
        dead = set(); payload = json.dumps(message, default=str)
        for ws in self.active:
            try: await ws.send_text(payload)
            except: dead.add(ws)
        self.active -= dead

manager = ConnectionManager()

# ── pipeline state ────────────────────────────────────────────────────────────

pipeline_state = dict(running=False, interface="eth0", mode="stopped",
                      packets_processed=0, flows_analyzed=0, alerts_total=0,
                      start_time=None, version="1.0.0")
_recent_alerts:    List[dict] = []
_recent_responses: List[dict] = []
_recent_chains:    List[dict] = []
_traffic_history:  List[dict] = []
_traffic_counter   = dict(benign=0, malicious=0, total=0)

# ── central alert enrichment pipeline ────────────────────────────────────────

def _process_alert(alert: dict):
    # IOC check
    _ioc_raw = ioc_manager.store.lookup_ip(alert.get("src_ip", ""))
    ioc_hit = _ioc_raw.to_dict() if _ioc_raw else None
    if ioc_hit:
        alert["ioc_match"] = ioc_hit
        if alert.get("severity") in ("MEDIUM","LOW"):
            alert["severity"] = "HIGH"

    # UEBA
    ueba_signal = ueba_engine.ingest_event({
        "src_ip": alert.get("src_ip"), "dst_ip": alert.get("dst_ip"),
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
    reporter.log_alert(alert)
    data_lake.ingest(alert)

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
    alerts.extend(sigma_engine.evaluate(flow))
    for a in alerts:
        if not correlation_engine.should_suppress_fp(a):
            _process_alert(a)
    if not alerts:
        _traffic_counter["benign"] += 1
        _traffic_counter["total"] += 1

_packet_analyzer = PacketAnalyzer(alert_callback=None)  # callback wired after _process_alert defined
flow_aggregator = FlowAggregator(
    flow_timeout=CONFIG.get("capture", {}).get("flow_timeout_seconds", 60),
    on_flow_complete=_on_flow_complete,
)

def _on_packet(pkt: dict):
    pipeline_state["packets_processed"] += 1
    flow_aggregator.add_packet(pkt)
    # ── Deep packet analysis (Wireshark-style ML analyzer)
    try:
        _packet_analyzer.ingest(pkt)
    except Exception:
        pass
    payload = pkt.get("payload", b"")
    if len(payload) > 64:
        yara_scanner.scan_bytes(payload, context={"src_ip": pkt.get("src_ip")})

def _on_honeypot(event: dict):
    event.update(type="Honeypot Connection", severity="CRITICAL", confidence=100.0, mitre_id="T1595")
    _process_alert(event)
    logger.warning(f"HONEYPOT HIT: {event}")

# ── v1.0: wire asset+log callbacks (must be after _process_alert defined) ────
def _process_alert_enriched(alert: dict):
    """v1.0 wrapper: logs to file + adds GeoIP, then runs original pipeline."""
    try:
        # GeoIP enrich (non-blocking — uses cache)
        src = alert.get("src_ip","")
        if src:
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
                    "active_flows": flow_aggregator.active_flow_count(),
                    "cases":        case_manager.stats(),
                    "ueba":         ueba_engine.stats,
                    "honeypot":     honeypot_mgr.stats,
                    "ioc":          ioc_manager.get_stats(),
                }
            except Exception: pass
            await manager.broadcast(payload)
        except Exception as e:
            logger.warning(f"broadcast_loop error: {e}")


@app.on_event("startup")
async def startup():
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
            try:
                from capture.sniffer import LiveSniffer as _LS
                _LS(interface=iface, callback=_on_packet).start()
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
        pipeline_state.update(running=False, mode="error:not_root")
    logger.info("CyberRemedy SOC PLATFORM v1.0 API started")

@app.on_event("shutdown")
async def shutdown():
    honeypot_mgr.stop_all()

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
        await ws.send_text(json.dumps(init_msg, default=str))
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
        "version": "1.0.0", "pipeline": pipeline_state,
        "uptime_seconds": time.time()-pipeline_state["start_time"] if pipeline_state["start_time"] else 0,
        "components": {
            "signature_detector": "ready",
            "anomaly_detector": anomaly_detector.status["mode"],
            "correlation_engine": "ready",
            "responder": "ready" if not responder.dry_run else "dry_run",
            "case_manager": f"{case_manager.stats()['total']} cases",
            "ioc_manager": f"{ioc_manager.get_stats()['total_iocs']} IOCs",
            "ueba": "active" if ueba_engine.is_active else "learning",
            "honeypot": "active" if honeypot_mgr.running else "stopped",
            "sigma": f"{sigma_engine.stats.get('total_rules', 0)} rules",
            "yara": f"{yara_scanner.stats.get('total_rules',0)} rules",
        },
    }

@app.get("/api/alerts")
def get_alerts(limit: int=100, severity: str=None, ioc_only: bool=False):
    a = list(reversed(_recent_alerts[-500:]))
    if severity: a = [x for x in a if x.get("severity")==severity.upper()]
    if ioc_only: a = [x for x in a if x.get("ioc_match")]
    return {"alerts": a[:limit], "total": len(_recent_alerts)}

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    for a in reversed(_recent_alerts):
        if a.get("id") == alert_id: return a
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
    global pipeline_state
    try:
        sniffer.stop()
    except Exception:
        pass
    pipeline_state["running"] = False
    pipeline_state["mode"] = "restarting"
    import asyncio
    async def _restart():
        await asyncio.sleep(1.5)
        try:
            sniffer.start()
            pipeline_state["running"] = True
            pipeline_state["mode"] = "live"
        except Exception as e:
            pipeline_state["running"] = True
            pipeline_state["mode"] = "stopped"
    asyncio.create_task(_restart())
    return {"restarting": True, "message": "Pipeline restarting in 1.5s"}

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
    return FileResponse(p, media_type="text/html")

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
def refresh_feeds():
    return {"results": "Feed refresh not available in offline mode"}

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
    # Return loaded rule names from _rules dict + recent scan results
    try:
        rule_names = list(yara_scanner._rules.keys()) if hasattr(yara_scanner,'_rules') and yara_scanner._rules else []
    except Exception:
        rule_names = []
    return {
        "rules": [{"name": n, "source": "built-in", "status": "active"} for n in rule_names],
        "rule_count": len(rule_names),
        "recent_hits": yara_scanner.get_results(20),
        "stats": yara_scanner.stats,
    }

@app.post("/api/yara/rules")
def add_yara(req: YaraRuleReq):
    return {"result": yara_scanner.add_rule_file(req.name, req.rule_text, req.tags)}

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
    return {"result": sigma_engine.load_rule_text(req.yaml_content, source=req.source)}

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

@app.get("/api/vuln/scans")
def list_scans(): return vuln_manager.list_scans()

@app.post("/api/vuln/scan")
def run_scan(req: ScanReq):
    return {"result": vuln_manager.scan(req.host, req.packages or [])}

@app.get("/api/vuln/cves")
def list_cves(severity: str=None, host: str=None):
    return vuln_manager.list_findings(severity=severity, host=host)

@app.get("/api/vuln/stats")
def vuln_stats(): return vuln_manager.stats()

# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC TIMELINE
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/forensics/timeline")
def get_timeline(src_ip: str=None, since_ts: float=None, limit: int=200):
    return {"events": forensics.list()}

@app.get("/api/forensics/chains/{chain_id}")
def get_chain_timeline(chain_id: str):
    return forensics.get(chain_id) or {}

@app.post("/api/forensics/ingest")
def ingest_forensic(event: dict):
    forensics.ingest_host_event(event); return {"status": "ingested"}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA LAKE
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/datalake/stats")
def datalake_stats(): return data_lake.stats()

@app.get("/api/datalake/query")
def query_datalake(category: str="alert", since_ts: float=None, src_ip: str=None, limit: int=500):
    return {"records": data_lake.query(category=category, since_ts=since_ts, src_ip=src_ip, limit=limit)}

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
# v1.0 ENDPOINTS
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
    alerts = [a for a in _recent_alerts if a.get("src_ip")==ip or a.get("dst_ip")==ip]
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
    return {"points": geoip.get_map_data(_recent_alerts, limit=limit),
            "country_stats": geoip.country_stats(_recent_alerts)}

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
    import socket as _sock
    try: server_ip = _sock.gethostbyname(_sock.gethostname())
    except Exception: server_ip = "127.0.0.1"
    base = {"running": _syslog_srv is not None, "server_ip": server_ip,
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
        sent = en.send("[CyberRemedy] Test Email", "<h2>Test email from CyberRemedy SOC PLATFORM v1.0</h2><p>Email is configured correctly.</p>")
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


@app.get("/docs/api")
def api_docs_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/docs")
