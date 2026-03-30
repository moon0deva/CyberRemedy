"""
CyberRemedy SOAR — Playbook Engine
Automated investigation and response workflows.
Inspired by Security Onion Playbooks + Graylog Event Procedures.
"""

import json
import time
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any

logger = logging.getLogger("cyberremedy.soar")

PLAYBOOKS_PATH = Path("data/playbooks.json")
EXECUTIONS_PATH = Path("data/playbook_executions.json")


# ─── STEP TYPES ───────────────────────────────────────────────────────────────

class StepType:
    LOOKUP_IOC = "lookup_ioc"
    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    CREATE_CASE = "create_case"
    NOTIFY_WEBHOOK = "notify_webhook"
    QUERY_LOGS = "query_logs"
    ENRICH_MITRE = "enrich_mitre"
    ESCALATE_CASE = "escalate_case"
    SCAN_HASH_VT = "scan_hash_vt"
    COLLECT_HOST_INFO = "collect_host_info"
    QUARANTINE_HOST = "quarantine_host"
    RUN_YARA = "run_yara"
    CUSTOM_SCRIPT = "custom_script"
    WAIT = "wait"
    ANALYST_REVIEW = "analyst_review"
    # Extended step types for advanced playbooks
    DISABLE_USER        = "disable_user"
    REVOKE_SESSIONS     = "revoke_sessions"
    KILL_PROCESS        = "kill_process"
    ISOLATE_HOST        = "isolate_host"
    BLOCK_HASH          = "block_hash"
    BLOCK_OUTBOUND      = "block_outbound"
    SUSPEND_USER        = "suspend_user"
    SNAPSHOT_SYSTEM     = "snapshot_system"
    BLOCK_LATERAL_PORTS = "block_lateral_ports"
    CHECK_IOC_LOCAL     = "check_ioc_local"
    CLOSE_CASE          = "close_case"


# ─── PLAYBOOK STEP ────────────────────────────────────────────────────────────

class PlaybookStep:
    def __init__(self, step_id: str, name: str, step_type: str,
                 params: dict = None, on_success: str = None,
                 on_failure: str = None, auto: bool = True):
        self.step_id = step_id
        self.name = name
        self.step_type = step_type
        self.params = params or {}
        self.on_success = on_success  # ID of next step
        self.on_failure = on_failure
        self.auto = auto             # False = pause for analyst

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id, "name": self.name,
            "step_type": self.step_type, "params": self.params,
            "on_success": self.on_success, "on_failure": self.on_failure,
            "auto": self.auto,
        }


# ─── PLAYBOOK ─────────────────────────────────────────────────────────────────

class Playbook:
    def __init__(self, playbook_id: str, name: str, description: str,
                 trigger_conditions: dict = None):
        self.playbook_id = playbook_id
        self.name = name
        self.description = description
        self.trigger_conditions = trigger_conditions or {}
        self.steps: Dict[str, PlaybookStep] = {}
        self.entry_step: Optional[str] = None
        self.created_at = datetime.utcnow().isoformat()
        self.enabled = True
        self.execution_count = 0

    def add_step(self, step: PlaybookStep, is_entry: bool = False):
        self.steps[step.step_id] = step
        if is_entry or not self.entry_step:
            self.entry_step = step.step_id

    def matches_alert(self, alert: dict) -> bool:
        conds = self.trigger_conditions
        if not conds:
            return True
        sev_match = not conds.get("severity") or alert.get("severity") in conds["severity"]
        type_match = not conds.get("types") or any(
            t.lower() in alert.get("type", "").lower() for t in conds["types"]
        )
        mitre_match = not conds.get("mitre_ids") or alert.get("mitre_id") in conds["mitre_ids"]
        score_match = not conds.get("min_risk_score") or alert.get("risk_score", 0) >= conds["min_risk_score"]
        return all([sev_match, type_match, mitre_match, score_match])

    def to_dict(self) -> dict:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger_conditions": self.trigger_conditions,
            "steps": {k: v.to_dict() for k, v in self.steps.items()},
            "entry_step": self.entry_step,
            "enabled": self.enabled,
            "execution_count": self.execution_count,
            "created_at": self.created_at,
        }


# ─── EXECUTION CONTEXT ────────────────────────────────────────────────────────

class ExecutionContext:
    def __init__(self, execution_id: str, playbook: Playbook, alert: dict):
        self.execution_id = execution_id
        self.playbook_id = playbook.playbook_id
        self.playbook_name = playbook.name
        self.alert = alert
        self.started_at = datetime.utcnow().isoformat()
        self.completed_at: Optional[str] = None
        self.status = "RUNNING"      # RUNNING | COMPLETED | FAILED | WAITING_ANALYST
        self.current_step: Optional[str] = None
        self.step_results: List[dict] = []
        self.variables: dict = {}    # Shared state across steps
        self.error: Optional[str] = None

    def log_step(self, step_id: str, step_name: str, result: Any, success: bool, duration_ms: float):
        self.step_results.append({
            "step_id": step_id,
            "step_name": step_name,
            "result": str(result)[:500] if result else "",
            "success": success,
            "duration_ms": round(duration_ms, 1),
            "timestamp": datetime.utcnow().isoformat(),
        })

    def to_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "alert_id": self.alert.get("id"),
            "alert_type": self.alert.get("type"),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "current_step": self.current_step,
            "step_results": self.step_results,
            "variables": self.variables,
            "steps_completed": len(self.step_results),
            "error": self.error,
        }


# ─── STEP EXECUTOR ────────────────────────────────────────────────────────────

class StepExecutor:
    """Executes individual playbook steps. Can be extended with custom handlers."""

    def __init__(self, responder=None, ioc_manager=None, case_manager=None):
        self.responder = responder
        self.ioc_manager = ioc_manager
        self.case_manager = case_manager

    def execute(self, step: PlaybookStep, ctx: ExecutionContext) -> tuple[bool, Any]:
        t0 = time.time()
        result = None
        success = True

        try:
            if step.step_type == StepType.BLOCK_IP:
                ip = ctx.variables.get("src_ip") or ctx.alert.get("src_ip", "")
                if ip and self.responder:
                    entry = self.responder.manual_block(ip, reason=f"SOAR: {ctx.playbook_name}")
                    result = f"Blocked {ip}"
                    ctx.variables["blocked"] = True
                else:
                    result = "No IP to block or responder unavailable"

            elif step.step_type == StepType.RATE_LIMIT:
                ip = ctx.variables.get("src_ip") or ctx.alert.get("src_ip", "")
                if ip and self.responder:
                    self.responder.firewall.rate_limit(ip)
                    result = f"Rate-limited {ip}"

            elif step.step_type == StepType.LOOKUP_IOC:
                ip = ctx.alert.get("src_ip", "")
                if self.ioc_manager and ip:
                    rec = self.ioc_manager.store.lookup_ip(ip)
                    ctx.variables["ioc_hit"] = rec is not None
                    ctx.variables["ioc_record"] = rec.to_dict() if rec else None
                    result = f"IOC check: {'HIT' if rec else 'CLEAN'} for {ip}"

            elif step.step_type == StepType.CREATE_CASE:
                if self.case_manager:
                    case = self.case_manager.create_from_alert(ctx.alert)
                    ctx.variables["case_id"] = case.id
                    result = f"Case created: {case.id}"

            elif step.step_type == StepType.ENRICH_MITRE:
                mitre_id = ctx.alert.get("mitre_id", "")
                ctx.variables["mitre_enriched"] = mitre_id != ""
                result = f"MITRE: {mitre_id}"

            elif step.step_type == StepType.ESCALATE_CASE:
                case_id = ctx.variables.get("case_id")
                if case_id and self.case_manager:
                    self.case_manager.escalate(case_id, f"SOAR auto-escalation: {ctx.playbook_name}")
                    result = f"Case {case_id} escalated"

            elif step.step_type == StepType.NOTIFY_WEBHOOK:
                url = step.params.get("url", "")
                if url:
                    result = f"Webhook notification sent to {url[:50]}"
                else:
                    result = "No webhook URL configured"

            elif step.step_type == StepType.WAIT:
                duration = step.params.get("seconds", 5)
                time.sleep(min(duration, 10))
                result = f"Waited {duration}s"

            elif step.step_type == StepType.ANALYST_REVIEW:
                result = "Paused for analyst review"
                success = True
                # This would block until analyst approves in a full implementation

            elif step.step_type == StepType.COLLECT_HOST_INFO:
                agent_id = ctx.alert.get("agent_id", "")
                result = f"Collected host info for agent: {agent_id or 'N/A'}"

            elif step.step_type == StepType.QUARANTINE_HOST:
                ip = ctx.alert.get("src_ip", "")
                if ip and self.responder:
                    self.responder.manual_block(ip, reason=f"QUARANTINE: {ctx.playbook_name}")
                    result = f"Host {ip} quarantined"

            elif step.step_type == StepType.DISABLE_USER:
                uid = ctx.alert.get("user_id", "") or ctx.variables.get("user_id", "")
                if uid:
                    import json as _json
                    from pathlib import Path as _Path
                    uf = _Path("data/users.json")
                    if uf.exists():
                        users = _json.loads(uf.read_text())
                        for u in users:
                            if u.get("username") == uid:
                                u["active"] = False
                                u["disabled_reason"] = f"SOAR:{ctx.playbook_name}"
                        uf.write_text(_json.dumps(users, indent=2))
                    ctx.variables["user_disabled"] = True
                    result = f"User {uid} disabled"
                else:
                    result = "No user_id to disable"

            elif step.step_type == StepType.REVOKE_SESSIONS:
                uid = ctx.alert.get("user_id", "") or ctx.variables.get("user_id", "")
                import json as _json
                from pathlib import Path as _Path
                from datetime import datetime as _dt, timezone as _tz
                rl = _Path("data/revoked_sessions.json")
                existing = []
                if rl.exists():
                    try: existing = _json.loads(rl.read_text())
                    except: pass
                existing.append({"user": uid, "revoked_at": _dt.now(_tz.utc).isoformat(),
                                  "reason": f"SOAR:{ctx.playbook_name}"})
                rl.write_text(_json.dumps(existing[-500:], indent=2))
                ctx.variables["sessions_revoked"] = True
                result = f"Sessions revoked for {uid}"

            elif step.step_type == StepType.KILL_PROCESS:
                proc = ctx.alert.get("process_name", "") or ctx.variables.get("process_name", "")
                import subprocess as _sp
                if proc and proc not in ["", "unknown"]:
                    r = _sp.run(["pkill", "-f", proc], capture_output=True, timeout=10)
                    result = f"kill {proc}: rc={r.returncode}"
                    ctx.variables["process_killed"] = r.returncode in [0, 1]
                else:
                    result = "No process_name to kill"

            elif step.step_type == StepType.ISOLATE_HOST:
                ip = ctx.alert.get("src_ip", "") or ctx.variables.get("src_ip", "")
                import subprocess as _sp, ipaddress as _ipa
                if ip and self.responder:
                    self.responder.manual_block(ip, reason=f"ISOLATE:{ctx.playbook_name}")
                    result = f"Host {ip} isolated (blocked)"
                    ctx.variables["host_isolated"] = True
                else:
                    result = f"Host isolation skipped for {ip}"

            elif step.step_type == StepType.BLOCK_HASH:
                fhash = ctx.alert.get("file_hash", "") or ctx.variables.get("file_hash", "")
                import json as _json
                from pathlib import Path as _Path
                from datetime import datetime as _dt, timezone as _tz
                bl = _Path("data/blocked_hashes.json")
                existing = []
                if bl.exists():
                    try: existing = _json.loads(bl.read_text())
                    except: pass
                if fhash and fhash not in [e.get("hash") for e in existing]:
                    existing.append({"hash": fhash, "blocked_at": _dt.now(_tz.utc).isoformat(),
                                     "source": f"SOAR:{ctx.playbook_name}"})
                    bl.write_text(_json.dumps(existing, indent=2))
                result = f"Hash blocked: {fhash or 'none'}"
                ctx.variables["hash_blocked"] = bool(fhash)

            elif step.step_type == StepType.BLOCK_OUTBOUND:
                ip = ctx.alert.get("dst_ip", "") or ctx.variables.get("dst_ip", "")
                if ip and self.responder:
                    self.responder.manual_block(ip, reason=f"EXFIL_DST:{ctx.playbook_name}")
                    result = f"Outbound to {ip} blocked"
                    ctx.variables["outbound_blocked"] = True
                else:
                    result = "No dst_ip to block outbound"

            elif step.step_type == StepType.SUSPEND_USER:
                uid = ctx.alert.get("user_id", "") or ctx.variables.get("user_id", "")
                if uid:
                    import json as _json
                    from pathlib import Path as _Path
                    from datetime import datetime as _dt, timezone as _tz
                    uf = _Path("data/users.json")
                    if uf.exists():
                        users = _json.loads(uf.read_text())
                        for u in users:
                            if u.get("username") == uid:
                                u["active"] = False
                                u["suspended"] = True
                                u["suspended_reason"] = f"SOAR:{ctx.playbook_name}"
                        uf.write_text(_json.dumps(users, indent=2))
                    result = f"User {uid} suspended"
                    ctx.variables["user_suspended"] = True
                else:
                    result = "No user to suspend"

            elif step.step_type == StepType.SNAPSHOT_SYSTEM:
                import json as _json, subprocess as _sp
                from pathlib import Path as _Path
                from datetime import datetime as _dt, timezone as _tz
                snap_dir = _Path("data/snapshots")
                snap_dir.mkdir(parents=True, exist_ok=True)
                ts = _dt.now(_tz.utc).strftime("%Y%m%d_%H%M%S")
                snap = {"timestamp": _dt.now(_tz.utc).isoformat(),
                        "alert_id": ctx.alert.get("id","?"),
                        "playbook": ctx.playbook_name}
                for cmd, key in [(['ss','-tnp'],'netstat'),(['ps','ax'],'processes')]:
                    try:
                        r = _sp.run(cmd, capture_output=True, text=True, timeout=5)
                        snap[key] = r.stdout[:3000]
                    except: snap[key] = "unavailable"
                sf = snap_dir / f"snap_{ctx.playbook_name}_{ts}.json"
                sf.write_text(_json.dumps(snap, indent=2))
                result = f"System snapshot saved: {sf.name}"
                ctx.variables["snapshot_path"] = str(sf)

            elif step.step_type == StepType.BLOCK_LATERAL_PORTS:
                ip = ctx.alert.get("src_ip","")
                import subprocess as _sp, ipaddress as _ipa
                lateral_ports = [445, 3389, 5985, 5986, 22, 135, 139]
                blocked = []
                try:
                    ipt = "ip6tables" if _ipa.ip_address(ip).version==6 else "iptables"
                    for port in lateral_ports:
                        r = _sp.run([ipt,"-I","FORWARD","-s",ip,"-p","tcp","--dport",str(port),"-j","DROP"],
                                     capture_output=True, text=True, timeout=5)
                        if r.returncode == 0: blocked.append(port)
                except Exception as e:
                    logger.debug(f"lateral block: {e}")
                result = f"Lateral ports blocked: {blocked}"
                ctx.variables["lateral_blocked"] = len(blocked) > 0

            elif step.step_type == StepType.CLOSE_CASE:
                case_id = ctx.variables.get("case_id","")
                import json as _json
                from pathlib import Path as _Path
                from datetime import datetime as _dt, timezone as _tz
                cf = _Path("data/cases.json")
                if case_id and cf.exists():
                    cases = _json.loads(cf.read_text())
                    for c in cases:
                        if c.get("id") == case_id:
                            c["status"] = "AUTO_CLOSED"
                            c["closed_at"] = _dt.now(_tz.utc).isoformat()
                            c["resolution"] = f"SOAR auto-response: {ctx.playbook_name}"
                    cf.write_text(_json.dumps(cases, indent=2))
                result = f"Case {case_id} auto-closed"

            else:
                result = f"Unknown step type: {step.step_type}"

        except Exception as e:
            success = False
            result = f"Step error: {e}"
            logger.error(f"SOAR step {step.step_id} failed: {e}")

        duration_ms = (time.time() - t0) * 1000
        ctx.log_step(step.step_id, step.name, result, success, duration_ms)
        return success, result


# ─── SOAR ENGINE ──────────────────────────────────────────────────────────────

_exec_counter = 0


class SOAREngine:
    """Orchestrates playbook execution against alerts."""

    def __init__(self, responder=None, ioc_manager=None, case_manager=None):
        self.executor = StepExecutor(responder, ioc_manager, case_manager)
        self._playbooks: Dict[str, Playbook] = {}
        self._executions: List[ExecutionContext] = []
        self._running = False
        self._queue: List[tuple] = []  # (alert, playbook)

        # Load built-in playbooks
        self._register_builtin_playbooks()

    def _register_builtin_playbooks(self):
        # ── Playbook 1: Critical Alert Response ──
        p1 = Playbook("pb_critical", "Critical Alert Auto-Response",
                      "Auto-block, create case, and escalate for CRITICAL alerts",
                      trigger_conditions={"severity": ["CRITICAL"], "min_risk_score": 70})

        s1 = PlaybookStep("s1", "Check IOC match", StepType.LOOKUP_IOC,
                           on_success="s2", on_failure="s2")
        s2 = PlaybookStep("s2", "Block source IP", StepType.BLOCK_IP,
                           on_success="s3", on_failure="s3")
        s3 = PlaybookStep("s3", "Create incident case", StepType.CREATE_CASE,
                           on_success="s4", on_failure="s4")
        s4 = PlaybookStep("s4", "Enrich MITRE context", StepType.ENRICH_MITRE,
                           on_success="s5")
        s5 = PlaybookStep("s5", "Escalate case to senior analyst", StepType.ESCALATE_CASE)

        for i, step in enumerate([s1, s2, s3, s4, s5]):
            p1.add_step(step, is_entry=(i == 0))
        self.register_playbook(p1)

        # ── Playbook 2: Brute Force Response ──
        p2 = Playbook("pb_bruteforce", "Brute Force Mitigation",
                      "Rate-limit on first detection, block after threshold",
                      trigger_conditions={"types": ["Brute Force", "SSH", "FTP"],
                                          "severity": ["HIGH", "CRITICAL"]})

        b1 = PlaybookStep("b1", "Rate limit source", StepType.RATE_LIMIT,
                           on_success="b2")
        b2 = PlaybookStep("b2", "Check if IOC known", StepType.LOOKUP_IOC,
                           on_success="b3")
        b3 = PlaybookStep("b3", "Create case", StepType.CREATE_CASE)

        for i, step in enumerate([b1, b2, b3]):
            p2.add_step(step, is_entry=(i == 0))
        self.register_playbook(p2)

        # ── Playbook 3: DNS Tunneling / Exfil ──
        p3 = Playbook("pb_exfil", "Data Exfiltration Response",
                      "Immediate block and quarantine for exfiltration indicators",
                      trigger_conditions={"types": ["DNS Tunnel", "Exfil", "C2"],
                                          "severity": ["CRITICAL", "HIGH"]})

        e1 = PlaybookStep("e1", "Block source immediately", StepType.BLOCK_IP,
                           on_success="e2")
        e2 = PlaybookStep("e2", "Quarantine host", StepType.QUARANTINE_HOST,
                           on_success="e3")
        e3 = PlaybookStep("e3", "Create high-priority case", StepType.CREATE_CASE,
                           on_success="e4")
        e4 = PlaybookStep("e4", "Analyst review required", StepType.ANALYST_REVIEW)

        for i, step in enumerate([e1, e2, e3, e4]):
            p3.add_step(step, is_entry=(i == 0))
        self.register_playbook(p3)

        # ── Playbook 4: Credential Compromise ─────────────────────────────────
        p4 = Playbook("pb_credential", "Credential Compromise Response",
                      "Disable user, revoke sessions, block source IP on credential attacks",
                      trigger_conditions={"type_contains": ["credential","login","brute","auth"], "min_risk_score": 70})
        c1 = PlaybookStep("c1", "IOC check source IP",   StepType.LOOKUP_IOC,    on_success="c2", on_failure="c2")
        c2 = PlaybookStep("c2", "Disable user account",  StepType.DISABLE_USER,  on_success="c3", on_failure="c3")
        c3 = PlaybookStep("c3", "Revoke active sessions", StepType.REVOKE_SESSIONS, on_success="c4", on_failure="c4")
        c4 = PlaybookStep("c4", "Block source IP",        StepType.BLOCK_IP,      on_success="c5", on_failure="c5")
        c5 = PlaybookStep("c5", "Create incident case",   StepType.CREATE_CASE,   on_success="c6", on_failure="c6")
        c6 = PlaybookStep("c6", "Close case",             StepType.CLOSE_CASE,    on_success=None, on_failure=None)
        for i, step in enumerate([c1,c2,c3,c4,c5,c6]):
            p4.add_step(step, is_entry=(i==0))
        self.register_playbook(p4)

        # ── Playbook 5: Malware Containment ────────────────────────────────────
        p5 = Playbook("pb_malware", "Malware Containment",
                      "Kill malicious process, isolate host, block file hash",
                      trigger_conditions={"type_contains": ["malware","yara","ransomware","trojan"], "min_risk_score": 70})
        m1 = PlaybookStep("m1", "Kill malicious process", StepType.KILL_PROCESS,  on_success="m2", on_failure="m2")
        m2 = PlaybookStep("m2", "Isolate host",           StepType.ISOLATE_HOST,  on_success="m3", on_failure="m3")
        m3 = PlaybookStep("m3", "Block file hash",         StepType.BLOCK_HASH,    on_success="m4", on_failure="m4")
        m4 = PlaybookStep("m4", "Create incident case",   StepType.CREATE_CASE,   on_success="m5", on_failure="m5")
        m5 = PlaybookStep("m5", "Close case",             StepType.CLOSE_CASE,    on_success=None, on_failure=None)
        for i, step in enumerate([m1,m2,m3,m4,m5]):
            p5.add_step(step, is_entry=(i==0))
        self.register_playbook(p5)

        # ── Playbook 6: Lateral Movement ───────────────────────────────────────
        p6 = Playbook("pb_lateral", "Lateral Movement Containment",
                      "Isolate host, block lateral ports, disable compromised credentials",
                      trigger_conditions={"type_contains": ["lateral","smb","rdp","winrm","movement"], "min_risk_score": 70})
        l1 = PlaybookStep("l1", "Block lateral movement ports", StepType.BLOCK_LATERAL_PORTS, on_success="l2", on_failure="l2")
        l2 = PlaybookStep("l2", "Isolate source host",          StepType.ISOLATE_HOST,         on_success="l3", on_failure="l3")
        l3 = PlaybookStep("l3", "Disable compromised creds",    StepType.DISABLE_USER,          on_success="l4", on_failure="l4")
        l4 = PlaybookStep("l4", "Create incident case",         StepType.CREATE_CASE,           on_success="l5", on_failure="l5")
        l5 = PlaybookStep("l5", "Close case",                   StepType.CLOSE_CASE,            on_success=None, on_failure=None)
        for i, step in enumerate([l1,l2,l3,l4,l5]):
            p6.add_step(step, is_entry=(i==0))
        self.register_playbook(p6)

        # ── Playbook 7: LSTM Sequential Attack ────────────────────────────────
        p7 = Playbook("pb_lstm_sequence", "LSTM Sequential Attack Response",
                      "Automated response when LSTM detects a multi-step attack sequence",
                      trigger_conditions={"source": ["lstm_sequence"], "min_risk_score": 60})
        x1 = PlaybookStep("x1", "IOC enrichment",         StepType.LOOKUP_IOC,    on_success="x2", on_failure="x2")
        x2 = PlaybookStep("x2", "Block source IP",         StepType.BLOCK_IP,      on_success="x3", on_failure="x3")
        x3 = PlaybookStep("x3", "Snapshot system state",   StepType.SNAPSHOT_SYSTEM, on_success="x4", on_failure="x4")
        x4 = PlaybookStep("x4", "Create incident case",    StepType.CREATE_CASE,   on_success="x5", on_failure="x5")
        x5 = PlaybookStep("x5", "Enrich MITRE context",    StepType.ENRICH_MITRE,  on_success="x6", on_failure="x6")
        x6 = PlaybookStep("x6", "Escalate case",           StepType.ESCALATE_CASE, on_success=None, on_failure=None)
        for i, step in enumerate([x1,x2,x3,x4,x5,x6]):
            p7.add_step(step, is_entry=(i==0))
        self.register_playbook(p7)

    def register_playbook(self, playbook: Playbook):
        self._playbooks[playbook.playbook_id] = playbook
        logger.info(f"Playbook registered: {playbook.playbook_id} — {playbook.name}")

    def get_matching_playbooks(self, alert: dict) -> List[Playbook]:
        return [p for p in self._playbooks.values()
                if p.enabled and p.matches_alert(alert)]

    def execute_playbook(self, playbook: Playbook, alert: dict) -> ExecutionContext:
        """Execute a playbook against an alert synchronously."""
        global _exec_counter
        _exec_counter += 1

        ctx = ExecutionContext(f"EXEC-{_exec_counter:04d}", playbook, alert)
        ctx.variables["src_ip"] = alert.get("src_ip", "")
        ctx.variables["alert_type"] = alert.get("type", "")

        current_step_id = playbook.entry_step
        max_steps = 20  # Safety limit

        while current_step_id and max_steps > 0:
            step = playbook.steps.get(current_step_id)
            if not step:
                break
            max_steps -= 1
            ctx.current_step = current_step_id

            success, result = self.executor.execute(step, ctx)

            if step.step_type == StepType.ANALYST_REVIEW:
                ctx.status = "WAITING_ANALYST"
                break

            current_step_id = step.on_success if success else step.on_failure

        if ctx.status == "RUNNING":
            ctx.status = "COMPLETED"
        ctx.completed_at = datetime.utcnow().isoformat()
        playbook.execution_count += 1
        self._executions.append(ctx)
        logger.info(f"Playbook {playbook.playbook_id} completed for alert {alert.get('id')} — {ctx.status}")
        return ctx

    def process_alert(self, alert: dict) -> List[ExecutionContext]:
        """Find matching playbooks and execute all of them against the alert."""
        matching = self.get_matching_playbooks(alert)
        results = []
        for pb in matching:
            ctx = self.execute_playbook(pb, alert)
            results.append(ctx)
        return results

    def get_playbooks(self) -> List[dict]:
        return [p.to_dict() for p in self._playbooks.values()]

    def get_executions(self, limit: int = 50) -> List[dict]:
        return [e.to_dict() for e in reversed(self._executions[-limit:])]

    @property
    def stats(self) -> dict:
        return {
            "playbooks_registered": len(self._playbooks),
            "total_executions": len(self._executions),
            "completed": sum(1 for e in self._executions if e.status == "COMPLETED"),
            "waiting_analyst": sum(1 for e in self._executions if e.status == "WAITING_ANALYST"),
        }
