"""
AID-ARS SOAR — Playbook Engine
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

logger = logging.getLogger("aidars.soar")

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
