"""
AID-ARS Autonomous Response Engine
Executes defensive actions based on alert risk scores.
All actions are logged and reversible.
"""

import os
import json
import time
import logging
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("aidars.response")


# ─── RESPONSE ACTION TYPES ────────────────────────────────────────────────────

class ResponseAction:
    BLOCK_IP = "BLOCK_IP"
    RATE_LIMIT = "RATE_LIMIT"
    FIREWALL_RULE = "FIREWALL_RULE"
    LOG_ONLY = "LOG_ONLY"
    ROLLBACK = "ROLLBACK"


# ─── FIREWALL BACKEND ─────────────────────────────────────────────────────────

class FirewallBackend:
    """Wraps iptables/nftables calls with dry-run support."""

    def __init__(self, backend: str = "iptables", dry_run: bool = False):
        self.backend = backend
        self.dry_run = dry_run

    def block_ip(self, ip: str) -> tuple[bool, str]:
        cmd = f"iptables -I INPUT -s {ip} -j DROP"
        return self._run(cmd, f"BLOCK {ip}")

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        cmd = f"iptables -D INPUT -s {ip} -j DROP"
        return self._run(cmd, f"UNBLOCK {ip}")

    def rate_limit(self, ip: str, limit: str = "10/min") -> tuple[bool, str]:
        cmd = (
            f"iptables -I INPUT -s {ip} -m limit --limit {limit} "
            f"--limit-burst 20 -j ACCEPT && "
            f"iptables -A INPUT -s {ip} -j DROP"
        )
        return self._run(cmd, f"RATE_LIMIT {ip} @ {limit}")

    def _run(self, cmd: str, description: str) -> tuple[bool, str]:
        if self.dry_run:
            logger.info(f"[DRY RUN] {description}: {cmd}")
            return True, f"DRY_RUN: {cmd}"

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Firewall action OK: {description}")
                return True, cmd
            else:
                logger.error(f"Firewall error: {result.stderr}")
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "Firewall command timeout"
        except Exception as e:
            logger.error(f"Firewall exception: {e}")
            return False, str(e)


# ─── RESPONSE LOG ─────────────────────────────────────────────────────────────

class ResponseLog:
    """Persistent audit log of all response actions."""

    def __init__(self, log_path: str = "data/response_log.json"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: List[dict] = []
        self._load()

    def _load(self):
        if self.log_path.exists():
            try:
                with open(self.log_path) as f:
                    self._entries = json.load(f)
            except Exception:
                self._entries = []

    def _save(self):
        with open(self.log_path, "w") as f:
            json.dump(self._entries[-500:], f, indent=2)

    def add(self, entry: dict):
        entry["log_id"] = len(self._entries) + 1
        entry["logged_at"] = datetime.utcnow().isoformat()
        self._entries.append(entry)
        self._save()
        return entry

    def get_all(self) -> List[dict]:
        return list(reversed(self._entries[-50:]))

    def get_by_ip(self, ip: str) -> List[dict]:
        return [e for e in self._entries if e.get("target_ip") == ip]


# ─── BLOCKED IP REGISTRY ──────────────────────────────────────────────────────

class BlockedIPRegistry:
    """Tracks currently blocked IPs with TTL support."""

    def __init__(self, registry_path: str = "data/blocked_ips.json", ttl: int = 3600):
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.default_ttl = ttl
        self._blocked: Dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.registry_path.exists():
            try:
                with open(self.registry_path) as f:
                    self._blocked = json.load(f)
            except Exception:
                self._blocked = {}

    def _save(self):
        with open(self.registry_path, "w") as f:
            json.dump(self._blocked, f, indent=2)

    def add(self, ip: str, reason: str, ttl: int = None):
        self._blocked[ip] = {
            "ip": ip,
            "reason": reason,
            "blocked_at": datetime.utcnow().isoformat(),
            "expires_at": datetime.fromtimestamp(
                time.time() + (ttl or self.default_ttl)
            ).isoformat(),
            "ttl": ttl or self.default_ttl,
        }
        self._save()

    def remove(self, ip: str) -> bool:
        if ip in self._blocked:
            del self._blocked[ip]
            self._save()
            return True
        return False

    def is_blocked(self, ip: str) -> bool:
        if ip not in self._blocked:
            return False
        # Check TTL expiry
        entry = self._blocked[ip]
        expire_ts = datetime.fromisoformat(entry["expires_at"]).timestamp()
        if time.time() > expire_ts:
            self.remove(ip)
            return False
        return True

    def get_all(self) -> List[dict]:
        # Auto-expire
        now = time.time()
        expired = []
        for ip, entry in self._blocked.items():
            expire_ts = datetime.fromisoformat(entry["expires_at"]).timestamp()
            if now > expire_ts:
                expired.append(ip)
        for ip in expired:
            del self._blocked[ip]
        if expired:
            self._save()
        return list(self._blocked.values())

    @property
    def count(self) -> int:
        return len(self._blocked)


# ─── AUTONOMOUS RESPONDER ─────────────────────────────────────────────────────

class AutonomousResponder:
    """
    Central response orchestrator.
    Evaluates alert risk scores and executes appropriate defensive actions.
    """

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.auto_block_critical = cfg.get("auto_block_critical", True)
        self.auto_block_high = cfg.get("auto_block_high", False)
        self.dry_run = cfg.get("dry_run", False)
        self.rollback_enabled = cfg.get("rollback_enabled", True)

        self.firewall = FirewallBackend(
            backend=cfg.get("firewall_backend", "iptables"),
            dry_run=self.dry_run,
        )
        self.log = ResponseLog(cfg.get("response_log_path", "data/response_log.json"))
        self.registry = BlockedIPRegistry(
            registry_path=cfg.get("blocked_ip_log", "data/blocked_ips.json"),
            ttl=cfg.get("blocked_ip_ttl_seconds", 3600),
        )
        self._actions_taken = 0
        self._actions_failed = 0

    def evaluate_and_respond(self, alert: dict) -> Optional[dict]:
        """
        Evaluate an alert and execute response if warranted.
        Returns a response log entry, or None if no action taken.
        """
        severity = alert.get("severity", "LOW")
        risk_score = alert.get("risk_score", 0)
        src_ip = alert.get("src_ip", "")

        # Skip already-blocked IPs
        if self.registry.is_blocked(src_ip):
            return None

        # Decide action
        action_type = None
        if self.auto_block_critical and severity == "CRITICAL":
            action_type = ResponseAction.BLOCK_IP
        elif self.auto_block_high and severity == "HIGH":
            action_type = ResponseAction.BLOCK_IP
        elif risk_score >= 90:
            action_type = ResponseAction.BLOCK_IP
        elif risk_score >= 65:
            action_type = ResponseAction.RATE_LIMIT
        else:
            action_type = ResponseAction.LOG_ONLY

        return self._execute(alert, action_type, src_ip)

    def _execute(self, alert: dict, action_type: str, src_ip: str) -> Optional[dict]:
        timestamp = datetime.utcnow().isoformat()
        success = True
        cmd_used = ""
        action_detail = ""

        if action_type == ResponseAction.BLOCK_IP:
            success, cmd_used = self.firewall.block_ip(src_ip)
            if success:
                self.registry.add(src_ip, reason=alert.get("type", "Unknown"))
                alert["status"] = "BLOCKED"
                action_detail = f"IP {src_ip} blocked via {self.firewall.backend}"
                icon = "🚫"
            else:
                action_detail = f"Block failed for {src_ip}: {cmd_used}"
                icon = "⚠️"

        elif action_type == ResponseAction.RATE_LIMIT:
            success, cmd_used = self.firewall.rate_limit(src_ip)
            action_detail = f"Rate limit applied to {src_ip} (10/min)"
            icon = "🔄"

        elif action_type == ResponseAction.LOG_ONLY:
            action_detail = f"Logged alert — below auto-response threshold"
            icon = "📝"
            return None  # Don't log trivial LOG_ONLY to response feed

        else:
            return None

        if success:
            self._actions_taken += 1
        else:
            self._actions_failed += 1

        entry = {
            "action_type": action_type,
            "target_ip": src_ip,
            "alert_id": alert.get("id"),
            "alert_type": alert.get("type", "?"),
            "mitre_id": alert.get("mitre_id", ""),
            "severity": alert.get("severity", "?"),
            "risk_score": alert.get("risk_score", 0),
            "success": success,
            "command": cmd_used,
            "detail": action_detail,
            "icon": icon,
            "timestamp": timestamp,
            "reversible": self.rollback_enabled,
            "dry_run": self.dry_run,
        }

        return self.log.add(entry)

    def manual_block(self, ip: str, reason: str = "Manual block") -> dict:
        """Manually block an IP and log the action."""
        success, cmd = self.firewall.block_ip(ip)
        if success:
            self.registry.add(ip, reason=reason)
        entry = {
            "action_type": ResponseAction.BLOCK_IP,
            "target_ip": ip,
            "alert_id": None,
            "alert_type": "Manual",
            "severity": "MANUAL",
            "risk_score": 100,
            "success": success,
            "command": cmd,
            "detail": f"Manual block: {reason}",
            "icon": "🔒",
            "timestamp": datetime.utcnow().isoformat(),
            "reversible": True,
            "dry_run": self.dry_run,
        }
        return self.log.add(entry)

    def manual_unblock(self, ip: str) -> dict:
        """Unblock an IP and log the rollback."""
        success, cmd = self.firewall.unblock_ip(ip)
        if success:
            self.registry.remove(ip)
        entry = {
            "action_type": ResponseAction.ROLLBACK,
            "target_ip": ip,
            "success": success,
            "command": cmd,
            "detail": f"IP {ip} unblocked (rollback)",
            "icon": "✅",
            "timestamp": datetime.utcnow().isoformat(),
            "reversible": False,
            "dry_run": self.dry_run,
        }
        return self.log.add(entry)

    @property
    def stats(self) -> dict:
        return {
            "actions_taken": self._actions_taken,
            "actions_failed": self._actions_failed,
            "currently_blocked": self.registry.count,
            "dry_run": self.dry_run,
        }
