"""
CyberRemedy Sigma Engine — Sigma 2.0 Rule Parser & Executor
Parses Sigma YAML rules and evaluates them against log events.
Supports: YAML loading, field mapping, condition evaluation, alert generation.
"""

import re
import json
import logging
import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger("cyberremedy.sigma")

SIGMA_RULES_DIR = Path("data/sigma_rules")
SIGMA_RESULTS_PATH = Path("data/sigma_alerts.json")

# ─── FIELD MAPPING ────────────────────────────────────────────────────────────

# Maps Sigma field names to CyberRemedy event field names
FIELD_MAP = {
    "src_ip": ["src_ip", "source_ip", "SourceIp"],
    "dst_ip": ["dst_ip", "dest_ip", "DestinationIp"],
    "dst_port": ["dst_port", "destination_port", "DestinationPort"],
    "src_port": ["src_port", "source_port", "SourcePort"],
    "protocol": ["protocol", "Protocol"],
    "user": ["user", "username", "User", "UserName"],
    "process": ["process", "ProcessName", "Image"],
    "cmdline": ["cmdline", "CommandLine"],
    "event_type": ["type", "event_type", "EventID"],
    "hostname": ["hostname", "ComputerName", "agent_id"],
    "file_path": ["path", "file_path", "TargetFilename"],
    "bytes": ["bytes", "total_bytes", "BytesSent"],
}


def resolve_field(event: dict, sigma_field: str) -> Optional[Any]:
    """Get event field value using Sigma field name with fallback mapping."""
    # Direct match first
    if sigma_field in event:
        return event[sigma_field]
    # Try mapped alternatives
    for alias in FIELD_MAP.get(sigma_field, []):
        if alias in event:
            return event[alias]
    return None


# ─── CONDITION EVALUATOR ──────────────────────────────────────────────────────

class SigmaConditionEvaluator:
    """Evaluates Sigma detection conditions against an event."""

    def evaluate_value(self, field_val: Any, expected: Any) -> bool:
        if field_val is None:
            return False
        fv = str(field_val)
        ev = str(expected)

        # Wildcard matching
        if "*" in ev or "?" in ev:
            return fnmatch.fnmatch(fv.lower(), ev.lower())

        # Exact match (case-insensitive)
        return fv.lower() == ev.lower()

    def evaluate_field_group(self, event: dict, conditions: dict) -> bool:
        """Check if all field conditions in a group match the event."""
        for field, expected in conditions.items():
            field_val = resolve_field(event, field)

            if isinstance(expected, list):
                # OR: any value in list can match
                if not any(self.evaluate_value(field_val, v) for v in expected):
                    return False
            elif isinstance(expected, dict):
                # Modifier: contains|startswith|endswith|re
                if "contains" in expected:
                    vals = expected["contains"] if isinstance(expected["contains"], list) else [expected["contains"]]
                    if not any(v.lower() in str(field_val).lower() for v in vals):
                        return False
                elif "startswith" in expected:
                    vals = expected["startswith"] if isinstance(expected["startswith"], list) else [expected["startswith"]]
                    if not any(str(field_val).lower().startswith(v.lower()) for v in vals):
                        return False
                elif "endswith" in expected:
                    vals = expected["endswith"] if isinstance(expected["endswith"], list) else [expected["endswith"]]
                    if not any(str(field_val).lower().endswith(v.lower()) for v in vals):
                        return False
                elif "re" in expected:
                    pattern = expected["re"]
                    if not re.search(pattern, str(field_val), re.IGNORECASE):
                        return False
            else:
                if not self.evaluate_value(field_val, expected):
                    return False
        return True

    def evaluate_selection(self, event: dict, detection: dict, selection_name: str) -> bool:
        """Evaluate a named selection from the detection block."""
        selection = detection.get(selection_name)
        if selection is None:
            return False

        if isinstance(selection, list):
            # List of groups (OR between groups)
            return any(self.evaluate_field_group(event, group) for group in selection
                       if isinstance(group, dict))
        elif isinstance(selection, dict):
            return self.evaluate_field_group(event, selection)
        return False

    def evaluate_condition(self, event: dict, detection: dict, condition_str: str) -> bool:
        """Parse and evaluate a Sigma condition expression."""
        condition = condition_str.strip()

        # Simple: "selection" or "keywords"
        if condition in detection:
            return self.evaluate_selection(event, detection, condition)

        # NOT
        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self.evaluate_condition(event, detection, inner)

        # AND
        if " and " in condition:
            parts = [p.strip() for p in condition.split(" and ")]
            return all(self.evaluate_condition(event, detection, p) for p in parts)

        # OR
        if " or " in condition:
            parts = [p.strip() for p in condition.split(" or ")]
            return any(self.evaluate_condition(event, detection, p) for p in parts)

        # Parentheses
        if condition.startswith("(") and condition.endswith(")"):
            return self.evaluate_condition(event, detection, condition[1:-1])

        # "1 of selection*" / "all of them"
        if condition.startswith("1 of ") or condition.startswith("all of "):
            prefix = condition.split("of ")[1].strip()
            pattern = prefix.replace("*", ".*")
            matching_keys = [k for k in detection.keys() if re.match(pattern, k)]
            if condition.startswith("1 of "):
                return any(self.evaluate_selection(event, detection, k) for k in matching_keys)
            else:
                return all(self.evaluate_selection(event, detection, k) for k in matching_keys)

        # Direct key reference
        if condition in detection:
            return self.evaluate_selection(event, detection, condition)

        return False


# ─── SIGMA RULE ───────────────────────────────────────────────────────────────

class SigmaRule:
    def __init__(self, rule_dict: dict, source_file: str = ""):
        self.title = rule_dict.get("title", "Unknown")
        self.id = rule_dict.get("id", "")
        self.status = rule_dict.get("status", "experimental")
        self.description = rule_dict.get("description", "")
        self.author = rule_dict.get("author", "")
        self.date = rule_dict.get("date", "")
        self.tags = rule_dict.get("tags", [])
        self.logsource = rule_dict.get("logsource", {})
        self.detection = rule_dict.get("detection", {})
        self.condition = self.detection.get("condition", "selection")
        self.falsepositives = rule_dict.get("falsepositives", [])
        self.level = rule_dict.get("level", "medium")    # informational|low|medium|high|critical
        self.source_file = source_file

        # Extract MITRE ATT&CK tag
        self.mitre_id = ""
        for tag in self.tags:
            if tag.startswith("attack.t"):
                self.mitre_id = tag.replace("attack.", "").upper()
                break

    @property

    def severity(self) -> str:
        return {"informational": "LOW", "low": "LOW", "medium": "MEDIUM",
                "high": "HIGH", "critical": "CRITICAL"}.get(self.level, "MEDIUM")

    def to_dict(self) -> dict:
        return {
            "title": self.title, "id": self.id, "status": self.status,
            "description": self.description, "level": self.level,
            "severity": self.severity, "mitre_id": self.mitre_id,
            "tags": self.tags, "source_file": self.source_file,
        }


# ─── BUILT-IN SIGMA RULES ─────────────────────────────────────────────────────

BUILTIN_SIGMA_RULES = [
    {
        "title": "High Auth Failure Rate",
        "id": "cyberremedy-001",
        "status": "stable",
        "description": "Detects high rate of authentication failures indicating brute force",
        "tags": ["attack.t1110", "attack.credential_access"],
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {"type": ["AUTH_FAIL", "SSH_INVALID_USER"]},
            "condition": "selection",
        },
        "level": "high",
    },
    {
        "title": "Suspicious Process Spawned from Web Server",
        "id": "cyberremedy-002",
        "status": "stable",
        "description": "Detects shell or interpreter spawned from web/db server process",
        "tags": ["attack.t1059", "attack.execution"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"type": ["PROC_SUSPICIOUS_SPAWN"]},
            "condition": "selection",
        },
        "level": "critical",
    },
    {
        "title": "File Integrity Violation on Critical Path",
        "id": "cyberremedy-003",
        "status": "stable",
        "description": "Detects modification or deletion of critical system files",
        "tags": ["attack.t1565", "attack.impact"],
        "logsource": {"category": "file_event"},
        "detection": {
            "selection": {"type": ["FIM_MODIFIED", "FIM_DELETED"]},
            "condition": "selection",
        },
        "level": "critical",
    },
    {
        "title": "Port Scan from Single Source",
        "id": "cyberremedy-004",
        "status": "stable",
        "description": "High number of unique destination ports from single source",
        "tags": ["attack.t1046", "attack.discovery"],
        "logsource": {"category": "network"},
        "detection": {
            "selection": {"type": ["Port Scan (SYN)", "Port Scan (FIN/NULL)"]},
            "condition": "selection",
        },
        "level": "medium",
    },
    {
        "title": "DNS Tunneling Detected",
        "id": "cyberremedy-005",
        "status": "stable",
        "description": "High entropy DNS queries indicative of data tunneling",
        "tags": ["attack.t1048", "attack.exfiltration"],
        "logsource": {"category": "network"},
        "detection": {
            "selection": {"type": ["DNS Tunneling"]},
            "condition": "selection",
        },
        "level": "critical",
    },
]


# ─── SIGMA ENGINE ─────────────────────────────────────────────────────────────

_sigma_alert_id = 9000


class SigmaEngine:
    """Loads Sigma rules and evaluates them against events."""

    def __init__(self, rules_dir: Path = SIGMA_RULES_DIR):
        self.rules_dir = rules_dir
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._rules: List[SigmaRule] = []
        self._evaluator = SigmaConditionEvaluator()
        self._alerts: List[dict] = []
        self._events_checked = 0
        self._load_builtin()
        self._load_from_dir()

    def _load_builtin(self):
        for rule_dict in BUILTIN_SIGMA_RULES:
            self._rules.append(SigmaRule(rule_dict, source_file="builtin"))
        logger.info(f"Sigma: {len(BUILTIN_SIGMA_RULES)} built-in rules loaded")

    def _load_from_dir(self):
        if not YAML_AVAILABLE:
            return
        count = 0
        for yf in self.rules_dir.glob("*.yml"):
            try:
                with open(yf) as f:
                    rule_dict = yaml.safe_load(f)
                if isinstance(rule_dict, dict) and "detection" in rule_dict:
                    self._rules.append(SigmaRule(rule_dict, source_file=str(yf)))
                    count += 1
            except Exception as e:
                logger.debug(f"Sigma rule load error ({yf}): {e}")
        if count:
            logger.info(f"Sigma: {count} rules loaded from {self.rules_dir}")

    def load_rule_text(self, yaml_text: str) -> Optional[SigmaRule]:
        """Load a single Sigma rule from YAML text."""
        if not YAML_AVAILABLE:
            logger.warning("PyYAML not installed — cannot load custom Sigma rules")
            return None
        try:
            rule_dict = yaml.safe_load(yaml_text)
            rule = SigmaRule(rule_dict, source_file="custom")
            self._rules.append(rule)
            return rule
        except Exception as e:
            logger.error(f"Sigma rule parse error: {e}")
            return None

    def evaluate(self, event: dict) -> List[dict]:
        """Run all enabled Sigma rules against a single event."""
        global _sigma_alert_id
        self._events_checked += 1
        alerts = []

        for rule in self._rules:
            try:
                match = self._evaluator.evaluate_condition(event, rule.detection, rule.condition)
                if match:
                    _sigma_alert_id += 1
                    alert = {
                        "id": _sigma_alert_id,
                        "timestamp": datetime.utcnow().isoformat(),
                        "type": f"[Sigma] {rule.title}",
                        "severity": rule.severity,
                        "src_ip": event.get("src_ip", "?"),
                        "dst_ip": event.get("dst_ip", "?"),
                        "src_port": event.get("src_port", 0),
                        "dst_port": event.get("dst_port", 0),
                        "protocol": event.get("protocol", "?"),
                        "mitre_id": rule.mitre_id or "T1059",
                        "confidence": 80,
                        "detail": f"Sigma rule matched: {rule.title} — {rule.description}",
                        "status": "OPEN",
                        "source": "sigma",
                        "sigma_rule_id": rule.id,
                        "risk_score": 0,
                        "correlated": False,
                    }
                    self._alerts.append(alert)
                    alerts.append(alert)
            except Exception as e:
                logger.debug(f"Sigma eval error for rule {rule.title}: {e}")

        return alerts

    def get_rules(self) -> List[dict]:
        return [r.to_dict() for r in self._rules]

    def get_alerts(self, limit: int = 100) -> List[dict]:
        return list(reversed(self._alerts[-limit:]))

    @property
    def stats(self) -> dict:
        return {
            "rules_loaded": len(self._rules),
            "events_checked": self._events_checked,
            "total_alerts": len(self._alerts),
        }


    def _load_builtin_rules(self):
        """Load built-in sigma rules from data/sigma_rules/builtin_rules.yml"""
        import yaml as _yaml
        from pathlib import Path as _Path
        builtin = _Path(__file__).parent.parent / "data" / "sigma_rules" / "builtin_rules.yml"
        if not builtin.exists():
            return
        try:
            with open(builtin) as f:
                data = _yaml.safe_load(f) or {}
            for rule in data.get("rules", []):
                self._rules[rule["id"]] = {
                    "id": rule["id"],
                    "name": rule["title"],
                    "title": rule["title"],
                    "severity": rule.get("severity", "MEDIUM"),
                    "mitre_id": rule.get("mitre_id", ""),
                    "category": rule.get("category", "network"),
                    "description": rule.get("description", ""),
                    "source": "builtin",
                    "hits": 0,
                }
            logger.info(f"Sigma: loaded {len(data.get('rules',[]))} built-in rules")
        except Exception as e:
            logger.warning(f"Sigma builtin load error: {e}")
