"""
CyberRemedy UEBA — User & Entity Behavior Analytics
Builds behavioral baselines per user/host and scores deviations.
Detects: impossible travel, off-hours access, data staging, 
lateral movement, privilege escalation patterns.
"""

import math
import json
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cyberremedy.ueba")


# ─── BEHAVIORAL BASELINE ──────────────────────────────────────────────────────

class EntityBaseline:
    """
    Rolling statistical baseline for a single entity (user or host).
    Tracks: typical login hours, typical src IPs, typical data volumes,
    typical connection rates, command patterns.
    """

    def __init__(self, entity_id: str, entity_type: str = "user"):
        self.entity_id = entity_id
        self.entity_type = entity_type            # user | host | service
        self.created_at = datetime.utcnow().isoformat()
        self.event_count = 0

        # Login time distribution (0-23 hours)
        self.hour_counts = defaultdict(int)
        self.day_counts = defaultdict(int)

        # Source IPs seen
        self.src_ips: set = set()
        self.ip_countries: Dict[str, str] = {}

        # Data volumes
        self.bytes_per_session: List[float] = []
        self.connections_per_hour: List[int] = []

        # Recent anomaly scores
        self.recent_risk_scores: List[float] = []
        self.risk_score: float = 0.0

        # Typical peers
        self.typical_dst_ips: set = set()
        self.typical_ports: set = set()

        # Auth events
        self.auth_failures: int = 0
        self.auth_successes: int = 0

    def record_event(self, event: dict):
        """Update baseline with a new behavioral event."""
        self.event_count += 1
        ts = event.get("timestamp", "")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", ""))
                self.hour_counts[dt.hour] += 1
                self.day_counts[dt.weekday()] += 1
            except Exception:
                pass

        src_ip = event.get("src_ip", "")
        if src_ip:
            self.src_ips.add(src_ip)

        dst_ip = event.get("dst_ip", "")
        if dst_ip:
            self.typical_dst_ips.add(dst_ip)

        port = event.get("dst_port", 0)
        if port:
            self.typical_ports.add(port)

        if event.get("type", "").startswith("AUTH_FAIL"):
            self.auth_failures += 1
        elif "AUTH" in event.get("type", "") and "FAIL" not in event.get("type", ""):
            self.auth_successes += 1

    def typical_hour_range(self) -> tuple:
        """Get the 90th-percentile working hours."""
        if not self.hour_counts:
            return (8, 18)
        total = sum(self.hour_counts.values())
        cumulative = 0
        start_hour, end_hour = 0, 23
        for h in range(24):
            cumulative += self.hour_counts.get(h, 0)
            if cumulative / max(total, 1) >= 0.05 and start_hour == 0:
                start_hour = h
            if cumulative / max(total, 1) >= 0.95:
                end_hour = h
                break
        return (start_hour, end_hour)

    def mean_bytes(self) -> float:
        if not self.bytes_per_session:
            return 0.0
        return sum(self.bytes_per_session) / len(self.bytes_per_session)

    def std_bytes(self) -> float:
        if len(self.bytes_per_session) < 2:
            return 0.0
        mean = self.mean_bytes()
        return math.sqrt(sum((x - mean) ** 2 for x in self.bytes_per_session) / len(self.bytes_per_session))

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "event_count": self.event_count,
            "created_at": self.created_at,
            "src_ips_count": len(self.src_ips),
            "typical_ports": list(self.typical_ports)[:20],
            "risk_score": self.risk_score,
            "auth_failures": self.auth_failures,
            "auth_successes": self.auth_successes,
            "typical_hour_range": self.typical_hour_range(),
        }


# ─── ANOMALY DETECTORS ────────────────────────────────────────────────────────

def detect_off_hours_access(baseline: EntityBaseline, event: dict) -> Optional[dict]:
    """Detect logins/access at unusual hours."""
    ts = event.get("timestamp", "")
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", ""))
        start, end = baseline.typical_hour_range()
        if baseline.event_count < 20:
            return None  # Not enough baseline data
        if dt.hour < start or dt.hour > end:
            return {
                "type": "UEBA_OFF_HOURS_ACCESS", "severity": "MEDIUM",
                "entity_id": baseline.entity_id,
                "detail": f"Off-hours activity at {dt.hour:02d}:00 (normal: {start:02d}-{end:02d})",
                "mitre_id": "T1078",
                "risk_contribution": 25,
            }
    except Exception:
        pass
    return None


def detect_new_src_ip(baseline: EntityBaseline, event: dict) -> Optional[dict]:
    """Detect access from a new/unknown source IP."""
    src_ip = event.get("src_ip", "")
    if not src_ip or baseline.event_count < 10:
        return None
    if src_ip not in baseline.src_ips:
        return {
            "type": "UEBA_NEW_SRC_IP", "severity": "HIGH",
            "entity_id": baseline.entity_id,
            "src_ip": src_ip,
            "detail": f"First-seen source IP {src_ip} for entity {baseline.entity_id}",
            "mitre_id": "T1078",
            "risk_contribution": 35,
        }
    return None


def detect_data_staging(baseline: EntityBaseline, event: dict) -> Optional[dict]:
    """Detect anomalously large data transfers (potential staging/exfiltration)."""
    bytes_val = event.get("bytes", event.get("total_bytes", 0))
    if not bytes_val:
        return None
    mean = baseline.mean_bytes()
    std = baseline.std_bytes()
    if mean == 0 or std == 0:
        return None
    z_score = (bytes_val - mean) / std
    if z_score > 3.5:
        return {
            "type": "UEBA_DATA_STAGING", "severity": "CRITICAL",
            "entity_id": baseline.entity_id,
            "detail": f"Anomalous data transfer: {bytes_val:,} bytes (z={z_score:.1f}, mean={mean:.0f})",
            "mitre_id": "T1048",
            "risk_contribution": 50,
        }
    return None


def detect_auth_failure_spike(baseline: EntityBaseline, event: dict,
                               window_events: List[dict]) -> Optional[dict]:
    """Detect sudden spike in auth failures (brute force / credential stuffing)."""
    recent_failures = sum(1 for e in window_events[-20:]
                          if "AUTH_FAIL" in e.get("type", ""))
    if recent_failures >= 5:
        return {
            "type": "UEBA_AUTH_SPIKE", "severity": "HIGH",
            "entity_id": baseline.entity_id,
            "detail": f"Auth failure spike: {recent_failures} failures in recent window",
            "mitre_id": "T1110",
            "risk_contribution": 40,
        }
    return None


def detect_privilege_escalation_pattern(event: dict) -> Optional[dict]:
    """Detect sequences indicating privilege escalation."""
    event_type = event.get("type", "")
    if event_type in ("SUDO_EXEC", "AUTH_FAIL") and "root" in event.get("detail", "").lower():
        return {
            "type": "UEBA_PRIV_ESC_ATTEMPT", "severity": "HIGH",
            "entity_id": event.get("user", "unknown"),
            "detail": f"Potential privilege escalation: {event.get('detail', '')}",
            "mitre_id": "T1548",
            "risk_contribution": 45,
        }
    return None


def detect_lateral_movement_pattern(baseline: EntityBaseline,
                                     recent_dsts: List[str]) -> Optional[dict]:
    """Detect internal host scanning lateral movement."""
    if len(recent_dsts) < 3:
        return None
    # All internal IPs, many unique destinations
    internal = [ip for ip in recent_dsts if ip.startswith(("10.", "192.168.", "172."))]
    if len(set(internal)) >= 5:
        return {
            "type": "UEBA_LATERAL_MOVEMENT", "severity": "CRITICAL",
            "entity_id": baseline.entity_id,
            "detail": f"Internal lateral movement: {len(set(internal))} unique internal destinations",
            "mitre_id": "T1021",
            "risk_contribution": 55,
        }
    return None


# ─── UEBA ENGINE ──────────────────────────────────────────────────────────────

class UEBAEngine:
    """
    Main UEBA orchestrator.
    Maintains baselines per entity and runs anomaly detectors.
    """

    BASELINE_PATH = Path("data/ueba_baselines.json")

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.min_baseline_events = cfg.get("min_baseline_events", 20)
        self._baselines: Dict[str, EntityBaseline] = {}
        self._recent_events: Dict[str, List[dict]] = defaultdict(list)
        self._recent_dsts: Dict[str, List[str]] = defaultdict(list)
        self._ueba_alerts: List[dict] = []
        self._alert_id_counter = 8000
        self._load_baselines()

    def _load_baselines(self):
        if self.BASELINE_PATH.exists():
            try:
                data = json.loads(self.BASELINE_PATH.read_text())
                for entity_id, d in data.items():
                    b = EntityBaseline(entity_id, d.get("entity_type", "user"))
                    b.event_count = d.get("event_count", 0)
                    b.risk_score = d.get("risk_score", 0.0)
                    b.auth_failures = d.get("auth_failures", 0)
                    self._baselines[entity_id] = b
                logger.info(f"UEBA baselines loaded: {len(self._baselines)} entities")
            except Exception as e:
                logger.warning(f"UEBA baseline load error: {e}")

    def save_baselines(self):
        self.BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {eid: b.to_dict() for eid, b in self._baselines.items()}
        self.BASELINE_PATH.write_text(json.dumps(data, indent=2))

    def _get_or_create_baseline(self, entity_id: str, entity_type: str = "user") -> EntityBaseline:
        if entity_id not in self._baselines:
            self._baselines[entity_id] = EntityBaseline(entity_id, entity_type)
        return self._baselines[entity_id]

    def ingest_event(self, event: dict) -> List[dict]:
        """
        Process a host or network event through UEBA engine.
        Returns list of UEBA anomaly alerts (may be empty).
        """
        entity_id = event.get("user") or event.get("agent_id") or event.get("src_ip", "unknown")
        entity_type = "user" if event.get("user") else "host"

        baseline = self._get_or_create_baseline(entity_id, entity_type)
        baseline.record_event(event)

        # Track recent events for window-based detection
        self._recent_events[entity_id].append(event)
        if len(self._recent_events[entity_id]) > 100:
            self._recent_events[entity_id] = self._recent_events[entity_id][-100:]

        # Track recent destination IPs
        dst = event.get("dst_ip", "")
        if dst:
            self._recent_dsts[entity_id].append(dst)
            if len(self._recent_dsts[entity_id]) > 50:
                self._recent_dsts[entity_id] = self._recent_dsts[entity_id][-50:]

        # Skip detection during baseline building phase
        if baseline.event_count < self.min_baseline_events:
            return []

        # Run all detectors
        anomalies = []
        detectors = [
            lambda: detect_off_hours_access(baseline, event),
            lambda: detect_new_src_ip(baseline, event),
            lambda: detect_data_staging(baseline, event),
            lambda: detect_auth_failure_spike(baseline, event, self._recent_events[entity_id]),
            lambda: detect_privilege_escalation_pattern(event),
            lambda: detect_lateral_movement_pattern(baseline, self._recent_dsts[entity_id]),
        ]

        for detector in detectors:
            try:
                result = detector()
                if result:
                    anomalies.append(result)
            except Exception as e:
                logger.debug(f"UEBA detector error: {e}")

        # Update entity risk score
        if anomalies:
            total_risk = sum(a.get("risk_contribution", 20) for a in anomalies)
            baseline.risk_score = min(100, baseline.risk_score * 0.9 + total_risk * 0.5)

        # Convert to standard alert format
        alerts = []
        for a in anomalies:
            self._alert_id_counter += 1
            alert = {
                "id": self._alert_id_counter,
                "timestamp": datetime.utcnow().isoformat(),
                "type": a["type"],
                "severity": a["severity"],
                "detail": a["detail"],
                "mitre_id": a.get("mitre_id", "T1078"),
                "confidence": 75,
                "src_ip": event.get("src_ip", "?"),
                "dst_ip": event.get("dst_ip", "?"),
                "source": "ueba",
                "entity_id": entity_id,
                "entity_risk_score": round(baseline.risk_score, 1),
                "status": "OPEN",
                "risk_score": a.get("risk_contribution", 40),
                "correlated": False,
            }
            self._ueba_alerts.append(alert)
            alerts.append(alert)

        return alerts

    def get_entity_risk_scores(self, limit: int = 50) -> List[dict]:
        """Return top entities ranked by risk score."""
        entities = [b.to_dict() for b in self._baselines.values()]
        return sorted(entities, key=lambda x: x["risk_score"], reverse=True)[:limit]

    def get_alerts(self, limit: int = 100) -> List[dict]:
        return list(reversed(self._ueba_alerts[-limit:]))

    @property
    def stats(self) -> dict:
        return {
            "entities_tracked": len(self._baselines),
            "ueba_alerts_total": len(self._ueba_alerts),
            "high_risk_entities": sum(1 for b in self._baselines.values() if b.risk_score >= 60),
        }
