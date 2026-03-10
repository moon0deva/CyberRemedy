"""
CyberRemedy Behavioral Correlation Engine
Correlates multiple alerts over time to reconstruct attack chains,
reduce false positives, and identify multi-stage intrusions.
"""

import time
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("cyberremedy.detection.correlation")


# ─── KILL CHAIN STAGES ────────────────────────────────────────────────────────

KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Discovery",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Defense Evasion",
]

MITRE_TACTIC_MAP = {
    "T1046": "Discovery",
    "T1595": "Reconnaissance",
    "T1110": "Credential Access",
    "T1071": "Command and Control",
    "T1048": "Exfiltration",
    "T1021": "Lateral Movement",
    "T1566": "Initial Access",
    "T1059": "Execution",
    "T1082": "Discovery",
    "T1055": "Defense Evasion",
    "T1105": "Command and Control",
    "T1190": "Initial Access",
}


# ─── DATA CLASSES ─────────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    chain_id: str
    src_ip: str
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    alerts: List[dict] = field(default_factory=list)
    stages_seen: List[str] = field(default_factory=list)
    is_active: bool = True

    @property
    def stage_count(self) -> int:
        return len(set(self.stages_seen))

    @property
    def risk_score(self) -> int:
        base = min(100, len(self.alerts) * 8)
        stage_bonus = self.stage_count * 12
        progression_bonus = 20 if self._is_progressing() else 0
        return min(100, base + stage_bonus + progression_bonus)

    @property
    def severity(self) -> str:
        score = self.risk_score
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        return "LOW"

    def _is_progressing(self) -> bool:
        """Check if chain shows kill-chain progression."""
        if len(self.stages_seen) < 2:
            return False
        seen_indices = [KILL_CHAIN_ORDER.index(s) for s in self.stages_seen if s in KILL_CHAIN_ORDER]
        if len(seen_indices) < 2:
            return False
        return seen_indices[-1] > seen_indices[0]

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "src_ip": self.src_ip,
            "alert_count": len(self.alerts),
            "stages": list(set(self.stages_seen)),
            "stage_count": self.stage_count,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "is_active": self.is_active,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "last_updated": datetime.fromtimestamp(self.last_updated).isoformat(),
            "duration_seconds": round(self.last_updated - self.created_at, 1),
            "progressing": self._is_progressing(),
            "alerts": self.alerts[-10:],  # Last 10 for payload size
        }


# ─── CORRELATION ENGINE ───────────────────────────────────────────────────────

_chain_counter = 0


class CorrelationEngine:
    """
    Maintains per-source-IP attack chains.
    Correlates incoming alerts into chains based on:
    - Same source IP within time window
    - Kill-chain stage progression
    - Related technique co-occurrence
    """

    def __init__(self, time_window: float = 300.0, min_chain_events: int = 2):
        self.time_window = time_window
        self.min_chain_events = min_chain_events
        self._chains: Dict[str, AttackChain] = {}        # chain_id -> chain
        self._src_to_chain: Dict[str, str] = {}          # src_ip -> chain_id
        self._completed_chains: List[AttackChain] = []
        self._last_cleanup = time.time()
        self.fp_suppressed = 0

    def ingest_alert(self, alert: dict) -> Optional[dict]:
        """
        Feed an alert into the correlation engine.
        Returns a correlated chain dict if the alert completes/updates a chain.
        """
        src_ip = alert.get("src_ip", "?")
        mitre_id = alert.get("mitre_id", "")
        tactic = MITRE_TACTIC_MAP.get(mitre_id, "Unknown")

        # Find or create chain for this source
        chain = self._get_or_create_chain(src_ip)
        chain.alerts.append(alert)
        chain.last_updated = time.time()

        if tactic not in chain.stages_seen:
            chain.stages_seen.append(tactic)

        # Mark alert as correlated
        alert["correlated"] = True
        alert["chain_id"] = chain.chain_id

        # Periodic cleanup of expired chains
        if time.time() - self._last_cleanup > 30:
            self._cleanup_expired()

        # Return chain if it has enough events to be significant
        if len(chain.alerts) >= self.min_chain_events:
            return chain.to_dict()

        return None

    def _get_or_create_chain(self, src_ip: str) -> AttackChain:
        global _chain_counter

        # Check existing chain for this IP
        if src_ip in self._src_to_chain:
            chain_id = self._src_to_chain[src_ip]
            if chain_id in self._chains:
                chain = self._chains[chain_id]
                # Still within time window?
                if time.time() - chain.last_updated < self.time_window:
                    return chain
                else:
                    # Expire old chain
                    chain.is_active = False
                    self._completed_chains.append(chain)
                    del self._chains[chain_id]

        # Create new chain
        _chain_counter += 1
        chain_id = f"CHAIN-{_chain_counter:04d}"
        chain = AttackChain(chain_id=chain_id, src_ip=src_ip)
        self._chains[chain_id] = chain
        self._src_to_chain[src_ip] = chain_id
        logger.info(f"New attack chain: {chain_id} from {src_ip}")
        return chain

    def _cleanup_expired(self):
        now = time.time()
        expired = [
            cid for cid, c in self._chains.items()
            if now - c.last_updated > self.time_window
        ]
        for cid in expired:
            chain = self._chains.pop(cid)
            chain.is_active = False
            self._completed_chains.append(chain)
            # Clean up IP mapping
            if self._src_to_chain.get(chain.src_ip) == cid:
                del self._src_to_chain[chain.src_ip]

        if expired:
            logger.debug(f"Expired {len(expired)} chains")

        self._last_cleanup = now

    def get_active_chains(self) -> List[dict]:
        return [c.to_dict() for c in self._chains.values()]

    def get_all_chains(self) -> List[dict]:
        active = [c.to_dict() for c in self._chains.values()]
        completed = [c.to_dict() for c in self._completed_chains[-20:]]
        return active + completed

    def should_suppress_fp(self, alert: dict) -> bool:
        """
        Suppress low-confidence alerts that have no corroborating chain evidence.
        Reduces false positives.
        """
        src_ip = alert.get("src_ip", "")
        confidence = alert.get("confidence", 100)

        # Only suppress low-confidence alerts
        if confidence >= 70:
            return False

        # If source has no chain history, suppress low-conf alerts
        if src_ip not in self._src_to_chain:
            self.fp_suppressed += 1
            return True

        return False

    @property
    def stats(self) -> dict:
        return {
            "active_chains": len(self._chains),
            "completed_chains": len(self._completed_chains),
            "fp_suppressed": self.fp_suppressed,
        }
