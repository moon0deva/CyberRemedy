"""
AID-ARS Threat Scoring Engine
Assigns a risk score 0-100 to each alert based on
confidence, severity, attack type, and asset impact.
"""

import logging
from typing import Optional

logger = logging.getLogger("aidars.scoring")

# Base severity scores
SEV_BASE = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 15}

# Attack type multipliers
ATTACK_MULTIPLIERS = {
    "DNS Tunneling": 1.25,
    "Data Exfiltration": 1.3,
    "C2 Beaconing": 1.2,
    "Lateral Movement": 1.15,
    "SSH Brute Force": 1.1,
    "FTP Brute Force": 1.0,
    "Port Scan (SYN)": 0.85,
    "Port Scan (FIN/NULL)": 0.80,
    "Process Injection": 1.3,
    "Suspicious Encrypted Traffic": 0.9,
    "[ML] Anomalous Behavior": 1.0,
}

# Sensitive destination ports raise impact
HIGH_IMPACT_PORTS = {22, 3389, 445, 1433, 3306, 5432, 27017, 6379, 2379}
CRITICAL_PORTS = {22, 3389, 445}


class ThreatScorer:
    """
    Computes a normalized risk score (0-100) for an alert.
    Score components:
      - Base severity (40% weight)
      - Detection confidence (30% weight)
      - Attack type multiplier
      - Asset impact (port sensitivity)
      - Chain context (correlated events raise score)
    """

    def score(self, alert: dict) -> dict:
        """Add risk_score and priority to an alert dict."""
        severity = alert.get("severity", "LOW")
        confidence = alert.get("confidence", 50) / 100.0
        attack_type = alert.get("type", "")
        dst_port = alert.get("dst_port", 0)
        correlated = alert.get("correlated", False)

        # Base from severity
        base = SEV_BASE.get(severity, 15)

        # Confidence modifier (±15 points)
        conf_delta = (confidence - 0.75) * 60  # centered at 75%

        # Attack type multiplier
        multiplier = 1.0
        for key, mult in ATTACK_MULTIPLIERS.items():
            if key.lower() in attack_type.lower():
                multiplier = mult
                break

        # Asset impact
        impact = 0
        if dst_port in CRITICAL_PORTS:
            impact = 15
        elif dst_port in HIGH_IMPACT_PORTS:
            impact = 8

        # Correlation bonus
        chain_bonus = 12 if correlated else 0

        # Final score
        raw = (base + conf_delta + impact + chain_bonus) * multiplier
        score = max(0, min(100, int(raw)))

        # Priority label
        if score >= 80:
            priority = "P1-CRITICAL"
        elif score >= 60:
            priority = "P2-HIGH"
        elif score >= 40:
            priority = "P3-MEDIUM"
        elif score >= 20:
            priority = "P4-LOW"
        else:
            priority = "P5-INFO"

        alert["risk_score"] = score
        alert["priority"] = priority
        return alert

    def score_batch(self, alerts: list) -> list:
        return [self.score(a) for a in alerts]

    def should_auto_respond(self, alert: dict, thresholds: dict) -> bool:
        """Check if an alert crosses the autonomous response threshold."""
        score = alert.get("risk_score", 0)
        sev = alert.get("severity", "LOW")

        if thresholds.get("auto_block_critical") and sev == "CRITICAL":
            return True
        if thresholds.get("auto_block_high") and sev == "HIGH":
            return True
        if score >= 90:
            return True

        return False
