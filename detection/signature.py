"""
AID-ARS Signature Detection Engine
Rule-based detection for known attack patterns.
Each rule returns None (no match) or an Alert dict.
"""

import logging
from datetime import datetime
from typing import Optional, List

logger = logging.getLogger("aidars.detection.signature")


# ─── ALERT FACTORY ────────────────────────────────────────────────────────────

_alert_id_counter = 1000

def _make_alert(
    flow: dict,
    attack_type: str,
    mitre_id: str,
    severity: str,
    confidence: float,
    detail: str,
) -> dict:
    global _alert_id_counter
    _alert_id_counter += 1
    return {
        "id": _alert_id_counter,
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "type": attack_type,
        "src_ip": flow.get("src_ip", "?"),
        "dst_ip": flow.get("dst_ip", "?"),
        "src_port": flow.get("src_port", 0),
        "dst_port": flow.get("dst_port", 0),
        "protocol": flow.get("protocol", "?"),
        "mitre_id": mitre_id,
        "confidence": round(confidence * 100),
        "detail": detail,
        "status": "OPEN",
        "source": "signature",
        "packets": flow.get("packet_count", 0),
        "bytes": flow.get("total_bytes", 0),
        "flow_key": flow.get("flow_key", ""),
        "correlated": False,
    }


# ─── INDIVIDUAL RULES ─────────────────────────────────────────────────────────

def rule_syn_scan(flow: dict, cfg: dict) -> Optional[dict]:
    """Detect SYN port scans: many unique destination ports, SYN-only flags."""
    threshold = cfg.get("port_scan_threshold", 15)
    if (
        flow.get("has_syn") == 1
        and flow.get("has_fin") == 0
        and flow.get("unique_dst_ports", 0) >= threshold
        and flow.get("protocol") == "TCP"
    ):
        confidence = min(0.99, 0.6 + (flow["unique_dst_ports"] - threshold) * 0.02)
        return _make_alert(
            flow, "Port Scan (SYN)", "T1046", "MEDIUM",
            confidence,
            f"SYN scan: {flow['unique_dst_ports']} ports probed from {flow['src_ip']}"
        )
    return None


def rule_fin_null_scan(flow: dict, cfg: dict) -> Optional[dict]:
    """Detect FIN/NULL scans used for stealth recon."""
    if (
        flow.get("has_null") == 1 or (
            flow.get("has_fin") == 1
            and flow.get("has_syn") == 0
            and flow.get("has_rst") == 0
        )
    ) and flow.get("unique_dst_ports", 0) >= 5:
        return _make_alert(
            flow, "Port Scan (FIN/NULL)", "T1046", "MEDIUM",
            0.82,
            f"Stealth scan (FIN/NULL) from {flow['src_ip']} — {flow['unique_dst_ports']} ports"
        )
    return None


def rule_brute_force(flow: dict, cfg: dict) -> Optional[dict]:
    """Detect brute-force: many packets to a single auth port."""
    threshold = cfg.get("brute_force_threshold", 10)
    auth_ports = {22, 21, 3389, 445, 1433, 3306, 5432, 23, 110, 143}
    if (
        flow.get("dst_port") in auth_ports
        and flow.get("packet_count", 0) >= threshold
        and flow.get("packets_per_second", 0) > 3
    ):
        port_service = {22: "SSH", 21: "FTP", 3389: "RDP", 445: "SMB", 23: "Telnet"}.get(
            flow["dst_port"], f"Port {flow['dst_port']}"
        )
        severity = "CRITICAL" if flow["packet_count"] > 200 else "HIGH"
        confidence = min(0.98, 0.65 + flow["packet_count"] / 1000)
        return _make_alert(
            flow, f"{port_service} Brute Force", "T1110", severity,
            confidence,
            f"{flow['packet_count']} packets to {flow['dst_ip']}:{flow['dst_port']} ({port_service}) at {flow['packets_per_second']:.1f} pkt/s"
        )
    return None


def rule_c2_beaconing(flow: dict, cfg: dict) -> Optional[dict]:
    """
    Detect C2 beaconing: highly regular inter-arrival times
    to an external host on HTTP/S or non-standard port.
    """
    if (
        flow.get("std_inter_arrival", 999) < 0.5
        and flow.get("avg_inter_arrival", 0) > 5
        and flow.get("packet_count", 0) >= 10
        and flow.get("protocol") in ("TCP", "UDP")
    ):
        return _make_alert(
            flow, "C2 Beaconing", "T1071", "HIGH",
            0.87,
            f"Regular beacon interval ~{flow['avg_inter_arrival']:.1f}s (std: {flow['std_inter_arrival']:.3f}s) to {flow['dst_ip']}:{flow['dst_port']}"
        )
    return None


def rule_dns_tunneling(flow: dict, cfg: dict) -> Optional[dict]:
    """Detect DNS tunneling: high entropy DNS payloads or large query sizes."""
    entropy_thresh = cfg.get("dns_entropy_threshold", 3.8)
    if (
        flow.get("protocol") == "DNS"
        and (
            flow.get("payload_entropy", 0) > entropy_thresh
            or flow.get("avg_packet_size", 0) > 200
            or flow.get("bytes_per_second", 0) > 5000
        )
    ):
        confidence = min(0.95, 0.6 + flow.get("payload_entropy", 0) * 0.05)
        return _make_alert(
            flow, "DNS Tunneling", "T1048", "CRITICAL",
            confidence,
            f"High entropy DNS: {flow.get('payload_entropy', 0):.2f} bits, avg size {flow.get('avg_packet_size', 0):.0f}B from {flow['src_ip']}"
        )
    return None


def rule_lateral_movement(flow: dict, cfg: dict) -> Optional[dict]:
    """Detect lateral movement: internal-to-internal connections on admin ports."""
    admin_ports = {22, 445, 135, 139, 3389, 5985, 5986}
    src = flow.get("src_ip", "")
    dst = flow.get("dst_ip", "")

    def is_internal(ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
        )

    if (
        is_internal(src)
        and is_internal(dst)
        and flow.get("dst_port") in admin_ports
        and flow.get("packet_count", 0) > 5
    ):
        port_name = {22: "SSH", 445: "SMB", 3389: "RDP", 135: "DCOM", 5985: "WinRM"}.get(
            flow["dst_port"], str(flow["dst_port"])
        )
        return _make_alert(
            flow, "Lateral Movement", "T1021", "HIGH",
            0.78,
            f"Internal {port_name} connection: {src} → {dst}:{flow['dst_port']}"
        )
    return None


def rule_large_outbound(flow: dict, cfg: dict) -> Optional[dict]:
    """Detect potential data exfiltration: unusually large outbound transfers."""
    if (
        flow.get("total_bytes", 0) > 10_000_000  # 10MB
        and flow.get("bytes_per_second", 0) > 50000
        and flow.get("dst_port") not in {80, 443}
    ):
        return _make_alert(
            flow, "Data Exfiltration", "T1048", "CRITICAL",
            0.72,
            f"Large outbound transfer: {flow['total_bytes'] // 1024 // 1024:.1f}MB at {flow['bytes_per_second'] / 1024:.1f} KB/s to {flow['dst_ip']}"
        )
    return None


def rule_suspicious_encrypted(flow: dict, cfg: dict) -> Optional[dict]:
    """Flag high-entropy encrypted traffic on unusual ports."""
    standard_tls_ports = {443, 8443, 993, 995, 465, 587}
    if (
        flow.get("protocol") == "TCP"
        and flow.get("dst_port") not in standard_tls_ports
        and flow.get("payload_entropy", 0) > 4.5
        and flow.get("avg_packet_size", 0) > 400
        and flow.get("packet_count", 0) > 20
    ):
        return _make_alert(
            flow, "Suspicious Encrypted Traffic", "T1105", "MEDIUM",
            0.68,
            f"High-entropy TCP on non-standard port {flow['dst_port']} from {flow['src_ip']}"
        )
    return None


# ─── SIGNATURE ENGINE ─────────────────────────────────────────────────────────

RULES = [
    rule_syn_scan,
    rule_fin_null_scan,
    rule_brute_force,
    rule_c2_beaconing,
    rule_dns_tunneling,
    rule_lateral_movement,
    rule_large_outbound,
    rule_suspicious_encrypted,
]


class SignatureDetector:
    """
    Runs all signature rules against a flow feature vector.
    Returns a list of matching alerts (may be empty).
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.total_analyzed = 0
        self.total_detected = 0

    def analyze(self, flow: dict) -> List[dict]:
        self.total_analyzed += 1
        alerts = []
        for rule in RULES:
            try:
                alert = rule(flow, self.config)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.debug(f"Rule {rule.__name__} error: {e}")

        self.total_detected += len(alerts)
        return alerts

    @property
    def stats(self) -> dict:
        return {
            "flows_analyzed": self.total_analyzed,
            "alerts_generated": self.total_detected,
            "detection_rate": round(
                self.total_detected / max(self.total_analyzed, 1), 4
            ),
        }
