"""
CyberRemedy Signature Detection Engine
Rule-based detection for known attack patterns.
Each rule returns None (no match) or an Alert dict.
"""

import logging
from datetime import datetime
from typing import Optional, List

logger = logging.getLogger("cyberremedy.detection.signature")


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


def rule_dns_leak(flow: dict, cfg: dict) -> Optional[dict]:
    """
    Detect DNS leak / resolver bypass.
    A DNS query going directly to a well-known public resolver instead of the
    LAN gateway indicates a VPN misconfiguration, split-tunnel leak, or
    deliberate policy bypass (T1071 — Application Layer Protocol).

    Configure expected_dns_servers in detection.signature to match your network.
    Default assumes the LAN gateway handles DNS (common home/SMB layout).
    """
    EXPECTED_RESOLVERS: set = set(cfg.get("expected_dns_servers", []))
    KNOWN_PUBLIC_DNS: set = {
        "8.8.8.8", "8.8.4.4",          # Google
        "1.1.1.1", "1.0.0.1",          # Cloudflare
        "9.9.9.9", "149.112.112.112",   # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "64.6.64.6", "64.6.65.6",      # Verisign
        "77.88.8.8", "77.88.8.1",      # Yandex
    }

    if flow.get("protocol") != "DNS":
        return None
    if flow.get("dst_port") != 53:
        return None

    dst = flow.get("dst_ip", "")
    src = flow.get("src_ip", "")
    if not dst:
        return None

    # Skip if destination is an expected/configured resolver
    if EXPECTED_RESOLVERS and dst in EXPECTED_RESOLVERS:
        return None

    def _is_private(ip: str) -> bool:
        return (ip.startswith("192.168.") or ip.startswith("10.")
                or ip.startswith("172.") or ip.startswith("127."))

    # Case 1: Query to a well-known public resolver — definite bypass
    if dst in KNOWN_PUBLIC_DNS:
        return _make_alert(
            flow, "DNS Leak / Resolver Bypass", "T1071", "MEDIUM", 0.82,
            f"DNS query from {src} sent directly to public resolver {dst} "
            f"— bypasses LAN DNS (VPN misconfiguration or deliberate bypass)"
        )

    # Case 2: Query going to any external (non-LAN) IP on port 53 — possible custom resolver
    if not _is_private(dst):
        return _make_alert(
            flow, "DNS Leak / Unknown Resolver", "T1071", "LOW", 0.60,
            f"DNS query from {src} to unexpected external resolver {dst}"
        )

    return None


def rule_mac_randomised(flow: dict, cfg: dict) -> Optional[dict]:
    """
    Detect Android/iOS MAC randomisation.

    Android 10+ and iOS 14+ assign a per-network randomised MAC by default.
    A randomised MAC has the locally-administered bit set — the second hex
    digit of the first octet is 2, 6, A, or E  (binary x010 in bit 1).

    Examples of randomised MACs:  02:xx, 06:xx, 0A:xx, 0E:xx,
                                   12:xx, 16:xx, 1A:xx, 1E:xx, ...

    This rule fires on NEW DEVICE alerts that carry a randomised MAC so the
    analyst knows the OUI vendor lookup will be unreliable and the device is
    likely a modern mobile phone or tablet.

    The alert is LOW severity — it is informational, not an attack — but it
    enriches the device registry entry so downstream rules have context.
    """
    mac = flow.get("mac", "")
    if not mac or len(mac) < 2:
        return None

    # Only fire on new-device type events that carry a mac field
    if flow.get("type") not in ("New WiFi Device", "new_device", "arp", "beacon", "mdns", "ssdp"):
        return None

    # Check locally-administered bit (bit 1 of first octet)
    try:
        first_octet = int(mac.replace(":", "").replace("-", "")[:2], 16)
        is_random = bool(first_octet & 0x02)   # bit 1 set = locally administered
    except ValueError:
        return None

    if not is_random:
        return None

    src = flow.get("src_ip", "") or flow.get("ip", "")
    return _make_alert(
        flow, "MAC Randomisation Detected", "T1040", "LOW", 0.90,
        f"Device {src or 'unknown IP'} uses a randomised MAC ({mac}) — "
        f"likely Android 10+ or iOS 14+ mobile device. "
        f"OUI vendor lookup unreliable. Use IP + mDNS/SSDP hostname for identification."
    )


def rule_dot_leak(flow: dict, cfg: dict) -> Optional[dict]:
    """
    Detect DNS-over-TLS (DoT) bypassing the LAN resolver — Android 9+ specific.

    Android 9+ introduced Private DNS (DNS-over-TLS) on port 853.
    When a device sends DoT directly to 8.8.8.8:853 or 1.1.1.1:853 it
    bypasses the LAN gateway resolver entirely — plain port-53 DNS leak
    detection (rule_dns_leak) misses this completely.

    This rule catches TCP/TLS flows to port 853 going to external IPs.
    Combined with rule_dns_leak it gives full coverage of DNS bypass
    for both Android 9 (DoT) and older devices (plain UDP 53).
    """
    if flow.get("dst_port") != 853:
        return None
    if flow.get("protocol") not in ("TCP", "TLS", "OTHER"):
        return None

    dst = flow.get("dst_ip", "")
    src = flow.get("src_ip", "")
    if not dst:
        return None

    def _is_private(ip: str) -> bool:
        return any(ip.startswith(p) for p in ("192.168.", "10.", "172.", "127."))

    if _is_private(dst):
        return None   # DoT to a LAN resolver is fine

    EXPECTED: set = set(cfg.get("expected_dns_servers", []))
    if EXPECTED and dst in EXPECTED:
        return None

    KNOWN_DOT = {
        "8.8.8.8", "8.8.4.4",           # Google
        "1.1.1.1", "1.0.0.1",           # Cloudflare
        "9.9.9.9", "149.112.112.112",    # Quad9
        "208.67.222.222",                # OpenDNS
    }
    severity   = "MEDIUM" if dst in KNOWN_DOT else "LOW"
    confidence = 0.85     if dst in KNOWN_DOT else 0.65

    return _make_alert(
        flow, "DNS-over-TLS Leak (Android Private DNS)", "T1071", severity, confidence,
        f"DoT connection from {src} to {dst}:853 bypasses LAN resolver — "
        f"Android Private DNS or iOS DoT. Plain UDP-53 DNS monitoring will "
        f"NOT see queries from this device."
    )


# ─── SIGNATURE ENGINE ─────────────────────────────────────────────────────────

RULES = [
    rule_syn_scan,
    rule_fin_null_scan,
    rule_brute_force,
    rule_c2_beaconing,
    rule_dns_tunneling,
    rule_dns_leak,              # UDP/53 resolver bypass (all devices)
    rule_dot_leak,              # TCP/853 DoT bypass (Android 9+ / iOS 14+)
    rule_mac_randomised,        # Android 10+ / iOS 14+ randomised MAC detection
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
