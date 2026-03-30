"""
CyberRemedy SIEM — VPN Fingerprinter
=====================================
Identifies VPN providers and protocols from passive traffic metadata.
No decryption — uses ports, IP ranges, packet size patterns, timing.
For protocol-level parsing (WireGuard handshake keys, IKEv2 SA_INIT,
OpenVPN opcodes) and traffic classification, see siem/vpn_deep_inspect.py.

Detects:
  WireGuard, OpenVPN, NordVPN, ExpressVPN, Mullvad, ProtonVPN,
  Tailscale, IPSec/IKEv2, PPTP, Shadowsocks, generic VPN patterns
"""
import ipaddress
import logging
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("cyberremedy.siem.vpn")

# ─── Known VPN port signatures ────────────────────────────────────────────────
_PORT_SIGNATURES = {
    51820: {"proto": "WireGuard",  "provider": "WireGuard",  "confidence": 95},
    1194:  {"proto": "OpenVPN",    "provider": "OpenVPN",    "confidence": 85},
    1197:  {"proto": "OpenVPN",    "provider": "ExpressVPN", "confidence": 80},
    1198:  {"proto": "OpenVPN",    "provider": "ExpressVPN", "confidence": 80},
    443:   {"proto": "OpenVPN/SSL","provider": "Unknown",    "confidence": 30},
    500:   {"proto": "IKEv2/IPSec","provider": "IPSec",      "confidence": 85},
    4500:  {"proto": "IKEv2/IPSec","provider": "IPSec",      "confidence": 85},
    1701:  {"proto": "L2TP",       "provider": "L2TP/IPSec", "confidence": 85},
    1723:  {"proto": "PPTP",       "provider": "PPTP",       "confidence": 90},
    8388:  {"proto": "Shadowsocks","provider": "Shadowsocks","confidence": 80},
    8080:  {"proto": "OpenVPN",    "provider": "Unknown",    "confidence": 40},
    41641: {"proto": "WireGuard",  "provider": "Tailscale",  "confidence": 90},
    3478:  {"proto": "STUN",       "provider": "Tailscale",  "confidence": 50},
}

# ─── Known VPN provider IP ranges (sampled — key server ranges) ──────────────
_PROVIDER_RANGES = {
    "NordVPN": [
        "37.120.131.0/24", "37.120.133.0/24", "37.120.135.0/24",
        "45.83.88.0/22",   "45.134.212.0/22", "89.38.96.0/22",
        "92.119.180.0/22", "103.86.96.0/22",  "185.93.0.0/22",
        "194.165.16.0/22", "217.138.192.0/22",
    ],
    "ExpressVPN": [
        "141.101.0.0/17", "162.252.86.0/24", "205.185.208.0/22",
        "209.209.50.0/24","216.19.208.0/22",
    ],
    "Mullvad": [
        "193.138.218.0/24","194.127.166.0/24","185.213.154.0/24",
        "31.171.152.0/24", "45.83.220.0/22",
    ],
    "ProtonVPN": [
        "185.159.156.0/22","37.19.200.0/22",  "94.247.128.0/22",
        "185.107.80.0/22", "103.234.220.0/22",
    ],
    "Tailscale": [
        "100.64.0.0/10",   # Tailscale uses 100.x.x.x CGNAT range
    ],
    "PureVPN": [
        "37.60.240.0/22",  "46.166.128.0/22", "87.121.48.0/22",
    ],
    "Surfshark": [
        "37.19.221.0/24",  "156.146.32.0/22", "195.181.160.0/22",
    ],
    "IPVanish": [
        "198.7.56.0/22",   "64.34.218.0/24",  "207.244.64.0/22",
    ],
}

# Pre-parse CIDR ranges
_PARSED_RANGES: Dict[str, List] = {}
for _provider, _cidrs in _PROVIDER_RANGES.items():
    _PARSED_RANGES[_provider] = []
    for _cidr in _cidrs:
        try:
            _PARSED_RANGES[_provider].append(ipaddress.IPv4Network(_cidr))
        except Exception:
            pass


class VPNFingerprinter:
    """
    Per-device VPN traffic analyser.
    Call .ingest(pkt) for every packet from a device.
    Call .analyse(ip) to get the current VPN assessment.
    """

    def __init__(self):
        # ip → list of recent packets (rolling window of last 200)
        self._pkts:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # ip → cached analysis result (cleared on new packets)
        self._cache: Dict[str, dict]  = {}
        # ip → set of dst_ips seen
        self._dsts:  Dict[str, set]   = defaultdict(set)

    def ingest(self, pkt: dict) -> None:
        """Feed a packet into the fingerprinter for its source IP."""
        src = pkt.get("src_ip", "")
        if not src or ":" in src:   # skip empty or MAC
            return
        self._pkts[src].append(pkt)
        dst = pkt.get("dst_ip", "")
        if dst:
            self._dsts[src].add(dst)
        # Invalidate cache for this IP
        self._cache.pop(src, None)

    def analyse(self, ip: str) -> dict:
        """
        Return VPN assessment for a device IP.
        {
          "is_vpn": bool,
          "protocol": str,       # WireGuard / OpenVPN / IKEv2 / unknown
          "provider": str,       # NordVPN / Tailscale / unknown etc
          "confidence": int,     # 0-100
          "tunnel_dst": str,     # VPN server IP seen
          "signals": [str],      # human-readable evidence list
          "traffic_stats": {...}
        }
        """
        if ip in self._cache:
            return self._cache[ip]

        pkts   = list(self._pkts.get(ip, []))
        result = self._run_analysis(ip, pkts)
        self._cache[ip] = result
        return result

    def analyse_all(self) -> Dict[str, dict]:
        """Return analysis for every tracked IP."""
        return {ip: self.analyse(ip) for ip in self._pkts}

    # ─── internal analysis ────────────────────────────────────────────────────

    def _run_analysis(self, ip: str, pkts: list) -> dict:
        if not pkts:
            return self._empty(ip)

        signals     = []
        confidence  = 0
        protocol    = "Unknown"
        provider    = "Unknown"
        tunnel_dst  = ""

        # --- Port-based detection ---
        port_hits = defaultdict(int)
        for p in pkts:
            dp = p.get("dst_port", 0)
            if dp in _PORT_SIGNATURES:
                port_hits[dp] += 1

        if port_hits:
            top_port = max(port_hits, key=port_hits.get)
            sig = _PORT_SIGNATURES[top_port]
            protocol   = sig["proto"]
            provider   = sig["provider"]
            confidence = sig["confidence"]
            signals.append(
                f"Port {top_port} ({protocol}) seen {port_hits[top_port]} times"
            )

        # --- Provider IP range matching ---
        dst_ips = list(self._dsts.get(ip, set()))
        matched_provider = self._match_provider_ranges(dst_ips)
        if matched_provider:
            provider   = matched_provider["provider"]
            tunnel_dst = matched_provider["dst_ip"]
            confidence = max(confidence, matched_provider["confidence"])
            signals.append(
                f"Destination {tunnel_dst} matches {provider} server range"
            )

        # --- WireGuard packet size fingerprint ---
        # WireGuard handshake initiation = 148 bytes, response = 92 bytes
        # Data packets are multiples of 16 + 32 (AEAD overhead)
        wg_sizes = sum(
            1 for p in pkts
            if p.get("length", 0) in (148, 92, 64, 80, 96, 112, 128)
            and p.get("protocol", "").upper() == "UDP"
        )
        if wg_sizes >= 3 and protocol == "Unknown":
            protocol   = "WireGuard"
            confidence = max(confidence, 70)
            signals.append(
                f"WireGuard-sized UDP packets: {wg_sizes} packets"
            )

        # --- Tailscale CGNAT range (100.x.x.x) ---
        cgnat = [d for d in dst_ips if d.startswith("100.")]
        if cgnat:
            provider   = "Tailscale"
            protocol   = "WireGuard"
            confidence = max(confidence, 90)
            tunnel_dst = cgnat[0]
            signals.append(f"Tailscale CGNAT address: {cgnat[0]}")

        # --- Traffic pattern analysis ---
        # VPN traffic tends to go to ONE destination IP for all traffic
        # (the VPN server acts as a single funnel)
        if dst_ips and len(pkts) > 10:
            top_dst_count = max(
                sum(1 for p in pkts if p.get("dst_ip") == d)
                for d in set(dst_ips)
            )
            top_dst_ratio = top_dst_count / len(pkts)
            if top_dst_ratio > 0.7 and len(set(dst_ips)) < 4:
                signals.append(
                    f"Tunnel pattern: {top_dst_ratio:.0%} traffic to single IP"
                )
                confidence = max(confidence, 55)
                # Find which IP is the tunnel destination
                if not tunnel_dst:
                    tunnel_dst = max(
                        set(dst_ips),
                        key=lambda d: sum(
                            1 for p in pkts if p.get("dst_ip") == d
                        )
                    )

        # --- Encrypted payload heuristic ---
        # VPN payloads have high entropy — uniform packet sizes, no HTTP headers
        udp_pkts = [p for p in pkts if p.get("protocol","").upper() == "UDP"]
        if len(udp_pkts) > 20 and confidence > 40:
            signals.append(
                f"Sustained UDP tunnel: {len(udp_pkts)} UDP packets"
            )

        # Traffic stats
        total_bytes = sum(p.get("length", 0) for p in pkts)
        udp_bytes   = sum(
            p.get("length", 0) for p in pkts
            if p.get("protocol","").upper() == "UDP"
        )

        result = {
            "ip":           ip,
            "is_vpn":       confidence >= 50,
            "protocol":     protocol,
            "provider":     provider,
            "confidence":   min(confidence, 99),
            "tunnel_dst":   tunnel_dst,
            "signals":      signals,
            "packet_count": len(pkts),
            "traffic_stats": {
                "total_bytes": total_bytes,
                "udp_bytes":   udp_bytes,
                "dst_count":   len(set(dst_ips)),
                "top_dst":     tunnel_dst,
            },
            "analysed_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        return result

    @staticmethod
    def _match_provider_ranges(dst_ips: list) -> Optional[dict]:
        """Check if any destination IP falls in a known VPN provider range."""
        for dst_ip in dst_ips:
            try:
                addr = ipaddress.IPv4Address(dst_ip)
            except Exception:
                continue
            for provider, networks in _PARSED_RANGES.items():
                for net in networks:
                    if addr in net:
                        return {
                            "provider":   provider,
                            "dst_ip":     dst_ip,
                            "confidence": 88,
                        }
        return None

    @staticmethod
    def _empty(ip: str) -> dict:
        return {
            "ip": ip, "is_vpn": False, "protocol": "Unknown",
            "provider": "Unknown", "confidence": 0,
            "tunnel_dst": "", "signals": [],
            "packet_count": 0,
            "traffic_stats": {
                "total_bytes": 0, "udp_bytes": 0,
                "dst_count": 0,   "top_dst": "",
            },
            "analysed_at": "",
        }
