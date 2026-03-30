"""
CyberRemedy SIEM — Per-Device Traffic Store
============================================
Keeps a rolling window of packets per device IP.
Separates normal traffic from VPN tunnel traffic.
Used by the split-view per-device panel in the dashboard.
"""
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

from utils.json_safe import sanitize

logger = logging.getLogger("cyberremedy.siem.device_traffic")

# VPN tunnel ports — packets to/from these are classified as VPN traffic
_VPN_PORTS = {
    51820, 41641,           # WireGuard / Tailscale
    1194, 1197, 1198,       # OpenVPN
    500, 4500, 1701,        # IKEv2 / L2TP
    1723,                   # PPTP
    8388,                   # Shadowsocks
}

_MAX_PACKETS_PER_DEVICE = 300   # rolling window per device


class DeviceTrafficStore:
    """
    Thread-safe per-device packet store with VPN/normal separation.

    Usage:
        store.ingest(pkt)                         → add a packet
        store.get_normal(ip, limit=50)            → normal traffic
        store.get_vpn(ip, limit=50)               → VPN traffic
        store.get_summary(ip)                     → stats dict
        store.get_all_device_ips()                → list of known IPs
    """

    def __init__(self):
        self._normal: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_PACKETS_PER_DEVICE)
        )
        self._vpn:    Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_PACKETS_PER_DEVICE)
        )
        self._stats:  Dict[str, dict]  = defaultdict(lambda: {
            "normal_count": 0, "vpn_count": 0,
            "total_bytes": 0,  "vpn_bytes": 0,
            "first_seen": "", "last_seen": "",
            "top_dsts": defaultdict(int),
            "protocols": defaultdict(int),
        })
        self._lock = threading.Lock()

    # ─── ingestion ────────────────────────────────────────────────────────────

    def ingest(self, pkt: dict) -> None:
        """
        Classify a packet as VPN or normal and store it under its source IP.
        Also stores under dst IP if the dst is a known device (reply traffic).
        """
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        if not src or ":" in src:   # skip empty / MAC-only
            return

        is_vpn = self._classify_vpn(pkt)
        now    = datetime.now(tz=timezone.utc).isoformat()
        # Strip bytes (_raw_payload etc.) before storing — prevents JSON errors
        clean  = sanitize(pkt)
        entry  = {**clean, "is_vpn": is_vpn, "captured_at": now}

        with self._lock:
            self._store(src, entry, is_vpn, now)

    def _store(self, ip: str, entry: dict, is_vpn: bool, now: str) -> None:
        if is_vpn:
            self._vpn[ip].append(entry)
            self._stats[ip]["vpn_count"]  += 1
            self._stats[ip]["vpn_bytes"]  += entry.get("length", 0)
        else:
            self._normal[ip].append(entry)
            self._stats[ip]["normal_count"] += 1

        self._stats[ip]["total_bytes"] += entry.get("length", 0)
        if not self._stats[ip]["first_seen"]:
            self._stats[ip]["first_seen"] = now
        self._stats[ip]["last_seen"] = now

        dst = entry.get("dst_ip", "")
        if dst:
            self._stats[ip]["top_dsts"][dst] += 1

        proto = entry.get("protocol", "unknown").upper()
        self._stats[ip]["protocols"][proto] += 1

    # ─── retrieval ────────────────────────────────────────────────────────────

    def get_normal(self, ip: str, limit: int = 100) -> List[dict]:
        with self._lock:
            pkts = list(self._normal.get(ip, []))
        return pkts[-limit:]

    def get_vpn(self, ip: str, limit: int = 100) -> List[dict]:
        with self._lock:
            pkts = list(self._vpn.get(ip, []))
        return pkts[-limit:]

    def get_summary(self, ip: str) -> dict:
        with self._lock:
            s = dict(self._stats.get(ip, {}))
        if not s:
            return {
                "ip": ip,
                "normal_count": 0, "vpn_count": 0,
                "total_bytes": 0,  "vpn_bytes": 0,
                "first_seen": "", "last_seen": "",
                "top_dsts": [], "protocols": {},
            }
        # Serialize top_dsts to sorted list
        top_dsts = sorted(
            s.get("top_dsts", {}).items(),
            key=lambda x: x[1], reverse=True
        )[:5]
        return {
            "ip":           ip,
            "normal_count": s["normal_count"],
            "vpn_count":    s["vpn_count"],
            "total_bytes":  s["total_bytes"],
            "vpn_bytes":    s["vpn_bytes"],
            "first_seen":   s["first_seen"],
            "last_seen":    s["last_seen"],
            "top_dsts":     [{"ip": d, "count": c} for d, c in top_dsts],
            "protocols":    dict(s.get("protocols", {})),
        }

    def get_all_device_ips(self) -> List[str]:
        with self._lock:
            ips = set(self._normal.keys()) | set(self._vpn.keys())
        return sorted(ips)

    # ─── VPN classification ───────────────────────────────────────────────────

    @staticmethod
    def _classify_vpn(pkt: dict) -> bool:
        """
        Returns True if this packet is part of a VPN tunnel.
        Uses port numbers and protocol patterns.
        """
        dst_port = pkt.get("dst_port", 0)
        src_port = pkt.get("src_port", 0)
        proto    = pkt.get("protocol", "").upper()

        # Direct port match
        if dst_port in _VPN_PORTS or src_port in _VPN_PORTS:
            return True

        # WireGuard packet size signature (UDP with specific sizes)
        if proto == "UDP" and pkt.get("length", 0) in (148, 92, 64, 80, 96):
            return True

        # IKEv2 uses UDP 500/4500 — already covered above
        # IPSec ESP is IP protocol 50, AH is 51
        if proto in ("ESP", "AH"):
            return True

        # Tailscale CGNAT addresses
        dst_ip = pkt.get("dst_ip", "")
        if dst_ip.startswith("100.") and proto == "UDP":
            return True

        return False
