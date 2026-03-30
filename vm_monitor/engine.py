"""
CyberRemedy — VM Traffic Monitor
=================================
Agentless monitoring of a VirtualBox VM running in Bridged mode on a
remote laptop (Laptop B) from Laptop A (running CyberRemedy).

How it works (no agent required on Laptop B or inside the VM):
──────────────────────────────────────────────────────────────
  Topology:
      WiFi Router ─── Laptop A (CyberRemedy, Linux)
                  └── Laptop B → VirtualBox (Bridged) → VM (Linux)

  Since the VM is in Bridged mode it gets its own IP on the WiFi.
  We use ARP poisoning to intercept all VM traffic:

  Step 1 — DISCOVER
    ARP-scan the local subnet to find all devices.
    Detect VMs by their MAC OUI (VirtualBox = 08:00:27:xx:xx:xx).
    Let the user pick which IP is the target VM.

  Step 2 — POISON
    Send spoofed ARP replies to the VM:
        "The router's MAC is MY MAC"  → VM sends all packets to us
    Send spoofed ARP replies to the router:
        "The VM's MAC is MY MAC"      → router sends responses to us
    Enable IP forwarding so traffic still reaches its destination.

  Step 3 — INTERCEPT & ANALYSE
    Capture all forwarded packets.
    Parse: protocol, ports, payload size, direction, L7 fingerprint.
    Feed into CyberRemedy's detection pipeline (alerts, MITRE, scoring).
    Buffer last 500 flows for the dashboard.

  Step 4 — RESTORE
    On stop: send correct ARP entries to both VM and router.
    IP forwarding reverted.

Dependencies:
    scapy  (pip install scapy)   ← required for ARP poisoning
    root / sudo                  ← required for raw sockets

Fallback (no scapy):
    Passive AF_PACKET sniff — sees broadcast + unicast to Laptop A only.
    No ARP poisoning. Partial visibility (router-forwarded packets only).
"""

import logging
import os
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("cyberremedy.vm_monitor")

# ── Capability detection ───────────────────────────────────────────────────────

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, ICMP, DNS, Raw,
        srp, sendp, sniff, get_if_hwaddr, get_if_addr,
        conf as scapy_conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.warning("[VMMonitor] scapy not installed — ARP MITM disabled, passive mode only")

ROOT_OK = os.geteuid() == 0 if hasattr(os, "geteuid") else False

# VirtualBox MAC OUI prefixes (Bridged VMs always use these)
VBOX_OUIS = {
    "08:00:27",  # VirtualBox default
    "0a:00:27",  # VirtualBox host-only (rare in bridged)
    "52:54:00",  # QEMU/KVM (also appears in VBox sometimes)
}

# Known hypervisor/cloud OUIs for VM fingerprinting
HYPERVISOR_OUIS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "0a:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3e": "Xen",
    "00:1c:42": "Parallels",
    "00:15:5d": "Hyper-V",
}

# L7 port fingerprinting
L7_PORTS = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
    23: "Telnet", 25: "SMTP", 587: "SMTP", 53: "DNS",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 3389: "RDP", 445: "SMB", 139: "NetBIOS",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 5000: "Flask",
    8000: "Django/FastAPI", 9200: "Elasticsearch", 5601: "Kibana",
}


# ── ARP helpers ───────────────────────────────────────────────────────────────

def _get_mac(ip: str, iface: str, timeout: int = 2) -> str:
    """Resolve IP → MAC via ARP request. Returns '' on failure."""
    if not SCAPY_OK:
        return ""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=timeout, verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc.lower()
    except Exception as e:
        logger.debug(f"[VMMonitor] ARP resolve {ip}: {e}")
    return ""


def _get_gateway(iface: str) -> tuple:
    """Return (gateway_ip, gateway_mac). Uses 'ip route' then ARP."""
    gw_ip = ""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "dev", iface],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    gw_ip = parts[parts.index("via") + 1]
                    break
    except Exception:
        pass

    if not gw_ip:
        # fallback: first hop via socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            gw_ip = ".".join(local_ip.split(".")[:3]) + ".1"
        except Exception:
            return "", ""

    gw_mac = _get_mac(gw_ip, iface)
    return gw_ip, gw_mac


def _get_local_ip(iface: str) -> str:
    """Get Laptop A's IP on the given interface."""
    try:
        if SCAPY_OK:
            return get_if_addr(iface) or ""
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            text=True, timeout=3, stderr=subprocess.DEVNULL,
        )
        import re
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _subnet_scan(iface: str, subnet: str = None, timeout: int = 3) -> List[dict]:
    """
    ARP-scan the subnet and return list of {ip, mac, vendor, is_vm}.
    subnet: e.g. '192.168.1.0/24' — auto-detected if None.
    """
    if not SCAPY_OK or not ROOT_OK:
        # Fallback: parse ARP table
        return _arp_table_scan()

    if not subnet:
        local_ip = _get_local_ip(iface)
        if not local_ip:
            return []
        # Assume /24
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"

    logger.info(f"[VMMonitor] ARP scanning {subnet} on {iface}...")
    devices = []
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=iface, timeout=timeout, verbose=False,
        )
        for _, rcv in ans:
            ip  = rcv.psrc
            mac = rcv.hwsrc.lower()
            oui = ":".join(mac.split(":")[:3])
            vendor = HYPERVISOR_OUIS.get(oui, _oui_vendor(oui))
            is_vm  = oui in HYPERVISOR_OUIS
            hostname = _try_reverse_dns(ip)
            devices.append({
                "ip":       ip,
                "mac":      mac,
                "vendor":   vendor,
                "is_vm":    is_vm,
                "hostname": hostname,
                "oui":      oui,
            })
    except Exception as e:
        logger.warning(f"[VMMonitor] ARP scan failed: {e}")

    logger.info(f"[VMMonitor] Found {len(devices)} devices ({sum(1 for d in devices if d['is_vm'])} VMs)")
    return devices


def _arp_table_scan() -> List[dict]:
    """Fallback: read kernel ARP table (no scapy needed)."""
    devices = []
    try:
        out = subprocess.check_output(["arp", "-n"], text=True, timeout=5)
        import re
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "(incomplete)":
                ip  = parts[0]
                mac = parts[2].lower()
                oui = ":".join(mac.split(":")[:3])
                vendor  = HYPERVISOR_OUIS.get(oui, "")
                is_vm   = oui in HYPERVISOR_OUIS
                devices.append({"ip": ip, "mac": mac, "vendor": vendor,
                                 "is_vm": is_vm, "hostname": "", "oui": oui})
    except Exception:
        pass
    return devices


def _try_reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _oui_vendor(oui: str) -> str:
    """Very small OUI lookup for common vendors."""
    OUI_MAP = {
        "00:50:56": "VMware",  "00:0c:29": "VMware",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU",
        "00:15:5d": "Hyper-V", "00:1c:42": "Parallels",
        "d4:be:d9": "Apple",   "3c:22:fb": "Apple",
        "00:1a:11": "Google",  "b8:27:eb": "Raspberry Pi",
    }
    return OUI_MAP.get(oui, "Unknown")


# ── IP forwarding ─────────────────────────────────────────────────────────────

def _enable_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        logger.info("[VMMonitor] IP forwarding ENABLED")
    except Exception as e:
        logger.warning(f"[VMMonitor] Could not enable IP forwarding: {e}")


def _disable_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        logger.info("[VMMonitor] IP forwarding DISABLED")
    except Exception as e:
        logger.warning(f"[VMMonitor] Could not disable IP forwarding: {e}")


# ── Packet parser ─────────────────────────────────────────────────────────────

def _parse_packet(pkt, target_ip: str, gateway_ip: str, my_ip: str) -> Optional[dict]:
    """
    Parse a scapy packet into a CyberRemedy-compatible flow dict.
    Only returns packets belonging to the target VM.
    """
    if not pkt.haslayer(IP):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst

    # Only process VM traffic (src or dst is the target)
    if src != target_ip and dst != target_ip:
        return None

    proto = pkt[IP].proto
    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

    src_port = dst_port = 0
    flags = ""
    payload_size = 0
    l7 = ""

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
        l7 = L7_PORTS.get(dst_port) or L7_PORTS.get(src_port, "")
        if pkt.haslayer(Raw):
            payload_size = len(bytes(pkt[Raw]))
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        l7 = L7_PORTS.get(dst_port) or L7_PORTS.get(src_port, "")
        if pkt.haslayer(Raw):
            payload_size = len(bytes(pkt[Raw]))
    elif pkt.haslayer(ICMP):
        proto_name = "ICMP"

    direction = "outbound" if src == target_ip else "inbound"
    size = len(pkt)

    # DNS query extraction
    dns_query = ""
    if pkt.haslayer(DNS) and pkt[DNS].qd:
        try:
            dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            pass

    return {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "src_ip":       src,
        "dst_ip":       dst,
        "src_port":     src_port,
        "dst_port":     dst_port,
        "protocol":     proto_name,
        "l7":           l7,
        "direction":    direction,
        "size":         size,
        "payload_size": payload_size,
        "flags":        flags,
        "dns_query":    dns_query,
        "ttl":          pkt[IP].ttl,
        "via_mitm":     True,
    }


# ── Main VM Monitor class ──────────────────────────────────────────────────────

class VMTrafficMonitor:
    """
    Monitors all network traffic of a VirtualBox VM (Bridged mode)
    from Laptop A without any agent on Laptop B or inside the VM.

    Usage:
        mon = VMTrafficMonitor(iface="wlan0", packet_callback=my_cb, alert_callback=my_alert)
        mon.start(target_ip="192.168.1.105")
        ...
        mon.stop()
    """

    def __init__(
        self,
        iface:            str = "auto",
        packet_callback:  Optional[Callable] = None,
        alert_callback:   Optional[Callable] = None,
    ):
        self.iface           = iface
        self._pkt_cb         = packet_callback
        self._alert_cb       = alert_callback

        self._target_ip      = ""
        self._target_mac     = ""
        self._gateway_ip     = ""
        self._gateway_mac    = ""
        self._my_ip          = ""
        self._my_mac         = ""

        self._running        = False
        self._poison_thread  = None
        self._sniff_thread   = None

        self._packets        = deque(maxlen=500)   # rolling packet log
        self._flows: Dict[str, dict] = {}          # active flow aggregation
        self._completed_flows = deque(maxlen=200)  # finished flows

        self._stats = defaultdict(int)
        self._stats.update({
            "packets_intercepted": 0,
            "bytes_intercepted":   0,
            "flows_total":         0,
            "dns_queries":         0,
            "alerts_generated":    0,
            "start_time":          None,
            "mode":                "stopped",
        })
        self._error = ""
        self._scan_cache: List[dict] = []
        self._lock = threading.Lock()

    # ─── Public API ──────────────────────────────────────────────────────────

    def scan_network(self, subnet: str = None) -> List[dict]:
        """
        ARP-scan the local subnet and return all devices.
        VMs are flagged with is_vm=True and vendor set to e.g. 'VirtualBox'.
        """
        iface = self._resolve_iface()
        devices = _subnet_scan(iface, subnet)
        self._scan_cache = devices
        return devices

    def start(self, target_ip: str) -> dict:
        """
        Start monitoring the specified VM IP.
        Returns {"ok": True} or {"ok": False, "error": "..."}
        """
        if self._running:
            return {"ok": False, "error": "Already running — stop first"}

        if not ROOT_OK:
            return {"ok": False, "error": "Root required — restart with: sudo python main.py"}

        self._target_ip = target_ip
        iface = self._resolve_iface()
        self.iface = iface

        # Resolve MACs
        logger.info(f"[VMMonitor] Resolving MACs for target={target_ip} on {iface}...")
        self._my_ip      = _get_local_ip(iface)
        self._my_mac     = get_if_hwaddr(iface).lower() if SCAPY_OK else ""
        self._target_mac = _get_mac(target_ip, iface)

        if not self._target_mac:
            return {"ok": False, "error": f"Could not resolve MAC for {target_ip} — is the VM reachable? Is it Bridged mode?"}

        self._gateway_ip, self._gateway_mac = _get_gateway(iface)
        if not self._gateway_ip:
            return {"ok": False, "error": "Could not determine gateway IP"}
        if not self._gateway_mac:
            self._gateway_mac = _get_mac(self._gateway_ip, iface)

        logger.info(f"[VMMonitor] Target:  {target_ip} ({self._target_mac})")
        logger.info(f"[VMMonitor] Gateway: {self._gateway_ip} ({self._gateway_mac})")
        logger.info(f"[VMMonitor] My MAC:  {self._my_mac} / {self._my_ip}")

        _enable_ip_forward()

        self._running = True
        self._stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self._stats["mode"] = "mitm" if SCAPY_OK else "passive"

        if SCAPY_OK:
            self._poison_thread = threading.Thread(
                target=self._poison_loop, daemon=True, name="vm-poison"
            )
            self._poison_thread.start()

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="vm-sniff"
        )
        self._sniff_thread.start()

        mode = "ARP MITM (full intercept)" if SCAPY_OK else "passive (partial visibility)"
        logger.info(f"[VMMonitor] Started in {mode} mode")
        return {
            "ok":         True,
            "target_ip":  target_ip,
            "target_mac": self._target_mac,
            "gateway_ip": self._gateway_ip,
            "iface":      iface,
            "mode":       self._stats["mode"],
            "message":    f"Monitoring VM {target_ip} via {mode}",
        }

    def stop(self) -> dict:
        """Stop monitoring and restore ARP caches."""
        if not self._running:
            return {"ok": False, "error": "Not running"}

        self._running = False

        # Restore ARP caches (send correct entries 5×)
        if SCAPY_OK and self._target_mac and self._gateway_mac:
            logger.info("[VMMonitor] Restoring ARP caches...")
            try:
                for _ in range(5):
                    # Restore VM: tell it the real gateway MAC
                    sendp(
                        Ether(dst=self._target_mac) /
                        ARP(op=2, pdst=self._target_ip, hwdst=self._target_mac,
                            psrc=self._gateway_ip, hwsrc=self._gateway_mac),
                        iface=self.iface, verbose=False,
                    )
                    # Restore gateway: tell it the real VM MAC
                    sendp(
                        Ether(dst=self._gateway_mac) /
                        ARP(op=2, pdst=self._gateway_ip, hwdst=self._gateway_mac,
                            psrc=self._target_ip, hwsrc=self._target_mac),
                        iface=self.iface, verbose=False,
                    )
                    time.sleep(0.2)
            except Exception as e:
                logger.warning(f"[VMMonitor] ARP restore error: {e}")

        _disable_ip_forward()
        self._stats["mode"] = "stopped"
        logger.info("[VMMonitor] Stopped")
        return {"ok": True, "stats": dict(self._stats)}

    def get_packets(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return list(self._packets)[-limit:]

    def get_flows(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return list(self._completed_flows)[-limit:]

    def get_active_flows(self) -> List[dict]:
        with self._lock:
            return list(self._flows.values())

    def status(self) -> dict:
        return {
            "running":     self._running,
            "target_ip":   self._target_ip,
            "target_mac":  self._target_mac,
            "gateway_ip":  self._gateway_ip,
            "iface":       self.iface,
            "mode":        self._stats["mode"],
            "scapy_ok":    SCAPY_OK,
            "root_ok":     ROOT_OK,
            "stats":       dict(self._stats),
            "error":       self._error,
            "scan_cache":  self._scan_cache,
        }

    # ─── Internal: ARP poison loop ────────────────────────────────────────────

    def _poison_loop(self):
        """
        Continuously re-poison ARP caches every 1.5s.
        Must keep going — caches expire and correct entries re-appear.
        """
        logger.info("[VMMonitor] Poison loop started")
        while self._running:
            try:
                # Tell VM: "the gateway is at MY MAC"
                sendp(
                    Ether(dst=self._target_mac) /
                    ARP(op=2, pdst=self._target_ip, hwdst=self._target_mac,
                        psrc=self._gateway_ip, hwsrc=self._my_mac),
                    iface=self.iface, verbose=False,
                )
                # Tell gateway: "the VM is at MY MAC"
                sendp(
                    Ether(dst=self._gateway_mac) /
                    ARP(op=2, pdst=self._gateway_ip, hwdst=self._gateway_mac,
                        psrc=self._target_ip, hwsrc=self._my_mac),
                    iface=self.iface, verbose=False,
                )
            except Exception as e:
                logger.warning(f"[VMMonitor] Poison error: {e}")
            time.sleep(1.5)
        logger.info("[VMMonitor] Poison loop stopped")

    # ─── Internal: Packet sniff loop ─────────────────────────────────────────

    def _sniff_loop(self):
        """Sniff packets and process VM traffic."""
        target = self._target_ip
        iface  = self.iface

        logger.info(f"[VMMonitor] Sniff loop started on {iface} for {target}")

        if SCAPY_OK and ROOT_OK:
            try:
                sniff(
                    iface=iface,
                    filter=f"host {target}",
                    prn=self._on_packet_scapy,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
            except Exception as e:
                self._error = str(e)
                logger.error(f"[VMMonitor] Sniff error: {e}")
        else:
            self._sniff_afpacket(iface, target)

        logger.info("[VMMonitor] Sniff loop stopped")

    def _on_packet_scapy(self, pkt):
        """Called for every captured packet by scapy."""
        if not self._running:
            return
        parsed = _parse_packet(pkt, self._target_ip, self._gateway_ip, self._my_ip)
        if not parsed:
            return
        self._process(parsed, raw_len=len(pkt))

    def _sniff_afpacket(self, iface: str, target_ip: str):
        """
        Fallback sniffer using raw AF_PACKET socket.
        Partial visibility — only sees packets addressed to/from Laptop A
        (no MITM, but catches some broadcast + misdirected traffic).
        """
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            s.bind((iface, 0))
            s.settimeout(1.0)
        except Exception as e:
            self._error = f"AF_PACKET: {e}"
            return

        while self._running:
            try:
                raw = s.recv(65535)
                parsed = self._parse_raw(raw, target_ip)
                if parsed:
                    self._process(parsed, raw_len=len(raw))
            except socket.timeout:
                continue
            except Exception:
                break
        s.close()

    def _parse_raw(self, raw: bytes, target_ip: str) -> Optional[dict]:
        """Minimal IP/TCP/UDP parser for the AF_PACKET fallback."""
        if len(raw) < 34:
            return None
        # Skip Ethernet header (14 bytes)
        ip_hdr = raw[14:]
        if len(ip_hdr) < 20:
            return None
        version_ihl = ip_hdr[0]
        ihl = (version_ihl & 0x0F) * 4
        proto = ip_hdr[9]
        src = socket.inet_ntoa(ip_hdr[12:16])
        dst = socket.inet_ntoa(ip_hdr[16:20])
        if src != target_ip and dst != target_ip:
            return None
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        src_port = dst_port = 0
        transport = ip_hdr[ihl:]
        if proto in (6, 17) and len(transport) >= 4:
            src_port = struct.unpack("!H", transport[0:2])[0]
            dst_port = struct.unpack("!H", transport[2:4])[0]
        return {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "src_ip":       src,
            "dst_ip":       dst,
            "src_port":     src_port,
            "dst_port":     dst_port,
            "protocol":     proto_name,
            "l7":           L7_PORTS.get(dst_port) or L7_PORTS.get(src_port, ""),
            "direction":    "outbound" if src == target_ip else "inbound",
            "size":         len(raw),
            "payload_size": max(0, len(transport) - (20 if proto == 6 else 8)),
            "flags":        "",
            "dns_query":    "",
            "ttl":          ip_hdr[8],
            "via_mitm":     False,
        }

    # ─── Internal: process + flow aggregation ────────────────────────────────

    def _process(self, pkt: dict, raw_len: int):
        """Aggregate packet into flow, fire callback, check for anomalies."""
        with self._lock:
            self._packets.append(pkt)
            self._stats["packets_intercepted"] += 1
            self._stats["bytes_intercepted"]   += raw_len
            if pkt.get("dns_query"):
                self._stats["dns_queries"] += 1

        # Flow key: bidirectional 5-tuple
        k1 = (pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], pkt["protocol"])
        k2 = (pkt["dst_ip"], pkt["src_ip"], pkt["dst_port"], pkt["src_port"], pkt["protocol"])
        flow_key = str(min(k1, k2))

        with self._lock:
            if flow_key not in self._flows:
                self._flows[flow_key] = {
                    "flow_key":   flow_key,
                    "src_ip":     pkt["src_ip"],
                    "dst_ip":     pkt["dst_ip"],
                    "src_port":   pkt["src_port"],
                    "dst_port":   pkt["dst_port"],
                    "protocol":   pkt["protocol"],
                    "l7":         pkt["l7"],
                    "direction":  pkt["direction"],
                    "start_time": pkt["timestamp"],
                    "last_time":  pkt["timestamp"],
                    "packets":    0,
                    "bytes":      0,
                    "dns_query":  pkt.get("dns_query", ""),
                    "flags_seen": set(),
                }
            flow = self._flows[flow_key]
            flow["packets"]  += 1
            flow["bytes"]    += raw_len
            flow["last_time"] = pkt["timestamp"]
            if pkt.get("flags"):
                flow["flags_seen"].add(pkt["flags"])
            if not flow["l7"] and pkt["l7"]:
                flow["l7"] = pkt["l7"]

        # Fire packet callback into main CyberRemedy pipeline
        if self._pkt_cb:
            try:
                self._pkt_cb(pkt)
            except Exception:
                pass

        # Simple anomaly checks → alert
        self._check_anomaly(pkt)

    def _check_anomaly(self, pkt: dict):
        """Fast inline anomaly checks for VM-specific threats."""
        alerts = []

        # Unencrypted protocol on sensitive port
        if pkt["protocol"] == "TCP" and pkt["dst_port"] in (23, 21, 139):
            proto_name = {23: "Telnet", 21: "FTP", 139: "NetBIOS"}[pkt["dst_port"]]
            alerts.append({
                "type":        f"Insecure Protocol ({proto_name})",
                "severity":    "MEDIUM",
                "mitre_id":    "T1021",
                "description": f"VM using {proto_name} — unencrypted protocol",
            })

        # RDP from external
        if pkt["dst_port"] == 3389 and pkt["direction"] == "inbound":
            alerts.append({
                "type":        "RDP Access",
                "severity":    "HIGH",
                "mitre_id":    "T1021.001",
                "description": f"Inbound RDP to VM from {pkt['src_ip']}",
            })

        # Potential port scan (many SYN flags, no SYN-ACK)
        if pkt.get("flags") == "S" and pkt["dst_port"] > 1024:
            self._stats["syn_count"] = self._stats.get("syn_count", 0) + 1
            if self._stats["syn_count"] > 50:
                alerts.append({
                    "type":        "Port Scan from VM",
                    "severity":    "HIGH",
                    "mitre_id":    "T1046",
                    "description": f"VM {self._target_ip} sending high SYN volume",
                })
                self._stats["syn_count"] = 0

        # Large outbound transfer
        if pkt["direction"] == "outbound" and pkt.get("payload_size", 0) > 60000:
            alerts.append({
                "type":        "Large Data Exfil Candidate",
                "severity":    "MEDIUM",
                "mitre_id":    "T1041",
                "description": f"VM sending large payload ({pkt['payload_size']} bytes) to {pkt['dst_ip']}",
            })

        for alert in alerts:
            alert.update({
                "src_ip":    self._target_ip,
                "dst_ip":    pkt.get("dst_ip", ""),
                "dst_port":  pkt.get("dst_port", 0),
                "timestamp": pkt["timestamp"],
                "source":    "vm_monitor",
                "confidence": 75.0,
            })
            self._stats["alerts_generated"] += 1
            if self._alert_cb:
                try:
                    self._alert_cb(alert)
                except Exception:
                    pass

    # ─── Interface resolution ─────────────────────────────────────────────────

    def _resolve_iface(self) -> str:
        if self.iface and self.iface != "auto":
            return self.iface
        # Auto-detect: pick the WiFi interface (wlan0 usually)
        for candidate in ["wlan0", "wlan1", "wifi0", "en0", "eth0"]:
            try:
                out = subprocess.check_output(
                    ["ip", "link", "show", candidate],
                    stderr=subprocess.DEVNULL, text=True, timeout=2,
                )
                if "UP" in out:
                    return candidate
            except Exception:
                continue
        return "wlan0"  # last resort
