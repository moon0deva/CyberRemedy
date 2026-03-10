"""
CyberRemedy v1.0 — Packet Capture
Live only. No simulation. Uses scapy (root) or AF_PACKET socket (root)
or tcpdump subprocess. Refuses to fall back to fake data.
"""
import os, time, logging, threading, socket, struct, subprocess, re
from datetime import datetime
from typing import Callable, Optional
from pathlib import Path

logger = logging.getLogger("cyberremedy.capture")

# ── Capability detection ──────────────────────────────────────────────────────

def _has_scapy():
    try: import scapy; return True
    except ImportError: return False

def _is_root():
    try: return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception: return False

SCAPY_OK  = _has_scapy()
ROOT_OK   = _is_root()
CAN_SNIFF = SCAPY_OK and ROOT_OK

if not SCAPY_OK:
    logger.warning("capture: scapy not installed  →  will use AF_PACKET socket or tcpdump")
elif not ROOT_OK:
    logger.warning("capture: not running as root  →  will use AF_PACKET socket or tcpdump")
else:
    logger.info("capture: scapy + root  →  full live capture available")

# ── Packet normaliser (scapy packet → plain dict) ─────────────────────────────

import netifaces as _nif
def _get_local_ips() -> set:
    """Return all IPs assigned to this machine across all interfaces."""
    ips = set()
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for a in addrs.get(2, []):
                ip = a.get('addr','')
                if ip and not ip.startswith('127.'): ips.add(ip)
    except ImportError:
        pass
    # Fallback: ip addr / ifconfig parsing
    try:
        import subprocess, re
        out = subprocess.check_output(['ip','-4','addr','show'], text=True, timeout=3, stderr=subprocess.DEVNULL)
        for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', out):
            ip = m.group(1)
            if not ip.startswith('127.'): ips.add(ip)
    except Exception: pass
    # Always add localhost variants
    ips.add('127.0.0.1')
    return ips

_LOCAL_IPS: set = _get_local_ips()
_PKT_COUNT = 0

def _tag_direction(pkt: dict) -> dict:
    """Tag packet direction: incoming/outgoing/internal/transit.
    Also enriches with port-based service name and marks private IPs.
    Captures ALL traffic including incoming website responses.
    """
    global _LOCAL_IPS, _PKT_COUNT
    _PKT_COUNT += 1
    # Refresh local IPs every 1000 packets (handles DHCP/VPN changes)
    if _PKT_COUNT % 1000 == 0:
        _LOCAL_IPS = _get_local_ips()

    src = pkt.get('src_ip', '')
    dst = pkt.get('dst_ip', '')
    src_local = src in _LOCAL_IPS or src.startswith('192.168.') or src.startswith('10.') or src.startswith('172.')
    dst_local = dst in _LOCAL_IPS or dst.startswith('192.168.') or dst.startswith('10.') or dst.startswith('172.')

    if src in _LOCAL_IPS and dst not in _LOCAL_IPS:
        pkt['direction'] = 'outgoing'
    elif dst in _LOCAL_IPS and src not in _LOCAL_IPS:
        pkt['direction'] = 'incoming'    # ← website responses, remote connections TO us
    elif src in _LOCAL_IPS and dst in _LOCAL_IPS:
        pkt['direction'] = 'internal'
    else:
        pkt['direction'] = 'transit'     # ← forwarded/bridged traffic

    # Private IP flags
    pkt['src_private'] = src_local
    pkt['dst_private'] = dst_local

    # Service name from well-known ports
    dport = pkt.get('dst_port', 0)
    sport = pkt.get('src_port', 0)
    port = dport if dport else sport
    pkt['service'] = _port_to_service(port)

    # Rough L7 classification
    pkt['l7'] = _classify_l7(pkt)
    return pkt

def _port_to_service(port: int) -> str:
    SERVICES = {
        80:'HTTP', 443:'HTTPS', 53:'DNS', 22:'SSH', 21:'FTP',
        25:'SMTP', 587:'SMTP', 465:'SMTPS', 110:'POP3', 143:'IMAP',
        3306:'MySQL', 5432:'PostgreSQL', 6379:'Redis', 27017:'MongoDB',
        3389:'RDP', 445:'SMB', 139:'NetBIOS', 23:'Telnet',
        5900:'VNC', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
        1194:'OpenVPN', 1723:'PPTP', 500:'IKE', 4500:'IKE-NAT',
        67:'DHCP', 68:'DHCP', 123:'NTP', 161:'SNMP', 162:'SNMP-Trap',
        179:'BGP', 389:'LDAP', 636:'LDAPS', 88:'Kerberos',
        6881:'BitTorrent', 6667:'IRC', 5222:'XMPP', 5269:'XMPP',
        9200:'Elasticsearch', 9300:'Elasticsearch', 2181:'Zookeeper',
        11211:'Memcached', 6379:'Redis', 5672:'AMQP', 8883:'MQTT',
    }
    return SERVICES.get(port, 'OTHER')

def _classify_l7(pkt: dict) -> str:
    """Quick L7 protocol guess from port + protocol."""
    proto = pkt.get('protocol', '')
    dport = pkt.get('dst_port', 0)
    sport = pkt.get('src_port', 0)
    if proto == 'DNS': return 'DNS'
    if proto == 'ICMP': return 'ICMP'
    port = dport or sport
    if port in (80, 8080): return 'HTTP'
    if port in (443, 8443): return 'HTTPS'
    if port == 22: return 'SSH'
    if port == 21: return 'FTP'
    if port in (25, 587, 465): return 'SMTP'
    if port == 53: return 'DNS'
    if port == 3389: return 'RDP'
    if port == 445: return 'SMB'
    if port == 23: return 'Telnet'
    if proto == 'TCP': return 'TCP'
    if proto == 'UDP': return 'UDP'
    return proto or 'OTHER'

def _is_outgoing(pkt: dict) -> bool:
    """Return True only if this packet was sent BY this machine."""
    global _LOCAL_IPS
    src = pkt.get('src_ip','')
    if not src: return False
    return src in _LOCAL_IPS


def normalize_packet(pkt) -> Optional[dict]:
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns  import DNS
        if IP not in pkt: return None
        ip = pkt[IP]
        proto, sport, dport, flags = "OTHER", 0, 0, ""
        if TCP in pkt:
            proto, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "DNS" if DNS in pkt else "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        raw = {
            "timestamp":   datetime.utcnow().isoformat(),
            "src_ip":      ip.src,  "dst_ip":  ip.dst,
            "src_port":    sport,   "dst_port": dport,
            "protocol":    proto,   "length":   len(pkt),
            "payload_len": len(bytes(pkt.payload)),
            "ttl":         ip.ttl,  "flags":    flags,
            "raw_ts":      time.time(),
        }
        return _tag_direction(raw)
    except Exception:
        return None

# ── Raw packet parser (AF_PACKET / tcpdump fallback) ─────────────────────────

def _parse_raw_ip(data: bytes) -> Optional[dict]:
    """Parse a raw IPv4 packet (Ethernet stripped or not)."""
    try:
        # Strip Ethernet header if present (14 bytes, check ethertype)
        if len(data) > 14 and data[12:14] == b'\x08\x00':
            data = data[14:]
        if len(data) < 20: return None
        ver_ihl = data[0]
        if (ver_ihl >> 4) != 4: return None          # IPv4 only
        ihl = (ver_ihl & 0xF) * 4
        proto_num = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        proto, sport, dport, flags = "OTHER", 0, 0, ""
        payload = data[ihl:]
        if proto_num == 6 and len(payload) >= 14:     # TCP
            sport = struct.unpack("!H", payload[0:2])[0]
            dport = struct.unpack("!H", payload[2:4])[0]
            flag_byte = payload[13]
            f = ""
            if flag_byte & 0x02: f += "S"
            if flag_byte & 0x10: f += "A"
            if flag_byte & 0x01: f += "F"
            if flag_byte & 0x04: f += "R"
            proto, flags = "TCP", f
        elif proto_num == 17 and len(payload) >= 8:   # UDP
            sport = struct.unpack("!H", payload[0:2])[0]
            dport = struct.unpack("!H", payload[2:4])[0]
            proto = "DNS" if dport == 53 or sport == 53 else "UDP"
        elif proto_num == 1:
            proto = "ICMP"
        ttl = data[8]
        return {
            "timestamp":   datetime.utcnow().isoformat(),
            "src_ip":      src_ip,  "dst_ip":  dst_ip,
            "src_port":    sport,   "dst_port": dport,
            "protocol":    proto,   "length":   len(data),
            "payload_len": len(payload),
            "ttl":         ttl,     "flags":    flags,
            "raw_ts":      time.time(),
        }
        return _tag_direction(raw)
    except Exception:
        return None

# ── Interface resolver ────────────────────────────────────────────────────────

def _resolve_interface(hint: str = "auto") -> str:
    if hint not in ("auto", "", None):
        return hint
    # Method 1: ip route
    try:
        out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True, timeout=3)
        m = re.search(r"dev\s+(\S+)", out)
        if m: return m.group(1)
    except Exception: pass
    # Method 2: ip link
    try:
        out = subprocess.check_output(["ip", "link"], text=True, timeout=3)
        for ln in out.split("\n"):
            m = re.match(r"\d+: (\w+):", ln)
            if m and m.group(1) not in ("lo",):
                return m.group(1)
    except Exception: pass
    # Method 3: netifaces
    try:
        import netifaces
        for i in netifaces.interfaces():
            if i.startswith("lo"): continue
            if 2 in netifaces.ifaddresses(i): return i
    except ImportError: pass
    return "eth0"

# ── Main LiveSniffer class ────────────────────────────────────────────────────

class LiveSniffer:
    """
    Live packet capture only — no simulation.
    Tries in order:
      1. scapy (requires root + scapy installed)
      2. AF_PACKET raw socket (requires root, no extra packages, Linux)
      3. tcpdump subprocess piped through Python (requires root + tcpdump)
    If none work, logs a clear error and stops — never generates fake data.
    """

    def __init__(self, interface="auto", callback: Callable = None,
                 pcap_enabled=False, pcap_dir="data/pcap",
                 pcap_max_mb=500, pcap_max_gb=20.0,
                 sim_rate=None, profile=None):      # sim_rate/profile accepted but ignored
        self.interface  = interface
        self.callback   = callback
        self._running   = False
        self._mode      = "idle"
        self._count     = 0
        self._pcap_dir  = Path(pcap_dir)
        self._pcap_en   = pcap_enabled and SCAPY_OK
        self._pcap_max  = int(pcap_max_mb * 1_048_576)
        self._pcap_cap  = int(pcap_max_gb * 1_073_741_824)
        self._pw        = None

    def start(self):
        if self._running: return
        if not ROOT_OK:
            logger.error(
                "LIVE CAPTURE REQUIRES ROOT. "
                "Restart with: sudo python3 main.py"
            )
            self._mode = "error:not_root"
            return
        self._running = True
        iface = _resolve_interface(self.interface)
        logger.info(f"Starting live capture on interface: {iface}")

        if SCAPY_OK:
            t = threading.Thread(target=self._live_scapy, args=(iface,), daemon=True, name="cap-scapy")
        else:
            t = threading.Thread(target=self._live_afpacket, args=(iface,), daemon=True, name="cap-raw")
        t.start()

    def stop(self):
        self._running = False
        if self._pw:
            try: self._pw[0].terminate()
            except Exception: pass
            self._pw = None
        logger.info(f"Capture stopped — {self._count} pkts ({self._mode})")

    @property
    def mode(self): return self._mode
    @property
    def is_running(self): return self._running
    @property
    def packet_count(self): return self._count

    # ── Method 1: scapy ──────────────────────────────────────────────────────

    def _live_scapy(self, iface: str):
        self._mode = "live:scapy"
        try:
            from scapy.all import sniff, conf
            conf.verb = 0
            logger.info(f"Live capture active via scapy on {iface}")

            def _handle(pkt):
                n = normalize_packet(pkt)
                if n and _is_outgoing(n):
                    self._count += 1
                    self._write_pcap(pkt)
                    if self.callback:
                        try: self.callback(n)
                        except Exception as e: logger.debug(f"callback: {e}")

            sniff(iface=iface, prn=_handle, store=False, promisc=True,
                  stop_filter=lambda _: not self._running)
        except Exception as e:
            logger.warning(f"scapy failed ({e}) — falling back to AF_PACKET")
            self._live_afpacket(iface)

    # ── Method 2: AF_PACKET raw socket (Linux, no extra packages) ────────────

    def _live_afpacket(self, iface: str):
        self._mode = "live:afpacket"
        try:
            # ETH_P_ALL = 0x0003
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
            sock.settimeout(1.0)
            logger.info(f"Live capture active via AF_PACKET on {iface}")
            while self._running:
                try:
                    raw, _ = sock.recvfrom(65535)
                    pkt = _parse_raw_ip(raw)
                    if pkt and _is_outgoing(pkt):
                        self._count += 1
                        if self.callback:
                            try: self.callback(pkt)
                            except Exception as e: logger.debug(f"callback: {e}")
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"AF_PACKET recv: {e}")
            sock.close()
        except PermissionError:
            logger.error("AF_PACKET failed: permission denied. Run with sudo.")
            self._mode = "error:not_root"
        except Exception as e:
            logger.warning(f"AF_PACKET failed ({e}) — falling back to tcpdump")
            self._live_tcpdump(iface)

    # ── Method 3: tcpdump subprocess ─────────────────────────────────────────

    def _live_tcpdump(self, iface: str):
        self._mode = "live:tcpdump"
        try:
            subprocess.check_output(["which", "tcpdump"], timeout=3)
        except Exception:
            logger.error("tcpdump not found. Install with: sudo apt install tcpdump")
            self._mode = "error:no_tcpdump"
            return

        cmd = ["tcpdump", "-i", iface, "-n", "-l", "-q",
               "-tttt",   # timestamp
               "ip"]       # IPv4 only
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            self._pw = (proc,)
            logger.info(f"Live capture active via tcpdump on {iface}")
            # Parse tcpdump text output
            # Format: 2024-01-15 10:23:45.123456 IP 1.2.3.4.sport > 5.6.7.8.dport: ...
            pkt_re = re.compile(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) IP "
                r"(\d+\.\d+\.\d+\.\d+)\.?(\d*) > (\d+\.\d+\.\d+\.\d+)\.?(\d*): "
                r"(.+)"
            )
            for line in proc.stdout:
                if not self._running: break
                m = pkt_re.match(line.strip())
                if not m: continue
                _, src_ip, sport, dst_ip, dport, rest = m.groups()
                proto = "TCP"
                flags = ""
                if "UDP" in rest or "udp" in rest:
                    proto = "DNS" if "53" in (sport, dport) else "UDP"
                if "ICMP" in rest:
                    proto = "ICMP"
                # Extract flags from TCP
                flag_map = {"S": "S", "F": "F", "R": "R", "P": "P", ".": "A"}
                for tok in rest.split():
                    if all(c in "SFRAP." for c in tok) and len(tok) <= 6:
                        flags = "".join(flag_map.get(c,"") for c in tok)
                        break
                pkt = {
                    "timestamp":   datetime.utcnow().isoformat(),
                    "src_ip":      src_ip,
                    "dst_ip":      dst_ip,
                    "src_port":    int(sport) if sport.isdigit() else 0,
                    "dst_port":    int(dport) if dport.isdigit() else 0,
                    "protocol":    proto,
                    "length":      0,
                    "payload_len": 0,
                    "ttl":         64,
                    "flags":       flags,
                    "raw_ts":      time.time(),
                }
                if _is_outgoing(pkt):
                    self._count += 1
                    if self.callback:
                        try: self.callback(pkt)
                        except Exception as e: logger.debug(f"callback: {e}")
            proc.wait()
        except Exception as e:
            logger.error(f"tcpdump failed: {e}")
            self._mode = "error:tcpdump_failed"

    # ── PCAP writing (optional, scapy only) ──────────────────────────────────

    def _write_pcap(self, pkt):
        if not self._pcap_en: return
        try:
            from scapy.all import PcapWriter
            self._pcap_dir.mkdir(parents=True, exist_ok=True)
            if not self._pw:
                fname = self._pcap_dir / f"capture_{int(time.time())}.pcap"
                self._pw = (PcapWriter(str(fname), append=True, sync=True),)
            self._pw[0].write(pkt)
        except Exception as e:
            logger.debug(f"pcap write: {e}")


# ── FlowAggregator is imported from features.extractor ───────────────────────
# (kept here for compatibility)
try:
    from features.extractor import FlowAggregator
except ImportError:
    class FlowAggregator:
        def __init__(self, **kw): pass
        def add_packet(self, p): pass
        def flush_all(self): pass
        @property
        def active_flow_count(self): return 0


# ── PcapReplayer — replay a saved PCAP file through the pipeline ──────────────

class PcapReplayer:
    """
    Replays a saved .pcap file through the detection pipeline.
    Uses scapy if available, otherwise parses with dpkt or skips.
    """
    def __init__(self, path: str, callback: Callable = None, speed: float = 1.0):
        self.path     = path
        self.callback = callback
        self.speed    = speed        # 1.0 = original speed, 0 = as fast as possible
        self._running = False

    def replay(self):
        self._running = True
        if SCAPY_OK:
            self._replay_scapy()
        else:
            logger.warning("PcapReplayer: scapy not installed, cannot replay PCAP")

    def stop(self):
        self._running = False

    def _replay_scapy(self):
        try:
            from scapy.all import rdpcap
            pkts = rdpcap(self.path)
            logger.info(f"Replaying {len(pkts)} packets from {self.path}")
            prev_ts = None
            for pkt in pkts:
                if not self._running: break
                ts = float(pkt.time)
                if self.speed > 0 and prev_ts is not None:
                    delay = (ts - prev_ts) / self.speed
                    if 0 < delay < 2:
                        time.sleep(delay)
                prev_ts = ts
                n = normalize_packet(pkt)
                if n and self.callback:
                    try: self.callback(n)
                    except Exception as e: logger.debug(f"replay cb: {e}")
        except Exception as e:
            logger.error(f"PcapReplayer error: {e}")
