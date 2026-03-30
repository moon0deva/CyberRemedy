"""
CyberRemedy v1.2 — Packet Capture
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

try:
    import netifaces as _nif
except ImportError:
    _nif = None

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
    """Tag packet direction: outgoing/incoming/internal/monitored.
    Also enriches with port-based service name and marks private IPs.

    Directions:
      outgoing  — Laptop A sent this packet (src = local IP)
      incoming  — Laptop A received this packet (dst = local IP)
      internal  — both src and dst are local IPs (loopback/LAN-to-LAN)
      monitored — third-party traffic seen via promiscuous/monitor mode
    """
    global _LOCAL_IPS, _PKT_COUNT
    _PKT_COUNT += 1
    # Refresh local IPs every 1000 packets (handles DHCP/VPN changes)
    if _PKT_COUNT % 1000 == 0:
        _LOCAL_IPS = _get_local_ips()

    src = pkt.get('src_ip', '')
    dst = pkt.get('dst_ip', '')
    src_is_mine = src in _LOCAL_IPS
    dst_is_mine = dst in _LOCAL_IPS

    if src_is_mine and not dst_is_mine:
        pkt['direction'] = 'outgoing'      # Laptop A → internet/LAN
    elif dst_is_mine and not src_is_mine:
        pkt['direction'] = 'incoming'      # internet/LAN → Laptop A (website responses etc)
    elif src_is_mine and dst_is_mine:
        pkt['direction'] = 'internal'      # local loopback / same-machine
    else:
        # Neither src nor dst is this machine — third-party traffic seen via
        # promiscuous/monitor mode (e.g. VM traffic, other LAN hosts).
        pkt['direction'] = 'monitored'

    # Private IP flags (useful for geo / alert enrichment)
    def _is_private(ip):
        return ip.startswith(('192.168.', '10.', '172.', '127.', 'fc', 'fd'))
    pkt['src_private'] = _is_private(src) if src else False
    pkt['dst_private'] = _is_private(dst) if dst else False

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

def _is_local_traffic(pkt: dict) -> bool:
    """
    Return True if this packet involves Laptop A as either sender OR receiver.
    This is the correct filter for monitoring Laptop A's own web traffic:
      - outgoing: Laptop A → website  (src_ip in _LOCAL_IPS)
      - incoming: website → Laptop A  (dst_ip in _LOCAL_IPS)
    Previously only outgoing was captured, causing website responses,
    downloads, and all inbound connections to be silently dropped.
    """
    global _LOCAL_IPS
    src = pkt.get('src_ip', '')
    dst = pkt.get('dst_ip', '')
    return bool(src and src in _LOCAL_IPS) or bool(dst and dst in _LOCAL_IPS)


def normalize_packet(pkt) -> Optional[dict]:
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns  import DNS, DNSQR, DNSRR
        if IP not in pkt: return None
        ip = pkt[IP]
        proto, sport, dport, flags = "OTHER", 0, 0, ""

        # ── Extract raw payload bytes for entropy analysis ─────────────────
        try:
            _raw_payload = bytes(pkt[IP].payload)
        except Exception:
            _raw_payload = b""

        if TCP in pkt:
            proto  = "TCP"
            sport  = pkt[TCP].sport
            dport  = pkt[TCP].dport
            flags  = str(pkt[TCP].flags)
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if DNS in pkt:
                proto = "DNS"
            else:
                proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"

        # Extract Ethernet layer MACs if available (needed for MITM MAC-matching)
        from scapy.layers.l2 import Ether
        _src_mac = pkt[Ether].src.lower() if Ether in pkt else ""
        _dst_mac = pkt[Ether].dst.lower() if Ether in pkt else ""

        raw = {
            "timestamp":    datetime.utcnow().isoformat(),
            "captured_at":  datetime.utcnow().isoformat(),
            "src_ip":       ip.src,
            "dst_ip":       ip.dst,
            "src_mac":      _src_mac,
            "dst_mac":      _dst_mac,
            "src_port":     sport,
            "dst_port":     dport,
            "protocol":     proto,
            "length":       len(pkt),
            "payload_len":  len(_raw_payload),
            "_raw_payload": _raw_payload,          # bytes → byte-entropy in FlowRecord
            "ttl":          ip.ttl,
            "flags":        flags,
            "raw_ts":       time.time(),
        }

        # ── Full DNS field extraction ──────────────────────────────────────
        if proto == "DNS" and DNS in pkt:
            dns = pkt[DNS]
            raw["dns_id"]       = int(dns.id)
            raw["dns_qr"]       = int(dns.qr)          # 0=query, 1=response
            raw["dns_opcode"]   = int(dns.opcode)
            raw["dns_rcode"]    = int(dns.rcode)
            raw["dns_qdcount"]  = int(dns.qdcount)     # question count
            raw["dns_ancount"]  = int(dns.ancount)     # answer count

            # Extract question section
            queries = []
            try:
                q = dns.qd                             # first question record
                while q is not None and hasattr(q, "qname"):
                    name = q.qname.decode("utf-8", errors="replace").rstrip(".")
                    queries.append({
                        "name":  name,
                        "qtype": int(q.qtype),         # 1=A, 28=AAAA, 15=MX, 16=TXT…
                    })
                    q = q.payload if hasattr(q.payload, "qname") else None
            except Exception:
                pass
            raw["dns_queries"] = queries
            raw["dns_query"]   = queries[0]["name"] if queries else ""

            # Extract answer section (resolved IPs / CNAME chains)
            answers = []
            try:
                a = dns.an
                while a is not None and hasattr(a, "rrname"):
                    ans = {
                        "name":  a.rrname.decode("utf-8", errors="replace").rstrip("."),
                        "type":  int(a.type),
                        "ttl":   int(a.ttl),
                    }
                    if a.type == 1:                    # A record
                        try: ans["rdata"] = str(a.rdata)
                        except Exception: pass
                    elif a.type == 28:                 # AAAA record
                        try: ans["rdata"] = str(a.rdata)
                        except Exception: pass
                    elif a.type == 5:                  # CNAME
                        try: ans["rdata"] = a.rdata.decode("utf-8", errors="replace").rstrip(".")
                        except Exception: pass
                    elif a.type == 16:                 # TXT
                        try: ans["rdata"] = str(a.rdata)
                        except Exception: pass
                    answers.append(ans)
                    a = a.payload if hasattr(a.payload, "rrname") else None
            except Exception:
                pass
            raw["dns_answers"]  = answers
            raw["dns_resolved"] = [
                a["rdata"] for a in answers if "rdata" in a and a["type"] in (1, 28)
            ]

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
        raw = {
            "timestamp":   datetime.utcnow().isoformat(),
            "src_ip":      src_ip,  "dst_ip":  dst_ip,
            "src_port":    sport,   "dst_port": dport,
            "protocol":    proto,   "length":   len(data),
            "payload_len": len(payload),
            "ttl":         ttl,     "flags":    flags,
            "raw_ts":      time.time(),
        }
        return _tag_direction(raw)   # ← was unreachable before; now correctly called
    except Exception:
        return None

# ── Interface resolver ────────────────────────────────────────────────────────

def _resolve_interface(hint: str = "auto") -> str:
    """
    Detect the active network interface.
    Works for: home WiFi, phone hotspot (USB/WiFi), wired ethernet.
    Excludes: loopback, Tailscale (100.x), Docker bridges (172.x), VPN tun/tap.
    """
    if hint not in ("auto", "", None):
        return hint

    # Method 1: ip route get 8.8.8.8 — finds the interface on the default path
    try:
        out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"],
                                      text=True, timeout=3)
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            iface = m.group(1)
            # Accept wlan*, eth*, enp*, usb* (hotspot tethering), rndis*
            # Reject tun*, tap*, tailscale*, docker*, virbr*, lo
            if not any(iface.startswith(x) for x in
                       ("lo","tun","tap","tailscale","docker","virbr","veth","br-")):
                return iface
    except Exception:
        pass

    # Method 2: Pick first UP non-virtual interface with an inet address
    # Handles hotspot USB tethering (usb0, rndis0) and WiFi hotspot (wlan0)
    IFACE_PREF = ["wlan0","wlan1","eth0","enp","ens","usb0","rndis0","bnep0"]
    try:
        out = subprocess.check_output(["ip", "addr", "show"], text=True, timeout=3)
        blocks = re.split(r"\n(?=\d+:)", out)
        candidates = []
        for block in blocks:
            name_m = re.match(r"\d+:\s+(\w+)", block)
            if not name_m: continue
            name = name_m.group(1)
            if any(name.startswith(x) for x in
                   ("lo","tun","tap","tailscale","docker","virbr","veth","br-")):
                continue
            if "UP" not in block and "LOWER_UP" not in block:
                continue
            ip_m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", block)
            if not ip_m: continue
            ip = ip_m.group(1)
            # Skip Tailscale CGNAT range (100.64-127.x.x)
            if ip.startswith("100."): continue
            # Score by interface name preference
            score = next((i for i, p in enumerate(IFACE_PREF) if name.startswith(p)), 99)
            candidates.append((score, name, ip))
        if candidates:
            candidates.sort()
            return candidates[0][1]
    except Exception:
        pass

    # Method 3: netifaces fallback
    try:
        import netifaces
        for i in netifaces.interfaces():
            if i.startswith("lo") or i.startswith("tailscale"): continue
            addrs = netifaces.ifaddresses(i)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0].get("addr","")
                if ip and not ip.startswith("100."): return i
    except ImportError:
        pass

    return "eth0"


def _detect_gateway(iface: str = None) -> str:
    """
    Detect the gateway IP for the given interface.
    Works on home WiFi, phone hotspot, and USB tethering.
    Returns the gateway IP or empty string if not found.
    """
    try:
        cmd = ["ip", "route", "show"]
        if iface:
            cmd += ["dev", iface]
        out = subprocess.check_output(cmd, text=True, timeout=3)
        for line in out.splitlines():
            if "default" in line:
                m = re.search(r"via\s+(\S+)", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ""

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
                 sim_rate=None, profile=None,
                 monitor_mode=False):       # NEW: set True when sniffing a remote target
        self.interface    = interface
        self.callback     = callback
        self._running     = False
        self._mode        = "idle"
        self._count       = 0
        self._pcap_dir    = Path(pcap_dir)
        self._pcap_en     = pcap_enabled and SCAPY_OK
        self._pcap_max    = int(pcap_max_mb * 1_048_576)
        self._pcap_cap    = int(pcap_max_gb * 1_073_741_824)
        self._pw          = None
        self._monitor_mode = monitor_mode  # when True: capture ALL packets, not just local outgoing

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
        gw    = _detect_gateway(iface)
        logger.info(f"Starting live capture on interface: {iface} (gateway: {gw or 'unknown'})")
        # Store for other modules to query
        self._active_iface   = iface
        self._active_gateway = gw

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
                # Capture ALL traffic involving this machine:
                #   - outgoing: Laptop A → internet/LAN
                #   - incoming: internet/LAN → Laptop A  ← was silently dropped before
                #   - monitored: third-party traffic seen via promiscuous/monitor mode
                # _is_local_traffic() returns True for both outgoing AND incoming.
                if n and (self._monitor_mode or _is_local_traffic(n)):
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
                    if pkt and (self._monitor_mode or _is_local_traffic(pkt)):
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
                if _is_local_traffic(pkt) or self._monitor_mode:
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
