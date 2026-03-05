"""
AID-ARS v4.0 — Packet Capture
Priority: live scapy (root) → simulation. Never crashes.
"""
import os, time, logging, threading, random
from datetime import datetime
from typing import Callable, Optional
from pathlib import Path

logger = logging.getLogger("aidars.capture")

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
    logger.info("capture: scapy not installed — simulation mode")
elif not ROOT_OK:
    logger.info("capture: not root — simulation mode (use sudo for live capture)")
else:
    logger.info("capture: scapy + root — live capture available")

def normalize_packet(pkt) -> Optional[dict]:
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns  import DNS
        if IP not in pkt: return None
        ip = pkt[IP]
        proto, sport, dport, flags = "OTHER", 0, 0, ""
        if TCP in pkt:
            proto,sport,dport,flags = "TCP",pkt[TCP].sport,pkt[TCP].dport,str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "DNS" if DNS in pkt else "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        return {"timestamp": datetime.utcnow().isoformat(),
                "src_ip": ip.src, "dst_ip": ip.dst,
                "src_port": sport, "dst_port": dport,
                "protocol": proto, "length": len(pkt),
                "payload_len": len(bytes(pkt.payload)),
                "ttl": ip.ttl, "flags": flags, "raw_ts": time.time()}
    except Exception:
        return None

_PORTS = [22,80,443,53,8080,21,23,3389,445,3306,5432,25,587]
_PROTO = ["TCP","UDP","DNS","ICMP"]
_FLAGS = ["S","SA","A","FA","R",""]

def _sim_pkt(profile="home"):
    ri = random.randint
    if profile == "cloud":
        src = f"{ri(1,223)}.{ri(0,255)}.{ri(0,255)}.{ri(1,254)}"
        dst = f"10.0.0.{ri(1,20)}"
    elif profile == "office":
        src = f"10.{ri(0,10)}.{ri(0,255)}.{ri(1,254)}"
        dst = f"10.0.{ri(0,5)}.{ri(1,50)}"
    else:
        src = f"192.168.{ri(0,5)}.{ri(1,254)}"
        dst = f"192.168.1.{ri(1,20)}"
    return {"timestamp": datetime.utcnow().isoformat(),
            "src_ip": src, "dst_ip": dst,
            "src_port": ri(1024,65535), "dst_port": random.choice(_PORTS),
            "protocol": random.choice(_PROTO), "length": ri(40,1500),
            "payload_len": ri(0,1460), "ttl": random.choice([64,128,255]),
            "flags": random.choice(_FLAGS), "raw_ts": time.time(), "simulated": True}

class LiveSniffer:
    def __init__(self, interface="auto", callback: Callable=None,
                 pcap_enabled=False, pcap_dir="data/pcap",
                 pcap_max_mb=500, pcap_max_gb=20.0,
                 sim_rate=0.05, profile="home"):
        self.interface = interface
        self.callback  = callback
        self.profile   = profile
        self._sim_rate = sim_rate
        self._running  = False
        self._mode     = "idle"
        self._count    = 0
        self._pcap_dir = Path(pcap_dir)
        self._pcap_en  = pcap_enabled and SCAPY_OK
        self._pcap_max = int(pcap_max_mb * 1_048_576)
        self._pcap_cap = int(pcap_max_gb * 1_073_741_824)
        self._pw       = None

    def start(self):
        if self._running: return
        self._running = True
        if CAN_SNIFF:
            iface = self._resolve_iface()
            t = threading.Thread(target=self._live, args=(iface,), daemon=True, name="cap-live")
        else:
            t = threading.Thread(target=self._sim, daemon=True, name="cap-sim")
        t.start()

    def stop(self):
        self._running = False
        if self._pw:
            try: self._pw[0].close()
            except Exception: pass
            self._pw = None
        logger.info(f"Capture stopped — {self._count} pkts ({self._mode})")

    @property
    def mode(self): return self._mode
    @property
    def is_running(self): return self._running
    @property
    def packet_count(self): return self._count

    def _resolve_iface(self):
        if self.interface not in ("auto","",None): return self.interface
        try:
            import netifaces
            for i in netifaces.interfaces():
                if i.startswith("lo"): continue
                if 2 in netifaces.ifaddresses(i): return i
        except ImportError: pass
        try:
            import subprocess, re
            out = subprocess.check_output(["ip","link"],text=True,timeout=3)
            for ln in out.split("\n"):
                m = re.match(r"\d+: (\w+):", ln)
                if m and m.group(1) != "lo": return m.group(1)
        except Exception: pass
        return "eth0"

    def _live(self, iface):
        self._mode = "live"
        try:
            from scapy.all import sniff, conf; conf.verb = 0
            def _h(pkt):
                n = normalize_packet(pkt)
                if n:
                    self._count += 1
                    self._write_pcap(pkt)
                    if self.callback:
                        try: self.callback(n)
                        except Exception as e: logger.debug(f"cb: {e}")
            sniff(iface=iface, prn=_h, store=False,
                  stop_filter=lambda _: not self._running)
        except Exception as e:
            logger.warning(f"Live capture failed ({e}) — falling back to simulation")
            self._sim()

    def _sim(self):
        self._mode = "simulation"
        while self._running:
            pkt = _sim_pkt(self.profile)
            self._count += 1
            if self.callback:
                try: self.callback(pkt)
                except Exception as e: logger.debug(f"sim cb: {e}")
            time.sleep(self._sim_rate)

    def _write_pcap(self, raw_pkt):
        if not self._pcap_en: return
        try:
            self._pcap_dir.mkdir(parents=True, exist_ok=True)
            if self._pw is None:
                from scapy.utils import PcapWriter as PW
                fname = self._pcap_dir / f"cap-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
                self._pw = (PW(str(fname),append=False,sync=True), 0)
            pw, sz = self._pw
            pw.write(raw_pkt); sz += len(raw_pkt)
            self._pw = (pw, sz)
            if sz >= self._pcap_max:
                try: pw.close()
                except Exception: pass
                self._pw = None
                self._trim_pcap()
        except Exception as e:
            logger.debug(f"PCAP: {e}")
            self._pw = None

    def _trim_pcap(self):
        files = sorted(self._pcap_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        total = sum(f.stat().st_size for f in files)
        while total > self._pcap_cap and files:
            f = files.pop(0); total -= f.stat().st_size; f.unlink()


class PcapReplayer:
    def __init__(self, pcap_path: str, callback: Callable=None, speed_factor=1.0):
        self.path = Path(pcap_path); self.callback = callback; self.speed = speed_factor
    def replay(self):
        if not self.path.exists(): raise FileNotFoundError(self.path)
        if not SCAPY_OK: raise RuntimeError("scapy not installed")
        from scapy.all import rdpcap
        pkts = rdpcap(str(self.path)); prev = None
        for pkt in pkts:
            n = normalize_packet(pkt)
            if not n: continue
            if prev and self.speed > 0:
                d = (pkt.time - prev) / self.speed
                if 0 < d < 5: time.sleep(d)
            prev = pkt.time
            if self.callback: self.callback(n)
