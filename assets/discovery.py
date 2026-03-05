"""AID-ARS v4.0 — Asset Discovery. ARP scan, port scan, inventory, rogue alerts."""
import re, json, socket, threading, subprocess, ipaddress, logging as _logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = _logging.getLogger("aidars.assets")

OUI = {"00:50:56":"VMware","08:00:27":"VirtualBox","00:0c:29":"VMware","b8:27:eb":"Raspberry Pi",
       "dc:a6:32":"Raspberry Pi","00:1b:21":"Intel","00:1e:67":"Microsoft","34:97:f6":"TP-Link",
       "50:c7:bf":"TP-Link","00:1d:7e":"Cisco","00:0a:41":"Cisco","fc:fb:fb":"Cisco",
       "ac:bc:32":"Apple","a4:c3:f0":"Apple","00:23:cd":"NETGEAR","94:b8:6d":"Huawei"}

def _vendor(mac):
    mac = mac.upper().replace("-",":")
    for k,v in OUI.items():
        if mac.startswith(k.upper()): return v
    return "Unknown"

def _resolve(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return ""

def _port_scan(ip, ports):
    open_p = []
    for p in ports:
        try:
            s = socket.socket(); s.settimeout(0.4)
            if s.connect_ex((ip,p))==0: open_p.append(p)
            s.close()
        except Exception: pass
    return open_p

def _read_arp_table():
    known = {}
    try:
        with open("/proc/net/arp") as f:
            for line in list(f)[1:]:
                parts = line.split()
                if len(parts)>=4 and parts[2]!="0x0":
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00":
                        known[parts[0]] = mac
    except Exception:
        try:
            out = subprocess.check_output(["arp","-a"],text=True,timeout=5,stderr=subprocess.DEVNULL)
            for line in out.split("\n"):
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)",line,re.I)
                if m: known[m.group(1)] = m.group(2).lower()
        except Exception: pass
    return known

def _ping_sweep(subnet):
    """Pure-Python ping sweep using ICMP or TCP connect — no root, no extra tools needed."""
    import ipaddress, concurrent.futures, socket as _sock
    found = []
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 254: hosts = hosts[:254]
    except Exception:
        return found

    def _probe(ip_obj):
        ip = str(ip_obj)
        # Method 1: subprocess ping (1 packet, 0.3s timeout)
        try:
            ret = subprocess.call(["ping","-c","1","-W","1",ip],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=2)
            if ret == 0:
                return ip
        except Exception: pass
        # Method 2: TCP connect probe on common ports
        for port in (80, 443, 22, 445, 135, 8080, 3389):
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    s.close(); return ip
                s.close()
            except Exception: pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        results = ex.map(_probe, hosts, timeout=30)
    for ip in results:
        if ip: found.append(ip)
    return found


def _arp_scan(subnet):
    devices = []
    # Method 1: arp-scan (fast, needs sudo or cap_net_raw)
    try:
        out = subprocess.check_output(["arp-scan","--localnet","--quiet"],
                                       text=True,timeout=30,stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            parts = line.split("\t")
            if len(parts)>=2 and re.match(r"\d+\.\d+\.\d+\.\d+",parts[0]):
                devices.append({"ip":parts[0],"mac":parts[1].lower() if len(parts)>1 else ""})
        if devices: return devices
    except Exception: pass
    # Method 2: nmap ping scan
    try:
        out = subprocess.check_output(["nmap","-sn","-T4",subnet,"--oG","-"],
                                       text=True,timeout=60,stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            if "Status: Up" in line:
                m = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)",line)
                if m: devices.append({"ip":m.group(1),"mac":""})
        if devices:
            arp = _read_arp_table()
            for d in devices:
                if d["ip"] in arp: d["mac"] = arp[d["ip"]]
            return devices
    except Exception: pass
    # Method 3: Read ARP table (catches anything already communicated with)
    arp = _read_arp_table()
    if arp:
        devices = [{"ip":ip,"mac":mac} for ip,mac in arp.items()]
        return devices
    # Method 4: Pure-Python ping/TCP sweep (always works, no root needed)
    logger.info(f"Asset scan: using Python ping sweep on {subnet}")
    live_ips = _ping_sweep(subnet)
    arp = _read_arp_table()  # re-read after pings populated ARP cache
    for ip in live_ips:
        devices.append({"ip":ip,"mac":arp.get(ip,"")})
    return devices

def _get_local_subnets():
    """
    Detect all local subnets. Uses 6 methods in order so it works
    on any Linux/macOS/Windows system with or without extra tools.
    """
    seen = set()
    results = []

    def _add(iface, ip, prefix=24):
        if not ip or ip.startswith("127.") or ip in seen:
            return
        seen.add(ip)
        try:
            net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            results.append({"iface": iface, "ip": ip, "subnet": str(net)})
            logger.debug(f"Asset subnet found [{iface}]: {net}")
        except Exception:
            pass

    # ── Method 1: UDP socket trick — pure Python, always works ───────────────
    # Connecting a UDP socket doesn't send any packets; it just looks up routing
    # and populates getsockname() with the real outbound IP for that destination.
    for target in [("8.8.8.8", 80), ("1.1.1.1", 80), ("10.0.0.1", 80),
                   ("192.168.0.1", 80), ("172.16.0.1", 80)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
            _add("auto", ip)
        except Exception:
            pass

    # ── Method 2: netifaces (if installed) ────────────────────────────────────
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if 2 in addrs:
                for a in addrs[2]:
                    ip, nm = a.get("addr", ""), a.get("netmask", "255.255.255.0")
                    if ip:
                        try:
                            prefix = ipaddress.IPv4Network(f"0.0.0.0/{nm}").prefixlen
                        except Exception:
                            prefix = 24
                        _add(iface, ip, prefix)
    except ImportError:
        pass

    # ── Method 3: `ip addr` command ───────────────────────────────────────────
    for cmd in [["ip", "addr"], ["ip", "-4", "addr", "show"]]:
        try:
            out = subprocess.check_output(cmd, text=True, timeout=5,
                                          stderr=subprocess.DEVNULL)
            iface = "eth0"
            for line in out.split("\n"):
                m = re.match(r"\d+: ([\w@.-]+):", line)
                if m:
                    iface = m.group(1).split("@")[0]
                m2 = re.match(r"\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if m2:
                    _add(iface, m2.group(1), int(m2.group(2)))
            if results:
                break
        except Exception:
            pass

    # ── Method 4: ifconfig ────────────────────────────────────────────────────
    if not results:
        try:
            out = subprocess.check_output(["ifconfig"], text=True, timeout=5,
                                          stderr=subprocess.DEVNULL)
            iface = "eth0"
            for line in out.split("\n"):
                if re.match(r"\w", line) and ":" in line:
                    iface = line.split(":")[0].strip()
                m = re.search(r"inet (addr:)?(\d+\.\d+\.\d+\.\d+)", line)
                nm = re.search(r"[Mm]ask:?(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    prefix = 24
                    if nm:
                        try:
                            prefix = ipaddress.IPv4Network(
                                f"0.0.0.0/{nm.group(1)}").prefixlen
                        except Exception:
                            pass
                    _add(iface, m.group(2), prefix)
        except Exception:
            pass

    # ── Method 5: /proc/net/fib_trie (Linux-only) ─────────────────────────────
    if not results:
        try:
            with open("/proc/net/fib_trie") as f:
                content = f.read()
            for m in re.finditer(
                    r"(\d+\.\d+\.\d+\.\d+)\s+/32.*?\bLOCAL\b", content):
                _add("proc", m.group(1))
        except Exception:
            pass

    # ── Method 6: socket.gethostbyname (last resort) ─────────────────────────
    if not results:
        try:
            for name in [socket.gethostname(), socket.getfqdn()]:
                ip = socket.gethostbyname(name)
                _add("hostname", ip)
        except Exception:
            pass

    # ── Always scan 192.168.x and 10.x if we found an IP in that range ────────
    # Ensures home/office LAN subnets are included even on multi-homed hosts
    extra = []
    for r in results:
        ip = r["ip"]
        if ip.startswith("192.168."):
            parts = ip.split(".")
            candidate = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if candidate != r["subnet"]:
                try:
                    extra.append({"iface": r["iface"], "ip": ip,
                                   "subnet": candidate})
                except Exception:
                    pass
    results.extend(extra)

    if not results:
        logger.warning("Asset scan: could not detect local subnets — "
                       "scanning 192.168.1.0/24 as fallback")
        results.append({"iface": "fallback", "ip": "192.168.1.1",
                         "subnet": "192.168.1.0/24"})

    logger.info(f"Asset scan: detected subnets: "
                f"{[r['subnet'] for r in results]}")
    return results


class AssetInventory:
    def __init__(self, config: dict):
        cfg = config.get("assets",{})
        self.enabled        = cfg.get("enabled",True)
        self.db_path        = Path(cfg.get("db_path","data/assets/inventory.json"))
        self.scan_interval  = int(cfg.get("scan_interval_seconds",60))
        self.port_scan_new  = cfg.get("port_scan_new_devices",False)  # off by default — keeps first scan fast
        self.scan_ports     = cfg.get("port_scan_ports",[22,80,443,3389,445,21,23,3306,5432,8080])
        self.rogue_alert    = cfg.get("rogue_device_alert",True)
        self.labels: dict   = cfg.get("labels",{})
        self._lock          = threading.Lock()
        self._devices: dict = {}
        self._known_macs: set = set()
        self._alert_cb      = None
        self._log_cb        = None
        self.db_path.parent.mkdir(parents=True,exist_ok=True)
        self._load()
        if self.enabled:
            threading.Thread(target=self._loop,daemon=True,name="asset-scan").start()
            logger.info(f"Asset discovery: scan every {self.scan_interval}s")

    def set_alert_callback(self, fn): self._alert_cb = fn
    def set_log_callback(self, fn):   self._log_cb   = fn

    def _loop(self):
        import time; time.sleep(5)   # brief wait for server startup
        while True:
            try: self.scan()
            except Exception as e: logger.warning(f"Asset scan error: {e}")
            import time; time.sleep(self.scan_interval)

    def scan(self):
        subnets = _get_local_subnets()
        if not subnets:
            logger.warning("Asset scan: no local subnets found"); return []
        # Filter to real LAN subnets: 192.168.x, 10.x, 172.16-31.x
        # Skip Docker bridge networks (172.17-20.x) and Tailscale (100.x)
        # unless they are the ONLY subnet found
        real_subnets = []
        for s in subnets:
            ip = s["ip"]
            iface = s.get("iface","")
            # Skip Docker bridges and Tailscale unless no real subnets
            if any(x in iface for x in ["docker","br-","virbr","veth","tailscale","vpn"]):
                continue
            if ip.startswith("100.") or ip.startswith("169.254."):
                continue
            real_subnets.append(s)
        # Fall back to all subnets if filtering removed everything
        if not real_subnets:
            real_subnets = subnets
        logger.info(f"Asset scan: scanning {[s['subnet'] for s in real_subnets]}")
        found = []
        for s in real_subnets:
            try:
                net = ipaddress.IPv4Network(s["subnet"],strict=False)
                if net.num_addresses > 1024:
                    logger.debug(f"Skipping large subnet {s['subnet']}"); continue
            except Exception: continue
            devs = _arp_scan(s["subnet"])
            for d in devs: d["interface"] = s["iface"]
            found.extend(devs)

        now = datetime.now().isoformat()
        new_devs = []
        with self._lock:
            for d in found:
                ip = d.get("ip",""); mac = d.get("mac","")
                if not ip: continue
                hostname = _resolve(ip)
                label = self.labels.get(ip) or self.labels.get(mac,"")
                vendor = _vendor(mac) if mac else "Unknown"
                if ip in self._devices:
                    self._devices[ip]["last_seen"] = now
                    if hostname: self._devices[ip]["hostname"] = hostname
                    if mac: self._devices[ip]["mac"] = mac
                else:
                    rec = {"ip":ip,"mac":mac,"hostname":hostname,"vendor":vendor,
                           "label":label,"first_seen":now,"last_seen":now,
                           "open_ports":[],"interface":d.get("interface",""),"status":"active"}
                    if self.port_scan_new:
                        rec["open_ports"] = _port_scan(ip, self.scan_ports)
                    self._devices[ip] = rec
                    new_devs.append(rec)
                    # rogue device alert — but ONLY if callback is set AND device is truly unknown
                    if self.rogue_alert and mac and mac not in self._known_macs and self._alert_cb:
                        try:
                            self._alert_cb({"type":"Rogue Device Detected","severity":"HIGH",
                                            "src_ip":ip,"dst_ip":ip,
                                            "detail":f"New device {vendor} ({mac}) on network",
                                            "mac":mac,"vendor":vendor,
                                            "timestamp":now,"confidence":90,"risk_score":60})
                        except Exception as e:
                            logger.warning(f"Rogue alert callback error: {e}")
                    if mac: self._known_macs.add(mac)
            self._save()
        if self._log_cb:
            for d in new_devs:
                try: self._log_cb(d)
                except Exception: pass
        logger.info(f"Asset scan: {len(self._devices)} total, {len(new_devs)} new")
        return new_devs

    def get_all(self):
        with self._lock: return list(self._devices.values())

    def get_device(self, ip):
        with self._lock: return self._devices.get(ip)

    def label_device(self, ip, label):
        with self._lock:
            if ip in self._devices:
                self._devices[ip]["label"] = label
                self.labels[ip] = label
                self._save()

    def stats(self):
        with self._lock: devs = list(self._devices.values())
        return {"total_devices":len(devs),
                "active_devices":sum(1 for d in devs if d.get("status")=="active"),
                "scan_interval_seconds":self.scan_interval}

    def _save(self):
        try:
            with open(self.db_path,"w") as f:
                json.dump({"devices":self._devices,"known_macs":list(self._known_macs),
                           "labels":self.labels},f,indent=2)
        except Exception as e: logger.warning(f"Asset save: {e}")

    def _load(self):
        if not self.db_path.exists(): return
        try:
            with open(self.db_path) as f: data = json.load(f)
            self._devices    = data.get("devices",{})
            self._known_macs = set(data.get("known_macs",[]))
            if not self.labels: self.labels = data.get("labels",{})
            logger.info(f"Asset DB: loaded {len(self._devices)} devices")
        except Exception as e: logger.warning(f"Asset load: {e}")
