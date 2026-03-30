"""
CyberRemedy SIEM — Device Discovery
=====================================
Two background threads that find devices on the wireless network:
  1. ARP scan of the local /24 subnet  (every INTERVAL seconds)
  2. Passive 802.11 Beacon / ProbeResponse parsing

Relationship to assets/discovery.py (AssetInventory):
  AssetInventory does periodic ARP scans + full port scans and owns the
  authoritative asset inventory at data/assets/inventory.json.

  SIEMDiscovery complements it:
    • Faster cycle, no port scanning — presence-only detection
    • Detects devices via 802.11 Beacons before they send any IP traffic
    • Feeds SIEMDetector.check_new_device() → _process_alert_enriched()
      so new-device alerts appear in the CyberRemedy dashboard
"""
import ipaddress
import logging
import socket
import struct
import subprocess
import threading
import time
from typing import Optional

logger = logging.getLogger("cyberremedy.siem.discovery")

_DEFAULT_INTERVAL = 30   # seconds between ARP sweeps

# ── mDNS / SSDP multicast addresses ──────────────────────────────────────────
_MDNS_ADDR  = "224.0.0.251"
_MDNS_PORT  = 5353
_SSDP_ADDR  = "239.255.255.250"
_SSDP_PORT  = 1900


class SIEMDiscovery:

    def __init__(
        self,
        original_iface: str,        # managed interface for ARP (e.g. "wlan0")
        monitor_iface:  str,        # monitor interface for beacons (e.g. "wlan0mon")
        detector,                   # SIEMDetector
        interval:       int = _DEFAULT_INTERVAL,
    ):
        self._iface     = original_iface
        self._mon_iface = monitor_iface
        self._detector  = detector
        self._interval  = interval
        self._running   = threading.Event()

        # Rolling store of mDNS/SSDP discovered devices — keyed by MAC or IP
        # { "mac_or_ip": { "ip", "mac", "hostname", "vendor", "os_hint", "source" } }
        self._mdns_devices: dict = {}
        self._ssdp_devices: dict = {}
        self._mdns_lock = threading.Lock()
        self._ssdp_lock = threading.Lock()

        self._arp_thread = threading.Thread(
            target=self._arp_loop, daemon=True, name="siem-discovery-arp"
        )
        self._beacon_thread = threading.Thread(
            target=self._beacon_loop, daemon=True, name="siem-discovery-beacon"
        )
        self._mdns_thread = threading.Thread(
            target=self._mdns_loop, daemon=True, name="siem-discovery-mdns"
        )
        self._ssdp_thread = threading.Thread(
            target=self._ssdp_loop, daemon=True, name="siem-discovery-ssdp"
        )

    # ─── public ───────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running.set()
        self._arp_thread.start()
        self._beacon_thread.start()
        self._mdns_thread.start()
        self._ssdp_thread.start()
        logger.info(
            f"[SIEM] Device discovery started "
            f"(ARP={self._iface}, beacons={self._mon_iface}, "
            f"mDNS+SSDP=multicast, interval={self._interval}s)"
        )

    def stop(self) -> None:
        self._running.clear()
        logger.info("[SIEM] Device discovery stopped")

    def get_mdns_devices(self) -> list:
        """Return list of devices identified via mDNS (port 5353)."""
        with self._mdns_lock:
            return list(self._mdns_devices.values())

    def get_ssdp_devices(self) -> list:
        """Return list of devices identified via SSDP (port 1900)."""
        with self._ssdp_lock:
            return list(self._ssdp_devices.values())

    # ─── mDNS listener (port 5353) ────────────────────────────────────────────

    def _mdns_loop(self) -> None:
        """
        Join the mDNS multicast group (224.0.0.251:5353) and listen for
        DNS-SD / Bonjour announcements.  Android and iOS devices broadcast
        their real hostname here even when MAC randomisation is active.

        Extracts:
          • PTR records  → device service names (e.g. "_googlecast._tcp.local")
          • A records    → IP ↔ hostname mapping  (e.g. "Pixel-8.local → 192.168.1.x")
          • Source IP    → always present in the IP header

        The real device name (e.g. "Galaxy-S24.local") survives MAC randomisation
        and gives us a stable identifier across DHCP lease renewals.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            sock.bind(("", _MDNS_PORT))
            # Join multicast group
            mreq = struct.pack("4sL", socket.inet_aton(_MDNS_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(2.0)
            logger.info("[SIEM] mDNS listener active on 224.0.0.251:5353")
        except Exception as exc:
            logger.warning(f"[SIEM] mDNS socket failed: {exc}")
            return

        while self._running.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                hostname = self._parse_mdns_name(data)
                if not hostname:
                    continue

                # Resolve MAC from ARP cache for this IP
                mac = self._mac_to_ip_reverse(src_ip)

                # Build OS hint from hostname patterns
                os_hint = self._os_hint_from_hostname(hostname)

                key = mac or src_ip
                entry = {
                    "ip":       src_ip,
                    "mac":      mac or "",
                    "hostname": hostname,
                    "os_hint":  os_hint,
                    "source":   "mdns",
                    "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                with self._mdns_lock:
                    existing = self._mdns_devices.get(key, {})
                    # Only update hostname if we got a better one (has a dot = FQDN)
                    if "." in hostname or not existing.get("hostname"):
                        self._mdns_devices[key] = entry

                # Also register with the detector so it appears in device registry
                self._detector.check_new_device(ip=src_ip, mac=mac or "", source="mdns")
                logger.debug(f"[SIEM] mDNS: {src_ip} → {hostname} ({os_hint})")

            except socket.timeout:
                continue
            except Exception as exc:
                logger.debug(f"[SIEM] mDNS recv error: {exc}")

        try:
            sock.close()
        except Exception:
            pass

    @staticmethod
    def _parse_mdns_name(data: bytes) -> str:
        """
        Parse the first DNS question or answer name from a raw mDNS packet.
        Returns the decoded hostname string or "" on failure.
        DNS wire format: series of length-prefixed labels ending with 0x00.
        """
        try:
            if len(data) < 12:
                return ""
            # Skip 12-byte DNS header
            pos = 12
            labels = []
            visited = set()
            while pos < len(data):
                if pos in visited:
                    break
                visited.add(pos)
                length = data[pos]
                if length == 0:
                    break
                # Pointer compression (0xC0 prefix)
                if (length & 0xC0) == 0xC0:
                    if pos + 1 >= len(data):
                        break
                    ptr = ((length & 0x3F) << 8) | data[pos + 1]
                    pos = ptr
                    continue
                pos += 1
                if pos + length > len(data):
                    break
                label = data[pos:pos + length].decode("utf-8", errors="replace")
                labels.append(label)
                pos += length
            return ".".join(labels) if labels else ""
        except Exception:
            return ""

    @staticmethod
    def _os_hint_from_hostname(hostname: str) -> str:
        """Guess OS from mDNS hostname patterns."""
        h = hostname.lower()
        if any(k in h for k in ("android", "pixel", "galaxy", "samsung", "oneplus",
                                  "xiaomi", "redmi", "huawei", "oppo", "vivo", "motorola")):
            return "Android"
        if any(k in h for k in ("iphone", "ipad", "ipod")):
            return "iOS"
        if any(k in h for k in ("macbook", "imac", "mac-mini", "mac-pro")):
            return "macOS"
        if "_googlecast" in h or "_chromecast" in h:
            return "ChromeOS/Cast"
        if "_airplay" in h or "_raop" in h:
            return "Apple"
        return "Unknown"

    @staticmethod
    def _mac_to_ip_reverse(ip: str) -> str:
        """Look up MAC for a given IP from /proc/net/arp."""
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip \
                            and parts[3] != "00:00:00:00:00:00":
                        return parts[3].lower()
        except Exception:
            pass
        return ""

    # ─── SSDP listener (port 1900) ────────────────────────────────────────────

    def _ssdp_loop(self) -> None:
        """
        Join the SSDP multicast group (239.255.255.250:1900) and listen for
        UPnP NOTIFY and M-SEARCH packets.

        Android broadcasts SSDP NOTIFY messages with:
          • SERVER header  → Android version + build  (e.g. "Linux/3.18 UPnP/1.0 ...")
          • USN header     → uuid:... (stable per-device identifier)
          • NT / ST header → service type  (e.g. "urn:schemas-upnp-org:device:...")
          • LOCATION header → http://<ip>:<port>/description.xml

        This gives us:
          1. Real source IP (from IP header — unaffected by MAC randomisation)
          2. Android OS version in the SERVER header
          3. A stable per-device UUID in the USN header
          4. The device's UPnP description URL we can optionally fetch
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            sock.bind(("", _SSDP_PORT))
            mreq = struct.pack("4sL", socket.inet_aton(_SSDP_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(2.0)
            logger.info("[SIEM] SSDP listener active on 239.255.255.250:1900")
        except Exception as exc:
            logger.warning(f"[SIEM] SSDP socket failed: {exc}")
            return

        while self._running.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                text   = data.decode("utf-8", errors="replace")
                parsed = self._parse_ssdp(text, src_ip)
                if not parsed:
                    continue

                mac = self._mac_to_ip_reverse(src_ip)
                parsed["mac"]      = mac or ""
                parsed["source"]   = "ssdp"
                parsed["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                key = parsed.get("usn") or mac or src_ip
                with self._ssdp_lock:
                    self._ssdp_devices[key] = parsed

                self._detector.check_new_device(ip=src_ip, mac=mac or "", source="ssdp")
                logger.debug(
                    f"[SIEM] SSDP: {src_ip} → {parsed.get('server','?')} "
                    f"USN={parsed.get('usn','?')}"
                )

            except socket.timeout:
                continue
            except Exception as exc:
                logger.debug(f"[SIEM] SSDP recv error: {exc}")

        try:
            sock.close()
        except Exception:
            pass

    @staticmethod
    def _parse_ssdp(text: str, src_ip: str) -> dict:
        """
        Parse SSDP NOTIFY or M-SEARCH headers into a structured dict.
        Returns {} if the packet carries no useful device information.
        """
        headers: dict = {}
        for line in text.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().upper()] = val.strip()

        server   = headers.get("SERVER", "")
        usn      = headers.get("USN", "")
        nt       = headers.get("NT", headers.get("ST", ""))
        location = headers.get("LOCATION", "")

        if not server and not usn:
            return {}

        # Determine OS hint from SERVER header
        os_hint = "Unknown"
        sl = server.lower()
        if "android" in sl:
            os_hint = "Android"
            # Extract version if present e.g. "Linux/4.14 UPnP/1.0 Android/10"
            import re as _re
            m = _re.search(r"android/(\d+[\.\d]*)", sl)
            if m:
                os_hint = f"Android {m.group(1)}"
        elif "linux" in sl:
            os_hint = "Linux"
        elif "windows" in sl:
            os_hint = "Windows"

        return {
            "ip":       src_ip,
            "server":   server,
            "usn":      usn,
            "nt":       nt,
            "location": location,
            "os_hint":  os_hint,
        }

    # ─── ARP sweep ────────────────────────────────────────────────────────────

    def _arp_loop(self) -> None:
        while self._running.is_set():
            try:
                # IPv4 ARP scan
                subnet = self._local_subnet()
                if subnet:
                    self._arp_scan(subnet)
                # IPv6 NDP — read neighbour table
                self._ndp_scan()
            except Exception as exc:
                logger.debug(f"[SIEM] ARP/NDP scan error: {exc}")
            time.sleep(self._interval)

    def _arp_scan(self, subnet: str) -> None:
        # Try Scapy first (higher quality — gets MAC addresses)
        try:
            from scapy.all import srp, Ether, ARP
            pkts = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(pkts, timeout=2, verbose=False, iface=self._iface)
            for _, reply in answered:
                self._detector.check_new_device(
                    ip=reply[ARP].psrc, mac=reply[ARP].hwsrc, source="arp"
                )
            return
        except Exception:
            pass

        # Fallback: read the kernel ARP cache (no extra packages needed)
        self._arp_proc_fallback()

    def _ndp_scan(self) -> None:
        """
        IPv6 Neighbour Discovery — find all devices with IPv6 addresses.
        Reads 'ip -6 neigh' (kernel neighbour cache) and parses /proc/net/ipv6_route
        to find the link-local and global IPv6 subnet, then reports any reachable
        neighbours to the detector.
        """
        # Method 1: ip -6 neigh show — populated by kernel NDP automatically
        try:
            out = subprocess.run(
                ["ip", "-6", "neigh", "show"],
                capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                # Format: "2a02:a31c:3a0:3800:ec46:22f:8d8f:c600 dev wlan0 lladdr xx:xx:xx:xx:xx:xx REACHABLE"
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ipv6 = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx] if mac_idx < len(parts) else ""
                    state = parts[-1] if parts else ""
                    # Only report REACHABLE or STALE (not FAILED/INCOMPLETE)
                    if state in ("REACHABLE", "STALE", "DELAY", "PROBE") and mac:
                        self._detector.check_new_device(
                            ip=ipv6, mac=mac, source="ndp"
                        )
        except Exception as exc:
            logger.debug(f"[SIEM] ip -6 neigh failed: {exc}")

        # Method 2: Active ICMPv6 multicast ping to ff02::1 (all-nodes)
        # This triggers devices to respond and populates the NDP cache
        try:
            iface = self._iface
            subprocess.run(
                ["ping6", "-c", "2", "-I", iface, "ff02::1"],
                capture_output=True, timeout=4
            )
            # After ping, re-read the neighbour table
            out = subprocess.run(
                ["ip", "-6", "neigh", "show"],
                capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ipv6 = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx] if mac_idx < len(parts) else ""
                    if mac and not ipv6.startswith("fe80"):   # skip link-local duplicates
                        self._detector.check_new_device(
                            ip=ipv6, mac=mac, source="ndp_active"
                        )
        except Exception as exc:
            logger.debug(f"[SIEM] ICMPv6 multicast ping: {exc}")

    def _arp_proc_fallback(self) -> None:
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        self._detector.check_new_device(
                            ip=parts[0], mac=parts[3], source="arp_cache"
                        )
        except Exception as exc:
            logger.debug(f"[SIEM] /proc/net/arp error: {exc}")

    @staticmethod
    def _local_subnet() -> Optional[str]:
        """
        Return the local IPv4 CIDR from 'ip route', e.g. "192.168.1.0/24".
        Returns None if it cannot be determined.
        """
        try:
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                if "kernel" in line and "src" in line:
                    parts   = line.split()
                    network = parts[0]
                    if "/" in network and not network.startswith("169.254"):
                        return network
        except Exception as exc:
            logger.debug(f"[SIEM] subnet detection error: {exc}")
        return None

    @staticmethod
    def _ipv6_subnets() -> list:
        """
        Return all non-link-local IPv6 prefixes this machine is on.
        e.g. ["2a02:a31c:3a0:3800::/64"]
        """
        subnets = []
        try:
            out = subprocess.run(
                ["ip", "-6", "route"],
                capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                network = parts[0]
                # Skip default route, link-local, multicast
                if network in ("default", "unreachable") or not "/" in network:
                    continue
                if network.startswith("fe80") or network.startswith("ff"):
                    continue
                if "kernel" in line or "proto" in line:
                    subnets.append(network)
        except Exception as exc:
            logger.debug(f"[SIEM] IPv6 subnet detection: {exc}")
        return subnets

    # ─── 802.11 beacon / probe parsing ────────────────────────────────────────

    def _beacon_loop(self) -> None:
        """
        Passively sniff 802.11 frames to catch devices that haven't sent
        any IP traffic yet (e.g. a phone that just joined the WiFi).
        """
        try:
            from scapy.all import sniff, conf as scapy_conf, Dot11
            scapy_conf.verb = 0
            logger.info(f"[SIEM] Beacon sniffer active on '{self._mon_iface}'")
        except ImportError:
            logger.warning("[SIEM] Scapy unavailable — beacon discovery disabled")
            return

        while self._running.is_set():
            try:
                from scapy.all import sniff, Dot11
                sniff(
                    iface=self._mon_iface,
                    prn=self._handle_dot11,
                    store=False,
                    timeout=self._interval,
                    lfilter=lambda p: p.haslayer(Dot11),
                )
            except Exception as exc:
                logger.debug(f"[SIEM] beacon sniff loop error: {exc}")
                time.sleep(5)

    def _handle_dot11(self, pkt) -> None:
        """Extract the transmitter MAC from any 802.11 frame."""
        try:
            from scapy.all import Dot11
            if not pkt.haslayer(Dot11):
                return
            mac = (pkt[Dot11].addr2 or "").lower()
            if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return
            ip = self._mac_to_ip(mac) or ""
            self._detector.check_new_device(ip=ip, mac=mac, source="beacon")
        except Exception as exc:
            logger.debug(f"[SIEM] dot11 handle error: {exc}")

    @staticmethod
    def _mac_to_ip(mac: str) -> str:
        """Instant MAC → IP lookup from the kernel ARP cache."""
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].lower() == mac:
                        return parts[0]
        except Exception:
            pass
        return ""
