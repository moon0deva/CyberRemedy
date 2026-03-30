"""
CyberRemedy SIEM — Monitor-Mode Packet Sniffer
================================================
Captures raw 802.11 frames using Scapy on a monitor-mode interface,
extracts the IP layer, and injects packets into CyberRemedy's pipeline.

Relationship to capture/sniffer.py (LiveSniffer):
  LiveSniffer captures traffic on wired / managed-mode wireless interfaces.
  MonitorSniffer captures ALL 802.11 frames passively in monitor mode — it
  sees traffic from every device on the channel, not just this machine.

  Both sniffers produce the same normalised packet dict schema
  (matching normalize_packet() in capture/sniffer.py), so the existing
  FlowAggregator / SignatureDetector / AnomalyDetector / CorrelationEngine
  all work on monitor-mode traffic with ZERO changes.

  MonitorSniffer uses TWO callbacks:
    packet_callback   → _on_packet() in api/server.py  (same as LiveSniffer)
    raw_pkt_callback  → SIEMDetector.inspect()         (WiFi-specific checks)
"""
import ipaddress
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("cyberremedy.siem.sniffer")


class MonitorSniffer:
    """Scapy-based 802.11 monitor-mode packet capture."""

    def __init__(
        self,
        monitor_iface:      str,
        packet_callback:    Optional[Callable] = None,  # → _on_packet (flow aggregator)
        raw_pkt_callback:   Optional[Callable] = None,  # → SIEMDetector.inspect
        new_device_callback: Optional[Callable] = None, # → SIEMDetector.check_new_device
    ):
        self._iface        = monitor_iface
        self._pkt_cb       = packet_callback
        self._raw_cb       = raw_pkt_callback
        self._newdev_cb    = new_device_callback

        self._running      = threading.Event()
        self._thread       = threading.Thread(
            target=self._run, daemon=True, name="siem-sniffer"
        )
        self._count        = 0

    # ─── public ───────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running.set()
        self._thread.start()
        logger.info(f"[SIEM] MonitorSniffer started on '{self._iface}'")

    def stop(self) -> None:
        self._running.clear()
        logger.info(
            f"[SIEM] MonitorSniffer stopped — {self._count} packets captured"
        )

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def packet_count(self) -> int:
        return self._count

    # ─── private ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        try:
            from scapy.all import sniff, conf as scapy_conf
            scapy_conf.verb = 0
            sniff(
                iface=self._iface,
                prn=self._handle,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            )
        except ImportError:
            logger.error(
                "[SIEM] Scapy not installed — monitor capture unavailable. "
                "pip install scapy"
            )
        except OSError as exc:
            logger.error(
                f"[SIEM] Cannot open '{self._iface}': {exc}. "
                "Ensure monitor mode is active and CyberRemedy runs as root."
            )
        except Exception as exc:
            logger.error(f"[SIEM] MonitorSniffer crashed: {exc}", exc_info=True)

    def _handle(self, pkt) -> None:
        try:
            info = self._extract(pkt)
            if info is None:
                return
            self._count += 1

            # 1. Main CyberRemedy pipeline (FlowAggregator → detection → scoring)
            if self._pkt_cb:
                try:
                    self._pkt_cb(info)
                except Exception as exc:
                    logger.debug(f"[SIEM] packet_callback error: {exc}")

            # 2. WiFi-specific per-packet anomaly checks
            if self._raw_cb:
                try:
                    self._raw_cb(info)
                except Exception as exc:
                    logger.debug(f"[SIEM] raw_pkt_callback error: {exc}")

            # 3. Device registration (MAC extracted from 802.11 header if available)
            if self._newdev_cb:
                try:
                    dot11_mac = getattr(pkt, "addr2", "") or ""
                    self._newdev_cb(
                        ip=info["src_ip"],
                        mac=dot11_mac,
                        source="monitor",
                    )
                except Exception as exc:
                    logger.debug(f"[SIEM] new_device_callback error: {exc}")

        except Exception as exc:
            logger.debug(f"[SIEM] _handle error: {exc}")

    @staticmethod
    def _extract(pkt) -> Optional[dict]:
        """
        Pull IP-layer data from any 802.11 frame.
        Returns a packet dict matching capture/sniffer.py normalize_packet(),
        or None if the packet has no usable IP layer.
        """
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS
        except ImportError:
            return None

        # Find IP layer
        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
        if ip_layer is None:
            return None

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        # Drop multicast / broadcast — not actionable
        try:
            if (ipaddress.ip_address(src_ip).is_multicast or
                    ipaddress.ip_address(dst_ip).is_multicast):
                return None
        except ValueError:
            return None

        # Transport layer
        protocol = "OTHER"
        src_port = dst_port = 0
        flags    = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "DNS" if pkt.haslayer(DNS) else "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        ttl = getattr(ip_layer, "ttl", 64)

        return {
            # ── Standard CyberRemedy packet schema ────────────────────────
            "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    src_port,
            "dst_port":    dst_port,
            "protocol":    protocol,
            "length":      len(pkt),
            "payload_len": len(bytes(pkt.payload)) if hasattr(pkt, "payload") else 0,
            "ttl":         ttl,
            "flags":       flags,
            "raw_ts":      time.time(),
            # ── SIEM extra field ──────────────────────────────────────────
            "source":      "siem_monitor",
        }
