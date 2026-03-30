"""
CyberRemedy SIEM — WiFi Anomaly Detector
==========================================
Runs fast, per-packet checks on monitor-mode traffic BEFORE packets enter
the main CyberRemedy detection pipeline (signature / ML / correlation).

Relationship to existing detectors:
  detection/signature.py  → rule-based flow analysis  (works on completed flows)
  detection/anomaly.py    → ML IsolationForest         (works on completed flows)
  detection/correlation.py→ multi-event chain engine   (works on scored alerts)
  scoring/scorer.py       → CVSS-style risk scoring    (works on single alerts)

  SIEMDetector adds WiFi-layer checks that fire on RAW PACKETS:
    1. Suspicious destination ports  (same list as signature.py, checked per-pkt)
    2. Per-source traffic spikes     (sliding-window packet counter per IP)
    3. New device detection          (delegates to DeviceRegistry)

  Alerts produced here have the same schema as the rest of CyberRemedy so
  they go straight into _process_alert_enriched() → MITRE enrich → score →
  correlate → auto-case → data-lake → dashboard.
"""
import logging
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("cyberremedy.siem.detector")

# ── Same suspicious-port set as detection/signature.py ───────────────────────
_SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143,
    445, 1433, 1434, 3306, 3389, 4444, 5900, 6379, 27017,
}

_DEFAULT_SPIKE_THRESHOLD = 50   # pkts/IP within window before spike alert
_DEFAULT_SPIKE_WINDOW    = 10   # seconds


class SIEMDetector:
    """
    Per-packet WiFi anomaly detector.

    alert_callback should be api/server.py's _process_alert_enriched so alerts
    flow through the full CyberRemedy enrichment/scoring/dashboard pipeline.
    """

    def __init__(
        self,
        registry,                                   # DeviceRegistry
        alert_callback: Optional[Callable] = None,
        spike_threshold: int = _DEFAULT_SPIKE_THRESHOLD,
        spike_window:    int = _DEFAULT_SPIKE_WINDOW,
    ):
        self._registry        = registry
        self._alert_cb        = alert_callback
        self._spike_threshold = spike_threshold
        self._spike_window    = spike_window

        self._lock            = threading.Lock()
        self._pkt_times:      dict = defaultdict(list)
        self._spike_alerted:  set  = set()

        # Stats exposed at GET /api/siem/status
        self.stats = {
            "suspicious_port_hits": 0,
            "traffic_spikes":       0,
            "new_devices":          0,
        }

    # ─── public ───────────────────────────────────────────────────────────────

    def inspect(self, pkt: dict) -> None:
        """
        Called for every packet from MonitorSniffer.
        pkt schema matches capture/sniffer.py normalize_packet() output.
        """
        src_ip   = pkt.get("src_ip", "")
        dst_port = int(pkt.get("dst_port") or 0)
        if src_ip:
            self._check_spike(src_ip)
        if dst_port:
            self._check_suspicious_port(pkt, src_ip, dst_port)

    def check_new_device(self, ip: str = "", mac: str = "",
                         source: str = "monitor") -> None:
        """
        Register a device sighting. Fires an alert if it's brand-new.
        Called by MonitorSniffer (per packet) and DeviceDiscovery (ARP/beacon).
        """
        is_new = self._registry.see(ip=ip, mac=mac, source=source)
        if not is_new:
            return

        self.stats["new_devices"] += 1
        entry  = (self._registry.get_by_ip(ip) or
                  self._registry.get_by_mac(mac) or {})
        vendor = entry.get("vendor", "")
        label  = ip or f"MAC:{mac}"
        detail = (
            f"New device detected on wireless network — "
            f"IP: {label}  MAC: {mac or 'unknown'}"
            + (f"  ({vendor})" if vendor else "")
        )
        logger.warning(f"[SIEM] {detail}")
        self._emit({
            "type":       "New WiFi Device",
            "severity":   "MEDIUM",
            "mitre_id":   "T1040",      # Network Sniffing / Rogue device
            "src_ip":     ip or "",     # Never use MAC as src_ip — breaks GeoIP lookup
            "dst_ip":     "",
            "src_port":   None,
            "dst_port":   None,
            "confidence": 90.0,
            "detail":     detail,
            "source":     "siem_monitor",
            "mac":        mac,
            "vendor":     vendor,
        })

    # ─── private ──────────────────────────────────────────────────────────────

    def _check_suspicious_port(self, pkt: dict, src_ip: str, dst_port: int) -> None:
        if dst_port not in _SUSPICIOUS_PORTS:
            return
        self.stats["suspicious_port_hits"] += 1
        detail = (
            f"Suspicious port activity — "
            f"{src_ip} → port {dst_port} ({pkt.get('protocol', '')})"
        )
        logger.warning(f"[SIEM] {detail}")
        self._emit({
            "type":       "Suspicious Port",
            "severity":   "HIGH",
            "mitre_id":   "T1046",   # Network Service Scanning
            "src_ip":     src_ip,
            "dst_ip":     pkt.get("dst_ip", ""),
            "src_port":   pkt.get("src_port"),
            "dst_port":   dst_port,
            "confidence": 75.0,
            "detail":     detail,
            "source":     "siem_monitor",
            "protocol":   pkt.get("protocol", ""),
        })

    def _check_spike(self, src_ip: str) -> None:
        now = time.time()
        with self._lock:
            times  = self._pkt_times[src_ip]
            times.append(now)
            cutoff = now - self._spike_window
            self._pkt_times[src_ip] = [t for t in times if t >= cutoff]
            count  = len(self._pkt_times[src_ip])

            if count < self._spike_threshold or src_ip in self._spike_alerted:
                return

            self._spike_alerted.add(src_ip)
        # outside lock for the rest
        self.stats["traffic_spikes"] += 1
        detail = (
            f"Traffic spike — {src_ip} sent "
            f"{count} packets in {self._spike_window}s"
        )
        logger.warning(f"[SIEM] {detail}")
        self._emit({
            "type":       "Traffic Spike",
            "severity":   "HIGH",
            "mitre_id":   "T1499",
            "src_ip":     src_ip,
            "dst_ip":     "",
            "src_port":   None,
            "dst_port":   None,
            "confidence": 85.0,
            "detail":     detail,
            "source":     "siem_monitor",
            "packet_count": count,
            "window_secs":  self._spike_window,
        })
        # Auto-reset so we can re-alert after 3× the window
        threading.Timer(
            self._spike_window * 3,
            lambda ip=src_ip: self._spike_alerted.discard(ip),
        ).start()

    def _emit(self, partial: dict) -> None:
        """Wrap in a full CyberRemedy alert dict and pass to the callback."""
        alert = {
            "id":         int(str(uuid.uuid4().int)[:9]),
            "timestamp":  datetime.now(tz=timezone.utc).isoformat(),
            "status":     "OPEN",
            "correlated": False,
            **partial,
        }
        if self._alert_cb:
            try:
                self._alert_cb(alert)
            except Exception as exc:
                logger.debug(f"[SIEM] alert_callback error: {exc}")
