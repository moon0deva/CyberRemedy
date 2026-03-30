"""
CyberRemedy SIEM — Manager (single integration point)
======================================================
SIEMManager is the ONLY class api/server.py needs to import.
It wires all SIEM sub-components together and exposes a clean lifecycle API.

HOW TO INTEGRATE INTO api/server.py
─────────────────────────────────────
1.  Import (near the top, after existing imports):

        from siem import SIEMManager

2.  Instantiate (after _process_alert_enriched is defined, ~line 281):

        siem_manager = SIEMManager(
            config           = CONFIG.get("siem", {}),
            packet_callback  = _on_packet,           # feeds FlowAggregator
            alert_callback   = _process_alert_enriched,
        )

3.  Start in startup() (after the LiveSniffer block):

        siem_manager.start_if_enabled()

4.  Stop in shutdown():

        siem_manager.stop()

5.  Wire the /api/siem/* REST routes (see api/server.py patch below).

CONFIG BLOCK (add to config/settings.yaml):
─────────────────────────────────────────────
    siem:
      enabled: false           # set true to activate
      interface: wlan0         # wireless interface to put into monitor mode
      spike_threshold: 50      # packets/IP in spike_window before alert
      spike_window: 10         # seconds
      discovery_interval: 30   # seconds between ARP sweeps
"""
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("cyberremedy.siem.manager")


class SIEMManager:
    """
    Orchestrator for the SIEM WiFi monitor subsystem.

    Lifecycle:
        siem_manager.start_if_enabled()   → reads config, enables monitor mode,
                                            starts sniffer + discovery + detector
        siem_manager.stop()               → graceful shutdown, restores WiFi
        siem_manager.generate_report()    → on-demand JSON + HTML report
        siem_manager.status()             → dict for /api/siem/status
    """

    def __init__(
        self,
        config:           dict,
        packet_callback:  Optional[Callable] = None,   # → _on_packet (FlowAggregator)
        alert_callback:   Optional[Callable] = None,   # → _process_alert_enriched
    ):
        self._cfg       = config
        self._pkt_cb    = packet_callback
        self._alert_cb  = alert_callback

        self._running   = False
        self._monitor   = None
        self._sniffer   = None
        self._discovery = None
        self._detector  = None
        self._reporter  = None
        self._registry  = None
        self._vpn_fp    = None   # VPN fingerprinter
        self._dev_traffic = None # per-device traffic store
        self._mitm      = None   # MITM engine
        self._active    = None   # ActiveCaptureEngine (active method)
        self._tls       = None   # TLS/HTTPS interception engine
        self._quic      = None   # QUIC/HTTP3 intercept + blocker engine
        self._vpn_di    = None   # VPN deep inspection engine
        self._session_start = ""
        self._error     = ""
        self._my_ip     = ""     # this machine's IP (Laptop A)

    # ─── public lifecycle ─────────────────────────────────────────────────────

    def start_if_enabled(self) -> None:
        """Start SIEM if siem.enabled = true in settings.yaml."""
        if not self._cfg.get("enabled", False):
            logger.info("[SIEM] WiFi monitor disabled in config (siem.enabled = false)")
            return
        self._start()

    def start(self) -> None:
        """Force-start regardless of config (used by /api/siem/start)."""
        self._start()

    def stop(self) -> None:
        if not self._running:
            return
        logger.info("[SIEM] Stopping WiFi monitor ...")
        self._running = False
        if self._active:
            try:
                self._active.stop()
            except Exception:
                pass
        if self._mitm:
            try:
                self._mitm.stop_all()
            except Exception:
                pass
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._discovery:
            try:
                self._discovery.stop()
            except Exception:
                pass
        if self._monitor:
            try:
                self._monitor.disable()
            except Exception:
                pass
        if self._tls:
            try:
                self._tls.stop()
            except Exception:
                pass
        if self._quic:
            try:
                self._quic.stop()
            except Exception:
                pass
        if self._vpn_di:
            try:
                self._vpn_di.stop()
            except Exception:
                pass
        logger.info("[SIEM] WiFi monitor stopped")

    def generate_report(self) -> dict:
        """
        Generate a WiFi session report.
        Returns {"json": str(path), "html": str(path)} or {"error": str}.
        """
        if not self._reporter:
            return {"error": "SIEM not running — no data to report"}
        try:
            json_p, html_p = self._reporter.generate()
            return {"json": str(json_p), "html": str(html_p)}
        except Exception as exc:
            logger.error(f"[SIEM] Report generation failed: {exc}")
            return {"error": str(exc)}

    @staticmethod
    def _detect_gateway() -> str:
        """Read default gateway IP from /proc/net/route."""
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        # Gateway is in hex little-endian
                        gw_hex = parts[2]
                        gw_bytes = bytes.fromhex(gw_hex)[::-1]
                        return ".".join(str(b) for b in gw_bytes)
        except Exception:
            pass
        return ""

    def status(self) -> dict:
        """Dict consumed by GET /api/siem/status."""
        cfg_iface = self._cfg.get("interface", "wlan0")
        return {
            "enabled":          self._cfg.get("enabled", False),
            "running":          self._running,
            "interface":        cfg_iface,
            "connected_iface":  self._cfg.get("connected_iface", "wlan0"),
            "monitor_iface":    self._monitor.monitor_iface if self._monitor else "",
            "channel":          self._monitor.channel if self._monitor else 0,
            "session_start":    self._session_start,
            "error":            self._error,
            "packet_count":     self._sniffer.packet_count if self._sniffer else 0,
            "device_count":     self._registry.count if self._registry else 0,
            "detector_stats":   self._detector.stats if self._detector else {},
            "my_ip":            self._my_ip,
            "gateway_ip":       self._mitm._gateway_ip if self._mitm else "",
            "mitm_sessions":    self._mitm.active_count if self._mitm else 0,
            "active_capture":   self._active.get_status() if self._active else {"running": False},
            "capture_mode":     self._cfg.get("capture_mode", "auto"),
            "tls_intercept":    self._tls.status() if self._tls else {"running": False},
            "quic_intercept":   self._quic.status() if self._quic else {"running": False},
            "vpn_deep_inspect": self._vpn_di.status() if self._vpn_di else {"running": False},
        }

    def devices(self) -> list:
        """List for GET /api/siem/devices."""
        return self._registry.all_devices() if self._registry else []

    def mark_known(self, ip: str) -> bool:
        """Called by POST /api/siem/devices/{ip}/mark_known."""
        if self._registry:
            return self._registry.mark_known(ip)
        return False

    def set_channel(self, channel: int) -> dict:
        """
        Manually lock the monitor interface to a specific channel.
        Called by POST /api/siem/channel.
        Returns {"channel": int, "ok": bool}.
        """
        if not self._monitor:
            return {"ok": False, "error": "SIEM not running"}
        ok = self._monitor.set_channel(channel)
        return {"ok": ok, "channel": channel if ok else self._monitor.channel}

    # ─── TLS/HTTPS interception ──────────────────────────────────────────────

    def start_tls_intercept(self, target_ips: list, config: dict = None) -> dict:
        """Start agentless TLS/HTTPS decryption engine."""
        from .tls_intercept import TLSInterceptEngine
        cfg = {**self._cfg.get("tls", {}), **(config or {})}
        self._tls = TLSInterceptEngine(
            config         = cfg,
            flow_callback  = None,
            alert_callback = self._alert_cb,
        )
        return self._tls.start(target_ips=target_ips)

    def stop_tls_intercept(self) -> dict:
        if not self._tls:
            return {"ok": False, "error": "TLS intercept not running"}
        self._tls.stop()
        self._tls = None
        return {"ok": True}

    def get_tls_flows(self, limit: int = 100, client_ip: str = "") -> list:
        if not self._tls:
            return []
        return self._tls.get_flows(limit=limit, client_ip=client_ip)

    def tls_status(self) -> dict:
        return self._tls.status() if self._tls else {"running": False}

    def tls_add_target(self, ip: str) -> bool:
        return self._tls.add_target(ip) if self._tls else False

    def tls_remove_target(self, ip: str) -> bool:
        return self._tls.remove_target(ip) if self._tls else False

    # ─── QUIC/HTTP3 interception ──────────────────────────────────────────────

    def start_quic_intercept(self, target_ips: list = None, block_quic: bool = True) -> dict:
        """Start QUIC blocker + sniffer. Blocking forces browser TCP fallback."""
        from .quic_intercept import QUICInterceptEngine
        iface = self._cfg.get("active_iface", self._cfg.get("interface", "wlan0"))
        self._quic = QUICInterceptEngine(
            iface          = iface,
            target_ips     = target_ips,
            packet_callback = None,
            alert_callback  = self._alert_cb,
            block_quic     = block_quic,
        )
        return self._quic.start()

    def stop_quic_intercept(self) -> dict:
        if not self._quic:
            return {"ok": False, "error": "QUIC intercept not running"}
        self._quic.stop()
        self._quic = None
        return {"ok": True}

    def get_quic_packets(self, limit: int = 100) -> list:
        return self._quic.get_quic_packets(limit) if self._quic else []

    def get_quic_sni_map(self) -> dict:
        return self._quic.get_sni_map() if self._quic else {}

    def quic_status(self) -> dict:
        return self._quic.status() if self._quic else {"running": False}

    # ─── VPN deep inspection ─────────────────────────────────────────────────

    def start_vpn_inspect(self, target_ips: list = None,
                          block_vpn: bool = False,
                          block_protocols: list = None) -> dict:
        """Start VPN protocol parser + traffic classifier. Optionally block VPN."""
        from .vpn_deep_inspect import VPNDeepInspectEngine
        iface = self._cfg.get("active_iface", self._cfg.get("interface", "wlan0"))
        self._vpn_di = VPNDeepInspectEngine(
            iface           = iface,
            target_ips      = target_ips,
            packet_callback = None,
            alert_callback  = self._alert_cb,
            block_vpn       = block_vpn,
            block_protocols = block_protocols,
        )
        return self._vpn_di.start()

    def stop_vpn_inspect(self) -> dict:
        if not self._vpn_di:
            return {"ok": False, "error": "VPN inspect not running"}
        self._vpn_di.stop()
        self._vpn_di = None
        return {"ok": True}

    def get_vpn_packets(self, limit: int = 100, vpn_type: str = "") -> list:
        return self._vpn_di.get_packets(limit=limit, vpn_type=vpn_type) if self._vpn_di else []

    def classify_vpn_peer(self, peer_ip: str) -> dict:
        return self._vpn_di.classify_peer(peer_ip) if self._vpn_di else {}

    def get_vpn_payload_analysis(self, peer_ip: str) -> dict:
        """Deep ciphertext byte analysis for a VPN peer."""
        return self._vpn_di.get_payload_analysis(peer_ip) if self._vpn_di else {"error": "VPN inspect not running"}

    def get_vpn_peers(self) -> list:
        """All peer IPs that have collected VPN packet/payload history."""
        return self._vpn_di.all_peers() if self._vpn_di else []

    def get_vpn_full_report(self, peer_ip: str) -> dict:
        """Full combined report: traffic class + payload analysis + recent packets."""
        return self._vpn_di.full_report(peer_ip) if self._vpn_di else {"error": "VPN inspect not running"}

    def vpn_inspect_status(self) -> dict:
        return self._vpn_di.status() if self._vpn_di else {"running": False}

    # ─── per-device traffic ──────────────────────────────────────────────────

    def device_traffic_normal(self, ip: str, limit: int = 100) -> list:
        if not self._dev_traffic:
            return []
        return self._dev_traffic.get_normal(ip, limit)

    def device_traffic_vpn(self, ip: str, limit: int = 100) -> list:
        if not self._dev_traffic:
            return []
        return self._dev_traffic.get_vpn(ip, limit)

    def device_traffic_summary(self, ip: str) -> dict:
        if not self._dev_traffic:
            return {}
        return self._dev_traffic.get_summary(ip)

    def vpn_analyse(self, ip: str) -> dict:
        if not self._vpn_fp:
            return {"ip": ip, "is_vpn": False, "protocol": "Unknown",
                    "provider": "Unknown", "confidence": 0, "signals": []}
        return self._vpn_fp.analyse(ip)

    # ─── MITM ─────────────────────────────────────────────────────────────────

    def mitm_start(self, target_ip: str) -> dict:
        if not self._mitm:
            return {"ok": False, "error": "SIEM not running"}
        return self._mitm.start_session(target_ip)

    def mitm_stop(self, target_ip: str) -> dict:
        if not self._mitm:
            return {"ok": False, "error": "SIEM not running"}
        return self._mitm.stop_session(target_ip)

    def mitm_status(self, target_ip: str) -> dict:
        if not self._mitm:
            return {"running": False}
        return self._mitm.get_session_status(target_ip)

    def mitm_packets(self, target_ip: str, limit: int = 100) -> list:
        if not self._mitm:
            return []
        return self._mitm.get_intercepted(target_ip, limit)

    def mitm_all_sessions(self) -> list:
        if not self._mitm:
            return []
        return self._mitm.all_sessions()

    @property
    def my_ip(self) -> str:
        return self._my_ip

    def add_active_target(self, ip: str) -> dict:
        """Dynamically add a device to the active MITM capture list."""
        if not self._active:
            return {"ok": False, "error": "Active capture engine not running"}
        return self._active.add_target(ip)

    def remove_active_target(self, ip: str) -> dict:
        """Remove a device from active MITM capture and restore its ARP."""
        if not self._active:
            return {"ok": False, "error": "Active capture engine not running"}
        return self._active.remove_target(ip)

    def active_capture_status(self) -> dict:
        """Status of the active capture engine."""
        if not self._active:
            return {"running": False, "error": "Active capture engine not running"}
        return self._active.get_status()

    def scan_ipv6_neighbours(self) -> list:
        """Run an active IPv6 NDP scan and return discovered neighbours."""
        if self._active:
            return self._active.scan_ipv6_neighbours()
        # Fallback: read kernel NDP cache directly without active engine
        import subprocess
        neighbours = []
        try:
            subprocess.run(
                ["ping6", "-c", "2", "-I",
                 self._cfg.get("connected_iface", "wlan0"), "ff02::1"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
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
                    if mac and parts[-1] in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                        neighbours.append({"ip": ipv6, "mac": mac, "state": parts[-1]})
        except Exception:
            pass
        return neighbours

    # ─── private ──────────────────────────────────────────────────────────────

    def _start(self) -> None:
        if self._running:
            logger.warning("[SIEM] Already running")
            return

        iface = self._cfg.get("interface", "wlan0")
        logger.info(f"[SIEM] Starting WiFi monitor on '{iface}' ...")

        # Run the full startup in a daemon thread so it never blocks the
        # FastAPI startup event (airmon-ng can take a few seconds)
        t = threading.Thread(target=self._startup_thread, args=(iface,),
                              daemon=True, name="siem-startup")
        t.start()

    def _startup_thread(self, iface: str) -> None:
        from .monitor          import MonitorMode
        from .device_registry  import DeviceRegistry
        from .detector         import SIEMDetector
        from .sniffer          import MonitorSniffer
        from .discovery        import SIEMDiscovery
        from .reporter         import SIEMReporter
        from .vpn_fingerprint  import VPNFingerprinter
        from .device_traffic   import DeviceTrafficStore
        from .mitm             import MITMEngine

        try:
            # 1. Monitor mode
            # connected_iface = wlan0 (internal, already on home router)
            # iface           = wlan1 (external, goes into monitor mode → wlan1mon)
            connected_iface = self._cfg.get("connected_iface", "wlan0")
            self._monitor = MonitorMode(iface, connected_iface=connected_iface)
            mon_iface     = self._monitor.enable()

            # 2. Device registry (loads previous session from disk)
            db_path = Path(self._cfg.get("db_path", "data/siem_devices.json"))
            self._registry = DeviceRegistry(db_path=db_path)

            # 2b. VPN fingerprinter + per-device traffic store
            self._vpn_fp      = VPNFingerprinter()
            self._dev_traffic = DeviceTrafficStore()

            # 2c. Detect this machine's own IP (Laptop A) to separate its traffic
            import socket as _socket
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self._my_ip = s.getsockname()[0]
                s.close()
            except Exception:
                self._my_ip = ""
            logger.info(f"[SIEM] This machine IP (Laptop A): {self._my_ip or 'unknown'}")

            # 2d. Detect gateway IP for MITM
            gateway_ip = self._detect_gateway()
            self._mitm = MITMEngine(
                iface           = connected_iface,  # MUST be wlan0 (managed), NOT wlan1 (monitor)
                gateway_ip      = gateway_ip,
                packet_callback = self._alert_cb,
            )
            logger.info(f"[SIEM] MITM engine ready (gateway: {gateway_ip or 'unknown'})")

            # 3. Anomaly detector
            self._detector = SIEMDetector(
                registry         = self._registry,
                alert_callback   = self._alert_cb,
                spike_threshold  = int(self._cfg.get("spike_threshold", 50)),
                spike_window     = int(self._cfg.get("spike_window",    10)),
            )

            # 4. Reporter (accumulates data for on-demand reports)
            self._session_start = datetime.now(tz=timezone.utc).isoformat()
            self._reporter = SIEMReporter(
                registry       = self._registry,
                monitor_iface  = mon_iface,
                session_start  = self._session_start,
            )

            # Wire reporter into the detector's alert callback so every
            # alert is also logged to the reporter's in-memory store
            _orig_cb = self._alert_cb
            def _wrapped_alert_cb(alert: dict) -> None:
                self._reporter.record_anomaly(alert)
                if _orig_cb:
                    _orig_cb(alert)
            self._detector._alert_cb = _wrapped_alert_cb

            # 5. Packet sniffer
            def _pkt_with_record(pkt: dict) -> None:
                self._reporter.record_packet(pkt)
                # Feed per-device traffic store
                if self._dev_traffic:
                    self._dev_traffic.ingest(pkt)
                # Feed VPN fingerprinter
                if self._vpn_fp:
                    self._vpn_fp.ingest(pkt)
                # Feed MITM engine (routes to active sessions)
                if self._mitm:
                    self._mitm.feed_packet(pkt)
                if self._pkt_cb:
                    self._pkt_cb(pkt)

            # ── Passive sniffer (monitor mode) ─────────────────────────
            capture_mode = self._cfg.get("capture_mode", "auto")
            use_passive = capture_mode in ("auto", "passive", "both")
            use_active  = capture_mode in ("auto", "active",  "both")

            if use_passive:
                self._sniffer = MonitorSniffer(
                    monitor_iface       = mon_iface,
                    packet_callback     = _pkt_with_record,
                    raw_pkt_callback    = self._detector.inspect,
                    new_device_callback = self._detector.check_new_device,
                )
                self._sniffer.start()
                logger.info(f"[SIEM] Passive monitor-mode sniffer running on '{mon_iface}'")
            else:
                logger.info("[SIEM] Passive sniffer skipped (capture_mode != passive/both/auto)")

            # ── Active capture engine ───────────────────────────────────
            if use_active:
                from .active_capture import ActiveCaptureEngine
                active_iface   = self._cfg.get("active_iface", connected_iface)
                active_targets = self._cfg.get("active_targets", [])
                active_bpf     = self._cfg.get("active_bpf", "")
                active_method  = self._cfg.get("active_method", "auto")

                self._active = ActiveCaptureEngine(
                    iface            = active_iface,
                    packet_callback  = _pkt_with_record,
                    alert_callback   = self._alert_cb,
                    target_ips       = active_targets,
                    gateway_ip       = gateway_ip,
                    bpf_filter       = active_bpf,
                    method           = active_method,
                )
                result = self._active.start()
                if result.get("ok"):
                    logger.info(
                        f"[SIEM] Active capture engine running — "
                        f"method={result.get('method')} iface={active_iface}"
                    )
                else:
                    logger.warning(
                        f"[SIEM] Active capture engine failed to start: "
                        f"{result.get('error')} — passive mode only"
                    )
                    self._active = None

            # ── TLS/HTTPS transparent interception (agentless) ─────────
            tls_cfg = self._cfg.get("tls", {})
            if tls_cfg.get("enabled", False):
                from .tls_intercept import TLSInterceptEngine
                self._tls = TLSInterceptEngine(
                    config         = tls_cfg,
                    flow_callback  = None,
                    alert_callback = self._alert_cb,
                )
                tls_targets = tls_cfg.get("target_ips", active_targets or [])
                tls_result  = self._tls.start(target_ips=tls_targets)
                if tls_result.get("ok"):
                    logger.info(
                        f"[SIEM] TLS intercept engine running — "
                        f"proxy=:{tls_cfg.get('proxy_port', 8080)} "
                        f"wpad=:{tls_cfg.get('wpad_port', 8088)} "
                        f"targets={tls_targets}"
                    )
                else:
                    logger.warning(
                        f"[SIEM] TLS intercept failed to start: {tls_result.get('error')}"
                    )
                    self._tls = None

            # ── QUIC/HTTP3 blocker + sniffer ────────────────────────────
            quic_cfg = self._cfg.get("quic", {})
            if quic_cfg.get("enabled", False):
                from .quic_intercept import QUICInterceptEngine
                quic_iface   = self._cfg.get("active_iface", connected_iface)
                quic_targets = quic_cfg.get("target_ips", active_targets or [])
                self._quic   = QUICInterceptEngine(
                    iface           = quic_iface,
                    target_ips      = quic_targets or None,
                    packet_callback = None,
                    alert_callback  = self._alert_cb,
                    block_quic      = quic_cfg.get("block_quic", True),
                )
                quic_result = self._quic.start()
                if quic_result.get("ok"):
                    logger.info(
                        f"[SIEM] QUIC intercept engine running — "
                        f"block={quic_cfg.get('block_quic', True)} iface={quic_iface}"
                    )
                else:
                    logger.warning("[SIEM] QUIC intercept failed to start")
                    self._quic = None

            # ── VPN deep inspection ──────────────────────────────────────
            vpn_cfg = self._cfg.get("vpn_inspect", {})
            if vpn_cfg.get("enabled", False):
                from .vpn_deep_inspect import VPNDeepInspectEngine
                vpn_iface   = self._cfg.get("active_iface", connected_iface)
                vpn_targets = vpn_cfg.get("target_ips", active_targets or [])
                self._vpn_di = VPNDeepInspectEngine(
                    iface           = vpn_iface,
                    target_ips      = vpn_targets or None,
                    packet_callback = None,
                    alert_callback  = self._alert_cb,
                    block_vpn       = vpn_cfg.get("block_vpn", False),
                    block_protocols = vpn_cfg.get("block_protocols", None),
                )
                vpn_result = self._vpn_di.start()
                if vpn_result.get("ok"):
                    logger.info(
                        f"[SIEM] VPN deep inspect engine running — "
                        f"block={vpn_cfg.get('block_vpn', False)} iface={vpn_iface}"
                    )
                else:
                    logger.warning("[SIEM] VPN deep inspect failed to start")
                    self._vpn_di = None

            # 6. Device discovery (ARP + beacons)
            self._discovery = SIEMDiscovery(
                original_iface = iface,
                monitor_iface  = mon_iface,
                detector       = self._detector,
                interval       = int(self._cfg.get("discovery_interval", 30)),
            )
            self._discovery.start()

            self._running = True
            self._error   = ""
            logger.info(
                f"[SIEM] WiFi monitor running on '{mon_iface}' — "
                f"packets → FlowAggregator + SIEMDetector"
            )

        except PermissionError as exc:
            self._error = str(exc)
            logger.error(f"[SIEM] Permission error: {exc}")
        except RuntimeError as exc:
            self._error = str(exc)
            logger.error(f"[SIEM] Startup error: {exc}")
        except Exception as exc:
            self._error = str(exc)
            logger.error(f"[SIEM] Unexpected startup error: {exc}", exc_info=True)
