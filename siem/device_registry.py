"""
CyberRemedy SIEM — Device Registry
===================================
Tracks every device seen on the wireless network in monitor mode.

Relationship to assets/discovery.py (AssetInventory):
  AssetInventory does periodic ARP scans + port scanning of LAN hosts and
  owns data/assets/inventory.json as the authoritative asset database.

  DeviceRegistry is the SIEM's faster, read-only companion:
    • No port scanning — passive presence detection only
    • Persists to data/siem_devices.json (separate from AssetInventory)
    • Survives restarts without re-alerting on known devices
    • Re-uses the OUI vendor table from assets/discovery.py
    • On new device detection the SIEMManager callback fires _process_alert_enriched
      so the alert appears in the CyberRemedy dashboard like any other alert
"""
import json
import logging
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("cyberremedy.siem.registry")

_DEFAULT_DB = Path("data/siem_devices.json")


class DeviceRegistry:
    """
    Thread-safe, file-backed registry of WiFi devices seen in monitor mode.

    Entry schema:
        {
            "ip":         "192.168.1.42",    # may be "" if only seen via beacon
            "mac":        "aa:bb:cc:dd:ee:ff",
            "hostname":   "laptop-b.local",
            "vendor":     "Apple",           # from assets/discovery.py OUI table
            "first_seen": "2026-03-12T10:00:00+00:00",
            "last_seen":  "2026-03-12T11:30:00+00:00",
            "is_known":   false,
            "source":     "monitor"          # "monitor" | "arp" | "beacon"
        }
    """

    def __init__(self, db_path: Path = _DEFAULT_DB):
        self._db_path = Path(db_path)
        self._lock    = threading.Lock()
        self._by_ip:  Dict[str, dict] = {}   # ip  → entry
        self._by_mac: Dict[str, dict] = {}   # mac → entry (same object as _by_ip value)
        self._load()

    # ─── public API ───────────────────────────────────────────────────────────

    def see(self, ip: str = "", mac: str = "", source: str = "monitor") -> bool:
        """
        Register a device sighting.
        Returns True if this is a brand-new device (triggers an alert upstream).
        Thread-safe.
        """
        if not ip and not mac:
            return False
        mac = mac.lower() if mac else ""

        with self._lock:
            entry = (
                self._by_ip.get(ip) if ip else None
            ) or (
                self._by_mac.get(mac) if mac else None
            )

            now = datetime.now(tz=timezone.utc).isoformat()

            if entry:
                entry["last_seen"] = now
                if ip  and not entry.get("ip"):
                    entry["ip"]  = ip
                    self._by_ip[ip] = entry
                if mac and not entry.get("mac"):
                    entry["mac"] = mac
                    self._by_mac[mac] = entry
                return False
            else:
                hostname = self._resolve(ip) if ip else ""
                vendor   = self._vendor(mac)
                entry = {
                    "ip":         ip   or "",
                    "mac":        mac  or "",
                    "hostname":   hostname,
                    "vendor":     vendor,
                    "first_seen": now,
                    "last_seen":  now,
                    "is_known":   False,
                    "source":     source,
                }
                if ip:  self._by_ip[ip]   = entry
                if mac: self._by_mac[mac] = entry
                self._save_async()
                return True

    def mark_known(self, ip: str) -> bool:
        """Mark an IP as a trusted/expected device so it won't alert again."""
        with self._lock:
            if ip in self._by_ip:
                self._by_ip[ip]["is_known"] = True
                self._save_async()
                return True
        return False

    def all_devices(self) -> list:
        with self._lock:
            seen, out = set(), []
            for e in list(self._by_ip.values()) + list(self._by_mac.values()):
                uid = id(e)
                if uid not in seen:
                    seen.add(uid)
                    out.append(dict(e))
            return out

    def get_by_ip(self, ip: str) -> Optional[dict]:
        with self._lock:
            e = self._by_ip.get(ip)
            return dict(e) if e else None

    def get_by_mac(self, mac: str) -> Optional[dict]:
        with self._lock:
            e = self._by_mac.get(mac.lower())
            return dict(e) if e else None

    @property
    def clear(self) -> None:
        """Clear all known devices — use when switching to a new network."""
        with self._lock:
            self._by_ip.clear()
            self._by_mac.clear()
        try:
            self._db_path.write_text("[]")
        except Exception as exc:
            logger.warning(f"[SIEM] Registry clear save error: {exc}")

    def count(self) -> int:
        with self._lock:
            return len(self._by_ip)

    # ─── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text())
            for e in data:
                ip  = e.get("ip",  "")
                mac = (e.get("mac") or "").lower()
                if ip:  self._by_ip[ip]   = e
                if mac: self._by_mac[mac] = e
            logger.info(
                f"[SIEM] Device registry loaded — "
                f"{len(self._by_ip)} devices from {self._db_path}"
            )
        except Exception as exc:
            logger.warning(f"[SIEM] Could not load device registry: {exc}")

    def _save_async(self) -> None:
        """Save in a daemon thread so sniffing is never blocked."""
        def _write():
            try:
                self._db_path.parent.mkdir(parents=True, exist_ok=True)
                seen, rows = set(), []
                for e in list(self._by_ip.values()) + list(self._by_mac.values()):
                    uid = id(e)
                    if uid not in seen:
                        seen.add(uid)
                        rows.append(e)
                self._db_path.write_text(json.dumps(rows, indent=2, default=str))
            except Exception as exc:
                logger.debug(f"[SIEM] registry save error: {exc}")
        import threading as _t
        _t.Thread(target=_write, daemon=True, name="siem-reg-save").start()

    # ─── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    @staticmethod
    def _vendor(mac: str) -> str:
        """Re-use CyberRemedy's OUI table from assets/discovery.py."""
        if not mac or len(mac) < 8:
            return ""
        try:
            from assets.discovery import OUI
            return OUI.get(mac.upper()[:8], "")
        except Exception:
            return ""
