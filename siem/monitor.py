"""
CyberRemedy SIEM — Monitor Mode Management
===========================================
Enables monitor mode on the EXTERNAL adapter (wlan1 → wlan1mon),
then locks it to the SAME 2.4GHz channel as the home router.

Key facts about the setup:
  - wlan0  = internal Intel adapter, connected to home router (may be 5GHz)
  - wlan1  = external AR9271 adapter — 2.4GHz ONLY, supports monitor mode
  - wlan1mon = monitor interface created by airmon-ng

Critical behaviour changes vs previous version:
  1. NO 'airmon-ng check kill' — that killed wlan0/NetworkManager too.
     Instead we just stop wlan1 cleanly before enabling monitor mode.
  2. Channel detection scans for a 2.4GHz channel specifically, because
     AR9271 cannot do 5GHz. If wlan0 is on 5GHz ch44, we scan the air
     to find the router's 2.4GHz band channel instead.
  3. Channel locking uses 'iw set freq' (more reliable than iwconfig).
"""
import logging
import os
import re
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("cyberremedy.siem.monitor")

# AR9271 and most USB adapters only support 2.4GHz (channels 1-13)
_24GHZ_MAX_CHANNEL = 13


class MonitorMode:

    def __init__(self, iface: str, connected_iface: str = "wlan0"):
        """
        iface           — external adapter (wlan1) → becomes wlan1mon
        connected_iface — internal adapter (wlan0), used to read channel
        """
        self.original_iface   = iface
        self.connected_iface  = connected_iface
        self.monitor_iface    = ""
        self.channel          = 0
        self._active          = False

    # ─── public ───────────────────────────────────────────────────────────────

    def enable(self) -> str:
        if self._active:
            return self.monitor_iface

        self._require_root()
        self._require_airmon()

        # Step 1 — detect the router's 2.4GHz channel from wlan0
        ch = self._get_24ghz_channel(self.connected_iface)
        if ch:
            logger.info(
                f"[SIEM] Router 2.4GHz channel detected: {ch} "
                f"(from {self.connected_iface})"
            )
        else:
            logger.warning(
                f"[SIEM] Could not detect 2.4GHz channel from "
                f"{self.connected_iface} — will scan after monitor mode starts"
            )

        # Step 2 — bring wlan1 down cleanly WITHOUT killing NetworkManager
        # This is the key fix: previous code ran 'airmon-ng check kill'
        # which killed NetworkManager and dropped wlan0 (internet) too.
        self._bring_down_cleanly(self.original_iface)

        # Step 3 — enable monitor mode on wlan1, passing channel directly to airmon-ng
        # "airmon-ng start wlan1 <channel>" is the most reliable way for AR9271
        # because airmon-ng puts the card into monitor mode already on that channel.
        cmd = ["airmon-ng", "start", self.original_iface]
        if ch and ch <= _24GHZ_MAX_CHANNEL:
            cmd.append(str(ch))   # airmon-ng start wlan1 6
            logger.info(
                f"[SIEM] Enabling monitor mode on '{self.original_iface}' "
                f"with channel {ch} ..."
            )
        else:
            logger.info(f"[SIEM] Enabling monitor mode on '{self.original_iface}' ...")
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
        )
        logger.debug(result.stdout)

        # Parse the new interface name from airmon-ng output
        # e.g. "(mac80211 monitor mode vif enabled for [phy3]wlan1 on [phy3]wlan1mon)"
        for line in result.stdout.splitlines():
            ll = line.lower()
            if "monitor mode" in ll and "enabled" in ll:
                for part in reversed(line.split()):
                    cand = part.strip(")([]")
                    if cand and self._iface_exists(cand):
                        self.monitor_iface = cand
                        break
            if self.monitor_iface:
                break

        # Fallback naming
        if not self.monitor_iface:
            for candidate in (f"{self.original_iface}mon", "mon0", "wlan1mon"):
                if self._iface_exists(candidate):
                    self.monitor_iface = candidate
                    break

        if not self.monitor_iface:
            raise RuntimeError(
                f"airmon-ng ran but monitor interface not found. "
                f"Try manually: sudo airmon-ng start {self.original_iface}"
            )

        # Brief pause to let the interface settle
        time.sleep(0.5)

        # Step 4 — if channel still unknown, scan the air for the router's SSID
        if not ch:
            ch = self._scan_for_router_channel(self.connected_iface)

        # Step 5 — lock to 2.4GHz channel
        if ch:
            if ch > _24GHZ_MAX_CHANNEL:
                logger.warning(
                    f"[SIEM] Channel {ch} is 5GHz — AR9271 is 2.4GHz only. "
                    f"Scanning for router's 2.4GHz band channel instead..."
                )
                ch = self._scan_for_router_channel(self.connected_iface)

            if ch and ch <= _24GHZ_MAX_CHANNEL:
                ok = self._lock_channel(self.monitor_iface, ch)
                if ok:
                    self.channel = ch
                else:
                    logger.warning(
                        f"[SIEM] Channel lock failed — "
                        f"try locking manually from the dashboard"
                    )
            else:
                logger.warning(
                    "[SIEM] Could not find a 2.4GHz channel — "
                    "lock manually from the dashboard"
                )
        else:
            logger.warning(
                "[SIEM] Channel unknown — lock manually from the dashboard"
            )

        self._active = True
        logger.info(
            f"[SIEM] Monitor mode active: {self.monitor_iface} "
            f"channel={self.channel or 'NOT LOCKED — set manually'}"
        )
        return self.monitor_iface

    def set_channel(self, channel: int) -> bool:
        """Manually lock to a channel from the dashboard."""
        if not self.monitor_iface:
            return False
        if channel > _24GHZ_MAX_CHANNEL:
            logger.warning(
                f"[SIEM] Channel {channel} is 5GHz — "
                f"AR9271 supports 2.4GHz only (ch 1-13)"
            )
            return False
        ok = self._lock_channel(self.monitor_iface, channel)
        if ok:
            self.channel = channel
        return ok

    def disable(self) -> None:
        if not self._active:
            return
        logger.info(f"[SIEM] Stopping monitor mode on '{self.monitor_iface}' ...")
        subprocess.run(["airmon-ng", "stop", self.monitor_iface],
                       capture_output=True)
        # Re-manage wlan1 with NetworkManager (we unmanaged it in _bring_down_cleanly)
        try:
            subprocess.run(
                ["nmcli", "device", "set", self.original_iface, "managed", "yes"],
                capture_output=True, timeout=5
            )
            logger.info(f"[SIEM] NetworkManager: re-managing '{self.original_iface}'")
        except Exception:
            pass
        # Bring interface back up
        try:
            subprocess.run(["ip", "link", "set", self.original_iface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        self._active  = False
        self.channel  = 0
        logger.info("[SIEM] Monitor mode stopped — WiFi restored")

    @property
    def is_active(self) -> bool:
        return self._active

    def info(self) -> dict:
        return {
            "monitor_iface":   self.monitor_iface,
            "original_iface":  self.original_iface,
            "connected_iface": self.connected_iface,
            "channel":         self.channel,
            "active":          self._active,
        }

    # ─── channel detection ────────────────────────────────────────────────────

    @staticmethod
    def _get_24ghz_channel(iface: str) -> int:
        """
        Read current WiFi channel from wlan0.
        Returns 0 if the channel is 5GHz (AR9271 can't use it)
        or if detection fails entirely.
        """
        ch = MonitorMode._read_channel_iw(iface)
        if not ch:
            ch = MonitorMode._read_channel_iwconfig(iface)
        if not ch:
            return 0
        # Only return if it's a 2.4GHz channel
        if ch <= _24GHZ_MAX_CHANNEL:
            return ch
        # It's a 5GHz channel — caller will need to scan for 2.4GHz
        logger.info(
            f"[SIEM] {iface} is on 5GHz channel {ch} — "
            f"need to find router's 2.4GHz band"
        )
        return 0

    @staticmethod
    def _read_channel_iw(iface: str) -> int:
        """iw dev wlan0 info → 'channel 6 (2437 MHz)'"""
        try:
            out = subprocess.run(
                ["iw", "dev", iface, "info"],
                capture_output=True, text=True, timeout=5
            ).stdout
            m = re.search(r"channel\s+(\d+)", out)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return 0

    @staticmethod
    def _read_channel_iwconfig(iface: str) -> int:
        """iwconfig wlan0 → 'Frequency:2.437 GHz' or 'Channel:6'"""
        try:
            out = subprocess.run(
                ["iwconfig", iface],
                capture_output=True, text=True, timeout=5
            ).stdout
            m = re.search(r"Channel[=:](\d+)", out, re.IGNORECASE)
            if m:
                return int(m.group(1))
            m = re.search(r"Frequency[=:](\d+\.\d+)\s*GHz", out, re.IGNORECASE)
            if m:
                return MonitorMode._freq_to_channel(float(m.group(1)))
        except Exception:
            pass
        return 0

    @staticmethod
    def _scan_for_router_channel(connected_iface: str) -> int:
        """
        Find the router's 2.4GHz channel.
        Priority order (fastest/most reliable first):
          1. Read frequency from active association  (iw dev wlan0 link)
          2. iw dev scan (works on iwlwifi / Intel adapters)
          3. iwlist scan (legacy fallback)
        Returns 0 if channel cannot be determined.
        """
        ssid = MonitorMode._get_connected_ssid(connected_iface)
        if not ssid:
            logger.warning("[SIEM] Could not determine connected SSID")
            return 0

        # ── Method 1: Read freq from the ACTIVE association ──────────────────
        # "iw dev wlan0 link" reports the exact freq we're already on —
        # no scanning needed, instant result, works on all drivers
        try:
            out = subprocess.run(
                ["iw", "dev", connected_iface, "link"],
                capture_output=True, text=True, timeout=5
            ).stdout
            m = re.search(r"freq[:\s]+(\d+)", out, re.IGNORECASE)
            if m:
                freq_mhz = int(m.group(1))
                ch = MonitorMode._freq_to_channel(freq_mhz / 1000.0)
                if 1 <= ch <= _24GHZ_MAX_CHANNEL:
                    logger.info(
                        f"[SIEM] Channel {ch} ({freq_mhz} MHz) read from "
                        f"active association on '{connected_iface}'"
                    )
                    return ch
                else:
                    logger.info(
                        f"[SIEM] Active association is on {freq_mhz} MHz "
                        f"(5GHz) — scanning for 2.4GHz band"
                    )
        except Exception as exc:
            logger.debug(f"[SIEM] iw link read: {exc}")

        # ── Method 2: iw dev scan (Intel iwlwifi, modern drivers) ────────────
        logger.info(
            f"[SIEM] Scanning for '{ssid}' 2.4GHz channel via 'iw dev scan' ..."
        )
        try:
            out = subprocess.run(
                ["iw", "dev", connected_iface, "scan"],
                capture_output=True, text=True, timeout=20
            ).stdout
            current_ch = 0
            current_ssid = ""
            for line in out.splitlines():
                line = line.strip()
                # "freq: 2437"
                mf = re.search(r"freq[:\s]+(\d+)", line, re.IGNORECASE)
                if mf:
                    freq_mhz = int(mf.group(1))
                    candidate = MonitorMode._freq_to_channel(freq_mhz / 1000.0)
                    if 1 <= candidate <= _24GHZ_MAX_CHANNEL:
                        current_ch = candidate
                # "DS Parameter set: channel 6"  or  "* primary channel: 6"
                mc = re.search(
                    r"(?:primary channel|DS Parameter set: channel)[:\s]+(\d+)",
                    line, re.IGNORECASE
                )
                if mc:
                    ch_direct = int(mc.group(1))
                    if 1 <= ch_direct <= _24GHZ_MAX_CHANNEL:
                        current_ch = ch_direct
                # "SSID: UPC1232123"
                ms = re.search(r"SSID: (.+)", line)
                if ms:
                    current_ssid = ms.group(1).strip()
                    if current_ssid == ssid and current_ch > 0:
                        logger.info(
                            f"[SIEM] iw scan: '{ssid}' on 2.4GHz channel {current_ch}"
                        )
                        return current_ch
        except Exception as exc:
            logger.warning(f"[SIEM] iw dev scan failed: {exc}")

        # ── Method 3: iwlist scan (legacy fallback) ───────────────────────────
        logger.info(
            f"[SIEM] Trying iwlist scan for '{ssid}' ..."
        )
        try:
            out = subprocess.run(
                ["iwlist", connected_iface, "scan"],
                capture_output=True, text=True, timeout=15
            ).stdout
            current_ch = 0
            current_ssid = ""
            for line in out.splitlines():
                line = line.strip()
                m = re.search(
                    r"Frequency[=:](\d+\.\d+)\s*GHz\s*\(Channel\s*(\d+)\)",
                    line, re.IGNORECASE
                )
                if m:
                    current_ch = int(m.group(2))
                m2 = re.search(r'ESSID:"([^"]*)"'  , line)
                if m2:
                    current_ssid = m2.group(1)
                    if (current_ssid == ssid and
                            current_ch > 0 and
                            current_ch <= _24GHZ_MAX_CHANNEL):
                        logger.info(
                            f"[SIEM] iwlist: '{ssid}' on 2.4GHz channel {current_ch}"
                        )
                        return current_ch
        except Exception as exc:
            logger.warning(f"[SIEM] iwlist scan failed: {exc}")

        return 0

    @staticmethod
    def _get_connected_ssid(iface: str) -> str:
        """Read the SSID wlan0 is currently associated with."""
        # Method 1: iw dev wlan0 link
        try:
            out = subprocess.run(
                ["iw", "dev", iface, "link"],
                capture_output=True, text=True, timeout=5
            ).stdout
            m = re.search(r"SSID:\s*(.+)", out)
            if m:
                return m.group(1).strip()
        except Exception:
            pass

        # Method 2: iwconfig wlan0  →  ESSID:"MyRouter"
        try:
            out = subprocess.run(
                ["iwconfig", iface],
                capture_output=True, text=True, timeout=5
            ).stdout
            m = re.search(r'ESSID:"([^"]+)"', out)
            if m:
                return m.group(1)
        except Exception:
            pass

        return ""

    # ─── channel locking ──────────────────────────────────────────────────────

    @staticmethod
    def _lock_channel(monitor_iface: str, channel: int) -> bool:
        """
        Lock wlan1mon to a specific 2.4GHz channel.
        Uses 'iw set freq' (more reliable for AR9271 than iwconfig).
        """
        # Convert channel to frequency in MHz for iw
        freq_mhz = MonitorMode._channel_to_freq(channel)
        if not freq_mhz:
            logger.warning(f"[SIEM] Cannot convert channel {channel} to frequency")
            return False

        logger.info(
            f"[SIEM] Locking {monitor_iface} to "
            f"channel {channel} ({freq_mhz} MHz) ..."
        )

        # Method 1: iw dev wlan1mon set freq <MHz>  (best for AR9271)
        try:
            r = subprocess.run(
                ["iw", "dev", monitor_iface, "set", "freq", str(freq_mhz)],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                logger.info(
                    f"[SIEM] ✅ Channel {channel} ({freq_mhz} MHz) "
                    f"locked via 'iw set freq'"
                )
                return True
            logger.debug(f"[SIEM] iw set freq: {r.stderr.strip()}")
        except Exception as exc:
            logger.debug(f"[SIEM] iw set freq error: {exc}")

        # Method 2: iw dev wlan1mon set channel X
        try:
            r = subprocess.run(
                ["iw", "dev", monitor_iface, "set", "channel", str(channel)],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                logger.info(f"[SIEM] ✅ Channel {channel} locked via 'iw set channel'")
                return True
            logger.debug(f"[SIEM] iw set channel: {r.stderr.strip()}")
        except Exception:
            pass

        # Method 3: iwconfig wlan1mon channel X
        try:
            r = subprocess.run(
                ["iwconfig", monitor_iface, "channel", str(channel)],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                logger.info(f"[SIEM] ✅ Channel {channel} locked via iwconfig")
                return True
            logger.debug(f"[SIEM] iwconfig: {r.stderr.strip()}")
        except Exception as exc:
            logger.debug(f"[SIEM] iwconfig error: {exc}")

        # Method 4: bring interface down, set freq, bring back up
        # Some drivers need the interface down before changing channel
        freq_mhz = MonitorMode._channel_to_freq(channel)
        try:
            subprocess.run(["ip", "link", "set", monitor_iface, "down"],
                           capture_output=True, timeout=3)
            r = subprocess.run(
                ["iw", "dev", monitor_iface, "set", "freq", str(freq_mhz)],
                capture_output=True, text=True, timeout=5
            )
            subprocess.run(["ip", "link", "set", monitor_iface, "up"],
                           capture_output=True, timeout=3)
            if r.returncode == 0:
                logger.info(
                    f"[SIEM] ✅ Channel {channel} locked via "
                    f"down+freq+up sequence"
                )
                return True
            logger.warning(
                f"[SIEM] ❌ All channel lock methods failed for channel {channel}. "
                f"Last error: {r.stderr.strip()}. "
                f"Try setting manually: sudo iw dev {monitor_iface} set freq {freq_mhz}"
            )
        except Exception as exc:
            logger.warning(f"[SIEM] down+freq+up error: {exc}")

        return False

    # ─── interface management ─────────────────────────────────────────────────

    @staticmethod
    def _bring_down_cleanly(iface: str) -> None:
        """
        Selectively stop ONLY the processes that conflict with monitor mode
        on the EXTERNAL adapter (wlan1), without touching wlan0/NetworkManager.

        Root cause from logs: wpa_supplicant and NetworkManager fight over
        wlan1 and flip it back to managed mode. We must unmanage wlan1 from
        NetworkManager specifically, then kill wpa_supplicant for wlan1 only.
        """
        logger.info(
            f"[SIEM] Preparing '{iface}' for monitor mode — "
            f"stopping conflicting processes on this adapter only ..."
        )

        # Step A: Tell NetworkManager to unmanage wlan1 ONLY (not wlan0)
        # nmcli marks wlan1 as unmanaged so NM won't fight us over it
        try:
            subprocess.run(
                ["nmcli", "device", "set", iface, "managed", "no"],
                capture_output=True, timeout=5
            )
            logger.info(f"[SIEM] NetworkManager: set '{iface}' unmanaged")
        except Exception as exc:
            logger.debug(f"[SIEM] nmcli unmanage failed (ok if nmcli absent): {exc}")

        # Step B: Kill wpa_supplicant ONLY for wlan1 (not the one on wlan0)
        killed_pids = []
        try:
            r = subprocess.run(
                ["pgrep", "-a", "wpa_supplicant"],
                capture_output=True, text=True
            )
            for line in r.stdout.strip().splitlines():
                if iface in line:
                    pid = line.split()[0]
                    subprocess.run(["kill", "-9", pid], capture_output=True)
                    killed_pids.append(pid)
                    logger.info(f"[SIEM] Killed wpa_supplicant PID {pid} (was on {iface})")
        except Exception as exc:
            logger.debug(f"[SIEM] wpa_supplicant kill check: {exc}")

        if not killed_pids:
            logger.info(f"[SIEM] No wpa_supplicant found for '{iface}' — none killed")

        # Step C: Bring the interface down so airmon-ng can take it cleanly
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
        time.sleep(0.3)
        logger.info(f"[SIEM] '{iface}' is down and ready for monitor mode")

    # ─── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _channel_to_freq(channel: int) -> int:
        """Convert 2.4GHz channel number to frequency in MHz."""
        if channel == 14:
            return 2484
        if 1 <= channel <= 13:
            return 2412 + (channel - 1) * 5
        # 5GHz (shouldn't reach here for AR9271)
        if 36 <= channel <= 177:
            return 5000 + channel * 5
        return 0

    @staticmethod
    def _freq_to_channel(freq_ghz: float) -> int:
        """Convert frequency in GHz to 802.11 channel number."""
        freq_mhz = round(freq_ghz * 1000)
        if freq_mhz == 2484:
            return 14
        if 2412 <= freq_mhz <= 2472:
            return (freq_mhz - 2412) // 5 + 1
        if 5180 <= freq_mhz <= 5825:
            return (freq_mhz - 5000) // 5
        return 0

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0:
            raise PermissionError(
                "Monitor mode requires root. Start with: sudo python3 main.py"
            )

    @staticmethod
    def _require_airmon() -> None:
        r = subprocess.run(["which", "airmon-ng"], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(
                "airmon-ng not found — install: sudo apt install aircrack-ng"
            )

    @staticmethod
    def _iface_exists(name: str) -> bool:
        return Path(f"/sys/class/net/{name}").exists()
