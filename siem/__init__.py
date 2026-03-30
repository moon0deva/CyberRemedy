"""
CyberRemedy — SIEM WiFi Monitor Module
=======================================
Passive 802.11 monitor-mode capture layer that slots into the existing
CyberRemedy pipeline without touching any existing modules.

Integration points (see siem/manager.py for details):
  • api/server.py startup()          → SIEMManager.start()
  • api/server.py shutdown()         → SIEMManager.stop()
  • _process_alert_enriched()        → used as alert_callback
  • _on_packet()                     → used as packet_callback (same flow aggregator)
  • /api/siem/* routes               → added in api/server.py
  • config/settings.yaml [siem]      → config block
  • data/siem_devices.json           → device registry persistence
  • data/reports/siem_wifi_*.html    → reports (served by existing /api/report/*)
"""

from .manager import SIEMManager

__all__ = ["SIEMManager"]
