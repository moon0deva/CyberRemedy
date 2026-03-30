"""
CyberRemedy SIEM — IoT & Handheld Device Payload Detector
===========================================================
Detects and fingerprints:
  - Android phones (hotspot, ARP, DHCP patterns)
  - iPhones (mDNS Bonjour, SSDP, Captive Portal patterns)
  - Smart TVs, cameras, routers, printers
  - USB tethered devices
  - Protocol payloads: MQTT, CoAP, RTSP, HTTP/REST APIs

Works without MITM - uses passive traffic analysis only.
"""
import re, logging, socket, struct
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cyberremedy.siem.iot")

# ── OUI prefix → vendor database (common IoT vendors) ─────────────────────────
_OUI_MAP = {
    # Apple (iPhone/iPad/Mac)
    "a4:c3:f0":"Apple","f0:b4:29":"Apple","d8:bb:2c":"Apple","3c:22:fb":"Apple",
    "8c:85:90":"Apple","00:17:f2":"Apple","ac:de:48":"Apple","b8:53:ac":"Apple",
    "78:fd:94":"Apple","4c:57:ca":"Apple","a8:51:ab":"Apple","dc:56:e7":"Apple",
    # Samsung (Android)
    "00:26:37":"Samsung","08:d4:2b":"Samsung","3c:8b:fe":"Samsung","40:0e:85":"Samsung",
    "8c:f5:a3":"Samsung","e8:03:9a":"Samsung","cc:07:ab":"Samsung","44:4e:6d":"Samsung",
    "50:32:75":"Samsung","a0:75:91":"Samsung","18:67:b0":"Samsung",
    # Google (Pixel/Nest)
    "f4:f5:db":"Google","94:95:a0":"Google","48:d6:d5":"Google","54:60:09":"Google",
    # Xiaomi
    "28:6c:07":"Xiaomi","00:9e:c8":"Xiaomi","f8:a4:5f":"Xiaomi","64:09:80":"Xiaomi",
    # Smart TVs
    "6c:56:97":"LG","00:05:cd":"LG","30:d6:c9":"Roku","b0:a7:37":"Roku",
    "cc:6d:a0":"Amazon","fc:a1:83":"Amazon","68:37:e9":"Amazon",
    "bc:83:85":"Sony","00:13:a9":"Sony","18:1d:ea":"Sony",
    "54:bd:79":"Samsung","78:bd:bc":"Samsung",
    # Routers/APs
    "b4:fb:e4":"Asus","a8:5e:45":"Asus","70:8b:cd":"Asus",
    "dc:ef:09":"TP-Link","50:c7:bf":"TP-Link","98:da:c4":"TP-Link",
    "74:da:38":"Edimax","b0:be:76":"Netgear","c4:04:15":"Netgear",
    # Cameras / IoT
    "00:40:8c":"Axis","ac:cc:8e":"Hikvision","b4:a3:82":"Hikvision",
    "00:0f:48":"Reolink","d4:f5:27":"Nest","18:b4:30":"Nest",
    # Printers
    "00:00:48":"Epson","00:26:ab":"Canon","00:00:85":"HP",
    # ESP8266/ESP32 (DIY IoT)
    "5c:cf:7f":"Espressif","a4:7b:9d":"Espressif","2c:f4:32":"Espressif",
    "24:6f:28":"Espressif","b4:e6:2d":"Espressif",
    # Raspberry Pi
    "b8:27:eb":"RaspberryPi","dc:a6:32":"RaspberryPi","e4:5f:01":"RaspberryPi",
}

# ── Protocol signatures ────────────────────────────────────────────────────────
_MQTT_CONNECT    = b"\x10"          # MQTT CONNECT packet type
_COAP_MAGIC      = b"\x40"          # CoAP version 1
_RTSP_SIG        = b"RTSP/"
_SSDP_SIG        = b"M-SEARCH * HTTP"
_MDNS_PORT       = 5353
_COAP_PORT       = 5683
_MQTT_PORT       = 1883
_MQTT_TLS_PORT   = 8883
_RTSP_PORT       = 554

# Android hotspot gateway always assigns itself 192.168.x.1
_ANDROID_GW_RE   = re.compile(r"^192\.168\.\d+\.1$")
# Apple Captive Portal detection domain
_APPLE_CAPTIVE   = b"captive.apple.com"
# Android Captive Portal
_ANDROID_CAPTIVE = b"connectivitycheck.gstatic.com"


def oui_lookup(mac: str) -> str:
    """Return vendor name from MAC OUI prefix."""
    if not mac or len(mac) < 8:
        return ""
    prefix = mac.lower()[:8]
    return _OUI_MAP.get(prefix, "")


def fingerprint_device(pkt: dict) -> dict:
    """
    Fingerprint a device from a packet dict.
    Returns enriched dict with: device_type, vendor, os_guess, confidence
    Called per-packet on SIEM captured traffic.
    """
    result = {
        "device_type": "unknown",
        "vendor":      "",
        "os_guess":    "",
        "confidence":  0,
        "protocols":   [],
        "flags":       [],
    }

    src_ip  = pkt.get("src_ip", "")
    dst_ip  = pkt.get("dst_ip", "")
    src_mac = (pkt.get("src_mac") or "").lower()
    payload = pkt.get("_raw_payload", b"") or b""
    dst_port= int(pkt.get("dst_port", 0) or 0)
    src_port= int(pkt.get("src_port", 0) or 0)
    proto   = (pkt.get("protocol") or "").upper()

    # ── OUI vendor lookup ────────────────────────────────────────────────────
    vendor = oui_lookup(src_mac)
    if vendor:
        result["vendor"] = vendor
        result["confidence"] = max(result["confidence"], 40)

    # ── Phone/tablet detection ───────────────────────────────────────────────
    if vendor in ("Apple",):
        result["device_type"] = "iPhone/iPad"
        result["os_guess"]    = "iOS"
        result["confidence"]  = 75

    if vendor in ("Samsung", "Google", "Xiaomi"):
        result["device_type"] = "Android phone/tablet"
        result["os_guess"]    = "Android"
        result["confidence"]  = 70

    # ── Android hotspot gateway pattern ─────────────────────────────────────
    if _ANDROID_GW_RE.match(src_ip) or _ANDROID_GW_RE.match(dst_ip):
        result["flags"].append("android_hotspot_gateway")
        result["device_type"] = "Android hotspot"
        result["os_guess"]    = "Android"
        result["confidence"]  = 85

    # ── Captive portal checks ────────────────────────────────────────────────
    if payload:
        if _APPLE_CAPTIVE in payload:
            result["flags"].append("apple_captive_portal")
            result["os_guess"] = "iOS/macOS"
            result["confidence"] = max(result["confidence"], 80)

        if _ANDROID_CAPTIVE in payload:
            result["flags"].append("android_captive_portal")
            result["os_guess"] = "Android"
            result["confidence"] = max(result["confidence"], 80)

    # ── IoT protocol detection ───────────────────────────────────────────────
    if dst_port == _MQTT_PORT or src_port == _MQTT_PORT:
        result["protocols"].append("MQTT")
        result["device_type"] = "IoT device (MQTT)"
        result["confidence"] = max(result["confidence"], 70)
        if payload and payload[:1] == _MQTT_CONNECT:
            result["flags"].append("mqtt_connect")

    if dst_port == _MQTT_TLS_PORT or src_port == _MQTT_TLS_PORT:
        result["protocols"].append("MQTT-TLS")
        result["device_type"] = "IoT device (MQTT/TLS)"

    if dst_port == _COAP_PORT or src_port == _COAP_PORT:
        result["protocols"].append("CoAP")
        result["device_type"] = "IoT device (CoAP)"
        result["confidence"] = max(result["confidence"], 70)

    if dst_port == _RTSP_PORT or src_port == _RTSP_PORT:
        result["protocols"].append("RTSP")
        result["device_type"] = "IP camera / media device"
        result["confidence"] = max(result["confidence"], 75)
        if payload and _RTSP_SIG in payload:
            result["flags"].append("rtsp_stream")

    # ── mDNS / SSDP (service discovery) ─────────────────────────────────────
    if dst_port == _MDNS_PORT or src_port == _MDNS_PORT:
        result["protocols"].append("mDNS")
        if payload:
            srv = _parse_mdns_service(payload)
            if srv:
                result["flags"].append(f"mdns:{srv}")
                result["device_type"] = _mdns_to_device_type(srv)

    if payload and _SSDP_SIG in payload:
        result["protocols"].append("SSDP")
        result["flags"].append("ssdp_discovery")
        if not result["device_type"] or result["device_type"] == "unknown":
            result["device_type"] = "Smart TV / media device"

    # ── Smart TV / streaming ─────────────────────────────────────────────────
    if vendor in ("Roku", "Amazon", "Sony", "LG") and result["device_type"] == "unknown":
        result["device_type"] = "Smart TV / streaming"
        result["confidence"] = 75

    # ── Camera ───────────────────────────────────────────────────────────────
    if vendor in ("Hikvision", "Axis", "Reolink", "Nest"):
        result["device_type"] = "IP Camera / security device"
        result["confidence"] = 80

    # ── Router/AP ────────────────────────────────────────────────────────────
    if vendor in ("TP-Link", "Asus", "Netgear", "Edimax"):
        result["device_type"] = "Router / Access Point"
        result["confidence"] = 75

    # ── DIY IoT (ESP8266/32, RPi) ────────────────────────────────────────────
    if vendor in ("Espressif",):
        result["device_type"] = "DIY IoT (ESP8266/ESP32)"
        result["confidence"] = 85

    if vendor in ("RaspberryPi",):
        result["device_type"] = "Raspberry Pi"
        result["confidence"] = 90

    return result


def _parse_mdns_service(payload: bytes) -> str:
    """Extract service type from mDNS payload (basic PTR record parsing)."""
    try:
        text = payload.decode("utf-8", errors="replace")
        for svc in ["_airplay","_raop","_companion-link","_googlecast",
                    "_spotify-connect","_http","_smb","_ipp","_printer",
                    "_daap","_homekit","_matter","_hap","_sleep-proxy"]:
            if svc in text:
                return svc
    except Exception:
        pass
    return ""


def _mdns_to_device_type(service: str) -> str:
    mapping = {
        "_airplay":         "Apple TV / AirPlay device",
        "_raop":            "AirPlay audio device",
        "_companion-link":  "iPhone/Apple Watch",
        "_googlecast":      "Chromecast / Google TV",
        "_spotify-connect": "Spotify-enabled speaker",
        "_homekit":         "HomeKit smart home device",
        "_matter":          "Matter smart home device",
        "_hap":             "HomeKit accessory",
        "_ipp":             "Network printer",
        "_printer":         "Network printer",
        "_sleep-proxy":     "Apple device (sleep)",
    }
    return mapping.get(service, "IoT / smart home device")


class HotspotDetector:
    """
    Detects when the laptop is connected to a mobile hotspot vs home router.
    Adjusts capture interface and gateway accordingly.

    Mobile hotspot indicators:
      - Gateway IP is 192.168.x.1 with short DHCP lease
      - Gateway MAC OUI belongs to a phone vendor
      - DNS server is same as gateway (phone acts as DNS)
      - MTU is 1500 but effective path MTU is lower (cellular)
    """

    def __init__(self):
        self._is_hotspot  = False
        self._hotspot_gw  = ""
        self._hotspot_if  = ""

    def detect(self) -> dict:
        """
        Run hotspot detection. Returns status dict.
        Call this when interface changes or on startup.
        """
        import subprocess, re as _re

        result = {
            "is_hotspot":    False,
            "interface":     "",
            "gateway_ip":    "",
            "gateway_mac":   "",
            "gateway_vendor":"",
            "subnet":        "",
            "confidence":    0,
            "advice":        "",
        }

        try:
            # Get default route
            route_out = subprocess.check_output(
                ["ip", "route", "get", "8.8.8.8"], text=True, timeout=3)
            dev_m = _re.search(r"dev\s+(\S+)", route_out)
            gw_m  = _re.search(r"via\s+(\S+)", route_out)
            src_m = _re.search(r"src\s+(\S+)", route_out)

            if not dev_m: return result
            iface  = dev_m.group(1)
            gw_ip  = gw_m.group(1) if gw_m else ""
            my_ip  = src_m.group(1) if src_m else ""

            result["interface"]  = iface
            result["gateway_ip"] = gw_ip
            result["subnet"]     = ".".join(my_ip.split(".")[:3]) + ".0/24" if my_ip else ""

            # Android hotspot: 192.168.x.1 gateway, wlan0 interface
            if gw_ip and _re.match(r"192\.168\.\d+\.1", gw_ip):
                result["confidence"] += 30

            # Resolve gateway MAC
            try:
                arp_out = subprocess.check_output(
                    ["arp", "-n", gw_ip], text=True, timeout=3)
                mac_m = _re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", arp_out, _re.I)
                if mac_m:
                    gw_mac    = mac_m.group(1).lower()
                    gw_vendor = oui_lookup(gw_mac)
                    result["gateway_mac"]    = gw_mac
                    result["gateway_vendor"] = gw_vendor
                    if gw_vendor in ("Apple","Samsung","Google","Xiaomi","LG"):
                        result["confidence"] += 50
                        result["is_hotspot"] = True
            except Exception:
                pass

            # DNS == Gateway is a strong hotspot signal
            try:
                with open("/etc/resolv.conf") as f:
                    dns_ips = _re.findall(r"nameserver\s+(\S+)", f.read())
                if gw_ip in dns_ips:
                    result["confidence"] += 20
            except Exception:
                pass

            is_hs = result["confidence"] >= 50
            result["is_hotspot"] = is_hs
            result["advice"] = (
                f"Hotspot detected via {iface} (gw {gw_ip} = {result['gateway_vendor'] or 'unknown vendor'}). "
                f"Use interface={iface}, gateway={gw_ip} for MITM."
            ) if is_hs else (
                f"Home/office network via {iface} (gw {gw_ip}). Normal capture mode."
            )

            self._is_hotspot = is_hs
            self._hotspot_gw = gw_ip
            self._hotspot_if = iface

        except Exception as e:
            logger.debug(f"[IoT] Hotspot detect error: {e}")

        return result


# Module-level singleton
hotspot_detector = HotspotDetector()
