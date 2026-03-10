"""CyberRemedy v1.0 — Asset Discovery. ARP scan, port scan, inventory, rogue alerts."""
import re, json, socket, threading, subprocess, ipaddress, logging as _logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = _logging.getLogger("cyberremedy.assets")


# ── OUI Vendor Table (top 400 prefixes — covers >90% of home/office devices) ──
OUI: dict = {
    # Apple
    "00:03:93":"Apple","00:05:02":"Apple","00:0A:27":"Apple","00:0A:95":"Apple",
    "00:0D:93":"Apple","00:11:24":"Apple","00:14:51":"Apple","00:16:CB":"Apple",
    "00:17:F2":"Apple","00:19:E3":"Apple","00:1B:63":"Apple","00:1C:B3":"Apple",
    "00:1D:4F":"Apple","00:1E:52":"Apple","00:1E:C2":"Apple","00:1F:5B":"Apple",
    "00:1F:F3":"Apple","00:21:E9":"Apple","00:22:41":"Apple","00:23:12":"Apple",
    "00:23:32":"Apple","00:23:6C":"Apple","00:23:DF":"Apple","00:24:36":"Apple",
    "00:25:00":"Apple","00:25:4B":"Apple","00:25:BC":"Apple","00:26:08":"Apple",
    "00:26:B0":"Apple","00:26:BB":"Apple","00:30:65":"Apple","34:C0:59":"Apple",
    "3C:07:54":"Apple","3C:15:C2":"Apple","40:31:3C":"Apple","40:6C:8F":"Apple",
    "40:A6:D9":"Apple","44:00:10":"Apple","44:2A:60":"Apple","44:FB:42":"Apple",
    "48:43:7C":"Apple","4C:57:CA":"Apple","4C:8D:79":"Apple","50:EA:D6":"Apple",
    "54:26:96":"Apple","58:1F:AA":"Apple","58:55:CA":"Apple","5C:59:48":"Apple",
    "60:03:08":"Apple","60:33:4B":"Apple","60:69:44":"Apple","60:C5:47":"Apple",
    "60:F4:45":"Apple","64:20:0C":"Apple","64:76:BA":"Apple","64:A3:CB":"Apple",
    "68:5B:35":"Apple","68:9C:70":"Apple","68:D9:3C":"Apple","6C:19:C0":"Apple",
    "6C:40:08":"Apple","6C:4D:73":"Apple","6C:70:9F":"Apple","70:3E:AC":"Apple",
    "70:48:0F":"Apple","70:56:81":"Apple","70:73:CB":"Apple","70:DE:E2":"Apple",
    "74:E1:B6":"Apple","74:E2:F5":"Apple","78:31:C1":"Apple","78:4F:43":"Apple",
    "7C:11:BE":"Apple","7C:D1:C3":"Apple","80:92:9F":"Apple","84:38:35":"Apple",
    "84:78:8B":"Apple","84:85:06":"Apple","88:19:08":"Apple","88:63:DF":"Apple",
    "8C:FA:BA":"Apple","90:3C:92":"Apple","98:03:D8":"Apple","98:01:A7":"Apple",
    "9C:20:7B":"Apple","A4:5E:60":"Apple","A8:86:DD":"Apple","A8:96:8A":"Apple",
    "AC:61:EA":"Apple","AC:7F:3E":"Apple","B8:09:8A":"Apple","B8:17:C2":"Apple",
    "B8:53:AC":"Apple","BC:3B:AF":"Apple","C8:B5:B7":"Apple","C8:BC:C8":"Apple",
    "CC:08:8D":"Apple","CC:78:5F":"Apple","D0:23:DB":"Apple","D4:61:9D":"Apple",
    "D8:00:4D":"Apple","D8:96:95":"Apple","E0:C7:67":"Apple","E4:CE:8F":"Apple",
    "E8:04:0B":"Apple","EC:35:86":"Apple","F0:99:BF":"Apple","F4:F1:5A":"Apple",
    "F8:1E:DF":"Apple","F8:27:93":"Apple","FC:25:3F":"Apple",
    # Samsung
    "00:02:78":"Samsung","00:07:AB":"Samsung","00:12:47":"Samsung","00:15:99":"Samsung",
    "00:16:32":"Samsung","00:17:C9":"Samsung","00:1A:8A":"Samsung","00:1D:25":"Samsung",
    "00:1E:7D":"Samsung","00:21:19":"Samsung","00:23:39":"Samsung","00:23:99":"Samsung",
    "08:08:C2":"Samsung","08:D4:2B":"Samsung","0C:14:20":"Samsung","14:49:E0":"Samsung",
    "14:A3:64":"Samsung","18:3A:2D":"Samsung","18:89:5B":"Samsung","1C:62:B8":"Samsung",
    "20:13:E0":"Samsung","20:54:76":"Samsung","24:4B:81":"Samsung","28:27:BF":"Samsung",
    "2C:AE:2B":"Samsung","30:07:4D":"Samsung","34:14:5F":"Samsung","38:2D:E8":"Samsung",
    "3C:62:00":"Samsung","3C:8B:FE":"Samsung","40:0E:85":"Samsung","44:4E:1A":"Samsung",
    "48:13:7E":"Samsung","4C:3C:16":"Samsung","50:01:BB":"Samsung","50:32:75":"Samsung",
    "54:88:0E":"Samsung","58:EF:68":"Samsung","5C:2E:59":"Samsung","5C:F8:21":"Samsung",
    "60:6B:BD":"Samsung","60:A1:0A":"Samsung","60:D0:A9":"Samsung","64:B3:10":"Samsung",
    "68:EB:AE":"Samsung","70:F9:27":"Samsung","74:45:8A":"Samsung","78:1F:DB":"Samsung",
    "7C:0B:C6":"Samsung","7C:61:93":"Samsung","80:65:6D":"Samsung","84:25:DB":"Samsung",
    "88:32:9B":"Samsung","8C:71:F8":"Samsung","90:18:7C":"Samsung","94:35:0A":"Samsung",
    "94:76:B7":"Samsung","98:52:B1":"Samsung","9C:3A:AF":"Samsung","A0:07:98":"Samsung",
    "A0:82:1F":"Samsung","A4:19:D7":"Samsung","AC:EE:9E":"Samsung","B4:3A:28":"Samsung",
    "B8:5E:7B":"Samsung","BC:14:85":"Samsung","BC:72:B1":"Samsung","C0:74:2B":"Samsung",
    "C8:19:F7":"Samsung","CC:05:1B":"Samsung","D0:22:BE":"Samsung","D4:87:D8":"Samsung",
    "D8:57:EF":"Samsung","DC:71:96":"Samsung","E4:40:E2":"Samsung","E8:03:9A":"Samsung",
    "EC:1F:72":"Samsung","F0:25:B7":"Samsung","F4:7B:5E":"Samsung","FC:A1:3E":"Samsung",
    # Google
    "00:1A:11":"Google","08:9E:08":"Google","1C:F2:9A":"Google","3C:5A:B4":"Google",
    "48:D6:D5":"Google","54:60:09":"Google","6C:AD:F8":"Google","70:3A:CB":"Google",
    "A4:77:33":"Google","B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
    "E4:5F:01":"Raspberry Pi","28:CD:C1":"Raspberry Pi",
    # Amazon
    "00:BB:3A":"Amazon","0C:47:C9":"Amazon","18:74:2E":"Amazon","34:D2:70":"Amazon",
    "40:B4:CD":"Amazon","44:65:0D":"Amazon","50:F5:DA":"Amazon","68:37:E9":"Amazon",
    "74:75:48":"Amazon","84:D6:D0":"Amazon","A0:02:DC":"Amazon","B4:7C:9C":"Amazon",
    "CC:9E:A2":"Amazon","F0:81:73":"Amazon","F0:D2:F1":"Amazon","FC:A1:83":"Amazon",
    # Microsoft
    "00:0D:3A":"Microsoft","00:12:5A":"Microsoft","00:17:FA":"Microsoft",
    "00:1D:D8":"Microsoft","00:22:48":"Microsoft","00:50:F2":"Microsoft",
    "28:18:78":"Microsoft","3C:18:A0":"Microsoft","48:50:73":"Microsoft",
    "58:82:A8":"Microsoft","60:45:BD":"Microsoft","7C:1E:52":"Microsoft",
    "7C:ED:8D":"Microsoft","98:5F:D3":"Microsoft","B4:AE:2B":"Microsoft",
    "C4:9D:ED":"Microsoft","DC:F7:56":"Microsoft",
    # Intel (common in laptops/PCs)
    "00:02:B3":"Intel","00:03:47":"Intel","00:04:23":"Intel","00:07:E9":"Intel",
    "00:0C:F1":"Intel","00:0E:0C":"Intel","00:0E:35":"Intel","00:11:11":"Intel",
    "00:13:02":"Intel","00:13:20":"Intel","00:13:CE":"Intel","00:13:E8":"Intel",
    "00:15:00":"Intel","00:16:76":"Intel","00:16:EA":"Intel","00:16:EB":"Intel",
    "00:18:DE":"Intel","00:19:D1":"Intel","00:19:D2":"Intel","00:1B:21":"Intel",
    "00:1C:BF":"Intel","00:1D:E0":"Intel","00:1E:64":"Intel","00:1E:65":"Intel",
    "00:1F:3B":"Intel","00:1F:3C":"Intel","00:21:5C":"Intel","00:21:5D":"Intel",
    "00:22:FA":"Intel","00:22:FB":"Intel","00:23:14":"Intel","00:23:15":"Intel",
    "40:25:C2":"Intel","44:85:00":"Intel","48:45:20":"Intel","4C:34:88":"Intel",
    "54:27:1E":"Intel","60:36:DD":"Intel","64:D4:DA":"Intel","68:05:CA":"Intel",
    "70:5A:0F":"Intel","74:E5:0B":"Intel","78:92:9C":"Intel","7C:5C:F8":"Intel",
    "80:19:34":"Intel","84:3A:4B":"Intel","88:53:2E":"Intel","8C:EC:4B":"Intel",
    "90:E2:BA":"Intel","94:65:9C":"Intel","9C:B6:D0":"Intel","A0:36:BC":"Intel",
    "A4:34:D9":"Intel","AC:72:89":"Intel","B0:35:9F":"Intel","B4:B6:76":"Intel",
    "B8:70:F4":"Intel","C4:D9:87":"Intel","C8:3D:D4":"Intel","CC:3D:82":"Intel",
    "D0:50:99":"Intel","D4:3D:7E":"Intel","D8:FC:93":"Intel","DC:53:60":"Intel",
    "E0:94:67":"Intel","E4:B3:18":"Intel","E8:6A:64":"Intel","EC:08:6B":"Intel",
    "F0:76:1C":"Intel","F4:4D:30":"Intel","F8:16:54":"Intel",
    # Cisco
    "00:00:0C":"Cisco","00:01:42":"Cisco","00:01:43":"Cisco","00:01:63":"Cisco",
    "00:01:64":"Cisco","00:01:96":"Cisco","00:01:97":"Cisco","00:02:16":"Cisco",
    "00:02:17":"Cisco","00:03:6B":"Cisco","00:03:6C":"Cisco","00:04:C0":"Cisco",
    "00:05:31":"Cisco","00:05:32":"Cisco","00:06:28":"Cisco","00:06:52":"Cisco",
    "00:07:0D":"Cisco","00:07:50":"Cisco","00:07:7D":"Cisco","00:07:EB":"Cisco",
    "00:08:30":"Cisco","00:0A:41":"Cisco","00:0A:42":"Cisco","00:0A:8A":"Cisco",
    "00:0A:F3":"Cisco","00:0B:45":"Cisco","00:0B:46":"Cisco","00:0B:BE":"Cisco",
    "00:0B:BF":"Cisco","00:0C:85":"Cisco","00:0C:86":"Cisco","00:0D:28":"Cisco",
    "00:0D:BD":"Cisco","00:0E:08":"Cisco","00:0E:38":"Cisco","00:0E:83":"Cisco",
    "00:0E:84":"Cisco","00:0F:23":"Cisco","00:0F:24":"Cisco","00:0F:34":"Cisco",
    "00:10:07":"Cisco","00:10:11":"Cisco","00:10:1F":"Cisco","00:10:2F":"Cisco",
    "58:97:1E":"Cisco","6C:20:56":"Cisco","70:69:5A":"Cisco","78:72:5D":"Cisco",
    "84:78:AC":"Cisco","88:75:98":"Cisco","8C:60:4F":"Cisco","90:6C:AC":"Cisco",
    "A0:93:51":"Cisco","A4:4C:11":"Cisco","A8:9D:21":"Cisco","AC:17:C8":"Cisco",
    "B0:FA:EB":"Cisco","B4:14:89":"Cisco","BC:16:F5":"Cisco","C0:67:AF":"Cisco",
    "C4:71:FE":"Cisco","C8:9C:1D":"Cisco","CC:AF:78":"Cisco","D0:57:4C":"Cisco",
    # TP-Link
    "00:27:19":"TP-Link","14:CF:92":"TP-Link","18:D6:C7":"TP-Link","1C:3B:F3":"TP-Link",
    "20:DC:E6":"TP-Link","28:2C:B2":"TP-Link","2C:4D:54":"TP-Link","38:2C:4A":"TP-Link",
    "40:8D:5C":"TP-Link","44:33:4C":"TP-Link","50:3E:AA":"TP-Link","54:AF:97":"TP-Link",
    "58:00:E3":"TP-Link","60:32:B1":"TP-Link","64:70:02":"TP-Link","6C:5A:B0":"TP-Link",
    "70:4F:57":"TP-Link","74:DA:38":"TP-Link","78:32:1B":"TP-Link","7C:8B:CA":"TP-Link",
    "80:35:C1":"TP-Link","84:16:F9":"TP-Link","90:F6:52":"TP-Link","94:D9:B3":"TP-Link",
    "98:DA:C4":"TP-Link","A0:F3:C1":"TP-Link","A4:2B:B0":"TP-Link","A8:40:41":"TP-Link",
    "AC:84:C6":"TP-Link","B0:4E:26":"TP-Link","B4:B0:24":"TP-Link","B8:AC:6F":"TP-Link",
    "BC:46:99":"TP-Link","C0:4A:00":"TP-Link","C4:E9:84":"TP-Link","C8:3A:35":"TP-Link",
    "CC:32:E5":"TP-Link","D4:6E:0E":"TP-Link","D8:15:0D":"TP-Link","DC:FE:18":"TP-Link",
    "E0:05:C5":"TP-Link","E4:C3:2A":"TP-Link","E8:DE:27":"TP-Link","EC:17:2F":"TP-Link",
    "F0:D4:E2":"TP-Link","F4:EC:38":"TP-Link","F8:1A:67":"TP-Link","FC:EC:DA":"TP-Link",
    # Netgear
    "00:09:5B":"Netgear","00:0F:B5":"Netgear","00:14:6C":"Netgear","00:18:4D":"Netgear",
    "00:1B:2F":"Netgear","00:1E:2A":"Netgear","00:22:3F":"Netgear","00:24:B2":"Netgear",
    "00:26:F2":"Netgear","04:A1:51":"Netgear","10:0C:6B":"Netgear","20:4E:7F":"Netgear",
    "28:C6:8E":"Netgear","2C:B0:5D":"Netgear","30:46:9A":"Netgear","3C:37:86":"Netgear",
    "44:94:FC":"Netgear","4C:60:DE":"Netgear","6C:B0:CE":"Netgear","74:44:01":"Netgear",
    "84:1B:5E":"Netgear","A0:21:B7":"Netgear","A0:40:A0":"Netgear","B0:39:56":"Netgear",
    "C0:3F:0E":"Netgear","C4:04:15":"Netgear","CC:40:D0":"Netgear","E0:46:9A":"Netgear",
    "E4:F4:C6":"Netgear",
    # Asus
    "00:0C:6E":"Asus","00:11:2F":"Asus","00:13:D4":"Asus","00:15:F2":"Asus",
    "00:17:31":"Asus","00:1A:92":"Asus","00:1D:60":"Asus","00:1E:8C":"Asus",
    "00:22:15":"Asus","00:23:54":"Asus","00:24:8C":"Asus","00:26:18":"Asus",
    "04:92:26":"Asus","08:60:6E":"Asus","10:02:B5":"Asus","10:BF:48":"Asus",
    "14:DA:E9":"Asus","18:31:BF":"Asus","1C:87:2C":"Asus","20:CF:30":"Asus",
    "24:4B:FE":"Asus","28:56:C8":"Asus","2C:56:DC":"Asus","30:5A:3A":"Asus",
    "38:2C:4A":"Asus","3C:97:0E":"Asus","40:16:7E":"Asus","48:5B:39":"Asus",
    "50:46:5D":"Asus","54:04:A6":"Asus","58:11:22":"Asus","5C:FF:35":"Asus",
    "60:45:CB":"Asus","6C:FD:B9":"Asus","70:8B:CD":"Asus","74:D0:2B":"Asus",
    "7C:10:C9":"Asus","88:D7:F6":"Asus","90:E6:BA":"Asus","A8:5E:45":"Asus",
    "AC:22:0B":"Asus","B0:6E:BF":"Asus","BC:AE:C5":"Asus","C8:60:00":"Asus",
    "D0:17:C2":"Asus","D4:5D:64":"Asus","D8:50:E6":"Asus","E0:CB:4E":"Asus",
    "E4:70:B8":"Asus","EC:4C:4D":"Asus","F0:2F:74":"Asus","F4:6D:04":"Asus",
    # Dell
    "00:06:5B":"Dell","00:08:74":"Dell","00:0B:DB":"Dell","00:0D:56":"Dell",
    "00:0F:1F":"Dell","00:11:43":"Dell","00:12:3F":"Dell","00:13:72":"Dell",
    "00:14:22":"Dell","00:15:C5":"Dell","00:16:F0":"Dell","00:18:8B":"Dell",
    "00:19:B9":"Dell","00:1A:A0":"Dell","00:1C:23":"Dell","00:1D:09":"Dell",
    "00:1E:4F":"Dell","00:21:70":"Dell","00:22:19":"Dell","00:23:AE":"Dell",
    "00:24:E8":"Dell","00:25:64":"Dell","00:26:B9":"Dell","18:03:73":"Dell",
    "18:66:DA":"Dell","1C:40:24":"Dell","20:47:47":"Dell","24:B6:FD":"Dell",
    "28:F1:0E":"Dell","2C:76:8A":"Dell","34:17:EB":"Dell","34:E6:D7":"Dell",
    "38:EA:A7":"Dell","3C:2C:30":"Dell","44:A8:42":"Dell","48:9A:D2":"Dell",
    "4C:D9:8F":"Dell","50:9A:4C":"Dell","54:9F:35":"Dell","58:8A:5A":"Dell",
    "5C:26:0A":"Dell","60:36:DD":"Dell","6C:AE:8B":"Dell","70:10:6F":"Dell",
    "74:86:7A":"Dell","78:45:C4":"Dell","84:8F:69":"Dell","90:B1:1C":"Dell",
    "98:90:96":"Dell","9C:EB:E8":"Dell","A4:1F:72":"Dell","A8:9F:BA":"Dell",
    "B0:83:FE":"Dell","B4:45:06":"Dell","BC:30:5B":"Dell","C8:1F:66":"Dell",
    "D0:94:66":"Dell","D4:BE:D9":"Dell","D8:D3:85":"Dell","DC:E9:94":"Dell",
    # Huawei
    "00:18:82":"Huawei","00:1E:10":"Huawei","00:25:9E":"Huawei","00:46:4B":"Huawei",
    "04:02:1F":"Huawei","04:BD:70":"Huawei","04:C0:6F":"Huawei","04:F9:38":"Huawei",
    "08:19:A6":"Huawei","08:3F:BC":"Huawei","08:63:61":"Huawei","08:7A:4C":"Huawei",
    "0C:37:DC":"Huawei","0C:96:BF":"Huawei","10:1B:54":"Huawei","10:47:80":"Huawei",
    "14:A5:1A":"Huawei","18:C5:8A":"Huawei","1C:8E:5C":"Huawei","20:08:ED":"Huawei",
    "20:2B:C1":"Huawei","20:F3:A3":"Huawei","24:09:95":"Huawei","24:4C:07":"Huawei",
    "28:6E:D4":"Huawei","2C:AB:00":"Huawei","2C:CF:CB":"Huawei","30:D1:7E":"Huawei",
    "34:6A:C2":"Huawei","38:F8:89":"Huawei","3C:F8:08":"Huawei","40:4D:8E":"Huawei",
    "48:00:31":"Huawei","4C:1F:CC":"Huawei","50:68:0A":"Huawei","54:51:1B":"Huawei",
    "5C:C3:07":"Huawei","60:DE:44":"Huawei","64:3E:8C":"Huawei","68:13:24":"Huawei",
    "6C:8D:C1":"Huawei","70:72:CF":"Huawei","74:A0:2F":"Huawei","78:1D:BA":"Huawei",
    "7C:A2:3E":"Huawei","80:38:BC":"Huawei","84:A8:E4":"Huawei","88:A2:5E":"Huawei",
    "8C:34:FD":"Huawei","90:17:AC":"Huawei","94:04:9C":"Huawei","98:D8:63":"Huawei",
    "9C:28:EF":"Huawei","A4:99:47":"Huawei","A8:0C:63":"Huawei","AC:4E:91":"Huawei",
    # Xiaomi
    "00:9E:C8":"Xiaomi","0C:1D:AF":"Xiaomi","10:2A:B3":"Xiaomi","14:F6:5A":"Xiaomi",
    "18:59:36":"Xiaomi","20:82:C0":"Xiaomi","28:6C:07":"Xiaomi","34:CE:00":"Xiaomi",
    "38:A4:ED":"Xiaomi","3C:BD:D8":"Xiaomi","50:64:2B":"Xiaomi","58:44:98":"Xiaomi",
    "64:09:80":"Xiaomi","68:DF:DD":"Xiaomi","74:23:44":"Xiaomi","78:02:F8":"Xiaomi",
    "8C:BE:BE":"Xiaomi","98:FA:E3":"Xiaomi","9C:99:A0":"Xiaomi","A4:50:46":"Xiaomi",
    "AC:C1:EE":"Xiaomi","B0:E2:35":"Xiaomi","C4:0B:CB":"Xiaomi","D4:97:0B":"Xiaomi",
    "F0:B4:29":"Xiaomi","F4:8B:32":"Xiaomi","FC:64:BA":"Xiaomi",
    # Sonos, Philips Hue, Ring, Nest (IoT)
    "00:0E:58":"Sonos","34:7E:5C":"Sonos","5C:AA:FD":"Sonos","78:28:CA":"Sonos",
    "94:9F:3E":"Sonos","B8:E9:37":"Sonos",
    "00:17:88":"Philips Hue","EC:B5:FA":"Philips Hue",
    "B0:09:DA":"Ring","FC:65:DE":"Ring",
    "18:B4:30":"Nest","64:16:66":"Nest",
    # Synology, QNAP (NAS)
    "00:11:32":"Synology","00:50:43":"Synology",
    "24:5E:BE":"QNAP","00:08:9B":"QNAP",
    # VMware / VirtualBox (VMs)
    "00:0C:29":"VMware","00:50:56":"VMware","00:05:69":"VMware",
    "08:00:27":"VirtualBox",
    # Ubiquiti
    "00:15:6D":"Ubiquiti","00:27:22":"Ubiquiti","04:18:D6":"Ubiquiti",
    "0E:A8:1F":"Ubiquiti","18:E8:29":"Ubiquiti","24:A4:3C":"Ubiquiti",
    "44:D9:E7":"Ubiquiti","68:72:51":"Ubiquiti","70:A7:41":"Ubiquiti",
    "74:83:C2":"Ubiquiti","78:8A:20":"Ubiquiti","80:2A:A8":"Ubiquiti",
    "B4:FB:E4":"Ubiquiti","DC:9F:DB":"Ubiquiti","F0:9F:C2":"Ubiquiti",
    "F4:92:BF":"Ubiquiti","FC:EC:DA":"Ubiquiti",
    # Nintendo, Sony PlayStation, Xbox
    "00:09:BF":"Nintendo","00:16:56":"Nintendo","00:17:AB":"Nintendo",
    "00:19:1D":"Nintendo","00:1A:E9":"Nintendo","00:1B:EA":"Nintendo",
    "00:1C:BE":"Nintendo","00:1E:35":"Nintendo","00:1F:32":"Nintendo",
    "00:21:47":"Nintendo","00:22:D7":"Nintendo","00:23:CC":"Nintendo",
    "00:24:44":"Nintendo","58:2F:40":"Nintendo","78:A2:A0":"Nintendo",
    "00:04:1F":"Sony","00:13:A9":"Sony","00:15:C1":"Sony","00:24:BE":"Sony",
    "28:0D:FC":"Sony","4C:B9:9B":"Sony","F8:D0:AC":"Sony",
    "00:50:F2":"Microsoft","7C:ED:8D":"Microsoft","00:25:AE":"Microsoft",
    # LG
    "00:1C:62":"LG","00:1E:75":"LG","00:AA:70":"LG","18:3D:A2":"LG",
    "20:82:C0":"LG","28:39:26":"LG","34:FC:EF":"LG","40:B0:FA":"LG",
    "48:59:29":"LG","50:55:27":"LG","64:99:5D":"LG","78:5D:C8":"LG",
    "8C:3C:4A":"LG","90:F1:AA":"LG","B4:E6:2A":"LG","CC:FA:00":"LG",
}


def _vendor(mac):
    mac = mac.upper().replace("-",":")
    for k,v in OUI.items():
        if mac.startswith(k.upper()): return v
    return "Unknown"

def _resolve(ip: str) -> str:
    """
    Resolve hostname via multiple methods:
    1. Reverse DNS (PTR record)
    2. mDNS/Bonjour (.local hostnames for Apple/Linux devices)
    3. NetBIOS name query (Windows devices)
    """
    hostname = ""
    # Method 1: Reverse DNS / PTR
    try:
        h = socket.gethostbyaddr(ip)[0]
        if h and h != ip:
            hostname = h
    except Exception: pass
    if hostname: return hostname
    # Method 2: mDNS via avahi-resolve (Linux — gets .local names)
    try:
        out = subprocess.check_output(
            ["avahi-resolve","-a", ip], text=True, timeout=2,
            stderr=subprocess.DEVNULL)
        m = re.search(r"\t(\S+\.local)", out)
        if m: return m.group(1)
    except Exception: pass
    # Method 3: nmblookup NetBIOS (Windows machines)
    try:
        out = subprocess.check_output(
            ["nmblookup","-A", ip], text=True, timeout=2,
            stderr=subprocess.DEVNULL)
        m = re.search(r"^\s+(\S+)\s+<00>\s+", out, re.MULTILINE)
        if m: return m.group(1).strip()
    except Exception: pass
    return ""

def _port_scan(ip: str, ports: list, timeout: float = 0.35) -> list:
    """Parallel TCP connect scan — all ports simultaneously."""
    import concurrent.futures as _cf
    import socket as _s
    open_p = []
    def _probe(p):
        try:
            sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
            sock.settimeout(timeout)
            r = sock.connect_ex((ip, p))
            sock.close()
            return p if r == 0 else None
        except Exception:
            return None
    with _cf.ThreadPoolExecutor(max_workers=min(len(ports), 30)) as ex:
        for result in ex.map(_probe, ports):
            if result is not None:
                open_p.append(result)
    return sorted(open_p)

def _read_arp_table():
    """Read ARP table from all available sources."""
    known = {}
    # Method 1: /proc/net/arp (Linux, most reliable)
    try:
        with open("/proc/net/arp") as f:
            for line in list(f)[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "0x0":
                    mac = parts[3].lower()
                    if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                        known[parts[0]] = mac
    except Exception: pass
    # Method 2: arp -a command
    try:
        out = subprocess.check_output(["arp","-a"], text=True, timeout=5,
                                       stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
            if m and m.group(1) not in known:
                known[m.group(1)] = m.group(2).lower()
    except Exception: pass
    # Method 3: ip neigh (iproute2 — more complete than arp -a)
    try:
        out = subprocess.check_output(["ip","neigh","show"], text=True, timeout=5,
                                       stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            # Format: IP dev IFACE lladdr MAC state STATE
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+).+lladdr\s+([0-9a-fA-F:]{17})", line)
            if m and m.group(1) not in known:
                known[m.group(1)] = m.group(2).lower()
    except Exception: pass
    return known


def _arping(ip: str) -> str:
    """
    Send an ARP request to a specific IP to force an ARP reply.
    After the request, read the ARP table to get the MAC.
    Works without root on most systems via arping tool.
    """
    # Method 1: arping (most reliable, may need root)
    for cmd in [["arping","-c","1","-W","1",ip],
                ["arping","-c","1","-w","1",ip]]:
        try:
            out = subprocess.check_output(cmd, text=True, timeout=3,
                                           stderr=subprocess.DEVNULL)
            m = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:"
                          r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", out)
            if m: return m.group(1).lower()
        except Exception: pass
    # Method 2: ping first (populates ARP cache) then read table
    try:
        subprocess.call(["ping","-c","1","-W","1",ip],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        time.sleep(0.1)   # give kernel time to update ARP cache
        arp = _read_arp_table()
        if ip in arp: return arp[ip]
    except Exception: pass
    return ""

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

        # Fill missing MACs using ARP table + targeted arping
        arp_cache = _read_arp_table()
        for d in found:
            if not d.get("mac"):
                ip = d.get("ip","")
                if ip in arp_cache:
                    d["mac"] = arp_cache[ip]
                else:
                    # Active ARP request — only for devices without a MAC
                    mac = _arping(ip)
                    if mac: d["mac"] = mac
                    elif ip in _read_arp_table(): d["mac"] = _read_arp_table()[ip]

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
        # ── Update online/offline status ──────────────────────────────────
        seen_ips = {d.get("ip") for d in found}
        with self._lock:
            for ip, dev in self._devices.items():
                dev["online"] = (ip in seen_ips)
        logger.info(f"Asset scan: {len(self._devices)} total, {len(new_devs)} new, "
                    f"{sum(1 for d in self._devices.values() if d.get('online'))} online")
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
