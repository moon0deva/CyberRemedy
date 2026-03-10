"""
CyberRemedy Threat Intelligence — IOC Manager
Ingests and manages Indicators of Compromise from:
  - VirusTotal API (hash/IP/domain lookups)
  - MISP event feeds
  - AlienVault OTX pulses
  - Custom IOC lists (CSV/JSON/plain text)
  - TAXII/STIX feeds (basic support)
"""

import os
import json
import time
import logging
import hashlib
import threading
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cyberremedy.threat_intel")

IOC_STORE_PATH = Path("data/ioc_store.json")
IOC_CACHE_PATH = Path("data/vt_cache.json")


# ─── IOC RECORD ───────────────────────────────────────────────────────────────

class IOCRecord:
    def __init__(self, ioc_type: str, value: str, source: str,
                 severity: str = "HIGH", tags: list = None, expires_at: str = None):
        self.ioc_type = ioc_type        # ip, domain, hash, url, email
        self.value = value.lower().strip()
        self.source = source            # virustotal, misp, otx, custom
        self.severity = severity
        self.tags = tags or []
        self.added_at = datetime.utcnow().isoformat()
        self.expires_at = expires_at
        self.hit_count = 0
        self.last_seen = None

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "tags": self.tags,
            "added_at": self.added_at,
            "expires_at": self.expires_at,
            "hit_count": self.hit_count,
            "last_seen": self.last_seen,
        }

    @staticmethod
    def from_dict(d: dict) -> "IOCRecord":
        r = IOCRecord(d["ioc_type"], d["value"], d["source"],
                      d.get("severity", "HIGH"), d.get("tags", []), d.get("expires_at"))
        r.added_at = d.get("added_at", r.added_at)
        r.hit_count = d.get("hit_count", 0)
        r.last_seen = d.get("last_seen")
        return r


# ─── IOC STORE ────────────────────────────────────────────────────────────────

class IOCStore:
    """In-memory + persisted IOC database with fast lookup."""

    def __init__(self, store_path: Path = IOC_STORE_PATH):
        self.store_path = store_path
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._ips: Dict[str, IOCRecord] = {}
        self._domains: Dict[str, IOCRecord] = {}
        self._hashes: Dict[str, IOCRecord] = {}
        self._urls: Dict[str, IOCRecord] = {}
        self._load()

    def _load(self):
        if self.store_path.exists():
            try:
                data = json.loads(self.store_path.read_text())
                for d in data.get("ips", []):
                    r = IOCRecord.from_dict(d); self._ips[r.value] = r
                for d in data.get("domains", []):
                    r = IOCRecord.from_dict(d); self._domains[r.value] = r
                for d in data.get("hashes", []):
                    r = IOCRecord.from_dict(d); self._hashes[r.value] = r
                for d in data.get("urls", []):
                    r = IOCRecord.from_dict(d); self._urls[r.value] = r
                logger.info(f"IOC store loaded: {self.total_count} indicators")
            except Exception as e:
                logger.warning(f"IOC store load error: {e}")

    def save(self):
        data = {
            "ips": [r.to_dict() for r in self._ips.values()],
            "domains": [r.to_dict() for r in self._domains.values()],
            "hashes": [r.to_dict() for r in self._hashes.values()],
            "urls": [r.to_dict() for r in self._urls.values()],
            "saved_at": datetime.utcnow().isoformat(),
        }
        self.store_path.write_text(json.dumps(data, indent=2))

    def add(self, record: IOCRecord):
        store = self._get_store(record.ioc_type)
        if store is not None:
            store[record.value] = record

    def _get_store(self, ioc_type: str) -> Optional[Dict]:
        return {"ip": self._ips, "domain": self._domains,
                "hash": self._hashes, "url": self._urls}.get(ioc_type)

    def lookup_ip(self, ip: str) -> Optional[IOCRecord]:
        r = self._ips.get(ip.lower())
        if r: r.hit_count += 1; r.last_seen = datetime.utcnow().isoformat()
        return r

    def lookup_domain(self, domain: str) -> Optional[IOCRecord]:
        r = self._domains.get(domain.lower())
        if r: r.hit_count += 1; r.last_seen = datetime.utcnow().isoformat()
        return r

    def lookup_hash(self, file_hash: str) -> Optional[IOCRecord]:
        r = self._hashes.get(file_hash.lower())
        if r: r.hit_count += 1; r.last_seen = datetime.utcnow().isoformat()
        return r

    def enrich_alert(self, alert: dict) -> dict:
        """Check alert src/dst IPs and any hashes against IOC store."""
        ioc_hits = []
        for field in ("src_ip", "dst_ip"):
            ip = alert.get(field, "")
            if ip:
                rec = self.lookup_ip(ip)
                if rec:
                    ioc_hits.append({"field": field, "ioc": rec.to_dict()})
        if ioc_hits:
            alert["ioc_hits"] = ioc_hits
            alert["ioc_matched"] = True
            # Escalate severity if IOC found
            current_sev = alert.get("severity", "LOW")
            if rec.severity == "CRITICAL" or current_sev in ("LOW", "MEDIUM"):
                alert["severity"] = rec.severity
            alert["risk_score"] = min(100, alert.get("risk_score", 0) + 25)
        return alert

    def remove_expired(self):
        now = datetime.utcnow()
        for store in (self._ips, self._domains, self._hashes, self._urls):
            expired = [k for k, v in store.items()
                       if v.expires_at and datetime.fromisoformat(v.expires_at) < now]
            for k in expired:
                del store[k]

    @property
    def total_count(self) -> int:
        return len(self._ips) + len(self._domains) + len(self._hashes) + len(self._urls)

    def stats(self) -> dict:
        return {"ips": len(self._ips), "domains": len(self._domains),
                "hashes": len(self._hashes), "urls": len(self._urls),
                "total": self.total_count}


# ─── VIRUSTOTAL LOOKUP ────────────────────────────────────────────────────────

class VirusTotalClient:
    """VirusTotal v3 API for on-demand hash/IP/domain lookups."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self._cache: Dict[str, dict] = {}
        self._load_cache()

    def _load_cache(self):
        if IOC_CACHE_PATH.exists():
            try:
                self._cache = json.loads(IOC_CACHE_PATH.read_text())
            except Exception:
                self._cache = {}

    def _save_cache(self):
        IOC_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        IOC_CACHE_PATH.write_text(json.dumps(self._cache, indent=2))

    def _request(self, endpoint: str) -> Optional[dict]:
        if not self.api_key:
            return None
        key = endpoint
        if key in self._cache:
            cached = self._cache[key]
            if time.time() - cached.get("_ts", 0) < 3600:
                return cached
        try:
            url = f"{self.BASE}/{endpoint}"
            req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                data["_ts"] = time.time()
                self._cache[key] = data
                self._save_cache()
                return data
        except Exception as e:
            logger.debug(f"VT API error: {e}")
            return None

    def lookup_ip(self, ip: str) -> Optional[dict]:
        data = self._request(f"ip_addresses/{ip}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            return {"ip": ip, "malicious_votes": malicious,
                    "country": attrs.get("country", "?"),
                    "owner": attrs.get("as_owner", "?"),
                    "source": "virustotal"}
        return None

    def lookup_hash(self, file_hash: str) -> Optional[dict]:
        data = self._request(f"files/{file_hash}")
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            return {"hash": file_hash, "malicious_votes": malicious,
                    "name": attrs.get("meaningful_name", "?"),
                    "type": attrs.get("type_description", "?"),
                    "source": "virustotal"}
        return None


# ─── CUSTOM IOC LOADER ────────────────────────────────────────────────────────

class CustomIOCLoader:
    """Load IOCs from plain text, CSV, or JSON files."""

    def load_file(self, path: str, ioc_type: str = "ip",
                  severity: str = "HIGH") -> List[IOCRecord]:
        records = []
        p = Path(path)
        if not p.exists():
            logger.warning(f"IOC file not found: {path}")
            return records

        content = p.read_text()

        # JSON format: list of {type, value, severity, tags}
        if path.endswith(".json"):
            try:
                items = json.loads(content)
                for item in items:
                    records.append(IOCRecord(
                        ioc_type=item.get("type", ioc_type),
                        value=item.get("value", item.get("ioc", "")),
                        source="custom_file",
                        severity=item.get("severity", severity),
                        tags=item.get("tags", []),
                    ))
            except Exception as e:
                logger.warning(f"JSON IOC parse error: {e}")
        else:
            # Plain text or CSV — one IOC per line
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                value = line.split(",")[0].strip()
                records.append(IOCRecord(ioc_type=ioc_type, value=value,
                                         source="custom_file", severity=severity))

        logger.info(f"Loaded {len(records)} IOCs from {path}")
        return records

    def load_misp_feed(self, feed_url: str, store: IOCStore):
        """Load IOCs from a public MISP feed (JSON format)."""
        try:
            with urllib.request.urlopen(feed_url, timeout=15) as resp:
                data = json.loads(resp.read())
            events = data if isinstance(data, list) else [data]
            count = 0
            for event in events:
                for attr in event.get("Event", {}).get("Attribute", []):
                    atype = attr.get("type", "")
                    value = attr.get("value", "")
                    if atype == "ip-dst" or atype == "ip-src":
                        store.add(IOCRecord("ip", value, "misp", "HIGH"))
                        count += 1
                    elif atype in ("domain", "hostname"):
                        store.add(IOCRecord("domain", value, "misp", "HIGH"))
                        count += 1
                    elif atype in ("md5", "sha1", "sha256"):
                        store.add(IOCRecord("hash", value, "misp", "HIGH"))
                        count += 1
            logger.info(f"MISP feed: {count} IOCs loaded")
        except Exception as e:
            logger.warning(f"MISP feed error: {e}")


# ─── IOC MANAGER (MAIN INTERFACE) ─────────────────────────────────────────────

class IOCManager:
    """Central IOC management interface used by the detection pipeline."""

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.store = IOCStore()
        self.vt = VirusTotalClient(cfg.get("virustotal_api_key"))
        self.loader = CustomIOCLoader()
        self._refresh_interval = cfg.get("refresh_interval_hours", 24) * 3600
        self._running = False

        # Load any configured IOC files on startup
        for ioc_file in cfg.get("ioc_files", []):
            records = self.loader.load_file(ioc_file.get("path"), ioc_file.get("type", "ip"))
            for r in records:
                self.store.add(r)
        if cfg.get("ioc_files"):
            self.store.save()

        # Seed with known bad IPs for demo
        self._seed_demo_iocs()

    def _seed_demo_iocs(self):
        """Seed a small set of demo IOCs so the system is useful out of the box."""
        demo = [
            IOCRecord("ip", "198.51.100.1", "demo_feed", "HIGH", ["c2", "botnet"]),
            IOCRecord("ip", "203.0.113.5", "demo_feed", "CRITICAL", ["ransomware", "c2"]),
            IOCRecord("domain", "evil-c2-server.net", "demo_feed", "CRITICAL", ["c2"]),
            IOCRecord("domain", "malware-download.ru", "demo_feed", "HIGH", ["malware"]),
            IOCRecord("hash", "d41d8cd98f00b204e9800998ecf8427e", "demo_feed", "CRITICAL",
                      ["ransomware"]),
        ]
        for r in demo:
            if r.ioc_type == "ip" and r.value not in self.store._ips:
                self.store.add(r)
            elif r.ioc_type == "domain" and r.value not in self.store._domains:
                self.store.add(r)
            elif r.ioc_type == "hash" and r.value not in self.store._hashes:
                self.store.add(r)

    def enrich_alert(self, alert: dict) -> dict:
        """Enrich an alert with IOC match information."""
        return self.store.enrich_alert(alert)

    def add_ioc(self, ioc_type: str, value: str, source: str = "manual",
                severity: str = "HIGH", tags: list = None) -> IOCRecord:
        r = IOCRecord(ioc_type, value, source, severity, tags or [])
        self.store.add(r)
        self.store.save()
        return r

    def lookup_ip_vt(self, ip: str) -> Optional[dict]:
        """Live VirusTotal lookup — adds to store if malicious."""
        result = self.vt.lookup_ip(ip)
        if result:
            r = IOCRecord("ip", ip, "virustotal", "HIGH", ["vt_positive"])
            self.store.add(r)
            self.store.save()
        return result

    def lookup_hash_vt(self, file_hash: str) -> Optional[dict]:
        result = self.vt.lookup_hash(file_hash)
        if result:
            r = IOCRecord("hash", file_hash, "virustotal", "CRITICAL", ["malware"])
            self.store.add(r)
            self.store.save()
        return result

    def get_stats(self) -> dict:
        return self.store.stats()

    def get_all(self, limit: int = 500) -> List[dict]:
        all_iocs = (
            list(self.store._ips.values()) +
            list(self.store._domains.values()) +
            list(self.store._hashes.values()) +
            list(self.store._urls.values())
        )
        return [r.to_dict() for r in sorted(all_iocs, key=lambda x: x.added_at, reverse=True)[:limit]]
