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

# ─── PUBLIC FEED CATALOG ─────────────────────────────────────────────────────
# All free, no-key-required threat intelligence feeds.
# Each entry: name, url, ioc_type, severity, tags, parser hint
FEED_CATALOG = [
    # ── Abuse.ch family ───────────────────────────────────────────────────────
    {
        "name": "FeodoTracker",
        "url":  "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "ip",  "severity": "CRITICAL",
        "tags": ["botnet", "c2", "feodotracker"],
        "parse": "csv_first_col",  "skip_prefix": ["#", "dst_ip"],
    },
    {
        "name": "URLhaus",
        "url":  "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "url", "severity": "HIGH",
        "tags": ["malware", "urlhaus"],
        "parse": "plain", "skip_prefix": ["#"],
    },
    {
        "name": "ThreatFox-IPs",
        "url":  "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "type": "ip",  "severity": "HIGH",
        "tags": ["threatfox", "malware"],
        "parse": "csv_col2_strip_port", "skip_prefix": ["#", '"first_seen"'],
    },
    {
        "name": "ThreatFox-Domains",
        "url":  "https://threatfox.abuse.ch/export/csv/domain/recent/",
        "type": "domain", "severity": "HIGH",
        "tags": ["threatfox", "malware"],
        "parse": "csv_col2", "skip_prefix": ["#", '"first_seen"'],
    },
    {
        "name": "MalwareBazaar",
        "url":  "https://bazaar.abuse.ch/export/csv/recent/",
        "type": "hash", "severity": "CRITICAL",
        "tags": ["malware", "malwarebazaar"],
        "parse": "csv_col1", "skip_prefix": ["#", '"first_seen"'],
    },
    # ── Emerging Threats ──────────────────────────────────────────────────────
    {
        "name": "ET-Compromised",
        "url":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",  "severity": "HIGH",
        "tags": ["emerging-threats", "compromised"],
        "parse": "plain_ip", "skip_prefix": ["#"],
    },
    # ── Tor exit nodes ────────────────────────────────────────────────────────
    {
        "name": "TorExitNodes",
        "url":  "https://check.torproject.org/torbulkexitlist",
        "type": "ip",  "severity": "MEDIUM",
        "tags": ["tor", "anonymization"],
        "parse": "plain_ip", "skip_prefix": ["#", "ExitAddress"],
    },
    # ── Binary Defense ────────────────────────────────────────────────────────
    {
        "name": "BinaryDefense",
        "url":  "https://www.binarydefense.com/banlist.txt",
        "type": "ip",  "severity": "HIGH",
        "tags": ["binarydefense", "scanner", "brute-force"],
        "parse": "plain_ip", "skip_prefix": ["#"],
    },
    # ── Botvrij domains ───────────────────────────────────────────────────────
    {
        "name": "Botvrij-Domains",
        "url":  "https://www.botvrij.eu/data/ioclist.domain.raw",
        "type": "domain", "severity": "HIGH",
        "tags": ["botvrij", "malware"],
        "parse": "plain", "skip_prefix": ["#"],
    },
    # ── OpenPhish ─────────────────────────────────────────────────────────────
    {
        "name": "OpenPhish",
        "url":  "https://openphish.com/feed.txt",
        "type": "url",  "severity": "HIGH",
        "tags": ["phishing", "openphish"],
        "parse": "plain", "skip_prefix": ["#"],
    },
    # ── Malware Domain List ───────────────────────────────────────────────────
    {
        "name": "PhishTank-Domains",
        "url":  "https://data.phishtank.com/data/online-valid.csv",
        "type": "url",  "severity": "HIGH",
        "tags": ["phishing", "phishtank"],
        "parse": "csv_col2", "skip_prefix": ["phish_id", "#"],
    },
    # ── Extra free high-volume feeds ─────────────────────────────────────────
    {
        "name": "Blocklist-de-All",
        "url":  "https://lists.blocklist.de/lists/all.txt",
        "type": "ip", "severity": "MEDIUM",
        "tags": ["blocklist"], "ttl": 86400,
    },
    {
        "name": "IPsum-Level3",
        "url":  "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "type": "ip", "severity": "HIGH",
        "tags": ["ipsum","scanner"], "ttl": 86400,
    },
    {
        "name": "Emerging-Block-IPs",
        "url":  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "type": "ip", "severity": "HIGH",
        "tags": ["emerging-threats"], "ttl": 86400,
    },
    {
        "name": "Abuse-SSLBL",
        "url":  "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "type": "ip", "severity": "CRITICAL",
        "tags": ["sslbl","botnet"], "ttl": 86400,
    },
    {
        "name": "Greensnow",
        "url":  "https://blocklist.greensnow.co/greensnow.txt",
        "type": "ip", "severity": "MEDIUM",
        "tags": ["scanner","greensnow"], "ttl": 86400,
    },
    {
        "name": "CINS-Army",
        "url":  "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip", "severity": "HIGH",
        "tags": ["cins","scanner"], "ttl": 86400,
    },
    {
        "name": "CyberCure-IPs",
        "url":  "https://api.cybercure.ai/feed/get_ips?type=csv",
        "type": "ip", "severity": "HIGH",
        "tags": ["cybercure"], "ttl": 86400,
    },
]

# Cache file: stores last-download timestamps per feed name
FEED_CACHE_PATH = Path("data/feed_cache.json")


def _parse_feed_line(line: str, parse_hint: str) -> Optional[str]:
    """
    Extract a single IOC value from a raw line using the feed's parse hint.
    Returns None if the line doesn't yield a valid value.
    """
    line = line.strip().strip('"')
    if not line:
        return None
    if parse_hint == "plain":
        return line.split()[0] if line else None
    if parse_hint == "plain_ip":
        try:
            import ipaddress
            val = line.split()[0].split(":")[0]
            ipaddress.IPv4Address(val)
            return val
        except Exception:
            return None
    if parse_hint == "csv_first_col":
        parts = line.split(",")
        val = parts[0].strip().strip('"').split(":")[0]
        try:
            import ipaddress; ipaddress.IPv4Address(val); return val
        except Exception:
            return None
    if parse_hint == "csv_col1":
        parts = line.split(",")
        return parts[1].strip().strip('"') if len(parts) > 1 else None
    if parse_hint == "csv_col2":
        parts = line.split(",")
        return parts[2].strip().strip('"') if len(parts) > 2 else None
    if parse_hint == "csv_col2_strip_port":
        parts = line.split(",")
        if len(parts) < 3:
            return None
        val = parts[2].strip().strip('"').split(":")[0]
        try:
            import ipaddress; ipaddress.IPv4Address(val); return val
        except Exception:
            return None
    return line


class IOCManager:
    """Central IOC management interface used by the detection pipeline."""

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.store  = IOCStore()
        self.vt     = VirusTotalClient(cfg.get("virustotal_api_key"))
        self.loader = CustomIOCLoader()
        self._refresh_interval = cfg.get("refresh_interval_hours", 24) * 3600
        self._running          = False
        self._feed_thread: Optional[threading.Thread] = None
        self._feed_status: dict = {}        # name → {ok, added, ts, error}
        self._load_feed_cache()

        # Load any configured IOC files on startup
        for ioc_file in cfg.get("ioc_files", []):
            records = self.loader.load_file(ioc_file.get("path"), ioc_file.get("type", "ip"))
            for r in records:
                self.store.add(r)
        if cfg.get("ioc_files"):
            self.store.save()

        # Seed with known bad IPs so the system is useful immediately
        self._seed_demo_iocs()

        # Auto-download all feeds in background on startup
        if cfg.get("auto_download_feeds", True):
            self.start_feed_refresh(background=True)

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

    def _load_feed_cache(self) -> None:
        """Load per-feed last-download timestamps from disk."""
        try:
            if FEED_CACHE_PATH.exists():
                self._feed_status = json.loads(FEED_CACHE_PATH.read_text())
        except Exception:
            self._feed_status = {}

    def _save_feed_cache(self) -> None:
        FEED_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            FEED_CACHE_PATH.write_text(json.dumps(self._feed_status, indent=2))
        except Exception:
            pass

    # How long to wait after startup before the first feed download begins.
    # This gives the user time to start browsing without competing with a
    # burst of large HTTP downloads.
    _STARTUP_DELAY_SECONDS = 30

    # Pause between consecutive feed downloads to spread bandwidth usage
    # over time instead of hammering all 17 feeds back-to-back.
    _INTER_FEED_SLEEP_SECONDS = 2

    def start_feed_refresh(self, background: bool = True, force: bool = False) -> None:
        """
        Download all FEED_CATALOG feeds.
        background=True → runs in a daemon thread (non-blocking).
        force=True       → re-downloads even if last download was recent.

        FIX: when background=True (the normal startup path) a 30-second
        initial delay is applied before the first network request, and a
        2-second pause is inserted between each feed.  This prevents the
        17-feed burst from saturating the connection right at startup.
        """
        if self._feed_thread and self._feed_thread.is_alive():
            logger.info("Feed refresh already in progress — skipping")
            return
        if background:
            self._feed_thread = threading.Thread(
                target=self._download_all_feeds,
                kwargs={"force": force, "startup_delay": self._STARTUP_DELAY_SECONDS},
                daemon=True,
                name="ioc-feed-refresh",
            )
            self._feed_thread.start()
            logger.info(
                f"Feed refresh scheduled in background ({len(FEED_CATALOG)} feeds, "
                f"starts in {self._STARTUP_DELAY_SECONDS}s)"
            )
        else:
            self._download_all_feeds(force=force, startup_delay=0)

    def _download_all_feeds(self, force: bool = False, startup_delay: int = 0) -> dict:
        """Download every feed in FEED_CATALOG and ingest IOCs into the store.

        FIX: startup_delay — sleep this many seconds before the very first
        download so the user's internet is not impacted immediately on startup.
        Between each feed a short _INTER_FEED_SLEEP_SECONDS pause is inserted
        to spread bandwidth usage over time.
        """
        if startup_delay > 0:
            logger.info(f"Feed refresh: waiting {startup_delay}s before first download …")
            time.sleep(startup_delay)

        results = {}
        total_added = 0
        now = time.time()
        feeds_downloaded = 0  # count of feeds actually fetched this run

        for feed in FEED_CATALOG:
            name = feed["name"]
            # Skip if downloaded within the last 6 hours (unless force)
            last = self._feed_status.get(name, {}).get("ts", 0)
            if not force and (now - last) < 6 * 3600:
                logger.debug(f"Feed {name}: cached, skipping")
                results[name] = self._feed_status.get(name, {})
                continue

            # Pause between feeds to avoid a bandwidth burst (skip before the first one)
            if feeds_downloaded > 0:
                time.sleep(self._INTER_FEED_SLEEP_SECONDS)

            added = 0
            error = None
            try:
                req = urllib.request.Request(
                    feed["url"],
                    headers={"User-Agent": "CyberRemedy-SOC/2.0"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")

                skip = feed.get("skip_prefix", ["#"])
                parse_hint = feed.get("parse", "plain")
                ioc_type   = feed["type"]
                severity   = feed["severity"]
                tags       = feed.get("tags", [])
                cap        = feed.get("cap", 2000)  # max IOCs per feed

                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if any(line.startswith(p) for p in skip):
                        continue
                    val = _parse_feed_line(line, parse_hint)
                    if not val or len(val) < 3:
                        continue
                    self.store.add(IOCRecord(ioc_type, val, name, severity, tags))
                    added += 1
                    if added >= cap:
                        break

                logger.info(f"Feed {name}: +{added} IOCs")
                feeds_downloaded += 1

            except Exception as exc:
                error = str(exc)
                logger.warning(f"Feed {name} failed: {exc}")
                feeds_downloaded += 1  # still counts as attempted

            entry = {
                "ok":    error is None,
                "added": added,
                "ts":    now,
                "error": error,
            }
            self._feed_status[name] = entry
            results[name] = entry
            total_added += added

        if total_added > 0:
            self.store.save()
            logger.info(f"Feed refresh complete: +{total_added} IOCs, store total={self.store.total_count}")
        self._save_feed_cache()
        return results

    def feed_status(self) -> list:
        """Return per-feed download status for the dashboard."""
        out = []
        for feed in FEED_CATALOG:
            name = feed["name"]
            st   = self._feed_status.get(name, {})
            out.append({
                "name":     name,
                "type":     feed["type"],
                "ok":       st.get("ok"),
                "added":    st.get("added", 0),
                "ts":       st.get("ts"),
                "error":    st.get("error"),
                "tags":     feed.get("tags", []),
            })
        return out

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
        s = self.store.stats()
        s["feeds_total"]     = len(FEED_CATALOG)
        s["feeds_ok"]        = sum(1 for f in self._feed_status.values() if f.get("ok"))
        s["feeds_refreshing"] = bool(self._feed_thread and self._feed_thread.is_alive())
        return s

    def get_all(self, limit: int = 500) -> List[dict]:
        all_iocs = (
            list(self.store._ips.values()) +
            list(self.store._domains.values()) +
            list(self.store._hashes.values()) +
            list(self.store._urls.values())
        )
        return [r.to_dict() for r in sorted(all_iocs, key=lambda x: x.added_at, reverse=True)[:limit]]
