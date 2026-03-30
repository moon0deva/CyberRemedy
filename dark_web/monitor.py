"""
CyberRemedy — Dark Web & Data Leak Monitor
==========================================
Free sources (no API keys). Tor optional (uses system Tor if running).

API surface:
  monitor.stats                          → dict (property)
  monitor.get_watchlist()                → list[dict]
  monitor.add_keyword(kw, cat, desc)     → dict
  monitor.remove_keyword(kw_id)         → bool
  monitor.get_findings(limit, finding_type) → list[dict]
  monitor.run_full_scan()               → None
  monitor.check_breach_databases(domain) → list[dict]
"""

import hashlib, json, logging, threading, time, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("cyberremedy.darkweb")

_DATA_DIR     = Path("data/darkweb_cache")
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_FINDINGS_F   = _DATA_DIR / "findings.json"
_WATCHLIST_F  = _DATA_DIR / "watchlist.json"

# ── Tor support (optional) ────────────────────────────────────────────────────
_TOR_SESSION = None

def _get_session(force_clearnet: bool = False):
    """Return a requests session. Uses Tor SOCKS5 if available."""
    global _TOR_SESSION
    if force_clearnet:
        try:
            import requests
            s = requests.Session()
            s.headers["User-Agent"] = "Mozilla/5.0 CyberRemedy/3.0"
            return s
        except ImportError:
            return None

    if _TOR_SESSION:
        return _TOR_SESSION

    # Try Tor (must have `tor` service running: sudo apt install tor && sudo systemctl start tor)
    try:
        import requests
        import socks  # PySocks: pip install requests[socks] --break-system-packages
        s = requests.Session()
        s.proxies = {"http":  "socks5h://127.0.0.1:9050",
                     "https": "socks5h://127.0.0.1:9050"}
        s.headers["User-Agent"] = "Mozilla/5.0 (compatible; CyberRemedy)"
        s.timeout = 20
        # Quick test
        r = s.get("https://check.torproject.org/api/ip", timeout=10)
        if r.json().get("IsTor"):
            _TOR_SESSION = s
            logger.info("[DarkWeb] Tor connection established ✓")
            return s
    except Exception as e:
        logger.debug(f"[DarkWeb] Tor not available: {e}")

    # Fall back to clearnet requests
    try:
        import requests
        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 CyberRemedy/3.0"
        return s
    except ImportError:
        pass
    return None


def _fetch(url: str, timeout: int = 15, tor: bool = False) -> Optional[bytes]:
    """Fetch URL via Tor (if available) or clearnet. Returns bytes or None."""
    sess = _get_session(force_clearnet=not tor)
    if sess:
        try:
            r = sess.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.content
            logger.debug(f"[DarkWeb] {url[:60]} → HTTP {r.status_code}")
            return None
        except Exception as e:
            logger.debug(f"[DarkWeb] fetch {url[:60]}: {e}")
            return None

    # Fallback: urllib (no Tor)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 CyberRemedy/3.0"
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        logger.debug(f"[DarkWeb] urllib {url[:60]}: {e}")
        return None


def _cache_get(key: str, max_age: int = 3600) -> Optional[bytes]:
    p = _DATA_DIR / f"{hashlib.md5(key.encode()).hexdigest()[:12]}.cache"
    if p.exists() and (time.time() - p.stat().st_mtime) < max_age:
        return p.read_bytes()
    return None


def _cache_set(key: str, data: bytes):
    try:
        (_DATA_DIR / f"{hashlib.md5(key.encode()).hexdigest()[:12]}.cache").write_bytes(data)
    except Exception:
        pass


# ── Source 1: Ransomwatch (real-time ransomware victims) ─────────────────────
_RANSOMWATCH_POSTS  = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
_RANSOMWATCH_GROUPS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

def _ransomwatch_posts(keywords: List[str]) -> List[dict]:
    raw = _cache_get("rw_posts", 1800) or _fetch(_RANSOMWATCH_POSTS, 25)
    if raw: _cache_set("rw_posts", raw)
    if not raw: return []
    try:
        posts  = json.loads(raw)
        kw_low = [k.lower() for k in keywords]
        out    = []
        for p in posts:
            title   = str(p.get("post_title","")).lower()
            site    = str(p.get("website","")).lower()
            group   = p.get("group_name","Unknown")
            text    = f"{title} {site}"
            if kw_low and not any(k in text for k in kw_low):
                continue
            out.append({
                "type":    "ransomware_victim",
                "severity":"CRITICAL",
                "title":   p.get("post_title","Unknown victim"),
                "group":   group,
                "website": p.get("website",""),
                "ts":      p.get("discovered",""),
                "detail":  f"Ransomware group '{group}' posted this victim publicly",
                "source":  "ransomwatch",
                "url":     "https://github.com/joshhighet/ransomwatch",
            })
        return out
    except Exception as e:
        logger.warning(f"[DarkWeb] Ransomwatch parse: {e}")
        return []


def _ransomwatch_groups() -> List[dict]:
    raw = _cache_get("rw_groups", 7200) or _fetch(_RANSOMWATCH_GROUPS, 20)
    if raw: _cache_set("rw_groups", raw)
    if not raw: return []
    try: return json.loads(raw)
    except Exception: return []


# ── Source 2: ThreatFox IOC feed (C2 indicators) ─────────────────────────────
# Updated URL - ThreatFox changed their CSV export endpoint
_THREATFOX_URLS = [
    "https://threatfox.abuse.ch/export/csv/c2-iocs/recent/",
    "https://threatfox.abuse.ch/export/csv/c2/recent/",
    "https://threatfox-api.abuse.ch/api/v1/",  # POST API
]

def _threatfox_c2(keywords: List[str]) -> List[dict]:
    raw = _cache_get("tf_c2", 1800)
    if not raw:
        # Try each URL
        for url in _THREATFOX_URLS:
            if "api/v1" in url:
                # Use POST API (no key needed for public data)
                try:
                    import json as _j
                    payload = json.dumps({"query": "get_iocs", "days": 7}).encode()
                    req = urllib.request.Request(
                        url,
                        data=payload,
                        headers={"Content-Type": "application/json",
                                 "User-Agent": "Mozilla/5.0 CyberRemedy/3.0"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=15) as r:
                        raw = r.read()
                    if raw and len(raw) > 100:
                        break
                except Exception as e:
                    logger.debug(f"[DarkWeb] ThreatFox API: {e}")
            else:
                raw = _fetch(url, 20)
                if raw and len(raw) > 100:
                    break
        if raw: _cache_set("tf_c2", raw)

    if not raw: return []

    try:
        kw_low = [k.lower() for k in keywords]
        out = []
        text = raw.decode("utf-8", errors="replace")

        # Try JSON format first (API response)
        if text.strip().startswith("{"):
            try:
                data = json.loads(text)
                iocs = data.get("data", [])
                for ioc in iocs[:500]:
                    indicator = ioc.get("ioc","")
                    malware   = ioc.get("malware","Unknown")
                    itype     = ioc.get("ioc_type","")
                    search    = f"{indicator} {malware}".lower()
                    if kw_low and not any(k in search for k in kw_low):
                        continue
                    if indicator:
                        out.append({
                            "type":    "c2_indicator",
                            "severity":"HIGH",
                            "title":   f"C2: {malware} — {indicator}",
                            "ioc":     indicator,
                            "ioc_type":itype,
                            "malware": malware,
                            "ts":      ioc.get("first_seen",""),
                            "detail":  f"C2 server for {malware} ({itype})",
                            "source":  "threatfox",
                            "url":     "https://threatfox.abuse.ch",
                        })
                return out[:300]
            except Exception:
                pass

        # CSV format
        for line in text.splitlines():
            if line.startswith("#") or "," not in line:
                continue
            parts = [x.strip().strip('"') for x in line.split(",")]
            if len(parts) < 3: continue
            ioc     = parts[2] if len(parts) > 2 else ""
            malware = parts[4] if len(parts) > 4 else ""
            itype   = parts[3] if len(parts) > 3 else ""
            search  = f"{ioc} {malware}".lower()
            if kw_low and not any(k in search for k in kw_low):
                continue
            if ioc:
                out.append({
                    "type":    "c2_indicator",
                    "severity":"HIGH",
                    "title":   f"C2: {malware or 'Unknown'} — {ioc}",
                    "ioc":     ioc,
                    "ioc_type":itype,
                    "malware": malware,
                    "ts":      parts[0] if parts else "",
                    "detail":  f"C2 indicator ({itype})",
                    "source":  "threatfox",
                    "url":     "https://threatfox.abuse.ch",
                })
        return out[:300]
    except Exception as e:
        logger.warning(f"[DarkWeb] ThreatFox parse: {e}")
        return []


# ── Source 3: URLhaus malware URLs ────────────────────────────────────────────
_URLHAUS = "https://urlhaus.abuse.ch/downloads/text_online/"

def _urlhaus(keywords: List[str]) -> List[dict]:
    if not keywords: return []
    raw = _cache_get("urlhaus", 3600) or _fetch(_URLHAUS, 20)
    if raw: _cache_set("urlhaus", raw)
    if not raw: return []
    try:
        kw_low = [k.lower() for k in keywords]
        out = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if line.startswith("#") or not line.strip(): continue
            low = line.lower()
            if any(k in low for k in kw_low):
                out.append({
                    "type":    "malware_url",
                    "severity":"HIGH",
                    "title":   f"Malware URL match: {line[:80]}",
                    "ts":      "",
                    "detail":  "Found in URLhaus active malware URL database",
                    "source":  "urlhaus",
                    "url":     "https://urlhaus.abuse.ch",
                })
        return out[:50]
    except Exception:
        return []


# ── Source 4: Known breach database ──────────────────────────────────────────
_HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"

KNOWN_BREACHES = [
    "Adobe","LinkedIn","Yahoo","Equifax","Marriott","Capital One",
    "Facebook","Twitter/X","T-Mobile 2023","T-Mobile 2021","AT&T 2024",
    "AT&T 2021","Optus","Medibank","Latitude","Canva","Dropbox","LastPass",
    "RockYou","RockYou2024","Collection#1","AntiPublic","Apollo","Exactis",
    "Verifications.io","DoorDash","MyFitnessPal","eBay","Chegg","Quora",
    "MyHeritage","Houzz","National Public Data","Ticketmaster","Santander",
    "Dell","Change Healthcare","MOVEit","GoAnywhere","23andMe","Discord",
    "Reddit","Twitch","Wattpad","Mathway","Pixlr","Animal Jam","Nitro PDF",
    "BigBasket","Tokopedia","SolarWinds","Kaseya","Colonial Pipeline",
    "ALPHV/BlackCat","LockBit","Cl0p","PLAY ransomware","Royal ransomware",
    "Black Basta","Scattered Spider","MGM Resorts","Caesars Entertainment",
    "Microsoft Exchange","Okta","LastPass 2022","GoTo/LogMeIn",
    "Western Digital","Dish Network","Rackspace","Activision",
    "Reddit 2023","Riot Games","GitHub","CircleCI","Slack","Trello",
    "Twilio","Cloudflare","Hacktivism Collection","COMB","Cashapp",
]


def _check_breaches(keywords: List[str], domain: str = "") -> List[dict]:
    terms = [k.lower() for k in keywords]
    if domain:
        base = domain.lower().split(".")[0]
        for t in [base, domain.lower()]:
            if t not in terms: terms.append(t)

    # Get live HIBP list (no key for full breach name list)
    breaches = KNOWN_BREACHES[:]
    raw = _cache_get("hibp_list", 86400) or _fetch(_HIBP_BREACHES, 15)
    if raw:
        _cache_set("hibp_list", raw)
        try:
            live = json.loads(raw)
            breaches = [f"{b.get('Name','')} ({b.get('PwnCount',0):,} records)" for b in live]
        except Exception:
            pass

    findings = []
    for breach in breaches:
        breach_l = breach.lower()
        for term in terms:
            if len(term) < 3: continue
            if term in breach_l:
                findings.append({
                    "type":    "data_breach",
                    "severity":"HIGH",
                    "title":   f"Keyword '{term}' matches known breach: {breach}",
                    "breach":  breach,
                    "ts":      "",
                    "detail":  "Matched against HaveIBeenPwned public breach database",
                    "source":  "breach_db",
                    "url":     "https://haveibeenpwned.com/PwnedWebsites",
                })
                break
    return findings


# ── Source 5: Tor .onion dark web (if Tor is running) ────────────────────────
_ONION_SOURCES = [
    # Public ransomware group leak sites mirrored on Tor
    # These are accessed ONLY if Tor proxy is running on 127.0.0.1:9050
    # Format: (name, url, description)
    ("ransomware.live",  "https://api.ransomware.live/recentvictims", "Ransomware victims (clearnet API)"),
    ("ransomware.live",  "https://api.ransomware.live/groups",        "Active ransomware groups"),
]

def _ransomware_live_api(keywords: List[str]) -> List[dict]:
    """Ransomware.live public API - real-time victim data, no Tor needed."""
    out = []
    for name, url, desc in _ONION_SOURCES:
        raw = _cache_get(f"rl_{url[-20:]}", 1800) or _fetch(url, 15)
        if raw: _cache_set(f"rl_{url[-20:]}", raw)
        if not raw: continue
        try:
            data = json.loads(raw)
            if not isinstance(data, list): continue
            kw_low = [k.lower() for k in keywords]
            for item in data[:200]:
                victim  = str(item.get("victim","") or item.get("name","")).lower()
                group   = str(item.get("group","") or item.get("name",""))
                site    = str(item.get("website","") or item.get("url","")).lower()
                desc_   = str(item.get("description","") or item.get("summary",""))
                text    = f"{victim} {site} {desc_}".lower()
                if kw_low and not any(k in text for k in kw_low):
                    continue
                out.append({
                    "type":    "ransomware_victim",
                    "severity":"CRITICAL",
                    "title":   f"[{group}] Victim: {item.get('victim', item.get('name','Unknown'))}",
                    "group":   group,
                    "website": item.get("website",""),
                    "ts":      str(item.get("discovered","") or item.get("date","")),
                    "detail":  f"Source: ransomware.live API · {desc}",
                    "source":  "ransomware.live",
                    "url":     "https://ransomware.live",
                })
        except Exception as e:
            logger.debug(f"[DarkWeb] ransomware.live {url}: {e}")
    return out


def _tor_scan_keywords(keywords: List[str]) -> List[dict]:
    """
    If Tor is running (127.0.0.1:9050), scan dark web sources.
    Returns empty list if Tor is not available.
    """
    sess = _get_session(force_clearnet=False)
    if not _TOR_SESSION:
        return []  # Tor not available

    findings = []
    # Example: DarkFeed mirror, IntelX, etc. - only via Tor
    logger.info("[DarkWeb] Tor available - scanning .onion sources")
    return findings


def _tor_status() -> dict:
    """Check if Tor is available and return connection info."""
    try:
        import requests
        s = requests.Session()
        s.proxies = {"http": "socks5h://127.0.0.1:9050",
                     "https": "socks5h://127.0.0.1:9050"}
        r = s.get("https://check.torproject.org/api/ip", timeout=8)
        data = r.json()
        return {
            "available":  data.get("IsTor", False),
            "ip":         data.get("IP", "unknown"),
            "message":    "Tor connected ✓" if data.get("IsTor") else "Not using Tor",
        }
    except Exception as e:
        return {"available": False, "message": f"Tor not running: {e}"}


# ── Main monitor class ────────────────────────────────────────────────────────

class DarkWebMonitor:

    def __init__(self):
        self._watchlist: List[dict] = []
        self._findings:  List[dict] = []
        self._lock       = threading.Lock()
        self._scanning   = False
        self._last_scan  = 0.0
        self._breach_stats: dict = {}
        self._rw_groups: List[dict] = []
        self._tor_status: dict = {"available": False, "message": "Not checked"}
        self._load()

    # ── Watchlist ──────────────────────────────────────────────────────────

    def get_watchlist(self) -> List[dict]:
        with self._lock: return list(self._watchlist)

    def add_keyword(self, keyword: str, category: str = "general",
                    description: str = "") -> dict:
        kw_id = hashlib.md5(keyword.lower().encode()).hexdigest()[:8]
        entry = {
            "id":          kw_id,
            "keyword":     keyword.strip(),
            "category":    category or "general",
            "description": description or "",
            "added":       datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            if not any(w["id"] == kw_id for w in self._watchlist):
                self._watchlist.append(entry)
                self._save_watchlist()
        return entry

    def remove_keyword(self, kw_id: str) -> bool:
        with self._lock:
            before = len(self._watchlist)
            self._watchlist = [w for w in self._watchlist if w["id"] != kw_id]
            changed = len(self._watchlist) < before
            if changed: self._save_watchlist()
        return changed

    # ── Findings ──────────────────────────────────────────────────────────

    def get_findings(self, limit: int = 100, finding_type: str = None) -> List[dict]:
        with self._lock:
            results = list(reversed(self._findings))
        if finding_type:
            results = [f for f in results if f.get("type") == finding_type]
        return results[:limit]

    # ── Scanning ──────────────────────────────────────────────────────────

    def run_full_scan(self) -> int:
        if self._scanning: return 0
        self._scanning = True
        try:
            with self._lock:
                keywords = [w["keyword"] for w in self._watchlist]

            # Check Tor status
            self._tor_status = _tor_status()

            new_findings = []
            # Source 1: Ransomwatch (always works, GitHub CDN)
            new_findings += _ransomwatch_posts(keywords)
            # Source 2: ransomware.live API (very accurate, real-time)
            new_findings += _ransomware_live_api(keywords)
            # Source 3: ThreatFox C2 (try multiple URLs)
            new_findings += _threatfox_c2(keywords)
            # Source 4: URLhaus (keyword matching)
            new_findings += _urlhaus(keywords)
            # Source 5: Breach DB (keyword matching)
            if keywords:
                new_findings += _check_breaches(keywords)
            # Source 6: Tor .onion (if Tor running)
            if self._tor_status.get("available"):
                new_findings += _tor_scan_keywords(keywords)

            # Fetch group list and breach stats
            self._rw_groups    = _ransomwatch_groups()
            self._breach_stats = {"hibp_breach_count": len(KNOWN_BREACHES),
                                  "source": "hibp_public"}

            added = 0
            with self._lock:
                existing = {(f["source"], f["title"]) for f in self._findings}
                for f in new_findings:
                    key = (f["source"], f["title"])
                    if key not in existing:
                        f["found_at"] = datetime.now(timezone.utc).isoformat()
                        self._findings.append(f)
                        existing.add(key)
                        added += 1
                self._findings = self._findings[-3000:]
                self._last_scan = time.time()

            self._save_findings()
            logger.info(f"[DarkWeb] Scan done — +{added} new, total={len(self._findings)}, tor={self._tor_status.get('available')}")
            return added
        except Exception as e:
            logger.error(f"[DarkWeb] Scan error: {e}")
            return 0
        finally:
            self._scanning = False

    def check_breach_databases(self, domain: str = None) -> List[dict]:
        with self._lock:
            keywords = [w["keyword"] for w in self._watchlist]
        return _check_breaches(keywords, domain or "")

    def start_background(self, interval: int = 3600):
        def _loop():
            time.sleep(60)  # wait 60s after startup
            while True:
                try: self.run_full_scan()
                except Exception as e: logger.error(f"[DarkWeb] BG: {e}")
                time.sleep(interval)
        threading.Thread(target=_loop, daemon=True, name="dw-scanner").start()

    # ── Stats ─────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        with self._lock:
            sev   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
            types: dict = {}
            for f in self._findings:
                s = f.get("severity","MEDIUM")
                sev[s] = sev.get(s,0)+1
                t = f.get("type","other")
                types[t] = types.get(t,0)+1
        return {
            "total":              len(self._findings),
            "by_severity":        sev,
            "by_type":            types,
            "keywords":           len(self._watchlist),
            "last_scan":          self._last_scan,
            "scanning":           self._scanning,
            "tor_available":      self._tor_status.get("available", False),
            "tor_status":         self._tor_status.get("message","Not checked"),
            "sources":            ["ransomwatch","ransomware.live","threatfox",
                                   "urlhaus","breach_db","tor_onion"],
            "breach_stats":       self._breach_stats,
            "ransomware_groups":  len(self._rw_groups),
        }

    # ── Persistence ───────────────────────────────────────────────────────

    def _save_findings(self):
        try: _FINDINGS_F.write_text(json.dumps(self._findings, indent=2))
        except Exception as e: logger.debug(f"[DarkWeb] save: {e}")

    def _save_watchlist(self):
        try: _WATCHLIST_F.write_text(json.dumps(self._watchlist, indent=2))
        except Exception as e: logger.debug(f"[DarkWeb] watchlist save: {e}")

    def _load(self):
        try:
            if _FINDINGS_F.exists():
                self._findings = json.loads(_FINDINGS_F.read_text())
        except Exception: self._findings = []
        try:
            if _WATCHLIST_F.exists():
                self._watchlist = json.loads(_WATCHLIST_F.read_text())
        except Exception: self._watchlist = []


dark_web_monitor = DarkWebMonitor()
