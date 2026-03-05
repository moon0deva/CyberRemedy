"""AID-ARS v4.0 — GeoIP. No API keys. Uses offline CSV (downloaded on startup) + ip-api.com fallback."""
import json, logging as _logging, threading, ipaddress, bisect
from pathlib import Path
from typing import Optional

logger = _logging.getLogger("aidars.geoip")

_PRIV = [ipaddress.IPv4Network(n) for n in
         ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","0.0.0.0/8"]]

def _is_private(ip):
    try: return any(ipaddress.IPv4Address(ip) in n for n in _PRIV)
    except Exception: return False

def _flag(code):
    if not code or len(code)!=2: return "🌐"
    return chr(0x1F1E6+ord(code[0])-65)+chr(0x1F1E6+ord(code[1])-65)

_COUNTRY_NAMES = {
    "US":"United States","CN":"China","RU":"Russia","DE":"Germany","GB":"United Kingdom",
    "FR":"France","IN":"India","BR":"Brazil","CA":"Canada","AU":"Australia","JP":"Japan",
    "KR":"South Korea","NL":"Netherlands","SG":"Singapore","IT":"Italy","ES":"Spain",
    "SE":"Sweden","NO":"Norway","FI":"Finland","PL":"Poland","UA":"Ukraine","IR":"Iran",
    "KP":"North Korea","BY":"Belarus","CU":"Cuba","SY":"Syria","TR":"Turkey",
    "SA":"Saudi Arabia","IL":"Israel","ZA":"South Africa","MX":"Mexico","AR":"Argentina",
    "RO":"Romania","HU":"Hungary","CZ":"Czechia","AT":"Austria","CH":"Switzerland",
    "BE":"Belgium","PT":"Portugal","GR":"Greece","DK":"Denmark","NZ":"New Zealand",
}


# Country centroids (lat, lon) for offline GeoIP fallback
_COUNTRY_CENTROIDS = {
    "US":(37.09,-95.71),"GB":(55.37,-3.43),"DE":(51.16,10.45),"FR":(46.22,2.21),
    "CN":(35.86,104.19),"RU":(61.52,105.31),"JP":(36.20,138.25),"KR":(35.90,127.76),
    "IN":(20.59,78.96),"BR":(14.23,-51.92),"AU":(-25.27,133.77),"CA":(56.13,-106.34),
    "NL":(52.13,5.29),"SE":(60.12,18.64),"NO":(60.47,8.46),"FI":(61.92,25.74),
    "PL":(51.91,19.14),"UA":(48.37,31.16),"IT":(41.87,12.56),"ES":(40.46,-3.74),
    "TR":(38.96,35.24),"IR":(32.42,53.68),"KP":(40.33,127.51),"SY":(34.80,38.99),
    "BY":(53.70,27.95),"CU":(21.52,-77.78),"NG":(9.08,8.67),"ZA":(-28.03,23.00),
    "MX":(23.63,-102.55),"AR":(-38.41,-63.61),"SG":(1.35,103.81),"HK":(22.39,114.10),
    "TW":(23.69,120.96),"VN":(14.05,108.27),"TH":(15.87,100.99),"ID":(-0.78,113.92),
    "PK":(30.37,69.34),"BD":(23.68,90.35),"EG":(26.82,30.80),"SA":(23.88,45.07),
    "IL":(31.04,34.85),"CH":(46.81,8.22),"AT":(47.51,14.55),"BE":(50.50,4.47),
    "PT":(39.39,-8.22),"RO":(45.94,24.96),"CZ":(49.81,15.47),"HU":(47.16,19.50),
    "GR":(39.07,21.82),"BG":(42.73,25.48),"SK":(48.66,19.69),"HR":(45.10,15.20),
    "DK":(56.26,9.50),"IE":(53.41,-8.24),"NZ":(-40.90,174.88),"MY":(4.21,101.97),
    "PH":(12.87,121.77),"CL":(-35.67,-71.54),"CO":(4.57,-74.29),"PE":(-9.18,-75.01),
    "VE":(6.42,-66.58),"RS":(44.01,21.00),"BA":(44.16,17.67),"LT":(55.16,23.88),
    "LV":(56.87,24.60),"EE":(58.59,25.01),"MK":(41.60,21.74),"MD":(47.41,28.36),
}

def _country_latlon(cc):
    """Return (lat, lon) for a country code, or (0,0) if unknown."""
    return _COUNTRY_CENTROIDS.get(cc, (0.0, 0.0))

class GeoIPLookup:
    def __init__(self, config: dict):
        cfg = config.get("geoip",{})
        self.enabled    = cfg.get("enabled",True)
        self.high_risk  = set(cfg.get("high_risk_countries",["CN","RU","KP","IR","BY","CU","SY"]))
        self._cache: dict = {}
        self._ranges     = None   # lazy-loaded CSV ranges
        self._lock       = threading.Lock()
        self._cache_path = Path("data/geoip/cache.json")
        self._csv_path   = Path("data/geoip/ip_country.json")
        self._load_cache()
        # Load CSV ranges in background so startup isn't delayed
        threading.Thread(target=self._load_ranges, daemon=True, name="geoip-init").start()
        logger.info("GeoIP ready (no API key required)")

    def _load_cache(self):
        self._cache_path.parent.mkdir(parents=True,exist_ok=True)
        if self._cache_path.exists():
            try:
                with open(self._cache_path) as f: self._cache = json.load(f)
            except Exception: pass

    def _load_ranges(self):
        if not self._csv_path.exists(): return
        try:
            with open(self._csv_path) as f: raw = json.load(f)
            ranges = []
            for row in raw:
                if len(row)<3: continue
                try:
                    s = int(ipaddress.IPv4Address(row[0]))
                    e = int(ipaddress.IPv4Address(row[1]))
                    ranges.append((s, e, row[2]))
                except Exception: continue
            ranges.sort(key=lambda x: x[0])
            with self._lock: self._ranges = ranges
            logger.info(f"GeoIP CSV: {len(ranges):,} IP ranges loaded")
        except Exception as e:
            logger.debug(f"GeoIP CSV load: {e}")

    def _lookup_csv(self, ip):
        with self._lock: ranges = self._ranges
        if not ranges: return None
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
            idx = bisect.bisect_right(ranges,(ip_int,float("inf"),""))-1
            if idx>=0:
                s,e,cc = ranges[idx]
                if s<=ip_int<=e:
                    return {"ip":ip,"country":_COUNTRY_NAMES.get(cc,cc),"country_code":cc,
                            "city":"","region":"","lat":_country_latlon(cc)[0],"lon":_country_latlon(cc)[1],"org":"","isp":"","is_private":False}
        except Exception: pass
        return None

    def _lookup_online(self, ip):
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,org,isp"
            with urllib.request.urlopen(url, timeout=4) as r:
                d = json.loads(r.read().decode())
            if d.get("status")=="success":
                return {"ip":ip,"country":d.get("country","Unknown"),"country_code":d.get("countryCode","??"),
                        "city":d.get("city",""),"region":d.get("regionName",""),
                        "lat":d.get("lat",0.0),"lon":d.get("lon",0.0),
                        "org":d.get("org",""),"isp":d.get("isp",""),"is_private":False}
        except Exception as e: logger.debug(f"ip-api.com {ip}: {e}")
        return None

    def lookup(self, ip: str) -> dict:
        if not self.enabled:
            return {"ip":ip,"country":"Unknown","country_code":"??","is_private":False,"flag":"🌐","high_risk":False}
        if _is_private(ip):
            return {"ip":ip,"country":"Private Network","country_code":"LAN","city":"Local",
                    "region":"","lat":0.0,"lon":0.0,"org":"Private","isp":"Local",
                    "is_private":True,"flag":"🏠","high_risk":False}
        with self._lock:
            if ip in self._cache: return self._cache[ip]
        result = self._lookup_csv(ip) or self._lookup_online(ip)
        if result is None:
            result = {"ip":ip,"country":"Unknown","country_code":"??","city":"","region":"",
                      "lat":0.0,"lon":0.0,"org":"","isp":"","is_private":False}
        result["flag"]      = _flag(result.get("country_code",""))
        result["high_risk"] = result.get("country_code","") in self.high_risk
        with self._lock:
            self._cache[ip] = result
            if len(self._cache)%50==0:
                try:
                    with open(self._cache_path,"w") as f: json.dump(self._cache,f)
                except Exception: pass
        return result

    def get_map_data(self, alerts, limit=200):
        seen = {}
        for a in alerts:
            ip = a.get("src_ip","")
            if not ip or _is_private(ip): continue
            if ip not in seen:
                g = self.lookup(ip)
                if g.get("lat") or g.get("lon"):
                    seen[ip] = {"ip":ip,"lat":g["lat"],"lon":g["lon"],
                                "country":g.get("country","?"),"country_code":g.get("country_code","??"),
                                "flag":g.get("flag","🌐"),"city":g.get("city",""),
                                "org":g.get("org",""),"high_risk":g.get("high_risk",False),
                                "alert_count":1,"severity":a.get("severity","LOW")}
            else:
                seen[ip]["alert_count"]+=1
                rank={"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0}
                if rank.get(a.get("severity","LOW"),0)>rank.get(seen[ip]["severity"],0):
                    seen[ip]["severity"]=a.get("severity")
        return list(seen.values())[:limit]

    def country_stats(self, alerts):
        counts={}
        for a in alerts:
            ip=a.get("src_ip","")
            if not ip or _is_private(ip): continue
            g=self.lookup(ip); cc=g.get("country_code","??")
            if cc not in counts:
                counts[cc]={"country_code":cc,"country":g.get("country","?"),
                            "flag":g.get("flag","🌐"),"count":0,"high_risk":g.get("high_risk",False)}
            counts[cc]["count"]+=1
        return sorted(counts.values(),key=lambda x:x["count"],reverse=True)[:20]
