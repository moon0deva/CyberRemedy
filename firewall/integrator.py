"""CyberRemedy v1.0 — Firewall Integrator. Auto-detects iptables/ufw/nftables/windows."""
import os, json, platform, subprocess, threading, logging as _logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = _logging.getLogger("cyberremedy.firewall")

def _run(cmd, dry=False):
    if dry:
        logger.info(f"[DRY] {' '.join(cmd)}"); return True,"dry-run"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode==0, (r.stdout or r.stderr).strip()
    except FileNotFoundError: return False, f"not found: {cmd[0]}"
    except Exception as e: return False, str(e)

def _which(c):
    import shutil; return shutil.which(c) is not None

def detect_backend():
    if platform.system()=="Windows": return "windows"
    if _which("ufw"):
        ok,out = _run(["ufw","status"])
        if ok and "inactive" not in out.lower(): return "ufw"
    if _which("iptables"): return "iptables"
    if _which("nft"): return "nftables"
    return "simulation"

class _IPT:
    def __init__(self, chain, dry):
        self.chain=chain; self.dry=dry
        _run(["iptables","-N",self.chain],dry)
        ok,_=_run(["iptables","-C","INPUT","-j",self.chain],False)
        if not ok: _run(["iptables","-I","INPUT","-j",self.chain],dry)
    def block(self,ip):   return _run(["iptables","-I",self.chain,"-s",ip,"-j","DROP"],self.dry)
    def unblock(self,ip): return _run(["iptables","-D",self.chain,"-s",ip,"-j","DROP"],self.dry)
    def rules(self):
        ok,out=_run(["iptables","-L",self.chain,"-n","--line-numbers"],False)
        if not ok: return []
        return [{"num":p[0],"target":p[1],"source":p[3]} for ln in out.split("\n")[2:] if len(p:=ln.split())>=4]
    def flush(self): return _run(["iptables","-F",self.chain],self.dry)

class _UFW:
    def __init__(self, dry): self.dry=dry
    def block(self,ip):   return _run(["ufw","deny","from",ip,"to","any"],self.dry)
    def unblock(self,ip): return _run(["ufw","delete","deny","from",ip,"to","any"],self.dry)
    def rules(self):
        ok,out=_run(["ufw","status","numbered"],False)
        return [{"raw":l.strip()} for l in (out.split("\n") if ok else []) if "DENY" in l]
    def flush(self): return True,"not supported — delete rules individually"

class _NFT:
    def __init__(self, dry):
        self.dry=dry
        for c in [["nft","add","table","inet","cyberremedy"],
                  ["nft","add","set","inet","cyberremedy","blocklist","{","type","ipv4_addr",";","}"],
                  ["nft","add","chain","inet","cyberremedy","input","{","type","filter","hook","input","priority","0",";","}"],
                  ["nft","add","rule","inet","cyberremedy","input","ip","saddr","@blocklist","drop"]]:
            _run(c, dry)
    def block(self,ip):   return _run(["nft","add","element","inet","cyberremedy","blocklist","{",ip,"}"],self.dry)
    def unblock(self,ip): return _run(["nft","delete","element","inet","cyberremedy","blocklist","{",ip,"}"],self.dry)
    def rules(self):
        ok,out=_run(["nft","list","set","inet","cyberremedy","blocklist"],False)
        return [{"source":l.strip().rstrip(",")} for l in (out.split("\n") if ok else []) if "." in l]
    def flush(self): return _run(["nft","flush","set","inet","cyberremedy","blocklist"],self.dry)

class _WIN:
    def __init__(self, prefix, dry): self.pfx=prefix; self.dry=dry
    def _n(self,ip): return f"{self.pfx}{ip.replace('.','_')}"
    def block(self,ip):
        return _run(["netsh","advfirewall","firewall","add","rule",f"name={self._n(ip)}",
                     "protocol=any","dir=in",f"remoteip={ip}","action=block"],self.dry)
    def unblock(self,ip):
        return _run(["netsh","advfirewall","firewall","delete","rule",f"name={self._n(ip)}"],self.dry)
    def rules(self): return []
    def flush(self):
        return _run(["netsh","advfirewall","firewall","delete","rule",f"name={self.pfx}*"],self.dry)

class _SIM:
    def __init__(self): self._b=set()
    def block(self,ip):   self._b.add(ip);   logger.info(f"[SIM] BLOCK {ip}");   return True,"sim"
    def unblock(self,ip): self._b.discard(ip);logger.info(f"[SIM] UNBLOCK {ip}");return True,"sim"
    def rules(self): return [{"source":ip,"target":"DROP"} for ip in self._b]
    def flush(self): self._b.clear(); return True,"sim"


class FirewallIntegrator:
    def __init__(self, config: dict):
        fw  = config.get("firewall", {})
        rsp = config.get("response", {})
        self.enabled      = fw.get("enabled", True)
        self.dry_run      = fw.get("dry_run", False)
        self.ttl          = rsp.get("blocked_ip_ttl_seconds", 3600)
        self._lock        = threading.Lock()
        self._blocked: dict = {}
        self._db          = Path("data/blocks_active.json")
        req = fw.get("backend","auto")
        self.backend_name = detect_backend() if req=="auto" else req
        self._be = self._mk(fw, self.backend_name)
        logger.info(f"Firewall: backend={self.backend_name} dry={self.dry_run}")
        self._load()
        threading.Thread(target=self._ttl_loop, daemon=True, name="fw-ttl").start()

    def _mk(self, cfg, name):
        if name=="iptables": return _IPT(cfg.get("chain_name","CYBERREMEDY"), self.dry_run)
        if name=="ufw":      return _UFW(self.dry_run)
        if name=="nftables": return _NFT(self.dry_run)
        if name=="windows":  return _WIN(cfg.get("windows_rule_prefix","CYBERREMEDY-Block-"), self.dry_run)
        return _SIM()

    def block_ip(self, ip, reason="alert", ttl: Optional[int]=None, alert_id=None):
        if not self.enabled: return {"success":False,"reason":"disabled"}
        with self._lock:
            if ip in self._blocked: return {"success":True,"already_blocked":True,"ip":ip}
            ttl_v = ttl if ttl is not None else self.ttl
            ok, msg = self._be.block(ip)
            now = datetime.now()
            exp = datetime.fromtimestamp(now.timestamp()+ttl_v).isoformat() if ttl_v>0 else None
            entry = {"ip":ip,"reason":reason,"blocked_at":now.isoformat(),
                     "ttl_seconds":ttl_v,"alert_id":alert_id,
                     "backend":self.backend_name,"expires_at":exp}
            if ok:
                self._blocked[ip]=entry; self._save()
            return {"success":ok,"message":msg,"ip":ip,"entry":entry}

    def unblock_ip(self, ip, reason="manual"):
        with self._lock:
            ok,msg = self._be.unblock(ip)
            self._blocked.pop(ip,None); self._save()
            logger.info(f"Unblocked {ip}: {reason}")
            return {"success":ok,"message":msg,"ip":ip}

    def is_blocked(self,ip): return ip in self._blocked
    def list_blocked(self): return list(self._blocked.values())
    def list_rules(self): return self._be.rules()
    def flush_all(self):
        with self._lock:
            ok,msg=self._be.flush(); self._blocked.clear(); self._save()
            return {"success":ok,"message":msg}
    def stats(self):
        return {"backend":self.backend_name,"enabled":self.enabled,
                "dry_run":self.dry_run,"blocked_count":len(self._blocked),"ttl_seconds":self.ttl}

    def _save(self):
        try:
            self._db.parent.mkdir(parents=True,exist_ok=True)
            with open(self._db,"w") as f: json.dump(self._blocked,f,indent=2,default=str)
        except Exception as e: logger.debug(f"FW save: {e}")

    def _load(self):
        if not self._db.exists(): return
        try:
            with open(self._db) as f: self._blocked=json.load(f)
            logger.info(f"Loaded {len(self._blocked)} active blocks")
        except Exception as e: logger.debug(f"FW load: {e}")

    def _ttl_loop(self):
        import time
        while True:
            time.sleep(60)
            now=datetime.now()
            for ip,entry in list(self._blocked.items()):
                exp=entry.get("expires_at")
                if exp:
                    try:
                        if datetime.fromisoformat(exp)<=now:
                            self.unblock_ip(ip,"ttl_expired")
                    except Exception: pass
