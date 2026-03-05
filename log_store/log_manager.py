"""AID-ARS v4.0 — Log Manager. Rotating JSONL, 1-year retention, CSV export."""
import os, json, gzip, shutil, threading, io, csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import logging as _logging

logger = _logging.getLogger("aidars.logmgr")

class LogChannel:
    def __init__(self, name, base_dir, rotate_daily=True, compress_old=True):
        self.name = name
        self.base_dir = Path(base_dir)
        self.rotate_daily = rotate_daily
        self.compress_old = compress_old
        self._lock = threading.Lock()
        self._cur_date = None
        self._cur_file = None
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._open_today()

    def _today(self): return datetime.now().strftime("%Y-%m-%d")
    def _path(self, date): return self.base_dir / f"{self.name}-{date}.jsonl"

    def _open_today(self):
        self._cur_date = self._today()
        self._cur_file = self._path(self._cur_date)

    def write(self, record: dict):
        if "ts" not in record:
            record["ts"] = datetime.now().isoformat()
        with self._lock:
            today = self._today()
            if self.rotate_daily and today != self._cur_date:
                self._compress(self._cur_file)
                self._open_today()
            try:
                with open(self._cur_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, default=str) + "\n")
            except Exception as e:
                logger.warning(f"Log write failed {self.name}: {e}")

    def _compress(self, path):
        if not self.compress_old or not path or not path.exists(): return
        gz = path.with_suffix(".jsonl.gz")
        try:
            with open(path,"rb") as fi, gzip.open(gz,"wb") as fo:
                shutil.copyfileobj(fi, fo)
            path.unlink()
        except Exception as e:
            logger.debug(f"Compress {path}: {e}")

    def query(self, since=None, until=None, filter_fn=None, limit=500):
        results = []
        files = sorted(
            list(self.base_dir.glob(f"{self.name}-*.jsonl")) +
            list(self.base_dir.glob(f"{self.name}-*.jsonl.gz")),
            key=lambda p: p.name, reverse=True
        )
        for fpath in files:
            if len(results) >= limit: break
            try:
                opener = gzip.open if str(fpath).endswith(".gz") else open
                with opener(fpath, "rt", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        try: rec = json.loads(line)
                        except Exception: continue
                        ts_s = rec.get("ts") or rec.get("timestamp","")
                        if ts_s and (since or until):
                            try:
                                ts = datetime.fromisoformat(ts_s[:19])
                                if since and ts < since: continue
                                if until and ts > until: continue
                            except Exception: pass
                        if filter_fn and not filter_fn(rec): continue
                        results.append(rec)
                        if len(results) >= limit: break
            except Exception as e:
                logger.debug(f"Read {fpath}: {e}")
        return results

    def stats(self):
        files = list(self.base_dir.glob(f"{self.name}-*.jsonl*"))
        total = sum(f.stat().st_size for f in files if f.exists())
        count = 0
        if self._cur_file and self._cur_file.exists():
            try:
                with open(self._cur_file) as f:
                    count = sum(1 for _ in f)
            except Exception: pass
        return {"channel": self.name, "files": len(files),
                "size_mb": round(total/1_048_576, 2), "today_records": count}


class LogManager:
    CHANNELS = ["alerts","traffic","blocks","events","assets"]

    def __init__(self, config: dict):
        cfg = config.get("logging", {})
        self.base_dir = Path(cfg.get("base_dir", "data/logs"))
        self.retention_days = int(cfg.get("retention_days", 365))
        self.max_total_gb = float(cfg.get("max_total_gb", 50))
        self.channels = {
            ch: LogChannel(ch, self.base_dir/ch,
                           rotate_daily=cfg.get("rotate_daily", True),
                           compress_old=cfg.get("compress_old", True))
            for ch in self.CHANNELS
        }
        threading.Thread(target=self._cleanup_loop, daemon=True, name="logmgr-gc").start()
        logger.info(f"LogManager ready — retention={self.retention_days}d base={self.base_dir}")

    def log_alert(self, a: dict):   self.channels["alerts"].write(a)
    def log_traffic(self, f: dict): self.channels["traffic"].write(f)
    def log_block(self, ip, reason, action="BLOCK", **kw):
        self.channels["blocks"].write({"action":action,"ip":ip,"reason":reason,"ts":datetime.now().isoformat(),**kw})
    def log_event(self, etype, detail, **kw):
        self.channels["events"].write({"event_type":etype,"detail":detail,"ts":datetime.now().isoformat(),**kw})
    def log_asset(self, a: dict): self.channels["assets"].write(a)

    def search(self, channel, text="", ip="", severity="", since_hours=24, limit=200):
        ch = self.channels.get(channel)
        if not ch: return []
        since = datetime.now() - timedelta(hours=since_hours) if since_hours else None
        tl = text.lower()
        def _f(r):
            if tl and tl not in json.dumps(r).lower(): return False
            if ip and r.get("src_ip")!=ip and r.get("ip")!=ip: return False
            if severity and r.get("severity","").upper()!=severity.upper(): return False
            return True
        return ch.query(since=since, filter_fn=_f, limit=limit)

    def stats(self):
        chs = {n: c.stats() for n,c in self.channels.items()}
        total = sum(s["size_mb"] for s in chs.values())
        pcap = Path("data/pcap")
        pcap_mb = round(sum(f.stat().st_size for f in pcap.glob("*.pcap*"))/1_048_576, 2) if pcap.exists() else 0
        return {"channels": chs, "total_size_mb": round(total,2),
                "pcap_size_mb": pcap_mb, "retention_days": self.retention_days}

    def export_csv(self, channel, since_hours=24):
        records = self.search(channel, since_hours=since_hours, limit=10000)
        if not records: return ""
        buf = io.StringIO()
        keys = list(records[0].keys())
        w = csv.DictWriter(buf, fieldnames=keys, extrasaction="ignore")
        w.writeheader(); w.writerows(records)
        return buf.getvalue()

    def _cleanup_loop(self):
        import time
        while True:
            time.sleep(3600)
            self._run_cleanup()

    def _run_cleanup(self):
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        deleted = 0
        for ch in self.channels.values():
            for fpath in list(ch.base_dir.glob("*.jsonl*")):
                try:
                    stem = fpath.stem.replace(".jsonl","")
                    date_s = stem.split("-",1)[-1]
                    if datetime.strptime(date_s,"%Y-%m-%d") < cutoff:
                        fpath.unlink(); deleted += 1
                except Exception: pass
        if deleted: logger.info(f"Log GC: removed {deleted} old files")
        self._enforce_size()

    def _enforce_size(self):
        cap = int(self.max_total_gb * 1_073_741_824)
        all_files = [f for ch in self.channels.values()
                     for f in ch.base_dir.glob("*.jsonl*")]
        all_files.sort(key=lambda p: p.stat().st_mtime)
        total = sum(f.stat().st_size for f in all_files)
        while total > cap and all_files:
            f = all_files.pop(0); sz = f.stat().st_size; f.unlink(); total -= sz
