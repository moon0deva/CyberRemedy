"""
CyberRemedy Data Lake — Tiered Storage
Hot (indexed, fast query) → Warm (compressed) → Cold (archive).
Inspired by Graylog Data Lake + Elastic frozen tier.
"""

import json
import gzip
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger("cyberremedy.datalake")

LAKE_BASE = Path("data/lake")
HOT_DIR = LAKE_BASE / "hot"
WARM_DIR = LAKE_BASE / "warm"
COLD_DIR = LAKE_BASE / "cold"


class DataLake:
    """
    Three-tier alert/event storage:
    - Hot: last 30 days, fully indexed in memory, fast query
    - Warm: 30-90 days, compressed JSON files, medium query speed
    - Cold: 90+ days, gzip archives, slow query (restore-on-demand)
    """

    HOT_DAYS = 30
    WARM_DAYS = 90

    def __init__(self):
        for d in (HOT_DIR, WARM_DIR, COLD_DIR):
            d.mkdir(parents=True, exist_ok=True)
        self._hot_index: List[dict] = []
        self._load_hot()

    def _load_hot(self):
        hot_file = HOT_DIR / "events.json"
        if hot_file.exists():
            try:
                self._hot_index = json.loads(hot_file.read_text())
                logger.info(f"Data lake hot tier: {len(self._hot_index)} events loaded")
            except Exception as e:
                logger.warning(f"Hot tier load error: {e}")
                self._hot_index = []

    def _save_hot(self):
        (HOT_DIR / "events.json").write_text(json.dumps(self._hot_index[-50000:]))

    def ingest(self, event: dict):
        """Add an event to the hot tier."""
        event.setdefault("ingested_at", datetime.utcnow().isoformat())
        event.setdefault("tier", "hot")
        self._hot_index.append(event)
        # Periodic save (every 100 events)
        if len(self._hot_index) % 100 == 0:
            self._save_hot()

    def ingest_batch(self, events: List[dict]):
        for e in events:
            self.ingest(e)
        self._save_hot()

    def query(self, src_ip: str = None, severity: str = None,
              event_type: str = None, mitre_id: str = None,
              start_time: str = None, end_time: str = None,
              limit: int = 500, tier: str = "hot") -> List[dict]:
        """Query events from hot (and optionally warm) tier."""
        if tier == "hot":
            events = list(reversed(self._hot_index[-10000:]))
        elif tier == "warm":
            events = self._load_warm_events()
        else:
            events = list(reversed(self._hot_index[-10000:])) + self._load_warm_events()

        # Apply filters
        if src_ip:
            events = [e for e in events if e.get("src_ip") == src_ip]
        if severity:
            events = [e for e in events if e.get("severity") == severity]
        if event_type:
            events = [e for e in events if event_type.lower() in e.get("type", "").lower()]
        if mitre_id:
            events = [e for e in events if e.get("mitre_id") == mitre_id]
        if start_time:
            events = [e for e in events if e.get("timestamp", "") >= start_time]
        if end_time:
            events = [e for e in events if e.get("timestamp", "") <= end_time]

        return events[:limit]

    def _load_warm_events(self) -> List[dict]:
        events = []
        for f in sorted(WARM_DIR.glob("*.json"))[-30:]:
            try:
                events.extend(json.loads(f.read_text()))
            except Exception:
                pass
        return list(reversed(events))

    def archive(self):
        """Move old hot events to warm tier, old warm to cold."""
        now = datetime.utcnow()
        hot_cutoff = (now - timedelta(days=self.HOT_DAYS)).isoformat()
        warm_cutoff = (now - timedelta(days=self.WARM_DAYS)).isoformat()

        # Move hot → warm
        warm_events = [e for e in self._hot_index if e.get("timestamp", "9") < hot_cutoff]
        self._hot_index = [e for e in self._hot_index if e.get("timestamp", "0") >= hot_cutoff]

        if warm_events:
            date_str = now.strftime("%Y%m%d_%H%M%S")
            warm_file = WARM_DIR / f"archive_{date_str}.json"
            warm_file.write_text(json.dumps(warm_events))
            logger.info(f"Archived {len(warm_events)} events to warm tier: {warm_file.name}")

        # Move old warm → cold (gzip)
        for f in WARM_DIR.glob("*.json"):
            stat = f.stat()
            file_date = datetime.fromtimestamp(stat.st_mtime)
            if (now - file_date).days > (self.WARM_DAYS - self.HOT_DAYS):
                cold_file = COLD_DIR / (f.name + ".gz")
                with open(f, "rb") as f_in:
                    with gzip.open(cold_file, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                f.unlink()
                logger.info(f"Archived to cold tier: {cold_file.name}")

        self._save_hot()

    def restore_from_cold(self, filename: str) -> List[dict]:
        """Restore events from a cold-tier archive for investigation."""
        cold_file = COLD_DIR / filename
        if not cold_file.exists():
            return []
        try:
            with gzip.open(cold_file, "rb") as f:
                events = json.loads(f.read())
            # Temporarily add to hot for querying
            for e in events:
                e["tier"] = "restored"
            self._hot_index.extend(events)
            logger.info(f"Restored {len(events)} events from cold: {filename}")
            return events
        except Exception as e:
            logger.error(f"Restore error: {e}")
            return []

    def list_archives(self) -> dict:
        warm = [{"name": f.name, "size_kb": round(f.stat().st_size / 1024, 1),
                 "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()}
                for f in sorted(WARM_DIR.glob("*.json"))]
        cold = [{"name": f.name, "size_kb": round(f.stat().st_size / 1024, 1),
                 "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()}
                for f in sorted(COLD_DIR.glob("*.gz"))]
        return {"warm": warm, "cold": cold}

    def stats(self) -> dict:
        hot_size = (HOT_DIR / "events.json").stat().st_size if (HOT_DIR / "events.json").exists() else 0
        warm_size = sum(f.stat().st_size for f in WARM_DIR.glob("*.json"))
        cold_size = sum(f.stat().st_size for f in COLD_DIR.glob("*.gz"))
        return {
            "hot_events": len(self._hot_index),
            "hot_size_mb": round(hot_size / 1e6, 2),
            "warm_files": len(list(WARM_DIR.glob("*.json"))),
            "warm_size_mb": round(warm_size / 1e6, 2),
            "cold_files": len(list(COLD_DIR.glob("*.gz"))),
            "cold_size_mb": round(cold_size / 1e6, 2),
            "total_size_mb": round((hot_size + warm_size + cold_size) / 1e6, 2),
        }
