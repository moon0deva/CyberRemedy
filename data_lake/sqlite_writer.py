"""
CyberRemedy — Buffered SQLite Writer
=====================================
Replaces per-event SQLite inserts with buffered batch writes.
Buffer flushes when:
  - Buffer reaches BATCH_SIZE (default 50 events)
  - FLUSH_INTERVAL seconds elapse (default 5s)
  - flush() is called explicitly (e.g. on shutdown)

Tables:
  alerts        — ML + signature + heuristic alerts
  events        — generic events (syslog, honeypot, UEBA, etc.)
  network_flows — completed flow feature vectors
  dns_events    — extracted DNS queries and answers
  assets        — discovered LAN devices

All writes are INSERT OR IGNORE or INSERT OR REPLACE to be idempotent.
Schema is created on first connect (no migration needed for new deploys).
"""

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberremedy.sqlite_writer")

DB_PATH      = Path("data/cyberremedy.db")
BATCH_SIZE   = 50          # flush after this many buffered items per table
FLUSH_INTERVAL = 5.0       # flush every N seconds even if buffer isn't full


# ── Schema definitions ─────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      TEXT UNIQUE,
    timestamp     TEXT NOT NULL,
    severity      TEXT,
    type          TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT,
    mitre_id      TEXT,
    confidence    REAL,
    detail        TEXT,
    status        TEXT DEFAULT 'OPEN',
    source        TEXT,
    flow_key      TEXT,
    anomaly_score REAL,
    raw_json      TEXT,
    ingested_at   TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip   ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(type);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    event_type  TEXT,
    severity    TEXT,
    src_ip      TEXT,
    message     TEXT,
    source      TEXT,
    raw_json    TEXT,
    ingested_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS network_flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_key        TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    packet_count    INTEGER,
    total_bytes     INTEGER,
    bytes_per_second REAL,
    packets_per_second REAL,
    flow_duration   REAL,
    payload_entropy REAL,
    connection_rate REAL,
    has_syn         INTEGER,
    has_rst         INTEGER,
    raw_json        TEXT,
    captured_at     TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_flows_src  ON network_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst  ON network_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_ts   ON network_flows(captured_at);

CREATE TABLE IF NOT EXISTS dns_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    src_ip      TEXT,
    dst_ip      TEXT,
    query_name  TEXT,
    qtype       INTEGER,
    is_response INTEGER,
    rcode       INTEGER,
    answers     TEXT,           -- JSON list of {name,type,rdata}
    resolved    TEXT,           -- JSON list of resolved IP strings
    raw_json    TEXT,
    ingested_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_events(query_name);
CREATE INDEX IF NOT EXISTS idx_dns_src  ON dns_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_dns_ts   ON dns_events(timestamp);

CREATE TABLE IF NOT EXISTS assets (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    os_guess    TEXT,
    open_ports  TEXT,           -- JSON list
    first_seen  TEXT,
    last_seen   TEXT,
    is_known    INTEGER DEFAULT 0,
    raw_json    TEXT,
    updated_at  TEXT DEFAULT (datetime('now'))
);
"""


# ── Per-table buffer ───────────────────────────────────────────────────────────

class _TableBuffer:
    """Holds rows for a single table until flush threshold is reached."""
    def __init__(self, name: str, batch_size: int = BATCH_SIZE):
        self.name       = name
        self.batch_size = batch_size
        self._rows: List[dict] = []
        self._lock = threading.Lock()

    def add(self, row: dict) -> bool:
        """Add a row. Returns True if buffer is now full (caller should flush)."""
        with self._lock:
            self._rows.append(row)
            return len(self._rows) >= self.batch_size

    def drain(self) -> List[dict]:
        """Atomically take all buffered rows."""
        with self._lock:
            rows, self._rows = self._rows, []
            return rows

    def __len__(self):
        with self._lock:
            return len(self._rows)


# ── Insert query builders ──────────────────────────────────────────────────────

def _insert_alert(row: dict) -> tuple:
    sql = """
    INSERT OR IGNORE INTO alerts
      (alert_id, timestamp, severity, type, src_ip, dst_ip, src_port, dst_port,
       protocol, mitre_id, confidence, detail, status, source, flow_key,
       anomaly_score, raw_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    vals = (
        str(row.get("id", "")),
        row.get("timestamp", ""),
        row.get("severity", ""),
        row.get("type", ""),
        row.get("src_ip", ""),
        row.get("dst_ip", ""),
        int(row.get("src_port", 0) or 0),
        int(row.get("dst_port", 0) or 0),
        row.get("protocol", ""),
        row.get("mitre_id", ""),
        float(row.get("confidence", 0) or 0),
        row.get("detail", ""),
        row.get("status", "OPEN"),
        row.get("source", ""),
        row.get("flow_key", ""),
        float(row.get("anomaly_score", 0) or 0) if row.get("anomaly_score") is not None else None,
        json.dumps(row, default=str),
    )
    return sql, vals


def _insert_event(row: dict) -> tuple:
    sql = """
    INSERT INTO events (timestamp, event_type, severity, src_ip, message, source, raw_json)
    VALUES (?,?,?,?,?,?,?)
    """
    vals = (
        row.get("timestamp", ""),
        row.get("type", row.get("event_type", "")),
        row.get("severity", ""),
        row.get("src_ip", ""),
        row.get("message", row.get("detail", "")),
        row.get("source", ""),
        json.dumps(row, default=str),
    )
    return sql, vals


def _insert_flow(row: dict) -> tuple:
    sql = """
    INSERT INTO network_flows
      (flow_key, src_ip, dst_ip, src_port, dst_port, protocol,
       packet_count, total_bytes, bytes_per_second, packets_per_second,
       flow_duration, payload_entropy, connection_rate, has_syn, has_rst, raw_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    vals = (
        row.get("flow_key", ""),
        row.get("src_ip", ""),
        row.get("dst_ip", ""),
        int(row.get("src_port", 0) or 0),
        int(row.get("dst_port", 0) or 0),
        row.get("protocol", ""),
        int(row.get("packet_count", 0) or 0),
        int(row.get("total_bytes", 0) or 0),
        float(row.get("bytes_per_second", 0) or 0),
        float(row.get("packets_per_second", 0) or 0),
        float(row.get("flow_duration", 0) or 0),
        float(row.get("payload_entropy", 0) or 0),
        float(row.get("connection_rate", 0) or 0),
        int(row.get("has_syn", 0) or 0),
        int(row.get("has_rst", 0) or 0),
        json.dumps(row, default=str),
    )
    return sql, vals


def _insert_dns(row: dict) -> tuple:
    sql = """
    INSERT INTO dns_events
      (timestamp, src_ip, dst_ip, query_name, qtype, is_response,
       rcode, answers, resolved, raw_json)
    VALUES (?,?,?,?,?,?,?,?,?,?)
    """
    queries = row.get("dns_queries", [])
    first_q = queries[0] if queries else {}
    vals = (
        row.get("timestamp", ""),
        row.get("src_ip", ""),
        row.get("dst_ip", ""),
        row.get("dns_query", first_q.get("name", "")),
        int(first_q.get("qtype", 0)),
        int(row.get("dns_qr", 0)),
        int(row.get("dns_rcode", 0)),
        json.dumps(row.get("dns_answers", []), default=str),
        json.dumps(row.get("dns_resolved", []), default=str),
        json.dumps(row, default=str),
    )
    return sql, vals


def _insert_asset(row: dict) -> tuple:
    sql = """
    INSERT OR REPLACE INTO assets
      (ip, mac, hostname, vendor, os_guess, open_ports,
       first_seen, last_seen, is_known, raw_json, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))
    """
    vals = (
        row.get("ip", ""),
        row.get("mac", ""),
        row.get("hostname", ""),
        row.get("vendor", ""),
        row.get("os_guess", ""),
        json.dumps(row.get("open_ports", []), default=str),
        row.get("first_seen", ""),
        row.get("last_seen", ""),
        int(bool(row.get("is_known", False))),
        json.dumps(row, default=str),
    )
    return sql, vals


# ── Main writer class ──────────────────────────────────────────────────────────

class SQLiteWriter:
    """
    Buffered batch writer for all CyberRemedy SQLite tables.

    Usage:
        writer = SQLiteWriter()
        writer.write_alert(alert_dict)
        writer.write_flow(flow_dict)
        writer.write_dns(packet_dict)   # only called when protocol=="DNS"
        writer.write_event(event_dict)
        writer.write_asset(asset_dict)
        writer.flush()                  # explicit flush (called on shutdown)
    """

    def __init__(
        self,
        db_path: Path = DB_PATH,
        batch_size: int = BATCH_SIZE,
        flush_interval: float = FLUSH_INTERVAL,
    ):
        self._db_path       = Path(db_path)
        self._batch_size    = batch_size
        self._flush_interval = flush_interval

        # Per-table buffers
        self._bufs: Dict[str, _TableBuffer] = {
            "alerts":        _TableBuffer("alerts",        batch_size),
            "events":        _TableBuffer("events",        batch_size),
            "network_flows": _TableBuffer("network_flows", batch_size),
            "dns_events":    _TableBuffer("dns_events",    batch_size),
            "assets":        _TableBuffer("assets",        batch_size),
        }

        # Stats
        self._total_written: Dict[str, int] = {k: 0 for k in self._bufs}
        self._flush_count   = 0
        self._errors        = 0

        # Background flush timer
        self._stop    = threading.Event()
        self._lock    = threading.Lock()
        self._thread  = threading.Thread(
            target=self._flush_loop, daemon=True, name="sqlite-flush"
        )

        # Init DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._thread.start()
        logger.info(f"SQLiteWriter ready: {self._db_path} (batch={batch_size}, interval={flush_interval}s)")

    # ── Public write methods ───────────────────────────────────────────────

    def write_alert(self, row: dict) -> None:
        if self._bufs["alerts"].add(row):
            self._flush_table("alerts")

    def write_event(self, row: dict) -> None:
        if self._bufs["events"].add(row):
            self._flush_table("events")

    def write_flow(self, row: dict) -> None:
        if self._bufs["network_flows"].add(row):
            self._flush_table("network_flows")

    def write_dns(self, row: dict) -> None:
        """Call this for any packet where protocol == 'DNS'."""
        if not row.get("dns_query") and not row.get("dns_queries"):
            return
        if self._bufs["dns_events"].add(row):
            self._flush_table("dns_events")

    def write_asset(self, row: dict) -> None:
        if self._bufs["assets"].add(row):
            self._flush_table("assets")

    def flush(self) -> None:
        """Flush all buffers immediately. Call on shutdown."""
        for table in self._bufs:
            self._flush_table(table)

    def stop(self) -> None:
        """Stop background flush thread and flush remaining rows."""
        self._stop.set()
        self.flush()
        self._thread.join(timeout=5)

    # ── Flush logic ───────────────────────────────────────────────────────

    def _flush_loop(self) -> None:
        """Background thread: flush every FLUSH_INTERVAL seconds."""
        while not self._stop.is_set():
            time.sleep(self._flush_interval)
            for table in self._bufs:
                if len(self._bufs[table]) > 0:
                    self._flush_table(table)

    def _flush_table(self, table: str) -> None:
        rows = self._bufs[table].drain()
        if not rows:
            return

        builders = {
            "alerts":        _insert_alert,
            "events":        _insert_event,
            "network_flows": _insert_flow,
            "dns_events":    _insert_dns,
            "assets":        _insert_asset,
        }
        builder = builders.get(table)
        if not builder:
            return

        stmts = [builder(r) for r in rows]
        try:
            with self._get_conn() as conn:
                for sql, vals in stmts:
                    try:
                        conn.execute(sql, vals)
                    except sqlite3.IntegrityError:
                        pass    # IGNORE duplicates
            self._total_written[table] += len(rows)
            self._flush_count += 1
        except Exception as exc:
            self._errors += 1
            logger.warning(f"SQLite flush [{table}] failed: {exc} — {len(rows)} rows dropped")

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        try:
            with self._get_conn() as conn:
                conn.executescript(_SCHEMA)
            logger.info("SQLite schema initialised")
        except Exception as exc:
            logger.error(f"SQLite schema init failed: {exc}")

    # ── Stats ─────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        return {
            "db_path":       str(self._db_path),
            "flush_count":   self._flush_count,
            "errors":        self._errors,
            "total_written": dict(self._total_written),
            "buffer_depths": {k: len(v) for k, v in self._bufs.items()},
        }

    def query_alerts(
        self,
        severity: Optional[str] = None,
        src_ip:   Optional[str] = None,
        limit:    int = 200,
    ) -> List[dict]:
        """Simple alert query for API endpoints."""
        sql  = "SELECT raw_json FROM alerts WHERE 1=1"
        args: List[Any] = []
        if severity:
            sql  += " AND severity = ?"; args.append(severity)
        if src_ip:
            sql  += " AND src_ip = ?";   args.append(src_ip)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        try:
            with self._get_conn() as conn:
                rows = conn.execute(sql, args).fetchall()
            return [json.loads(r[0]) for r in rows]
        except Exception as exc:
            logger.warning(f"query_alerts: {exc}")
            return []

    def query_dns(
        self,
        name:   Optional[str] = None,
        src_ip: Optional[str] = None,
        limit:  int = 500,
    ) -> List[dict]:
        """Return recent DNS events, optionally filtered."""
        sql  = "SELECT raw_json FROM dns_events WHERE 1=1"
        args: List[Any] = []
        if name:
            sql  += " AND query_name LIKE ?"; args.append(f"%{name}%")
        if src_ip:
            sql  += " AND src_ip = ?";        args.append(src_ip)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        try:
            with self._get_conn() as conn:
                rows = conn.execute(sql, args).fetchall()
            return [json.loads(r[0]) for r in rows]
        except Exception as exc:
            logger.warning(f"query_dns: {exc}")
            return []

    def db_stats(self) -> dict:
        """Return row counts for all tables."""
        counts = {}
        try:
            with self._get_conn() as conn:
                for table in self._bufs:
                    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                    counts[table] = row[0] if row else 0
        except Exception:
            pass
        return counts
