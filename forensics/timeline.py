"""
CyberRemedy — Forensic Lab
==========================
Full forensic investigation workspace. Handles:

  1. Attack timeline reconstruction   — all events on one time axis, persisted to disk
  2. Session reconstruction           — step-by-step attacker activity replay
  3. Pivot / lateral movement graph   — IP → IP hop tracking
  4. IOC extraction                   — all IPs/domains/hashes seen in an incident
  5. PCAP correlation                 — link network packets to specific timeline events
  6. Evidence export                  — full case ZIP (timeline JSON, PCAP CSV, IOCs)
  7. MITRE ATT&CK narrative           — kill-chain story grouped by tactic stage
  8. Process tree visualization       — parent→child process chains (host events)
"""

import json
from utils.json_safe import sanitize, safe_dumps
import logging
import os
import re
import zipfile
import io
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cyberremedy.forensics")

TIMELINE_DIR  = Path("data/forensics")
TIMELINE_DIR.mkdir(parents=True, exist_ok=True)

# ─── MITRE tactic ordering + mapping ─────────────────────────────────────────

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "C2", "Exfiltration", "Impact",
]

MITRE_TACTIC_MAP = {
    "T1595": "Reconnaissance",    "T1596": "Reconnaissance",
    "T1046": "Discovery",         "T1082": "Discovery",         "T1083": "Discovery",
    "T1110": "Credential Access", "T1555": "Credential Access", "T1503": "Credential Access",
    "T1059": "Execution",         "T1203": "Execution",         "T1106": "Execution",
    "T1548": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1078": "Initial Access",    "T1190": "Initial Access",    "T1566": "Initial Access",
    "T1021": "Lateral Movement",  "T1570": "Lateral Movement",  "T1534": "Lateral Movement",
    "T1071": "C2",                "T1572": "C2",                "T1090": "C2",
    "T1048": "Exfiltration",      "T1041": "Exfiltration",
    "T1136": "Persistence",       "T1543": "Persistence",       "T1547": "Persistence",
    "T1040": "Collection",        "T1056": "Collection",
    "T1486": "Impact",            "T1490": "Impact",            "T1565": "Impact",
    "T1036": "Defense Evasion",   "T1055": "Defense Evasion",   "T1070": "Defense Evasion",
}


# ─── Data models ──────────────────────────────────────────────────────────────

class TimelineEvent:
    def __init__(self, event_id: str, timestamp: str, event_type: str,
                 source: str, entity: str, detail: str, raw: dict = None):
        self.event_id   = event_id
        self.timestamp  = timestamp
        self.event_type = event_type
        self.source     = source        # network|hids|auth|sigma|yara|ueba|tls|vpn|quic
        self.entity     = entity        # IP, hostname, user
        self.detail     = detail
        self.raw        = sanitize(raw or {})
        self.mitre_id   = raw.get("mitre_id", "") if raw else ""
        self.severity   = raw.get("severity", "INFO") if raw else "INFO"
        self.src_ip     = raw.get("src_ip", "") if raw else ""
        self.dst_ip     = raw.get("dst_ip", "") if raw else ""
        self.tags: List[str] = []
        # PCAP correlation
        self.pcap_ref: Optional[str] = None   # "filename:offset" or packet hash

    def to_dict(self) -> dict:
        return {
            "event_id":   self.event_id,
            "timestamp":  self.timestamp,
            "event_type": self.event_type,
            "source":     self.source,
            "entity":     self.entity,
            "detail":     self.detail,
            "mitre_id":   self.mitre_id,
            "severity":   self.severity,
            "src_ip":     self.src_ip,
            "dst_ip":     self.dst_ip,
            "tags":       self.tags,
            "pcap_ref":   self.pcap_ref,
        }


class ProcessNode:
    def __init__(self, pid: int, name: str, cmdline: str = "",
                 parent_pid: int = 0, username: str = "", exe: str = ""):
        self.pid        = pid
        self.name       = name
        self.cmdline    = cmdline
        self.parent_pid = parent_pid
        self.username   = username
        self.exe        = exe
        self.children: List["ProcessNode"] = []
        self.suspicious = False
        self.mitre_ids: List[str] = []

    def to_dict(self) -> dict:
        return {
            "pid": self.pid, "name": self.name, "cmdline": self.cmdline,
            "parent_pid": self.parent_pid, "username": self.username,
            "exe": self.exe, "suspicious": self.suspicious,
            "mitre_ids": self.mitre_ids,
            "children": [c.to_dict() for c in self.children],
        }


class PivotNode:
    """Node in the lateral movement graph."""
    def __init__(self, ip: str):
        self.ip          = ip
        self.hops_from:  Set[str] = set()   # IPs that reached this node
        self.hops_to:    Set[str] = set()   # IPs this node reached
        self.first_seen: str = ""
        self.last_seen:  str = ""
        self.event_count: int = 0
        self.techniques: Set[str] = set()

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "hops_from":   list(self.hops_from),
            "hops_to":     list(self.hops_to),
            "first_seen":  self.first_seen,
            "last_seen":   self.last_seen,
            "event_count": self.event_count,
            "techniques":  list(self.techniques),
        }


# ─── ForensicTimeline ─────────────────────────────────────────────────────────

class ForensicTimeline:
    """
    Complete forensic record for a single incident / entity.
    Persisted to data/forensics/<timeline_id>.json automatically.
    """

    def __init__(self, timeline_id: str, entity: str = "unknown",
                 description: str = ""):
        self.timeline_id  = timeline_id
        self.entity       = entity
        self.description  = description
        self.created_at   = datetime.now(tz=timezone.utc).isoformat()
        self.updated_at   = self.created_at
        self._events:       List[TimelineEvent]    = []
        self._process_nodes: Dict[int, ProcessNode] = {}
        self._pivot_nodes:   Dict[str, PivotNode]   = {}

    # ── ingestion ─────────────────────────────────────────────────────────────

    def add_event(self, event: TimelineEvent):
        self._events.append(event)
        self._events.sort(key=lambda e: e.timestamp)
        self.updated_at = datetime.now(tz=timezone.utc).isoformat()
        # Update pivot graph
        if event.src_ip and event.dst_ip and event.src_ip != event.dst_ip:
            self._update_pivot(event.src_ip, event.dst_ip,
                               event.timestamp, event.mitre_id)
        self._save()

    def add_from_alert(self, alert: dict):
        evt = TimelineEvent(
            event_id   = str(alert.get("id", id(alert))),
            timestamp  = alert.get("timestamp", datetime.now(tz=timezone.utc).isoformat()),
            event_type = alert.get("type", "UNKNOWN"),
            source     = alert.get("source", "detection"),
            entity     = alert.get("src_ip", alert.get("entity_id", "unknown")),
            detail     = alert.get("detail", alert.get("description", "")),
            raw        = alert,
        )
        self.add_event(evt)

    def add_process_event(self, proc_event: dict):
        pid  = proc_event.get("pid", 0)
        ppid = proc_event.get("parent_pid", 0)
        node = ProcessNode(
            pid=pid, name=proc_event.get("name", "?"),
            cmdline=proc_event.get("cmdline", ""),
            parent_pid=ppid, username=proc_event.get("username", "?"),
            exe=proc_event.get("exe", ""),
        )
        suspicious_types = {"PROC_SUSPICIOUS_SPAWN", "PROC_DELETED_BINARY", "PROC_SUSPICIOUS_TOOL"}
        if proc_event.get("type") in suspicious_types:
            node.suspicious = True
            node.mitre_ids  = [proc_event.get("mitre_id", "T1059")]
        self._process_nodes[pid] = node
        if ppid and ppid in self._process_nodes:
            self._process_nodes[ppid].children.append(node)
        self.add_event(TimelineEvent(
            event_id   = f"proc-{pid}",
            timestamp  = proc_event.get("timestamp", datetime.now(tz=timezone.utc).isoformat()),
            event_type = proc_event.get("type", "PROC_CREATE"),
            source     = "hids",
            entity     = proc_event.get("agent_id", "?"),
            detail     = f"PID {pid} — {node.name} — {node.cmdline[:80]}",
            raw        = proc_event,
        ))

    def correlate_pcap(self, pcap_filename: str, packets: List[dict]):
        """
        Link raw packet records to timeline events by matching src_ip/dst_ip/timestamp.
        Sets event.pcap_ref = 'filename:packet_index' for matched events.
        """
        correlated = 0
        for evt in self._events:
            if not evt.src_ip:
                continue
            for i, pkt in enumerate(packets):
                if (pkt.get("src_ip") == evt.src_ip or
                    pkt.get("dst_ip") == evt.src_ip):
                    # Check timestamp proximity (within 2 seconds)
                    try:
                        evt_ts = datetime.fromisoformat(
                            evt.timestamp.replace("Z", "")).timestamp()
                        pkt_ts = float(pkt.get("raw_ts", pkt.get("timestamp", 0)))
                        if abs(evt_ts - pkt_ts) <= 2.0:
                            evt.pcap_ref = f"{pcap_filename}:{i}"
                            correlated += 1
                            break
                    except Exception:
                        pass
        self._save()
        return correlated

    # ── queries ───────────────────────────────────────────────────────────────

    def get_events(self, source: str = None, severity: str = None,
                   mitre_id: str = None, src_ip: str = None,
                   since: str = None, limit: int = 500) -> List[dict]:
        events = self._events
        if source:   events = [e for e in events if e.source   == source]
        if severity: events = [e for e in events if e.severity == severity]
        if mitre_id: events = [e for e in events if e.mitre_id == mitre_id]
        if src_ip:   events = [e for e in events if e.src_ip   == src_ip or e.entity == src_ip]
        if since:
            events = [e for e in events if e.timestamp >= since]
        return [e.to_dict() for e in events[-limit:]]

    def get_session_replay(self, src_ip: str) -> List[dict]:
        """
        Reconstruct an attacker's session step-by-step.
        Returns ordered events for src_ip with diffs between steps.
        """
        events = [e for e in self._events
                  if e.src_ip == src_ip or e.entity == src_ip]
        replay = []
        prev_ts = None
        for i, evt in enumerate(events):
            try:
                ts = datetime.fromisoformat(evt.timestamp.replace("Z", "")).timestamp()
                gap_s = ts - prev_ts if prev_ts else 0
                prev_ts = ts
            except Exception:
                gap_s = 0
            step = evt.to_dict()
            step["step"]         = i + 1
            step["gap_seconds"]  = round(gap_s, 2)
            step["tactic"]       = MITRE_TACTIC_MAP.get(evt.mitre_id, "")
            replay.append(step)
        return replay

    def get_pivot_graph(self) -> dict:
        """Return lateral movement graph: nodes + edges."""
        nodes = [n.to_dict() for n in self._pivot_nodes.values()]
        edges = []
        seen_edges: Set[str] = set()
        for node in self._pivot_nodes.values():
            for dst in node.hops_to:
                key = f"{node.ip}->{dst}"
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({
                        "from": node.ip, "to": dst,
                        "count": sum(
                            1 for e in self._events
                            if e.src_ip == node.ip and e.dst_ip == dst
                        ),
                    })
        return {"nodes": nodes, "edges": edges}

    def extract_iocs(self) -> dict:
        """Extract all IOCs seen in this timeline."""
        ips:     Set[str] = set()
        domains: Set[str] = set()
        hashes:  Set[str] = set()
        urls:    Set[str] = set()
        emails:  Set[str] = set()

        ip_re     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        domain_re = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        hash_re   = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
        url_re    = re.compile(r'https?://\S+')
        email_re  = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        for evt in self._events:
            text = json.dumps(sanitize(evt.raw))
            ips.update(ip_re.findall(text))
            urls_found = url_re.findall(text)
            urls.update(urls_found)
            for u in urls_found:
                # Extract domain from URL
                m = re.search(r'https?://([^/?\s]+)', u)
                if m:
                    domains.add(m.group(1))
            domains.update(d for d in domain_re.findall(text)
                           if '.' in d and not ip_re.match(d))
            hashes.update(h for h in hash_re.findall(text) if len(h) in (32, 40, 64))
            emails.update(email_re.findall(text))

        # Filter out noise
        private_prefixes = ("192.168.", "10.", "172.", "127.", "0.", "255.")
        ips = {ip for ip in ips
               if not any(ip.startswith(p) for p in private_prefixes)}

        return {
            "ips":     sorted(ips),
            "domains": sorted(domains),
            "hashes":  sorted(hashes),
            "urls":    sorted(urls),
            "emails":  sorted(emails),
            "total":   len(ips) + len(domains) + len(hashes),
        }

    def get_process_tree(self) -> List[dict]:
        roots = [n for n in self._process_nodes.values()
                 if n.parent_pid not in self._process_nodes]
        return [n.to_dict() for n in roots]

    def get_attack_narrative(self) -> List[dict]:
        """Events grouped by MITRE tactic stage."""
        grouped = defaultdict(list)
        for evt in self._events:
            if evt.mitre_id:
                tactic = MITRE_TACTIC_MAP.get(evt.mitre_id, "Other")
                grouped[tactic].append(evt.to_dict())
        narrative = []
        for tactic in TACTIC_ORDER:
            if tactic in grouped:
                narrative.append({
                    "stage":       tactic,
                    "event_count": len(grouped[tactic]),
                    "events":      grouped[tactic][:10],
                })
        if "Other" in grouped:
            narrative.append({
                "stage": "Other", "event_count": len(grouped["Other"]),
                "events": grouped["Other"][:5],
            })
        return narrative

    def export_zip(self) -> bytes:
        """
        Export complete forensic case as a ZIP archive:
          timeline.json     — all events
          session_replay.json — step-by-step attacker sessions
          pivot_graph.json  — lateral movement graph
          iocs.json         — extracted IOCs
          process_tree.json — process tree
          narrative.json    — MITRE kill-chain narrative
          summary.txt       — human-readable summary
        """
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("timeline.json",
                        json.dumps(self.to_dict(), indent=2))
            zf.writestr("iocs.json",
                        safe_dumps(self.extract_iocs(), indent=2))
            zf.writestr("pivot_graph.json",
                        safe_dumps(self.get_pivot_graph(), indent=2))
            zf.writestr("process_tree.json",
                        safe_dumps(self.get_process_tree(), indent=2))
            zf.writestr("narrative.json",
                        safe_dumps(self.get_attack_narrative(), indent=2))
            # Session replays for each unique source IP
            src_ips = {e.src_ip for e in self._events if e.src_ip}
            replays = {}
            for ip in src_ips:
                replays[ip] = self.get_session_replay(ip)
            zf.writestr("session_replays.json",
                        safe_dumps(replays, indent=2))
            # Human readable summary
            s = self.summary()
            lines = [
                f"CyberRemedy Forensic Export",
                f"Timeline ID : {self.timeline_id}",
                f"Entity      : {self.entity}",
                f"Description : {self.description}",
                f"Created     : {self.created_at}",
                f"Events      : {s['event_count']}",
                f"First event : {s['first_event']}",
                f"Last event  : {s['last_event']}",
                f"MITRE IDs   : {', '.join(s['mitre_ids'])}",
                f"Severity    : {safe_dumps(s['severity_breakdown'])}",
                f"Sources     : {safe_dumps(s['source_breakdown'])}",
            ]
            zf.writestr("summary.txt", "\n".join(lines))
        return buf.getvalue()

    def summary(self) -> dict:
        severities = defaultdict(int)
        sources    = defaultdict(int)
        mitre_ids  = set()
        for e in self._events:
            severities[e.severity] += 1
            sources[e.source]      += 1
            if e.mitre_id:
                mitre_ids.add(e.mitre_id)
        start = self._events[0].timestamp  if self._events else None
        end   = self._events[-1].timestamp if self._events else None
        iocs  = self.extract_iocs()
        return {
            "timeline_id":        self.timeline_id,
            "entity":             self.entity,
            "description":        self.description,
            "created_at":         self.created_at,
            "updated_at":         self.updated_at,
            "event_count":        len(self._events),
            "first_event":        start,
            "last_event":         end,
            "severity_breakdown": dict(severities),
            "source_breakdown":   dict(sources),
            "mitre_ids":          list(mitre_ids),
            "process_nodes":      len(self._process_nodes),
            "pivot_nodes":        len(self._pivot_nodes),
            "ioc_count":          iocs["total"],
            "unique_src_ips":     len({e.src_ip for e in self._events if e.src_ip}),
        }

    def to_dict(self) -> dict:
        return {
            **self.summary(),
            "events":           self.get_events(),
            "process_tree":     self.get_process_tree(),
            "attack_narrative": self.get_attack_narrative(),
            "pivot_graph":      self.get_pivot_graph(),
        }

    # ── persistence ───────────────────────────────────────────────────────────

    def _save(self):
        try:
            path = TIMELINE_DIR / f"{self.timeline_id}.json"
            path.write_text(safe_dumps(self.to_dict(), indent=2))
        except Exception as exc:
            logger.debug(f"[Forensics] Save error: {exc}")

    @classmethod
    def load(cls, timeline_id: str) -> Optional["ForensicTimeline"]:
        path = TIMELINE_DIR / f"{timeline_id}.json"
        if not path.exists():
            return None
        try:
            data   = json.loads(path.read_text())
            tl     = cls(timeline_id, data.get("entity", "unknown"),
                         data.get("description", ""))
            tl.created_at = data.get("created_at", tl.created_at)
            tl.updated_at = data.get("updated_at", tl.created_at)
            for ev in data.get("events", []):
                tl._events.append(TimelineEvent(
                    event_id   = ev.get("event_id", ""),
                    timestamp  = ev.get("timestamp", ""),
                    event_type = ev.get("event_type", ""),
                    source     = ev.get("source", ""),
                    entity     = ev.get("entity", ""),
                    detail     = ev.get("detail", ""),
                    raw        = ev,
                ))
            return tl
        except Exception as exc:
            logger.error(f"[Forensics] Load error {timeline_id}: {exc}")
            return None

    # ── private ───────────────────────────────────────────────────────────────

    def _update_pivot(self, src: str, dst: str, ts: str, mitre_id: str):
        if src not in self._pivot_nodes:
            self._pivot_nodes[src] = PivotNode(src)
        if dst not in self._pivot_nodes:
            self._pivot_nodes[dst] = PivotNode(dst)
        sn = self._pivot_nodes[src]
        dn = self._pivot_nodes[dst]
        sn.hops_to.add(dst)
        dn.hops_from.add(src)
        sn.event_count += 1
        dn.event_count += 1
        if not sn.first_seen or ts < sn.first_seen: sn.first_seen = ts
        if not sn.last_seen  or ts > sn.last_seen:  sn.last_seen  = ts
        if mitre_id:
            sn.techniques.add(mitre_id)


# ─── ForensicsManager ─────────────────────────────────────────────────────────

class ForensicsManager:
    """
    Manages all forensic timelines.
    Persists to data/forensics/ and reloads on startup.
    """

    def __init__(self):
        self._timelines: Dict[str, ForensicTimeline] = {}
        self._tl_counter = 0
        self._load_all()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def create_timeline(self, entity: str = "unknown",
                        description: str = "") -> ForensicTimeline:
        self._tl_counter += 1
        tid = f"TL-{self._tl_counter:04d}"
        tl  = ForensicTimeline(tid, entity, description)
        self._timelines[tid] = tl
        return tl

    def create_from_chain(self, chain: dict,
                          all_alerts: List[dict]) -> ForensicTimeline:
        src_ip = chain.get("src_ip", "unknown")
        tl = self.create_timeline(
            src_ip, f"Attack chain — {src_ip} ({chain.get('chain_id','?')})"
        )
        chain_ids = set(chain.get("alert_ids", []))
        for alert in all_alerts:
            if alert.get("src_ip") == src_ip or alert.get("id") in chain_ids:
                tl.add_from_alert(alert)
        return tl

    def ingest_host_event(self, event: dict):
        entity = event.get("agent_id") or event.get("src_ip", "unknown")
        tl = next(
            (t for t in self._timelines.values() if t.entity == entity),
            None,
        )
        if tl is None:
            tl = self.create_timeline(entity, f"Auto-timeline — {entity}")
        if "pid" in event:
            tl.add_process_event(event)
        else:
            tl.add_event(TimelineEvent(
                event_id   = str(id(event)),
                timestamp  = event.get("timestamp", datetime.now(tz=timezone.utc).isoformat()),
                event_type = event.get("type", "HOST_EVENT"),
                source     = event.get("source", "detection"),
                entity     = entity,
                detail     = event.get("detail", event.get("description", "")),
                raw        = event,
            ))

    # ── queries ───────────────────────────────────────────────────────────────

    def get(self, timeline_id: str) -> Optional[ForensicTimeline]:
        return self._timelines.get(timeline_id)

    def get_or_create(self, entity: str) -> ForensicTimeline:
        tl = next((t for t in self._timelines.values() if t.entity == entity), None)
        if tl is None:
            tl = self.create_timeline(entity)
        return tl

    def list(self, src_ip: str = None,
             since_ts: float = None,
             limit: int = 200) -> List[dict]:
        tls = list(self._timelines.values())
        if src_ip:
            tls = [t for t in tls
                   if t.entity == src_ip
                   or any(e.src_ip == src_ip for e in t._events)]
        if since_ts:
            iso = datetime.fromtimestamp(since_ts, tz=timezone.utc).isoformat()
            tls = [t for t in tls if t.updated_at >= iso]
        return [t.summary() for t in sorted(
            tls, key=lambda t: t.updated_at, reverse=True
        )[:limit]]

    def get_all_events(self, src_ip: str = None,
                       severity: str = None,
                       since_ts: float = None,
                       limit: int = 500) -> List[dict]:
        """Flattened event list across all timelines."""
        events = []
        for tl in self._timelines.values():
            since_iso = (datetime.fromtimestamp(since_ts, tz=timezone.utc).isoformat()
                         if since_ts else None)
            events.extend(tl.get_events(
                src_ip=src_ip, severity=severity, since=since_iso, limit=limit
            ))
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return events[:limit]

    def correlate_pcap(self, timeline_id: str,
                       pcap_filename: str,
                       packets: List[dict]) -> dict:
        tl = self.get(timeline_id)
        if not tl:
            return {"ok": False, "error": f"Timeline {timeline_id} not found"}
        n = tl.correlate_pcap(pcap_filename, packets)
        return {"ok": True, "correlated": n, "timeline_id": timeline_id}

    def export_zip(self, timeline_id: str) -> Optional[bytes]:
        tl = self.get(timeline_id)
        return tl.export_zip() if tl else None

    def delete(self, timeline_id: str) -> bool:
        tl = self._timelines.pop(timeline_id, None)
        if tl:
            path = TIMELINE_DIR / f"{timeline_id}.json"
            if path.exists():
                path.unlink()
            return True
        return False

    @property
    def stats(self) -> dict:
        total_events = sum(len(t._events) for t in self._timelines.values())
        severity_dist = defaultdict(int)
        for t in self._timelines.values():
            for e in t._events:
                severity_dist[e.severity] += 1
        return {
            "total_timelines": len(self._timelines),
            "total_events":    total_events,
            "severity_dist":   dict(severity_dist),
            "persisted_files": len(list(TIMELINE_DIR.glob("*.json"))),
        }

    # ── persistence ───────────────────────────────────────────────────────────

    def _load_all(self):
        for path in sorted(TIMELINE_DIR.glob("TL-*.json")):
            tid = path.stem
            tl  = ForensicTimeline.load(tid)
            if tl:
                self._timelines[tid] = tl
                # Update counter to avoid ID collisions
                try:
                    n = int(tid.split("-")[1])
                    if n >= self._tl_counter:
                        self._tl_counter = n
                except Exception:
                    pass
        if self._timelines:
            logger.info(f"[Forensics] Loaded {len(self._timelines)} timelines from disk")
