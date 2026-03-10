"""
CyberRemedy Forensic Timeline
Reconstructs attack timelines from correlated events.
Provides process tree visualization, session reconstruction, and pivot analysis.
"""

import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cyberremedy.forensics")

TIMELINE_PATH = Path("data/forensic_timelines.json")


class TimelineEvent:
    def __init__(self, event_id: str, timestamp: str, event_type: str,
                 source: str, entity: str, detail: str, raw: dict = None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.event_type = event_type
        self.source = source        # network | hids | auth | sigma | yara | ueba
        self.entity = entity        # IP, hostname, user
        self.detail = detail
        self.raw = raw or {}
        self.mitre_id = raw.get("mitre_id", "") if raw else ""
        self.severity = raw.get("severity", "INFO") if raw else "INFO"
        self.tags: List[str] = []

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source": self.source,
            "entity": self.entity,
            "detail": self.detail,
            "mitre_id": self.mitre_id,
            "severity": self.severity,
            "tags": self.tags,
        }


class ProcessNode:
    """Node in a process tree for host forensics."""

    def __init__(self, pid: int, name: str, cmdline: str = "",
                 parent_pid: int = 0, username: str = "", exe: str = ""):
        self.pid = pid
        self.name = name
        self.cmdline = cmdline
        self.parent_pid = parent_pid
        self.username = username
        self.exe = exe
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


class ForensicTimeline:
    """
    Builds and queries attack timelines for a given entity or time window.
    """

    def __init__(self, timeline_id: str, entity: str = "unknown",
                 description: str = ""):
        self.timeline_id = timeline_id
        self.entity = entity
        self.description = description
        self.created_at = datetime.utcnow().isoformat()
        self._events: List[TimelineEvent] = []
        self._process_nodes: Dict[int, ProcessNode] = {}

    def add_event(self, event: TimelineEvent):
        self._events.append(event)
        self._events.sort(key=lambda e: e.timestamp)

    def add_from_alert(self, alert: dict):
        """Convert a detection alert into a timeline event."""
        evt = TimelineEvent(
            event_id=str(alert.get("id", id(alert))),
            timestamp=alert.get("timestamp", datetime.utcnow().isoformat()),
            event_type=alert.get("type", "UNKNOWN"),
            source=alert.get("source", "detection"),
            entity=alert.get("src_ip", alert.get("entity_id", "unknown")),
            detail=alert.get("detail", ""),
            raw=alert,
        )
        evt.severity = alert.get("severity", "INFO")
        evt.mitre_id = alert.get("mitre_id", "")
        self.add_event(evt)

    def add_process_event(self, proc_event: dict):
        """Add a process creation event to the process tree."""
        pid = proc_event.get("pid", 0)
        ppid = proc_event.get("parent_pid", 0)
        node = ProcessNode(
            pid=pid,
            name=proc_event.get("name", "?"),
            cmdline=proc_event.get("cmdline", ""),
            parent_pid=ppid,
            username=proc_event.get("username", "?"),
            exe=proc_event.get("exe", ""),
        )
        # Mark suspicious
        suspicious_types = {"PROC_SUSPICIOUS_SPAWN", "PROC_DELETED_BINARY", "PROC_SUSPICIOUS_TOOL"}
        if proc_event.get("type") in suspicious_types:
            node.suspicious = True
            node.mitre_ids = [proc_event.get("mitre_id", "T1059")]

        self._process_nodes[pid] = node

        # Link to parent
        if ppid and ppid in self._process_nodes:
            self._process_nodes[ppid].children.append(node)

        # Also add as timeline event
        self.add_event(TimelineEvent(
            event_id=f"proc-{pid}",
            timestamp=proc_event.get("timestamp", datetime.utcnow().isoformat()),
            event_type=proc_event.get("type", "PROC_CREATE"),
            source="hids",
            entity=proc_event.get("agent_id", "?"),
            detail=f"PID {pid} — {node.name} — {node.cmdline[:80]}",
            raw=proc_event,
        ))

    def get_events(self, source: str = None, severity: str = None,
                   mitre_id: str = None) -> List[dict]:
        events = self._events
        if source:
            events = [e for e in events if e.source == source]
        if severity:
            events = [e for e in events if e.severity == severity]
        if mitre_id:
            events = [e for e in events if e.mitre_id == mitre_id]
        return [e.to_dict() for e in events]

    def get_process_tree(self) -> List[dict]:
        """Return root-level process nodes with full child trees."""
        roots = [n for n in self._process_nodes.values()
                 if n.parent_pid not in self._process_nodes]
        return [n.to_dict() for n in roots]

    def get_attack_narrative(self) -> List[dict]:
        """Return key events grouped by MITRE tactic stage."""
        tactic_order = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "C2", "Exfiltration",
        ]
        mitre_map = {
            "T1595": "Reconnaissance", "T1046": "Discovery",
            "T1110": "Credential Access", "T1059": "Execution",
            "T1548": "Privilege Escalation", "T1078": "Initial Access",
            "T1021": "Lateral Movement", "T1071": "C2",
            "T1048": "Exfiltration", "T1565": "Impact",
            "T1136": "Persistence", "T1503": "Credential Access",
            "T1486": "Impact",
        }
        grouped = defaultdict(list)
        for evt in self._events:
            if evt.mitre_id:
                tactic = mitre_map.get(evt.mitre_id, "Other")
                grouped[tactic].append(evt.to_dict())

        narrative = []
        for tactic in tactic_order:
            if tactic in grouped:
                narrative.append({
                    "stage": tactic,
                    "event_count": len(grouped[tactic]),
                    "events": grouped[tactic][:5],  # top 5 per stage
                })
        return narrative

    def summary(self) -> dict:
        severities = defaultdict(int)
        sources = defaultdict(int)
        mitre_ids = set()
        for e in self._events:
            severities[e.severity] += 1
            sources[e.source] += 1
            if e.mitre_id:
                mitre_ids.add(e.mitre_id)

        start = self._events[0].timestamp if self._events else None
        end = self._events[-1].timestamp if self._events else None

        return {
            "timeline_id": self.timeline_id,
            "entity": self.entity,
            "description": self.description,
            "created_at": self.created_at,
            "event_count": len(self._events),
            "first_event": start,
            "last_event": end,
            "severity_breakdown": dict(severities),
            "source_breakdown": dict(sources),
            "mitre_ids": list(mitre_ids),
            "process_nodes": len(self._process_nodes),
        }

    def to_dict(self) -> dict:
        return {
            **self.summary(),
            "events": self.get_events(),
            "process_tree": self.get_process_tree(),
            "attack_narrative": self.get_attack_narrative(),
        }


class ForensicsManager:
    """Manages multiple forensic timelines."""

    def __init__(self):
        self._timelines: Dict[str, ForensicTimeline] = {}
        self._tl_counter = 0

    def create_timeline(self, entity: str = "unknown",
                        description: str = "") -> ForensicTimeline:
        self._tl_counter += 1
        tid = f"TL-{self._tl_counter:04d}"
        tl = ForensicTimeline(tid, entity, description)
        self._timelines[tid] = tl
        return tl

    def create_from_chain(self, chain: dict, all_alerts: List[dict]) -> ForensicTimeline:
        """Auto-build a timeline from an attack chain."""
        src_ip = chain.get("src_ip", "unknown")
        tl = self.create_timeline(src_ip, f"Attack chain timeline for {src_ip}")
        chain_alert_ids = set(chain.get("alert_ids", []))
        for alert in all_alerts:
            if alert.get("src_ip") == src_ip or alert.get("id") in chain_alert_ids:
                tl.add_from_alert(alert)
        return tl

    def ingest_host_event(self, event: dict):
        """Route a host event to the correct timeline (create if needed)."""
        entity = event.get("agent_id") or event.get("src_ip", "unknown")
        # Find or create timeline for entity
        tl = next((t for t in self._timelines.values() if t.entity == entity), None)
        if tl is None:
            tl = self.create_timeline(entity, f"Auto-timeline for {entity}")
        if "pid" in event:
            tl.add_process_event(event)
        else:
            tl.add_event(TimelineEvent(
                event_id=str(id(event)),
                timestamp=event.get("timestamp", datetime.utcnow().isoformat()),
                event_type=event.get("type", "HOST_EVENT"),
                source=event.get("source", "hids"),
                entity=entity,
                detail=event.get("detail", ""),
                raw=event,
            ))

    def get(self, timeline_id: str) -> Optional[ForensicTimeline]:
        return self._timelines.get(timeline_id)

    def list(self) -> List[dict]:
        return [tl.summary() for tl in self._timelines.values()]

    @property
    def stats(self) -> dict:
        return {
            "total_timelines": len(self._timelines),
            "total_events": sum(len(tl._events) for tl in self._timelines.values()),
        }
