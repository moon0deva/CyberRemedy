"""
CyberRemedy Case Management System
Inspired by Security Onion Cases + Elastic Security Cases.
Full lifecycle: Open → Investigating → Pending Review → Closed
Features: alert attachment, analyst assignment, comments, evidence, SLA tracking.
"""

import json
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cyberremedy.cases")

CASES_DB_PATH = Path("data/cases.json")


# ─── ENUMS ────────────────────────────────────────────────────────────────────

class CaseStatus:
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    PENDING_REVIEW = "PENDING_REVIEW"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class CaseSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ─── COMMENT ──────────────────────────────────────────────────────────────────

class CaseComment:
    def __init__(self, text: str, author: str = "analyst", comment_type: str = "note"):
        self.id = str(uuid.uuid4())[:8]
        self.text = text
        self.author = author
        self.type = comment_type  # note | action | escalation | resolution
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "text": self.text,
            "author": self.author,
            "type": self.type,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "CaseComment":
        c = CaseComment(d["text"], d.get("author", "analyst"), d.get("type", "note"))
        c.id = d.get("id", c.id)
        c.created_at = d.get("created_at", c.created_at)
        return c


# ─── EVIDENCE ITEM ────────────────────────────────────────────────────────────

class EvidenceItem:
    def __init__(self, name: str, evidence_type: str, content: str, added_by: str = "system"):
        self.id = str(uuid.uuid4())[:8]
        self.name = name
        self.type = evidence_type   # pcap_ref | log_extract | ioc | screenshot | file_hash
        self.content = content
        self.added_by = added_by
        self.added_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "type": self.type,
                "content": self.content, "added_by": self.added_by, "added_at": self.added_at}

    @staticmethod
    def from_dict(d: dict) -> "EvidenceItem":
        e = EvidenceItem(d["name"], d["type"], d["content"], d.get("added_by", "system"))
        e.id = d.get("id", e.id)
        e.added_at = d.get("added_at", e.added_at)
        return e


# ─── CASE ─────────────────────────────────────────────────────────────────────

class Case:
    def __init__(self, title: str, description: str = "",
                 severity: str = CaseSeverity.MEDIUM,
                 created_by: str = "system",
                 sla_hours: int = 24):
        self.id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
        self.title = title
        self.description = description
        self.severity = severity
        self.status = CaseStatus.OPEN
        self.created_by = created_by
        self.assigned_to: Optional[str] = None
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        self.closed_at: Optional[str] = None

        # SLA tracking
        self.sla_deadline = (datetime.utcnow() + timedelta(hours=sla_hours)).isoformat()
        self.sla_breached = False

        # Linked artifacts
        self.alert_ids: List[int] = []
        self.iocs: List[str] = []
        self.comments: List[CaseComment] = []
        self.evidence: List[EvidenceItem] = []
        self.mitre_ids: List[str] = []
        self.tags: List[str] = []

        # Metrics
        self.escalation_count = 0
        self.time_to_detect_s: Optional[float] = None
        self.time_to_respond_s: Optional[float] = None

    def add_comment(self, text: str, author: str = "analyst",
                    comment_type: str = "note") -> CaseComment:
        c = CaseComment(text, author, comment_type)
        self.comments.append(c)
        self._touch()
        return c

    def add_evidence(self, name: str, evidence_type: str, content: str,
                     added_by: str = "analyst") -> EvidenceItem:
        e = EvidenceItem(name, evidence_type, content, added_by)
        self.evidence.append(e)
        self._touch()
        return e

    def attach_alert(self, alert_id: int):
        if alert_id not in self.alert_ids:
            self.alert_ids.append(alert_id)
        self._touch()

    def transition(self, new_status: str, comment: str = None, author: str = "analyst"):
        old = self.status
        self.status = new_status
        if new_status in (CaseStatus.CLOSED, CaseStatus.RESOLVED, CaseStatus.FALSE_POSITIVE):
            self.closed_at = datetime.utcnow().isoformat()
            self.time_to_respond_s = (
                datetime.fromisoformat(self.closed_at) -
                datetime.fromisoformat(self.created_at)
            ).total_seconds()
        if comment:
            self.add_comment(f"[Status: {old} → {new_status}] {comment}", author, "action")
        self._touch()

    def check_sla(self):
        if self.status not in (CaseStatus.CLOSED, CaseStatus.RESOLVED):
            if datetime.utcnow() > datetime.fromisoformat(self.sla_deadline):
                self.sla_breached = True

    def assign(self, analyst: str, comment: str = None):
        self.assigned_to = analyst
        if comment:
            self.add_comment(f"Assigned to {analyst}. {comment}", "system", "action")
        self._touch()

    def escalate(self, comment: str, author: str = "analyst"):
        self.escalation_count += 1
        self.add_comment(f"[ESCALATION #{self.escalation_count}] {comment}", author, "escalation")
        if self.severity == CaseSeverity.MEDIUM:
            self.severity = CaseSeverity.HIGH
        elif self.severity == CaseSeverity.HIGH:
            self.severity = CaseSeverity.CRITICAL
        self._touch()

    def _touch(self):
        self.updated_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        self.check_sla()
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "created_by": self.created_by,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "sla_deadline": self.sla_deadline,
            "sla_breached": self.sla_breached,
            "alert_ids": self.alert_ids,
            "iocs": self.iocs,
            "mitre_ids": self.mitre_ids,
            "tags": self.tags,
            "comments": [c.to_dict() for c in self.comments],
            "evidence": [e.to_dict() for e in self.evidence],
            "escalation_count": self.escalation_count,
            "time_to_respond_s": self.time_to_respond_s,
            "comment_count": len(self.comments),
            "evidence_count": len(self.evidence),
        }

    @staticmethod
    def from_dict(d: dict) -> "Case":
        c = Case(d["title"], d.get("description", ""), d.get("severity", "MEDIUM"),
                 d.get("created_by", "system"))
        c.id = d["id"]
        c.status = d.get("status", CaseStatus.OPEN)
        c.assigned_to = d.get("assigned_to")
        c.created_at = d.get("created_at", c.created_at)
        c.updated_at = d.get("updated_at", c.updated_at)
        c.closed_at = d.get("closed_at")
        c.sla_deadline = d.get("sla_deadline", c.sla_deadline)
        c.sla_breached = d.get("sla_breached", False)
        c.alert_ids = d.get("alert_ids", [])
        c.iocs = d.get("iocs", [])
        c.mitre_ids = d.get("mitre_ids", [])
        c.tags = d.get("tags", [])
        c.comments = [CaseComment.from_dict(x) for x in d.get("comments", [])]
        c.evidence = [EvidenceItem.from_dict(x) for x in d.get("evidence", [])]
        c.escalation_count = d.get("escalation_count", 0)
        c.time_to_respond_s = d.get("time_to_respond_s")
        return c


# ─── CASE MANAGER ─────────────────────────────────────────────────────────────

class CaseManager:
    """Central case store with full CRUD and analytics."""

    def __init__(self, db_path: Path = CASES_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._cases: Dict[str, Case] = {}
        self._load()

    def _load(self):
        if self.db_path.exists():
            try:
                data = json.loads(self.db_path.read_text())
                for d in data:
                    c = Case.from_dict(d)
                    self._cases[c.id] = c
                logger.info(f"Cases loaded: {len(self._cases)}")
            except Exception as e:
                logger.warning(f"Case DB load error: {e}")

    def _save(self):
        data = [c.to_dict() for c in self._cases.values()]
        self.db_path.write_text(json.dumps(data, indent=2, default=str))

    def create_case(self, title: str, description: str = "",
                    severity: str = CaseSeverity.MEDIUM,
                    alert_ids: List[int] = None,
                    created_by: str = "system",
                    sla_hours: int = 24) -> Case:
        case = Case(title, description, severity, created_by, sla_hours)
        for aid in (alert_ids or []):
            case.attach_alert(aid)
        self._cases[case.id] = case
        self._save()
        logger.info(f"Case created: {case.id} — {title}")
        return case

    def create_from_alert(self, alert: dict) -> Case:
        """Auto-create a case from a CRITICAL/HIGH alert."""
        title = f"[{alert.get('severity')}] {alert.get('type', 'Security Alert')} — {alert.get('src_ip', '?')}"
        desc = (
            f"Auto-created from alert ID {alert.get('id')}.\n"
            f"Source: {alert.get('src_ip')} → {alert.get('dst_ip')}\n"
            f"MITRE: {alert.get('mitre_id', '')} — {alert.get('mitre_name', '')}\n"
            f"Detail: {alert.get('detail', '')}"
        )
        sev = alert.get("severity", CaseSeverity.MEDIUM)
        sla = 4 if sev == CaseSeverity.CRITICAL else 24
        case = self.create_case(title, desc, sev, [alert.get("id")], sla_hours=sla)
        case.mitre_ids = [alert.get("mitre_id", "")]
        if alert.get("src_ip"):
            case.iocs.append(alert["src_ip"])
        self._save()
        return case

    def get(self, case_id: str) -> Optional[Case]:
        return self._cases.get(case_id)

    def list(self, status: str = None, severity: str = None,
             assigned_to: str = None, limit: int = 50) -> List[dict]:
        cases = list(self._cases.values())
        if status:
            cases = [c for c in cases if c.status == status]
        if severity:
            cases = [c for c in cases if c.severity == severity]
        if assigned_to:
            cases = [c for c in cases if c.assigned_to == assigned_to]
        cases.sort(key=lambda c: c.updated_at, reverse=True)
        return [c.to_dict() for c in cases[:limit]]

    def add_comment(self, case_id: str, text: str, author: str = "analyst") -> Optional[dict]:
        case = self.get(case_id)
        if not case:
            return None
        c = case.add_comment(text, author)
        self._save()
        return c.to_dict()

    def add_evidence(self, case_id: str, name: str, evidence_type: str,
                     content: str, added_by: str = "analyst") -> Optional[dict]:
        case = self.get(case_id)
        if not case:
            return None
        e = case.add_evidence(name, evidence_type, content, added_by)
        self._save()
        return e.to_dict()

    def transition(self, case_id: str, new_status: str,
                   comment: str = None, author: str = "analyst") -> Optional[dict]:
        case = self.get(case_id)
        if not case:
            return None
        case.transition(new_status, comment, author)
        self._save()
        return case.to_dict()

    def assign(self, case_id: str, analyst: str) -> Optional[dict]:
        case = self.get(case_id)
        if not case:
            return None
        case.assign(analyst)
        self._save()
        return case.to_dict()

    def escalate(self, case_id: str, comment: str, author: str = "analyst") -> Optional[dict]:
        case = self.get(case_id)
        if not case:
            return None
        case.escalate(comment, author)
        self._save()
        return case.to_dict()

    def stats(self) -> dict:
        all_cases = list(self._cases.values())
        closed = [c for c in all_cases if c.closed_at]
        ttrs = [c.time_to_respond_s for c in closed if c.time_to_respond_s]
        return {
            "total": len(all_cases),
            "open": sum(1 for c in all_cases if c.status == CaseStatus.OPEN),
            "investigating": sum(1 for c in all_cases if c.status == CaseStatus.INVESTIGATING),
            "resolved": sum(1 for c in all_cases if c.status in (CaseStatus.RESOLVED, CaseStatus.CLOSED)),
            "sla_breached": sum(1 for c in all_cases if c.sla_breached),
            "avg_ttr_hours": round(sum(ttrs) / len(ttrs) / 3600, 1) if ttrs else None,
            "critical_open": sum(1 for c in all_cases if c.severity == CaseSeverity.CRITICAL
                                  and c.status not in (CaseStatus.CLOSED, CaseStatus.RESOLVED)),
        }
