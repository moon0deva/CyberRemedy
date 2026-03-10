"""
CyberRemedy MITRE ATT&CK Mapper
Maps alert detections to MITRE ATT&CK techniques and tactics.
Fully offline using local techniques.json database.
"""

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cyberremedy.mitre")

_DB_PATH = Path(__file__).parent / "techniques.json"


class MitreMapper:
    """
    Enriches alerts with full MITRE ATT&CK context from local DB.
    """

    def __init__(self, db_path: str = None):
        path = Path(db_path) if db_path else _DB_PATH
        self._db = {}
        self._load(path)

    def _load(self, path: Path):
        try:
            with open(path, "r") as f:
                self._db = json.load(f)
            logger.info(f"MITRE DB loaded: {len(self._db)} techniques from {path}")
        except FileNotFoundError:
            logger.warning(f"MITRE DB not found at {path} — using empty DB")
        except json.JSONDecodeError as e:
            logger.error(f"MITRE DB parse error: {e}")

    def enrich(self, alert: dict) -> dict:
        """
        Add full MITRE context to an alert dict.
        Adds: mitre_name, mitre_tactic, mitre_description, mitre_mitigations
        """
        mitre_id = alert.get("mitre_id", "")
        tech = self._db.get(mitre_id)

        if tech:
            alert["mitre_name"] = tech.get("name", "Unknown")
            alert["mitre_tactic"] = tech.get("tactic", "Unknown")
            alert["mitre_tactic_id"] = tech.get("tactic_id", "")
            alert["mitre_description"] = tech.get("description", "")
            alert["mitre_indicators"] = tech.get("indicators", [])
            alert["mitre_mitigations"] = tech.get("mitigations", [])
        else:
            alert["mitre_name"] = "Unknown Technique"
            alert["mitre_tactic"] = "Unknown"
            alert["mitre_tactic_id"] = ""
            alert["mitre_description"] = ""
            alert["mitre_indicators"] = []
            alert["mitre_mitigations"] = []

        return alert

    def get_technique(self, technique_id: str) -> Optional[dict]:
        return self._db.get(technique_id)

    def get_all_techniques(self) -> dict:
        return self._db.copy()

    def get_coverage_summary(self, alerts: list) -> dict:
        """Summarize MITRE technique coverage across a list of alerts."""
        techniques_hit = {}
        for alert in alerts:
            mid = alert.get("mitre_id", "")
            if mid and mid in self._db:
                tech = self._db[mid]
                if mid not in techniques_hit:
                    techniques_hit[mid] = {
                        "id": mid,
                        "name": tech["name"],
                        "tactic": tech["tactic"],
                        "count": 0,
                    }
                techniques_hit[mid]["count"] += 1

        tactics_coverage = {}
        for t in techniques_hit.values():
            tactic = t["tactic"]
            if tactic not in tactics_coverage:
                tactics_coverage[tactic] = 0
            tactics_coverage[tactic] += t["count"]

        return {
            "techniques_detected": len(techniques_hit),
            "total_techniques_in_db": len(self._db),
            "techniques": list(techniques_hit.values()),
            "tactics_coverage": tactics_coverage,
        }
