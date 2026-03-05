"""
AID-ARS Vulnerability Management
Collects software inventory from agents, correlates with NVD CVE DB.
"""

import json
import logging
import re
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("aidars.vuln")

VULN_DB_PATH = Path("data/vuln_db.json")
INVENTORY_PATH = Path("data/software_inventory.json")

# ─── CVE RECORD ───────────────────────────────────────────────────────────────

class CVERecord:
    def __init__(self, cve_id: str, description: str, cvss_score: float,
                 cvss_vector: str = "", severity: str = "MEDIUM",
                 affected_software: list = None, remediation: str = ""):
        self.cve_id = cve_id
        self.description = description
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.severity = severity
        self.affected_software = affected_software or []
        self.remediation = remediation
        self.published = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id, "description": self.description,
            "cvss_score": self.cvss_score, "cvss_vector": self.cvss_vector,
            "severity": self.severity, "affected_software": self.affected_software,
            "remediation": self.remediation, "published": self.published,
        }

    @staticmethod
    def severity_from_cvss(score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"


# ─── BUILT-IN CVE ENTRIES (demo dataset) ─────────────────────────────────────

BUILTIN_CVES = [
    CVERecord("CVE-2021-44228", "Apache Log4Shell — remote code execution via JNDI",
              10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CRITICAL",
              ["log4j-core 2.0-2.14.1", "log4j2"], "Upgrade to log4j >= 2.17.1"),
    CVERecord("CVE-2021-45046", "Apache Log4j2 incomplete fix for Log4Shell",
              9.0, "", "CRITICAL",
              ["log4j-core 2.15.0"], "Upgrade to log4j >= 2.17.1"),
    CVERecord("CVE-2022-0847", "Linux Dirty Pipe privilege escalation",
              7.8, "", "HIGH",
              ["Linux kernel 5.8-5.16.11"], "Update kernel to >= 5.16.11"),
    CVERecord("CVE-2021-3156", "sudo Heap Overflow — local privilege escalation",
              7.8, "", "HIGH",
              ["sudo 1.8.2-1.8.31p2", "sudo 1.9.0-1.9.5p1"], "Update sudo >= 1.9.5p2"),
    CVERecord("CVE-2022-1292", "OpenSSL c_rehash script injection",
              9.8, "", "CRITICAL",
              ["openssl 1.0.2", "openssl 1.1.1"], "Upgrade OpenSSL >= 1.1.1o or 3.0.3"),
    CVERecord("CVE-2022-2068", "OpenSSL c_rehash script injection additional",
              9.8, "", "CRITICAL",
              ["openssl 1.0.2", "openssl 1.1.1", "openssl 3.0"], "Upgrade OpenSSL"),
    CVERecord("CVE-2023-44487", "HTTP/2 Rapid Reset DDoS attack",
              7.5, "", "HIGH",
              ["nginx < 1.25.3", "apache httpd < 2.4.58"],
              "Update web server, enable HTTP/2 rate limiting"),
    CVERecord("CVE-2023-46604", "Apache ActiveMQ RCE (ExceptionResponse)",
              10.0, "", "CRITICAL",
              ["activemq 5.15.x", "activemq 5.16.x < 5.16.6"],
              "Upgrade to ActiveMQ >= 5.15.16 / 5.16.7 / 5.17.6"),
    CVERecord("CVE-2024-3094", "XZ Utils backdoor (supply chain attack)",
              10.0, "", "CRITICAL",
              ["xz-utils 5.6.0", "xz-utils 5.6.1"],
              "Downgrade xz-utils to <= 5.4.x immediately"),
]


# ─── SOFTWARE INVENTORY ───────────────────────────────────────────────────────

class SoftwareInventory:
    def __init__(self):
        self.INVENTORY_PATH = INVENTORY_PATH
        self._inventory: Dict[str, List[dict]] = {}  # agent_id -> [packages]
        self._load()

    def _load(self):
        if self.INVENTORY_PATH.exists():
            try:
                self._inventory = json.loads(self.INVENTORY_PATH.read_text())
            except Exception:
                self._inventory = {}

    def _save(self):
        self.INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.INVENTORY_PATH.write_text(json.dumps(self._inventory, indent=2))

    def update_from_agent(self, agent_id: str, packages: List[dict]):
        """Update software list from agent report."""
        self._inventory[agent_id] = packages
        self._save()

    def get_all_packages(self) -> List[dict]:
        """Return all packages across all agents with deduplication."""
        seen = set()
        all_pkgs = []
        for agent_id, packages in self._inventory.items():
            for pkg in packages:
                key = f"{pkg.get('name')}:{pkg.get('version')}"
                if key not in seen:
                    seen.add(key)
                    pkg["agents"] = [agent_id]
                    all_pkgs.append(pkg)
                else:
                    # Add agent to existing entry
                    for p in all_pkgs:
                        if f"{p['name']}:{p['version']}" == key:
                            if agent_id not in p.get("agents", []):
                                p.setdefault("agents", []).append(agent_id)
        return all_pkgs


# ─── VULN MANAGER ─────────────────────────────────────────────────────────────

class VulnManager:
    """
    Matches software inventory against CVE database.
    Generates vulnerability findings with CVSS scores and remediation.
    """

    def __init__(self, config: dict = None):
        self._cves: List[CVERecord] = list(BUILTIN_CVES)
        self.inventory = SoftwareInventory()
        self._findings: List[dict] = []
        self._load_findings()

    def _load_findings(self):
        if VULN_DB_PATH.exists():
            try:
                self._findings = json.loads(VULN_DB_PATH.read_text())
            except Exception:
                self._findings = []

    def _save_findings(self):
        VULN_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        VULN_DB_PATH.write_text(json.dumps(self._findings, indent=2))

    def scan_packages(self, packages: List[dict], agent_id: str = "unknown") -> List[dict]:
        """
        Match a list of {name, version} dicts against the CVE database.
        Returns list of vulnerability findings.
        """
        findings = []
        for cve in self._cves:
            for affected in cve.affected_software:
                for pkg in packages:
                    pkg_str = f"{pkg.get('name', '')} {pkg.get('version', '')}".lower()
                    if any(part.lower() in pkg_str for part in affected.lower().split()):
                        finding = {
                            "cve_id": cve.cve_id,
                            "description": cve.description,
                            "cvss_score": cve.cvss_score,
                            "severity": cve.severity,
                            "package": pkg.get("name"),
                            "version": pkg.get("version"),
                            "affected_pattern": affected,
                            "remediation": cve.remediation,
                            "agent_id": agent_id,
                            "detected_at": datetime.utcnow().isoformat(),
                            "status": "OPEN",
                        }
                        findings.append(finding)
                        self._findings.append(finding)

        if findings:
            self._save_findings()
        return findings

    def update_from_agent(self, agent_id: str, packages: List[dict]) -> List[dict]:
        """Process a package list from an agent and return vulnerability findings."""
        self.inventory.update_from_agent(agent_id, packages)
        return self.scan_packages(packages, agent_id)

    def get_findings(self, severity: str = None, limit: int = 100) -> List[dict]:
        findings = list(reversed(self._findings[-200:]))
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        return findings[:limit]

    def get_cves(self) -> List[dict]:
        return [c.to_dict() for c in self._cves]

    def stats(self) -> dict:
        findings = self._findings
        return {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "open": sum(1 for f in findings if f.get("status") == "OPEN"),
            "cve_db_size": len(self._cves),
            "agents_scanned": len(self.inventory._inventory),
        }
