"""
AID-ARS Compliance Checker
Maps detection coverage and system configuration to compliance frameworks.
Supports: PCI DSS 4.0, HIPAA Security Rule, NIST 800-53 Rev 5, CIS Controls v8.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("aidars.compliance")

COMPLIANCE_REPORT_PATH = Path("data/compliance_reports.json")

# ─── COMPLIANCE FRAMEWORKS ────────────────────────────────────────────────────

FRAMEWORKS = {
    "PCI_DSS_4": {
        "name": "PCI DSS 4.0",
        "controls": [
            {"id": "1.1", "title": "Network security controls installed", "mitre_ids": ["T1046", "T1595"],
             "check_fn": "check_network_monitoring", "weight": 3},
            {"id": "1.3", "title": "Restrict inbound/outbound traffic", "mitre_ids": ["T1071", "T1048"],
             "check_fn": "check_firewall_rules", "weight": 3},
            {"id": "2.2", "title": "System components configured securely", "mitre_ids": [],
             "check_fn": "check_secure_config", "weight": 2},
            {"id": "6.3", "title": "Security vulnerabilities identified and addressed", "mitre_ids": [],
             "check_fn": "check_vuln_management", "weight": 3},
            {"id": "8.2", "title": "User IDs managed for all users", "mitre_ids": ["T1078", "T1110"],
             "check_fn": "check_auth_monitoring", "weight": 2},
            {"id": "10.1", "title": "All access to cardholder data is logged", "mitre_ids": [],
             "check_fn": "check_logging", "weight": 3},
            {"id": "10.4", "title": "Security events reviewed daily", "mitre_ids": [],
             "check_fn": "check_alert_review", "weight": 2},
            {"id": "10.7", "title": "Failures detected and reported promptly", "mitre_ids": [],
             "check_fn": "check_soc_response", "weight": 2},
            {"id": "11.4", "title": "Intrusion detection techniques in use", "mitre_ids": [],
             "check_fn": "check_ids_active", "weight": 3},
            {"id": "12.3", "title": "Targeted risk analysis performed", "mitre_ids": [],
             "check_fn": "check_risk_scoring", "weight": 2},
        ],
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "controls": [
            {"id": "164.312(a)(1)", "title": "Access Control — unique user identification",
             "mitre_ids": ["T1078"], "check_fn": "check_auth_monitoring", "weight": 3},
            {"id": "164.312(b)", "title": "Audit Controls — system activity reviews",
             "mitre_ids": [], "check_fn": "check_logging", "weight": 3},
            {"id": "164.312(c)(1)", "title": "Integrity — data not improperly altered",
             "mitre_ids": ["T1565"], "check_fn": "check_fim", "weight": 2},
            {"id": "164.312(e)(1)", "title": "Transmission Security", "mitre_ids": ["T1071"],
             "check_fn": "check_network_monitoring", "weight": 2},
            {"id": "164.308(a)(5)", "title": "Security Awareness and Training",
             "mitre_ids": [], "check_fn": "check_detection_coverage", "weight": 1},
            {"id": "164.308(a)(1)", "title": "Security Management Process — risk analysis",
             "mitre_ids": [], "check_fn": "check_risk_scoring", "weight": 3},
        ],
    },
    "NIST_800_53": {
        "name": "NIST 800-53 Rev 5",
        "controls": [
            {"id": "AU-2", "title": "Event Logging", "mitre_ids": [],
             "check_fn": "check_logging", "weight": 3},
            {"id": "AU-3", "title": "Content of Audit Records", "mitre_ids": [],
             "check_fn": "check_logging", "weight": 2},
            {"id": "AU-12", "title": "Audit Record Generation", "mitre_ids": [],
             "check_fn": "check_logging", "weight": 2},
            {"id": "CA-7", "title": "Continuous Monitoring", "mitre_ids": [],
             "check_fn": "check_ids_active", "weight": 3},
            {"id": "IA-5", "title": "Authenticator Management", "mitre_ids": ["T1110"],
             "check_fn": "check_auth_monitoring", "weight": 2},
            {"id": "IR-4", "title": "Incident Handling", "mitre_ids": [],
             "check_fn": "check_case_management", "weight": 3},
            {"id": "IR-5", "title": "Incident Monitoring", "mitre_ids": [],
             "check_fn": "check_soc_response", "weight": 2},
            {"id": "RA-3", "title": "Risk Assessment", "mitre_ids": [],
             "check_fn": "check_risk_scoring", "weight": 2},
            {"id": "RA-5", "title": "Vulnerability Monitoring and Scanning", "mitre_ids": [],
             "check_fn": "check_vuln_management", "weight": 3},
            {"id": "SC-7", "title": "Boundary Protection", "mitre_ids": ["T1046"],
             "check_fn": "check_network_monitoring", "weight": 3},
            {"id": "SI-3", "title": "Malicious Code Protection", "mitre_ids": [],
             "check_fn": "check_yara_active", "weight": 2},
            {"id": "SI-4", "title": "System Monitoring", "mitre_ids": [],
             "check_fn": "check_ids_active", "weight": 3},
        ],
    },
    "CIS_V8": {
        "name": "CIS Controls v8",
        "controls": [
            {"id": "CIS-1", "title": "Inventory and Control of Enterprise Assets",
             "mitre_ids": [], "check_fn": "check_agent_inventory", "weight": 2},
            {"id": "CIS-2", "title": "Inventory and Control of Software Assets",
             "mitre_ids": [], "check_fn": "check_vuln_management", "weight": 2},
            {"id": "CIS-6", "title": "Access Control Management", "mitre_ids": ["T1078"],
             "check_fn": "check_auth_monitoring", "weight": 3},
            {"id": "CIS-8", "title": "Audit Log Management", "mitre_ids": [],
             "check_fn": "check_logging", "weight": 3},
            {"id": "CIS-10", "title": "Malware Defenses", "mitre_ids": [],
             "check_fn": "check_yara_active", "weight": 3},
            {"id": "CIS-12", "title": "Network Infrastructure Management",
             "mitre_ids": ["T1046"], "check_fn": "check_network_monitoring", "weight": 2},
            {"id": "CIS-13", "title": "Network Monitoring and Defense",
             "mitre_ids": [], "check_fn": "check_ids_active", "weight": 3},
            {"id": "CIS-17", "title": "Incident Response Management",
             "mitre_ids": [], "check_fn": "check_case_management", "weight": 3},
        ],
    },
}


# ─── CHECK FUNCTIONS ──────────────────────────────────────────────────────────

def _check(system_state: dict, check_fn: str) -> tuple[bool, str]:
    """Run a named check against system state. Returns (pass, detail)."""
    alerts_total = system_state.get("alerts_total", 0)
    modules = system_state.get("modules_active", [])
    agents = system_state.get("agents_registered", 0)
    cases_total = system_state.get("cases_total", 0)
    vuln_scanned = system_state.get("vuln_agents_scanned", 0)

    checks = {
        "check_network_monitoring": (
            "network_ids" in modules,
            "Network IDS active" if "network_ids" in modules else "No network IDS active"
        ),
        "check_firewall_rules": (
            "auto_response" in modules,
            "Auto-response firewall rules active" if "auto_response" in modules else "No automated firewall control"
        ),
        "check_logging": (
            alerts_total > 0 or "logging" in modules,
            f"{alerts_total} events logged" if alerts_total > 0 else "No event logging detected"
        ),
        "check_auth_monitoring": (
            agents > 0 or "hids" in modules,
            f"HIDS monitoring {agents} agents" if agents > 0 else "No endpoint auth monitoring"
        ),
        "check_ids_active": (
            "network_ids" in modules or "signature_detection" in modules,
            "IDS active" if ("network_ids" in modules or "signature_detection" in modules) else "IDS not active"
        ),
        "check_risk_scoring": (
            "risk_scoring" in modules,
            "Risk scoring engine active" if "risk_scoring" in modules else "No automated risk scoring"
        ),
        "check_case_management": (
            cases_total > 0 or "cases" in modules,
            f"{cases_total} cases tracked" if cases_total > 0 else "No case management"
        ),
        "check_soc_response": (
            "soar" in modules or "auto_response" in modules,
            "SOAR/auto-response active" if ("soar" in modules or "auto_response" in modules) else "No automated response"
        ),
        "check_fim": (
            "fim" in modules or "hids" in modules,
            "FIM monitoring active" if ("fim" in modules or "hids" in modules) else "No FIM monitoring"
        ),
        "check_vuln_management": (
            vuln_scanned > 0 or "vuln_mgmt" in modules,
            f"Vuln scanning on {vuln_scanned} agents" if vuln_scanned > 0 else "No vulnerability management"
        ),
        "check_detection_coverage": (
            "mitre_mapping" in modules and alerts_total > 0,
            "MITRE coverage tracked" if "mitre_mapping" in modules else "No MITRE coverage tracking"
        ),
        "check_yara_active": (
            "yara" in modules,
            "YARA scanning active" if "yara" in modules else "YARA not configured"
        ),
        "check_secure_config": (
            "sca" in modules,
            "SCA checks running" if "sca" in modules else "No hardening checks configured"
        ),
        "check_alert_review": (
            "dashboard" in modules,
            "Dashboard active for alert review" if "dashboard" in modules else "No alert review interface"
        ),
        "check_agent_inventory": (
            agents > 0,
            f"{agents} agents registered" if agents > 0 else "No agent inventory"
        ),
    }
    return checks.get(check_fn, (False, f"Check '{check_fn}' not implemented"))


# ─── COMPLIANCE ENGINE ────────────────────────────────────────────────────────

class ComplianceChecker:
    def __init__(self):
        self._reports: List[dict] = []

    def run_assessment(self, system_state: dict, framework_id: str) -> dict:
        """Run a compliance assessment for a given framework."""
        framework = FRAMEWORKS.get(framework_id)
        if not framework:
            return {"error": f"Unknown framework: {framework_id}"}

        controls = framework["controls"]
        results = []
        total_weight = 0
        passed_weight = 0

        for ctrl in controls:
            passed, detail = _check(system_state, ctrl["check_fn"])
            weight = ctrl.get("weight", 1)
            total_weight += weight
            if passed:
                passed_weight += weight

            results.append({
                "control_id": ctrl["id"],
                "title": ctrl["title"],
                "passed": passed,
                "detail": detail,
                "weight": weight,
                "mitre_ids": ctrl.get("mitre_ids", []),
            })

        score = round((passed_weight / max(total_weight, 1)) * 100, 1)
        status = "COMPLIANT" if score >= 85 else ("PARTIAL" if score >= 50 else "NON_COMPLIANT")

        report = {
            "framework_id": framework_id,
            "framework_name": framework["name"],
            "assessed_at": datetime.utcnow().isoformat(),
            "score": score,
            "status": status,
            "total_controls": len(controls),
            "passed_controls": sum(1 for r in results if r["passed"]),
            "failed_controls": sum(1 for r in results if not r["passed"]),
            "controls": results,
            "gaps": [r for r in results if not r["passed"]],
        }
        self._reports.append(report)

        # Persist
        COMPLIANCE_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        COMPLIANCE_REPORT_PATH.write_text(json.dumps(self._reports[-20:], indent=2))
        return report

    def run_all(self, system_state: dict) -> dict:
        """Run all frameworks and return aggregated results."""
        all_results = {}
        for fid in FRAMEWORKS:
            all_results[fid] = self.run_assessment(system_state, fid)
        return all_results

    def get_reports(self, limit: int = 20) -> List[dict]:
        return list(reversed(self._reports[-limit:]))

    @staticmethod
    def list_frameworks() -> List[dict]:
        return [{"id": fid, "name": fw["name"], "controls": len(fw["controls"])}
                for fid, fw in FRAMEWORKS.items()]
