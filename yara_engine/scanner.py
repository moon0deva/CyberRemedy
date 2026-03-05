"""
AID-ARS YARA Engine — File & Memory Scanning
Scans files, byte streams, and extracted network payloads against YARA rules.
Includes built-in ruleset for common malware families.
"""

import os
import re
import json
import logging
import hashlib
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

logger = logging.getLogger("aidars.yara")

RULES_DIR = Path("data/yara_rules")
RESULTS_PATH = Path("data/yara_results.json")

# ─── BUILT-IN YARA RULES (TEXT FORMAT) ───────────────────────────────────────

BUILTIN_RULES = {
    "malware_generic": '''
rule SuspiciousShellCommand {
    meta:
        description = "Detects common reverse shell command patterns"
        severity = "CRITICAL"
        mitre = "T1059"
    strings:
        $bash_tcp = "/dev/tcp/" ascii nocase
        $nc_exec = "nc -e /bin" ascii nocase
        $nc_exec2 = "nc.exe -e" ascii nocase
        $python_socket = "import socket" ascii
        $perl_socket = "use Socket" ascii
    condition:
        any of them
}

rule MimikatzIndicator {
    meta:
        description = "Detects Mimikatz credential harvester"
        severity = "CRITICAL"
        mitre = "T1003"
    strings:
        $str1 = "mimikatz" ascii nocase
        $str2 = "sekurlsa" ascii nocase
        $str3 = "lsadump" ascii nocase
        $str4 = "kerberos::list" ascii nocase
    condition:
        any of them
}

rule PowershellObfuscation {
    meta:
        description = "Detects PowerShell obfuscation techniques"
        severity = "HIGH"
        mitre = "T1027"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $invoke = "IEX(" ascii nocase
        $invoke2 = "Invoke-Expression" ascii nocase
        $download = "DownloadString" ascii nocase
        $webclient = "New-Object Net.WebClient" ascii nocase
    condition:
        2 of them
}

rule CobaltStrikeBeacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        severity = "CRITICAL"
        mitre = "T1071"
    strings:
        $cs1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
        $cs_str = "ReflectiveLoader" ascii
        $cs_pipe = "\\\\.\\pipe\\MSSE-" ascii
    condition:
        any of them
}

rule WebshellPHP {
    meta:
        description = "PHP webshell detection"
        severity = "CRITICAL"
        mitre = "T1505"
    strings:
        $eval = "eval(base64_decode" ascii nocase
        $system = "system($_" ascii nocase
        $passthru = "passthru($_" ascii nocase
        $shell_exec = "shell_exec($_" ascii nocase
    condition:
        any of them
}
''',
    "ransomware": '''
rule RansomwareFileActivity {
    meta:
        description = "Generic ransomware file extension patterns"
        severity = "CRITICAL"
        mitre = "T1486"
    strings:
        $ext1 = ".encrypted" ascii nocase
        $ext2 = ".locked" ascii nocase
        $ext3 = ".crypto" ascii nocase
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $note2 = "PAY RANSOM" ascii nocase
        $note3 = "bitcoin" ascii nocase
    condition:
        2 of them
}

rule WannaCryIndicator {
    meta:
        description = "WannaCry ransomware indicators"
        severity = "CRITICAL"
        mitre = "T1486"
    strings:
        $wc1 = "WannaDecryptor" ascii
        $wc2 = "@WanaDecryptor" ascii
        $wc3 = "WANACRY!" ascii
        $wc4 = "tasksche.exe" ascii nocase
    condition:
        any of them
}
''',
}

# ─── SIMPLE YARA PATTERN MATCHER (no yara-python dependency) ─────────────────

class SimpleYARARule:
    """Pure-Python YARA-like rule for when yara-python is not installed."""

    def __init__(self, rule_name: str, description: str, severity: str,
                 mitre: str, strings: dict, condition: str):
        self.rule_name = rule_name
        self.description = description
        self.severity = severity
        self.mitre = mitre
        self.strings = strings  # {var_name: (pattern, flags)}
        self.condition = condition  # "any of them" | "all of them" | "2 of them"

    def match(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="replace").lower()
        except Exception:
            text = ""

        hits = []
        for name, (pattern, flags) in self.strings.items():
            p = pattern.lower() if "nocase" in flags else pattern
            if isinstance(p, bytes):
                if p in data:
                    hits.append(name)
            elif p in text:
                hits.append(name)

        # Evaluate condition
        cond = self.condition.strip().lower()
        total = len(self.strings)
        hit_count = len(hits)

        if cond == "any of them":
            return hit_count > 0
        elif cond == "all of them":
            return hit_count == total
        else:
            # "N of them"
            m = re.match(r"(\d+) of them", cond)
            if m:
                required = int(m.group(1))
                return hit_count >= required
        return hit_count > 0


# ─── RULE PARSER ──────────────────────────────────────────────────────────────

def parse_builtin_rules() -> List[SimpleYARARule]:
    """Parse the built-in YARA rules text into SimpleYARARule objects."""
    rules = []
    for ruleset_name, ruleset_text in BUILTIN_RULES.items():
        rule_blocks = re.findall(
            r'rule\s+(\w+)\s*\{(.*?)\}', ruleset_text, re.DOTALL
        )
        for rule_name, block in rule_blocks:
            # Extract meta
            desc = re.search(r'description\s*=\s*"([^"]+)"', block)
            sev = re.search(r'severity\s*=\s*"([^"]+)"', block)
            mitre = re.search(r'mitre\s*=\s*"([^"]+)"', block)

            # Extract strings section
            strings_section = re.search(r'strings:(.*?)condition:', block, re.DOTALL)
            parsed_strings = {}
            if strings_section:
                for m in re.finditer(r'\$(\w+)\s*=\s*"([^"]+)"\s*([\w\s]*)', strings_section.group(1)):
                    var, pattern, flags = m.group(1), m.group(2), m.group(3).strip()
                    parsed_strings[var] = (pattern, flags)

            # Extract condition
            cond_section = re.search(r'condition:(.*?)$', block, re.DOTALL)
            condition = cond_section.group(1).strip() if cond_section else "any of them"

            if parsed_strings:
                rules.append(SimpleYARARule(
                    rule_name=rule_name,
                    description=desc.group(1) if desc else rule_name,
                    severity=sev.group(1) if sev else "HIGH",
                    mitre=mitre.group(1) if mitre else "T1059",
                    strings=parsed_strings,
                    condition=condition,
                ))
    return rules


# ─── YARA SCANNER ─────────────────────────────────────────────────────────────

class YARAScanner:
    """
    Primary YARA scanning interface.
    Tries to use native yara-python if installed, falls back to SimpleYARARule.
    """

    def __init__(self, rules_dir: Path = RULES_DIR):
        self.rules_dir = rules_dir
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._yara_available = False
        self._compiled = None
        self._simple_rules: List[SimpleYARARule] = []
        self._results: List[dict] = []
        self._scan_count = 0
        self._setup()

    def _setup(self):
        # Save built-in rules to files
        for name, content in BUILTIN_RULES.items():
            rule_file = self.rules_dir / f"{name}.yar"
            if not rule_file.exists():
                rule_file.write_text(content)

        # Try yara-python
        try:
            import yara
            rule_files = {
                p.stem: str(p) for p in self.rules_dir.glob("*.yar")
            }
            if rule_files:
                self._compiled = yara.compile(filepaths=rule_files)
                self._yara_available = True
                logger.info(f"YARA: native yara-python loaded {len(rule_files)} rulesets")
        except ImportError:
            logger.info("YARA: yara-python not installed — using built-in pattern matcher")
            self._simple_rules = parse_builtin_rules()
            logger.info(f"YARA: {len(self._simple_rules)} built-in rules loaded")
        except Exception as e:
            logger.warning(f"YARA compile error: {e} — using pattern matcher")
            self._simple_rules = parse_builtin_rules()

    def scan_bytes(self, data: bytes, source_name: str = "unknown") -> List[dict]:
        """Scan raw bytes. Returns list of match dicts."""
        self._scan_count += 1
        file_hash = hashlib.sha256(data).hexdigest()
        matches = []

        if self._yara_available and self._compiled:
            try:
                for match in self._compiled.match(data=data):
                    result = {
                        "rule": match.rule,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                        "severity": match.meta.get("severity", "HIGH"),
                        "mitre_id": match.meta.get("mitre", "T1059"),
                        "description": match.meta.get("description", match.rule),
                    }
                    matches.append(result)
            except Exception as e:
                logger.debug(f"YARA native scan error: {e}")
        else:
            for rule in self._simple_rules:
                if rule.match(data):
                    matches.append({
                        "rule": rule.rule_name,
                        "tags": [],
                        "meta": {"description": rule.description, "severity": rule.severity},
                        "severity": rule.severity,
                        "mitre_id": rule.mitre,
                        "description": rule.description,
                    })

        if matches:
            entry = {
                "source_name": source_name,
                "file_hash": file_hash,
                "file_size": len(data),
                "matches": matches,
                "match_count": len(matches),
                "scanned_at": datetime.utcnow().isoformat(),
                "severity": max(matches, key=lambda x: ["LOW","MEDIUM","HIGH","CRITICAL"].index(
                    x.get("severity","LOW")))["severity"],
            }
            self._results.append(entry)
            logger.warning(f"YARA: {len(matches)} matches in {source_name} ({file_hash[:8]})")
            return [entry]
        return []

    def scan_file(self, file_path: str) -> List[dict]:
        """Scan a file by path."""
        try:
            data = Path(file_path).read_bytes()
            return self.scan_bytes(data, source_name=file_path)
        except Exception as e:
            logger.error(f"YARA file scan error ({file_path}): {e}")
            return []

    def add_rule_file(self, rule_path: str) -> bool:
        """Load an additional YARA rule file."""
        try:
            shutil = __import__("shutil")
            dest = self.rules_dir / Path(rule_path).name
            shutil.copy(rule_path, dest)
            self._setup()  # Recompile
            return True
        except Exception as e:
            logger.error(f"Rule add error: {e}")
            return False

    def get_results(self, limit: int = 100) -> List[dict]:
        return list(reversed(self._results[-limit:]))

    @property
    def stats(self) -> dict:
        return {
            "engine": "native" if self._yara_available else "builtin_patterns",
            "rules_loaded": len(self._simple_rules) if not self._yara_available else "compiled",
            "files_scanned": self._scan_count,
            "total_hits": len(self._results),
        }
