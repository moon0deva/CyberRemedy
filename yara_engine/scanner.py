"""
CyberRemedy YARA Engine — File & Memory Scanning
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

logger = logging.getLogger("cyberremedy.yara")

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

rule SuspiciousBase64Decode {
    meta:
        description = "Detects base64 decode patterns used in droppers"
        severity = "HIGH"
        mitre = "T1027"
    strings:
        $b64_linux = "base64 -d" ascii nocase
        $b64_win   = "FromBase64String" ascii nocase
        $b64_py    = "b64decode" ascii nocase
    condition:
        any of them
}

rule C2BeaconingPattern {
    meta:
        description = "Detects HTTP C2 beacon patterns"
        severity = "HIGH"
        mitre = "T1071"
    strings:
        $ua1 = "Mozilla/5.0 (compatible;" ascii nocase
        $pwr = "powershell" ascii nocase
        $cmd = "cmd.exe /c" ascii nocase
    condition:
        any of them
}
''',
}
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


    def _load_builtin_rules(self):
        """Load built-in YARA rules from data/yara_rules/builtin.yar"""
        from pathlib import Path as _Path
        builtin = _Path(__file__).parent.parent / "data" / "yara_rules" / "builtin.yar"
        if not builtin.exists():
            return
        try:
            import yara as _yara
            compiled = _yara.compile(str(builtin))
            self._compiled_rules["builtin"] = compiled
            # Count rules
            count = len(open(str(builtin)).read().split("rule ")) - 1
            self._rule_meta["builtin"] = {"name": "builtin", "count": count, "source": "builtin"}
            logger.info(f"YARA: loaded {count} built-in rules from {builtin.name}")
        except ImportError:
            # yara-python not installed — store rules as text for display
            text = _Path(str(builtin)).read_text()
            rule_names = [l.split()[1] for l in text.split("\n") if l.startswith("rule ")]
            for name in rule_names:
                self._rule_meta[name] = {"name": name, "source": "builtin", "severity": "HIGH", "mitre_id": ""}
            logger.info(f"YARA: registered {len(rule_names)} built-in rules (yara-python not installed)")
        except Exception as e:
            logger.warning(f"YARA builtin load error: {e}")
