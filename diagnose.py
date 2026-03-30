#!/usr/bin/env python3
"""
CyberRemedy v1.2 — Diagnostic & Self-Healing Script
Run this if the app fails to start or behaves unexpectedly.

Usage:
    python diagnose.py          # Check everything, fix what can be auto-fixed
    python diagnose.py --fix    # Auto-fix all fixable issues
    python diagnose.py --test   # Full import test (deeper check)
"""

import os, sys, re, json, subprocess, importlib, argparse
from pathlib import Path

ROOT = Path(__file__).parent

RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
NC     = "\033[0m"

def ok(msg):    print(f"  {GREEN}✅ {msg}{NC}")
def fail(msg):  print(f"  {RED}❌ {msg}{NC}")
def warn(msg):  print(f"  {YELLOW}⚠  {msg}{NC}")
def info(msg):  print(f"  {CYAN}ℹ  {msg}{NC}")
def section(s): print(f"\n{BOLD}{CYAN}── {s} {'─'*(50-len(s))}{NC}")

fixes_applied = []
issues_found  = []

# ─────────────────────────────────────────────────────────────────────
# 1. Python version
# ─────────────────────────────────────────────────────────────────────
def check_python():
    section("Python Version")
    v = sys.version_info
    if v >= (3, 9):
        ok(f"Python {v.major}.{v.minor}.{v.micro} — compatible")
    else:
        fail(f"Python {v.major}.{v.minor} detected — need 3.9+")
        issues_found.append("Python version too old (need 3.9+)")

# ─────────────────────────────────────────────────────────────────────
# 2. Required packages
# ─────────────────────────────────────────────────────────────────────
REQUIRED_PACKAGES = [
    ("fastapi",    "fastapi==0.111.0"),
    ("uvicorn",    "uvicorn[standard]==0.29.0"),
    ("pydantic",   "pydantic>=2.0"),
    ("yaml",       "pyyaml>=6.0"),
    ("sklearn",    "scikit-learn>=1.3"),
    ("numpy",      "numpy>=1.24"),
    ("joblib",     "joblib>=1.3"),
    ("jinja2",     "jinja2>=3.1"),
    ("aiofiles",   "aiofiles>=23.1"),
    ("psutil",     "psutil>=5.9"),
    ("websockets", "websockets>=12.0"),
    ("jwt",        "PyJWT>=2.8"),
    ("bcrypt",     "bcrypt>=4.0"),
    ("tinydb",     "tinydb>=4.8"),
    ("requests",   "requests>=2.28"),
]

OPTIONAL_PACKAGES = [
    ("scapy",      "scapy>=2.5",      "live packet capture (simulation fallback available)"),
    ("netifaces",  "netifaces>=0.11", "interface detection (auto-detect fallback available)"),
    ("pandas",     "pandas>=2.0",     "data export features"),
    ("ruamel.yaml","ruamel.yaml>=0.18","Sigma rule parsing"),
    ("pyarrow",    "pyarrow>=16.0",   "Parquet data lake format"),
    ("scipy",      "scipy>=1.13",     "advanced ML features"),
]

def check_packages(auto_fix=False):
    section("Required Packages")
    missing_required = []
    for mod, pkg in REQUIRED_PACKAGES:
        try:
            importlib.import_module(mod)
            ok(mod)
        except ImportError:
            fail(f"{mod} — NOT installed  (pip install {pkg})")
            missing_required.append(pkg)
            issues_found.append(f"Missing required package: {pkg}")

    if missing_required and auto_fix:
        print(f"\n  Auto-installing {len(missing_required)} missing packages...")
        for pkg in missing_required:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg,
                     "--quiet", "--break-system-packages"],
                    stderr=subprocess.DEVNULL
                )
                ok(f"Installed: {pkg}")
                fixes_applied.append(f"Installed {pkg}")
            except subprocess.CalledProcessError:
                try:
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                        stderr=subprocess.DEVNULL
                    )
                    ok(f"Installed: {pkg}")
                    fixes_applied.append(f"Installed {pkg}")
                except Exception as e:
                    fail(f"Could not install {pkg}: {e}")

    section("Optional Packages")
    for mod, pkg, desc in OPTIONAL_PACKAGES:
        try:
            importlib.import_module(mod.split(".")[0])
            ok(f"{mod} — available")
        except ImportError:
            warn(f"{mod} — not installed  ({desc})")
            info(f"   Fix: pip install {pkg}")

# ─────────────────────────────────────────────────────────────────────
# 3. Directory structure
# ─────────────────────────────────────────────────────────────────────
REQUIRED_DIRS = [
    "data", "data/logs", "data/logs/alerts", "data/logs/traffic",
    "data/logs/blocks", "data/logs/events", "data/logs/assets",
    "data/reports", "data/datasets", "data/yara_rules", "data/sigma_rules",
    "data/lake", "data/lake/hot", "data/lake/warm", "data/lake/cold",
    "data/pcap", "data/geoip", "data/assets", "models", "logs",
]

def check_dirs(auto_fix=False):
    section("Directory Structure")
    missing = []
    for d in REQUIRED_DIRS:
        p = ROOT / d
        if p.exists():
            ok(d)
        else:
            fail(f"{d} — MISSING")
            missing.append(d)
            issues_found.append(f"Missing directory: {d}")

    if missing and auto_fix:
        for d in missing:
            (ROOT / d).mkdir(parents=True, exist_ok=True)
            ok(f"Created: {d}")
            fixes_applied.append(f"Created directory: {d}")

# ─────────────────────────────────────────────────────────────────────
# 4. Critical files
# ─────────────────────────────────────────────────────────────────────
REQUIRED_FILES = [
    ("main.py",                      "Entry point"),
    ("api/server.py",                "FastAPI backend"),
    ("config/settings.yaml",         "Configuration"),
    ("dashboard/index.html",         "Frontend dashboard"),
    ("requirements.txt",             "Dependencies list"),
    ("models/anomaly_model.joblib",  "ML anomaly model"),
    ("models/rf_attack_model.joblib","ML classifier model"),
    ("models/label_encoder.joblib",  "ML label encoder"),
    ("data/yara_rules/builtin.yar",  "YARA built-in rules"),
    ("data/sigma_rules/builtin_rules.yml", "Sigma built-in rules"),
]

DATA_FILES_WITH_DEFAULTS = [
    ("data/logs.json",          "[]"),
    ("data/cases.json",         "[]"),
    ("data/blocks_active.json", "[]"),
    ("data/response_log.json",  "[]"),
    ("data/users.json",         "[]"),
]

def check_files(auto_fix=False):
    section("Critical Files")
    for rel, desc in REQUIRED_FILES:
        p = ROOT / rel
        if p.exists():
            size = p.stat().st_size
            ok(f"{rel}  ({size:,} bytes)  — {desc}")
        else:
            fail(f"{rel} — MISSING  ({desc})")
            issues_found.append(f"Missing file: {rel}")

    section("Data Files")
    for rel, default in DATA_FILES_WITH_DEFAULTS:
        p = ROOT / rel
        if p.exists():
            ok(f"{rel}")
        else:
            fail(f"{rel} — MISSING")
            issues_found.append(f"Missing data file: {rel}")
            if auto_fix:
                p.write_text(default)
                ok(f"Created: {rel} (with default content)")
                fixes_applied.append(f"Created {rel}")

# ─────────────────────────────────────────────────────────────────────
# 5. Module __init__.py files
# ─────────────────────────────────────────────────────────────────────
REQUIRED_MODULES = [
    "capture", "api", "detection", "scoring", "mitre", "response",
    "reporting", "cases", "threat_intel", "ueba", "soar",
    "yara_engine", "sigma_engine", "honeypot", "compliance",
    "vuln", "forensics", "data_lake", "rbac", "log_store",
    "firewall", "assets", "geoip", "agent", "ml", "features",
    "packet_analyzer", "siem",
]

def check_modules(auto_fix=False):
    section("Module __init__.py Files")
    missing = []
    for mod in REQUIRED_MODULES:
        init = ROOT / mod / "__init__.py"
        if init.exists():
            ok(mod)
        else:
            if (ROOT / mod).exists():
                fail(f"{mod}/__init__.py — MISSING")
                missing.append(mod)
                issues_found.append(f"Missing __init__.py: {mod}")
            else:
                fail(f"{mod}/ — directory missing entirely")
                issues_found.append(f"Missing module directory: {mod}")

    if missing and auto_fix:
        for mod in missing:
            init = ROOT / mod / "__init__.py"
            init.touch()
            ok(f"Created: {mod}/__init__.py")
            fixes_applied.append(f"Created {mod}/__init__.py")

# ─────────────────────────────────────────────────────────────────────
# 6. Config validation
# ─────────────────────────────────────────────────────────────────────
def check_config(auto_fix=False):
    section("Configuration (settings.yaml)")
    cfg_path = ROOT / "config" / "settings.yaml"
    if not cfg_path.exists():
        fail("config/settings.yaml not found")
        issues_found.append("settings.yaml missing")
        return

    try:
        import yaml
        content = cfg_path.read_text()
        cfg = yaml.safe_load(content)

        # Check for duplicate keys
        top_keys = re.findall(r'^(\w+):', content, re.MULTILINE)
        from collections import Counter
        dupes = [k for k, v in Counter(top_keys).items() if v > 1]
        if dupes:
            fail(f"Duplicate YAML keys: {dupes}")
            issues_found.append(f"Duplicate YAML keys: {dupes}")
        else:
            ok("No duplicate YAML keys")

        # Check model paths
        model_path = cfg.get('detection', {}).get('anomaly', {}).get('model_path', '')
        classifier_path = cfg.get('detection', {}).get('anomaly', {}).get('classifier_path', '')

        if model_path.endswith('.pkl'):
            fail(f"model_path uses .pkl: {model_path}")
            issues_found.append("model_path uses wrong .pkl extension")
            if auto_fix:
                new = content.replace(model_path, model_path.replace('.pkl', '.joblib'))
                cfg_path.write_text(new)
                ok("Fixed: model_path → .joblib")
                fixes_applied.append("Fixed model_path extension")
        else:
            ok(f"model_path: {model_path}")

        if classifier_path.endswith('.pkl'):
            fail(f"classifier_path uses .pkl: {classifier_path}")
            issues_found.append("classifier_path uses wrong .pkl extension")
            if auto_fix:
                new = content.replace(classifier_path, 'models/rf_attack_model.joblib')
                cfg_path.write_text(new)
                ok("Fixed: classifier_path → rf_attack_model.joblib")
                fixes_applied.append("Fixed classifier_path extension")
        else:
            ok(f"classifier_path: {classifier_path}")

        # Check JWT secret
        jwt = cfg.get('rbac', {}).get('jwt_secret', '')
        if jwt == 'CHANGE_ME_IN_PRODUCTION':
            warn("JWT secret is default — change before production deployment")
        else:
            ok("JWT secret is customised")

        ok("YAML parses successfully")

    except Exception as e:
        fail(f"YAML parse error: {e}")
        issues_found.append(f"YAML parse error: {e}")

# ─────────────────────────────────────────────────────────────────────
# 7. Deep import test
# ─────────────────────────────────────────────────────────────────────
def check_imports():
    section("Module Import Test")
    sys.path.insert(0, str(ROOT))

    MODULE_TESTS = [
        ("capture.sniffer",         "LiveSniffer"),
        ("packet_analyzer.engine",  "PacketAnalyzer"),
        ("features.extractor",      "FlowAggregator"),
        ("detection.signature",     "SignatureDetector"),
        ("detection.anomaly",       "AnomalyDetector"),
        ("detection.correlation",   "CorrelationEngine"),
        ("scoring.scorer",          "ThreatScorer"),
        ("mitre.mapper",            "MitreMapper"),
        ("response.responder",      "AutonomousResponder"),
        ("reporting.reporter",      "SOCReporter"),
        ("cases.manager",           "CaseManager"),
        ("threat_intel.ioc_manager","IOCManager"),
        ("ueba.engine",             "UEBAEngine"),
        ("soar.playbooks",          "SOAREngine"),
        ("yara_engine.scanner",     "YARAScanner"),
        ("sigma_engine.converter",  "SigmaEngine"),
        ("honeypot.traps",          "HoneypotManager"),
        ("compliance.checker",      "ComplianceChecker"),
        ("vuln.manager",            "VulnManager"),
        ("forensics.timeline",      "ForensicsManager"),
        ("data_lake.storage",       "DataLake"),
        ("data_lake.sqlite_writer", "SQLiteWriter"),
        ("rbac.auth",               "RBACManager"),
        ("log_store.log_manager",   "LogManager"),
        ("firewall.integrator",     "FirewallIntegrator"),
        ("assets.discovery",        "AssetInventory"),
        ("geoip.lookup",            "GeoIPLookup"),
    ]

    passed = 0
    failed_list = []
    for mod, cls in MODULE_TESTS:
        try:
            m = importlib.import_module(mod)
            getattr(m, cls)
            ok(f"{mod}.{cls}")
            passed += 1
        except Exception as e:
            fail(f"{mod}.{cls}  →  {e}")
            issues_found.append(f"Import failed: {mod}.{cls}: {e}")
            failed_list.append((mod, cls, str(e)))

    print(f"\n  Result: {passed}/{len(MODULE_TESTS)} modules imported successfully")
    if failed_list:
        fail(f"{len(failed_list)} modules failed to import")

# ─────────────────────────────────────────────────────────────────────
# 8. Port availability
# ─────────────────────────────────────────────────────────────────────
def check_ports():
    section("Port Availability")
    import socket
    ports = [
        (8000, "HTTP API + Dashboard"),
        (5514, "Syslog UDP/TCP"),
        (5515, "Windows Event Log"),
        (5516, "Agent telemetry"),
    ]
    for port, desc in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.close()
            ok(f":{port}  available  ({desc})")
        except OSError:
            fail(f":{port}  IN USE  ({desc})")
            issues_found.append(f"Port {port} already in use")
            info(f"   Fix: lsof -i :{port}  then kill the process, or use --port XXXX")

# ─────────────────────────────────────────────────────────────────────
# 9. Permissions
# ─────────────────────────────────────────────────────────────────────
def check_permissions():
    section("Permissions & Runtime")
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    if is_root:
        ok("Running as root — live packet capture ENABLED")
    else:
        warn("Not root — live packet capture DISABLED (simulation mode active)")
        info("   Fix: sudo python main.py")

    # Check write permission on data/
    try:
        test = ROOT / "data" / ".write_test"
        test.write_text("ok")
        test.unlink()
        ok("data/ directory is writable")
    except Exception as e:
        fail(f"data/ directory not writable: {e}")
        issues_found.append("data/ directory not writable")

    # Check config writable
    try:
        cfg = ROOT / "config" / "settings.yaml"
        cfg.open("a").close()
        ok("config/settings.yaml is writable")
    except Exception:
        fail("config/settings.yaml is read-only")
        issues_found.append("config/settings.yaml not writable")

# ─────────────────────────────────────────────────────────────────────
# 10. Syntax check all Python files
# ─────────────────────────────────────────────────────────────────────
def check_syntax():
    section("Python Syntax Check (all .py files)")
    import ast
    errors = []
    count = 0
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in ['__pycache__']]
        for f in files:
            if f.endswith('.py'):
                path = Path(root) / f
                count += 1
                try:
                    ast.parse(path.read_text())
                except SyntaxError as e:
                    fail(f"{path.relative_to(ROOT)}:{e.lineno} — {e.msg}")
                    errors.append(str(path))
                    issues_found.append(f"Syntax error in {path}: {e.msg}")
    if not errors:
        ok(f"All {count} Python files parse cleanly")
    else:
        fail(f"{len(errors)} files have syntax errors")

# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CyberRemedy Diagnostic Tool")
    parser.add_argument("--fix",  action="store_true", help="Auto-fix all fixable issues")
    parser.add_argument("--test", action="store_true", help="Run deep import test")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║   CyberRemedy v1.2 — Diagnostic Tool            ║")
    print(f"╚══════════════════════════════════════════════════╝{NC}")
    if args.fix:
        print(f"  {YELLOW}AUTO-FIX MODE ENABLED{NC}")

    check_python()
    check_dirs(auto_fix=args.fix)
    check_files(auto_fix=args.fix)
    check_modules(auto_fix=args.fix)
    check_config(auto_fix=args.fix)
    check_packages(auto_fix=args.fix)
    check_ports()
    check_permissions()
    check_syntax()

    if args.test:
        check_imports()

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}── Summary {'─'*42}{NC}")

    if fixes_applied:
        print(f"\n  {GREEN}Auto-fixes applied ({len(fixes_applied)}):{NC}")
        for f in fixes_applied:
            print(f"    ✅ {f}")

    if issues_found:
        print(f"\n  {RED}Issues found ({len(issues_found)}):{NC}")
        for i in issues_found:
            print(f"    ❌ {i}")
        print(f"\n  {YELLOW}Run with --fix to auto-resolve fixable issues:{NC}")
        print(f"    python diagnose.py --fix")
        print(f"\n  {YELLOW}For import errors, run the deep test:{NC}")
        print(f"    python diagnose.py --test --fix")
    else:
        print(f"\n  {GREEN}✅ All checks passed — app should start correctly!{NC}")
        print(f"\n  Start with:")
        print(f"    {CYAN}python main.py{NC}           (simulation mode)")
        print(f"    {CYAN}sudo python main.py{NC}      (live capture)")
        print(f"    {CYAN}bash startup.sh{NC}          (quick start)")

    print()

if __name__ == "__main__":
    main()
