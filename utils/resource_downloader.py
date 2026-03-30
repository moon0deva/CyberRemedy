"""
CyberRemedy — Free Resource Downloader
=======================================
Downloads all external free resources on first run.
NO API KEYS required. All sources are public domain or open licence.

Run manually:   python3 utils/resource_downloader.py
Auto-run:       Called by main.py on startup if resources are stale/missing.

Sources:
  MITRE ATT&CK  — MITRE CTI GitHub (CC BY 4.0)
  YARA rules    — Neo23x0/signature-base (MIT), elastic/detection-rules (Apache 2.0)
  Sigma rules   — SigmaHQ/sigma core rules (Apache 2.0)
  NVD CVEs      — NIST NVD JSON feed (public domain)
  IOC feeds     — abuse.ch, EmergingThreats, Tor exits (all free/public)
"""

import gzip
import hashlib
import json
import logging
import os
import shutil
import sys
import threading
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("cyberremedy.downloader")

BASE_DIR = Path(__file__).parent.parent

# ── Download manifest ──────────────────────────────────────────────────────────
RESOURCES = {

    # ── MITRE ATT&CK Enterprise Matrix ────────────────────────────────────────
    "mitre_attack": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "dest": BASE_DIR / "data" / "mitre_attack_full.json",
        "ttl_days": 30,
        "description": "MITRE ATT&CK Enterprise Matrix (CC BY 4.0)",
        "size_hint": "~15 MB",
        "processor": "process_mitre_attack",
    },

    # ── YARA rule packs ───────────────────────────────────────────────────────
    "yara_signature_base": {
        "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        "dest": BASE_DIR / "data" / "downloads" / "signature-base.zip",
        "extract_to": BASE_DIR / "data" / "downloads" / "signature-base",
        "ttl_days": 14,
        "description": "Neo23x0 signature-base YARA rules (MIT licence)",
        "size_hint": "~8 MB",
        "processor": "process_yara_pack",
    },
    "yara_elastic": {
        "url": "https://github.com/elastic/detection-rules/archive/refs/heads/main.zip",
        "dest": BASE_DIR / "data" / "downloads" / "elastic-detection.zip",
        "extract_to": BASE_DIR / "data" / "downloads" / "elastic-detection",
        "ttl_days": 14,
        "description": "Elastic detection rules YARA pack (Apache 2.0)",
        "size_hint": "~25 MB",
        "processor": "process_yara_elastic",
    },

    # ── Sigma rules ────────────────────────────────────────────────────────────
    "sigma_core": {
        "url": "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
        "dest": BASE_DIR / "data" / "downloads" / "sigma-master.zip",
        "extract_to": BASE_DIR / "data" / "downloads" / "sigma-master",
        "ttl_days": 14,
        "description": "SigmaHQ core detection rules (Apache 2.0)",
        "size_hint": "~30 MB",
        "processor": "process_sigma_pack",
    },

    # ── NVD CVE database ──────────────────────────────────────────────────────
    "nvd_2024": {
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz",
        "dest": BASE_DIR / "data" / "nvd" / "nvdcve-2024.json.gz",
        "ttl_days": 7,
        "description": "NVD CVE feed 2024 — public domain",
        "size_hint": "~45 MB compressed",
        "processor": "process_nvd_feed",
    },
    "nvd_2023": {
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz",
        "dest": BASE_DIR / "data" / "nvd" / "nvdcve-2023.json.gz",
        "ttl_days": 30,
        "description": "NVD CVE feed 2023 — public domain",
        "size_hint": "~50 MB compressed",
        "processor": "process_nvd_feed",
    },
    "nvd_modified": {
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
        "dest": BASE_DIR / "data" / "nvd" / "nvdcve-modified.json.gz",
        "ttl_days": 1,
        "description": "NVD modified CVEs (last 8 days) — public domain",
        "size_hint": "~5 MB compressed",
        "processor": "process_nvd_feed",
    },
}


# ── State tracking ─────────────────────────────────────────────────────────────
_STATE_FILE = BASE_DIR / "data" / "downloader_state.json"

def _load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text())
        except Exception:
            pass
    return {}

def _save_state(state: dict):
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2))

def _is_stale(resource_key: str, ttl_days: int) -> bool:
    state = _load_state()
    last = state.get(resource_key, {}).get("downloaded_at")
    if not last:
        return True
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).days
        return age >= ttl_days
    except Exception:
        return True

def _mark_done(resource_key: str, extra: dict = None):
    state = _load_state()
    state[resource_key] = {
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        **(extra or {}),
    }
    _save_state(state)


# ── HTTP downloader ────────────────────────────────────────────────────────────
def _download(url: str, dest: Path, desc: str,
               progress_cb: Callable = None, timeout: int = 120) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberRemedy/3.0 (free-resource-downloader)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.getheader("Content-Length", 0))
            downloaded = 0
            chunk = 65536
            with open(tmp, "wb") as f:
                while True:
                    buf = resp.read(chunk)
                    if not buf:
                        break
                    f.write(buf)
                    downloaded += len(buf)
                    if progress_cb and total:
                        progress_cb(downloaded, total)
        shutil.move(str(tmp), str(dest))
        logger.info(f"Downloaded {desc}: {downloaded:,} bytes → {dest.name}")
        return True
    except Exception as exc:
        if tmp.exists():
            tmp.unlink()
        logger.error(f"Download failed [{desc}]: {exc}")
        return False


# ── Processors ────────────────────────────────────────────────────────────────

def process_mitre_attack(dest: Path) -> dict:
    """Parse MITRE ATT&CK full JSON → compact techniques.json."""
    logger.info("Processing MITRE ATT&CK matrix ...")
    out_file = BASE_DIR / "mitre" / "techniques.json"
    try:
        data = json.loads(dest.read_text())
        objects = data.get("objects", [])
        techniques = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext_refs = obj.get("external_references", [])
            tid = next((r["external_id"] for r in ext_refs
                        if r.get("source_name") == "mitre-attack"), None)
            if not tid:
                continue
            phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
            techniques.append({
                "id":          tid,
                "name":        obj.get("name", ""),
                "description": obj.get("description", "")[:300],
                "tactic":      phases[0] if phases else "",
                "tactics":     phases,
                "platforms":   obj.get("x_mitre_platforms", []),
                "is_subtechnique": "." in tid,
                "deprecated":  obj.get("x_mitre_deprecated", False),
            })
        techniques.sort(key=lambda t: t["id"])
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(techniques, indent=2))
        logger.info(f"MITRE: {len(techniques)} techniques → {out_file}")
        return {"techniques": len(techniques)}
    except Exception as exc:
        logger.error(f"MITRE processing failed: {exc}")
        return {}


def process_yara_pack(dest: Path) -> dict:
    """Extract signature-base YARA pack and merge into community.yar."""
    extract_to = dest.parent / "signature-base"
    try:
        with zipfile.ZipFile(dest) as z:
            z.extractall(extract_to)
    except Exception as exc:
        logger.error(f"YARA extract failed: {exc}")
        return {}

    yara_dir = extract_to / "signature-base-master" / "yara"
    if not yara_dir.exists():
        # Try alternate path
        yara_dirs = list(extract_to.rglob("yara"))
        yara_dir = yara_dirs[0] if yara_dirs else None
    if not yara_dir:
        logger.warning("YARA: could not find yara/ dir in signature-base")
        return {}

    out_file = BASE_DIR / "data" / "yara_rules" / "community.yar"
    rules_written = 0
    with open(out_file, "w") as out:
        out.write("// CyberRemedy Community YARA Rules — Neo23x0 signature-base (MIT)\n")
        out.write(f"// Downloaded: {datetime.utcnow().isoformat()}\n\n")
        for yar in sorted(yara_dir.glob("*.yar"))[:50]:  # cap at 50 files
            try:
                content = yar.read_text(errors="replace")
                # Skip rules with includes or complex dependencies
                if "include " in content.lower():
                    continue
                rule_count = content.count("\nrule ")
                out.write(f"\n// === {yar.name} ===\n")
                out.write(content + "\n")
                rules_written += rule_count
            except Exception:
                continue

    logger.info(f"YARA community.yar: ~{rules_written} rules from signature-base")
    return {"rules": rules_written}


def process_yara_elastic(dest: Path) -> dict:
    """Extract and merge Elastic YARA rules."""
    extract_to = dest.parent / "elastic-detection"
    try:
        with zipfile.ZipFile(dest) as z:
            # Only extract YARA files to save space
            yara_members = [m for m in z.namelist()
                            if m.endswith(".yar") or m.endswith(".yara")]
            for member in yara_members[:30]:
                z.extract(member, extract_to)
    except Exception as exc:
        logger.error(f"Elastic YARA extract failed: {exc}")
        return {}

    out_file = BASE_DIR / "data" / "yara_rules" / "elastic.yar"
    rules_written = 0
    with open(out_file, "w") as out:
        out.write("// CyberRemedy Elastic Detection YARA Rules (Apache 2.0)\n\n")
        for yar in sorted(extract_to.rglob("*.yar"))[:30]:
            try:
                content = yar.read_text(errors="replace")
                if "include " in content.lower():
                    continue
                out.write(content + "\n")
                rules_written += content.count("\nrule ")
            except Exception:
                continue

    logger.info(f"YARA elastic.yar: ~{rules_written} rules")
    return {"rules": rules_written}


def process_sigma_pack(dest: Path) -> dict:
    """Extract SigmaHQ rules and convert to CyberRemedy Sigma format."""
    extract_to = dest.parent / "sigma-master"
    try:
        with zipfile.ZipFile(dest) as z:
            sigma_members = [m for m in z.namelist()
                             if m.endswith(".yml") and "/rules/" in m]
            # Take up to 300 rules from key categories
            categories = ["network", "linux", "windows/process_creation",
                          "windows/network_connection", "application"]
            chosen = []
            for cat in categories:
                cat_rules = [m for m in sigma_members if f"/{cat}/" in m or f"/rules/{cat}" in m]
                chosen.extend(cat_rules[:60])
            chosen = chosen[:300]
            for member in chosen:
                z.extract(member, extract_to)
    except Exception as exc:
        logger.error(f"Sigma extract failed: {exc}")
        return {}

    import yaml as _yaml_mod
    out_file = BASE_DIR / "data" / "sigma_rules" / "community_rules.yml"
    rules = []
    for yml in extract_to.rglob("*.yml"):
        try:
            content = yml.read_text(errors="replace")
            # Quick validity check
            if "title:" not in content or "detection:" not in content:
                continue
            rules.append(content.strip())
        except Exception:
            continue

    if rules:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as f:
            f.write("# CyberRemedy Community Sigma Rules — SigmaHQ (Apache 2.0)\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n\n")
            for r in rules[:300]:
                f.write("---\n")
                f.write(r)
                f.write("\n\n")
        logger.info(f"Sigma community_rules.yml: {len(rules)} rules")

    return {"rules": len(rules)}


def process_nvd_feed(dest: Path) -> dict:
    """Decompress NVD JSON feed and extract high-severity CVEs."""
    logger.info(f"Processing NVD feed: {dest.name} ...")
    nvd_dir = BASE_DIR / "data" / "nvd"
    nvd_dir.mkdir(parents=True, exist_ok=True)
    out_file = nvd_dir / (dest.stem.replace(".json", "") + "_parsed.json")

    try:
        with gzip.open(dest, "rb") as gz:
            data = json.loads(gz.read())
    except Exception as exc:
        logger.error(f"NVD decompress failed: {exc}")
        return {}

    cves = []
    for item in data.get("CVE_Items", []):
        try:
            cve_id  = item["cve"]["CVE_data_meta"]["ID"]
            desc    = item["cve"]["description"]["description_data"]
            desc_en = next((d["value"] for d in desc if d["lang"] == "en"), "")

            # Get CVSS v3 score (prefer), fall back to v2
            impact  = item.get("impact", {})
            cvss3   = impact.get("baseMetricV3", {}).get("cvssV3", {})
            cvss2   = impact.get("baseMetricV2", {}).get("cvssV2", {})
            score   = cvss3.get("baseScore") or cvss2.get("baseScore") or 0
            vector  = cvss3.get("vectorString") or cvss2.get("vectorString") or ""
            sev     = cvss3.get("baseSeverity") or impact.get("baseMetricV2", {}).get("severity") or "UNKNOWN"

            # Only keep HIGH/CRITICAL (score >= 7.0) to save space
            if float(score) < 7.0:
                continue

            # Extract affected software (CPE)
            cpes = []
            for node in item.get("configurations", {}).get("nodes", []):
                for cpe in node.get("cpe_match", []):
                    if cpe.get("vulnerable"):
                        cpes.append(cpe.get("cpe23Uri", ""))

            published = item.get("publishedDate", "")

            cves.append({
                "cve_id":      cve_id,
                "description": desc_en[:500],
                "cvss_score":  float(score),
                "severity":    sev.upper(),
                "vector":      vector,
                "cpes":        cpes[:5],
                "published":   published[:10],
            })
        except Exception:
            continue

    # Sort by severity
    cves.sort(key=lambda c: c["cvss_score"], reverse=True)
    out_file.write_text(json.dumps(cves, indent=2))
    logger.info(f"NVD {dest.name}: {len(cves)} HIGH/CRITICAL CVEs → {out_file.name}")
    return {"cves": len(cves), "output": str(out_file)}


# ── Main download orchestrator ─────────────────────────────────────────────────

def download_all(force: bool = False,
                 resources: List[str] = None,
                 progress_cb: Callable = None) -> dict:
    """
    Download and process all configured resources.
    Skips resources that are fresh (within TTL).

    Args:
        force:     Force re-download even if fresh
        resources: Limit to these resource keys (None = all)
        progress_cb: Called with (resource_key, downloaded, total)

    Returns: dict of {resource_key: result_dict}
    """
    results = {}
    target = resources or list(RESOURCES.keys())

    for key in target:
        cfg = RESOURCES.get(key)
        if not cfg:
            logger.warning(f"Unknown resource: {key}")
            continue

        if not force and not _is_stale(key, cfg["ttl_days"]):
            dest = cfg["dest"]
            # Check file actually exists
            if Path(dest).exists():
                logger.debug(f"[{key}] fresh — skipping")
                results[key] = {"status": "cached"}
                continue

        logger.info(f"[{key}] Downloading: {cfg['description']} ({cfg['size_hint']})")
        dest = Path(cfg["dest"])

        def _prog(dl, total, k=key):
            if progress_cb and total:
                progress_cb(k, dl, total)

        ok = _download(cfg["url"], dest, cfg["description"], _prog)
        if not ok:
            results[key] = {"status": "failed"}
            continue

        # Run processor
        proc_name = cfg.get("processor")
        if proc_name:
            proc_fn = globals().get(proc_name)
            if proc_fn:
                try:
                    proc_result = proc_fn(dest)
                    results[key] = {"status": "ok", **proc_result}
                except Exception as exc:
                    logger.error(f"[{key}] Processor failed: {exc}")
                    results[key] = {"status": "processor_error", "error": str(exc)}
            else:
                results[key] = {"status": "ok", "note": f"no processor {proc_name}"}
        else:
            results[key] = {"status": "ok"}

        _mark_done(key, results[key])

    return results


def download_background(callback: Callable = None):
    """Run download_all in a background thread."""
    def _run():
        try:
            results = download_all()
            logger.info(f"Background download complete: {results}")
            if callback:
                callback(results)
        except Exception as exc:
            logger.error(f"Background download error: {exc}")

    t = threading.Thread(target=_run, daemon=True, name="resource-downloader")
    t.start()
    return t


def status() -> dict:
    """Return download status for all resources."""
    state = _load_state()
    result = {}
    for key, cfg in RESOURCES.items():
        dest = Path(cfg["dest"])
        last = state.get(key, {}).get("downloaded_at")
        stale = _is_stale(key, cfg["ttl_days"])
        result[key] = {
            "description": cfg["description"],
            "size_hint":   cfg["size_hint"],
            "ttl_days":    cfg["ttl_days"],
            "exists":      dest.exists(),
            "stale":       stale,
            "last_download": last or "never",
        }
    return result


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="CyberRemedy resource downloader")
    parser.add_argument("--force", action="store_true", help="Force re-download")
    parser.add_argument("--resource", help="Download specific resource only")
    parser.add_argument("--status", action="store_true", help="Show status only")
    args = parser.parse_args()

    if args.status:
        s = status()
        for k, v in s.items():
            flag = "STALE" if v["stale"] else "OK   "
            exists = "✓" if v["exists"] else "✗"
            print(f"  [{flag}] {exists} {k:25s}  last={v['last_download'][:19]}  {v['description'][:50]}")
    else:
        res = [args.resource] if args.resource else None
        results = download_all(force=args.force, resources=res)
        print(json.dumps(results, indent=2))
