#!/usr/bin/env python3
"""
CyberRemedy v4.0 — Entry point

Usage:
  python main.py                    # Start API + dashboard (default)
  python main.py --port 9000        # Custom port
  python main.py --host 127.0.0.1   # Bind to localhost only
  python main.py --train            # Train ML models
  python main.py --test             # Run test suite
"""
import argparse, logging, logging.handlers, sys, os
from pathlib import Path

ROOT = Path(__file__).parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-26s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("cyberremedy.main")


def ensure_dirs():
    for d in [
        "data", "data/reports", "data/datasets",
        "data/yara_rules", "data/sigma_rules",
        "data/lake", "data/lake/hot", "data/lake/warm", "data/lake/cold",
        "data/logs", "data/logs/alerts", "data/logs/traffic",
        "data/logs/blocks", "data/logs/events", "data/logs/assets",
        "data/pcap", "data/geoip", "data/assets",
        "models", "logs",
    ]:
        (ROOT / d).mkdir(parents=True, exist_ok=True)


def setup_file_logging():
    """Rotate log at 10 MB, keep 10 files. All DEBUG+ goes to file."""
    log_path = ROOT / "data" / "logs" / "cyberremedy.log"
    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(name)-26s %(levelname)-8s %(message)s"
    ))
    logging.getLogger().addHandler(fh)
    logging.getLogger().setLevel(logging.DEBUG)
    logger.info(f"File logging active → {log_path}")


def download_geoip():
    """
    Download free offline GeoIP data from db-ip.com — no API key needed.
    Only runs if the file doesn't already exist.
    """
    import urllib.request, gzip as _gz, csv, json
    from datetime import datetime as _dt

    out_json = ROOT / "data" / "geoip" / "ip_country.json"
    marker   = ROOT / "data" / "geoip" / "ip_country.csv"

    import time as _geoip_time
    _geoip_age = _geoip_time.time() - marker.stat().st_mtime if marker.exists() else 999999
    if marker.exists() and marker.stat().st_size > 50_000 and _geoip_age < 30 * 86400:
        logger.info(f"GeoIP: offline DB present ({marker.stat().st_size//1024} KB, {int(_geoip_age/86400)}d old) — skipping download")
        return
    if marker.exists() and _geoip_age >= 30 * 86400:
        logger.info("GeoIP: database is 30+ days old — auto-refreshing…")

    # Try multiple free sources (no account or key needed)
    sources = [
        # ip-location-db (GitHub, public, no key, updated monthly)
        "https://raw.githubusercontent.com/sapics/ip-location-db/main/country/country-ipv4.csv",
        # dbip mirror (some months are accessible)
        "https://raw.githubusercontent.com/sapics/ip-location-db/main/country/country-ipv4-num.csv",
    ]

    for url in sources:
        try:
            logger.info(f"GeoIP: trying {url}")
            import zipfile, io
            with urllib.request.urlopen(url, timeout=30) as resp:
                raw = resp.read()
            # Handle zip vs csv
            if url.endswith(".ZIP") or url.endswith(".zip"):
                zf = zipfile.ZipFile(io.BytesIO(raw))
                data = zf.read(zf.namelist()[0]).decode("utf-8", errors="replace")
            elif url.endswith(".gz"):
                data = _gz.decompress(raw).decode("utf-8", errors="replace")
            else:
                data = raw.decode("utf-8", errors="replace")
            raw_rows = list(csv.reader(data.splitlines()))
            # Handle both formats: (start,end,cc) and (start_num,end_num,cc)
            rows = [r[:3] for r in raw_rows if len(r) >= 3 and not r[0].startswith('#')]
            json.dump(rows, open(out_json, "w"))
            marker.write_text(f"source:{url}\nrows:{len(rows)}")
            logger.info(f"GeoIP: saved {len(rows):,} IP ranges → {out_json}")
            return
        except Exception as e:
            logger.warning(f"GeoIP source failed ({url}): {e}")

    logger.warning("GeoIP: offline download failed — ip-api.com online fallback will be used (45 req/min free)")


def cmd_api(args):
    ensure_dirs()
    setup_file_logging()
    try:
        download_geoip()
    except Exception as e:
        logger.warning(f"GeoIP setup skipped: {e}")

    import uvicorn
    logger.info(f"Starting CyberRemedy v4.0 on http://{args.host}:{args.port}")
    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="info",
        app_dir=str(ROOT),
    )


def cmd_train(args):
    ensure_dirs()
    logger.info("Training ML models …")
    sys.path.insert(0, str(ROOT))
    from detection.anomaly import AnomalyDetector
    import numpy as np

    detector = AnomalyDetector(
        model_path="models/anomaly_model.pkl",
        classifier_path="models/classifier_model.pkl",
    )
    FEATURES = [
        "packet_count","total_bytes","bytes_per_second","packets_per_second",
        "avg_packet_size","min_packet_size","max_packet_size","std_packet_size",
        "flow_duration","avg_inter_arrival","std_inter_arrival","min_inter_arrival",
        "unique_dst_ports","unique_src_ips","dst_port_entropy","flag_entropy",
        "ttl_entropy","payload_entropy","has_syn","has_fin","has_rst","has_null",
    ]
    rng = np.random.default_rng(42)
    benign = [{f: float(rng.uniform(0,1)) for f in FEATURES} for _ in range(500)]
    attack = [{f: float(rng.uniform(0,1)) for f in FEATURES} for _ in range(100)]
    for s in attack:
        s["packet_count"] = float(rng.integers(500, 5000))
        s["unique_dst_ports"] = float(rng.integers(50, 200))
    all_flows = benign + attack
    labels = [0]*500 + [1]*100
    detector.train(all_flows, labels)
    logger.info("Training complete — models saved to models/")


def cmd_test(args):
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v"],
        cwd=str(ROOT)
    )
    sys.exit(result.returncode)


def main():
    p = argparse.ArgumentParser(description="CyberRemedy v4.0 SIEM")
    p.add_argument("--host",  default="0.0.0.0")
    p.add_argument("--port",  type=int, default=8000)
    p.add_argument("--train", action="store_true", help="Train ML models and exit")
    p.add_argument("--test",  action="store_true", help="Run test suite and exit")

    args = p.parse_args()

    if args.train:
        cmd_train(args)
    elif args.test:
        cmd_test(args)
    else:
        cmd_api(args)


if __name__ == "__main__":
    main()
