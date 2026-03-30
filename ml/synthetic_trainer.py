"""
CyberRemedy ML — Synthetic Training Data Generator + Model Trainer
===================================================================
Generates a realistic synthetic dataset covering 8 attack classes,
then trains and saves both:
  models/rf_attack_model.joblib    — RandomForestClassifier (attack type)
  models/anomaly_model.joblib      — IsolationForest (anomaly detection)

Attack classes and their feature signatures:
  Benign              — normal varied traffic
  Port Scan           — many unique dst_ports, SYN only, short duration
  Brute Force         — many packets to same port (SSH/RDP/FTP), rapid rate
  C2 Beaconing        — very regular inter-arrival, small packets, long duration
  DNS Tunneling       — DNS protocol, oversized packets, high entropy
  Lateral Movement    — internal dst, SMB/RDP/WinRM ports, moderate rate
  Data Exfiltration   — high bytes_per_second, high total_bytes, high entropy
  DoS/Flood           — extreme packets_per_second, tiny packets, many src IPs

Feature columns (must match FEATURE_COLS in detection/anomaly.py):
  packet_count, total_bytes, bytes_per_second, packets_per_second,
  avg_packet_size, min_packet_size, max_packet_size, std_packet_size,
  flow_duration, avg_inter_arrival, std_inter_arrival, min_inter_arrival,
  unique_dst_ports, unique_src_ips,
  dst_port_entropy, flag_entropy, ttl_entropy, payload_entropy,
  has_syn, has_fin, has_rst, has_null
"""

import os
import logging
import numpy as np
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger("cyberremedy.ml.trainer")

# ── sklearn availability — checked once at import ─────────────────────────────
_SKLEARN_OK = False
try:
    from sklearn.ensemble import RandomForestClassifier as _RFC
    from sklearn.ensemble import IsolationForest as _IsolationForest
    from sklearn.preprocessing import LabelEncoder as _LabelEncoder
    from sklearn.model_selection import cross_val_score as _cv_score
    import joblib as _joblib
    _SKLEARN_OK = True
except ImportError as _sklearn_exc:
    logger.warning(
        f"scikit-learn/joblib not installed — ML training disabled. "
        f"Run: pip install scikit-learn joblib --break-system-packages  ({_sklearn_exc})"
    )

FEATURE_COLS = [
    "packet_count", "total_bytes", "bytes_per_second", "packets_per_second",
    "avg_packet_size", "min_packet_size", "max_packet_size", "std_packet_size",
    "flow_duration", "avg_inter_arrival", "std_inter_arrival", "min_inter_arrival",
    "unique_dst_ports", "unique_src_ips",
    "dst_port_entropy", "flag_entropy", "ttl_entropy", "payload_entropy",
    "has_syn", "has_fin", "has_rst", "has_null",
]

MODELS_DIR = Path("models")


# ── Per-class feature profile generators ──────────────────────────────────────

def _profile_benign(n: int, rng: np.random.Generator) -> np.ndarray:
    """Normal web/app traffic — varied sizes, reasonable rates."""
    rows = []
    for _ in range(n):
        dur   = rng.uniform(0.5, 120.0)
        pkts  = int(rng.uniform(5, 300))
        tb    = int(pkts * rng.uniform(200, 1200))
        bps   = tb / max(dur, 0.001)
        pps   = pkts / max(dur, 0.001)
        ap    = tb / pkts
        rows.append([
            pkts, tb, bps, pps,
            ap, rng.uniform(40, 80), rng.uniform(1200, 1500), rng.uniform(50, 400),
            dur,
            rng.uniform(0.05, 2.0), rng.uniform(0.02, 1.0), rng.uniform(0.001, 0.1),
            rng.integers(1, 4), 1,
            rng.uniform(0.0, 1.2), rng.uniform(0.5, 1.8), rng.uniform(0.0, 0.5),
            rng.uniform(2.0, 5.5),
            1, rng.integers(0, 2), 0, 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_port_scan(n: int, rng: np.random.Generator) -> np.ndarray:
    """SYN scan — many unique ports, tiny packets, very short flows."""
    rows = []
    for _ in range(n):
        udp  = int(rng.uniform(50, 60000))
        pkts = udp
        dur  = rng.uniform(0.5, 30.0)
        rows.append([
            pkts, pkts * 60,                            # tiny SYN packets
            pkts * 60 / max(dur, 0.001), pkts / max(dur, 0.001),
            60.0, 40.0, 80.0, rng.uniform(5, 20),
            dur,
            dur / max(pkts, 1), rng.uniform(0.0, 0.005), 0.0,
            udp, 1,
            rng.uniform(3.5, 6.0), 0.2, 0.0, 0.5,
            1, 0, 0, 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_brute_force(n: int, rng: np.random.Generator) -> np.ndarray:
    """Rapid repeated connections to single auth port."""
    rows = []
    for _ in range(n):
        pkts = int(rng.uniform(200, 5000))
        dur  = rng.uniform(10.0, 300.0)
        ap   = rng.uniform(60, 120)
        tb   = pkts * ap
        rows.append([
            pkts, tb, tb / dur, pkts / dur,
            ap, 40.0, 200.0, rng.uniform(10, 50),
            dur,
            dur / pkts, rng.uniform(0.001, 0.05), 0.0,
            1, 1,
            0.0, rng.uniform(0.8, 1.5), 0.0, rng.uniform(1.0, 3.0),
            1, rng.integers(0, 2), rng.integers(0, 2), 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_c2_beaconing(n: int, rng: np.random.Generator) -> np.ndarray:
    """Periodic heartbeat — extremely regular IAT, small payloads, long duration."""
    rows = []
    for _ in range(n):
        interval = rng.uniform(10.0, 120.0)
        pkts     = int(rng.uniform(20, 200))
        dur      = pkts * interval
        ap       = rng.uniform(64, 256)
        tb       = pkts * ap
        rows.append([
            pkts, tb, tb / dur, pkts / dur,
            ap, ap - 10, ap + 10, rng.uniform(0, 5),    # very uniform sizes
            dur,
            interval, rng.uniform(0.0, 0.5), interval * 0.9,  # very low std  ← KEY
            1, 1,
            0.0, rng.uniform(0.5, 1.2), 0.0, rng.uniform(4.5, 7.5),
            rng.integers(0, 2), rng.integers(0, 2), 0, 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_dns_tunneling(n: int, rng: np.random.Generator) -> np.ndarray:
    """Data over DNS — oversized packets, high entropy, port 53."""
    rows = []
    for _ in range(n):
        pkts = int(rng.uniform(50, 1000))
        dur  = rng.uniform(5.0, 600.0)
        ap   = rng.uniform(200, 800)                    # far above normal 60B DNS
        tb   = pkts * ap
        rows.append([
            pkts, tb, tb / dur, pkts / dur,
            ap, 100.0, 1200.0, rng.uniform(100, 300),
            dur,
            rng.uniform(0.1, 2.0), rng.uniform(0.1, 1.0), 0.01,
            1, 1,
            0.0, rng.uniform(0.0, 0.5), 0.0,
            rng.uniform(6.5, 8.0),                      # HIGH entropy  ← KEY
            0, 0, 0, 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_lateral_movement(n: int, rng: np.random.Generator) -> np.ndarray:
    """Internal-to-internal, SMB/RDP/WinRM ports, moderate packet counts."""
    rows = []
    for _ in range(n):
        pkts = int(rng.uniform(20, 500))
        dur  = rng.uniform(1.0, 60.0)
        ap   = rng.uniform(200, 600)
        tb   = pkts * ap
        rows.append([
            pkts, tb, tb / dur, pkts / dur,
            ap, 60.0, 1400.0, rng.uniform(100, 400),
            dur,
            rng.uniform(0.01, 0.5), rng.uniform(0.01, 0.3), 0.001,
            rng.integers(1, 4), 1,
            rng.uniform(0.0, 1.5), rng.uniform(0.5, 2.0), 0.0, rng.uniform(3.0, 6.0),
            1, rng.integers(0, 2), rng.integers(0, 2), 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_exfiltration(n: int, rng: np.random.Generator) -> np.ndarray:
    """Large sustained outbound transfer — high bps, large volume, high entropy."""
    rows = []
    for _ in range(n):
        dur  = rng.uniform(30.0, 3600.0)
        ap   = rng.uniform(800, 1500)
        pkts = int(rng.uniform(500, 50000))
        tb   = pkts * ap
        rows.append([
            pkts, tb,
            tb / dur,                                   # HIGH bps  ← KEY
            pkts / dur,
            ap, 400.0, 1500.0, rng.uniform(100, 300),
            dur,
            rng.uniform(0.001, 0.05), rng.uniform(0.0, 0.02), 0.0,
            1, 1,
            0.0, rng.uniform(0.5, 1.5), 0.0,
            rng.uniform(6.5, 8.0),                      # HIGH entropy  ← KEY
            rng.integers(0, 2), rng.integers(0, 2), 0, 0,
        ])
    return np.array(rows, dtype=np.float32)


def _profile_dos_flood(n: int, rng: np.random.Generator) -> np.ndarray:
    """Extreme pps, tiny packets, many source IPs."""
    rows = []
    for _ in range(n):
        pkts = int(rng.uniform(10000, 1000000))
        dur  = rng.uniform(1.0, 60.0)
        ap   = rng.uniform(40, 80)
        tb   = pkts * ap
        rows.append([
            pkts, tb, tb / dur,
            pkts / dur,                                 # extreme pps  ← KEY
            ap, 40.0, 100.0, rng.uniform(0, 20),
            dur,
            dur / pkts, rng.uniform(0.0, 0.0001), 0.0,
            rng.integers(1, 5),
            rng.integers(50, 10000),                    # many src IPs  ← KEY
            rng.uniform(0.0, 2.0), rng.uniform(0.0, 0.5), 0.0, rng.uniform(0.5, 3.0),
            rng.integers(0, 2), 0, rng.integers(0, 2), 0,
        ])
    return np.array(rows, dtype=np.float32)


# ── Dataset builder ────────────────────────────────────────────────────────────

def generate_dataset(
    n_per_class: int = 500,
    seed: int = 42,
) -> Tuple[np.ndarray, List[str]]:
    """Build synthetic feature matrix and label list."""
    rng = np.random.default_rng(seed)
    classes = {
        "Benign":            _profile_benign,
        "Port Scan":         _profile_port_scan,
        "Brute Force":       _profile_brute_force,
        "C2 Beaconing":      _profile_c2_beaconing,
        "DNS Tunneling":     _profile_dns_tunneling,
        "Lateral Movement":  _profile_lateral_movement,
        "Data Exfiltration": _profile_exfiltration,
        "DoS/Flood":         _profile_dos_flood,
    }
    X_parts, y_parts = [], []
    for label, fn in classes.items():
        rows = fn(n_per_class, rng)
        rows = np.clip(rows, 0, None)
        rows += rng.normal(0, rows * 0.02 + 1e-6)      # 2% gaussian noise
        rows = np.clip(rows, 0, None)
        X_parts.append(rows)
        y_parts.extend([label] * n_per_class)
        logger.info(f"  Generated {n_per_class} {label} samples")
    return np.vstack(X_parts).astype(np.float32), y_parts


# ── Trainer ───────────────────────────────────────────────────────────────────

def train_and_save(
    n_per_class: int = 600,
    models_dir: Path = MODELS_DIR,
    force: bool = False,
) -> dict:
    """
    Train RandomForest + IsolationForest on synthetic data and persist to disk.
    Skips if both model files already exist (pass force=True to retrain).
    Returns a result dict.
    """
    rf_path  = models_dir / "rf_attack_model.joblib"
    if_path  = models_dir / "anomaly_model.joblib"
    enc_path = models_dir / "label_encoder.joblib"

    if rf_path.exists() and if_path.exists() and not force:
        logger.info("Models already saved — skipping training")
        return {"status": "skipped", "rf": str(rf_path), "if": str(if_path)}

    if not _SKLEARN_OK:
        reason = "scikit-learn/joblib not installed"
        logger.error(f"Model training failed: {reason}")
        return {"status": "error", "reason": reason}

    models_dir.mkdir(parents=True, exist_ok=True)
    total = n_per_class * 8
    logger.info(f"Generating {total} synthetic training samples ({n_per_class}/class × 8)…")
    X, y = generate_dataset(n_per_class=n_per_class)

    # Label encoder persisted alongside models
    le    = _LabelEncoder()
    y_enc = le.fit_transform(y)
    _joblib.dump(le, enc_path)

    # ── RandomForestClassifier ─────────────────────────────────────────────
    logger.info("Training RandomForestClassifier (200 trees)…")
    rf = _RFC(
        n_estimators=200,
        max_depth=20,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X, y)
    _joblib.dump(rf, rf_path)
    logger.info(f"  Saved → {rf_path}")

    # Quick 3-fold CV on a smaller estimator
    f1 = 0.0
    try:
        cv = _cv_score(
            _RFC(n_estimators=50, random_state=42, n_jobs=-1),
            X, y, cv=3, scoring="f1_macro",
        )
        f1 = float(cv.mean())
        logger.info(f"  CV F1-macro: {f1:.3f} ± {cv.std():.3f}")
    except Exception as exc:
        logger.warning(f"  CV failed (non-critical): {exc}")

    fi = sorted(zip(FEATURE_COLS, rf.feature_importances_), key=lambda x: -x[1])
    logger.info("  Top-5 features: " + ", ".join(f"{n}={v:.3f}" for n, v in fi[:5]))

    # ── IsolationForest trained on benign-only ─────────────────────────────
    logger.info("Training IsolationForest on benign samples only…")
    benign_X = X[np.array(y) == "Benign"]
    iso = _IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(benign_X)
    _joblib.dump(iso, if_path)
    logger.info(f"  Saved → {if_path}")

    return {
        "status":       "trained",
        "rf":           str(rf_path),
        "if":           str(if_path),
        "encoder":      str(enc_path),
        "n_samples":    len(X),
        "f1_macro":     round(f1, 3),
        "classes":      list(le.classes_),
        "top_features": [(n, round(v, 4)) for n, v in fi[:5]],
    }


def ensure_models(models_dir: Path = MODELS_DIR) -> bool:
    """
    Called at startup. Trains models if not present.
    Returns True when models are ready.
    Fast path (~0ms) if .joblib files exist. Slow path (~5–10s) on first run.
    """
    # ── Auto-install sklearn if missing ───────────────────────────────────
    global _SKLEARN_OK
    if not _SKLEARN_OK:
        logger.info("scikit-learn missing — attempting auto-install …")
        import subprocess, sys
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "scikit-learn", "joblib",
             "--break-system-packages", "--quiet"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            try:
                from sklearn.ensemble import RandomForestClassifier as _RFC      # noqa
                from sklearn.ensemble import IsolationForest as _IsolationForest # noqa
                from sklearn.preprocessing import LabelEncoder as _LabelEncoder  # noqa
                import joblib as _joblib                                          # noqa
                _SKLEARN_OK = True
                logger.info("scikit-learn installed and imported successfully")
            except ImportError as e:
                logger.error(f"sklearn install succeeded but import still failed: {e}")
        else:
            logger.error(f"sklearn auto-install failed: {r.stderr[:300]}")

    rf  = models_dir / "rf_attack_model.joblib"
    iso = models_dir / "anomaly_model.joblib"
    if rf.exists() and iso.exists():
        logger.info(f"ML models present: {rf.name}, {iso.name}")
        sklearn_ok = True
    else:
        logger.info("ML models not found — running first-time training…")
        result = train_and_save(models_dir=models_dir)
        sklearn_ok = result.get("status") in ("trained", "skipped")
        if sklearn_ok:
            logger.info(f"ML models ready (F1={result.get('f1_macro', '?')})")
        else:
            logger.error(f"Model training failed: {result.get('reason', 'unknown')}")

    # ── Also ensure LSTM is trained ────────────────────────────────────────
    lstm_pt    = models_dir / "lstm_detector.pt"
    lstm_keras = models_dir / "lstm_detector.keras"
    if not lstm_pt.exists() and not lstm_keras.exists():
        logger.info("LSTM model not found — launching background training …")
        import subprocess, sys, threading
        def _run_lstm():
            r = subprocess.run(
                [sys.executable, "ml/lstm/trainer.py"],
                capture_output=True, text=True, timeout=600
            )
            if r.returncode == 0:
                logger.info("LSTM background training complete — model ready")
            else:
                logger.warning(f"LSTM background training failed:\n{r.stderr[-400:]}")
        threading.Thread(target=_run_lstm, daemon=True, name="lstm-first-train").start()
    else:
        logger.info("LSTM model present — no training needed")

    return sklearn_ok
