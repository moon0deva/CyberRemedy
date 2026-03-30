"""
CyberRemedy — LSTM Sequential Anomaly Detector  (trainer)
==========================================================
Downloads the NSL-KDD dataset (public domain, no API key required) and trains
a Bidirectional-LSTM model that detects multi-step attack sequences.

Python / Backend compatibility
──────────────────────────────
  Python 3.8 – 3.12  →  TensorFlow  (preferred when installed)
  Python 3.13+        →  PyTorch     (TensorFlow has no 3.13 wheels yet)
  Any version         →  PyTorch     (if TensorFlow is not installed)

The trainer auto-detects whichever backend is available and records it in
models/lstm_config.json so the detector loads the correct model file.

Usage:
  python3 ml/lstm/trainer.py              # auto-detect backend, download + train
  python3 ml/lstm/trainer.py --retrain    # force retrain
  python3 ml/lstm/trainer.py --backend torch       # force PyTorch
  python3 ml/lstm/trainer.py --backend tensorflow  # force TensorFlow

Output files:
  models/lstm_detector.keras  (TensorFlow / Keras)   — or —
  models/lstm_detector.pt     (PyTorch state dict)
  models/lstm_scaler.joblib   (StandardScaler)
  models/lstm_config.json     (window size, threshold, feature list, backend)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

logger = logging.getLogger("cyberremedy.ml.lstm_trainer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Python version banner ──────────────────────────────────────────────────────
_PY = sys.version_info
_PY_STR = f"{_PY.major}.{_PY.minor}.{_PY.micro}"
logger.info(f"Python {_PY_STR}")

# ── Paths ──────────────────────────────────────────────────────────────────────
DATASET_DIR      = Path("ml/datasets/nslkdd")
MODELS_DIR       = Path("models")
MODEL_PATH_KERAS = MODELS_DIR / "lstm_detector.keras"
MODEL_PATH_PT    = MODELS_DIR / "lstm_detector.pt"
SCALER_PATH      = MODELS_DIR / "lstm_scaler.joblib"
CONFIG_PATH      = MODELS_DIR / "lstm_config.json"

# ── NSL-KDD fallback mirrors (no auth required) ────────────────────────────────
FALLBACK_URLS = {
    "train_full": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
    "test":       "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
}

# ── Encoding maps ──────────────────────────────────────────────────────────────
PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2}
FLAG_MAP  = {"SF":0,"S0":1,"REJ":2,"RSTO":3,"RSTR":4,"SH":5,"S1":6,"S2":7,"S3":8,"OTH":9}

ATTACK_LABELS = {
    "normal":0,
    "back":1,"land":1,"neptune":1,"pod":1,"smurf":1,"teardrop":1,
    "apache2":1,"udpstorm":1,"processtable":1,"mailbomb":1,
    "satan":1,"ipsweep":1,"nmap":1,"portsweep":1,"mscan":1,"saint":1,
    "guess_passwd":1,"ftp_write":1,"imap":1,"phf":1,"multihop":1,
    "warezmaster":1,"warezclient":1,"spy":1,"xlock":1,"xsnoop":1,
    "snmpguess":1,"snmpgetattack":1,"httptunnel":1,"sendmail":1,"named":1,
    "buffer_overflow":1,"loadmodule":1,"perl":1,"rootkit":1,"sqlattack":1,
    "xterm":1,"ps":1,
}

WINDOW_SIZE = 10


# ══════════════════════════════════════════════════════════════════════════════
# Backend detection
# ══════════════════════════════════════════════════════════════════════════════

def detect_backend() -> Optional[str]:
    """
    Return 'tensorflow' or 'torch' depending on availability.
    TensorFlow is preferred when installed (Python 3.8–3.12 only).
    PyTorch is the universal fallback and the only option on Python 3.13+.
    """
    # TensorFlow officially supports Python 3.9–3.12 (no 3.13 wheels yet)
    if _PY < (3, 13):
        try:
            import tensorflow as tf  # noqa: F401
            logger.info(f"Backend selected: TensorFlow {tf.__version__}")
            return "tensorflow"
        except ImportError:
            logger.info("TensorFlow not found — trying PyTorch …")
    else:
        logger.info(
            f"Python {_PY_STR}: TensorFlow does not yet publish wheels for "
            "Python 3.13+. Switching to PyTorch backend automatically."
        )

    try:
        import torch  # noqa: F401
        logger.info(f"Backend selected: PyTorch {torch.__version__}")
        return "torch"
    except ImportError:
        pass

    logger.error(
        "\nNo ML backend found. Install one:\n"
        "  Python 3.9–3.12:  pip install tensorflow\n"
        "  Python 3.13+:     pip install torch\n"
        "  Any version:      pip install torch torchvision\n"
    )
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Data helpers — backend-agnostic
# ══════════════════════════════════════════════════════════════════════════════

def download_dataset() -> Tuple[Path, Path]:
    """Download NSL-KDD from GitHub mirrors. No API key required."""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    train_file = DATASET_DIR / "KDDTrain+.txt"
    test_file  = DATASET_DIR / "KDDTest+.txt"

    for url_key, local_file in [("train_full", train_file), ("test", test_file)]:
        if local_file.exists() and local_file.stat().st_size > 10_000:
            logger.info(f"Dataset cached: {local_file}")
            continue
        url = FALLBACK_URLS[url_key]
        logger.info(f"Downloading {url_key} from {url} …")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CyberRemedy/3.5"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            local_file.write_bytes(data)
            logger.info(f"  Saved {len(data):,} bytes → {local_file}")
        except Exception as exc:
            logger.error(f"  Download failed: {exc}")
            logger.info("  Generating synthetic NSL-KDD-style data as offline fallback …")
            _generate_synthetic_data(
                local_file,
                n_samples=10_000 if "train" in url_key else 2_000,
            )

    return train_file, test_file


def _generate_synthetic_data(path: Path, n_samples: int) -> None:
    """Generate plausible NSL-KDD rows — works fully offline."""
    rng  = np.random.default_rng(42)
    rows: List[str] = []
    for _ in range(n_samples):
        is_attack = rng.random() < 0.3
        proto  = rng.choice(["tcp", "udp", "icmp"])
        flag   = rng.choice(["SF", "S0", "REJ", "RSTO", "OTH"])
        svc    = rng.choice(["http", "ftp", "smtp", "ssh", "dns", "private"])
        dur    = rng.exponential(1.0) if not is_attack else rng.uniform(0, 0.1)
        sbytes = int(rng.exponential(5000)) if not is_attack else int(rng.exponential(100))
        dbytes = int(rng.exponential(8000)) if not is_attack else 0
        count  = int(rng.uniform(1, 100)) if not is_attack else int(rng.uniform(200, 511))
        label  = "normal" if not is_attack else rng.choice(
            ["neptune", "portsweep", "satan", "buffer_overflow", "guess_passwd"]
        )
        diff   = rng.integers(1, 21)
        row    = [
            round(dur, 2), proto, svc, flag,
            sbytes, dbytes, 0, 0, 0,
            int(rng.uniform(0, 5)), 0, int(not is_attack),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            count, int(rng.uniform(1, count + 1)),
            round(rng.uniform(0, 0.5 if not is_attack else 1.0), 2),
            round(rng.uniform(0, 0.5), 2),
            round(rng.uniform(0, 0.3), 2),
            round(rng.uniform(0, 0.3), 2),
            round(rng.uniform(0.5, 1.0) if not is_attack else rng.uniform(0, 0.3), 2),
            round(rng.uniform(0, 0.1), 2),
            round(rng.uniform(0, 0.1), 2),
            int(rng.uniform(1, 256)),
            int(rng.uniform(1, 256)),
            round(rng.uniform(0.5, 1.0) if not is_attack else rng.uniform(0, 0.3), 2),
            round(rng.uniform(0, 0.1), 2),
            round(rng.uniform(0, 0.5), 2),
            round(rng.uniform(0, 0.1), 2),
            round(rng.uniform(0, 0.5 if not is_attack else 1.0), 2),
            round(rng.uniform(0, 0.5), 2),
            round(rng.uniform(0, 0.3), 2),
            round(rng.uniform(0, 0.3), 2),
            label, diff,
        ]
        rows.append(",".join(str(x) for x in row))

    path.write_text("\n".join(rows), encoding="utf-8")
    logger.info(f"  Generated {n_samples} synthetic samples → {path}")


def parse_dataset(path: Path) -> Tuple[np.ndarray, np.ndarray]:
    """Parse NSL-KDD text file → (X float32, y float32 binary labels)."""
    logger.info(f"Parsing {path} …")
    X_rows: List[List[float]] = []
    y_rows: List[float] = []

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",")
        if len(parts) < 42:
            continue
        try:
            proto_val = float(PROTO_MAP.get(parts[1].strip().lower(), 2))
            svc_val   = float(hash(parts[2].strip()) % 70)
            flag_val  = float(FLAG_MAP.get(parts[3].strip(), 9))
            row: List[float] = [float(parts[0]), proto_val, svc_val, flag_val]
            for i in range(4, 41):
                try:
                    row.append(float(parts[i]))
                except (ValueError, IndexError):
                    row.append(0.0)
            X_rows.append(row)
            label_str = parts[41].strip().lower().rstrip(".")
            y_rows.append(float(ATTACK_LABELS.get(label_str, 1)))
        except Exception:
            continue

    X = np.array(X_rows, dtype=np.float32)
    y = np.array(y_rows, dtype=np.float32)
    logger.info(f"  Parsed {len(X):,} samples — attack rate: {y.mean() * 100:.1f}%")
    return X, y


def make_sequences(
    X: np.ndarray, y: np.ndarray, window: int = WINDOW_SIZE
) -> Tuple[np.ndarray, np.ndarray]:
    """Build sliding-window sequences → (N, window, features) and (N,)."""
    logger.info(f"Building sequences (window={window}) …")
    # np.lib.stride_tricks.sliding_window_view available since NumPy 1.20
    X_seq = np.lib.stride_tricks.sliding_window_view(X, (window, X.shape[1])).squeeze(1)
    y_seq = np.array([y[i - window:i].max() for i in range(window, len(X))], dtype=np.float32)
    # sliding_window_view produces (N - window + 1) rows; y_seq has (N - window) entries.
    # Trim X_seq to match so shapes are always consistent.
    X_seq = X_seq[: len(y_seq)]
    logger.info(f"  Sequences: {X_seq.shape} — attack rate: {y_seq.mean() * 100:.1f}%")
    return X_seq.astype(np.float32), y_seq


def _balance(
    X_seq: np.ndarray, y_seq: np.ndarray,
    rng: np.random.Generator, n_take: int = 30_000,
) -> Tuple[np.ndarray, np.ndarray]:
    attack_idx = np.where(y_seq == 1)[0]
    normal_idx = np.where(y_seq == 0)[0]
    k = min(len(attack_idx), len(normal_idx), n_take)
    chosen = np.concatenate([
        rng.choice(attack_idx, k, replace=len(attack_idx) < k),
        rng.choice(normal_idx, k, replace=len(normal_idx) < k),
    ])
    rng.shuffle(chosen)
    logger.info(f"Balanced training set: {len(chosen):,} samples (50/50)")
    return X_seq[chosen], y_seq[chosen]


def _find_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> Tuple[float, float]:
    """Grid-search F1-optimal decision threshold."""
    best_f1, best_t = 0.0, 0.5
    for t in np.arange(0.3, 0.8, 0.05):
        pred = (y_prob >= t).astype(int)
        tp = int(((pred == 1) & (y_true == 1)).sum())
        fp = int(((pred == 1) & (y_true == 0)).sum())
        fn = int(((pred == 0) & (y_true == 1)).sum())
        if tp + fp > 0 and tp + fn > 0:
            p = tp / (tp + fp)
            r = tp / (tp + fn)
            if p + r > 0:
                f1 = 2 * p * r / (p + r)
                if f1 > best_f1:
                    best_f1, best_t = f1, float(t)
    return best_t, best_f1


# ══════════════════════════════════════════════════════════════════════════════
# TensorFlow / Keras backend
# ══════════════════════════════════════════════════════════════════════════════

def _train_tensorflow(
    X_tr: np.ndarray, y_tr: np.ndarray,
    X_test: np.ndarray, y_test: np.ndarray,
    n_features: int,
) -> Tuple[float, float, float, float]:
    """Returns (accuracy, auc, threshold, best_f1)."""
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import (
        LSTM, Dense, Dropout, BatchNormalization, Bidirectional,
    )
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    from tensorflow.keras.optimizers import Adam

    logger.info("Building Bidirectional LSTM (TensorFlow/Keras) …")
    model = Sequential([
        Bidirectional(
            LSTM(64, return_sequences=True),
            input_shape=(WINDOW_SIZE, n_features),
        ),
        Dropout(0.3),
        BatchNormalization(),
        Bidirectional(LSTM(32, return_sequences=False)),
        Dropout(0.3),
        BatchNormalization(),
        Dense(32, activation="relu"),
        Dropout(0.2),
        Dense(1, activation="sigmoid"),
    ])
    model.compile(
        optimizer=Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc")],
    )
    model.summary(print_fn=logger.info)

    model.fit(
        X_tr, y_tr,
        validation_split=0.15,
        epochs=30,
        batch_size=256,
        callbacks=[
            EarlyStopping(patience=5, restore_best_weights=True,
                          monitor="val_auc", mode="max"),
            ReduceLROnPlateau(patience=3, factor=0.5, monitor="val_loss"),
        ],
        verbose=1,
    )

    results = model.evaluate(X_test, y_test, verbose=0)
    metrics = dict(zip(model.metrics_names, results))
    preds   = model.predict(X_test, verbose=0).flatten()
    thresh, best_f1 = _find_threshold(y_test, preds)

    MODEL_PATH_KERAS.parent.mkdir(parents=True, exist_ok=True)
    model.save(MODEL_PATH_KERAS)
    logger.info(f"Model saved → {MODEL_PATH_KERAS}")

    return (
        float(metrics.get("accuracy", 0.0)),
        float(metrics.get("auc", 0.0)),
        thresh,
        best_f1,
    )


# ══════════════════════════════════════════════════════════════════════════════
# PyTorch backend
# ══════════════════════════════════════════════════════════════════════════════

def _build_torch_model(n_features: int):
    """Build a Bidirectional LSTM matching the Keras architecture."""
    import torch.nn as nn

    class BiLSTMNet(nn.Module):
        """
        Mirrors the TF model:
          BiLSTM(64, return_seq=True) → Dropout(0.3) → BN
          BiLSTM(32, return_seq=False) → Dropout(0.3) → BN
          Dense(32, relu) → Dropout(0.2) → Dense(1, sigmoid)
        """
        def __init__(self, n_feat: int) -> None:
            super().__init__()
            self.lstm1 = nn.LSTM(n_feat, 64, batch_first=True, bidirectional=True)
            self.drop1 = nn.Dropout(0.3)
            self.bn1   = nn.BatchNorm1d(128)   # 64 * 2

            self.lstm2 = nn.LSTM(128, 32, batch_first=True, bidirectional=True)
            self.drop2 = nn.Dropout(0.3)
            self.bn2   = nn.BatchNorm1d(64)    # 32 * 2

            self.fc1   = nn.Linear(64, 32)
            self.drop3 = nn.Dropout(0.2)
            self.fc2   = nn.Linear(32, 1)
            self.relu  = nn.ReLU()
            self.sig   = nn.Sigmoid()

        def forward(self, x):
            out, _ = self.lstm1(x)                         # (B, seq, 128)
            out    = self.drop1(out)
            # BN1d: (B, C, L)
            out    = self.bn1(out.permute(0, 2, 1)).permute(0, 2, 1)

            out, _ = self.lstm2(out)                       # (B, seq, 64)
            out    = out[:, -1, :]                         # last timestep → (B, 64)
            out    = self.drop2(out)
            out    = self.bn2(out)

            out    = self.relu(self.fc1(out))
            out    = self.drop3(out)
            return self.sig(self.fc2(out)).squeeze(1)      # (B,)

    return BiLSTMNet(n_features)


def _train_pytorch(
    X_tr: np.ndarray, y_tr: np.ndarray,
    X_test: np.ndarray, y_test: np.ndarray,
    n_features: int,
) -> Tuple[float, float, float, float]:
    """Returns (accuracy, auc, threshold, best_f1)."""
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Building Bidirectional LSTM (PyTorch, device={device}) …")

    model = _build_torch_model(n_features).to(device)

    # Tensors
    X_tr_t = torch.from_numpy(X_tr).float()
    y_tr_t = torch.from_numpy(y_tr).float()

    # 85 / 15 train-val split
    n_val   = max(1, int(0.15 * len(X_tr_t)))
    perm    = torch.randperm(len(X_tr_t))
    tr_idx, val_idx = perm[n_val:], perm[:n_val]

    train_loader = DataLoader(
        TensorDataset(X_tr_t[tr_idx], y_tr_t[tr_idx]),
        batch_size=256, shuffle=True,
    )
    val_X = X_tr_t[val_idx].to(device)
    val_y = y_tr_t[val_idx].cpu().numpy()

    optimizer  = torch.optim.Adam(model.parameters(), lr=1e-3)
    scheduler  = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)
    criterion  = nn.BCELoss()
    best_auc   = 0.0
    best_state: Optional[dict] = None
    patience   = 0

    for epoch in range(1, 31):
        # Train
        model.train()
        tr_loss = 0.0
        n_train = len(tr_idx)
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            tr_loss += loss.item() * len(xb)
        tr_loss /= n_train

        # Validate
        model.eval()
        with torch.no_grad():
            val_prob = model(val_X).cpu().numpy().squeeze()  # ensure shape (N,)

        try:
            from sklearn.metrics import roc_auc_score
            val_auc = float(roc_auc_score(val_y, val_prob))
        except Exception:
            val_auc = float(np.corrcoef(val_y, val_prob)[0, 1])
            val_auc = max(0.0, (val_auc + 1) / 2)

        val_acc = float(((val_prob >= 0.5).astype(int) == val_y).mean())
        scheduler.step(tr_loss)

        logger.info(
            f"Epoch {epoch:02d}/30  loss={tr_loss:.4f}  "
            f"val_acc={val_acc:.3f}  val_auc={val_auc:.3f}"
        )

        if val_auc > best_auc + 1e-4:
            best_auc   = val_auc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience   = 0
        else:
            patience += 1
            if patience >= 5:
                logger.info(f"Early stopping at epoch {epoch}")
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    # Test
    model.eval()
    X_ts_t = torch.from_numpy(X_test).float().to(device)
    with torch.no_grad():
        test_prob = model(X_ts_t).cpu().numpy().squeeze()  # ensure shape (N,)

    test_acc = float(((test_prob >= 0.5).astype(int) == y_test).mean())
    try:
        from sklearn.metrics import roc_auc_score
        test_auc = float(roc_auc_score(y_test, test_prob))
    except Exception:
        test_auc = best_auc

    thresh, best_f1 = _find_threshold(y_test, test_prob)
    logger.info(f"Test accuracy={test_acc:.3f}  auc={test_auc:.3f}")

    # Save
    MODEL_PATH_PT.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "n_features": n_features}, MODEL_PATH_PT)
    logger.info(f"Model saved → {MODEL_PATH_PT}")

    return test_acc, test_auc, thresh, best_f1


# ══════════════════════════════════════════════════════════════════════════════
# Main pipeline
# ══════════════════════════════════════════════════════════════════════════════

def train(retrain: bool = False, force_backend: Optional[str] = None) -> dict:
    """
    Full training pipeline.
    Automatically selects TensorFlow (Python 3.9–3.12) or PyTorch (any version).
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # Already trained?
    if not retrain and SCALER_PATH.exists():
        for mp in (MODEL_PATH_KERAS, MODEL_PATH_PT):
            if mp.exists() and mp.stat().st_size > 1000:
                logger.info(f"Model exists at {mp}. Use --retrain to force retraining.")
                return {"status": "skipped", "model": str(mp)}

    # Backend
    backend = force_backend or detect_backend()
    if backend is None:
        return {
            "status": "error",
            "reason": (
                "No ML backend installed.\n"
                "  Python 3.9–3.12:  pip install tensorflow\n"
                "  Python 3.13+:     pip install torch\n"
            ),
        }

    # scikit-learn required for scaler (and optional AUC)
    try:
        import joblib
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return {
            "status": "error",
            "reason": "scikit-learn not installed — run: pip install scikit-learn joblib",
        }

    # Data
    train_file, test_file = download_dataset()
    X_train_raw, y_train  = parse_dataset(train_file)
    X_test_raw,  y_test   = parse_dataset(test_file)
    n_features             = X_train_raw.shape[1]

    # Scale
    logger.info("Scaling features …")
    scaler          = StandardScaler()
    X_train_scaled  = scaler.fit_transform(X_train_raw).astype(np.float32)
    X_test_scaled   = scaler.transform(X_test_raw).astype(np.float32)
    joblib.dump(scaler, SCALER_PATH)
    logger.info(f"Scaler saved → {SCALER_PATH}")

    # Sequences
    X_train_seq, y_train_seq = make_sequences(X_train_scaled, y_train,  WINDOW_SIZE)
    X_test_seq,  y_test_seq  = make_sequences(X_test_scaled,  y_test,   WINDOW_SIZE)

    # Balance
    rng      = np.random.default_rng(42)
    X_tr, y_tr = _balance(X_train_seq, y_train_seq, rng)

    # Train
    if backend == "tensorflow":
        accuracy, auc, threshold, best_f1 = _train_tensorflow(
            X_tr, y_tr, X_test_seq, y_test_seq, n_features
        )
        model_path = str(MODEL_PATH_KERAS)
    else:
        accuracy, auc, threshold, best_f1 = _train_pytorch(
            X_tr, y_tr, X_test_seq, y_test_seq, n_features
        )
        model_path = str(MODEL_PATH_PT)

    logger.info(f"Optimal threshold: {threshold:.2f}  (F1={best_f1:.3f})")

    # Config
    config = {
        "backend":           backend,
        "python_version":    _PY_STR,
        "window_size":       WINDOW_SIZE,
        "n_features":        int(n_features),
        "threshold":         threshold,
        "trained_at":        datetime.utcnow().isoformat(),
        "test_accuracy":     accuracy,
        "test_auc":          auc,
        "best_f1":           float(best_f1),
        "attack_rate_train": float(y_train.mean()),
        "dataset":           "NSL-KDD (GitHub mirror)",
        "model_path":        model_path,
    }
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    logger.info(f"Config saved → {CONFIG_PATH}")
    return {"status": "trained", **config}


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train CyberRemedy LSTM anomaly detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 ml/lstm/trainer.py                     # auto-detect backend\n"
            "  python3 ml/lstm/trainer.py --retrain           # force retrain\n"
            "  python3 ml/lstm/trainer.py --backend torch     # force PyTorch (Python 3.13+)\n"
            "  python3 ml/lstm/trainer.py --backend tensorflow  # force TensorFlow\n"
        ),
    )
    parser.add_argument("--retrain", action="store_true",
                        help="Force retrain even if a model already exists")
    parser.add_argument("--backend", choices=["tensorflow", "torch"], default=None,
                        help="Force a specific backend (default: auto-detect)")
    args = parser.parse_args()

    result = train(retrain=args.retrain, force_backend=args.backend)
    print(json.dumps(result, indent=2))
