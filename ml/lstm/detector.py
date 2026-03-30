"""
CyberRemedy — LSTM Sequential Anomaly Detector (Inference Engine)
=================================================================
Loads the trained Bidirectional LSTM and scores live network flows.

Backend compatibility
─────────────────────
  The detector reads models/lstm_config.json to discover which backend
  (tensorflow or torch) was used during training, then loads accordingly.
  This means the model will always load correctly regardless of whether
  it was trained on Python 3.8-3.12 (TF) or 3.13+ (PyTorch).

Usage:
  lstm_engine = LSTMDetector()
  lstm_engine.load()               # auto-selects backend from config
  alert = lstm_engine.analyze(flow)  # None if normal, dict if attack
"""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np

logger = logging.getLogger("cyberremedy.detection.lstm")

MODELS_DIR  = Path("models")
MODEL_PATH_KERAS = MODELS_DIR / "lstm_detector.keras"
MODEL_PATH_PT    = MODELS_DIR / "lstm_detector.pt"
SCALER_PATH = MODELS_DIR / "lstm_scaler.joblib"
CONFIG_PATH = MODELS_DIR / "lstm_config.json"

# ── MITRE mapping for sequence patterns ───────────────────────────────────────
_SEQUENCE_MITRE = {
    "Port Scan":       ("T1046", "MEDIUM"),
    "Brute Force":     ("T1110", "HIGH"),
    "Lateral Move":    ("T1021", "HIGH"),
    "Data Exfil":      ("T1041", "CRITICAL"),
    "C2 Beacon":       ("T1071", "HIGH"),
    "Privilege Abuse": ("T1068", "HIGH"),
    "Unknown Attack":  ("T1059", "MEDIUM"),
}

_alert_id_counter = 9000


# ══════════════════════════════════════════════════════════════════════════════
# Backend loaders
# ══════════════════════════════════════════════════════════════════════════════

def _load_tf(model_path: Path):
    """Load a TensorFlow/Keras model. Returns (model, predict_fn)."""
    import tensorflow as tf
    model = tf.keras.models.load_model(model_path)

    def predict(seq_np: np.ndarray) -> float:
        return float(model.predict(seq_np, verbose=0)[0, 0])

    return model, predict


def _load_torch(model_path: Path, n_features: int, window_size: int):
    """Load a PyTorch model. Returns (model, predict_fn)."""
    import torch
    import torch.nn as nn

    class BiLSTMNet(nn.Module):
        def __init__(self, n_feat: int) -> None:
            super().__init__()
            self.lstm1 = nn.LSTM(n_feat, 64, batch_first=True, bidirectional=True)
            self.drop1 = nn.Dropout(0.3)
            self.bn1   = nn.BatchNorm1d(128)
            self.lstm2 = nn.LSTM(128, 32, batch_first=True, bidirectional=True)
            self.drop2 = nn.Dropout(0.3)
            self.bn2   = nn.BatchNorm1d(64)
            self.fc1   = nn.Linear(64, 32)
            self.drop3 = nn.Dropout(0.2)
            self.fc2   = nn.Linear(32, 1)
            self.relu  = nn.ReLU()
            self.sig   = nn.Sigmoid()

        def forward(self, x):
            out, _ = self.lstm1(x)
            out    = self.drop1(out)
            out    = self.bn1(out.permute(0, 2, 1)).permute(0, 2, 1)
            out, _ = self.lstm2(out)
            out    = out[:, -1, :]
            out    = self.drop2(out)
            out    = self.bn2(out)
            out    = self.relu(self.fc1(out))
            out    = self.drop3(out)
            return self.sig(self.fc2(out)).squeeze(1)

    device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt      = torch.load(model_path, map_location=device, weights_only=True)
    n_feat    = ckpt.get("n_features", n_features)
    net       = BiLSTMNet(n_feat).to(device)
    net.load_state_dict(ckpt["state_dict"])
    net.eval()

    def predict(seq_np: np.ndarray) -> float:
        with torch.no_grad():
            t = torch.from_numpy(seq_np).float().to(device)
            return float(net(t).cpu().numpy()[0])

    return net, predict


# ══════════════════════════════════════════════════════════════════════════════
# LSTMDetector
# ══════════════════════════════════════════════════════════════════════════════

class LSTMDetector:
    """
    Real-time LSTM-based sequential anomaly detector.

    Maintains a per-source-IP sliding window of recent flow feature vectors.
    When the window fills up, runs the LSTM and emits an alert if the score
    exceeds the trained threshold.

    Works with models trained by either the TensorFlow or PyTorch backend —
    the backend is read automatically from lstm_config.json.
    """

    def __init__(self) -> None:
        self._predict_fn = None
        self._scaler     = None
        self._config: dict = {}
        self._ready      = False
        self._lock       = threading.Lock()
        self._windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self._stats = {
            "flows_scored":   0,
            "alerts_emitted": 0,
            "model_loaded":   False,
            "threshold":      0.5,
            "backend":        "none",
        }

    # ── Model loading ──────────────────────────────────────────────────────────

    def load(self) -> bool:
        """
        Load trained model from disk.
        Backend (tensorflow / torch) is detected from lstm_config.json.
        Returns True on success.
        """
        if not CONFIG_PATH.exists():
            logger.info("[LSTM] No config found — run: python3 ml/lstm/trainer.py")
            return False

        try:
            import joblib
        except ImportError:
            logger.warning("[LSTM] joblib not installed — cannot load scaler")
            return False

        if not SCALER_PATH.exists():
            logger.info("[LSTM] Scaler not found — run: python3 ml/lstm/trainer.py")
            return False

        try:
            self._config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error(f"[LSTM] Bad config file: {exc}")
            return False

        backend    = self._config.get("backend", "tensorflow")
        n_features = self._config.get("n_features", 41)
        window     = self._config.get("window_size", 10)

        # Load the right model file
        if backend == "tensorflow":
            if not MODEL_PATH_KERAS.exists():
                logger.info(
                    "[LSTM] TF model file missing — retrain: python3 ml/lstm/trainer.py"
                )
                return False
            try:
                _, self._predict_fn = _load_tf(MODEL_PATH_KERAS)
            except ImportError:
                logger.error(
                    "[LSTM] Model was trained with TensorFlow but TF is not installed. "
                    "Retrain with PyTorch: python3 ml/lstm/trainer.py --retrain --backend torch"
                )
                return False
            except Exception as exc:
                logger.error(f"[LSTM] TF model load failed: {exc}")
                return False

        elif backend == "torch":
            if not MODEL_PATH_PT.exists():
                logger.info(
                    "[LSTM] PyTorch model file missing — retrain: python3 ml/lstm/trainer.py"
                )
                return False
            try:
                _, self._predict_fn = _load_torch(MODEL_PATH_PT, n_features, window)
            except ImportError:
                logger.error(
                    "[LSTM] Model was trained with PyTorch but torch is not installed. "
                    "Install: pip install torch"
                )
                return False
            except Exception as exc:
                logger.error(f"[LSTM] PyTorch model load failed: {exc}")
                return False

        else:
            logger.error(f"[LSTM] Unknown backend in config: {backend!r}")
            return False

        try:
            self._scaler = joblib.load(SCALER_PATH)
        except Exception as exc:
            logger.error(f"[LSTM] Scaler load failed: {exc}")
            return False

        self._stats["threshold"]   = self._config.get("threshold", 0.5)
        self._stats["model_loaded"] = True
        self._stats["backend"]     = backend
        self._ready                = True

        logger.info(
            f"[LSTM] Model loaded — backend={backend}  "
            f"window={window}  threshold={self._stats['threshold']:.2f}  "
            f"AUC={self._config.get('test_auc', 0):.3f}"
        )
        return True

    # ── Feature extraction ─────────────────────────────────────────────────────

    @staticmethod
    def _flow_to_vector(flow: dict) -> np.ndarray:
        """Map a CyberRemedy flow dict to the NSL-KDD-compatible 41-feature vector."""
        proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "DNS": 1, "OTHER": 2}
        flag_map  = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTR": 4, "S": 5}

        proto    = flow.get("protocol", "OTHER").upper()
        flags    = flow.get("flags", "")
        dst_p    = int(flow.get("dst_port", 0) or 0)
        duration = float(flow.get("duration", 0) or 0)
        src_b    = float(flow.get("byte_count", flow.get("bytes", 0)) or 0)
        logged_in  = 1.0 if dst_p in (22, 21, 23, 3389, 80, 443) else 0.0
        count      = float(flow.get("pkt_count", 1) or 1)
        serror_r   = 1.0 if "S0" in flags or "REJ" in flags else 0.0
        rerror_r   = 1.0 if "RST" in flags.upper() or "R" in flags else 0.0
        same_srv   = 1.0 if flow.get("dst_private", False) else 0.0
        diff_srv   = 0.0 if same_srv else 1.0
        bps        = float(flow.get("bps", 0) or 0)

        return np.array([
            duration,
            float(proto_map.get(proto, 2)),
            float(hash(flow.get("service", "other")) % 70),
            float(flag_map.get(flags[:2] if flags else "SF", 0)),
            src_b, 0.0, 0.0, 0.0, 0.0,
            float(flow.get("flag_syn", 0)),
            0.0, logged_in,
            float(flow.get("flag_rst", 0)),
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            min(count, 511), min(count, 511),
            serror_r, serror_r, rerror_r, rerror_r,
            same_srv, diff_srv, 0.0,
            min(float(flow.get("unique_dports", 1)), 255),
            min(float(flow.get("unique_dports", 1)), 255),
            same_srv, diff_srv,
            min(bps / 1e6, 1.0),
            0.0, serror_r, serror_r, rerror_r, rerror_r,
        ], dtype=np.float32)

    # ── Inference ──────────────────────────────────────────────────────────────

    def analyze(self, flow: dict) -> Optional[dict]:
        """
        Score a flow against the LSTM.
        Returns an alert dict if the sequence score exceeds threshold, else None.
        """
        if not self._ready:
            return None

        src_ip = flow.get("src_ip", "unknown")
        vec    = self._flow_to_vector(flow)

        with self._lock:
            window = self._windows[src_ip]
            window.append(vec)
            self._stats["flows_scored"] += 1
            window_size = self._config.get("window_size", 10)
            if len(window) < window_size:
                return None
            seq = np.array(list(window)[-window_size:], dtype=np.float32)

        try:
            n_feat = seq.shape[1]
            flat_s = self._scaler.transform(seq.reshape(-1, n_feat))
            seq_s  = flat_s.reshape(1, window_size, n_feat)
            score  = self._predict_fn(seq_s)
        except Exception as exc:
            logger.debug(f"[LSTM] Inference error for {src_ip}: {exc}")
            return None

        if score < self._stats["threshold"]:
            return None

        with self._lock:
            self._stats["alerts_emitted"] += 1

        return self._make_alert(flow, score, src_ip)

    def _make_alert(self, flow: dict, score: float, src_ip: str) -> dict:
        global _alert_id_counter
        _alert_id_counter += 1
        attack_type, mitre_id, severity = self._classify_sequence(flow, score)
        return {
            "id":            _alert_id_counter,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "severity":      severity,
            "type":          f"[LSTM] {attack_type}",
            "src_ip":        src_ip,
            "dst_ip":        flow.get("dst_ip", "?"),
            "src_port":      flow.get("src_port", 0),
            "dst_port":      flow.get("dst_port", 0),
            "protocol":      flow.get("protocol", "?"),
            "mitre_id":      mitre_id,
            "confidence":    round(score * 100),
            "detail": (
                f"LSTM sequence score {score:.3f} > threshold "
                f"{self._stats['threshold']:.2f}. "
                f"Sequential attack pattern detected for {src_ip}."
            ),
            "anomaly_score": round(score, 4),
            "status":        "OPEN",
            "source":        "lstm_sequence",
            "packets":       flow.get("pkt_count", 0),
            "bytes":         flow.get("byte_count", 0),
            "correlated":    False,
        }

    @staticmethod
    def _classify_sequence(flow: dict, score: float) -> tuple:
        dst_p = int(flow.get("dst_port", 0) or 0)
        pps   = float(flow.get("pps", 0) or 0)
        bps   = float(flow.get("bps", 0) or 0)
        dur   = float(flow.get("duration", 0) or 0)
        flags = flow.get("flags", "")

        if pps > 100 or "S0" in flags:
            return "Port Scan Sequence",      "T1046", "HIGH"
        if dst_p in (22, 3389, 21, 23, 445) and pps > 10:
            return "Brute Force Sequence",    "T1110", "HIGH"
        if dst_p in (445, 3389, 5985, 135) and bps < 50_000:
            return "Lateral Movement Sequence","T1021", "HIGH"
        if bps > 500_000 and flow.get("direction") == "outgoing":
            return "Data Exfiltration Sequence","T1041","CRITICAL"
        if dur > 30 and pps < 2:
            return "C2 Beaconing Sequence",   "T1071", "HIGH"

        severity = "CRITICAL" if score > 0.9 else "HIGH" if score > 0.75 else "MEDIUM"
        return "Unknown Attack Sequence", "T1059", severity

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def clear_window(self, src_ip: str) -> None:
        """Clear the sliding window for a source IP (e.g. after blocking)."""
        with self._lock:
            self._windows.pop(src_ip, None)
