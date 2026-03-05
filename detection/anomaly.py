"""
AID-ARS ML Anomaly Detection Engine
Isolation Forest for unknown/zero-day detection.
RandomForest classifier for known attack classification.
Falls back to heuristic scoring when no model is trained.
"""

import os
import logging
import numpy as np
from typing import Optional, List, Tuple
from datetime import datetime

logger = logging.getLogger("aidars.detection.anomaly")

# Feature columns used for ML (numeric only)
FEATURE_COLS = [
    "packet_count", "total_bytes", "bytes_per_second", "packets_per_second",
    "avg_packet_size", "min_packet_size", "max_packet_size", "std_packet_size",
    "flow_duration", "avg_inter_arrival", "std_inter_arrival", "min_inter_arrival",
    "unique_dst_ports", "unique_src_ips",
    "dst_port_entropy", "flag_entropy", "ttl_entropy", "payload_entropy",
    "has_syn", "has_fin", "has_rst", "has_null",
]

ATTACK_CLASSES = [
    "Benign", "Port Scan", "Brute Force", "C2 Beaconing",
    "DNS Tunneling", "Lateral Movement", "Data Exfiltration",
    "Suspicious Traffic"
]

_alert_id_counter = 5000


def _make_alert(flow, attack_type, mitre_id, severity, confidence, detail, anomaly_score=None):
    global _alert_id_counter
    _alert_id_counter += 1
    alert = {
        "id": _alert_id_counter,
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "type": attack_type,
        "src_ip": flow.get("src_ip", "?"),
        "dst_ip": flow.get("dst_ip", "?"),
        "src_port": flow.get("src_port", 0),
        "dst_port": flow.get("dst_port", 0),
        "protocol": flow.get("protocol", "?"),
        "mitre_id": mitre_id,
        "confidence": round(confidence * 100),
        "detail": detail,
        "status": "OPEN",
        "source": "ml_anomaly",
        "packets": flow.get("packet_count", 0),
        "bytes": flow.get("total_bytes", 0),
        "flow_key": flow.get("flow_key", ""),
        "correlated": False,
    }
    if anomaly_score is not None:
        alert["anomaly_score"] = round(float(anomaly_score), 4)
    return alert


def _extract_vector(flow: dict) -> np.ndarray:
    """Convert flow dict to numeric feature vector."""
    vec = []
    for col in FEATURE_COLS:
        val = flow.get(col, 0)
        try:
            vec.append(float(val))
        except (TypeError, ValueError):
            vec.append(0.0)
    return np.array(vec, dtype=np.float32)


def _heuristic_anomaly_score(flow: dict) -> float:
    """
    Rule-free anomaly scoring when no model is trained.
    Returns a score in [-1, 1] where negative = more anomalous.
    """
    score = 0.0
    score -= min(flow.get("unique_dst_ports", 0) / 100.0, 0.4)
    score -= min(flow.get("payload_entropy", 0) / 8.0 * 0.3, 0.3)
    score += max(0, (1 - flow.get("avg_packet_size", 500) / 1500.0) * 0.2)
    if flow.get("std_inter_arrival", 1.0) < 0.1:
        score -= 0.3  # Too regular = beaconing
    if flow.get("packet_count", 0) > 500:
        score -= 0.2
    return max(-1.0, min(1.0, score))


class AnomalyDetector:
    """
    Two-stage ML detector:
    1. Isolation Forest — detects anomalous flows (unknown attacks)
    2. RandomForest Classifier — classifies known attack types
    """

    def __init__(self, model_path: str = "models/anomaly_model.pkl",
                 classifier_path: str = "models/classifier_model.pkl",
                 contamination: float = 0.05):
        self.model_path = model_path
        self.classifier_path = classifier_path
        self.contamination = contamination
        self.iso_forest = None
        self.classifier = None
        self.model_trained = False
        self._load_models()

    def _load_models(self):
        try:
            import joblib
            if os.path.exists(self.model_path):
                self.iso_forest = joblib.load(self.model_path)
                logger.info("Isolation Forest model loaded")
            if os.path.exists(self.classifier_path):
                self.classifier = joblib.load(self.classifier_path)
                logger.info("RandomForest classifier loaded")
            self.model_trained = self.iso_forest is not None
        except Exception as e:
            logger.warning(f"Model load failed: {e} — using heuristic mode")

    def train(self, flows: List[dict], labels: Optional[List[str]] = None):
        """
        Train Isolation Forest on unlabeled flows (unsupervised).
        If labels are provided, also trains the RandomForest classifier.
        """
        try:
            from sklearn.ensemble import IsolationForest, RandomForestClassifier
            import joblib

            if len(flows) < 50:
                logger.warning("Insufficient training data (need >= 50 flows)")
                return

            X = np.array([_extract_vector(f) for f in flows])
            logger.info(f"Training Isolation Forest on {len(X)} flows...")

            self.iso_forest = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,
                random_state=42,
                n_jobs=-1,
            )
            self.iso_forest.fit(X)

            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.iso_forest, self.model_path)
            logger.info(f"Isolation Forest saved: {self.model_path}")

            if labels and len(labels) == len(flows):
                logger.info("Training RandomForest classifier...")
                self.classifier = RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    n_jobs=-1,
                )
                self.classifier.fit(X, labels)
                joblib.dump(self.classifier, self.classifier_path)
                logger.info(f"RandomForest classifier saved: {self.classifier_path}")

            self.model_trained = True

        except ImportError:
            logger.error("scikit-learn not installed — cannot train models")
        except Exception as e:
            logger.error(f"Training failed: {e}")

    def analyze(self, flow: dict) -> Optional[dict]:
        """
        Analyze a single flow. Returns an alert dict if anomalous, else None.
        """
        vec = _extract_vector(flow)

        if self.iso_forest is not None:
            try:
                score = float(self.iso_forest.decision_function([vec])[0])
                prediction = self.iso_forest.predict([vec])[0]  # 1=normal, -1=anomaly
            except Exception as e:
                logger.debug(f"IF scoring failed: {e}")
                score = _heuristic_anomaly_score(flow)
                prediction = -1 if score < -0.2 else 1
        else:
            score = _heuristic_anomaly_score(flow)
            prediction = -1 if score < -0.2 else 1

        # Only raise alert if anomalous
        if prediction != -1:
            return None

        # Map anomaly score to confidence (more negative = more anomalous)
        confidence = min(0.97, max(0.55, 0.75 + abs(score) * 0.5))

        # Try classifier for attack type
        attack_type = "Anomalous Behavior"
        mitre_id = "T1071"
        severity = "HIGH"

        if self.classifier is not None:
            try:
                pred_class = self.classifier.predict([vec])[0]
                proba = self.classifier.predict_proba([vec])[0]
                confidence = max(confidence, float(max(proba)))
                attack_type = pred_class

                class_map = {
                    "Port Scan": ("T1046", "MEDIUM"),
                    "Brute Force": ("T1110", "HIGH"),
                    "C2 Beaconing": ("T1071", "HIGH"),
                    "DNS Tunneling": ("T1048", "CRITICAL"),
                    "Lateral Movement": ("T1021", "HIGH"),
                    "Data Exfiltration": ("T1048", "CRITICAL"),
                    "Suspicious Traffic": ("T1105", "MEDIUM"),
                }
                if attack_type in class_map:
                    mitre_id, severity = class_map[attack_type]
            except Exception as e:
                logger.debug(f"Classifier failed: {e}")

        # Severity from anomaly depth if no classifier
        elif score < -0.5:
            severity = "CRITICAL"
        elif score < -0.3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return _make_alert(
            flow,
            f"[ML] {attack_type}",
            mitre_id,
            severity,
            confidence,
            f"Anomaly score: {score:.4f} — {flow.get('packet_count',0)} packets, {flow.get('bytes_per_second',0):.0f} B/s from {flow.get('src_ip','?')}",
            anomaly_score=score,
        )

    def analyze_batch(self, flows: List[dict]) -> List[dict]:
        """Analyze multiple flows efficiently."""
        alerts = []
        for flow in flows:
            alert = self.analyze(flow)
            if alert:
                alerts.append(alert)
        return alerts

    @property
    def status(self) -> dict:
        return {
            "model_trained": self.model_trained,
            "iso_forest_ready": self.iso_forest is not None,
            "classifier_ready": self.classifier is not None,
            "mode": "ml" if self.model_trained else "heuristic",
        }
