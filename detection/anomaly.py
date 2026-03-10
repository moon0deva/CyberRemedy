"""
CyberRemedy ML Anomaly Detection Engine
Isolation Forest for unknown/zero-day detection.
RandomForest classifier for known attack classification.
Falls back to heuristic scoring when no model is trained.
"""

import os
import logging
import numpy as np
from typing import Optional, List, Tuple
from datetime import datetime

logger = logging.getLogger("cyberremedy.detection.anomaly")

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


def max_sev(a: str, b: str) -> str:
    """Return the higher of two severity strings."""
    _order = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
    return a if _order.get(a,0) >= _order.get(b,0) else b


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
    Multi-dimensional heuristic anomaly scorer used when no trained model exists.
    Scores 12 independent behavioural dimensions, each normalized to [-1, 0].
    Returns sum normalized to [-1, +1]: negative = more anomalous.
    """
    score = 0.0
    weights = []

    # ── 1. Port scan signature ─────────────────────────────────────────────
    udp = flow.get("unique_dst_ports", 0)
    if udp > 50:    score -= 0.40; weights.append("port_scan_heavy")
    elif udp > 15:  score -= 0.20; weights.append("port_scan_light")

    # ── 2. Beaconing regularity (C2) ──────────────────────────────────────
    std_ia = flow.get("std_inter_arrival", 9999.0)
    pkt_c  = flow.get("packet_count", 0)
    if std_ia < 0.05 and pkt_c > 20:
        score -= 0.45; weights.append("beaconing_regular")
    elif std_ia < 0.15 and pkt_c > 10:
        score -= 0.20; weights.append("beaconing_possible")

    # ── 3. Data volume anomaly ────────────────────────────────────────────
    bps = flow.get("bytes_per_second", 0)
    tb  = flow.get("total_bytes", 0)
    if bps > 10_000_000:   score -= 0.40; weights.append("exfil_high_rate")
    elif bps > 1_000_000:  score -= 0.20; weights.append("exfil_med_rate")
    if tb > 50_000_000:    score -= 0.30; weights.append("exfil_large_volume")
    elif tb > 5_000_000:   score -= 0.10; weights.append("exfil_med_volume")

    # ── 4. Payload entropy (encrypted/tunneled data) ──────────────────────
    pe = flow.get("payload_entropy", 0.0)
    if pe > 7.5:   score -= 0.25; weights.append("high_entropy_encrypted")
    elif pe > 7.0: score -= 0.10; weights.append("elevated_entropy")
    elif pe < 1.0 and flow.get("total_bytes", 0) > 10000:
        score -= 0.15; weights.append("low_entropy_repeated_payload")

    # ── 5. Suspicious destination ports ──────────────────────────────────
    dst = flow.get("dst_port", 0)
    SUSPICIOUS_PORTS = {4444,1337,31337,8888,9999,6666,6667,6697,  # C2 classics
                        1080,3128,8080,8118,9050,                   # proxies/Tor
                        23,69,512,513,514,                          # legacy/dangerous
                        445,135,137,138,139,                        # SMB/CIFS lateral
                        3389,5900,5901,                             # RDP/VNC
                        4443,8443,8444,                             # alt-HTTPS
                        2222,2223,                                  # alt-SSH
                        }
    if dst in SUSPICIOUS_PORTS:
        score -= 0.30; weights.append(f"suspicious_port_{dst}")

    # ── 6. Flag anomalies (Xmas, Null, FIN-only scans) ───────────────────
    flags = flow.get("flags", "")
    flag_e = flow.get("flag_entropy", 0.0)
    if flags in ("FPU", "FSRPAU", ""):   # Xmas / Null scan
        if pkt_c > 5: score -= 0.35; weights.append("flag_scan_xmas_null")
    if flag_e > 2.5 and pkt_c > 20:
        score -= 0.20; weights.append("flag_entropy_high")

    # ── 7. TTL anomaly (OS fingerprinting or spoofing) ────────────────────
    ttl = flow.get("ttl", 64)
    if ttl not in (32, 48, 64, 128, 255):
        score -= 0.10; weights.append("ttl_unusual")

    # ── 8. Packet size anomaly ────────────────────────────────────────────
    avg_ps = flow.get("avg_packet_size", 500)
    std_ps = flow.get("std_packet_size", 100)
    if avg_ps < 50 and pkt_c > 30:
        score -= 0.20; weights.append("tiny_packets_flood")
    if std_ps > 600:
        score -= 0.10; weights.append("high_size_variance")

    # ── 9. Flow duration anomaly ──────────────────────────────────────────
    dur = flow.get("flow_duration", 1.0)
    if dur > 3600:
        score -= 0.15; weights.append("very_long_flow")
    elif dur < 0.001 and pkt_c > 10:
        score -= 0.15; weights.append("burst_flood")

    # ── 10. DNS anomalies ─────────────────────────────────────────────────
    if flow.get("protocol") == "DNS":
        dns_len = flow.get("avg_packet_size", 0)
        if dns_len > 512:
            score -= 0.30; weights.append("dns_oversized_tunneling")
        if pkt_c > 100:
            score -= 0.25; weights.append("dns_query_flood")

    # ── 11. Lateral movement: internal → internal, unusual port ──────────
    src = flow.get("src_ip","")
    dst_ip = flow.get("dst_ip","")
    def _is_private(ip):
        return (ip.startswith("192.168.") or ip.startswith("10.") or
                (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31))
    if _is_private(src) and _is_private(dst_ip) and dst in {445,135,139,3389,5985,5986}:
        score -= 0.35; weights.append("lateral_smb_rdp_winrm")

    # ── 12. High unique source IPs (amplification/DDoS) ──────────────────
    usrc = flow.get("unique_src_ips", 0)
    if usrc > 100:
        score -= 0.30; weights.append("many_source_ips_ddos")
    elif usrc > 30:
        score -= 0.10; weights.append("elevated_source_ips")

    final = max(-1.0, min(1.0, score))
    if weights:
        flow["_heuristic_reasons"] = weights
    return final


def _classify_heuristic(flow: dict, score: float) -> tuple:
    """
    Map heuristic dimensions to an attack type + MITRE ATT&CK ID.
    Returns (attack_type, mitre_id, severity)
    """
    reasons = flow.get("_heuristic_reasons", [])
    dst = flow.get("dst_port", 0)
    proto = flow.get("protocol","")

    if any("port_scan" in r for r in reasons):
        return "Port Scan (Heuristic)", "T1046", "MEDIUM"
    if any("beaconing" in r for r in reasons):
        return "C2 Beaconing (Heuristic)", "T1071", "HIGH"
    if any("exfil" in r for r in reasons):
        return "Data Exfiltration (Heuristic)", "T1041", "HIGH" if score < -0.4 else "MEDIUM"
    if any("lateral" in r for r in reasons):
        return "Lateral Movement (Heuristic)", "T1021", "HIGH"
    if any("dns" in r for r in reasons):
        return "DNS Tunneling (Heuristic)", "T1048", "HIGH"
    if any("flag_scan" in r for r in reasons):
        return "TCP Flag Scan (Heuristic)", "T1046", "MEDIUM"
    if any("suspicious_port" in r for r in reasons):
        return "Suspicious Port Activity", "T1571", "MEDIUM"
    if any("ddos" in r or "flood" in r for r in reasons):
        return "DoS/Flood (Heuristic)", "T1498", "HIGH"
    if any("entropy" in r for r in reasons):
        return "Encrypted/Tunneled Traffic", "T1573", "MEDIUM"
    return "Anomalous Behavior", "T1071", "MEDIUM"





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
        self._flow_buffer  = []       # recent normal flows for online retraining
        self._if_scores    = []       # rolling IF scores for adaptive threshold
        self._anomaly_count = 0       # total anomalies detected this session
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
            self._flow_buffer = []    # clear buffer after training
            # Log feature importances if RF classifier trained
            if self.classifier is not None and hasattr(self.classifier, "feature_importances_"):
                fi = list(zip(FEATURE_COLS, self.classifier.feature_importances_))
                fi.sort(key=lambda x: -x[1])
                top5 = ", ".join(f"{f}={v:.3f}" for f,v in fi[:5])
                logger.info(f"Top-5 features: {top5}")

        except ImportError:
            logger.error("scikit-learn not installed — cannot train models")
        except Exception as e:
            logger.error(f"Training failed: {e}")

    def analyze(self, flow: dict) -> Optional[dict]:
        """
        Two-stage ML detection:
        Stage 1 — Isolation Forest (or heuristic): is this flow anomalous?
        Stage 2 — Random Forest (or heuristic classify): what type of attack?
        Also: online incremental learning buffers real flows for periodic retraining.
        """
        vec = _extract_vector(flow)

        # ── Stage 1: anomaly detection ─────────────────────────────────────
        if self.iso_forest is not None:
            try:
                score       = float(self.iso_forest.decision_function([vec])[0])
                prediction  = self.iso_forest.predict([vec])[0]   # 1=normal, -1=anomaly
                self._if_scores.append(score)
                if len(self._if_scores) > 10000: self._if_scores.pop(0)
            except Exception as e:
                logger.debug(f"IF scoring: {e}")
                score      = _heuristic_anomaly_score(flow)
                prediction = -1 if score < -0.2 else 1
        else:
            score      = _heuristic_anomaly_score(flow)
            prediction = -1 if score < -0.2 else 1

        # Buffer for online learning (store benign flows for retraining)
        if prediction == 1:
            self._flow_buffer.append(flow)
            if len(self._flow_buffer) > 5000: self._flow_buffer.pop(0)

        if prediction != -1:
            return None

        # ── Stage 2: attack classification ────────────────────────────────
        confidence  = min(0.97, max(0.55, 0.75 + abs(score) * 0.4))
        attack_type = "Anomalous Behavior"
        mitre_id    = "T1071"
        severity    = "MEDIUM"

        if self.classifier is not None:
            try:
                pred_class = self.classifier.predict([vec])[0]
                proba      = self.classifier.predict_proba([vec])[0]
                top_conf   = float(max(proba))
                if top_conf > 0.45:        # only trust confident predictions
                    confidence  = max(confidence, top_conf)
                    attack_type = pred_class
                    class_map = {
                        "Port Scan":          ("T1046", "MEDIUM"),
                        "Brute Force":        ("T1110", "HIGH"),
                        "C2 Beaconing":       ("T1071", "HIGH"),
                        "DNS Tunneling":      ("T1048", "CRITICAL"),
                        "Lateral Movement":   ("T1021", "HIGH"),
                        "Data Exfiltration":  ("T1041", "CRITICAL"),
                        "Suspicious Traffic": ("T1105", "MEDIUM"),
                    }
                    if attack_type in class_map:
                        mitre_id, severity = class_map[attack_type]
                else:
                    # Low confidence — fall back to heuristic classification
                    attack_type, mitre_id, severity = _classify_heuristic(flow, score)
            except Exception as e:
                logger.debug(f"Classifier: {e}")
                attack_type, mitre_id, severity = _classify_heuristic(flow, score)
        else:
            attack_type, mitre_id, severity = _classify_heuristic(flow, score)

        # Severity override based on anomaly depth
        if score < -0.65:   severity = "CRITICAL"
        elif score < -0.40: severity = max_sev(severity, "HIGH")

        # Track stats
        self._anomaly_count += 1

        return _make_alert(
            flow,
            f"[ML] {attack_type}",
            mitre_id,
            severity,
            confidence,
            f"Anomaly score: {score:.4f} | reasons: {flow.get('_heuristic_reasons', [])} | "
            f"{flow.get('packet_count',0)} pkts, {flow.get('bytes_per_second',0):.0f} B/s "
            f"from {flow.get('src_ip','?')}",
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


    def maybe_retrain(self, min_flows: int = 500):
        """Trigger incremental retraining when enough new flows are buffered."""
        if len(self._flow_buffer) < min_flows:
            return
        logger.info(f"Auto-retraining on {len(self._flow_buffer)} buffered flows")
        self.train(self._flow_buffer)

