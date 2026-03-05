"""
AID-ARS Pipeline Tests
Tests all major modules: capture, features, detection, scoring, mitre, response, reporting.
"""

import time
import json
import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─── FIXTURE DATA ─────────────────────────────────────────────────────────────

def make_packet(src="10.0.0.1", dst="192.168.1.1", proto="TCP",
                src_port=12345, dst_port=80, flags="S", length=64, payload=20):
    return {
        "timestamp": "2026-02-28T12:00:00",
        "src_ip": src, "dst_ip": dst,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": proto, "length": length,
        "payload_len": payload, "ttl": 64,
        "flags": flags, "raw_ts": time.time(),
    }


def make_flow(**kwargs):
    base = {
        "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8",
        "src_port": 12345, "dst_port": 53,
        "protocol": "TCP", "flow_key": "test_flow",
        "packet_count": 50, "total_bytes": 10000,
        "bytes_per_second": 5000.0, "packets_per_second": 25.0,
        "avg_packet_size": 200.0, "min_packet_size": 40, "max_packet_size": 1500,
        "std_packet_size": 100.0, "flow_duration": 2.0,
        "avg_inter_arrival": 0.04, "std_inter_arrival": 0.01, "min_inter_arrival": 0.001,
        "unique_dst_ports": 3, "unique_src_ips": 1,
        "dst_port_entropy": 1.5, "flag_entropy": 1.2, "ttl_entropy": 0.5,
        "payload_entropy": 2.5, "has_syn": 1, "has_fin": 0, "has_rst": 0, "has_null": 0,
    }
    base.update(kwargs)
    return base


# ─── FEATURE EXTRACTOR TESTS ──────────────────────────────────────────────────

class TestFlowAggregator:
    def test_flow_key_bidirectional(self):
        from features.extractor import flow_key
        p1 = make_packet("10.0.0.1", "10.0.0.2", src_port=100, dst_port=80)
        p2 = make_packet("10.0.0.2", "10.0.0.1", src_port=80, dst_port=100)
        assert flow_key(p1) == flow_key(p2), "Bidirectional flows should have same key"

    def test_entropy_calculation(self):
        from features.extractor import shannon_entropy
        assert shannon_entropy([]) == 0.0
        assert shannon_entropy([1, 1, 1, 1]) == 0.0
        e = shannon_entropy([1, 2, 3, 4])
        assert e > 1.9, "4 equal-prob events should have entropy ~2.0"

    def test_flow_record_accumulates(self):
        from features.extractor import FlowRecord
        p = make_packet()
        record = FlowRecord(p)
        for _ in range(4):
            time.sleep(0.001)
            record.add_packet(make_packet())
        assert len(record.packet_lengths) == 5
        assert len(record.inter_arrival_times) == 4

    def test_feature_vector_keys(self):
        from features.extractor import FlowRecord
        p = make_packet()
        record = FlowRecord(p)
        for _ in range(9):
            record.add_packet(make_packet())
        fv = record.to_feature_vector()
        required = ["packet_count", "total_bytes", "avg_packet_size", "flow_duration",
                    "unique_dst_ports", "payload_entropy", "has_syn", "has_fin"]
        for key in required:
            assert key in fv, f"Missing feature: {key}"

    def test_aggregator_emits_on_rst(self):
        from features.extractor import FlowAggregator
        emitted = []
        agg = FlowAggregator(on_flow_complete=lambda f: emitted.append(f))
        for _ in range(3):
            agg.add_packet(make_packet(flags="S"))
        agg.add_packet(make_packet(flags="RA"))  # RST+ACK closes flow
        assert len(emitted) == 1, "Flow should emit on RST"


# ─── SIGNATURE DETECTOR TESTS ─────────────────────────────────────────────────

class TestSignatureDetector:
    def test_syn_scan_detection(self):
        from detection.signature import SignatureDetector
        det = SignatureDetector({"port_scan_threshold": 10})
        flow = make_flow(has_syn=1, has_fin=0, unique_dst_ports=20, protocol="TCP")
        alerts = det.analyze(flow)
        types = [a["type"] for a in alerts]
        assert any("SYN" in t for t in types), f"SYN scan not detected. Got: {types}"

    def test_brute_force_ssh(self):
        from detection.signature import SignatureDetector
        det = SignatureDetector({"brute_force_threshold": 10})
        flow = make_flow(dst_port=22, packet_count=500, packets_per_second=50.0, protocol="TCP")
        alerts = det.analyze(flow)
        assert any("Brute" in a["type"] or "SSH" in a["type"] for a in alerts), \
            f"SSH brute force not detected. Got: {[a['type'] for a in alerts]}"

    def test_c2_beaconing(self):
        from detection.signature import SignatureDetector
        det = SignatureDetector()
        flow = make_flow(std_inter_arrival=0.05, avg_inter_arrival=30.0, packet_count=20)
        alerts = det.analyze(flow)
        assert any("C2" in a["type"] or "Beacon" in a["type"] for a in alerts), \
            f"C2 beaconing not detected. Got: {[a['type'] for a in alerts]}"

    def test_dns_tunneling(self):
        from detection.signature import SignatureDetector
        det = SignatureDetector({"dns_entropy_threshold": 3.5})
        flow = make_flow(protocol="DNS", payload_entropy=5.2, avg_packet_size=250)
        alerts = det.analyze(flow)
        assert any("DNS" in a["type"] or "Tunnel" in a["type"] for a in alerts), \
            f"DNS tunneling not detected. Got: {[a['type'] for a in alerts]}"

    def test_benign_traffic_no_alert(self):
        from detection.signature import SignatureDetector
        det = SignatureDetector()
        flow = make_flow(
            packet_count=10, unique_dst_ports=1, dst_port=443,
            packets_per_second=2.0, std_inter_arrival=2.0,
            payload_entropy=2.0, protocol="TCP"
        )
        alerts = det.analyze(flow)
        assert len(alerts) == 0, f"False positive on benign traffic: {[a['type'] for a in alerts]}"

    def test_stats_tracking(self):
        from detection.signature import SignatureDetector
        det = SignatureDetector()
        det.analyze(make_flow())
        det.analyze(make_flow())
        assert det.stats["flows_analyzed"] == 2


# ─── ANOMALY DETECTOR TESTS ───────────────────────────────────────────────────

class TestAnomalyDetector:
    def test_heuristic_anomaly_score(self):
        from detection.anomaly import _heuristic_anomaly_score
        normal = make_flow(unique_dst_ports=1, payload_entropy=2.0, packet_count=10)
        attack = make_flow(unique_dst_ports=80, payload_entropy=5.5, packet_count=1000)
        score_normal = _heuristic_anomaly_score(normal)
        score_attack = _heuristic_anomaly_score(attack)
        assert score_attack < score_normal, "Attack should have lower (more anomalous) score"

    def test_extract_vector_shape(self):
        from detection.anomaly import _extract_vector, FEATURE_COLS
        flow = make_flow()
        vec = _extract_vector(flow)
        assert len(vec) == len(FEATURE_COLS)
        assert all(isinstance(v, float) for v in vec)

    def test_detector_no_model(self):
        from detection.anomaly import AnomalyDetector
        det = AnomalyDetector(model_path="/nonexistent.pkl", classifier_path="/nonexistent2.pkl")
        assert det.status["mode"] == "heuristic"

    def test_train_and_detect(self):
        """Train on synthetic data and verify model works."""
        from detection.anomaly import AnomalyDetector
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = os.path.join(tmpdir, "iso.pkl")
            cp = os.path.join(tmpdir, "rf.pkl")
            det = AnomalyDetector(model_path=mp, classifier_path=cp)
            # Build training data
            benign = [make_flow(packet_count=i % 20 + 5, unique_dst_ports=1) for i in range(60)]
            attack = [make_flow(packet_count=1000, unique_dst_ports=50, payload_entropy=5.0) for _ in range(10)]
            all_flows = benign + attack
            labels = ["Benign"] * 60 + ["Port Scan"] * 10
            det.train(all_flows, labels)
            assert det.model_trained
            # Verify attack is detected (probabilistic — check no crash)
            result = det.analyze(make_flow(unique_dst_ports=80, payload_entropy=5.0, packet_count=2000))
            # Result may or may not be None depending on model; just ensure no exception


# ─── CORRELATION ENGINE TESTS ─────────────────────────────────────────────────

class TestCorrelationEngine:
    def _make_alert(self, src="10.0.0.1", mitre_id="T1046", sev="MEDIUM", confidence=80):
        return {
            "id": 1, "severity": sev, "type": "Port Scan",
            "src_ip": src, "dst_ip": "192.168.1.1",
            "mitre_id": mitre_id, "confidence": confidence,
            "status": "OPEN", "risk_score": 50,
        }

    def test_chain_creation(self):
        from detection.correlation import CorrelationEngine
        eng = CorrelationEngine(time_window=60)
        a1 = self._make_alert(mitre_id="T1046")
        a2 = self._make_alert(mitre_id="T1110")
        eng.ingest_alert(a1)
        chain = eng.ingest_alert(a2)
        assert chain is not None, "Chain should be returned after 2 events"
        assert chain["alert_count"] == 2

    def test_different_sources_different_chains(self):
        from detection.correlation import CorrelationEngine
        eng = CorrelationEngine()
        eng.ingest_alert(self._make_alert(src="10.0.0.1"))
        eng.ingest_alert(self._make_alert(src="10.0.0.2"))
        assert eng.stats["active_chains"] == 2

    def test_fp_suppression(self):
        from detection.correlation import CorrelationEngine
        eng = CorrelationEngine()
        low_conf = self._make_alert(src="1.2.3.4", confidence=40)
        assert eng.should_suppress_fp(low_conf) == True

    def test_chain_severity_escalates(self):
        from detection.correlation import CorrelationEngine
        eng = CorrelationEngine()
        for mitre_id in ["T1046", "T1110", "T1021", "T1048", "T1071"]:
            eng.ingest_alert(self._make_alert(mitre_id=mitre_id))
        chains = eng.get_active_chains()
        assert len(chains) == 1
        assert chains[0]["severity"] in ("CRITICAL", "HIGH")


# ─── THREAT SCORER TESTS ──────────────────────────────────────────────────────

class TestThreatScorer:
    def _alert(self, sev="HIGH", confidence=85, attack="SSH Brute Force", port=22, correlated=False):
        return {"severity": sev, "confidence": confidence, "type": attack, "dst_port": port, "correlated": correlated}

    def test_score_range(self):
        from scoring.scorer import ThreatScorer
        s = ThreatScorer()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            a = s.score(self._alert(sev=sev))
            assert 0 <= a["risk_score"] <= 100

    def test_critical_higher_than_low(self):
        from scoring.scorer import ThreatScorer
        s = ThreatScorer()
        crit = s.score(self._alert(sev="CRITICAL", confidence=95))
        low = s.score(self._alert(sev="LOW", confidence=60))
        assert crit["risk_score"] > low["risk_score"]

    def test_correlated_raises_score(self):
        from scoring.scorer import ThreatScorer
        s = ThreatScorer()
        a1 = s.score(self._alert(correlated=False))
        a2 = s.score(self._alert(correlated=True))
        assert a2["risk_score"] > a1["risk_score"]

    def test_priority_labels(self):
        from scoring.scorer import ThreatScorer
        s = ThreatScorer()
        a = s.score(self._alert(sev="CRITICAL", confidence=99))
        assert "P1" in a["priority"] or "P2" in a["priority"]


# ─── MITRE MAPPER TESTS ───────────────────────────────────────────────────────

class TestMitreMapper:
    def test_enrich_known_technique(self):
        from mitre.mapper import MitreMapper
        m = MitreMapper()
        alert = {"mitre_id": "T1046", "severity": "MEDIUM"}
        enriched = m.enrich(alert)
        assert enriched["mitre_name"] != "Unknown Technique"
        assert enriched["mitre_tactic"] != ""

    def test_enrich_unknown_technique(self):
        from mitre.mapper import MitreMapper
        m = MitreMapper()
        alert = {"mitre_id": "T9999"}
        enriched = m.enrich(alert)
        assert enriched["mitre_name"] == "Unknown Technique"

    def test_coverage_summary(self):
        from mitre.mapper import MitreMapper
        m = MitreMapper()
        alerts = [
            {"mitre_id": "T1046"}, {"mitre_id": "T1046"},
            {"mitre_id": "T1110"}, {"mitre_id": "T9999"},
        ]
        summary = m.get_coverage_summary(alerts)
        assert summary["techniques_detected"] == 2  # T9999 not in DB
        assert "T1046" in [t["id"] for t in summary["techniques"]]


# ─── REPORTER TESTS ───────────────────────────────────────────────────────────

class TestSOCReporter:
    def test_log_and_retrieve(self, tmp_path):
        from reporting.reporter import SOCReporter
        r = SOCReporter({"json_log_path": str(tmp_path / "logs.json"), "html_report_dir": str(tmp_path / "reports")})
        alert = {"id": 1, "severity": "HIGH", "type": "Test", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                 "mitre_id": "T1046", "status": "OPEN", "timestamp": "2026-02-28T00:00:00"}
        r.log_alert(alert)
        recent = r.get_recent_alerts(10)
        assert len(recent) == 1
        assert recent[0]["severity"] == "HIGH"

    def test_html_report_generation(self, tmp_path):
        from reporting.reporter import SOCReporter
        r = SOCReporter({"json_log_path": str(tmp_path / "logs.json"), "html_report_dir": str(tmp_path / "reports")})
        alerts = [{"id": i, "severity": "HIGH", "type": "Scan", "src_ip": f"10.0.0.{i}",
                   "dst_ip": "192.168.1.1", "mitre_id": "T1046", "mitre_name": "Scanning",
                   "mitre_tactic": "Discovery", "confidence": 85, "status": "OPEN",
                   "timestamp": "2026-02-28T12:00:00"} for i in range(3)]
        path = r.generate_html_report(alerts=alerts)
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "AID-ARS" in content
        assert "T1046" in content


# ─── INTEGRATION TEST ─────────────────────────────────────────────────────────

class TestFullPipeline:
    def test_packet_to_alert(self):
        """Full pipeline: raw packets → flow → alert with MITRE + score."""
        from features.extractor import FlowAggregator
        from detection.signature import SignatureDetector
        from scoring.scorer import ThreatScorer
        from mitre.mapper import MitreMapper

        results = []
        sig = SignatureDetector({"port_scan_threshold": 5, "brute_force_threshold": 5})
        scorer = ThreatScorer()
        mapper = MitreMapper()

        def on_flow(flow):
            alerts = sig.analyze(flow)
            for a in alerts:
                a = mapper.enrich(a)
                a = scorer.score(a)
                results.append(a)

        agg = FlowAggregator(on_flow_complete=on_flow)

        # Simulate a SYN port scan
        for dst_port in range(20, 35):  # 15 unique ports
            agg.add_packet(make_packet(dst_port=dst_port, flags="S", length=40, payload=0))
        agg.flush_all()

        assert len(results) > 0, "No alerts from SYN port scan simulation"
        a = results[0]
        assert a["mitre_id"] != ""
        assert a["risk_score"] > 0
        assert "priority" in a


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
