"""
CyberRemedy — ML Packet Analyzer
Wireshark-style deep packet analysis with ML classification.
Classifies every flow by: protocol, application, threat level, anomaly score.
Uses IsolationForest (unsupervised) + rule-based L7 classification.
No simulation — real packets only.
"""
import time, logging, threading, collections, math, hashlib
from datetime import datetime
from typing import Optional, Dict, List

import numpy as np

logger = logging.getLogger("cyberremedy.packet_analyzer")

# ── ML model (lazy init) ──────────────────────────────────────────────────────
_iso_forest = None
_iso_trained = False
_iso_lock    = threading.Lock()
_training_buf: List[list] = []
_TRAIN_MIN = 200   # minimum flows before training

def _get_features(flow: dict) -> list:
    """Extract numeric feature vector from a flow for ML."""
    return [
        float(flow.get('pkt_count', 1)),
        float(flow.get('byte_count', 0)),
        float(flow.get('bytes_per_pkt', 0)),
        float(flow.get('duration', 0)),
        float(flow.get('pps', 0)),
        float(flow.get('bps', 0)),
        float(flow.get('avg_pkt_size', 0)),
        float(flow.get('dst_port', 0)),
        float(flow.get('src_port', 0)),
        float(1 if flow.get('protocol') == 'TCP' else 0),
        float(1 if flow.get('protocol') == 'UDP' else 0),
        float(1 if flow.get('protocol') == 'ICMP' else 0),
        float(flow.get('ttl', 64)),
        float(flow.get('flag_syn', 0)),
        float(flow.get('flag_rst', 0)),
        float(flow.get('flag_fin', 0)),
        float(1 if flow.get('direction') == 'incoming' else 0),
        float(1 if flow.get('direction') == 'outgoing' else 0),
        float(1 if flow.get('src_private', False) else 0),
        float(1 if flow.get('dst_private', False) else 0),
    ]

def _train_if_ready():
    global _iso_forest, _iso_trained
    with _iso_lock:
        if _iso_trained or len(_training_buf) < _TRAIN_MIN:
            return
        try:
            from sklearn.ensemble import IsolationForest
            X = np.array(_training_buf, dtype=float)
            # Replace NaN/inf with 0
            X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)
            model = IsolationForest(n_estimators=100, contamination=0.05,
                                    random_state=42, n_jobs=-1)
            model.fit(X)
            _iso_forest = model
            _iso_trained = True
            logger.info(f"PacketAnalyzer: IsolationForest trained on {len(X)} flows")
        except Exception as e:
            logger.warning(f"PacketAnalyzer: ML train failed: {e}")

def _anomaly_score(flow: dict) -> float:
    """Returns 0.0 (normal) to 1.0 (very anomalous)."""
    global _iso_forest, _iso_trained, _training_buf
    features = _get_features(flow)
    _training_buf.append(features)
    if len(_training_buf) > 5000:
        _training_buf = _training_buf[-3000:]  # keep recent
    if not _iso_trained:
        threading.Thread(target=_train_if_ready, daemon=True).start()
        return _heuristic_score(flow)
    try:
        X = np.array([features], dtype=float)
        X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)
        score = _iso_forest.score_samples(X)[0]  # negative: more anomalous
        # Convert: typically [-0.5, 0] normal, < -0.5 anomalous
        normalized = max(0.0, min(1.0, (-score - 0.3) * 2.0))
        return normalized
    except Exception:
        return _heuristic_score(flow)

def _heuristic_score(flow: dict) -> float:
    """Rule-based anomaly score when ML not yet trained."""
    score = 0.0
    dport = flow.get('dst_port', 0)
    pps   = flow.get('pps', 0)
    bps   = flow.get('bps', 0)
    proto = flow.get('protocol', '')

    # High packet rate = scan or flood
    if pps > 500:  score += 0.4
    elif pps > 100: score += 0.2

    # Large data transfer
    if bps > 10_000_000: score += 0.2   # 10 MB/s

    # Suspicious destination ports
    suspicious_ports = {22, 23, 3389, 445, 135, 137, 139, 1433, 3306, 5432,
                        4444, 4445, 9001, 9090, 8888, 31337}
    if dport in suspicious_ports: score += 0.15

    # Non-standard protocols
    if proto not in ('TCP','UDP','ICMP','DNS'): score += 0.1

    # Very high/low TTL (tunneling or spoofing indicators)
    ttl = flow.get('ttl', 64)
    if ttl < 5 or ttl > 250: score += 0.15

    # Many RST flags = scan or rejected connections
    if flow.get('flag_rst', 0) > 5: score += 0.2

    return min(1.0, score)


# ── Threat classification ─────────────────────────────────────────────────────

THREAT_RULES = [
    # (name, mitre_id, severity, test_fn)
    ("Port Scan",         "T1046",     "HIGH",     lambda f: f.get('pps',0) > 50  and f.get('unique_dports',0) > 10),
    ("Brute Force",       "T1110.001", "HIGH",     lambda f: f.get('pkt_count',0) > 20 and f.get('dst_port',0) in (22,3389,21,23,445)),
    ("Data Exfiltration", "T1041",     "CRITICAL", lambda f: f.get('bps',0) > 5_000_000 and f.get('direction') == 'outgoing'),
    ("C2 Beacon",         "T1071.001", "HIGH",     lambda f: f.get('duration',0) > 30 and 0.9 < (f.get('pps',0) % 1 + 1) < 1.1),
    ("DNS Tunneling",     "T1048.003", "HIGH",     lambda f: f.get('protocol') == 'DNS' and f.get('byte_count',0) > 1000),
    ("ICMP Flood",        "T1498.001", "HIGH",     lambda f: f.get('protocol') == 'ICMP' and f.get('pps',0) > 100),
    ("Cleartext Creds",   "T1040",     "MEDIUM",   lambda f: f.get('dst_port',0) in (21,23,110,143) and f.get('byte_count',0) > 100),
    ("SSH Brute Force",   "T1110.001", "CRITICAL", lambda f: f.get('dst_port',0) == 22 and f.get('pkt_count',0) > 15),
    ("RDP Attack",        "T1021.001", "CRITICAL", lambda f: f.get('dst_port',0) == 3389 and f.get('pkt_count',0) > 10),
    ("SMB Lateral Move",  "T1021.002", "HIGH",     lambda f: f.get('dst_port',0) == 445),
    ("Telnet (Cleartext)","T1059",     "MEDIUM",   lambda f: f.get('dst_port',0) == 23),
    ("Tor/Non-std Port",  "T1090.003", "MEDIUM",   lambda f: f.get('dst_port',0) in (9001,9030,9050,9150)),
    ("Large Upload",      "T1041",     "LOW",      lambda f: f.get('direction') == 'outgoing' and f.get('byte_count',0) > 1_000_000),
    ("Unusual Protocol",  "T1095",     "LOW",      lambda f: f.get('protocol') not in ('TCP','UDP','ICMP','DNS') and f.get('protocol') != 'OTHER'),
]

def classify_threat(flow: dict) -> tuple:
    """Returns (threat_name, mitre_id, severity) or None if clean."""
    for name, mitre, severity, test in THREAT_RULES:
        try:
            if test(flow):
                return name, mitre, severity
        except Exception:
            pass
    return None, None, "INFO"


# ── Flow table ────────────────────────────────────────────────────────────────

class FlowKey:
    """Bidirectional 5-tuple flow key."""
    __slots__ = ['key']
    def __init__(self, pkt: dict):
        src, dst = pkt.get('src_ip',''), pkt.get('dst_ip','')
        sp, dp   = pkt.get('src_port',0), pkt.get('dst_port',0)
        proto    = pkt.get('protocol','')
        # Normalize: smaller IP first for bidirectional
        if (src, sp) < (dst, dp):
            self.key = (src, sp, dst, dp, proto)
        else:
            self.key = (dst, dp, src, sp, proto)
    def __hash__(self): return hash(self.key)
    def __eq__(self, other): return self.key == other.key


class Flow:
    """Active network flow — accumulates packets."""
    __slots__ = [
        'src_ip','dst_ip','src_port','dst_port','protocol','service','l7',
        'direction','src_private','dst_private',
        'pkt_count','byte_count','start_ts','last_ts',
        'flag_syn','flag_rst','flag_fin','flag_ack',
        'ttl','pkt_sizes','unique_dports',
        'anomaly_score','threat','mitre','severity',
        'flow_id','analyzed',
    ]
    def __init__(self, pkt: dict):
        self.src_ip      = pkt.get('src_ip','')
        self.dst_ip      = pkt.get('dst_ip','')
        self.src_port    = pkt.get('src_port', 0)
        self.dst_port    = pkt.get('dst_port', 0)
        self.protocol    = pkt.get('protocol','OTHER')
        self.service     = pkt.get('service','OTHER')
        self.l7          = pkt.get('l7','OTHER')
        self.direction   = pkt.get('direction','unknown')
        self.src_private = pkt.get('src_private', False)
        self.dst_private = pkt.get('dst_private', False)
        self.pkt_count   = 1
        self.byte_count  = pkt.get('length', 0)
        self.start_ts    = pkt.get('raw_ts', time.time())
        self.last_ts     = self.start_ts
        self.flag_syn    = 0
        self.flag_rst    = 0
        self.flag_fin    = 0
        self.flag_ack    = 0
        self.ttl         = pkt.get('ttl', 64)
        self.pkt_sizes   = [pkt.get('length', 0)]
        self.unique_dports = set()
        self.unique_dports.add(pkt.get('dst_port', 0))
        self.anomaly_score = 0.0
        self.threat      = None
        self.mitre       = None
        self.severity    = 'INFO'
        self.analyzed    = False
        # Stable hash-based ID
        h = hashlib.md5(f"{self.src_ip}{self.src_port}{self.dst_ip}{self.dst_port}{self.protocol}".encode()).hexdigest()[:8]
        self.flow_id = f"F-{h}"
        self._update_flags(pkt)

    def _update_flags(self, pkt: dict):
        flags = pkt.get('flags', '')
        if 'S' in flags: self.flag_syn += 1
        if 'R' in flags: self.flag_rst += 1
        if 'F' in flags: self.flag_fin += 1
        if 'A' in flags: self.flag_ack += 1

    def update(self, pkt: dict):
        self.pkt_count += 1
        self.byte_count += pkt.get('length', 0)
        self.last_ts     = pkt.get('raw_ts', time.time())
        self.pkt_sizes.append(pkt.get('length', 0))
        self.unique_dports.add(pkt.get('dst_port', 0))
        self._update_flags(pkt)

    def to_dict(self) -> dict:
        dur = max(0.001, self.last_ts - self.start_ts)
        avg = self.byte_count / self.pkt_count if self.pkt_count else 0
        return {
            'flow_id':      self.flow_id,
            'src_ip':       self.src_ip,
            'dst_ip':       self.dst_ip,
            'src_port':     self.src_port,
            'dst_port':     self.dst_port,
            'protocol':     self.protocol,
            'service':      self.service,
            'l7':           self.l7,
            'direction':    self.direction,
            'src_private':  self.src_private,
            'dst_private':  self.dst_private,
            'pkt_count':    self.pkt_count,
            'byte_count':   self.byte_count,
            'duration':     round(dur, 3),
            'bps':          round(self.byte_count / dur),
            'pps':          round(self.pkt_count / dur, 2),
            'bytes_per_pkt':round(avg, 1),
            'avg_pkt_size': round(avg, 1),
            'flag_syn':     self.flag_syn,
            'flag_rst':     self.flag_rst,
            'flag_fin':     self.flag_fin,
            'flag_ack':     self.flag_ack,
            'ttl':          self.ttl,
            'unique_dports':len(self.unique_dports),
            'anomaly_score':round(self.anomaly_score * 100),
            'threat':       self.threat,
            'mitre':        self.mitre,
            'severity':     self.severity,
            'start_time':   datetime.fromtimestamp(self.start_ts).isoformat(),
            'last_time':    datetime.fromtimestamp(self.last_ts).isoformat(),
        }


# ── Main analyzer class ───────────────────────────────────────────────────────

FLOW_IDLE_TIMEOUT = 60    # seconds of inactivity → expire flow
FLOW_HARD_TIMEOUT = 300   # max flow duration → force expire
MAX_FLOWS = 5000

class PacketAnalyzer:
    """
    Real-time packet analysis engine.
    Maintains flow table, runs ML + rule-based classification,
    emits analyzed flows to a callback.
    """

    def __init__(self, alert_callback=None):
        self._flows: Dict[int, Flow] = {}
        self._completed: List[dict]  = []   # ring buffer of analyzed flows
        self._lock = threading.Lock()
        self._alert_cb = alert_callback
        self._stats = {
            'total_packets': 0,
            'total_bytes':   0,
            'total_flows':   0,
            'active_flows':  0,
            'threats':       0,
            'anomalies':     0,
            'by_protocol':   collections.Counter(),
            'by_service':    collections.Counter(),
            'by_direction':  collections.Counter(),
            'by_l7':         collections.Counter(),
        }
        # Start flow expiry thread
        self._running = True
        threading.Thread(target=self._expire_loop, daemon=True,
                         name="flow-expiry").start()
        logger.info("PacketAnalyzer: started (IsolationForest ML + rule-based)")

    def ingest(self, pkt: dict):
        """Feed one normalized packet dict into the analyzer."""
        if not pkt: return
        with self._lock:
            self._stats['total_packets'] += 1
            self._stats['total_bytes']   += pkt.get('length', 0)
            self._stats['by_protocol'][pkt.get('protocol','?')] += 1
            self._stats['by_direction'][pkt.get('direction','?')] += 1
            self._stats['by_l7'][pkt.get('l7','?')] += 1

            key = hash(FlowKey(pkt))
            if key in self._flows:
                self._flows[key].update(pkt)
            else:
                if len(self._flows) >= MAX_FLOWS:
                    # Evict oldest
                    oldest = min(self._flows, key=lambda k: self._flows[k].last_ts)
                    self._expire_flow(oldest)
                self._flows[key] = Flow(pkt)
                self._stats['total_flows'] += 1
            self._stats['active_flows'] = len(self._flows)

    def _expire_flow(self, key: int):
        """Finalize and classify a flow, remove from active table."""
        flow = self._flows.pop(key, None)
        if not flow: return
        fd = flow.to_dict()

        # ML anomaly score
        fd['anomaly_score'] = round(_anomaly_score(fd) * 100)

        # Rule-based threat classification
        threat, mitre, severity = classify_threat(fd)
        fd['threat']   = threat
        fd['mitre']    = mitre
        fd['severity'] = severity

        if threat:
            self._stats['threats'] += 1
            if self._alert_cb:
                try:
                    self._alert_cb({
                        'type':      threat,
                        'src_ip':    fd['src_ip'],
                        'dst_ip':    fd['dst_ip'],
                        'src_port':  fd['src_port'],
                        'dst_port':  fd['dst_port'],
                        'protocol':  fd['protocol'],
                        'mitre_id':  mitre,
                        'severity':  severity,
                        'score':     max(fd['anomaly_score'], 50),
                        'direction': fd['direction'],
                        'detail':    f"{fd['pkt_count']} pkts, {fd['byte_count']} bytes, {fd['bps']} bps",
                        'source':    'packet_analyzer',
                        'timestamp': datetime.utcnow().isoformat(),
                    })
                except Exception: pass

        if fd['anomaly_score'] > 60:
            self._stats['anomalies'] += 1

        self._stats['by_service'][fd['service']] += 1
        self._completed.append(fd)
        if len(self._completed) > 2000:
            self._completed = self._completed[-1500:]

    def _expire_loop(self):
        """Background thread: expire idle/old flows every 5 seconds."""
        while self._running:
            time.sleep(5)
            now = time.time()
            with self._lock:
                expired = [k for k, f in self._flows.items()
                           if now - f.last_ts > FLOW_IDLE_TIMEOUT
                           or now - f.start_ts > FLOW_HARD_TIMEOUT]
                for k in expired:
                    self._expire_flow(k)

    def get_flows(self, limit=200, severity_filter=None, protocol_filter=None,
                  direction_filter=None, threat_only=False) -> List[dict]:
        """Get recent analyzed flows with optional filters."""
        with self._lock:
            flows = list(self._completed)
        flows.reverse()   # newest first
        if threat_only:
            flows = [f for f in flows if f.get('threat')]
        if severity_filter:
            flows = [f for f in flows if f.get('severity') == severity_filter]
        if protocol_filter:
            flows = [f for f in flows if f.get('protocol') == protocol_filter or f.get('l7') == protocol_filter]
        if direction_filter:
            flows = [f for f in flows if f.get('direction') == direction_filter]
        return flows[:limit]

    def get_active_flows(self, limit=100) -> List[dict]:
        """Get currently active (incomplete) flows."""
        with self._lock:
            active = sorted(self._flows.values(),
                            key=lambda f: f.last_ts, reverse=True)
        return [f.to_dict() for f in active[:limit]]

    @property
    def stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
            s['by_protocol'] = dict(s['by_protocol'])
            s['by_service']  = dict(s['by_service'])
            s['by_direction']= dict(s['by_direction'])
            s['by_l7']       = dict(s['by_l7'])
            s['ml_trained']  = _iso_trained
            s['training_samples'] = len(_training_buf)
        return s

    def stop(self):
        self._running = False
