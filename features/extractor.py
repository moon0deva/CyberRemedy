"""
AID-ARS Feature Extraction Engine
Aggregates raw packets into network flows and extracts
statistical, entropy, and behavioral features for ML models.
"""

import math
import time
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional

logger = logging.getLogger("aidars.features")

# ─── FLOW KEY ─────────────────────────────────────────────────────────────────

def flow_key(pkt: dict) -> str:
    """Create bidirectional flow key from packet."""
    src = f"{pkt['src_ip']}:{pkt['src_port']}"
    dst = f"{pkt['dst_ip']}:{pkt['dst_port']}"
    proto = pkt.get("protocol", "?")
    # Bidirectional: sort so A->B and B->A map to same flow
    endpoints = sorted([src, dst])
    return f"{endpoints[0]}-{endpoints[1]}-{proto}"


# ─── ENTROPY CALCULATOR ───────────────────────────────────────────────────────

def shannon_entropy(values: List) -> float:
    """Compute Shannon entropy of a distribution."""
    if not values:
        return 0.0
    total = len(values)
    freq = defaultdict(int)
    for v in values:
        freq[v] += 1
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ─── FLOW RECORD ──────────────────────────────────────────────────────────────

class FlowRecord:
    """Tracks statistics for a single network flow."""

    def __init__(self, first_pkt: dict):
        self.key = flow_key(first_pkt)
        self.src_ip = first_pkt["src_ip"]
        self.dst_ip = first_pkt["dst_ip"]
        self.src_port = first_pkt["src_port"]
        self.dst_port = first_pkt["dst_port"]
        self.protocol = first_pkt["protocol"]
        self.start_time = first_pkt["raw_ts"]
        self.last_time = first_pkt["raw_ts"]

        self.packet_lengths: List[int] = [first_pkt["length"]]
        self.inter_arrival_times: List[float] = []
        self.flags_seen: List[str] = [first_pkt.get("flags", "")]
        self.dst_ports_seen: set = {first_pkt["dst_port"]}
        self.src_ips_seen: set = {first_pkt["src_ip"]}
        self.ttls_seen: List[int] = [first_pkt.get("ttl", 64)]
        self.payload_sizes: List[int] = [first_pkt.get("payload_len", 0)]

    def add_packet(self, pkt: dict):
        now = pkt["raw_ts"]
        iat = now - self.last_time
        self.inter_arrival_times.append(iat)
        self.last_time = now
        self.packet_lengths.append(pkt["length"])
        self.flags_seen.append(pkt.get("flags", ""))
        self.dst_ports_seen.add(pkt["dst_port"])
        self.src_ips_seen.add(pkt["src_ip"])
        self.ttls_seen.append(pkt.get("ttl", 64))
        self.payload_sizes.append(pkt.get("payload_len", 0))

    def to_feature_vector(self) -> dict:
        pkts = self.packet_lengths
        iats = self.inter_arrival_times if self.inter_arrival_times else [0]
        duration = max(self.last_time - self.start_time, 0.001)
        total_bytes = sum(pkts)

        # Variance helper
        def variance(lst):
            if len(lst) < 2:
                return 0.0
            mean = sum(lst) / len(lst)
            return sum((x - mean) ** 2 for x in lst) / len(lst)

        return {
            # Volume
            "packet_count": len(pkts),
            "total_bytes": total_bytes,
            "bytes_per_second": round(total_bytes / duration, 2),
            "packets_per_second": round(len(pkts) / duration, 2),

            # Size stats
            "avg_packet_size": round(sum(pkts) / len(pkts), 2),
            "min_packet_size": min(pkts),
            "max_packet_size": max(pkts),
            "std_packet_size": round(math.sqrt(variance(pkts)), 2),

            # Timing
            "flow_duration": round(duration, 4),
            "avg_inter_arrival": round(sum(iats) / len(iats), 4),
            "std_inter_arrival": round(math.sqrt(variance(iats)), 4),
            "min_inter_arrival": round(min(iats), 4),

            # Diversity
            "unique_dst_ports": len(self.dst_ports_seen),
            "unique_src_ips": len(self.src_ips_seen),

            # Entropy
            "dst_port_entropy": shannon_entropy(list(self.dst_ports_seen)),
            "flag_entropy": shannon_entropy(self.flags_seen),
            "ttl_entropy": shannon_entropy(self.ttls_seen),
            "payload_entropy": shannon_entropy(
                [min(p // 100, 9) for p in self.payload_sizes]
            ),

            # Protocol
            "protocol": self.protocol,
            "has_syn": int("S" in "".join(self.flags_seen)),
            "has_fin": int("F" in "".join(self.flags_seen)),
            "has_rst": int("R" in "".join(self.flags_seen)),
            "has_null": int(all(f == "" for f in self.flags_seen)),

            # Identity
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "flow_key": self.key,
        }


# ─── FLOW AGGREGATOR ──────────────────────────────────────────────────────────

class FlowAggregator:
    """
    Maintains active flows and emits completed flow feature vectors.
    A flow is considered complete when:
      - No packets for flow_timeout seconds, OR
      - The flow has seen RST/FIN flags, OR
      - The flow exceeds max_packets
    """

    def __init__(
        self,
        flow_timeout: float = 60.0,
        max_packets_per_flow: int = 5000,
        on_flow_complete: callable = None,
    ):
        self.flow_timeout = flow_timeout
        self.max_packets_per_flow = max_packets_per_flow
        self.on_flow_complete = on_flow_complete
        self._flows: Dict[str, FlowRecord] = {}
        self._last_cleanup = time.time()

    def add_packet(self, pkt: dict):
        key = flow_key(pkt)

        if key not in self._flows:
            self._flows[key] = FlowRecord(pkt)
        else:
            self._flows[key].add_packet(pkt)

        flow = self._flows[key]

        # Emit on RST or FIN+ACK
        flags = pkt.get("flags", "")
        if "R" in flags or ("F" in flags and "A" in flags):
            self._emit_flow(key)
            return

        # Emit when flow exceeds max packets
        if len(flow.packet_lengths) >= self.max_packets_per_flow:
            self._emit_flow(key)
            return

        # Periodic timeout cleanup
        if time.time() - self._last_cleanup > 10:
            self._cleanup_timed_out_flows()

    def _emit_flow(self, key: str):
        if key in self._flows:
            flow = self._flows.pop(key)
            features = flow.to_feature_vector()
            if self.on_flow_complete:
                self.on_flow_complete(features)

    def _cleanup_timed_out_flows(self):
        now = time.time()
        timed_out = [
            k for k, v in self._flows.items()
            if now - v.last_time > self.flow_timeout
        ]
        for key in timed_out:
            self._emit_flow(key)
        self._last_cleanup = now
        if timed_out:
            logger.debug(f"Timed out {len(timed_out)} flows")

    def flush_all(self):
        """Emit all active flows (call on shutdown)."""
        for key in list(self._flows.keys()):
            self._emit_flow(key)

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)
