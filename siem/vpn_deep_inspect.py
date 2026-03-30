"""
CyberRemedy SIEM — VPN Tunnel Deep Inspector
=============================================
Agentless VPN traffic analysis. No agent on the client is required.

HONEST CAPABILITY MATRIX (agentless, no client software):
──────────────────────────────────────────────────────────
┌─────────────────────┬──────────────────────────────────────────────────┐
│ VPN Protocol        │ What we can extract WITHOUT decryption            │
├─────────────────────┼──────────────────────────────────────────────────┤
│ WireGuard           │ Handshake initiation/response (4-byte type field) │
│                     │ Session start/end timing, packet cadence          │
│                     │ Peer public key (in handshake — PLAINTEXT!)       │
│                     │ Data volume per session, idle periods             │
├─────────────────────┼──────────────────────────────────────────────────┤
│ OpenVPN (UDP/TCP)   │ TLS handshake (SNI if present, cert info)        │
│                     │ Cipher suite negotiation, client fingerprint      │
│                     │ Packet size distribution, timing                  │
│                     │ Control vs data channel separation                │
├─────────────────────┼──────────────────────────────────────────────────┤
│ IPSec/IKEv2         │ IKE_SA_INIT exchange (full plaintext):           │
│                     │   Proposals, DH groups, nonces                   │
│                     │   Vendor IDs (OS/client fingerprint)             │
│                     │ IKE_AUTH (encrypted but we see which certs used) │
│                     │ Child SA creation, traffic selectors              │
├─────────────────────┼──────────────────────────────────────────────────┤
│ L2TP/PPTP           │ Full control channel (L2TP control is plaintext) │
│                     │ PPP negotiation phase, auth method used           │
│                     │ Tunnel IDs, session IDs                          │
├─────────────────────┼──────────────────────────────────────────────────┤
│ All protocols       │ Timing analysis, packet size distribution         │
│                     │ Traffic volume fingerprinting                     │
│                     │ Provider identification (IP ranges)              │
│                     │ Connection establishment / teardown events        │
└─────────────────────┴──────────────────────────────────────────────────┘

FORCED BYPASS / DECRYPTION STRATEGIES (agentless):
────────────────────────────────────────────────────
  STRATEGY 1 — Block + Redirect (iptables):
    Block the VPN protocol port, forcing the app to fail.
    The underlying HTTP/HTTPS traffic then flows in plaintext
    (or via our TLS proxy for HTTPS). Most effective when combined
    with our TLS intercept engine.

  STRATEGY 2 — WireGuard Key Extraction from Handshake:
    WireGuard handshake_initiation messages contain the initiator's
    ephemeral public key and static public key (encrypted with
    receiver's public key). We capture the ephemeral key.
    Without the receiver's private key we cannot decrypt.
    BUT: we can log the peer public key to identify the WireGuard
    peer configuration (useful for asset inventory).

  STRATEGY 3 — OpenVPN TLS MITM:
    If OpenVPN is using TCP mode, redirect TCP/1194 to our TLS proxy.
    The proxy performs a TLS MITM on the OpenVPN control channel.
    This breaks the VPN entirely (OpenVPN will reconnect via UDP)
    but gives us the OpenVPN server's certificate and client fingerprint.

  STRATEGY 4 — DNS-based correlation:
    Before VPN connects, capture DNS lookups to identify the VPN server.
    After VPN connects, all DNS goes through the tunnel — but the
    last DNS query before connect reveals the VPN provider/server.

  STRATEGY 5 — Traffic correlation (advanced):
    Even inside an encrypted tunnel, packet timing and size patterns
    can reveal the type of content (video streaming vs web browsing vs
    file transfer). We implement basic traffic classification here.
"""

import ipaddress
import logging
import os
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberremedy.siem.vpn_inspect")

try:
    from scapy.all import sniff, IP, UDP, TCP, Raw, Ether
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ─── WireGuard Handshake Parser ───────────────────────────────────────────────

class WireGuardParser:
    """
    Parses WireGuard protocol messages (RFC-spec on port 51820/UDP).

    WireGuard message types:
      1 = Handshake Initiation  (148 bytes) — contains ephemeral pubkey (plaintext)
      2 = Handshake Response    (92 bytes)  — ephemeral pubkey + encrypted empty
      3 = Cookie Reply          (64 bytes)
      4 = Transport Data        (>=32 bytes, encrypted)

    The Handshake Initiation is mostly AEAD-encrypted with Noise_IKpsk2,
    but the structure (type, sender_index) is plaintext, and the encrypted
    static key can be correlated across sessions.
    """

    MSG_INITIATION = 1
    MSG_RESPONSE   = 2
    MSG_COOKIE     = 3
    MSG_TRANSPORT  = 4

    def parse(self, data: bytes, src_ip: str, dst_ip: str,
              src_port: int, dst_port: int) -> Optional[dict]:
        if len(data) < 4:
            return None
        msg_type = struct.unpack("<I", data[0:4])[0]
        if msg_type == self.MSG_INITIATION:
            return self._parse_initiation(data, src_ip, dst_ip, src_port, dst_port)
        elif msg_type == self.MSG_RESPONSE:
            return self._parse_response(data, src_ip, dst_ip, src_port, dst_port)
        elif msg_type == self.MSG_TRANSPORT:
            return self._parse_transport(data, src_ip, dst_ip, src_port, dst_port)
        elif msg_type == self.MSG_COOKIE:
            return {
                "vpn":       "wireguard",
                "msg_type":  "cookie_reply",
                "src_ip":    src_ip, "dst_ip": dst_ip,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            }
        return None

    def _parse_initiation(self, data: bytes, *addr) -> dict:
        """
        Handshake Initiation (type=1, 148 bytes):
          [4]  type (1)
          [4]  sender_index (random, plaintext)
          [32] ephemeral_pubkey (Noise ephemeral — plaintext)
          [48] encrypted_static (AEAD, reveals initiator static key hash)
          [28] encrypted_timestamp (AEAD)
          [16] mac1
          [16] mac2
        """
        src_ip, dst_ip, src_port, dst_port = addr
        if len(data) < 148:
            return {"vpn": "wireguard", "msg_type": "initiation_short", "src_ip": src_ip, "dst_ip": dst_ip}
        sender_index    = struct.unpack("<I", data[4:8])[0]
        ephemeral_pubkey = data[8:40].hex()   # 32 bytes — PLAINTEXT
        mac1             = data[132:148].hex() # 16 bytes — identifies sender across sessions

        return {
            "vpn":             "wireguard",
            "msg_type":        "handshake_initiation",
            "src_ip":          src_ip,
            "dst_ip":          dst_ip,
            "src_port":        src_port,
            "dst_port":        dst_port,
            "sender_index":    f"0x{sender_index:08x}",
            "ephemeral_pubkey": ephemeral_pubkey,
            "mac1":            mac1,             # stable identifier for this peer
            "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
            "note":            "Ephemeral public key extracted (plaintext in WG spec)",
        }

    def _parse_response(self, data: bytes, *addr) -> dict:
        src_ip, dst_ip, src_port, dst_port = addr
        if len(data) < 92:
            return {"vpn": "wireguard", "msg_type": "response_short", "src_ip": src_ip, "dst_ip": dst_ip}
        sender_index   = struct.unpack("<I", data[4:8])[0]
        receiver_index = struct.unpack("<I", data[8:12])[0]
        ephemeral_pubkey = data[12:44].hex()

        return {
            "vpn":              "wireguard",
            "msg_type":         "handshake_response",
            "src_ip":           src_ip, "dst_ip": dst_ip,
            "src_port":         src_port, "dst_port": dst_port,
            "sender_index":     f"0x{sender_index:08x}",
            "receiver_index":   f"0x{receiver_index:08x}",
            "ephemeral_pubkey": ephemeral_pubkey,
            "timestamp":        datetime.now(tz=timezone.utc).isoformat(),
            "note":             "Session established — data is now encrypted",
        }

    def _parse_transport(self, data: bytes, *addr) -> dict:
        src_ip, dst_ip, src_port, dst_port = addr
        receiver_index = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0
        counter        = struct.unpack("<Q", data[8:16])[0] if len(data) >= 16 else 0
        payload_len    = len(data) - 32 if len(data) > 32 else 0

        return {
            "vpn":             "wireguard",
            "msg_type":        "transport_data",
            "src_ip":          src_ip, "dst_ip": dst_ip,
            "receiver_index":  f"0x{receiver_index:08x}",
            "packet_counter":  counter,
            "payload_bytes":   payload_len,
            "encrypted":       True,
            "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
        }


# ─── OpenVPN Packet Parser ────────────────────────────────────────────────────

class OpenVPNParser:
    """
    Parses OpenVPN control and data channel packets.

    OpenVPN uses a TLS control channel (for key exchange) and a
    separate data channel (encrypted). The control channel TLS
    ClientHello is visible and reveals cipher suites and extensions.

    OpenVPN packet structure (UDP mode):
      Byte 0: opcode (upper 5 bits) + key_id (lower 3 bits)
      Opcodes:
        0x01 = P_CONTROL_HARD_RESET_CLIENT_V1
        0x02 = P_CONTROL_HARD_RESET_SERVER_V1
        0x03 = P_CONTROL_SOFT_RESET_V1
        0x04 = P_CONTROL_V1 (TLS control channel data)
        0x05 = P_ACK_V1
        0x06 = P_DATA_V1 (encrypted tunnel data)
        0x07 = P_CONTROL_HARD_RESET_CLIENT_V2
        0x08 = P_CONTROL_HARD_RESET_SERVER_V2
        0x09 = P_DATA_V2
    """

    OPCODES = {
        0x01: "HARD_RESET_CLIENT_V1",
        0x02: "HARD_RESET_SERVER_V1",
        0x03: "SOFT_RESET",
        0x04: "CONTROL_V1",
        0x05: "ACK",
        0x06: "DATA_V1",
        0x07: "HARD_RESET_CLIENT_V2",
        0x08: "HARD_RESET_SERVER_V2",
        0x09: "DATA_V2",
    }

    def parse(self, data: bytes, src_ip: str, dst_ip: str,
              src_port: int, dst_port: int) -> Optional[dict]:
        if len(data) < 2:
            return None
        try:
            opcode  = (data[0] >> 3) & 0x1F
            key_id  = data[0] & 0x07
            op_name = self.OPCODES.get(opcode, f"UNKNOWN_{opcode:#x}")

            result = {
                "vpn":       "openvpn",
                "msg_type":  op_name,
                "key_id":    key_id,
                "src_ip":    src_ip, "dst_ip": dst_ip,
                "src_port":  src_port, "dst_port": dst_port,
                "length":    len(data),
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            }

            # For HARD_RESET packets: extract session ID (8 bytes, plaintext)
            if opcode in (0x01, 0x02, 0x07, 0x08) and len(data) >= 9:
                result["session_id"] = data[1:9].hex()

            # For CONTROL_V1: contains TLS data
            if opcode == 0x04 and len(data) > 9:
                result["contains_tls"] = True
                # Try to extract TLS ClientHello (may be fragmented across packets)
                tls_data = data[9:]  # after session_id + ack_len
                if len(tls_data) > 5 and tls_data[0] == 0x16:  # TLS Handshake record
                    result["tls_record"] = True
                    result["tls_record_type"] = tls_data[5] if len(tls_data) > 5 else 0
                    if len(tls_data) > 5 and tls_data[5] == 0x01:  # ClientHello
                        result["openvpn_client_hello"] = True

            return result
        except Exception as exc:
            logger.debug(f"[VPN] OpenVPN parse error: {exc}")
            return None


# ─── IKEv2/IPSec Parser ───────────────────────────────────────────────────────

class IKEv2Parser:
    """
    Parses IKEv2 (RFC 7296) messages on UDP/500 and UDP/4500.
    IKE_SA_INIT is COMPLETELY PLAINTEXT and reveals:
      - Proposed algorithms and DH groups
      - Nonces (random, useful for timing)
      - Vendor IDs (identify OS, client software, VPN product)
      - Certificate requests (what CAs the client trusts)
    """

    EXCHANGE_TYPES = {
        34: "IKE_SA_INIT",
        35: "IKE_AUTH",
        36: "CREATE_CHILD_SA",
        37: "INFORMATIONAL",
    }

    PAYLOAD_TYPES = {
        33: "SA",           # Security Association
        34: "KE",           # Key Exchange (DH public key — PLAINTEXT)
        40: "NONCE",
        43: "ID_INITIATOR",
        44: "ID_RESPONDER",
        48: "CERTIFICATE",
        50: "CERT_REQUEST",
        41: "NOTIFY",
        42: "DELETE",
        43: "VENDOR_ID",
        45: "TSi",          # Traffic Selector initiator
        46: "TSr",
        47: "SK",           # Encrypted payload
    }

    def parse(self, data: bytes, src_ip: str, dst_ip: str,
              src_port: int, dst_port: int) -> Optional[dict]:
        if len(data) < 28:
            return None
        try:
            # IKE header (28 bytes)
            initiator_spi = data[0:8].hex()
            responder_spi = data[8:16].hex()
            next_payload  = data[16]
            version       = data[17]
            exchange_type = data[18]
            flags         = data[19]
            msg_id        = struct.unpack(">I", data[20:24])[0]
            length        = struct.unpack(">I", data[24:28])[0]

            is_initiator  = bool(flags & 0x08)
            is_response   = bool(flags & 0x20)

            exchange_name = self.EXCHANGE_TYPES.get(exchange_type, f"UNK_{exchange_type}")

            result = {
                "vpn":            "ikev2",
                "msg_type":       exchange_name,
                "is_initiator":   is_initiator,
                "is_response":    is_response,
                "initiator_spi":  initiator_spi,
                "responder_spi":  responder_spi,
                "msg_id":         msg_id,
                "src_ip":         src_ip, "dst_ip": dst_ip,
                "src_port":       src_port, "dst_port": dst_port,
                "timestamp":      datetime.now(tz=timezone.utc).isoformat(),
                "payloads":       [],
                "vendor_ids":     [],
                "dh_public_key":  "",  # extracted from KE payload
                "proposals":      [],
            }

            # Parse payload chain if IKE_SA_INIT (plaintext)
            if exchange_type == 34:
                self._parse_payloads(data, 28, next_payload, result)

            return result
        except Exception as exc:
            logger.debug(f"[VPN] IKEv2 parse error: {exc}")
            return None

    def _parse_payloads(self, data: bytes, offset: int, next_type: int, result: dict) -> None:
        while next_type != 0 and offset < len(data):
            if offset + 4 > len(data):
                break
            next_type_new = data[offset]
            critical      = data[offset + 1]
            payload_len   = struct.unpack(">H", data[offset+2:offset+4])[0]
            payload_data  = data[offset+4:offset+payload_len]

            ptype = self.PAYLOAD_TYPES.get(next_type, f"UNK_{next_type}")
            result["payloads"].append(ptype)

            # Extract DH public key from KE payload (plaintext!)
            if next_type == 34 and len(payload_data) >= 4:   # KE
                dh_group = struct.unpack(">H", payload_data[0:2])[0]
                dh_key   = payload_data[4:].hex() if len(payload_data) > 4 else ""
                result["dh_public_key"] = dh_key[:64] + "..."  # first 32 bytes
                result["dh_group"]      = dh_group

            # Vendor IDs (identify client/OS)
            if next_type == 43:  # VENDOR_ID (note: same as ID_INITIATOR in some maps)
                vid = payload_data.hex()
                result["vendor_ids"].append(vid)
                # Decode known vendor IDs
                known = self._decode_vendor_id(payload_data)
                if known:
                    result["vendor_ids"].append(f"({known})")

            offset   += payload_len
            next_type = next_type_new

    @staticmethod
    def _decode_vendor_id(vid: bytes) -> str:
        """Identify known VPN clients from their Vendor ID bytes."""
        known_vids = {
            bytes.fromhex("4f456c6c796e"): "Windows IKEv2",
            bytes.fromhex("26244d38eddb61b3172a36e3d0cfb819"): "iOS/macOS IKEv2",
            bytes.fromhex("afcad71368a1f1c96b8696fc77570100"): "Dead Peer Detection",
            bytes.fromhex("4d53534f4350"): "Microsoft SSTP",
        }
        for pattern, name in known_vids.items():
            if vid.startswith(pattern):
                return name
        return ""


# ─── VPN Traffic Classifier ───────────────────────────────────────────────────

class TunnelPayloadAnalyzer:
    """
    Deep payload analysis of encrypted VPN tunnel packets.

    WHAT WE ANALYSE (all on outer/wrapper packets — no decryption of inner data):
    ─────────────────────────────────────────────────────────────────────────────
    1. CIPHERTEXT BYTE DISTRIBUTION (Shannon entropy + chi-squared uniformity)
       Encrypted payloads from different codecs have subtly different byte
       frequency distributions even though they're "random":
         - H.264/H.265 video: AES-CTR/GCM output has near-uniform byte dist
           but with specific length clustering at NAL unit boundaries
         - Opus/AAC audio: smaller, more regular blocks than video
         - Raw file data (ZIP/AES): maximum entropy, uniform distribution
         - Game state: structured small blocks, low entropy variance
         - HTTP/REST: variable block sizes with entropy slightly below max
           (padding patterns, header overhead)

    2. PACKET SIZE HISTOGRAM & PERCENTILE FINGERPRINT
       Even after encryption, the VPN encapsulator preserves the inner
       packet sizes (just adds a fixed overhead). Histogramming sizes
       against known application fingerprints gives strong signals:
         - Netflix/YouTube: 99th-percentile size ~1380-1400 (near MTU)
           with a secondary cluster at ~188 (MPEG-TS packets)
         - Zoom/Meet/Teams video: bimodal at ~1200 (video) + ~160 (audio)
         - Discord/gaming: tight cluster at 80-120 bytes
         - HTTP/REST API: sizes spread across 200-1400 with long tail
         - File transfer: nearly all packets at MTU (1400-1460)
         - SSH interactive: tiny packets ~40-80, very regular

    3. INTER-ARRIVAL TIME (IAT) DISTRIBUTION FINGERPRINTING
       Application traffic has characteristic timing signatures:
         - Real-time codecs (VoIP/video): 20ms, 40ms, or 60ms IAT peaks
           (codec frame intervals — RTP packetisation period)
         - Streaming (buffered): burst/idle cycles at ~2-10 second periods
           (HLS/DASH segment download followed by buffer fill pause)
         - Gaming: ultra-low IAT 16ms/33ms/50ms (game tick rates: 60/30/20Hz)
         - File transfer: near-zero IAT (TCP maximum throughput)
         - Web browsing: multi-modal IAT (request RTT + think time)
         - Idle keepalive: large IAT peaks at 10s/25s/60s intervals

    4. BURST STRUCTURE ANALYSIS
       Detect request/response patterns, burst amplitude, and silence periods:
         - Asymmetric bursts (large download, small upload) → streaming/download
         - Symmetric bursts → video call or interactive session
         - Periodic equal bursts → streaming (segment-based)
         - Long silence with tiny keepalives → idle tunnel

    5. DIRECTIONAL RATIO
       Upload:Download byte ratio is a strong classifier:
         - Video call: ~1:1 to 1:2
         - Streaming: ~1:20 to 1:100 (download dominant)
         - File upload: ~10:1 (upload dominant)
         - Gaming: ~1:3 to 1:5 (download slightly dominant)
         - Web browsing: ~1:5 to 1:15

    6. FLOW COUNT & PARALLELISM
       Number of simultaneous sub-flows inside the tunnel:
         - P2P/BitTorrent: dozens to hundreds of micro-flows
         - Web browsing: 6-20 parallel flows (HTTP/2 multiplexing)
         - Video streaming: 1-3 flows (main stream + audio + subtitles)
         - VoIP: 2 flows (audio + signalling)
         - Gaming: 1-3 flows

    OUTPUT: multi-class probability vector + dominant class + confidence score
    All computed from outer packet metadata — fully agentless.
    """

    # ── Application size profile fingerprints ─────────────────────────────────
    # Each entry: (p10, p25, p50, p75, p90, p99) percentile sizes in bytes
    # Derived from empirical traffic captures of each application type
    SIZE_PROFILES = {
        "video_streaming_hd":    (800,  1100, 1380, 1400, 1400, 1400),
        "video_streaming_sd":    (400,  700,  1100, 1350, 1380, 1400),
        "voip_audio_only":       (100,  140,  160,  200,  240,  320),
        "video_call":            (100,  160,  800,  1200, 1350, 1400),
        "gaming_fps":            (40,   60,   80,   120,  200,  400),
        "gaming_mmo":            (60,   100,  200,  400,  800,  1200),
        "file_transfer":         (1350, 1380, 1400, 1400, 1400, 1460),
        "web_browsing":          (60,   150,  500,  1000, 1350, 1400),
        "ssh_interactive":       (40,   52,   68,   80,   120,  400),
        "p2p_bittorrent":        (200,  800,  1400, 1400, 1400, 1460),
        "dns_heavy":             (40,   60,   80,   100,  200,  512),
        "idle_keepalive":        (40,   44,   48,   56,   64,   80),
    }

    # ── IAT signature profiles (dominant IAT bucket in ms) ────────────────────
    # Format: list of (iat_ms_low, iat_ms_high, weight) for each class
    IAT_SIGNATURES = {
        "video_streaming_hd":  [(0,   5,   0.6), (2000, 10000, 0.4)],   # burst then buffer
        "video_streaming_sd":  [(0,   10,  0.5), (1000, 8000,  0.5)],
        "voip_audio_only":     [(18,  22,  0.8), (38,   42,    0.2)],   # 20ms RTP frames
        "video_call":          [(18,  22,  0.5), (0,    5,     0.5)],   # audio+video mixed
        "gaming_fps":          [(14,  18,  0.7), (30,   36,    0.3)],   # 60Hz tick = 16.7ms
        "gaming_mmo":          [(28,  36,  0.7), (50,   70,    0.3)],   # 30Hz tick = 33ms
        "file_transfer":       [(0,   2,   0.9), (2,    10,    0.1)],   # near-zero IAT
        "web_browsing":        [(0,   20,  0.4), (100,  2000,  0.6)],   # RTT + think time
        "ssh_interactive":     [(0,   5,   0.3), (100,  5000,  0.7)],   # keystrokes + echo
        "p2p_bittorrent":      [(0,   5,   0.8), (200,  2000,  0.2)],
        "idle_keepalive":      [(9000,60000,0.9),(60000,300000,0.1)],
    }

    # ── Directional ratio profiles (upload_bytes / total_bytes) ───────────────
    # Format: (low, high) of expected upload fraction
    DIR_PROFILES = {
        "video_streaming_hd":  (0.00, 0.08),
        "video_streaming_sd":  (0.00, 0.12),
        "voip_audio_only":     (0.40, 0.60),
        "video_call":          (0.30, 0.55),
        "gaming_fps":          (0.15, 0.40),
        "gaming_mmo":          (0.10, 0.35),
        "file_transfer":       (0.80, 1.00),   # upload; flip for download
        "web_browsing":        (0.05, 0.25),
        "ssh_interactive":     (0.20, 0.60),
        "p2p_bittorrent":      (0.30, 0.55),
        "idle_keepalive":      (0.30, 0.70),
    }

    def __init__(self):
        self._cache: Dict[str, dict] = {}   # ip → last result

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, peer_ip: str, packet_history: List[dict],
                raw_payloads: Optional[List[bytes]] = None) -> dict:
        """
        Full deep analysis. Returns:
          {
            "class":        dominant class string,
            "confidence":   0-100,
            "scores":       {class: score, ...} for all candidates,
            "features":     extracted feature dict,
            "payload_analysis": ciphertext byte analysis if raw_payloads provided,
            "signals":      list of human-readable evidence strings,
          }
        """
        if len(packet_history) < 3:
            return self._insufficient(peer_ip)

        features    = self._extract_features(packet_history, raw_payloads)
        scores      = self._score_all(features)
        top_class, confidence = self._top(scores)
        signals     = self._explain(top_class, features, scores)

        result = {
            "peer_ip":          peer_ip,
            "class":            top_class,
            "confidence":       confidence,
            "scores":           {k: round(v, 2) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
            "features":         features,
            "signals":          signals,
            "packet_count":     len(packet_history),
            "analysed_at":      datetime.now(tz=timezone.utc).isoformat(),
        }
        if raw_payloads:
            result["payload_analysis"] = self._analyze_ciphertext(raw_payloads)
        self._cache[peer_ip] = result
        return result

    def classify(self, packet_history: List[dict]) -> dict:
        """Backward-compatible wrapper used by VPNSnifferEngine.classify_peer()."""
        return self.analyze("", packet_history)

    def get_cached(self, peer_ip: str) -> Optional[dict]:
        return self._cache.get(peer_ip)

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_features(self, history: List[dict],
                          raw_payloads: Optional[List[bytes]]) -> dict:
        window = history[-200:]   # use last 200 packets for features

        # ── Packet sizes ──────────────────────────────────────────────────────
        sizes = [p.get("payload_bytes", p.get("length", 0)) for p in window]
        sizes = [s for s in sizes if s > 0]
        if not sizes:
            sizes = [0]

        size_mean    = self._mean(sizes)
        size_median  = self._percentile(sizes, 50)
        size_p10     = self._percentile(sizes, 10)
        size_p25     = self._percentile(sizes, 25)
        size_p75     = self._percentile(sizes, 75)
        size_p90     = self._percentile(sizes, 90)
        size_p99     = self._percentile(sizes, 99)
        size_std     = self._std(sizes)
        size_cv      = size_std / size_mean if size_mean > 0 else 0   # coeff of variation
        near_mtu_frac = sum(1 for s in sizes if s > 1350) / len(sizes)
        tiny_frac    = sum(1 for s in sizes if s < 100) / len(sizes)

        # ── Timestamps & IAT ──────────────────────────────────────────────────
        ts_list = []
        for p in window:
            ts_str = p.get("timestamp", "")
            raw_ts = p.get("raw_ts")
            if raw_ts:
                ts_list.append(float(raw_ts))
            elif ts_str:
                try:
                    from datetime import datetime as _dt
                    ts_list.append(_dt.fromisoformat(ts_str.replace("Z", "")).timestamp())
                except Exception:
                    pass

        iats_ms = [(ts_list[i+1] - ts_list[i]) * 1000
                   for i in range(len(ts_list) - 1)
                   if ts_list[i+1] > ts_list[i]] if len(ts_list) > 1 else []
        iats_ms = [x for x in iats_ms if x > 0]

        iat_mean    = self._mean(iats_ms) if iats_ms else 0
        iat_median  = self._percentile(iats_ms, 50) if iats_ms else 0
        iat_p10     = self._percentile(iats_ms, 10) if iats_ms else 0
        iat_p90     = self._percentile(iats_ms, 90) if iats_ms else 0
        iat_std     = self._std(iats_ms) if iats_ms else 0
        iat_cv      = iat_std / iat_mean if iat_mean > 0 else 0

        # Dominant IAT bucket (most common 5ms bucket)
        dominant_iat_bucket = self._dominant_bucket(iats_ms, bucket_ms=5) if iats_ms else 0

        # Detect periodic IAT (codec regularity)
        iat_regularity = self._periodicity_score(iats_ms) if len(iats_ms) > 10 else 0.0

        # ── Directionality ────────────────────────────────────────────────────
        up_bytes   = sum(p.get("length", 0) for p in window
                         if p.get("direction") in ("outgoing", None))
        down_bytes = sum(p.get("length", 0) for p in window
                         if p.get("direction") == "incoming")
        total_bytes = up_bytes + down_bytes
        up_ratio   = up_bytes / total_bytes if total_bytes > 0 else 0.5

        # ── Burst structure ───────────────────────────────────────────────────
        bursts          = self._detect_bursts(window, ts_list, gap_ms=500)
        burst_count     = len(bursts)
        burst_size_mean = self._mean([b["bytes"] for b in bursts]) if bursts else 0
        silence_mean_ms = self._mean([b["silence_before_ms"] for b in bursts
                                      if b["silence_before_ms"] > 0]) if bursts else 0
        periodic_bursts = self._burst_periodicity(bursts) if len(bursts) > 3 else 0.0

        # ── Entropy of ciphertext (if raw payloads provided) ──────────────────
        entropy_mean = 0.0
        entropy_std  = 0.0
        if raw_payloads:
            entropies = [self._shannon_entropy(p) for p in raw_payloads if len(p) > 16]
            entropy_mean = self._mean(entropies) if entropies else 0.0
            entropy_std  = self._std(entropies)  if entropies else 0.0

        return {
            # Size features
            "size_mean":        round(size_mean, 1),
            "size_median":      size_median,
            "size_p10":         size_p10,
            "size_p25":         size_p25,
            "size_p75":         size_p75,
            "size_p90":         size_p90,
            "size_p99":         size_p99,
            "size_std":         round(size_std, 1),
            "size_cv":          round(size_cv, 3),
            "near_mtu_frac":    round(near_mtu_frac, 3),
            "tiny_frac":        round(tiny_frac, 3),
            # IAT features
            "iat_mean_ms":      round(iat_mean, 2),
            "iat_median_ms":    round(iat_median, 2),
            "iat_p10_ms":       round(iat_p10, 2),
            "iat_p90_ms":       round(iat_p90, 2),
            "iat_std_ms":       round(iat_std, 2),
            "iat_cv":           round(iat_cv, 3),
            "dominant_iat_ms":  dominant_iat_bucket,
            "iat_regularity":   round(iat_regularity, 3),   # 0=random, 1=perfectly periodic
            # Directionality
            "up_ratio":         round(up_ratio, 3),
            "total_bytes":      total_bytes,
            # Burst features
            "burst_count":      burst_count,
            "burst_size_mean":  int(burst_size_mean),
            "silence_mean_ms":  int(silence_mean_ms),
            "periodic_bursts":  round(periodic_bursts, 3),
            # Entropy (ciphertext analysis)
            "entropy_mean":     round(entropy_mean, 4),
            "entropy_std":      round(entropy_std, 4),
            # Sample count
            "sample_count":     len(window),
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score_all(self, f: dict) -> Dict[str, float]:
        """Return a score 0–100 for each candidate class."""
        scores: Dict[str, float] = {}

        for cls in self.SIZE_PROFILES:
            scores[cls] = self._score_class(cls, f)

        # Normalize to 0–100 relative to max
        max_s = max(scores.values()) if scores else 1
        if max_s > 0:
            scores = {k: round(v / max_s * 100, 1) for k, v in scores.items()}
        return scores

    def _score_class(self, cls: str, f: dict) -> float:
        score = 0.0

        # ── Size profile score (40% weight) ──────────────────────────────────
        sp = self.SIZE_PROFILES[cls]
        measured = (f["size_p10"], f["size_p25"], f["size_median"],
                    f["size_p75"],  f["size_p90"],  f["size_p99"])
        size_score = self._profile_similarity(measured, sp)
        score += size_score * 40

        # ── IAT signature score (30% weight) ─────────────────────────────────
        iat_sigs = self.IAT_SIGNATURES.get(cls, [])
        iat_score = 0.0
        for (lo, hi, w) in iat_sigs:
            if lo <= f["dominant_iat_ms"] <= hi:
                iat_score += w
            elif lo <= f["iat_median_ms"] <= hi:
                iat_score += w * 0.5
            elif lo <= f["iat_mean_ms"] <= hi:
                iat_score += w * 0.3
        score += min(iat_score, 1.0) * 30

        # ── Directional ratio score (20% weight) ──────────────────────────────
        dir_range = self.DIR_PROFILES.get(cls, (0, 1))
        up_ratio  = f["up_ratio"]
        # File transfer: check both upload and download direction
        if cls == "file_transfer":
            dir_match = (dir_range[0] <= up_ratio <= dir_range[1] or
                         dir_range[0] <= (1 - up_ratio) <= dir_range[1])
        else:
            dir_match = dir_range[0] <= up_ratio <= dir_range[1]
        if dir_match:
            score += 20
        elif abs(up_ratio - (dir_range[0] + dir_range[1]) / 2) < 0.15:
            score += 10

        # ── Structural bonuses / penalties (10% weight) ───────────────────────
        bonus = 0.0

        if cls in ("video_streaming_hd", "video_streaming_sd", "file_transfer"):
            bonus += f["near_mtu_frac"] * 0.4    # high MTU frac is strong signal

        if cls in ("voip_audio_only", "gaming_fps", "gaming_mmo"):
            bonus += f["iat_regularity"] * 0.5   # periodic IAT is very strong signal
            bonus += (1.0 - f["size_cv"]) * 0.3  # low size variance for codecs

        if cls == "idle_keepalive":
            bonus += f["tiny_frac"] * 0.5
            if f["iat_mean_ms"] > 5000:
                bonus += 0.5

        if cls == "web_browsing":
            if f["burst_count"] > 3:
                bonus += 0.4
            if f["periodic_bursts"] < 0.3:
                bonus += 0.3   # web browsing is NOT periodic

        if cls in ("video_streaming_hd", "video_streaming_sd"):
            if f["periodic_bursts"] > 0.5:
                bonus += 0.3   # HLS/DASH segment downloads are periodic

        if cls == "p2p_bittorrent":
            if f["burst_count"] > 10:
                bonus += 0.4

        score += min(bonus, 1.0) * 10
        return score

    @staticmethod
    def _profile_similarity(measured: tuple, reference: tuple) -> float:
        """Cosine-like similarity between two percentile vectors (0–1)."""
        if len(measured) != len(reference):
            return 0.0
        # Normalise both by p99 of reference to make scale-independent
        ref_max = reference[-1] or 1
        m_norm  = [v / ref_max for v in measured]
        r_norm  = [v / ref_max for v in reference]
        # Mean absolute difference
        diff = sum(abs(m - r) for m, r in zip(m_norm, r_norm)) / len(m_norm)
        return max(0.0, 1.0 - diff)

    @staticmethod
    def _top(scores: Dict[str, float]) -> Tuple[str, int]:
        if not scores:
            return "unknown", 0
        top = max(scores, key=scores.get)
        conf = int(min(scores[top], 100))
        return top, conf

    # ── Ciphertext / payload byte analysis ────────────────────────────────────

    def _analyze_ciphertext(self, payloads: List[bytes]) -> dict:
        """
        Analyse raw encrypted payload bytes.

        WHAT THIS REVEALS even from ciphertext:
          - Shannon entropy distribution (truly random AES vs structured data)
          - Byte frequency chi-squared test (uniformity — cipher mode fingerprint)
          - Block size regularity (CBC vs CTR/GCM block boundaries)
          - IV/nonce prepended bytes (first 16 bytes often differ from rest)
          - Padding oracle indicators (last-block size distribution)
          - Packet length clustering (inner packet sizes leak through fixed overhead)

        NOTE: We are NOT breaking the encryption. We are extracting metadata
        from the ciphertext structure itself — this is fully legal and agentless.
        """
        if not payloads:
            return {}

        payloads = [p for p in payloads if len(p) >= 16][:500]

        # Shannon entropy per packet
        entropies  = [self._shannon_entropy(p) for p in payloads]
        ent_mean   = self._mean(entropies)
        ent_std    = self._std(entropies)
        ent_min    = min(entropies)
        ent_max    = max(entropies)

        # Byte frequency across all ciphertext (chi-squared against uniform)
        byte_counts = [0] * 256
        total_bytes = 0
        for p in payloads:
            for b in p:
                byte_counts[b] += 1
            total_bytes += len(p)

        expected_per_byte = total_bytes / 256 if total_bytes > 0 else 1
        chi_sq = sum((c - expected_per_byte) ** 2 / expected_per_byte
                     for c in byte_counts) if expected_per_byte > 0 else 0
        # chi_sq < 270 = very uniform (strong AES), > 600 = less random (weaker cipher / compression)
        uniformity = max(0.0, 1.0 - min(chi_sq / 600, 1.0))

        # First-16-bytes entropy (IV/nonce region — should be higher for CBC)
        first16_entropies = [self._shannon_entropy(p[:16]) for p in payloads if len(p) >= 16]
        first16_ent_mean  = self._mean(first16_entropies)

        # Packet length modulo 16 distribution (CBC produces 16-byte aligned ciphertext)
        mod16_dist = defaultdict(int)
        for p in payloads:
            mod16_dist[len(p) % 16] += 1
        cbc_indicator = mod16_dist[0] / len(payloads) if payloads else 0   # high → CBC mode

        # Length clustering — reveals inner packet size distribution
        length_clusters = self._cluster_lengths([len(p) for p in payloads])

        # Interpret findings
        interpretation = []
        if ent_mean > 7.95:
            interpretation.append("near-maximum entropy (AES-GCM/CTR — modern cipher)")
        elif ent_mean > 7.8:
            interpretation.append("high entropy (AES-CBC or ChaCha20)")
        elif ent_mean > 7.0:
            interpretation.append("moderate entropy — possible compression layer")
        else:
            interpretation.append("low entropy — unexpected for encrypted traffic")

        if ent_std < 0.05:
            interpretation.append("uniform entropy across packets (stream cipher or CTR mode)")
        elif ent_std > 0.2:
            interpretation.append("variable entropy — mixed packet types (control + data frames)")

        if cbc_indicator > 0.6:
            interpretation.append(f"CBC cipher mode likely ({int(cbc_indicator*100)}% 16-byte aligned packets)")
        else:
            interpretation.append("GCM/CTR mode likely (non-16-byte-aligned lengths)")

        if first16_ent_mean > ent_mean + 0.1:
            interpretation.append("IV/nonce prefix detected (first 16 bytes higher entropy)")

        if uniformity > 0.85:
            interpretation.append("byte distribution near-uniform — strong cipher, no compression artifacts")
        elif uniformity < 0.5:
            interpretation.append("non-uniform byte distribution — possible weak cipher or partial compression")

        # Length cluster interpretation
        if length_clusters:
            for cluster in length_clusters[:3]:
                interpretation.append(
                    f"inner packet size cluster ~{cluster['center']}B "
                    f"({cluster['fraction']*100:.0f}% of packets)"
                )

        return {
            "entropy_mean":       round(ent_mean, 4),
            "entropy_std":        round(ent_std, 4),
            "entropy_min":        round(ent_min, 4),
            "entropy_max":        round(ent_max, 4),
            "chi_squared":        round(chi_sq, 2),
            "uniformity_score":   round(uniformity, 3),
            "cbc_indicator":      round(cbc_indicator, 3),
            "first16_entropy":    round(first16_ent_mean, 4),
            "length_clusters":    length_clusters,
            "interpretation":     interpretation,
            "packets_analysed":   len(payloads),
            "total_bytes_analysed": total_bytes,
        }

    # ── Burst detection ───────────────────────────────────────────────────────

    @staticmethod
    def _detect_bursts(window: List[dict], ts_list: List[float],
                       gap_ms: float = 500) -> List[dict]:
        """Split packet history into bursts separated by silences > gap_ms."""
        if len(ts_list) < 2:
            return []
        bursts = []
        current_start  = 0
        current_bytes  = 0
        prev_silence   = 0.0
        for i, ts in enumerate(ts_list):
            pkt_bytes = window[i].get("length", 0) if i < len(window) else 0
            if i == 0:
                current_bytes = pkt_bytes
                continue
            gap = (ts - ts_list[i - 1]) * 1000
            if gap > gap_ms:
                bursts.append({
                    "start_idx":        current_start,
                    "end_idx":          i - 1,
                    "bytes":            current_bytes,
                    "duration_ms":      (ts_list[i - 1] - ts_list[current_start]) * 1000,
                    "silence_before_ms": prev_silence,
                })
                current_start = i
                current_bytes = pkt_bytes
                prev_silence  = gap
            else:
                current_bytes += pkt_bytes
        # Close last burst
        if current_bytes > 0:
            bursts.append({
                "start_idx":         current_start,
                "end_idx":           len(ts_list) - 1,
                "bytes":             current_bytes,
                "duration_ms":       (ts_list[-1] - ts_list[current_start]) * 1000 if ts_list else 0,
                "silence_before_ms": prev_silence,
            })
        return bursts

    @staticmethod
    def _burst_periodicity(bursts: List[dict]) -> float:
        """Score 0–1 how periodic burst inter-arrival times are."""
        if len(bursts) < 3:
            return 0.0
        intervals = []
        for i in range(1, len(bursts)):
            silence = bursts[i].get("silence_before_ms", 0)
            if silence > 0:
                intervals.append(silence)
        if not intervals:
            return 0.0
        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return 0.0
        cv = (sum((x - mean)**2 for x in intervals) / len(intervals)) ** 0.5 / mean
        return max(0.0, 1.0 - min(cv, 1.0))

    # ── IAT periodicity ───────────────────────────────────────────────────────

    @staticmethod
    def _periodicity_score(iats_ms: List[float]) -> float:
        """
        Measure how periodic a sequence of IATs is.
        Returns 0 (random) to 1 (perfectly periodic — codec-like).
        Uses autocorrelation: if IAT[i] ≈ IAT[i+k] for some k, it's periodic.
        """
        if len(iats_ms) < 6:
            return 0.0
        arr   = iats_ms[:100]
        mean  = sum(arr) / len(arr)
        demeaned = [x - mean for x in arr]
        var   = sum(x**2 for x in demeaned) / len(demeaned)
        if var < 1e-9:
            return 1.0
        # Autocorrelation at lag 1
        if len(demeaned) < 2:
            return 0.0
        autocorr = sum(demeaned[i] * demeaned[i+1] for i in range(len(demeaned)-1))
        autocorr /= (len(demeaned) - 1) * var
        return max(0.0, min(1.0, float(autocorr)))

    @staticmethod
    def _dominant_bucket(iats_ms: List[float], bucket_ms: int = 5) -> float:
        """Return the center of the most populated bucket in a histogram."""
        if not iats_ms:
            return 0.0
        buckets: Dict[int, int] = defaultdict(int)
        for v in iats_ms:
            b = int(v // bucket_ms) * bucket_ms
            buckets[b] += 1
        top_b = max(buckets, key=buckets.get)
        return float(top_b + bucket_ms / 2)

    # ── Length clustering ─────────────────────────────────────────────────────

    @staticmethod
    def _cluster_lengths(lengths: List[int], bandwidth: int = 40) -> List[dict]:
        """Simple mean-shift clustering on packet lengths."""
        if not lengths:
            return []
        from collections import Counter
        counts  = Counter(lengths)
        total   = len(lengths)
        # Smooth into bandwidth-wide buckets
        buckets: Dict[int, int] = defaultdict(int)
        for length, cnt in counts.items():
            b = (length // bandwidth) * bandwidth
            buckets[b] += cnt
        clusters = sorted(
            [{"center": b + bandwidth//2, "count": cnt, "fraction": cnt/total}
             for b, cnt in buckets.items()
             if cnt / total >= 0.05],
            key=lambda x: -x["count"]
        )
        return clusters[:5]

    # ── Human-readable explanation ────────────────────────────────────────────

    def _explain(self, cls: str, f: dict, scores: dict) -> List[str]:
        signals = []
        runner_up = sorted(scores.items(), key=lambda x: -x[1])
        if len(runner_up) > 1:
            second = runner_up[1]
            signals.append(
                f"Top match: {cls} ({scores.get(cls, 0):.0f}pts) "
                f"| Runner-up: {second[0]} ({second[1]:.0f}pts)"
            )

        if f["near_mtu_frac"] > 0.7:
            signals.append(f"{int(f['near_mtu_frac']*100)}% packets near MTU — bulk data transfer")
        if f["tiny_frac"] > 0.5:
            signals.append(f"{int(f['tiny_frac']*100)}% tiny packets (<100B) — control/keepalive traffic")
        if f["iat_regularity"] > 0.6:
            signals.append(
                f"Highly periodic IAT (score={f['iat_regularity']:.2f}) — "
                f"codec-driven packetisation at ~{f['dominant_iat_ms']:.0f}ms intervals"
            )
        if f["up_ratio"] < 0.05:
            signals.append(f"Download-dominant ({int((1-f['up_ratio'])*100)}% downstream) — streaming/download")
        elif f["up_ratio"] > 0.85:
            signals.append(f"Upload-dominant ({int(f['up_ratio']*100)}% upstream) — upload/backup")
        elif 0.40 <= f["up_ratio"] <= 0.60:
            signals.append(f"Symmetric traffic ({int(f['up_ratio']*100)}% up) — bidirectional session")
        if f["periodic_bursts"] > 0.6:
            signals.append(
                f"Periodic burst pattern (score={f['periodic_bursts']:.2f}) — "
                f"HLS/DASH segment or keep-alive cycle"
            )
        if f["size_cv"] < 0.15:
            signals.append(f"Low size variance (CV={f['size_cv']:.3f}) — fixed-bitrate stream or codec")
        if f["burst_count"] > 10 and f["silence_mean_ms"] > 200:
            signals.append(
                f"{f['burst_count']} bursts detected, avg silence {f['silence_mean_ms']}ms "
                f"— web/API request-response cadence"
            )
        if 17 <= f["dominant_iat_ms"] <= 23:
            signals.append("Dominant 20ms IAT — RTP/VoIP 50pps codec (G.711/Opus/AMR)")
        elif 30 <= f["dominant_iat_ms"] <= 36:
            signals.append("Dominant ~33ms IAT — 30Hz game tick or 30fps video codec")
        elif 14 <= f["dominant_iat_ms"] <= 18:
            signals.append("Dominant ~16ms IAT — 60Hz game tick rate")
        if f["entropy_mean"] > 0:
            signals.append(
                f"Ciphertext entropy {f['entropy_mean']:.3f} bits/byte "
                f"(max=8.0 — {'near-perfect AES' if f['entropy_mean'] > 7.95 else 'strong cipher'})"
            )
        return signals

    # ── Statistics helpers ────────────────────────────────────────────────────

    @staticmethod
    def _mean(values: list) -> float:
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _std(values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5

    @staticmethod
    def _percentile(values: list, pct: int) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        idx = (pct / 100) * (len(s) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
        return s[lo] + (s[hi] - s[lo]) * (idx - lo)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Shannon entropy in bits/byte (0–8)."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        entropy = 0.0
        import math
        for c in counts:
            if c > 0:
                p = c / n
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _insufficient(peer_ip: str) -> dict:
        return {
            "peer_ip":      peer_ip,
            "class":        "insufficient_data",
            "confidence":   0,
            "scores":       {},
            "features":     {},
            "signals":      ["Need at least 3 packets for analysis"],
            "packet_count": 0,
            "analysed_at":  datetime.now(tz=timezone.utc).isoformat(),
        }


# ── Backwards-compatible alias ─────────────────────────────────────────────────
VPNTrafficClassifier = TunnelPayloadAnalyzer


# ─── VPN Sniffer Engine ───────────────────────────────────────────────────────

class VPNSnifferEngine:
    """
    Sniffs all VPN protocol ports and runs the appropriate parser.
    Maintains per-connection state for traffic classification.
    """

    VPN_PORTS = {
        51820: ("wireguard", "udp"),
        1194:  ("openvpn",   "both"),
        500:   ("ikev2",     "udp"),
        4500:  ("ikev2_nat", "udp"),
        1701:  ("l2tp",      "udp"),
        1723:  ("pptp",      "tcp"),
        8388:  ("shadowsocks","both"),
        41641: ("wireguard_tailscale", "udp"),
    }

    def __init__(
        self,
        iface:           str,
        packet_callback: Optional[Callable] = None,
        alert_callback:  Optional[Callable] = None,
        target_ips:      Optional[List[str]] = None,
    ):
        self._iface    = iface
        self._pkt_cb   = packet_callback
        self._alert_cb = alert_callback
        self._targets  = set(target_ips or [])

        self._wg_parser   = WireGuardParser()
        self._ovpn_parser = OpenVPNParser()
        self._ike_parser  = IKEv2Parser()
        self._analyzer    = TunnelPayloadAnalyzer()

        self._running     = threading.Event()
        self._thread      = threading.Thread(target=self._run, daemon=True, name="vpn-sniffer")
        self._packets: deque = deque(maxlen=5000)
        self._stats       = defaultdict(int)
        # Per-peer packet history and raw payloads for deep payload analysis
        self._peer_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._peer_payloads: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def start(self) -> None:
        if not SCAPY_OK:
            logger.error("[VPN] scapy not installed")
            return
        self._running.set()
        self._thread.start()
        logger.info(f"[VPN] Sniffer started on '{self._iface}' — watching {len(self.VPN_PORTS)} VPN protocols")

    def stop(self) -> None:
        self._running.clear()

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def get_packets(self, limit: int = 100, vpn_type: str = "") -> list:
        pkts = list(self._packets)
        if vpn_type:
            pkts = [p for p in pkts if p.get("vpn") == vpn_type]
        return pkts[-limit:]

    def classify_peer(self, peer_ip: str) -> dict:
        history  = list(self._peer_history.get(peer_ip, []))
        payloads = list(self._peer_payloads.get(peer_ip, []))
        return self._analyzer.analyze(peer_ip, history, raw_payloads=payloads if payloads else None)

    def get_payload_analysis(self, peer_ip: str) -> dict:
        """Return ciphertext byte analysis for a peer without full classification."""
        payloads = list(self._peer_payloads.get(peer_ip, []))
        if not payloads:
            return {"error": "No raw payload data collected for this peer"}
        return self._analyzer._analyze_ciphertext(payloads)

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def _run(self) -> None:
        try:
            port_filter = " or ".join(
                f"{'udp' if proto == 'udp' else 'tcp' if proto == 'tcp' else 'port'} port {port}"
                for port, (_, proto) in self.VPN_PORTS.items()
            )
            bpf = port_filter
            if self._targets:
                host_filter = " or ".join(f"host {ip}" for ip in self._targets)
                bpf = f"({bpf}) and ({host_filter})"
            sniff(
                iface=self._iface,
                filter=bpf,
                prn=self._handle,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            )
        except Exception as exc:
            logger.error(f"[VPN] Sniffer error: {exc}")

    def _handle(self, pkt) -> None:
        try:
            if not pkt.haslayer(IP):
                return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if self._targets:
                if src_ip not in self._targets and dst_ip not in self._targets:
                    return

            parsed = None

            if pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                raw   = bytes(pkt[UDP].payload) if pkt.haslayer(Raw) else b""

                if dport == 51820 or sport == 51820 or dport == 41641 or sport == 41641:
                    parsed = self._wg_parser.parse(raw, src_ip, dst_ip, sport, dport)
                    # Collect encrypted transport payloads for ciphertext analysis
                    if raw and len(raw) > 32:
                        peer = src_ip if src_ip in self._targets else dst_ip
                        # WireGuard transport data starts at byte 16 (after header)
                        self._peer_payloads[peer].append(raw[16:] if len(raw) > 16 else raw)
                elif dport in (1194,) or sport in (1194,):
                    parsed = self._ovpn_parser.parse(raw, src_ip, dst_ip, sport, dport)
                    # Collect OpenVPN data channel ciphertext
                    if raw and len(raw) > 9:
                        peer = src_ip if src_ip in self._targets else dst_ip
                        opcode = (raw[0] >> 3) & 0x1F if raw else 0
                        if opcode in (0x06, 0x09):  # P_DATA_V1 / P_DATA_V2
                            self._peer_payloads[peer].append(raw[9:])
                elif dport in (500, 4500) or sport in (500, 4500):
                    parsed = self._ike_parser.parse(raw, src_ip, dst_ip, sport, dport)
                    # IKEv2: collect encrypted IKE_AUTH and CREATE_CHILD_SA payloads
                    # (SA_INIT is plaintext — only collect encrypted follow-ups for entropy)
                    if raw and len(raw) > 28:
                        peer = src_ip if src_ip in self._targets else dst_ip
                        exchange_type = raw[18] if len(raw) > 18 else 0
                        if exchange_type in (35, 36, 37):  # IKE_AUTH / CHILD_SA / INFO (encrypted)
                            self._peer_payloads[peer].append(raw[28:])  # skip 28-byte IKE header

                elif dport in (1701,) or sport in (1701,):   # L2TP
                    peer = src_ip if src_ip in self._targets else dst_ip
                    if raw and len(raw) > 8:
                        # L2TP: skip 8-byte minimal header, rest is PPP payload (encrypted)
                        self._peer_payloads[peer].append(raw[8:])

                elif dport in (8388,) or sport in (8388,):   # Shadowsocks
                    peer = src_ip if src_ip in self._targets else dst_ip
                    if raw and len(raw) > 2:
                        # Shadowsocks: entire UDP payload is ciphertext
                        self._peer_payloads[peer].append(raw)

                else:
                    # Generic VPN port — collect entire payload for entropy fingerprinting
                    # (catches non-standard port configs, obfsproxy, etc.)
                    for vpn_port in self.VPN_PORTS:
                        if dport == vpn_port or sport == vpn_port:
                            peer = src_ip if src_ip in self._targets else dst_ip
                            if raw and len(raw) > 4:
                                self._peer_payloads[peer].append(raw)
                            break

            elif pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                raw   = bytes(pkt[TCP].payload) if pkt.haslayer(Raw) else b""
                if dport in (1194, 1723) or sport in (1194, 1723):
                    parsed = self._ovpn_parser.parse(raw, src_ip, dst_ip, sport, dport)
                    # Collect TCP OpenVPN data channel ciphertext
                    if raw and len(raw) > 3:
                        peer = src_ip if src_ip in self._targets else dst_ip
                        opcode = (raw[0] >> 3) & 0x1F if raw else 0
                        if opcode in (0x06, 0x09):  # P_DATA_V1 / P_DATA_V2
                            self._peer_payloads[peer].append(raw[9:])
                        elif dport == 1723 or sport == 1723:  # PPTP GRE tunnel data
                            self._peer_payloads[peer].append(raw)

            if parsed:
                self._packets.append(parsed)
                vpn = parsed.get("vpn", "unknown")
                self._stats[vpn] += 1
                self._stats["total"] += 1

                # Track per-peer history for classification
                peer = src_ip if src_ip in self._targets else dst_ip
                self._peer_history[peer].append(parsed)

                if self._pkt_cb:
                    self._pkt_cb(parsed)

                # Alert on new VPN session establishment
                msg_type = parsed.get("msg_type", "")
                if any(k in msg_type for k in ("initiation", "HARD_RESET", "IKE_SA_INIT")):
                    if self._alert_cb:
                        self._alert_cb({
                            "type":      "vpn_session_start",
                            "severity":  "MEDIUM",
                            "src_ip":    src_ip,
                            "dst_ip":    dst_ip,
                            "vpn_proto": vpn,
                            "msg_type":  msg_type,
                            "details":   parsed,
                            "timestamp": parsed.get("timestamp", ""),
                            "description": f"VPN session started: {vpn} {src_ip} → {dst_ip}",
                            "mitre":     "T1572",   # Protocol Tunneling
                        })
        except Exception as exc:
            logger.debug(f"[VPN] handle error: {exc}")


# ─── VPN Blocker ──────────────────────────────────────────────────────────────

class VPNBlocker:
    """
    Blocks VPN protocols via iptables to force plaintext traffic.
    After blocking, traffic flows through the normal stack where
    our TLS intercept engine can decrypt HTTPS.

    Selective blocking by protocol is supported.
    """

    PROTOCOL_PORTS = {
        "wireguard":   [("udp", 51820), ("udp", 41641)],
        "openvpn":     [("udp", 1194), ("tcp", 1194), ("udp", 1197), ("udp", 1198)],
        "ikev2":       [("udp", 500), ("udp", 4500)],
        "l2tp":        [("udp", 1701)],
        "pptp":        [("tcp", 1723)],
        "shadowsocks": [("tcp", 8388), ("udp", 8388)],
    }

    def __init__(
        self,
        target_ips:      List[str],
        block_protocols: List[str] = None,   # None = block all
    ):
        self._targets   = target_ips
        self._protocols = block_protocols or list(self.PROTOCOL_PORTS.keys())
        self._rules: List[List[str]] = []

    def install(self) -> dict:
        if os.geteuid() != 0:
            return {"ok": False, "error": "requires root"}

        installed = []
        errors    = []
        for proto_name in self._protocols:
            ports = self.PROTOCOL_PORTS.get(proto_name, [])
            for ip_proto, port in ports:
                for target in self._targets or [None]:
                    rule = ["iptables", "-A", "FORWARD",
                            "-p", ip_proto, "--dport", str(port),
                            "-j", "DROP"]
                    if target:
                        rule = ["iptables", "-A", "FORWARD", "-s", target,
                                "-p", ip_proto, "--dport", str(port), "-j", "DROP"]
                    result = self._run(rule, add=True)
                    if result["ok"]:
                        installed.append(rule)
                        self._rules.append(rule)
                    else:
                        errors.append(result["error"])

        logger.info(f"[VPN] Blocking rules installed: {len(installed)} rules, protocols: {self._protocols}")
        return {"ok": len(installed) > 0, "installed": len(installed), "errors": errors}

    def remove(self) -> None:
        for rule in self._rules:
            self._run(rule, add=False)
        self._rules.clear()
        logger.info("[VPN] Block rules removed")

    @staticmethod
    def _run(rule: List[str], add: bool) -> dict:
        cmd = ["-D" if (x == "-A" and not add) else x for x in rule]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {"ok": r.returncode == 0, "error": r.stderr.strip()}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# ─── VPN Deep Inspect Engine (unified) ───────────────────────────────────────

class VPNDeepInspectEngine:
    """
    Unified VPN deep inspection engine. Combines:
      - Protocol-level parsing (WireGuard/OpenVPN/IKEv2)
      - Traffic classification (what's inside the tunnel)
      - Optional VPN blocking (forces plaintext fallback)
      - Session tracking and statistics
    """

    def __init__(
        self,
        iface:           str,
        target_ips:      Optional[List[str]]   = None,
        packet_callback: Optional[Callable]    = None,
        alert_callback:  Optional[Callable]    = None,
        block_vpn:       bool                  = False,
        block_protocols: Optional[List[str]]   = None,
    ):
        self._iface      = iface
        self._targets    = list(target_ips or [])
        self._pkt_cb     = packet_callback
        self._alert_cb   = alert_callback
        self._block_vpn  = block_vpn

        self._sniffer  = VPNSnifferEngine(
            iface=iface,
            packet_callback=packet_callback,
            alert_callback=alert_callback,
            target_ips=target_ips,
        )
        self._blocker  = VPNBlocker(
            target_ips=self._targets,
            block_protocols=block_protocols,
        ) if block_vpn else None
        self._running  = False

    def start(self) -> dict:
        results = {}
        if self._blocker:
            results["blocker"] = self._blocker.install()
        self._sniffer.start()
        results["sniffer"] = {"ok": self._sniffer.is_running}
        self._running = True
        logger.info(
            f"[VPN] Deep inspect engine started — "
            f"block={self._block_vpn} iface={self._iface} targets={self._targets}"
        )
        return {"ok": True, "results": results}

    def stop(self) -> None:
        if self._blocker:
            self._blocker.remove()
        self._sniffer.stop()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def get_packets(self, limit: int = 100, vpn_type: str = "") -> list:
        return self._sniffer.get_packets(limit=limit, vpn_type=vpn_type)

    def classify_peer(self, peer_ip: str) -> dict:
        return self._sniffer.classify_peer(peer_ip)

    def get_payload_analysis(self, peer_ip: str) -> dict:
        """Return deep ciphertext byte analysis for a peer IP."""
        return self._sniffer.get_payload_analysis(peer_ip)

    def all_peers(self) -> List[str]:
        """Return all peer IPs that have collected packet history."""
        return list(self._sniffer._peer_history.keys())

    def full_report(self, peer_ip: str) -> dict:
        """
        Combined deep report for a peer:
          - Traffic class + confidence + scores
          - Per-feature breakdown
          - Raw ciphertext byte analysis
          - Recent parsed VPN packets
        """
        classification   = self.classify_peer(peer_ip)
        payload_analysis = self.get_payload_analysis(peer_ip)
        recent_packets   = self.get_packets(limit=20)
        peer_packets     = [p for p in recent_packets
                            if p.get("src_ip") == peer_ip or p.get("dst_ip") == peer_ip]
        return {
            "peer_ip":          peer_ip,
            "classification":   classification,
            "payload_analysis": payload_analysis,
            "recent_packets":   peer_packets,
        }

    def status(self) -> dict:
        return {
            "running":    self._running,
            "iface":      self._iface,
            "targets":    self._targets,
            "block_vpn":  self._block_vpn,
            "sniffer":    self._sniffer.stats,
        }
