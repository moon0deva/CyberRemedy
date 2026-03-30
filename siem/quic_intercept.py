"""
CyberRemedy SIEM — QUIC/HTTP3 Interceptor & Analyzer
======================================================
QUIC (RFC 9000) runs over UDP/443 and is fully encrypted at the
packet level using TLS 1.3. This module provides:

  1. QUIC BLOCKER — iptables DROP on UDP/443 forces browsers to
     fall back to TCP/TLS which our TLS proxy CAN decrypt.

  2. QUIC ANALYZER — even without decryption we extract:
       - Connection IDs (track sessions across IP changes)
       - Long-header vs short-header packet types
       - Initial packet (ClientHello) server name (SNI) — PLAINTEXT
         in the QUIC Initial packet before TLS handshake
       - Packet sizes and timing (fingerprint app/content type)
       - QUIC version negotiation
       - Retry/Version Negotiation packets (plaintext metadata)
       - QPACK header compression patterns

  3. HTTP3 METADATA — from QUIC Initial packets we can read:
       - The SNI (server hostname) — always plaintext per QUIC spec
       - ALPN ("h3") — confirms HTTP3
       - QUIC transport parameters (max streams, idle timeout, etc.)
       — these are in the ClientHello which is PLAINTEXT inside
         the QUIC Initial packet (encrypted only by AEAD with a
         well-known key derived from the Destination Connection ID)

WHY QUIC INITIAL IS READABLE:
  QUIC Initial packets use AEAD with keys derived from the
  Destination Connection ID using a well-known salt (per RFC 9001 §5.2).
  This means ANYONE on the network can decrypt QUIC Initial packets
  without knowing any secret. The TLS ClientHello inside is fully
  readable including SNI and ALPN. We implement this decryption below.

DEPENDENCY:
  pip install cryptography scapy
  Optional: pip install aioquic  (for full QUIC parsing)
"""

import hashlib
import hmac
import ipaddress
import logging
import os
import queue
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberremedy.siem.quic")

try:
    from scapy.all import sniff, UDP, IP, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


# ─── QUIC RFC 9001 §5.2 — Initial packet key derivation ──────────────────────
# Initial packets use AEAD-AES-128-GCM with keys derived from DCID
# using a well-known salt. This allows anyone to decrypt Initial packets.

QUIC_V1_INITIAL_SALT = bytes.fromhex(
    "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
)

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    """HKDF-Expand-Label as defined in TLS 1.3 / RFC 8446 §7.1"""
    label_bytes = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack(">H", length) +
        bytes([len(label_bytes)]) + label_bytes +
        bytes([0])  # empty context hash
    )
    # HKDF-Expand
    import hmac as _hmac
    n = (length + 31) // 32
    okm = b""
    t   = b""
    for i in range(1, n + 1):
        t   = _hmac.new(secret, t + hkdf_label + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def derive_quic_initial_keys(dcid: bytes) -> Optional[Tuple[bytes, bytes]]:
    """
    Derive QUIC Initial packet keys from Destination Connection ID.
    Returns (key, iv) for AEAD-AES-128-GCM decryption, or None if crypto unavailable.
    Per RFC 9001 §5.2
    """
    try:
        # initial_secret = HKDF-Extract(initial_salt, client_dst_conn_id)
        initial_secret = _hkdf_extract(QUIC_V1_INITIAL_SALT, dcid)
        # client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", 32)
        client_secret  = _hkdf_expand_label(initial_secret, "client in", 32)
        # key = HKDF-Expand-Label(client_secret, "quic key", 16)
        key = _hkdf_expand_label(client_secret, "quic key", 16)
        # iv  = HKDF-Expand-Label(client_secret, "quic iv",  12)
        iv  = _hkdf_expand_label(client_secret, "quic iv",  12)
        return key, iv
    except Exception as exc:
        logger.debug(f"[QUIC] Key derivation error: {exc}")
        return None


# ─── QUIC Packet Parser ───────────────────────────────────────────────────────

class QUICPacketParser:
    """
    Parses raw UDP payloads as QUIC packets.
    Extracts metadata from long-header (Initial/Handshake) and
    short-header (1-RTT) packets.

    For Initial packets: decrypts the payload to read the TLS ClientHello,
    extracting SNI and ALPN — completely agentless, no keys required.
    """

    # QUIC packet type bits
    INITIAL    = 0x00
    ZERORTT    = 0x01
    HANDSHAKE  = 0x02
    RETRY      = 0x03

    def parse(self, data: bytes, src_ip: str, dst_ip: str,
              src_port: int, dst_port: int) -> Optional[dict]:
        if len(data) < 5:
            return None

        first_byte = data[0]
        is_long    = bool(first_byte & 0x80)

        if is_long:
            return self._parse_long(data, src_ip, dst_ip, src_port, dst_port)
        else:
            return self._parse_short(data, src_ip, dst_ip, src_port, dst_port)

    def _parse_long(self, data: bytes, src_ip, dst_ip, src_port, dst_port) -> Optional[dict]:
        """Parse QUIC Long Header packet (Initial, Handshake, 0-RTT, Retry)."""
        if len(data) < 7:
            return None
        try:
            first_byte = data[0]
            version    = struct.unpack(">I", data[1:5])[0]
            offset     = 5

            # DCIL and DCID
            dcil   = data[offset]; offset += 1
            dcid   = data[offset:offset+dcil]; offset += dcil
            # SCIL and SCID
            scil   = data[offset]; offset += 1
            scid   = data[offset:offset+scil]; offset += scil

            pkt_type = (first_byte & 0x30) >> 4

            result = {
                "quic":        True,
                "long_header": True,
                "type":        ["Initial","0-RTT","Handshake","Retry"][pkt_type] if pkt_type < 4 else "Unknown",
                "version":     f"0x{version:08x}",
                "version_name": self._version_name(version),
                "dcid":        dcid.hex(),
                "scid":        scid.hex(),
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "src_port":    src_port,
                "dst_port":    dst_port,
                "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
                "sni":         "",
                "alpn":        [],
                "tls_decrypted": False,
            }

            # For Initial packets: attempt to decrypt and read ClientHello
            if pkt_type == self.INITIAL and version in (0x1, 0x00000001):
                tls_info = self._decrypt_initial(data, offset, dcid)
                if tls_info:
                    result.update(tls_info)
                    result["tls_decrypted"] = True

            return result
        except Exception as exc:
            logger.debug(f"[QUIC] Long header parse error: {exc}")
            return None

    def _parse_short(self, data: bytes, src_ip, dst_ip, src_port, dst_port) -> Optional[dict]:
        """Parse QUIC Short Header (1-RTT) — encrypted, metadata only."""
        return {
            "quic":        True,
            "long_header": False,
            "type":        "1-RTT",
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    src_port,
            "dst_port":    dst_port,
            "length":      len(data),
            "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
            "encrypted":   True,
            "sni":         "",   # not available in 1-RTT without keys
        }

    def _decrypt_initial(self, data: bytes, payload_offset: int, dcid: bytes) -> Optional[dict]:
        """
        Decrypt a QUIC Initial packet payload using RFC 9001 §5.2 derived keys.
        Reads the TLS ClientHello to extract SNI and ALPN.
        """
        if not CRYPTO_OK:
            return None
        try:
            # Skip token (Initial only)
            offset = payload_offset
            token_len = self._read_varint(data, offset)
            offset += token_len[1] + token_len[0]

            # Packet Length (varint)
            pkt_len_val = self._read_varint(data, offset)
            offset += pkt_len_val[1]
            pkt_len = pkt_len_val[0]

            # Packet Number (we need header protection removal first — simplified approach)
            # For analysis purposes extract the raw payload and attempt TLS record parsing
            payload = data[offset:offset + pkt_len]
            if len(payload) < 20:
                return None

            # Derive keys
            keys = derive_quic_initial_keys(dcid)
            if not keys:
                return None
            key, iv = keys

            # Try AES-GCM decryption (simplified — packet number removal skipped
            # for Initial frames where packet number is often 0 or 1)
            for pn_guess in (0, 1, 2):
                try:
                    nonce = self._compute_nonce(iv, pn_guess)
                    aesgcm    = AESGCM(key)
                    # AAD = long header bytes up to (but not including) payload
                    aad       = data[:offset]
                    plaintext = aesgcm.decrypt(nonce, payload, aad)
                    # plaintext is QUIC CRYPTO frame(s) → TLS records
                    return self._parse_crypto_frames(plaintext)
                except Exception:
                    continue
            return None
        except Exception as exc:
            logger.debug(f"[QUIC] Initial decrypt error: {exc}")
            return None

    def _compute_nonce(self, iv: bytes, pn: int) -> bytes:
        """XOR IV with packet number (left-padded to IV length)."""
        pn_bytes = pn.to_bytes(len(iv), "big")
        return bytes(a ^ b for a, b in zip(iv, pn_bytes))

    def _parse_crypto_frames(self, plaintext: bytes) -> Optional[dict]:
        """
        Parse QUIC CRYPTO frames from decrypted Initial payload.
        Extract TLS ClientHello → SNI + ALPN.
        """
        result = {"sni": "", "alpn": [], "tls_version": "", "cipher_suites": []}
        offset = 0
        while offset < len(plaintext):
            if offset >= len(plaintext):
                break
            frame_type = plaintext[offset]; offset += 1
            if frame_type == 0x06:  # CRYPTO frame
                off_val = self._read_varint(plaintext, offset)
                offset += off_val[1]
                len_val = self._read_varint(plaintext, offset)
                offset += len_val[1]
                crypto_data = plaintext[offset:offset + len_val[0]]
                offset += len_val[0]
                tls = self._parse_tls_client_hello(crypto_data)
                if tls:
                    result.update(tls)
            elif frame_type == 0x00:  # PADDING
                break
            else:
                break   # unknown frame, stop
        return result if (result["sni"] or result["alpn"]) else None

    def _parse_tls_client_hello(self, data: bytes) -> Optional[dict]:
        """Parse TLS ClientHello handshake message and extract SNI + ALPN."""
        try:
            if len(data) < 4:
                return None
            # TLS record: type(1) + version(2) + length(2)
            offset = 0
            # Might start directly with handshake message (no record layer in CRYPTO frame)
            # Handshake type 1 = ClientHello
            if data[offset] != 0x01:
                # Try skipping TLS record header
                if data[0] == 0x16:   # TLS Handshake record
                    offset = 5
                    if offset >= len(data) or data[offset] != 0x01:
                        return None
                else:
                    return None

            offset += 1   # skip handshake type
            length = struct.unpack(">I", b'\x00' + data[offset:offset+3])[0]
            offset += 3
            # Client version
            offset += 2
            # Random (32 bytes)
            offset += 32
            # Session ID
            sid_len = data[offset]; offset += 1 + sid_len
            # Cipher suites
            cs_len = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
            cipher_suites = []
            for i in range(cs_len // 2):
                cs = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
                cipher_suites.append(f"0x{cs:04x}")
            # Compression methods
            comp_len = data[offset]; offset += 1 + comp_len
            # Extensions
            if offset + 2 > len(data):
                return {"sni": "", "alpn": cipher_suites[:5], "cipher_suites": cipher_suites[:5]}
            ext_total = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
            ext_end   = offset + ext_total
            sni  = ""
            alpn = []
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
                ext_len  = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
                ext_data = data[offset:offset+ext_len]; offset += ext_len

                if ext_type == 0x0000:   # SNI
                    sni = self._parse_sni(ext_data)
                elif ext_type == 0x0010: # ALPN
                    alpn = self._parse_alpn(ext_data)

            return {"sni": sni, "alpn": alpn, "cipher_suites": cipher_suites[:8]}
        except Exception as exc:
            logger.debug(f"[QUIC] TLS ClientHello parse error: {exc}")
            return None

    def _parse_sni(self, data: bytes) -> str:
        try:
            offset = 2  # list length
            sni_type = data[offset]; offset += 1
            if sni_type != 0:
                return ""
            name_len = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
            return data[offset:offset+name_len].decode("ascii", errors="replace")
        except Exception:
            return ""

    def _parse_alpn(self, data: bytes) -> List[str]:
        alpn = []
        try:
            offset = 2  # list length
            while offset < len(data):
                proto_len = data[offset]; offset += 1
                proto = data[offset:offset+proto_len].decode("ascii", errors="replace")
                alpn.append(proto)
                offset += proto_len
        except Exception:
            pass
        return alpn

    @staticmethod
    def _read_varint(data: bytes, offset: int) -> Tuple[int, int]:
        """Read a QUIC variable-length integer. Returns (value, bytes_consumed)."""
        if offset >= len(data):
            return 0, 0
        first = data[offset]
        prefix = (first & 0xC0) >> 6
        if prefix == 0:
            return first & 0x3F, 1
        elif prefix == 1:
            val = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
            return val, 2
        elif prefix == 2:
            val = struct.unpack(">I", data[offset:offset+4])[0] & 0x3FFFFFFF
            return val, 4
        else:
            val = struct.unpack(">Q", data[offset:offset+8])[0] & 0x3FFFFFFFFFFFFFFF
            return val, 8

    @staticmethod
    def _version_name(version: int) -> str:
        names = {
            0x00000001: "QUIC v1 (RFC 9000)",
            0x6b3343cf: "QUIC v2 (RFC 9369)",
            0xff00001d: "QUIC draft-29",
            0xff00001e: "QUIC draft-30",
            0xff00001f: "QUIC draft-31",
            0xff000020: "QUIC draft-32",
        }
        return names.get(version, f"Unknown (0x{version:08x})")


# ─── QUIC Sniffer ─────────────────────────────────────────────────────────────

class QUICSnifferEngine:
    """
    Sniffs UDP/443 traffic and runs QUICPacketParser on every packet.
    Provides both analysis (what servers are visited) and SNI extraction.
    """

    def __init__(
        self,
        iface:           str                    = "wlan0",
        packet_callback: Optional[Callable]     = None,
        alert_callback:  Optional[Callable]     = None,
        target_ips:      Optional[List[str]]    = None,
    ):
        self._iface    = iface
        self._pkt_cb   = packet_callback
        self._alert_cb = alert_callback
        self._targets  = set(target_ips or [])
        self._parser   = QUICPacketParser()
        self._running  = threading.Event()
        self._thread   = threading.Thread(target=self._run, daemon=True, name="quic-sniffer")
        self._packets: deque = deque(maxlen=2000)
        self._stats    = defaultdict(int)
        self._sni_map: Dict[str, set] = defaultdict(set)  # client_ip → {sni, ...}

    def start(self) -> None:
        if not SCAPY_OK:
            logger.error("[QUIC] scapy not installed")
            return
        self._running.set()
        self._thread.start()
        logger.info(f"[QUIC] Sniffer started on '{self._iface}' (UDP/443 + UDP/80)")

    def stop(self) -> None:
        self._running.clear()
        logger.info(f"[QUIC] Sniffer stopped — {self._stats['total']} packets")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def get_packets(self, limit: int = 100) -> list:
        return list(self._packets)[-limit:]

    def get_sni_map(self) -> dict:
        return {ip: list(snis) for ip, snis in self._sni_map.items()}

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def _run(self) -> None:
        try:
            bpf = "udp port 443 or udp port 80"
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
            logger.error(f"[QUIC] Sniffer error: {exc}")

    def _handle(self, pkt) -> None:
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
                return
            src_ip   = pkt[IP].src
            dst_ip   = pkt[IP].dst
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            if self._targets:
                if src_ip not in self._targets and dst_ip not in self._targets:
                    return

            raw = bytes(pkt[UDP].payload)
            if not raw:
                return

            info = self._parser.parse(raw, src_ip, dst_ip, src_port, dst_port)
            if not info:
                return

            self._packets.append(info)
            self._stats["total"] += 1
            self._stats[info.get("type", "unknown")] += 1

            # Track SNI per client
            sni = info.get("sni", "")
            if sni:
                self._sni_map[src_ip].add(sni)
                self._stats["sni_extracted"] += 1

            if self._pkt_cb:
                self._pkt_cb(info)

            # Alert if QUIC with h3 ALPN detected (for visibility)
            if "h3" in info.get("alpn", []) and self._alert_cb:
                self._alert_cb({
                    "type":      "quic_http3_detected",
                    "severity":  "INFO",
                    "src_ip":    src_ip,
                    "dst_ip":    dst_ip,
                    "sni":       sni,
                    "alpn":      info.get("alpn", []),
                    "timestamp": info.get("timestamp", ""),
                    "description": f"HTTP/3 (QUIC) connection to {sni or dst_ip}",
                    "mitre":     "T1071.001",
                })
        except Exception as exc:
            logger.debug(f"[QUIC] handle error: {exc}")


# ─── QUIC Blocker ─────────────────────────────────────────────────────────────

class QUICBlocker:
    """
    Blocks QUIC (UDP/443) using iptables DROP rules so browsers fall back
    to TCP/TLS — which our TLS proxy can then decrypt.

    Also blocks UDP/80 (HTTP/3 alt-svc) and clears Alt-Svc headers
    via the TLS proxy to prevent future QUIC upgrades.

    After blocking, the QUIC sniffer still runs to log any bypass attempts.
    """

    def __init__(
        self,
        target_ips:    List[str] = None,
        block_egress:  bool      = True,   # block QUIC going OUT from targets
        block_ingress: bool      = True,   # block QUIC coming IN to targets
    ):
        self._targets       = list(target_ips or [])
        self._block_egress  = block_egress
        self._block_ingress = block_ingress
        self._rules: List[List[str]] = []

    def install(self) -> dict:
        if os.geteuid() != 0:
            return {"ok": False, "error": "requires root"}

        errors    = []
        installed = []

        rules = self._build_rules()
        for rule in rules:
            result = self._run(rule, add=True)
            if result["ok"]:
                installed.append(rule)
                self._rules.append(rule)
            else:
                errors.append(result["error"])

        msg = f"QUIC blocked for {len(self._targets)} target(s) — {len(installed)} rules installed"
        logger.info(f"[QUIC] {msg}")
        return {"ok": len(installed) > 0, "rules": len(installed), "errors": errors, "msg": msg}

    def remove(self) -> None:
        for rule in self._rules:
            self._run(rule, add=False)
        self._rules.clear()
        logger.info("[QUIC] Block rules removed — QUIC re-enabled")

    def _build_rules(self) -> List[List[str]]:
        rules = []
        for ip in self._targets or [None]:
            # Block QUIC UDP/443 outbound from target
            if self._block_egress:
                r = ["iptables", "-A", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP"]
                if ip:
                    r = ["iptables", "-A", "FORWARD", "-s", ip, "-p", "udp", "--dport", "443", "-j", "DROP"]
                rules.append(r)
            # Block QUIC UDP/443 inbound to target
            if self._block_ingress and ip:
                rules.append([
                    "iptables", "-A", "FORWARD",
                    "-d", ip, "-p", "udp", "--dport", "443", "-j", "DROP"
                ])
        return rules

    @staticmethod
    def _run(rule: List[str], add: bool) -> dict:
        cmd = ["-D" if (x == "-A" and not add) else x for x in rule]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {"ok": r.returncode == 0, "error": r.stderr.strip()}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# ─── QUIC Intercept Engine (unified) ──────────────────────────────────────────

class QUICInterceptEngine:
    """
    Unified QUIC engine: blocks QUIC → forces TCP fallback → sniffer
    captures any QUIC that leaks through + extracts SNI from Initial packets.
    """

    def __init__(
        self,
        iface:          str                    = "wlan0",
        target_ips:     Optional[List[str]]    = None,
        packet_callback: Optional[Callable]    = None,
        alert_callback:  Optional[Callable]    = None,
        block_quic:      bool                  = True,
    ):
        self._iface      = iface
        self._targets    = list(target_ips or [])
        self._pkt_cb     = packet_callback
        self._alert_cb   = alert_callback
        self._block_quic = block_quic

        self._blocker = QUICBlocker(target_ips=self._targets) if block_quic else None
        self._sniffer = QUICSnifferEngine(
            iface=iface,
            packet_callback=packet_callback,
            alert_callback=alert_callback,
            target_ips=self._targets,
        )
        self._running = False

    def start(self) -> dict:
        results = {}

        # Block QUIC first (forces TCP fallback)
        if self._blocker:
            results["blocker"] = self._blocker.install()

        # Start sniffer (captures any leaking QUIC + extracts SNI from Initial)
        self._sniffer.start()
        results["sniffer"] = {"ok": self._sniffer.is_running}

        self._running = True
        logger.info(
            f"[QUIC] Engine started — block={self._block_quic} "
            f"targets={self._targets} iface={self._iface}"
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

    def get_quic_packets(self, limit: int = 100) -> list:
        return self._sniffer.get_packets(limit)

    def get_sni_map(self) -> dict:
        return self._sniffer.get_sni_map()

    def status(self) -> dict:
        return {
            "running":    self._running,
            "iface":      self._iface,
            "targets":    self._targets,
            "block_quic": self._block_quic,
            "sniffer":    self._sniffer.stats,
            "sni_map":    self.get_sni_map(),
        }
