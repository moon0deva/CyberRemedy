"""
CyberRemedy SIEM — Agentless TLS/HTTPS Interception Engine
===========================================================
Decrypts HTTPS traffic without installing any software on the target device.

HOW AGENTLESS TLS INTERCEPTION WORKS
--------------------------------------
Standard TLS MITM requires the target to trust your CA certificate.
Agentless approaches to achieve this:

  METHOD A — WPAD/PAC Auto-Proxy (best, works on most networks):
    1. We run a local HTTP server serving a proxy.pac (WPAD) file
    2. We spoof DHCP option 252 (WPAD URL) OR answer mDNS/LLMNR "wpad" queries
    3. Target OS automatically fetches the PAC file and configures our proxy
    4. All HTTP/HTTPS flows through our transparent proxy
    5. On first HTTPS connect the browser shows ONE cert warning
       (click Advanced → Proceed) — after that, flows are captured silently.
       On managed/corporate devices the CA can be pre-trusted.

  METHOD B — iptables REDIRECT (Linux targets on same subnet only):
    Redirect TCP/443 to our local proxy port using DNAT.
    Works transparently; client sees the real cert replaced by ours.
    Same single-warning caveat applies.

  METHOD C — DNS Spoofing + SNI Proxy:
    Intercept DNS, return our IP for target domains,
    run a SNI-aware TLS proxy that presents a forged cert.

WHAT WE CAPTURE (per HTTPS connection):
  - Full URL (scheme + host + path + query string)
  - HTTP method, status code, response size
  - Request headers (User-Agent, Cookie, Authorization, etc.)
  - Response headers
  - Request + response body (JSON, HTML, form data, etc.)
  - TLS version, cipher suite, SNI hostname
  - Certificate info of the real server

WHAT WE CANNOT CAPTURE (honest limits):
  - Certificate-pinned apps (mobile banking, etc.) — they will refuse our cert
  - HPKP-pinned sites (rare now, mostly deprecated)
  - DoH traffic on port 443 (looks like HTTPS, but we do decrypt it anyway
    since it flows through our proxy — DNS queries become visible)

QUIC/HTTP3 BLOCKING:
  QUIC runs on UDP/443. We block it with iptables so browsers fall back
  to TCP/TLS which we then intercept. See quic_blocker.py.

DEPENDENCIES:
  pip install mitmproxy cryptography pyOpenSSL
  System: iptables (Linux), dnsmasq (optional, for WPAD DHCP option)
"""

import asyncio
import ipaddress
import json
import logging
import os
import queue
import socket
import ssl
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("cyberremedy.siem.tls_intercept")

# ─── optional mitmproxy import ────────────────────────────────────────────────
try:
    from mitmproxy import options as mitm_options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import http as mitm_http
    from mitmproxy.addons import default_addons
    MITMPROXY_OK = True
except ImportError:
    MITMPROXY_OK = False
    logger.warning("[TLS] mitmproxy not installed — pip install mitmproxy")

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime as _dt
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    logger.warning("[TLS] cryptography not installed — pip install cryptography")


# ─── CA Certificate Generator ─────────────────────────────────────────────────

class CARootGenerator:
    """
    Generates a self-signed CA root certificate used to sign per-domain
    leaf certificates on-the-fly during interception.

    The CA cert must be trusted by the target device for seamless interception.
    Without trust, the browser will show a TLS warning (still interceptable
    but user must click through).

    Agentless trust methods:
      - WPAD/PAC auto-proxy (browser handles trust via proxy tunnel)
      - Network captive portal (present CA download page on first HTTP req)
      - Push via DHCP option 252 + auto-download script
    """

    CA_DIR = Path("data/tls_ca")

    def __init__(self):
        self.CA_DIR.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.CA_DIR / "cyberremedy_ca.crt"
        self.ca_key_path  = self.CA_DIR / "cyberremedy_ca.key"
        self._ca_cert = None
        self._ca_key  = None
        self._leaf_cache: Dict[str, tuple] = {}   # hostname → (cert_path, key_path)

    def ensure_ca(self) -> tuple:
        """Load existing CA or generate a new one. Returns (cert_path, key_path)."""
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info("[TLS] Using existing CA certificate")
            return str(self.ca_cert_path), str(self.ca_key_path)

        if not CRYPTO_OK:
            raise RuntimeError("cryptography package required: pip install cryptography")

        logger.info("[TLS] Generating new CA root certificate ...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "CyberRemedy Security"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Network Analysis CA"),
            x509.NameAttribute(NameOID.COMMON_NAME,              "CyberRemedy Root CA"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        # Write key
        self.ca_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        # Write cert
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        logger.info(f"[TLS] CA certificate generated: {self.ca_cert_path}")
        self._ca_cert = cert
        self._ca_key  = key
        return str(self.ca_cert_path), str(self.ca_key_path)

    def get_ca_cert_pem(self) -> str:
        """Return CA cert as PEM string (for WPAD/captive portal download)."""
        if self.ca_cert_path.exists():
            return self.ca_cert_path.read_text()
        return ""


# ─── mitmproxy Addon: captures decrypted flows ────────────────────────────────

class TLSFlowCapture:
    """
    mitmproxy addon that captures every decrypted HTTP/HTTPS flow
    and forwards it to CyberRemedy's alert/analysis pipeline.
    """

    def __init__(self, flow_callback: Optional[Callable] = None):
        self._cb     = flow_callback
        self._count  = 0
        self._flows: deque = deque(maxlen=2000)
        self._stats: Dict  = defaultdict(int)

    # ── mitmproxy hooks ───────────────────────────────────────────────────────

    def request(self, flow: "mitm_http.HTTPFlow") -> None:
        """Called when a full request is received (before sending to server)."""
        try:
            self._tag_flow(flow, "request")
        except Exception as exc:
            logger.debug(f"[TLS] request hook error: {exc}")

    def response(self, flow: "mitm_http.HTTPFlow") -> None:
        """Called when full response is received. Best place to capture body."""
        try:
            record = self._extract(flow)
            if record:
                self._flows.append(record)
                self._count += 1
                self._stats[record["scheme"]] += 1
                self._stats["total"] += 1
                if self._cb:
                    self._cb(record)
        except Exception as exc:
            logger.debug(f"[TLS] response hook error: {exc}")

    def tls_start_client(self, tls_start) -> None:
        """Log TLS handshake metadata."""
        try:
            self._stats["tls_handshakes"] += 1
        except Exception:
            pass

    # ── extraction ────────────────────────────────────────────────────────────

    def _tag_flow(self, flow, stage: str) -> None:
        flow.metadata["cr_stage"] = stage
        flow.metadata["cr_ts"]    = datetime.now(tz=timezone.utc).isoformat()

    def _extract(self, flow) -> Optional[dict]:
        req  = flow.request
        resp = flow.response

        # Request body
        req_body = b""
        try:
            req_body = req.content or b""
        except Exception:
            pass

        # Response body (decode if text)
        resp_body_raw = b""
        resp_body_str = ""
        try:
            resp_body_raw = resp.content or b""
            ct = resp.headers.get("content-type", "")
            if any(t in ct for t in ("text", "json", "xml", "javascript", "html")):
                resp_body_str = resp_body_raw.decode("utf-8", errors="replace")[:8192]
        except Exception:
            pass

        # TLS info
        tls_info = {}
        try:
            if flow.server_conn and flow.server_conn.tls_established:
                tls_info = {
                    "version":    str(flow.server_conn.tls_version or ""),
                    "cipher":     str(flow.server_conn.cipher or ""),
                    "sni":        flow.server_conn.sni or "",
                    "server_cert_cn": self._cert_cn(flow),
                }
        except Exception:
            pass

        # Client IP
        client_ip = ""
        try:
            client_ip = flow.client_conn.peername[0] if flow.client_conn else ""
        except Exception:
            pass

        record = {
            "timestamp":      datetime.now(tz=timezone.utc).isoformat(),
            "type":           "tls_decrypted",
            "client_ip":      client_ip,
            "scheme":         req.scheme,           # "https" or "http"
            "host":           req.pretty_host,
            "url":            req.pretty_url,
            "method":         req.method,
            "path":           req.path,
            "http_version":   req.http_version,

            # Request details
            "req_headers":    dict(req.headers),
            "req_body_len":   len(req_body),
            "req_body":       req_body.decode("utf-8", errors="replace")[:4096] if req_body else "",
            "req_content_type": req.headers.get("content-type", ""),

            # Response details
            "status_code":    resp.status_code if resp else 0,
            "resp_headers":   dict(resp.headers) if resp else {},
            "resp_body_len":  len(resp_body_raw),
            "resp_body":      resp_body_str,
            "resp_content_type": resp.headers.get("content-type", "") if resp else "",

            # TLS metadata
            "tls":            tls_info,
            "is_https":       req.scheme == "https",
        }

        # Detect sensitive data patterns in decrypted body
        record["sensitive_fields"] = self._detect_sensitive(req, req_body)

        return record

    def _cert_cn(self, flow) -> str:
        try:
            cert = flow.server_conn.certificate
            if cert:
                return cert.cn or ""
        except Exception:
            pass
        return ""

    def _detect_sensitive(self, req, body: bytes) -> list:
        """Flag requests containing credentials, tokens, or PII."""
        found = []
        body_str = body.decode("utf-8", errors="replace").lower() if body else ""
        headers  = {k.lower(): v for k, v in req.headers.items()}

        checks = [
            ("authorization_header",  "authorization" in headers),
            ("bearer_token",          "bearer " in headers.get("authorization", "").lower()),
            ("basic_auth",            "basic "  in headers.get("authorization", "").lower()),
            ("cookie_header",         "cookie"  in headers),
            ("session_token",         any(k in body_str for k in ("session", "sess_id", "sessionid"))),
            ("password_field",        any(k in body_str for k in ("password=", "passwd=", "pwd="))),
            ("username_field",        any(k in body_str for k in ("username=", "user=", "email=", "login="))),
            ("api_key",               any(k in body_str for k in ("api_key=", "apikey=", "access_token=", "token="))),
            ("credit_card_pattern",   self._has_cc_pattern(body_str)),
            ("form_post",             req.method == "POST" and "application/x-www-form-urlencoded" in req.headers.get("content-type", "")),
            ("json_credentials",      req.method in ("POST", "PUT") and "application/json" in req.headers.get("content-type", "") and any(k in body_str for k in ("password", "secret", "token", "credential"))),
        ]
        for name, condition in checks:
            if condition:
                found.append(name)
        return found

    @staticmethod
    def _has_cc_pattern(text: str) -> bool:
        """Very rough Luhn-ish credit card number detection."""
        import re
        return bool(re.search(r'\b(?:\d[ -]?){13,16}\b', text))

    # ── accessors ─────────────────────────────────────────────────────────────

    def get_flows(self, limit: int = 100, client_ip: str = "") -> list:
        flows = list(self._flows)
        if client_ip:
            flows = [f for f in flows if f.get("client_ip") == client_ip]
        return flows[-limit:]

    @property
    def total_count(self) -> int:
        return self._count

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# ─── Transparent TLS Proxy (mitmproxy wrapper) ────────────────────────────────

class TransparentTLSProxy:
    """
    Runs mitmproxy in transparent mode on a local port.
    Traffic is redirected here via iptables REDIRECT rules (set by IptablesRedirector).

    Agentless delivery methods for the CA cert:
      A) WPAD auto-proxy   — target configures proxy automatically via DHCP/DNS
      B) Captive portal    — first HTTP request served a "install CA" page
      C) Manual            — admin installs CA on target once (not truly agentless)
    """

    DEFAULT_PORT = 8080   # transparent proxy listen port

    def __init__(
        self,
        listen_port:    int           = DEFAULT_PORT,
        ca_cert_path:   str           = "",
        ca_key_path:    str           = "",
        flow_callback:  Optional[Callable] = None,
        target_ips:     Optional[List[str]] = None,
        mode:           str           = "transparent",  # transparent | regular
    ):
        self._port      = listen_port
        self._ca_cert   = ca_cert_path
        self._ca_key    = ca_key_path
        self._flow_cb   = flow_callback
        self._targets   = set(target_ips or [])
        self._mode      = mode

        self._addon     = TLSFlowCapture(flow_callback=self._on_flow)
        self._master    = None
        self._thread    = None
        self._loop      = None
        self._running   = False
        self._error     = ""

    def start(self) -> dict:
        if not MITMPROXY_OK:
            return {"ok": False, "error": "mitmproxy not installed — pip install mitmproxy"}
        if not self._ca_cert or not Path(self._ca_cert).exists():
            return {"ok": False, "error": f"CA cert not found: {self._ca_cert}"}

        try:
            self._thread = threading.Thread(
                target=self._run_proxy,
                daemon=True,
                name="tls-proxy",
            )
            self._thread.start()
            time.sleep(1.5)   # give mitmproxy time to bind
            self._running = True
            logger.info(
                f"[TLS] Transparent proxy started on port {self._port} "
                f"(mode={self._mode})"
            )
            return {"ok": True, "port": self._port, "mode": self._mode}
        except Exception as exc:
            self._error = str(exc)
            logger.error(f"[TLS] Proxy start failed: {exc}")
            return {"ok": False, "error": str(exc)}

    def stop(self) -> None:
        if self._master:
            try:
                self._master.shutdown()
            except Exception:
                pass
        self._running = False
        logger.info("[TLS] Transparent proxy stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def get_flows(self, limit: int = 100, client_ip: str = "") -> list:
        return self._addon.get_flows(limit=limit, client_ip=client_ip)

    @property
    def stats(self) -> dict:
        return {
            "running":       self._running,
            "port":          self._port,
            "mode":          self._mode,
            "total_flows":   self._addon.total_count,
            **self._addon.stats,
            "error":         self._error,
        }

    def _on_flow(self, record: dict) -> None:
        """Filter by target IPs if configured, then forward to callback."""
        if self._targets and record.get("client_ip") not in self._targets:
            return
        if self._flow_cb:
            try:
                self._flow_cb(record)
            except Exception as exc:
                logger.debug(f"[TLS] flow_callback error: {exc}")

    def _run_proxy(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            opts = mitm_options.Options(
                listen_host  = "0.0.0.0",
                listen_port  = self._port,
                ssl_insecure = True,      # accept self-signed certs from real servers
                confdir      = str(Path("data/tls_ca")),
            )

            if self._mode == "transparent":
                opts.update(mode=["transparent"])
            else:
                opts.update(mode=["regular"])

            self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self._master.addons.add(self._addon)

            self._loop.run_until_complete(self._master.run())
        except Exception as exc:
            if "address already in use" in str(exc).lower():
                self._error = f"Port {self._port} already in use — change tls.proxy_port in config"
            else:
                self._error = str(exc)
            logger.error(f"[TLS] Proxy thread error: {exc}")
            self._running = False


# ─── iptables Redirector ──────────────────────────────────────────────────────

class IptablesRedirector:
    """
    Uses iptables REDIRECT to transparently forward TCP/443 (HTTPS) and
    TCP/80 (HTTP) from target devices to our local proxy port.

    Rules are inserted in the PREROUTING chain (DNAT) so packets destined
    for any external server are redirected to localhost:proxy_port instead.

    Cleanup: rules are removed on stop() to restore normal routing.
    """

    def __init__(
        self,
        proxy_port:  int        = 8080,
        target_ips:  List[str]  = None,
        intercept_http:  bool   = True,
        intercept_https: bool   = True,
    ):
        self._proxy_port       = proxy_port
        self._targets          = list(target_ips or [])
        self._intercept_http   = intercept_http
        self._intercept_https  = intercept_https
        self._rules_installed  = []   # track inserted rules for cleanup

    def install(self) -> dict:
        """Install iptables REDIRECT rules for all target IPs."""
        if os.geteuid() != 0:
            return {"ok": False, "error": "iptables requires root"}

        errors = []
        installed = []

        for ip in self._targets:
            rules = self._build_rules(ip)
            for rule in rules:
                result = self._run_iptables(rule, add=True)
                if result["ok"]:
                    installed.append(rule)
                    self._rules_installed.append(rule)
                else:
                    errors.append(result["error"])

        # Enable IP forwarding
        self._set_ip_forward(True)

        if errors:
            logger.warning(f"[TLS] iptables: {len(errors)} rule(s) failed: {errors}")
        logger.info(
            f"[TLS] iptables REDIRECT installed for {len(self._targets)} target(s) "
            f"→ port {self._proxy_port}"
        )
        return {
            "ok":        len(installed) > 0,
            "installed": len(installed),
            "errors":    errors,
        }

    def remove(self) -> None:
        """Remove all installed iptables rules."""
        for rule in self._rules_installed:
            self._run_iptables(rule, add=False)
        self._rules_installed.clear()
        logger.info("[TLS] iptables REDIRECT rules removed")

    def add_target(self, ip: str) -> bool:
        """Dynamically add a new target IP to redirect."""
        if ip in self._targets:
            return True
        rules = self._build_rules(ip)
        ok = True
        for rule in rules:
            result = self._run_iptables(rule, add=True)
            if result["ok"]:
                self._rules_installed.append(rule)
            else:
                ok = False
        if ok:
            self._targets.append(ip)
        return ok

    def remove_target(self, ip: str) -> bool:
        """Remove redirect rules for a specific IP."""
        rules = self._build_rules(ip)
        for rule in rules:
            self._run_iptables(rule, add=False)
            if rule in self._rules_installed:
                self._rules_installed.remove(rule)
        if ip in self._targets:
            self._targets.remove(ip)
        return True

    def _build_rules(self, ip: str) -> List[List[str]]:
        rules = []
        if self._intercept_https:
            # HTTPS: redirect port 443 to proxy
            rules.append([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-s", ip,
                "-p", "tcp", "--dport", "443",
                "-j", "REDIRECT", "--to-port", str(self._proxy_port),
            ])
        if self._intercept_http:
            # HTTP: redirect port 80 to proxy
            rules.append([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-s", ip,
                "-p", "tcp", "--dport", "80",
                "-j", "REDIRECT", "--to-port", str(self._proxy_port),
            ])
        return rules

    @staticmethod
    def _run_iptables(rule: List[str], add: bool) -> dict:
        cmd = list(rule)
        if not add:
            # Replace -A (append) with -D (delete)
            cmd = ["-D" if x == "-A" else x for x in cmd]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return {"ok": False, "error": result.stderr.strip()}
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @staticmethod
    def _set_ip_forward(enable: bool) -> None:
        val = "1" if enable else "0"
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text(val + "\n")
        except Exception as exc:
            logger.warning(f"[TLS] IP forward set failed: {exc}")


# ─── WPAD Auto-Proxy Server ───────────────────────────────────────────────────

class WPADServer:
    """
    Serves a WPAD (Web Proxy Auto-Discovery) PAC file so target devices
    automatically configure CyberRemedy as their HTTP/HTTPS proxy.

    Agentless delivery:
      - DHCP option 252 (wpad-url) pointing to http://<our-ip>/wpad.dat
      - mDNS/LLMNR response for "wpad" hostname
      - Target browser checks http://wpad/wpad.dat automatically on startup

    The PAC file routes ALL traffic through our proxy.
    On first HTTPS connection the browser shows one cert warning;
    after accepting it, all subsequent connections are silently decrypted.

    ALSO serves:
      GET /ca.crt  — CA certificate download for manual installation
      GET /        — Captive portal page with CA install instructions
    """

    def __init__(
        self,
        proxy_host:  str = "",        # our IP on the network
        proxy_port:  int = 8080,
        listen_port: int = 8088,      # WPAD HTTP server port
        ca_cert_pem: str = "",
    ):
        self._proxy_host  = proxy_host or self._detect_local_ip()
        self._proxy_port  = proxy_port
        self._listen_port = listen_port
        self._ca_pem      = ca_cert_pem
        self._server      = None
        self._thread      = None
        self._running     = False

    def start(self) -> dict:
        try:
            import http.server
            proxy_host = self._proxy_host
            proxy_port = self._proxy_port
            ca_pem     = self._ca_pem
            listen_port = self._listen_port

            class WPADHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path in ("/wpad.dat", "/wpad", "/proxy.pac"):
                        self._serve_pac()
                    elif self.path in ("/ca.crt", "/ca.pem", "/cyberremedy_ca.crt"):
                        self._serve_ca()
                    else:
                        self._serve_portal()

                def _serve_pac(self):
                    pac = (
                        f'function FindProxyForURL(url, host) {{\n'
                        f'  return "PROXY {proxy_host}:{proxy_port}; DIRECT";\n'
                        f'}}\n'
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                    self.send_header("Content-Length", str(len(pac)))
                    self.end_headers()
                    self.wfile.write(pac.encode())

                def _serve_ca(self):
                    cert = ca_pem.encode() if ca_pem else b""
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-x509-ca-cert")
                    self.send_header("Content-Disposition", 'attachment; filename="cyberremedy_ca.crt"')
                    self.send_header("Content-Length", str(len(cert)))
                    self.end_headers()
                    self.wfile.write(cert)

                def _serve_portal(self):
                    html = f"""<!DOCTYPE html>
<html><head><title>CyberRemedy Network Security</title>
<style>body{{font-family:sans-serif;max-width:700px;margin:40px auto;padding:20px;}}
.btn{{background:#2563eb;color:#fff;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:16px;text-decoration:none;display:inline-block;margin:8px 4px;}}
.warn{{background:#fef3c7;border:1px solid #f59e0b;padding:16px;border-radius:6px;margin:16px 0;}}
code{{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-family:monospace;}}
</style></head><body>
<h2>🔒 CyberRemedy — Network Security Monitor</h2>
<p>This network is monitored by CyberRemedy for security analysis.</p>
<div class="warn">
<strong>Action required:</strong> To enable full HTTPS analysis, install the
CyberRemedy CA certificate on this device.
</div>
<h3>Install CA Certificate:</h3>
<a class="btn" href="/ca.crt">⬇ Download CA Certificate</a>
<h3>Installation Instructions:</h3>
<p><strong>Windows:</strong> Double-click the .crt file → Install Certificate →
Local Machine → Place in "Trusted Root Certification Authorities"</p>
<p><strong>macOS:</strong> Double-click → Keychain Access → Always Trust</p>
<p><strong>Linux/Chrome:</strong> Settings → Privacy → Manage Certificates →
Import → Authorities</p>
<p><strong>Android:</strong> Settings → Security → Install from storage</p>
<p><strong>iOS:</strong> Open link → Install profile → Settings → General →
VPN & Device Management → Trust</p>
<hr>
<p>Proxy: <code>{proxy_host}:{proxy_port}</code> &nbsp;|&nbsp;
PAC: <code>http://{proxy_host}:{listen_port}/wpad.dat</code></p>
</body></html>"""
                    body = html.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, fmt, *args):
                    pass  # suppress access log noise

            import socketserver
            self._server = socketserver.ThreadingTCPServer(("0.0.0.0", listen_port), WPADHandler)
            self._server.allow_reuse_address = True
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
                name="wpad-server",
            )
            self._thread.start()
            self._running = True
            wpad_url = f"http://{self._proxy_host}:{listen_port}/wpad.dat"
            ca_url   = f"http://{self._proxy_host}:{listen_port}/ca.crt"
            logger.info(f"[TLS] WPAD server running — PAC: {wpad_url}  CA: {ca_url}")
            return {
                "ok":       True,
                "wpad_url": wpad_url,
                "ca_url":   ca_url,
                "proxy":    f"{self._proxy_host}:{proxy_port}",
            }
        except Exception as exc:
            self._running = False
            logger.error(f"[TLS] WPAD server error: {exc}")
            return {"ok": False, "error": str(exc)}

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass
        self._running = False

    @staticmethod
    def _detect_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


# ─── TLS Intercept Engine (unified façade) ────────────────────────────────────

class TLSInterceptEngine:
    """
    Unified TLS/HTTPS decryption engine. Wires together:
      - CARootGenerator  (generate/load CA cert)
      - WPADServer       (auto-configure proxy on targets — agentless)
      - IptablesRedirector (transparent TCP redirect — Linux)
      - TransparentTLSProxy (mitmproxy — actual decryption)

    Usage (from SIEMManager or API):
      engine = TLSInterceptEngine(config, flow_callback=my_callback)
      engine.start(target_ips=["192.168.1.50"])
      flows = engine.get_flows(client_ip="192.168.1.50")
      engine.stop()
    """

    def __init__(
        self,
        config:         dict             = None,
        flow_callback:  Optional[Callable] = None,
        alert_callback: Optional[Callable] = None,
    ):
        cfg = config or {}
        self._proxy_port    = cfg.get("proxy_port",  8080)
        self._wpad_port     = cfg.get("wpad_port",   8088)
        self._mode          = cfg.get("mode",         "transparent")   # transparent | wpad
        self._intercept_http  = cfg.get("intercept_http",  True)
        self._intercept_https = cfg.get("intercept_https", True)
        self._flow_cb       = flow_callback
        self._alert_cb      = alert_callback

        self._ca_gen        = CARootGenerator()
        self._proxy         = None
        self._wpad          = None
        self._redirector    = None
        self._running       = False
        self._target_ips: List[str] = []
        self._intercepted: deque = deque(maxlen=5000)
        self._error         = ""

    def start(self, target_ips: List[str] = None) -> dict:
        """Start full TLS interception pipeline."""
        self._target_ips = list(target_ips or [])
        results = {}

        # 1. Generate / load CA
        try:
            ca_cert, ca_key = self._ca_gen.ensure_ca()
            results["ca"] = {"ok": True, "cert": ca_cert, "key": ca_key}
        except Exception as exc:
            return {"ok": False, "error": f"CA generation failed: {exc}"}

        # 2. Start mitmproxy
        self._proxy = TransparentTLSProxy(
            listen_port   = self._proxy_port,
            ca_cert_path  = ca_cert,
            ca_key_path   = ca_key,
            flow_callback = self._on_flow,
            target_ips    = self._target_ips,
            mode          = self._mode,
        )
        proxy_result = self._proxy.start()
        results["proxy"] = proxy_result
        if not proxy_result["ok"]:
            return {"ok": False, "error": proxy_result["error"], "results": results}

        # 3. Start WPAD server (agentless CA delivery + PAC file)
        self._wpad = WPADServer(
            proxy_port  = self._proxy_port,
            listen_port = self._wpad_port,
            ca_cert_pem = self._ca_gen.get_ca_cert_pem(),
        )
        wpad_result = self._wpad.start()
        results["wpad"] = wpad_result

        # 4. Install iptables REDIRECT rules (transparent mode)
        if self._mode == "transparent" and self._target_ips and os.geteuid() == 0:
            self._redirector = IptablesRedirector(
                proxy_port      = self._proxy_port,
                target_ips      = self._target_ips,
                intercept_http  = self._intercept_http,
                intercept_https = self._intercept_https,
            )
            redir_result = self._redirector.install()
            results["iptables"] = redir_result
        else:
            results["iptables"] = {"ok": False, "reason": "no targets or not root — use WPAD mode"}

        self._running = True
        logger.info(
            f"[TLS] Interception engine started — "
            f"targets={self._target_ips} mode={self._mode} "
            f"proxy=:{self._proxy_port} wpad=:{self._wpad_port}"
        )
        return {"ok": True, "results": results}

    def stop(self) -> None:
        if self._proxy:
            self._proxy.stop()
        if self._wpad:
            self._wpad.stop()
        if self._redirector:
            self._redirector.remove()
        self._running = False
        logger.info("[TLS] Interception engine stopped")

    def add_target(self, ip: str) -> bool:
        if ip not in self._target_ips:
            self._target_ips.append(ip)
        if self._redirector:
            return self._redirector.add_target(ip)
        if self._proxy:
            self._proxy._targets.add(ip)
        return True

    def remove_target(self, ip: str) -> bool:
        if ip in self._target_ips:
            self._target_ips.remove(ip)
        if self._redirector:
            return self._redirector.remove_target(ip)
        if self._proxy and ip in self._proxy._targets:
            self._proxy._targets.discard(ip)
        return True

    def get_flows(self, limit: int = 100, client_ip: str = "") -> list:
        flows = list(self._intercepted)
        if client_ip:
            flows = [f for f in flows if f.get("client_ip") == client_ip]
        return flows[-limit:]

    def status(self) -> dict:
        return {
            "running":      self._running,
            "mode":         self._mode,
            "proxy_port":   self._proxy_port,
            "wpad_port":    self._wpad_port,
            "targets":      self._target_ips,
            "ca_cert":      str(self._ca_gen.ca_cert_path),
            "proxy":        self._proxy.stats if self._proxy else {},
            "wpad_running": self._wpad._running if self._wpad else False,
            "error":        self._error,
            "total_flows":  len(self._intercepted),
        }

    def _on_flow(self, record: dict) -> None:
        self._intercepted.append(record)
        # Generate alert for sensitive data
        if record.get("sensitive_fields") and self._alert_cb:
            try:
                self._alert_cb({
                    "type":         "tls_sensitive_data",
                    "severity":     "HIGH",
                    "src_ip":       record.get("client_ip", ""),
                    "dst_host":     record.get("host", ""),
                    "url":          record.get("url", ""),
                    "method":       record.get("method", ""),
                    "sensitive":    record.get("sensitive_fields", []),
                    "timestamp":    record.get("timestamp", ""),
                    "description":  f"Sensitive data intercepted: {record.get('sensitive_fields')}",
                    "mitre":        "T1040",  # Network Sniffing
                })
            except Exception as exc:
                logger.debug(f"[TLS] alert_callback error: {exc}")
