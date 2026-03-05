"""
AID-ARS Honeypot Sensors
Deploys decoy services (SSH, HTTP, SMB, FTP, Telnet) that alert on any connection.
Zero false positives — any connection to a honeypot is malicious by definition.
Inspired by OpenCanary.
"""

import socket
import threading
import logging
from datetime import datetime
from typing import List, Dict, Callable, Optional

logger = logging.getLogger("aidars.honeypot")


class HoneypotService:
    """Base class for all honeypot services."""

    def __init__(self, port: int, service_name: str, banner: bytes,
                 alert_callback: Callable = None):
        self.port = port
        self.service_name = service_name
        self.banner = banner
        self.alert_callback = alert_callback
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.connection_count = 0

    def _emit_alert(self, src_ip: str, src_port: int, data: bytes = b""):
        self.connection_count += 1
        alert = {
            "type": f"HONEYPOT_{self.service_name.upper()}_HIT",
            "severity": "CRITICAL",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": self.port,
            "detail": (
                f"Honeypot {self.service_name} connection from {src_ip}:{src_port}. "
                f"Any connection to a decoy service is malicious."
            ),
            "mitre_id": "T1046",
            "confidence": 100,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "honeypot",
            "honeypot_service": self.service_name,
            "risk_score": 95,
            "data_preview": data[:100].decode("utf-8", errors="replace") if data else "",
        }
        logger.critical(f"HONEYPOT HIT: {self.service_name}:{self.port} from {src_ip}:{src_port}")
        if self.alert_callback:
            self.alert_callback(alert)
        return alert

    def _handle_client(self, conn: socket.socket, addr):
        src_ip, src_port = addr[0], addr[1]
        try:
            # Send banner to appear realistic
            if self.banner:
                conn.sendall(self.banner)
            # Try to receive credentials/data
            conn.settimeout(3.0)
            try:
                data = conn.recv(512)
            except socket.timeout:
                data = b""
            self._emit_alert(src_ip, src_port, data)
        except Exception as e:
            logger.debug(f"Honeypot {self.service_name} client error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def start(self):
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("0.0.0.0", self.port))
            self._server_sock.listen(5)
            self._server_sock.settimeout(1.0)
            self._running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            logger.info(f"Honeypot {self.service_name} listening on port {self.port}")
            return True
        except OSError as e:
            logger.warning(f"Honeypot {self.service_name}:{self.port} bind failed: {e}")
            return False

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def to_dict(self) -> dict:
        return {
            "service": self.service_name,
            "port": self.port,
            "running": self._running,
            "connection_count": self.connection_count,
        }


class SSHHoneypot(HoneypotService):
    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def __init__(self, port: int = 2222, alert_callback: Callable = None):
        super().__init__(port, "SSH", self.BANNER, alert_callback)


class HTTPHoneypot(HoneypotService):
    BANNER = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.58\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body><h1>Admin Panel</h1></body></html>"
    )

    def __init__(self, port: int = 8080, alert_callback: Callable = None):
        super().__init__(port, "HTTP", self.BANNER, alert_callback)


class FTPHoneypot(HoneypotService):
    BANNER = b"220 FTP Server Ready\r\n"

    def __init__(self, port: int = 2121, alert_callback: Callable = None):
        super().__init__(port, "FTP", self.BANNER, alert_callback)


class TelnetHoneypot(HoneypotService):
    BANNER = b"\r\nUbuntu 22.04 LTS\r\nlogin: "

    def __init__(self, port: int = 2323, alert_callback: Callable = None):
        super().__init__(port, "TELNET", self.BANNER, alert_callback)


class SMBHoneypot(HoneypotService):
    """SMB honeypot — just listens on port, no real SMB negotiation needed."""
    BANNER = b""

    def __init__(self, port: int = 4445, alert_callback: Callable = None):
        super().__init__(port, "SMB", self.BANNER, alert_callback)


class MySQLHoneypot(HoneypotService):
    # MySQL 8.0 greeting packet (simplified)
    BANNER = b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00"

    def __init__(self, port: int = 3307, alert_callback: Callable = None):
        super().__init__(port, "MYSQL", self.BANNER, alert_callback)


class HoneypotManager:
    """
    Manages all honeypot services.
    All alerts funnel through a single callback to the detection pipeline.
    """

    DEFAULT_SERVICES = [
        ("ssh", SSHHoneypot, 2222),
        ("http", HTTPHoneypot, 8080),
        ("ftp", FTPHoneypot, 2121),
        ("telnet", TelnetHoneypot, 2323),
        ("smb", SMBHoneypot, 4445),
        ("mysql", MySQLHoneypot, 3307),
    ]

    def __init__(self, alert_callback: Callable = None, config: dict = None):
        self.alert_callback = alert_callback
        self._services: Dict[str, HoneypotService] = {}
        self._alerts: List[dict] = []
        self._config = config or {}
        self._enabled = self._config.get("enabled", True)

    def _on_alert(self, alert: dict):
        self._alerts.append(alert)
        if self.alert_callback:
            self.alert_callback(alert)

    def start_all(self):
        if not self._enabled:
            logger.info("Honeypots disabled in config")
            return

        enabled_services = self._config.get("services", [s[0] for s in self.DEFAULT_SERVICES])
        port_overrides = self._config.get("ports", {})

        service_classes = {
            "ssh": SSHHoneypot,
            "http": HTTPHoneypot,
            "ftp": FTPHoneypot,
            "telnet": TelnetHoneypot,
            "smb": SMBHoneypot,
            "mysql": MySQLHoneypot,
        }
        default_ports = {s[0]: s[2] for s in self.DEFAULT_SERVICES}

        started = 0
        for name in enabled_services:
            cls = service_classes.get(name)
            if not cls:
                continue
            port = port_overrides.get(name, default_ports.get(name, 9999))
            svc = cls(port=port, alert_callback=self._on_alert)
            if svc.start():
                self._services[name] = svc
                started += 1

        logger.info(f"Honeypot manager: {started}/{len(enabled_services)} services started")

    def stop_all(self):
        for svc in self._services.values():
            svc.stop()

    def get_alerts(self, limit: int = 100) -> List[dict]:
        return list(reversed(self._alerts[-limit:]))

    def get_status(self) -> List[dict]:
        return [svc.to_dict() for svc in self._services.values()]

    @property
    def stats(self) -> dict:
        return {
            "services_running": sum(1 for s in self._services.values() if s._running),
            "total_hits": len(self._alerts),
            "total_connections": sum(s.connection_count for s in self._services.values()),
        }
