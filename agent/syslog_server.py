"""
AID-ARS v4.0 — Syslog Ingestion Server
Listens on UDP/TCP 514 (or custom port) for RFC 3164/5424 syslog.
Also accepts Windows Event Log in JSON format from the agent.
No root needed if port > 1024 (default: 5514).
"""
import re, json, socket, threading, logging as _logging
from datetime import datetime
from typing import Callable, Optional
from pathlib import Path

logger = _logging.getLogger("aidars.syslog")

# RFC 3164 syslog pattern
_SYSLOG_RE = re.compile(
    r'<(?P<pri>\d+)>'
    r'(?P<ts>\w{3}\s+\d+ \d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<tag>\S+?):\s*'
    r'(?P<msg>.*)', re.DOTALL
)

_SEVERITY_MAP = {0:"CRITICAL",1:"CRITICAL",2:"CRITICAL",3:"HIGH",
                 4:"HIGH",5:"MEDIUM",6:"LOW",7:"LOW"}
_FACILITY_MAP = {0:"kernel",1:"user",2:"mail",3:"system",4:"auth",
                 5:"syslog",6:"lpr",7:"news",8:"uucp",9:"clock",
                 10:"auth",11:"ftp",16:"local0",17:"local1",18:"local2"}

def parse_syslog(raw: str) -> Optional[dict]:
    """Parse RFC 3164 syslog message into structured dict."""
    raw = raw.strip()
    m = _SYSLOG_RE.match(raw)
    if not m:
        # Fallback: treat whole line as message
        return {"raw": raw, "severity": "LOW", "facility": "unknown",
                "host": "unknown", "tag": "syslog", "message": raw,
                "timestamp": datetime.utcnow().isoformat(), "source": "syslog"}
    pri = int(m.group("pri"))
    facility = _FACILITY_MAP.get(pri >> 3, f"facility_{pri>>3}")
    sev_num  = pri & 0x07
    return {
        "raw": raw, "timestamp": datetime.utcnow().isoformat(),
        "source": "syslog", "host": m.group("host"),
        "facility": facility, "tag": m.group("tag"),
        "message": m.group("msg").strip(),
        "severity": _SEVERITY_MAP.get(sev_num, "LOW"),
        "src_ip": m.group("host"),
        "type": f"Syslog/{m.group('tag').split('[')[0]}",
    }


class SyslogServer:
    """UDP + TCP syslog listener. Calls callback(parsed_event) for each message."""

    def __init__(self, host="0.0.0.0", port=5514,
                 callback: Callable = None,
                 winlog_port=5515,
                 max_queue=10000):
        self.host        = host
        self.port        = port
        self.winlog_port = winlog_port
        self.callback    = callback
        self._running    = False
        self._count      = 0

    def start(self):
        if self._running: return
        self._running = True
        threading.Thread(target=self._udp_loop, daemon=True, name="syslog-udp").start()
        threading.Thread(target=self._tcp_loop, daemon=True, name="syslog-tcp").start()
        threading.Thread(target=self._winlog_loop, daemon=True, name="syslog-winlog").start()
        logger.info(f"Syslog server: UDP/TCP :{self.port}, WinLog :{self.winlog_port}")

    def stop(self):
        self._running = False

    @property
    def count(self): return self._count

    def _emit(self, raw: str):
        parsed = parse_syslog(raw)
        if parsed and self.callback:
            self._count += 1
            try: self.callback(parsed)
            except Exception as e: logger.debug(f"Syslog callback: {e}")

    def _udp_loop(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.settimeout(1.0)
            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    self._emit(data.decode("utf-8", errors="replace"))
                except socket.timeout: pass
            s.close()
        except Exception as e:
            logger.warning(f"Syslog UDP: {e}")

    def _tcp_loop(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(20); srv.settimeout(1.0)
            while self._running:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(target=self._tcp_client,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout: pass
            srv.close()
        except Exception as e:
            logger.warning(f"Syslog TCP: {e}")

    def _tcp_client(self, conn, addr):
        buf = b""
        conn.settimeout(30)
        try:
            while self._running:
                chunk = conn.recv(4096)
                if not chunk: break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._emit(line.decode("utf-8", errors="replace"))
        except Exception: pass
        finally: conn.close()

    def _winlog_loop(self):
        """Accepts Windows Event Log in JSON format on a separate port."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.winlog_port))
            srv.listen(10); srv.settimeout(1.0)
            while self._running:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(target=self._winlog_client,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout: pass
            srv.close()
        except Exception as e:
            logger.warning(f"WinLog TCP: {e}")

    def _winlog_client(self, conn, addr):
        buf = b""
        conn.settimeout(30)
        try:
            while self._running:
                chunk = conn.recv(65535)
                if not chunk: break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line: continue
                    try:
                        evt = json.loads(line)
                        evt.setdefault("source", "windows_event_log")
                        evt.setdefault("timestamp", datetime.utcnow().isoformat())
                        evt.setdefault("src_ip", addr[0])
                        # Map Windows event levels to severity
                        level = evt.get("Level", evt.get("level", 4))
                        evt["severity"] = {1:"CRITICAL",2:"HIGH",3:"MEDIUM",4:"LOW"}.get(int(level),"LOW")
                        evt["type"] = f"WinEvent/{evt.get('ProviderName', evt.get('provider','Unknown'))}"
                        if self.callback:
                            self._count += 1
                            self.callback(evt)
                    except Exception as e:
                        logger.debug(f"WinLog parse: {e}")
        except Exception: pass
        finally: conn.close()


class AgentReceiver:
    """
    Receives JSON telemetry from AID-ARS agents (Linux/Windows).
    Agent sends: {type, host, data, timestamp}
    """
    def __init__(self, host="0.0.0.0", port=5516, callback: Callable = None):
        self.host = host; self.port = port; self.callback = callback
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="agent-recv").start()
        logger.info(f"Agent receiver: TCP :{self.port}")

    def stop(self): self._running = False

    def _loop(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port)); srv.listen(50); srv.settimeout(1.0)
            while self._running:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(target=self._client,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout: pass
            srv.close()
        except Exception as e:
            logger.warning(f"Agent receiver: {e}")

    def _client(self, conn, addr):
        buf = b""
        conn.settimeout(60)
        try:
            while self._running:
                chunk = conn.recv(65535)
                if not chunk: break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip(): continue
                    try:
                        msg = json.loads(line)
                        msg.setdefault("agent_ip", addr[0])
                        msg.setdefault("timestamp", datetime.utcnow().isoformat())
                        if self.callback: self.callback(msg)
                    except Exception: pass
        except Exception: pass
        finally: conn.close()
