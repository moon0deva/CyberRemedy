"""
AID-ARS Endpoint Agent — Host Intrusion Detection (HIDS)
Collects: FIM (file integrity), processes, auth logs, network connections, system info.
Designed to run on Linux/macOS/Windows and forward telemetry to the AID-ARS API.
"""

import os
import sys
import json
import time
import hashlib
import logging
import platform
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("aidars.agent")

# ─── SYSTEM INFO ──────────────────────────────────────────────────────────────

def collect_system_info() -> dict:
    import socket
    info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "timestamp": datetime.utcnow().isoformat(),
    }
    try:
        import psutil
        mem = psutil.virtual_memory()
        info["memory_total_gb"] = round(mem.total / 1e9, 2)
        info["cpu_percent"] = psutil.cpu_percent(interval=0.5)
        info["memory_percent"] = mem.percent
        info["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
    except ImportError:
        pass
    return info


# ─── FILE INTEGRITY MONITORING ────────────────────────────────────────────────

class FileIntegrityMonitor:
    """
    Monitors critical files and directories for changes.
    Computes SHA-256 hashes and detects add/modify/delete.
    """

    CRITICAL_PATHS_LINUX = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/ssh/sshd_config", "/etc/crontab",
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    ]
    CRITICAL_PATHS_WINDOWS = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\config",
    ]

    def __init__(self, watch_paths: List[str] = None, callback=None):
        self.watch_paths = watch_paths or self._default_paths()
        self.callback = callback
        self._baseline: Dict[str, dict] = {}
        self._running = False

    def _default_paths(self) -> List[str]:
        if platform.system() == "Windows":
            return self.CRITICAL_PATHS_WINDOWS
        return self.CRITICAL_PATHS_LINUX

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            return None

    def _scan(self, path: str) -> Dict[str, dict]:
        result = {}
        p = Path(path)
        if p.is_file():
            h = self._hash_file(str(p))
            if h:
                result[str(p)] = {"hash": h, "size": p.stat().st_size, "mtime": p.stat().st_mtime}
        elif p.is_dir():
            for child in p.rglob("*"):
                if child.is_file():
                    h = self._hash_file(str(child))
                    if h:
                        result[str(child)] = {"hash": h, "size": child.stat().st_size, "mtime": child.stat().st_mtime}
        return result

    def build_baseline(self):
        """Scan all watch paths and build initial hash baseline."""
        for path in self.watch_paths:
            self._baseline.update(self._scan(path))
        logger.info(f"FIM baseline: {len(self._baseline)} files indexed")

    def check(self) -> List[dict]:
        """Compare current state against baseline. Returns list of changes."""
        events = []
        current = {}
        for path in self.watch_paths:
            current.update(self._scan(path))

        # Modified or deleted
        for fpath, old in self._baseline.items():
            if fpath not in current:
                events.append({"type": "FIM_DELETED", "path": fpath, "severity": "HIGH",
                                "detail": f"File deleted: {fpath}", "old_hash": old["hash"]})
            elif current[fpath]["hash"] != old["hash"]:
                events.append({"type": "FIM_MODIFIED", "path": fpath, "severity": "CRITICAL",
                                "detail": f"File modified: {fpath}",
                                "old_hash": old["hash"], "new_hash": current[fpath]["hash"],
                                "size_delta": current[fpath]["size"] - old["size"]})

        # New files
        for fpath in current:
            if fpath not in self._baseline:
                events.append({"type": "FIM_CREATED", "path": fpath, "severity": "MEDIUM",
                                "detail": f"New file: {fpath}", "new_hash": current[fpath]["hash"]})

        self._baseline = current
        return events

    def start_monitoring(self, interval: float = 60.0):
        """Start background FIM loop."""
        self.build_baseline()
        self._running = True

        def _loop():
            while self._running:
                time.sleep(interval)
                changes = self.check()
                for c in changes:
                    c["timestamp"] = datetime.utcnow().isoformat()
                    c["source"] = "fim"
                    logger.warning(f"FIM: {c['type']} — {c['path']}")
                    if self.callback:
                        self.callback(c)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False


# ─── PROCESS MONITOR ─────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Monitors running processes for suspicious activity:
    - New privileged processes
    - Shell spawned from unexpected parent
    - Hidden/deleted process binaries
    """

    SUSPICIOUS_NAMES = {"nc", "ncat", "netcat", "socat", "msfconsole", "mimikatz",
                        "python", "python3", "perl", "ruby", "wget", "curl"}
    SUSPICIOUS_PARENTS = {"sshd", "apache2", "nginx", "httpd", "mysqld"}

    def __init__(self, callback=None):
        self.callback = callback
        self._known_pids = set()

    def scan(self) -> List[dict]:
        events = []
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid",
                                              "username", "status", "create_time"]):
                try:
                    info = proc.info
                    pid = info["pid"]

                    # New process
                    if pid not in self._known_pids:
                        self._known_pids.add(pid)
                        name = (info.get("name") or "").lower()
                        exe = info.get("exe") or ""
                        cmdline = " ".join(info.get("cmdline") or [])

                        # Deleted binary (running from /proc/x/exe which shows "(deleted)")
                        if exe and "(deleted)" in exe:
                            events.append({
                                "type": "PROC_DELETED_BINARY", "severity": "CRITICAL",
                                "detail": f"Process running from deleted binary: PID {pid} {name} {exe}",
                                "pid": pid, "name": name, "exe": exe,
                            })

                        # Suspicious process from web/db parent
                        try:
                            parent = psutil.Process(info["ppid"])
                            parent_name = (parent.name() or "").lower()
                            if parent_name in self.SUSPICIOUS_PARENTS and name in {"bash", "sh", "python", "perl"}:
                                events.append({
                                    "type": "PROC_SUSPICIOUS_SPAWN", "severity": "CRITICAL",
                                    "detail": f"Shell spawned from {parent_name}: PID {pid} cmd={cmdline[:100]}",
                                    "pid": pid, "name": name, "parent": parent_name,
                                    "mitre_id": "T1059",
                                })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        # Network tool
                        if name in self.SUSPICIOUS_NAMES and info.get("username") not in ("root", "SYSTEM"):
                            events.append({
                                "type": "PROC_SUSPICIOUS_TOOL", "severity": "HIGH",
                                "detail": f"Suspicious tool detected: {name} (PID {pid}) by {info.get('username')}",
                                "pid": pid, "name": name, "cmdline": cmdline[:200],
                            })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        except ImportError:
            logger.warning("psutil not installed — process monitoring unavailable")
        return events


# ─── AUTH LOG MONITOR ─────────────────────────────────────────────────────────

class AuthLogMonitor:
    """
    Parses /var/log/auth.log (Linux) for suspicious auth events:
    - Failed login attempts (brute force)
    - Successful sudo escalation
    - New user creation
    - SSH invalid user attempts
    """

    AUTH_LOG = "/var/log/auth.log"
    SECURE_LOG = "/var/log/secure"  # RHEL/CentOS

    def __init__(self, callback=None):
        self.callback = callback
        self._offset = 0
        self._failure_counts: Dict[str, int] = {}
        self._log_path = self._find_log()

    def _find_log(self) -> Optional[str]:
        for p in [self.AUTH_LOG, self.SECURE_LOG]:
            if Path(p).exists():
                return p
        return None

    def read_new_lines(self) -> List[dict]:
        if not self._log_path:
            return []
        events = []
        try:
            with open(self._log_path, "r", errors="ignore") as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()

            for line in lines:
                event = self._parse_line(line.strip())
                if event:
                    events.append(event)
        except (PermissionError, FileNotFoundError):
            pass
        return events

    def _parse_line(self, line: str) -> Optional[dict]:
        # Failed password
        if "Failed password" in line or "authentication failure" in line:
            src = self._extract_ip(line)
            user = self._extract_user(line)
            key = src or "unknown"
            self._failure_counts[key] = self._failure_counts.get(key, 0) + 1
            sev = "CRITICAL" if self._failure_counts[key] >= 10 else "HIGH"
            return {
                "type": "AUTH_FAIL", "severity": sev,
                "detail": f"Auth failure for {user} from {src} (total: {self._failure_counts[key]})",
                "src_ip": src, "user": user, "fail_count": self._failure_counts[key],
                "mitre_id": "T1110", "raw": line[:200],
            }
        # Sudo escalation
        if "sudo:" in line and "COMMAND" in line:
            return {
                "type": "SUDO_EXEC", "severity": "MEDIUM",
                "detail": f"Sudo command: {line[100:200]}",
                "mitre_id": "T1548", "raw": line[:200],
            }
        # New user
        if "new user" in line or "useradd" in line:
            return {
                "type": "USER_CREATED", "severity": "HIGH",
                "detail": f"New user account created: {line[:200]}",
                "mitre_id": "T1136", "raw": line[:200],
            }
        # Invalid SSH user
        if "Invalid user" in line:
            src = self._extract_ip(line)
            user = self._extract_user(line)
            return {
                "type": "SSH_INVALID_USER", "severity": "MEDIUM",
                "detail": f"SSH invalid user {user} from {src}",
                "src_ip": src, "user": user, "mitre_id": "T1110",
            }
        return None

    def _extract_ip(self, line: str) -> str:
        import re
        m = re.search(r'from\s+([\d.]+)', line)
        return m.group(1) if m else "unknown"

    def _extract_user(self, line: str) -> str:
        import re
        m = re.search(r'(?:for|user)\s+(\S+)', line)
        return m.group(1) if m else "unknown"


# ─── NETWORK CONNECTION MONITOR ───────────────────────────────────────────────

class NetworkConnectionMonitor:
    """Monitors active network connections for suspicious outbound activity."""

    SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 7777, 8888, 9999, 31337, 1337}
    C2_INDICATORS = {4444, 4445, 5555}

    def __init__(self, callback=None):
        self.callback = callback
        self._seen = set()

    def scan(self) -> List[dict]:
        events = []
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                if conn.status not in ("ESTABLISHED", "LISTEN"):
                    continue
                laddr = conn.laddr
                raddr = conn.raddr
                key = (laddr.ip if laddr else "", laddr.port if laddr else 0,
                       raddr.ip if raddr else "", raddr.port if raddr else 0)
                if key in self._seen or not raddr:
                    continue
                self._seen.add(key)

                r_port = raddr.port if raddr else 0
                if r_port in self.C2_INDICATORS:
                    events.append({
                        "type": "NET_C2_PORT", "severity": "CRITICAL",
                        "detail": f"Outbound connection to potential C2 port {r_port} → {raddr.ip}",
                        "dst_ip": raddr.ip, "dst_port": r_port,
                        "mitre_id": "T1071",
                    })
                elif r_port in self.SUSPICIOUS_PORTS:
                    events.append({
                        "type": "NET_SUSPICIOUS_PORT", "severity": "HIGH",
                        "detail": f"Connection to suspicious port {r_port} → {raddr.ip}",
                        "dst_ip": raddr.ip, "dst_port": r_port,
                        "mitre_id": "T1071",
                    })
        except ImportError:
            pass
        return events


# ─── AGENT RUNNER ─────────────────────────────────────────────────────────────

class HIDSAgent:
    """
    Orchestrates all HIDS collection modules.
    Runs continuously and POSTs telemetry to the AID-ARS API.
    """

    def __init__(self, api_url: str = "http://localhost:8000", interval: float = 30.0,
                 agent_id: str = None):
        self.api_url = api_url
        self.interval = interval
        self.agent_id = agent_id or platform.node()
        self._running = False

        self.fim = FileIntegrityMonitor()
        self.proc = ProcessMonitor()
        self.auth = AuthLogMonitor()
        self.net = NetworkConnectionMonitor()

    def _post_events(self, events: List[dict]):
        """POST a batch of host events to the AID-ARS API."""
        if not events:
            return
        try:
            import urllib.request
            payload = json.dumps({
                "agent_id": self.agent_id,
                "hostname": platform.node(),
                "os": platform.system(),
                "events": events,
            }).encode()
            req = urllib.request.Request(
                f"{self.api_url}/api/agent/events",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            logger.debug(f"Agent POST failed: {e} — buffering events")
            # Log locally if API unreachable
            self._log_local(events)

    def _log_local(self, events: List[dict]):
        log_path = Path("data/agent_events.json")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if log_path.exists():
            try:
                existing = json.loads(log_path.read_text())
            except Exception:
                pass
        existing.extend(events)
        log_path.write_text(json.dumps(existing[-5000:], indent=2))

    def start(self):
        """Start the HIDS agent loop."""
        logger.info(f"HIDS Agent starting on {self.agent_id}")
        self._running = True
        self.fim.build_baseline()

        sys_info = collect_system_info()
        self._post_events([{"type": "AGENT_HEARTBEAT", "severity": "INFO",
                            "detail": "Agent started", "system_info": sys_info}])

        while self._running:
            all_events = []
            ts = datetime.utcnow().isoformat()

            # FIM
            fim_events = self.fim.check()
            for e in fim_events:
                e["timestamp"] = ts
                e["source"] = "fim"
                e["agent_id"] = self.agent_id
            all_events.extend(fim_events)

            # Processes
            proc_events = self.proc.scan()
            for e in proc_events:
                e["timestamp"] = ts
                e["source"] = "process_monitor"
                e["agent_id"] = self.agent_id
            all_events.extend(proc_events)

            # Auth logs
            auth_events = self.auth.read_new_lines()
            for e in auth_events:
                e["timestamp"] = ts
                e["source"] = "auth_log"
                e["agent_id"] = self.agent_id
            all_events.extend(auth_events)

            # Network
            net_events = self.net.scan()
            for e in net_events:
                e["timestamp"] = ts
                e["source"] = "net_monitor"
                e["agent_id"] = self.agent_id
            all_events.extend(net_events)

            if all_events:
                logger.info(f"Agent {self.agent_id}: {len(all_events)} events collected")
                self._post_events(all_events)

            time.sleep(self.interval)

    def stop(self):
        self._running = False
        self.fim.stop()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AID-ARS HIDS Agent")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--agent-id", default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    agent = HIDSAgent(api_url=args.api, interval=args.interval, agent_id=args.agent_id)
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
