"""
AID-ARS v4.0 — Windows Event Log Agent
Run on Windows machines to ship event logs to AID-ARS server.
Usage: python windows_agent.py --server 192.168.1.100 --port 5515
"""
import json, socket, time, threading, argparse, sys, platform
from datetime import datetime

def get_windows_events(channel="Security", max_events=50):
    """Read Windows Event Log using wevtapi (pywin32) or wevtutil fallback."""
    events = []
    # Try pywin32 first
    try:
        import win32evtlog, win32evtlogutil, win32con
        hand = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        recs = win32evtlog.ReadEventLog(hand, flags, 0)
        for rec in (recs or [])[:max_events]:
            try:
                events.append({
                    "EventID": rec.EventID & 0xFFFF,
                    "ProviderName": rec.SourceName,
                    "Level": rec.EventType,
                    "TimeCreated": rec.TimeGenerated.Format(),
                    "Channel": channel,
                    "Computer": rec.ComputerName,
                    "Message": str(win32evtlogutil.SafeFormatMessage(rec, channel)),
                    "timestamp": datetime.utcnow().isoformat(),
                })
            except Exception: pass
        win32evtlog.CloseEventLog(hand)
        return events
    except ImportError: pass
    # Fallback: wevtutil (no dependencies)
    try:
        import subprocess
        cmd = ["wevtutil", "qe", channel, f"/count:{max_events}", "/format:xml", "/rd:true"]
        out = subprocess.check_output(cmd, text=True, timeout=10, stderr=subprocess.DEVNULL)
        import re, xml.etree.ElementTree as ET
        for ev in re.split(r'<Event xmlns', out):
            if not ev.strip(): continue
            try:
                root = ET.fromstring('<Event xmlns' + ev)
                ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                eid = root.findtext('.//e:EventID', namespaces=ns) or "0"
                level = root.findtext('.//e:Level', namespaces=ns) or "4"
                provider = root.find('.//e:Provider', namespaces=ns)
                pname = provider.get('Name', 'Unknown') if provider is not None else 'Unknown'
                tc = root.findtext('.//e:TimeCreated/@SystemTime', namespaces=ns) or datetime.utcnow().isoformat()
                events.append({"EventID":int(eid),"ProviderName":pname,"Level":int(level),
                               "Channel":channel,"timestamp":datetime.utcnow().isoformat()})
            except Exception: pass
    except Exception: pass
    return events

def get_linux_logs(max_lines=50):
    """Read recent syslog/journald entries on Linux."""
    events = []
    try:
        import subprocess
        out = subprocess.check_output(
            ["journalctl","-n",str(max_lines),"--no-pager","-o","json"],
            text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        for line in out.strip().split("\n"):
            if not line: continue
            try:
                j = json.loads(line)
                events.append({
                    "ProviderName": j.get("SYSLOG_IDENTIFIER","unknown"),
                    "Level": {"emerg":1,"alert":1,"crit":1,"err":2,"warning":3,"notice":4,"info":4,"debug":4}.get(j.get("PRIORITY","4"),4),
                    "Message": j.get("MESSAGE",""),
                    "Channel": "journal",
                    "Computer": j.get("_HOSTNAME","localhost"),
                    "timestamp": datetime.utcnow().isoformat(),
                })
            except Exception: pass
    except Exception:
        # Fallback: read /var/log/syslog
        try:
            with open("/var/log/syslog") as f:
                lines = f.readlines()[-max_lines:]
            for line in lines:
                events.append({"ProviderName":"syslog","Level":4,
                               "Message":line.strip(),"Channel":"syslog",
                               "timestamp":datetime.utcnow().isoformat()})
        except Exception: pass
    return events


def send_events(events, server, port):
    if not events: return 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((server, port))
        for ev in events:
            s.send((json.dumps(ev) + "\n").encode("utf-8"))
        s.close()
        return len(events)
    except Exception as e:
        print(f"[agent] Send failed: {e}")
        return 0


def main():
    p = argparse.ArgumentParser(description="AID-ARS Event Log Agent")
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5515)
    p.add_argument("--interval", type=int, default=30, help="Seconds between polls")
    p.add_argument("--channels", default="Security,System,Application",
                   help="Windows event channels (comma-separated)")
    args = p.parse_args()

    print(f"[agent] Shipping logs to {args.server}:{args.port} every {args.interval}s")
    is_win = platform.system() == "Windows"

    while True:
        events = []
        if is_win:
            for ch in args.channels.split(","):
                events.extend(get_windows_events(ch.strip(), max_events=50))
        else:
            events.extend(get_linux_logs(max_lines=50))
        n = send_events(events, args.server, args.port)
        print(f"[agent] Shipped {n} events")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
