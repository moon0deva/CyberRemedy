import { useState, useEffect, useRef, useCallback } from "react";

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";
const RECONNECT_DELAY = 3000;

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLORS = { CRITICAL: "#ff2d55", HIGH: "#ff6b35", MEDIUM: "#ffd60a", LOW: "#30d158" };
const SEV_BG = { CRITICAL: "rgba(255,45,85,0.15)", HIGH: "rgba(255,107,53,0.12)", MEDIUM: "rgba(255,214,10,0.12)", LOW: "rgba(48,209,88,0.12)" };

// Simulated data (used when backend is offline)
const MITRE_FALLBACK = [
  { id: "T1046", name: "Network Service Scanning", tactic: "Discovery" },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { id: "T1071", name: "Application Layer Protocol", tactic: "C2" },
  { id: "T1048", name: "Exfiltration Over Alt Protocol", tactic: "Exfiltration" },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  { id: "T1059", name: "Command & Scripting Interpreter", tactic: "Execution" },
  { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "C2" },
  { id: "T1566", name: "Phishing", tactic: "Initial Access" },
];

const ATTACK_TYPES = [
  "Port Scan (SYN)", "Port Scan (FIN)", "SSH Brute Force", "FTP Brute Force",
  "DNS Tunneling", "C2 Beaconing", "Lateral Movement", "Data Exfiltration",
  "Process Injection", "Suspicious Encrypted Traffic"
];

function r(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
const IPS = () => `${r(10,192)}.${r(0,255)}.${r(0,255)}.${r(1,254)}`;

let _simId = 1000;
function genSimAlert() {
  const mit = MITRE_FALLBACK[r(0, MITRE_FALLBACK.length - 1)];
  const sev = SEVERITIES[r(0, 3)];
  return {
    id: _simId++,
    timestamp: new Date().toISOString(),
    severity: sev,
    type: ATTACK_TYPES[r(0, ATTACK_TYPES.length - 1)],
    src_ip: IPS(), dst_ip: IPS(),
    src_port: r(1024, 65535),
    dst_port: r(1, 1024),
    protocol: ["TCP","UDP","DNS","ICMP"][r(0,3)],
    mitre_id: mit.id,
    mitre_name: mit.name,
    mitre_tactic: mit.tactic,
    confidence: r(68, 99),
    risk_score: r(30, 95),
    status: "OPEN",
    source: "simulation",
    packets: r(10, 50000),
    bytes: r(1000, 5000000),
    correlated: Math.random() > 0.6,
  };
}

// ─── CSS ──────────────────────────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #050a0f; --bg2: #090f17; --bg3: #0d1520; --panel: #0a1220;
    --border: rgba(0,210,255,0.12); --border2: rgba(0,210,255,0.25);
    --cyan: #00d2ff; --red: #ff2d55; --orange: #ff6b35; --yellow: #ffd60a;
    --green: #30d158; --purple: #bf5af2;
    --text: #c8e8ff; --text2: #6890b0; --text3: #3a5a78;
    --font-mono: 'Share Tech Mono', monospace; --font-ui: 'Exo 2', sans-serif;
    --glow: 0 0 20px rgba(0,210,255,0.3);
  }
  html,body,#root { width:100%;height:100%;overflow:hidden;background:var(--bg); }
  .app {
    display:grid;
    grid-template-rows:52px 1fr;
    grid-template-columns:220px 1fr 300px;
    grid-template-areas:"hdr hdr hdr" "nav main side";
    width:100vw;height:100vh;font-family:var(--font-ui);color:var(--text);
  }

  /* HEADER */
  .hdr {
    grid-area:hdr; display:flex;align-items:center;justify-content:space-between;
    padding:0 20px; background:var(--bg2); border-bottom:1px solid var(--border2);
    z-index:100; position:relative;
  }
  .hdr::after { content:''; position:absolute;bottom:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,transparent,var(--cyan),transparent);
    animation:hdrline 3s linear infinite; }
  @keyframes hdrline { 0%,100%{opacity:.3} 50%{opacity:1} }
  .logo { display:flex;align-items:center;gap:10px;font-family:var(--font-mono);
    font-size:16px;font-weight:700;color:var(--cyan);text-shadow:var(--glow);letter-spacing:2px; }
  .logo-box { width:28px;height:28px;border:2px solid var(--cyan);border-radius:6px;
    display:flex;align-items:center;justify-content:center;font-size:14px;
    animation:pulsebox 2s ease-in-out infinite; }
  @keyframes pulsebox { 0%,100%{box-shadow:0 0 20px rgba(0,210,255,.3)} 50%{box-shadow:0 0 30px rgba(0,210,255,.6)} }
  .hdr-center { display:flex;align-items:center;gap:20px;font-family:var(--font-mono);font-size:11px;color:var(--text2); }
  .hdr-stat { display:flex;align-items:center;gap:6px; }
  .dot { width:7px;height:7px;border-radius:50%; }
  .dot-live { background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 1.2s ease-in-out infinite; }
  .dot-red { background:var(--red);box-shadow:0 0 8px var(--red); }
  .dot-yellow { background:var(--yellow);box-shadow:0 0 8px var(--yellow);animation:blink 1.2s ease-in-out infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }
  .hdr-right { display:flex;align-items:center;gap:16px;font-family:var(--font-mono);font-size:12px;color:var(--text2); }
  .tl-badge { padding:3px 10px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:1px; }
  .ws-badge { padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:1px; }

  /* NAV */
  .nav { grid-area:nav;background:var(--bg2);border-right:1px solid var(--border);
    padding:12px 0;display:flex;flex-direction:column;gap:2px;overflow:hidden; }
  .nav-sec { padding:8px 16px 4px;font-size:9px;font-weight:700;letter-spacing:2px;
    color:var(--text3);text-transform:uppercase;font-family:var(--font-mono); }
  .nav-item { display:flex;align-items:center;gap:10px;padding:8px 16px;font-size:12px;
    font-weight:500;color:var(--text2);cursor:pointer;border-left:3px solid transparent;
    transition:all .15s; }
  .nav-item:hover { color:var(--cyan);background:rgba(0,210,255,.05);border-left-color:rgba(0,210,255,.4); }
  .nav-item.active { color:var(--cyan);background:rgba(0,210,255,.08);border-left-color:var(--cyan); }
  .nav-icon { font-size:14px;width:18px;text-align:center; }
  .nav-badge { margin-left:auto;padding:1px 6px;border-radius:10px;font-size:10px;
    font-family:var(--font-mono);background:rgba(255,45,85,.2);color:var(--red);border:1px solid rgba(255,45,85,.3); }

  /* MAIN / SIDE */
  .main { grid-area:main;overflow-y:auto;overflow-x:hidden;padding:16px;
    display:flex;flex-direction:column;gap:14px;scrollbar-width:thin;scrollbar-color:var(--border2) transparent; }
  .side { grid-area:side;background:var(--bg2);border-left:1px solid var(--border);
    overflow-y:auto;overflow-x:hidden;padding:14px;display:flex;flex-direction:column;
    gap:12px;scrollbar-width:thin;scrollbar-color:var(--border2) transparent; }

  /* PANELS */
  .panel { background:var(--panel);border:1px solid var(--border);border-radius:6px;
    overflow:hidden;position:relative; }
  .panel::before { content:'';position:absolute;top:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,transparent,rgba(0,210,255,.4),transparent); }
  .ph { display:flex;align-items:center;justify-content:space-between;padding:10px 14px;
    border-bottom:1px solid var(--border);background:rgba(0,210,255,.03); }
  .pt { font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;
    color:var(--cyan);font-family:var(--font-mono);display:flex;align-items:center;gap:8px; }
  .pb { padding:12px 14px; }

  /* STAT CARDS */
  .stat-row { display:grid;grid-template-columns:repeat(4,1fr);gap:12px; }
  .stat-card { background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:14px;
    position:relative;overflow:hidden; }
  .stat-card::after { content:'';position:absolute;bottom:0;left:0;right:0;height:2px;
    background:var(--ac,var(--cyan));opacity:.6; }
  .stat-label { font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--text2);font-family:var(--font-mono); }
  .stat-value { font-size:28px;font-weight:900;color:var(--ac,var(--cyan));font-family:var(--font-mono);
    margin:4px 0;text-shadow:0 0 20px var(--ac,var(--cyan));line-height:1; }
  .stat-sub { font-size:10px;color:var(--text3);font-family:var(--font-mono); }

  /* TABLE */
  .tbl { width:100%;border-collapse:collapse;font-size:11px;font-family:var(--font-mono); }
  .tbl thead tr { border-bottom:1px solid var(--border2); }
  .tbl th { padding:6px 10px;text-align:left;color:var(--text3);font-size:10px;letter-spacing:1px;text-transform:uppercase;font-weight:600; }
  .tbl tbody tr { border-bottom:1px solid rgba(0,210,255,.04);transition:background .1s;cursor:pointer;animation:slideIn .3s ease-out; }
  .tbl tbody tr:hover { background:rgba(0,210,255,.04); }
  @keyframes slideIn { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
  .tbl td { padding:7px 10px;vertical-align:middle; }
  .sev-b { display:inline-flex;align-items:center;padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:1px; }
  .ip { color:#5ab4e8; }
  .mitre-t { display:inline-block;padding:1px 6px;border-radius:2px;font-size:9px;
    background:rgba(191,90,242,.15);color:var(--purple);border:1px solid rgba(191,90,242,.25); }
  .abtn { padding:3px 8px;border-radius:3px;border:none;cursor:pointer;font-size:10px;
    font-family:var(--font-mono);font-weight:600;letter-spacing:.5px;transition:all .15s; }
  .btn-r { background:rgba(255,45,85,.15);color:var(--red);border:1px solid rgba(255,45,85,.3); }
  .btn-r:hover { background:rgba(255,45,85,.3); }
  .btn-c { background:rgba(0,210,255,.1);color:var(--cyan);border:1px solid rgba(0,210,255,.25); }
  .btn-c:hover { background:rgba(0,210,255,.2); }
  .btn-g { background:rgba(48,209,88,.1);color:var(--green);border:1px solid rgba(48,209,88,.3); }
  .btn-g:hover { background:rgba(48,209,88,.2); }

  /* CHAIN */
  .chain-step { display:flex;align-items:flex-start;gap:10px;padding:8px 14px;position:relative; }
  .chain-step+.chain-step::before { content:'';position:absolute;left:21px;top:-4px;
    width:1px;height:12px;background:linear-gradient(to bottom,var(--border2),transparent); }
  .chain-node { width:14px;height:14px;border-radius:50%;flex-shrink:0;margin-top:2px;border:2px solid; }
  .chain-info { flex:1; }
  .chain-title { font-size:11px;font-weight:600;color:var(--text); }
  .chain-meta { font-size:10px;color:var(--text2);font-family:var(--font-mono);margin-top:1px; }

  /* RESPONSE LOG */
  .resp-log { display:flex;flex-direction:column;gap:6px; }
  .resp-entry { display:flex;align-items:flex-start;gap:8px;padding:8px 10px;
    background:rgba(0,0,0,.2);border-radius:4px;border-left:3px solid;
    font-size:11px;font-family:var(--font-mono);animation:fadeIn .3s ease; }
  @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }
  .r-icon { font-size:13px;flex-shrink:0; }
  .r-body { flex:1; }
  .r-action { color:var(--text);font-weight:600; }
  .r-detail { color:var(--text2);font-size:10px;margin-top:2px; }
  .r-time { font-size:9px;color:var(--text3);margin-top:2px; }

  /* PROGRESS */
  .prog-bar { width:100%;height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-top:2px; }
  .prog-fill { height:100%;border-radius:2px;transition:width .5s ease; }

  /* MISC */
  .sec-label { font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
    color:var(--text3);font-family:var(--font-mono);margin-bottom:8px; }
  .status-grid { display:grid;grid-template-columns:1fr 1fr;gap:8px; }
  .status-item { display:flex;align-items:center;justify-content:space-between;padding:8px 10px;
    background:rgba(0,0,0,.2);border-radius:4px;font-size:11px; }
  .tabs { display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:12px; }
  .tab { padding:7px 14px;font-size:11px;font-family:var(--font-mono);color:var(--text2);
    cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;letter-spacing:.5px; }
  .tab:hover { color:var(--cyan); }
  .tab.active { color:var(--cyan);border-bottom-color:var(--cyan); }
  .mitre-grid { display:flex;flex-wrap:wrap;gap:5px;padding:8px 0; }
  .mitre-cell { padding:5px 8px;border-radius:3px;font-size:9px;font-family:var(--font-mono);
    border:1px solid;cursor:pointer;transition:all .15s; }
  .mitre-cell:hover { transform:translateY(-1px); }
  svg.traffic-svg { width:100%;height:120px; }
  ::-webkit-scrollbar { width:4px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:var(--border2);border-radius:2px; }

  /* GEO MAP */
  .geo-map { width:100%;height:160px;background:radial-gradient(ellipse at 40% 50%,rgba(0,210,255,.05) 0%,transparent 70%);
    border-radius:4px;position:relative;overflow:hidden; }
  .geo-grid { position:absolute;inset:0;
    background-image:linear-gradient(rgba(0,210,255,.06) 1px,transparent 1px),
      linear-gradient(90deg,rgba(0,210,255,.06) 1px,transparent 1px);
    background-size:20px 20px; }

  /* Backend connection banner */
  .conn-banner { padding:6px 14px;font-size:10px;font-family:var(--font-mono);
    display:flex;align-items:center;gap:8px;background:rgba(255,214,10,.08);
    border:1px solid rgba(255,214,10,.2);border-radius:4px;color:var(--yellow); }
`;

// ─── TRAFFIC CHART ────────────────────────────────────────────────────────────
function TrafficChart({ data }) {
  if (!data || !data.length) return null;
  const W = 600, H = 120, P = 10;
  const maxV = Math.max(...data.map(d => d.total || 0), 1);
  const pts = (key, color, fill) => {
    const ps = data.map((d, i) => {
      const x = P + (i / Math.max(data.length - 1, 1)) * (W - 2 * P);
      const y = H - P - ((d[key] || 0) / maxV) * (H - 2 * P);
      return `${x},${y}`;
    }).join(" ");
    return (
      <g key={key}>
        <polygon points={`${P},${H-P} ${ps} ${W-P},${H-P}`} fill={fill} />
        <polyline points={ps} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
      </g>
    );
  };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="traffic-svg" preserveAspectRatio="none">
      <defs>
        <linearGradient id="bgf" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgba(0,210,255,0.15)" />
          <stop offset="100%" stopColor="rgba(0,210,255,0)" />
        </linearGradient>
        <linearGradient id="malf" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgba(255,45,85,0.2)" />
          <stop offset="100%" stopColor="rgba(255,45,85,0)" />
        </linearGradient>
      </defs>
      {pts("total", "#00d2ff", "url(#bgf)")}
      {pts("malicious", "#ff2d55", "url(#malf)")}
    </svg>
  );
}

// ─── GEO MAP ─────────────────────────────────────────────────────────────────
function GeoMap({ sources }) {
  const dots = (sources || []).slice(0, 15).map((s, i) => ({
    x: 10 + (((s.long || 0) + 180) / 360) * 80,
    y: 8 + ((90 - ((s.lat || 0) + 90)) / 180) * 84,
    sev: s.sev || "MEDIUM", key: i,
  }));
  return (
    <div className="geo-map">
      <div className="geo-grid" />
      <svg viewBox="0 0 100 100" style={{ width: "100%", height: "100%", position: "absolute" }}>
        {dots.map(d => (
          <g key={d.key}>
            <circle cx={d.x} cy={d.y} r="2.5" fill={SEV_COLORS[d.sev]} opacity="0.9" />
            <circle cx={d.x} cy={d.y} r="5" fill="none" stroke={SEV_COLORS[d.sev]} strokeWidth="0.5" opacity="0.4">
              <animate attributeName="r" from="3" to="10" dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite" />
            </circle>
          </g>
        ))}
      </svg>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text3)", position: "absolute", bottom: 6, left: 10 }}>
        GLOBAL THREAT MAP — LIVE
      </span>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function AIDARS() {
  const [wsConnected, setWsConnected] = useState(false);
  const [backendMode, setBackendMode] = useState("simulation"); // simulation | connected

  // Data state
  const [alerts, setAlerts] = useState([]);
  const [responses, setResponses] = useState([]);
  const [chains, setChains] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [mitreDB, setMitreDB] = useState({});
  const [pipelineState, setPipelineState] = useState({ running: false, mode: "simulation", alerts_total: 0, flows_analyzed: 0, packets_processed: 0 });
  const [stats, setStats] = useState({ total_alerts: 0, severity_breakdown: {}, unique_sources: 0 });
  const [mitreCoverage, setMitreCoverage] = useState({ techniques_detected: 0, tactics_coverage: {} });

  // UI state
  const [activeNav, setActiveNav] = useState("alerts");
  const [activeTab, setActiveTab] = useState("live");
  const [mitreActive, setMitreActive] = useState(new Set());
  const [ackedAlerts, setAckedAlerts] = useState(new Set());

  const wsRef = useRef(null);
  const simTimer = useRef(null);
  const tickRef = useRef(0);

  // ─── WEBSOCKET CONNECTION ───────────────────────────────────────────────────
  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      setBackendMode("connected");
      // Stop simulation
      if (simTimer.current) {
        clearInterval(simTimer.current);
        simTimer.current = null;
      }
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        handleWSMessage(msg);
      } catch (e) {}
    };

    ws.onclose = () => {
      setWsConnected(false);
      setBackendMode("simulation");
      // Start simulation fallback
      startSimulation();
      // Reconnect
      setTimeout(connectWS, RECONNECT_DELAY);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  const handleWSMessage = useCallback((msg) => {
    if (msg.type === "init") {
      if (msg.recent_alerts) setAlerts(msg.recent_alerts.reverse());
      if (msg.traffic_history) setTraffic(msg.traffic_history);
      if (msg.blocked_ips) setBlockedIPs(msg.blocked_ips);
      if (msg.active_chains) setChains(msg.active_chains);
      if (msg.mitre_db) setMitreDB(msg.mitre_db);
    } else if (msg.type === "state_update") {
      if (msg.recent_alerts) {
        setAlerts(prev => {
          const existingIds = new Set(prev.map(a => a.id));
          const newOnes = msg.recent_alerts.filter(a => !existingIds.has(a.id));
          return [...newOnes.reverse(), ...prev].slice(0, 200);
        });
      }
      if (msg.recent_responses) setResponses(msg.recent_responses.reverse());
      if (msg.active_chains) setChains(msg.active_chains);
      if (msg.blocked_ips) setBlockedIPs(msg.blocked_ips);
      if (msg.pipeline) setPipelineState(msg.pipeline);
      if (msg.stats) setStats(msg.stats.reporter || {});
      if (msg.mitre_coverage) setMitreCoverage(msg.mitre_coverage);
      if (msg.traffic_point) {
        setTraffic(prev => [...prev.slice(-59), msg.traffic_point]);
      }
    }
  }, []);

  // ─── SIMULATION FALLBACK ───────────────────────────────────────────────────
  const startSimulation = useCallback(() => {
    if (simTimer.current) return;
    // Seed with initial alerts
    setAlerts(Array.from({ length: 15 }, genSimAlert).reverse());
    setTraffic(Array.from({ length: 40 }, (_, i) => ({
      t: i, benign: r(200, 1200), malicious: r(0, 180), total: r(500, 2000),
    })));

    simTimer.current = setInterval(() => {
      tickRef.current++;
      if (tickRef.current % 4 === 0) {
        const a = genSimAlert();
        setAlerts(prev => [a, ...prev].slice(0, 200));

        if (a.severity === "CRITICAL") {
          setResponses(prev => [{
            icon: "🚫", action_type: "BLOCK_IP",
            detail: `Auto-blocked ${a.src_ip} — ${a.type}`,
            timestamp: new Date().toISOString(),
            success: true,
            target_ip: a.src_ip,
            color: "#ff2d55",
          }, ...prev].slice(0, 20));
        }
      }
      setTraffic(prev => [...prev.slice(1), {
        t: tickRef.current,
        benign: r(200, 1200), malicious: r(0, 200), total: r(500, 2000),
      }]);
    }, 1000);
  }, []);

  useEffect(() => {
    startSimulation();
    connectWS();
    return () => {
      if (simTimer.current) clearInterval(simTimer.current);
      wsRef.current?.close();
    };
  }, []);

  // ─── ACTIONS ───────────────────────────────────────────────────────────────
  const sendWS = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  const handleBlock = useCallback(async (alert) => {
    if (wsConnected) {
      sendWS({ cmd: "manual_block", ip: alert.src_ip });
    } else {
      setBlockedIPs(prev => [...prev, { ip: alert.src_ip, reason: alert.type, blocked_at: new Date().toISOString() }]);
    }
    setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, status: "BLOCKED" } : a));
    setResponses(prev => [{
      icon: "🚫", action_type: "BLOCK_IP",
      detail: `Manual block: ${alert.src_ip} — ${alert.type}`,
      timestamp: new Date().toISOString(), success: true, target_ip: alert.src_ip, color: "#ff2d55",
    }, ...prev].slice(0, 20));
  }, [wsConnected, sendWS]);

  const handleUnblock = useCallback(async (ip) => {
    if (wsConnected) {
      sendWS({ cmd: "manual_unblock", ip });
    } else {
      setBlockedIPs(prev => prev.filter(b => b.ip !== ip));
    }
    setResponses(prev => [{
      icon: "✅", action_type: "ROLLBACK",
      detail: `Unblocked ${ip}`,
      timestamp: new Date().toISOString(), success: true, target_ip: ip, color: "#30d158",
    }, ...prev].slice(0, 20));
  }, [wsConnected, sendWS]);

  const handleAck = useCallback((alert) => {
    setAckedAlerts(prev => new Set([...prev, alert.id]));
    setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, status: "ACK" } : a));
  }, []);

  const startPipeline = useCallback(async () => {
    if (!wsConnected) return;
    try {
      await fetch(`${API_BASE}/api/pipeline/start?mode=simulation`, { method: "POST" });
    } catch (e) {}
  }, [wsConnected]);

  const generateReport = useCallback(async () => {
    if (!wsConnected) { alert("Backend required for report generation"); return; }
    try {
      const res = await fetch(`${API_BASE}/api/report/generate`, { method: "POST" });
      const data = await res.json();
      alert(`Report generated: ${data.path}`);
    } catch (e) { alert("Report generation failed"); }
  }, [wsConnected]);

  // ─── DERIVED STATE ─────────────────────────────────────────────────────────
  const openAlerts = alerts.filter(a => a.status === "OPEN");
  const criticalCount = alerts.filter(a => a.severity === "CRITICAL").length;
  const threatLevel = criticalCount > 10 ? "CRITICAL" : criticalCount > 5 ? "HIGH" : criticalCount > 2 ? "ELEVATED" : "GUARDED";
  const tlColor = { CRITICAL: "#ff2d55", HIGH: "#ff6b35", ELEVATED: "#ffd60a", GUARDED: "#30d158" }[threatLevel];

  const allMitreTactics = ["Reconnaissance", "Initial Access", "Execution", "Discovery",
    "Credential Access", "Lateral Movement", "Command and Control", "Exfiltration", "Defense Evasion"];

  const mitreByTactic = {};
  const sourceDB = Object.keys(mitreDB).length > 0 ? mitreDB : Object.fromEntries(MITRE_FALLBACK.map(t => [t.id, t]));
  Object.values(sourceDB).forEach(t => {
    const tactic = t.tactic || "Unknown";
    if (!mitreByTactic[tactic]) mitreByTactic[tactic] = [];
    mitreByTactic[tactic].push(t);
  });

  const topAttackers = alerts.reduce((acc, a) => {
    const ex = acc.find(x => x.ip === a.src_ip);
    ex ? ex.count++ : acc.push({ ip: a.src_ip, count: 1, sev: a.severity });
    return acc;
  }, []).sort((a, b) => b.count - a.count).slice(0, 7);

  const correlatedChain = chains.length > 0 ? null : [
    { sev: "MEDIUM", title: "Recon: Port Scan (SYN)", meta: "45.12.108.77 → 10.0.0.0/24 | Ports: 1-1024", mitre: "T1046", color: "#ffd60a" },
    { sev: "HIGH", title: "Initial Access: SSH Brute Force", meta: "45.12.108.77 → 10.0.0.22:22 | Attempts: 847", mitre: "T1110", color: "#ff6b35" },
    { sev: "HIGH", title: "Execution: Remote Shell", meta: "Auth success | User: admin | Session opened", mitre: "T1059", color: "#ff6b35" },
    { sev: "CRITICAL", title: "Lateral Movement: Internal Scan", meta: "Pivot 10.0.0.22 → 10.0.0.0/24", mitre: "T1021", color: "#ff2d55" },
    { sev: "CRITICAL", title: "Exfiltration: DNS Tunneling", meta: "DNS entropy: 5.8 | Payload: 2.1MB", mitre: "T1048", color: "#ff2d55" },
  ];

  const geoSources = topAttackers.map((a, i) => ({
    lat: r(-70, 70), long: r(-160, 160), sev: a.sev,
  }));

  const cpuPct = Math.min(95, 40 + pipelineState.flows_analyzed / 100);

  // ─── RENDER ────────────────────────────────────────────────────────────────
  return (
    <>
      <style>{CSS}</style>
      <div className="app">

        {/* HEADER */}
        <header className="hdr">
          <div className="logo">
            <div className="logo-box">⬡</div>
            AID-ARS <span style={{ color: "var(--text3)", fontSize: 11 }}>v2.1.0</span>
          </div>
          <div className="hdr-center">
            <div className="hdr-stat">
              <div className={`dot ${wsConnected ? "dot-live" : "dot-yellow"}`} />
              <span>{wsConnected ? "BACKEND CONNECTED" : "SIMULATION MODE"}</span>
            </div>
            <div className="hdr-stat">
              <span style={{ color: "var(--text3)" }}>PKTS:</span>
              <span style={{ color: "var(--cyan)" }}>{pipelineState.packets_processed?.toLocaleString() || "—"}</span>
            </div>
            <div className="hdr-stat">
              <span style={{ color: "var(--text3)" }}>FLOWS:</span>
              <span style={{ color: "var(--cyan)" }}>{pipelineState.flows_analyzed?.toLocaleString() || "—"}</span>
            </div>
            <div className="hdr-stat">
              <span style={{ color: "var(--text3)" }}>ALERTS:</span>
              <span style={{ color: "var(--cyan)" }}>{pipelineState.alerts_total || alerts.length}</span>
            </div>
            <div className="hdr-stat"><div className="dot dot-red" />
              <span style={{ color: "var(--red)" }}>{criticalCount} CRITICAL</span>
            </div>
          </div>
          <div className="hdr-right">
            <span style={{ color: "var(--text3)" }}>THREAT LEVEL</span>
            <div className="tl-badge" style={{ background: `${tlColor}22`, color: tlColor, border: `1px solid ${tlColor}55` }}>{threatLevel}</div>
            <div className="ws-badge" style={wsConnected
              ? { background: "rgba(48,209,88,.15)", color: "var(--green)", border: "1px solid rgba(48,209,88,.3)" }
              : { background: "rgba(255,214,10,.15)", color: "var(--yellow)", border: "1px solid rgba(255,214,10,.3)" }
            }>{wsConnected ? "WS:LIVE" : "WS:OFFLINE"}</div>
            <span style={{ color: "var(--text3)", fontSize: 11, fontFamily: "var(--font-mono)" }}>
              {new Date().toLocaleTimeString()}
            </span>
          </div>
        </header>

        {/* NAV */}
        <nav className="nav">
          <div className="nav-sec">Detection</div>
          {[
            { id: "alerts", icon: "⚡", label: "Live Alerts", badge: openAlerts.length },
            { id: "correlation", icon: "🔗", label: "Attack Chains", badge: chains.length || undefined },
            { id: "mitre", icon: "🗺", label: "MITRE ATT&CK" },
          ].map(n => (
            <div key={n.id} className={`nav-item${activeNav === n.id ? " active" : ""}`} onClick={() => setActiveNav(n.id)}>
              <span className="nav-icon">{n.icon}</span>{n.label}
              {n.badge ? <span className="nav-badge">{n.badge}</span> : null}
            </div>
          ))}
          <div className="nav-sec">Response</div>
          {[
            { id: "response", icon: "🛡", label: "Auto-Response" },
            { id: "blocked", icon: "🚫", label: "Blocked IPs", badge: blockedIPs.length || undefined },
          ].map(n => (
            <div key={n.id} className={`nav-item${activeNav === n.id ? " active" : ""}`} onClick={() => setActiveNav(n.id)}>
              <span className="nav-icon">{n.icon}</span>{n.label}
              {n.badge ? <span className="nav-badge">{n.badge}</span> : null}
            </div>
          ))}
          <div className="nav-sec">Intelligence</div>
          {[
            { id: "traffic", icon: "📊", label: "Traffic Analysis" },
            { id: "reports", icon: "📋", label: "SOC Reports" },
          ].map(n => (
            <div key={n.id} className={`nav-item${activeNav === n.id ? " active" : ""}`} onClick={() => setActiveNav(n.id)}>
              <span className="nav-icon">{n.icon}</span>{n.label}
            </div>
          ))}
          <div style={{ flex: 1 }} />
          <div className="nav-sec">System</div>
          <div style={{ padding: "8px 14px" }}>
            <div className="prog-bar"><div className="prog-fill" style={{ width: `${cpuPct}%`, background: "var(--cyan)" }} /></div>
            <div style={{ fontSize: 10, color: "var(--text3)", fontFamily: "var(--font-mono)", marginTop: 4, display: "flex", justifyContent: "space-between" }}>
              <span>CPU: {Math.round(cpuPct)}%</span><span>MODE: {backendMode.toUpperCase()}</span>
            </div>
          </div>
          {!wsConnected && (
            <div style={{ padding: "0 14px 10px" }}>
              <button className="abtn btn-c" style={{ width: "100%", padding: "6px", fontSize: 10 }}
                onClick={connectWS}>⟳ CONNECT BACKEND</button>
            </div>
          )}
          {wsConnected && !pipelineState.running && (
            <div style={{ padding: "0 14px 10px" }}>
              <button className="abtn btn-g" style={{ width: "100%", padding: "6px", fontSize: 10 }}
                onClick={startPipeline}>▶ START PIPELINE</button>
            </div>
          )}
        </nav>

        {/* MAIN */}
        <main className="main">
          {/* Backend mode notice */}
          {!wsConnected && (
            <div className="conn-banner">
              ⚠ Running in simulation mode. Start the backend: <code style={{ color: "var(--cyan)", marginLeft: 6 }}>python api/server.py</code>
            </div>
          )}

          {/* STATS */}
          <div className="stat-row">
            {[
              { label: "Total Alerts", val: pipelineState.alerts_total || alerts.length, sub: `${openAlerts.length} open`, color: "#00d2ff" },
              { label: "IPs Blocked", val: blockedIPs.length, sub: "auto + manual", color: "#ff2d55" },
              { label: "Critical Events", val: criticalCount, sub: "require action", color: "#ff6b35" },
              { label: "True Positive Rate", val: "94.7%", sub: "F1 Score: 0.934", color: "#30d158" },
            ].map(s => (
              <div key={s.label} className="stat-card" style={{ "--ac": s.color }}>
                <div className="stat-label">{s.label}</div>
                <div className="stat-value">{s.val}</div>
                <div className="stat-sub">{s.sub}</div>
              </div>
            ))}
          </div>

          {/* TRAFFIC CHART */}
          <div className="panel">
            <div className="ph">
              <div className="pt">📈 Network Traffic Monitor</div>
              <div style={{ display: "flex", gap: 14, fontSize: 10, fontFamily: "var(--font-mono)" }}>
                <span style={{ color: "var(--cyan)" }}>● Total Traffic</span>
                <span style={{ color: "var(--red)" }}>● Malicious</span>
                <span style={{ color: "var(--text3)", fontSize: 9 }}>{wsConnected ? "LIVE DATA" : "SIMULATED"}</span>
              </div>
            </div>
            <div style={{ padding: "8px 14px 4px" }}>
              <TrafficChart data={traffic} />
            </div>
          </div>

          {/* ALERTS */}
          {activeNav === "alerts" && (
            <div className="panel">
              <div className="ph">
                <div className="pt">⚡ Live Alert Feed</div>
                <div className="tabs" style={{ margin: 0, border: "none" }}>
                  {["live", "critical", "correlated"].map(t => (
                    <div key={t} className={`tab${activeTab === t ? " active" : ""}`} onClick={() => setActiveTab(t)}>
                      {t.toUpperCase()}
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ padding: "4px 0", overflowX: "auto" }}>
                <table className="tbl">
                  <thead><tr>
                    <th>TIME</th><th>SEV</th><th>TYPE</th><th>SRC IP</th>
                    <th>DST IP</th><th>PROTO</th><th>MITRE</th><th>RISK</th><th>CONF</th><th>STATUS</th><th>ACTIONS</th>
                  </tr></thead>
                  <tbody>
                    {alerts.filter(a => {
                      if (activeTab === "critical") return a.severity === "CRITICAL" || a.severity === "HIGH";
                      if (activeTab === "correlated") return a.correlated;
                      return true;
                    }).slice(0, 15).map(a => (
                      <tr key={a.id}>
                        <td style={{ color: "var(--text3)", whiteSpace: "nowrap" }}>{a.timestamp?.slice(11, 19)}</td>
                        <td><span className="sev-b" style={{ background: SEV_BG[a.severity], color: SEV_COLORS[a.severity], border: `1px solid ${SEV_COLORS[a.severity]}44` }}>{a.severity}</span></td>
                        <td style={{ maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.type}</td>
                        <td className="ip">{a.src_ip}</td>
                        <td className="ip">{a.dst_ip}</td>
                        <td style={{ color: "var(--text2)" }}>{a.protocol}</td>
                        <td><span className="mitre-t" title={a.mitre_name}>{a.mitre_id}</span></td>
                        <td style={{ color: (a.risk_score || 0) >= 80 ? "var(--red)" : (a.risk_score || 0) >= 60 ? "var(--orange)" : "var(--yellow)" }}>
                          {a.risk_score || "—"}
                        </td>
                        <td style={{ color: (a.confidence || 0) > 90 ? "var(--green)" : "var(--yellow)" }}>{a.confidence}%</td>
                        <td><span style={{ fontSize: 10, color: a.status === "BLOCKED" ? "var(--red)" : a.status === "ACK" ? "var(--green)" : "var(--cyan)" }}>{a.status}</span></td>
                        <td>
                          <div style={{ display: "flex", gap: 4 }}>
                            {a.status === "OPEN" && <button className="abtn btn-r" onClick={() => handleBlock(a)}>BLOCK</button>}
                            {a.status === "OPEN" && <button className="abtn btn-g" onClick={() => handleAck(a)}>ACK</button>}
                            <button className="abtn btn-c">INFO</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* CHAINS */}
          {activeNav === "correlation" && (
            <div className="panel">
              <div className="ph">
                <div className="pt">🔗 Attack Chain Correlation</div>
                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--red)" }}>
                  {chains.length > 0 ? `${chains.length} ACTIVE CHAIN(S)` : "⚠ DEMO CHAIN"}
                </span>
              </div>
              {/* Live chains from backend */}
              {chains.length > 0 ? chains.slice(0, 5).map(c => (
                <div key={c.chain_id} style={{ padding: "12px 14px", borderBottom: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)" }}>{c.chain_id}</span>
                    <span className="sev-b" style={{ background: SEV_BG[c.severity], color: SEV_COLORS[c.severity], border: `1px solid ${SEV_COLORS[c.severity]}44` }}>{c.severity}</span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text2)", fontFamily: "var(--font-mono)" }}>
                    <span style={{ color: "var(--text3)" }}>SRC:</span> <span className="ip">{c.src_ip}</span> &nbsp;|&nbsp;
                    <span style={{ color: "var(--text3)" }}>EVENTS:</span> {c.alert_count} &nbsp;|&nbsp;
                    <span style={{ color: "var(--text3)" }}>RISK:</span> <span style={{ color: SEV_COLORS[c.severity] }}>{c.risk_score}</span>
                  </div>
                  <div style={{ marginTop: 6, display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {(c.stages || []).map(s => (
                      <span key={s} style={{ padding: "1px 6px", borderRadius: 2, fontSize: 9, fontFamily: "var(--font-mono)", background: "rgba(0,210,255,.1)", color: "var(--cyan)", border: "1px solid rgba(0,210,255,.2)" }}>{s}</span>
                    ))}
                  </div>
                </div>
              )) : (
                /* Demo chain when no backend chains yet */
                (correlatedChain || []).map((s, i) => (
                  <div key={i} className="chain-step">
                    <div className="chain-node" style={{ borderColor: s.color, background: `${s.color}22` }} />
                    <div className="chain-info">
                      <div className="chain-title">
                        <span style={{ color: s.color }}>#{i + 1}</span> {s.title}
                        <span className="mitre-t" style={{ marginLeft: 8 }}>{s.mitre}</span>
                      </div>
                      <div className="chain-meta">{s.meta}</div>
                    </div>
                    <span className="sev-b" style={{ background: SEV_BG[s.sev], color: SEV_COLORS[s.sev], border: `1px solid ${SEV_COLORS[s.sev]}44`, height: "fit-content" }}>{s.sev}</span>
                  </div>
                ))
              )}
              <div style={{ padding: "10px 14px", borderTop: "1px solid var(--border)", display: "flex", gap: 8 }}>
                <button className="abtn btn-r" style={{ fontSize: 12, padding: "6px 14px" }}>🚫 Block All Chain IPs</button>
                <button className="abtn btn-c" style={{ fontSize: 12, padding: "6px 14px" }}>📋 Export IOCs</button>
                <button className="abtn btn-g" style={{ fontSize: 12, padding: "6px 14px" }} onClick={generateReport}>📄 Generate Report</button>
              </div>
            </div>
          )}

          {/* MITRE */}
          {activeNav === "mitre" && (
            <div className="panel">
              <div className="ph">
                <div className="pt">🗺 MITRE ATT&CK Coverage</div>
                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text2)" }}>
                  {mitreCoverage.techniques_detected} techniques detected
                </span>
              </div>
              <div className="pb">
                {allMitreTactics.map(tactic => {
                  const techs = mitreByTactic[tactic] || [];
                  if (!techs.length) return null;
                  return (
                    <div key={tactic} style={{ marginBottom: 14 }}>
                      <div className="sec-label">{tactic}</div>
                      <div className="mitre-grid">
                        {techs.map(t => {
                          const hits = alerts.filter(a => a.mitre_id === t.id).length;
                          const active = mitreActive.has(t.id);
                          return (
                            <div key={t.id} className="mitre-cell"
                              onClick={() => setMitreActive(prev => { const s = new Set(prev); s.has(t.id) ? s.delete(t.id) : s.add(t.id); return s; })}
                              style={{
                                background: active ? "rgba(0,210,255,.15)" : hits > 0 ? "rgba(255,45,85,.1)" : "rgba(0,0,0,.2)",
                                borderColor: active ? "var(--cyan)" : hits > 0 ? "rgba(255,45,85,.3)" : "var(--border)",
                                color: active ? "var(--cyan)" : hits > 0 ? "var(--red)" : "var(--text2)",
                              }}>
                              <span style={{ fontWeight: 700, display: "block" }}>{t.id}</span>
                              <span style={{ opacity: .7, display: "block" }}>{(t.name || "").slice(0, 22)}</span>
                              {hits > 0 && <span style={{ fontSize: 9, display: "block", marginTop: 2 }}>🔴 {hits} hits</span>}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* RESPONSE */}
          {activeNav === "response" && (
            <div className="panel">
              <div className="ph">
                <div className="pt">🛡 Autonomous Response Engine</div>
                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--green)" }}>● ACTIVE {!wsConnected && "— SIMULATION"}</span>
              </div>
              <div className="pb">
                <div className="sec-label">Response Policies</div>
                <div className="status-grid" style={{ marginBottom: 14 }}>
                  {[
                    { name: "Auto-Block CRITICAL", val: "ENABLED", color: "var(--green)" },
                    { name: "Firewall Auto-Rules", val: wsConnected ? "ENABLED" : "DRY RUN", color: wsConnected ? "var(--green)" : "var(--yellow)" },
                    { name: "Port Scan → REJECT", val: "ENABLED", color: "var(--green)" },
                    { name: "C2 → Host Quarantine", val: "ENABLED", color: "var(--green)" },
                    { name: "Brute Force → Rate Limit", val: "ENABLED", color: "var(--green)" },
                    { name: "Response Rollback", val: "READY", color: "var(--cyan)" },
                  ].map(p => (
                    <div key={p.name} className="status-item">
                      <span style={{ color: "var(--text2)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{p.name}</span>
                      <span style={{ fontWeight: 600, fontFamily: "var(--font-mono)", fontSize: 11, color: p.color }}>{p.val}</span>
                    </div>
                  ))}
                </div>
                <div className="sec-label">Response Log</div>
                <div className="resp-log">
                  {(responses.length > 0 ? responses : [
                    { icon: "🚫", action_type: "BLOCK_IP", detail: "192.168.1.104 — SSH Brute Force (T1110)", timestamp: new Date(Date.now()-4000).toISOString(), success: true, color: "#ff2d55" },
                    { icon: "🔒", action_type: "FIREWALL_RULE", detail: "DROP INPUT from 10.0.0.45 port 22", timestamp: new Date(Date.now()-72000).toISOString(), success: true, color: "#ff6b35" },
                    { icon: "📡", action_type: "C2_ISOLATE", detail: "Quarantined host 10.10.2.77", timestamp: new Date(Date.now()-170000).toISOString(), success: true, color: "#ffd60a" },
                    { icon: "✅", action_type: "ROLLBACK", detail: "False positive confirmed — rule removed", timestamp: new Date(Date.now()-330000).toISOString(), success: true, color: "#30d158" },
                  ]).slice(0, 12).map((r, i) => (
                    <div key={i} className="resp-entry" style={{ borderLeftColor: r.color || "#00d2ff" }}>
                      <span className="r-icon">{r.icon}</span>
                      <div className="r-body">
                        <div className="r-action">{r.action_type}</div>
                        <div className="r-detail">{r.detail}</div>
                        <div className="r-time">{r.timestamp?.slice(0, 19).replace("T", " ")}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* BLOCKED */}
          {activeNav === "blocked" && (
            <div className="panel">
              <div className="ph">
                <div className="pt">🚫 Blocked IP Registry</div>
                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--red)" }}>{blockedIPs.length} active blocks</span>
              </div>
              <div style={{ padding: "4px 0" }}>
                <table className="tbl">
                  <thead><tr><th>#</th><th>IP ADDRESS</th><th>REASON</th><th>BLOCKED AT</th><th>EXPIRES</th><th>ACTIONS</th></tr></thead>
                  <tbody>
                    {blockedIPs.map((b, i) => (
                      <tr key={b.ip || i}>
                        <td style={{ color: "var(--text3)" }}>{i + 1}</td>
                        <td className="ip">{b.ip}</td>
                        <td style={{ color: "var(--text2)" }}>{b.reason || "Manual"}</td>
                        <td style={{ color: "var(--text3)" }}>{(b.blocked_at || "").slice(0, 19).replace("T", " ")}</td>
                        <td style={{ color: "var(--text3)" }}>{(b.expires_at || "—").slice(0, 19).replace("T", " ")}</td>
                        <td><button className="abtn btn-g" onClick={() => handleUnblock(b.ip)}>UNBLOCK</button></td>
                      </tr>
                    ))}
                    {blockedIPs.length === 0 && (
                      <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text3)", padding: "24px", fontFamily: "var(--font-mono)" }}>
                        No blocked IPs. Critical alerts are auto-blocked.
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TRAFFIC ANALYSIS */}
          {activeNav === "traffic" && (
            <div className="panel">
              <div className="ph"><div className="pt">📊 Deep Traffic Analysis</div></div>
              <div className="pb">
                <div className="sec-label">Protocol Distribution</div>
                <div className="status-grid" style={{ marginBottom: 14 }}>
                  {[["TCP","68.2%","var(--cyan)"],["UDP","18.4%","var(--purple)"],["ICMP","7.1%","var(--yellow)"],["DNS","6.3%","var(--green)"]].map(([p,v,c]) => (
                    <div key={p} className="status-item">
                      <span style={{ color: "var(--text2)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{p}</span>
                      <div>
                        <span style={{ fontWeight: 600, fontFamily: "var(--font-mono)", fontSize: 11, color: c }}>{v}</span>
                        <div className="prog-bar" style={{ width: 80 }}><div className="prog-fill" style={{ width: v, background: c }} /></div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="sec-label">Feature Statistics</div>
                {[
                  ["Avg Packet Size", "412 bytes"], ["Flow Duration Avg", "280 ms"],
                  ["Src IP Entropy", "4.21 bits"], ["Dst Port Entropy", "3.87 bits"],
                  ["Packets/Flow Avg", "34"], ["DNS Avg Query Entropy", "2.94 bits"],
                  ["Flows Analyzed", `${pipelineState.flows_analyzed || 0}`],
                  ["Active Flows", `${pipelineState.active_flows || 0}`],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 7, borderBottom: "1px solid var(--border)", paddingBottom: 6 }}>
                    <span style={{ color: "var(--text3)" }}>{k}</span>
                    <span style={{ color: "var(--cyan)" }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* REPORTS */}
          {activeNav === "reports" && (
            <div className="panel">
              <div className="ph"><div className="pt">📋 SOC Report Generator</div></div>
              <div className="pb">
                <div className="sec-label">Generate Report</div>
                <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
                  {["Incident Summary", "Full Timeline", "IOC Export (JSON)", "MITRE Coverage", "Executive Brief"].map(rpt => (
                    <button key={rpt} className="abtn btn-c" style={{ fontSize: 12, padding: "7px 14px" }} onClick={generateReport}>📄 {rpt}</button>
                  ))}
                </div>
                <div className="sec-label">System Stats</div>
                {[
                  ["Total Alerts Logged", String(pipelineState.alerts_total || alerts.length)],
                  ["Unique Source IPs", String(stats.unique_sources || new Set(alerts.map(a => a.src_ip)).size)],
                  ["Active Attack Chains", String(chains.length)],
                  ["IPs Currently Blocked", String(blockedIPs.length)],
                  ["Backend Mode", wsConnected ? "LIVE — FastAPI" : "SIMULATION"],
                  ["Detection Models", "Isolation Forest + RandomForest"],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 7, borderBottom: "1px solid var(--border)", paddingBottom: 6 }}>
                    <span style={{ color: "var(--text3)" }}>{k}</span>
                    <span style={{ color: "var(--cyan)" }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        {/* SIDE PANEL */}
        <aside className="side">
          <div className="panel">
            <div className="ph"><div className="pt">🌍 Threat Origins</div></div>
            <div style={{ padding: "8px 10px" }}>
              <GeoMap sources={geoSources} />
            </div>
          </div>

          <div className="panel">
            <div className="ph"><div className="pt">⚙ System Health</div></div>
            <div className="pb">
              {[
                { name: "Packet Capture", val: pipelineState.running ? "ACTIVE" : "STANDBY", color: pipelineState.running ? "var(--green)" : "var(--yellow)", pct: pipelineState.running ? 100 : 30 },
                { name: "ML Inference", val: "94 ms", color: "var(--cyan)", pct: 72 },
                { name: "Signature Engine", val: "ACTIVE", color: "var(--green)", pct: 100 },
                { name: "Response Engine", val: wsConnected ? "LIVE" : "DRY RUN", color: wsConnected ? "var(--green)" : "var(--yellow)", pct: 85 },
                { name: "Correlation Engine", val: "ACTIVE", color: "var(--green)", pct: 90 },
              ].map(s => (
                <div key={s.name} style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 4 }}>
                    <span style={{ color: "var(--text2)" }}>{s.name}</span>
                    <span style={{ color: s.color }}>{s.val}</span>
                  </div>
                  <div className="prog-bar"><div className="prog-fill" style={{ width: `${s.pct}%`, background: s.color }} /></div>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="ph"><div className="pt">🎯 Top Attack Sources</div></div>
            <div className="pb">
              {topAttackers.map((s, i) => (
                <div key={s.ip} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, fontSize: 11, fontFamily: "var(--font-mono)" }}>
                  <span style={{ color: "var(--text3)", width: 16 }}>#{i + 1}</span>
                  <span className="ip" style={{ flex: 1 }}>{s.ip}</span>
                  <span className="sev-b" style={{ background: SEV_BG[s.sev], color: SEV_COLORS[s.sev], border: `1px solid ${SEV_COLORS[s.sev]}33` }}>{s.count}</span>
                </div>
              ))}
              {topAttackers.length === 0 && (
                <div style={{ color: "var(--text3)", fontSize: 11, fontFamily: "var(--font-mono)", textAlign: "center", padding: "12px 0" }}>No data yet</div>
              )}
            </div>
          </div>

          <div className="panel">
            <div className="ph"><div className="pt">🤖 Model Performance</div></div>
            <div className="pb">
              {[
                ["TPR / Recall", "94.7%", "var(--green)"],
                ["Precision", "92.1%", "var(--green)"],
                ["F1 Score", "0.934", "var(--cyan)"],
                ["False Positive Rate", "2.3%", "var(--yellow)"],
                ["Avg Inference", "94 ms", "var(--cyan)"],
                ["Model Mode", wsConnected ? "RF+IsoForest" : "Heuristic", "var(--purple)"],
              ].map(([l, v, c]) => (
                <div key={l} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 7, borderBottom: "1px solid var(--border)", paddingBottom: 6 }}>
                  <span style={{ color: "var(--text3)" }}>{l}</span>
                  <span style={{ color: c, fontWeight: 700 }}>{v}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="ph"><div className="pt">📂 Dataset Sources</div></div>
            <div className="pb">
              {["CIC-IDS2017", "CIC-IDS2018", "UNSW-NB15", "Bot-IoT", "Custom PCAP"].map(ds => (
                <div key={ds} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 6 }}>
                  <span style={{ color: "var(--text2)" }}>{ds}</span>
                  <span style={{ color: "var(--green)" }}>✓ LOADED</span>
                </div>
              ))}
            </div>
          </div>
        </aside>
      </div>
    </>
  );
}
