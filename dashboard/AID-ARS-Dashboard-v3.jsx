import { useState, useEffect, useRef, useCallback } from "react";
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from "recharts";

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";
const RECONNECT_DELAY = 3000;

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLOR = { CRITICAL:"#ff3b5c", HIGH:"#ff6b35", MEDIUM:"#ffd60a", LOW:"#30d158" };
const SEV_BG    = { CRITICAL:"rgba(255,59,92,.13)", HIGH:"rgba(255,107,53,.12)", MEDIUM:"rgba(255,214,10,.11)", LOW:"rgba(48,209,88,.1)" };
const STATUS_COLOR = { OPEN:"#ff3b5c", INVESTIGATING:"#ffd60a", PENDING_REVIEW:"#ff6b35", RESOLVED:"#30d158", CLOSED:"#4a6a7a", FALSE_POSITIVE:"#7c5cbf" };

const MITRE_FALLBACK = [
  { id:"T1046",name:"Network Service Scanning",tactic:"Discovery" },
  { id:"T1110",name:"Brute Force",tactic:"Credential Access" },
  { id:"T1071",name:"Application Layer Protocol",tactic:"C2" },
  { id:"T1048",name:"Exfiltration Over Alt Protocol",tactic:"Exfiltration" },
  { id:"T1021",name:"Remote Services",tactic:"Lateral Movement" },
  { id:"T1059",name:"Command & Scripting Interpreter",tactic:"Execution" },
  { id:"T1082",name:"System Information Discovery",tactic:"Discovery" },
  { id:"T1055",name:"Process Injection",tactic:"Defense Evasion" },
  { id:"T1105",name:"Ingress Tool Transfer",tactic:"C2" },
  { id:"T1566",name:"Phishing",tactic:"Initial Access" },
];
const ATTACK_TYPES = ["Port Scan (SYN)","SSH Brute Force","DNS Tunneling","C2 Beaconing","Lateral Movement","Data Exfiltration","YARA Match","Honeypot Connection","UEBA Anomaly","Sigma Rule Hit"];

// ─── APP ──────────────────────────────────────────────────────────────────────
export default function App() {
  // connection
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  // core pipeline state
  const [alerts,       setAlerts]       = useState([]);
  const [responses,    setResponses]    = useState([]);
  const [chains,       setChains]       = useState([]);
  const [blockedIPs,   setBlockedIPs]   = useState([]);
  const [traffic,      setTraffic]      = useState([]);
  const [pipeline,     setPipeline]     = useState({ running:false,mode:"idle",alerts_total:0,flows_analyzed:0,packets_processed:0 });
  const [stats,        setStats]        = useState({ total_alerts:0,severity_breakdown:{},unique_sources:0 });
  const [mitreCov,     setMitreCov]     = useState({ techniques_detected:0,tactics_coverage:{} });
  const [mitreDB,      setMitreDB]      = useState({});
  const [acked,        setAcked]        = useState(new Set());

  // v3.0 new state
  const [cases,        setCases]        = useState([]);
  const [caseStats,    setCaseStats]    = useState({ total:0,open:0,critical_open:0,sla_breached:0 });
  const [iocStats,     setIocStats]     = useState({ total_iocs:0,hits_today:0 });
  const [uebaAnomaly,  setUebaAnomaly]  = useState([]);
  const [uebaStats,    setUebaStats]    = useState({ entities_tracked:0,anomalies_today:0,learning:true });
  const [honeypotEvts, setHoneypotEvts] = useState([]);
  const [honeypotStat, setHoneypotStat] = useState({ connections:0,unique_attackers:0,running:false });
  const [playbooks,    setPlaybooks]    = useState([]);
  const [pbHistory,    setPbHistory]    = useState([]);
  const [sigmaRules,   setSigmaRules]   = useState([]);
  const [yaraRules,    setYaraRules]    = useState([]);
  const [compReport,   setCompReport]   = useState(null);
  const [vulnFindings, setVulnFindings] = useState([]);
  const [timeline,     setTimeline]     = useState([]);
  const [lakeStats,    setLakeStats]    = useState({ total_records:0,size_mb:0 });

  // Monitor Tools state (agentless fallback — no agent on target device)
  const [monitorStatus,  setMonitorStatus]  = useState({ running:false, mode:"idle", packet_count:0, buffered_packets:0, dns_leaks_detected:0 });
  const [monitorPackets, setMonitorPackets] = useState([]);
  const [dnsLeaks,       setDnsLeaks]       = useState([]);
  const [dnsLeakSummary, setDnsLeakSummary] = useState({ known_public:0, unknown_external:0, unique_sources:0, unique_resolvers:0 });
  const [mitmSessions,   setMitmSessions]   = useState([]);
  const [monitorIface,   setMonitorIface]   = useState("wlan0");
  const [monitorTarget,  setMonitorTarget]  = useState("");
  const [mitmTarget,     setMitmTarget]     = useState("");
  const [mitmGateway,    setMitmGateway]    = useState("");
  const [monitorTab,     setMonitorTab]     = useState("capture");  // capture | mitm | dns | android

  // Android / mobile device identification state
  const [androidStatus,  setAndroidStatus]  = useState({ mdns_listener:false, ssdp_listener:false, mdns_devices:0, ssdp_devices:0, mac_rand_alerts:0, unique_android:0 });
  const [androidDevices, setAndroidDevices] = useState([]);
  const [macRandAlerts,  setMacRandAlerts]  = useState([]);
  const [androidIface,   setAndroidIface]   = useState("wlan0");

  // UI state
  const [nav,    setNav]    = useState("alerts");
  const [tab,    setTab]    = useState("live");
  const [selCase,setSelCase]= useState(null);
  const [selAlert,setSelAlert]=useState(null);
  const [newComment,setNewComment]=useState("");
  const [iocInput,setIocInput]=useState("");
  const [sigmaInput,setSigmaInput]=useState("");
  const [yaraInput,setYaraInput]=useState("");
  const [yaraName,setYaraName]=useState("");

  // ── WEBSOCKET ──────────────────────────────────────────────────────────────
  const sendWS = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN)
      wsRef.current.send(JSON.stringify(msg));
  }, []);

  const handleMsg = useCallback((msg) => {
    if (msg.type === "init") {
      if (msg.recent_alerts)  setAlerts(msg.recent_alerts.slice().reverse());
      if (msg.traffic_history) setTraffic(msg.traffic_history);
      if (msg.blocked_ips)    setBlockedIPs(msg.blocked_ips);
      if (msg.active_chains)  setChains(msg.active_chains);
      if (msg.mitre_db)       setMitreDB(msg.mitre_db);
      if (msg.playbooks)      setPlaybooks(msg.playbooks);
      if (msg.sigma_rules)    setSigmaRules(msg.sigma_rules);
      if (msg.yara_rules)     setYaraRules(msg.yara_rules);
    } else if (msg.type === "state_update") {
      if (msg.recent_alerts) setAlerts(prev => {
        const ids = new Set(prev.map(a=>a.id));
        return [...msg.recent_alerts.filter(a=>!ids.has(a.id)).reverse(), ...prev].slice(0,500);
      });
      if (msg.recent_responses) setResponses(msg.recent_responses.slice().reverse());
      if (msg.active_chains)  setChains(msg.active_chains);
      if (msg.blocked_ips)    setBlockedIPs(msg.blocked_ips);
      if (msg.pipeline)       setPipeline(msg.pipeline);
      if (msg.mitre_coverage) setMitreCov(msg.mitre_coverage);
      if (msg.traffic_point)  setTraffic(prev=>[...prev.slice(-59), msg.traffic_point]);
      if (msg.stats) {
        if (msg.stats.reporter) setStats(msg.stats.reporter);
        if (msg.stats.cases)    setCaseStats(msg.stats.cases);
        if (msg.stats.ioc)      setIocStats(msg.stats.ioc);
        if (msg.stats.ueba)     setUebaStats(msg.stats.ueba);
        if (msg.stats.honeypot) setHoneypotStat(msg.stats.honeypot);
      }
      if (msg.ueba_alerts)     setUebaAnomaly(msg.ueba_alerts);
      if (msg.honeypot_events) setHoneypotEvts(msg.honeypot_events);
    }
  }, []);

  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    ws.onopen = () => { setWsConnected(true); };
    ws.onmessage = e => { try { handleMsg(JSON.parse(e.data)); } catch(_){} };
    ws.onclose = () => { setWsConnected(false); setTimeout(connectWS, RECONNECT_DELAY); };
    ws.onerror = () => ws.close();
  }, [handleMsg]);

  useEffect(() => { connectWS(); return () => { wsRef.current?.close(); }; },[]);

  // ── API HELPERS ────────────────────────────────────────────────────────────
  const api = useCallback(async (method, path, body) => {
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        method, headers:{"Content-Type":"application/json"},
        body: body ? JSON.stringify(body) : undefined,
      });
      return await res.json();
    } catch(e){ return null; }
  },[]);

  const blockAlert = useCallback((a) => {
    sendWS({ cmd:"manual_block", ip:a.src_ip });
    setAlerts(prev=>prev.map(x=>x.id===a.id?{...x,status:"BLOCKED"}:x));
    setBlockedIPs(prev=>[...prev,{ ip:a.src_ip,reason:a.type,blocked_at:new Date().toISOString() }]);
  },[sendWS]);

  const unblockIP = useCallback((ip) => {
    sendWS({ cmd:"manual_unblock", ip });
    setBlockedIPs(prev=>prev.filter(b=>b.ip!==ip));
  },[sendWS]);

  const ackAlert = useCallback((id) => setAcked(prev=>new Set([...prev,id])),[]);

  const createCase = useCallback((a) => {
    const id = `CASE-${new Date().toISOString().slice(0,10).replace(/-/g,"")}-${a.id}`;
    const c = { id, title:`[${a.severity}] ${a.type} — ${a.src_ip}`, severity:a.severity,
      status:"OPEN", created_at:new Date().toISOString(), assigned_to:null,
      alert_ids:[a.id], comments:[], sla_breached:false, escalation_count:0 };
    setCases(prev=>[c,...prev]);
    setAlerts(prev=>prev.map(x=>x.id===a.id?{...x,has_case:true}:x));
    api("POST","/api/cases/from-alert/"+a.id);
  },[api]);

  const addCaseComment = useCallback(() => {
    if (!selCase || !newComment.trim()) return;
    setCases(prev=>prev.map(c=>c.id===selCase.id
      ? {...c,comments:[...c.comments,{ id:Date.now(),text:newComment,author:"analyst",created_at:new Date().toISOString() }]}
      : c));
    setSelCase(prev=>prev?{...prev,comments:[...prev.comments,{ id:Date.now(),text:newComment,author:"analyst",created_at:new Date().toISOString() }]}:prev);
    api("POST",`/api/cases/${selCase.id}/comments`,{ text:newComment,author:"analyst" });
    setNewComment("");
  },[selCase,newComment,api]);

  const transitionCase = useCallback((caseId,status) => {
    setCases(prev=>prev.map(c=>c.id===caseId?{...c,status}:c));
    if (selCase?.id===caseId) setSelCase(prev=>prev?{...prev,status}:prev);
    api("PATCH",`/api/cases/${caseId}/status`,{ status });
  },[selCase,api]);

  const addIOC = useCallback(() => {
    if (!iocInput.trim()) return;
    api("POST","/api/intel/iocs",{ indicator:iocInput.trim(),ioc_type:"ip",source:"manual",score:80 });
    setIocStats(prev=>({...prev,total_iocs:prev.total_iocs+1}));
    setIocInput("");
  },[iocInput,api]);

  const importSigma = useCallback(() => {
    if (!sigmaInput.trim()) return;
    api("POST","/api/sigma/import",{ yaml_content:sigmaInput,source:"manual" });
    setSigmaRules(prev=>[...prev,{ id:"sr-"+Date.now(),name:"Imported Rule",source:"manual",enabled:true,hits:0 }]);
    setSigmaInput("");
  },[sigmaInput,api]);

  const addYara = useCallback(() => {
    if (!yaraInput.trim()||!yaraName.trim()) return;
    api("POST","/api/yara/rules",{ name:yaraName,rule_text:yaraInput });
    setYaraRules(prev=>[...prev,{ id:"yr-"+Date.now(),name:yaraName,enabled:true,hits:0 }]);
    setYaraInput(""); setYaraName("");
  },[yaraInput,yaraName,api]);

  // ── MONITOR TOOLS API ACTIONS ──────────────────────────────────────────────
  const monitorPoll = useCallback(async () => {
    const [status, pkts, leaks, mitm] = await Promise.all([
      api("GET", "/api/monitor/status"),
      api("GET", "/api/monitor/packets?limit=50"),
      api("GET", "/api/monitor/dns/leaks?limit=100"),
      api("GET", "/api/monitor/mitm/status"),
    ]);
    if (status)  setMonitorStatus(status);
    if (pkts?.packets)   setMonitorPackets(pkts.packets.slice().reverse());
    if (leaks?.leaks)  { setDnsLeaks(leaks.leaks.slice().reverse()); setDnsLeakSummary(leaks.summary||{}); }
    if (mitm?.sessions)  setMitmSessions(mitm.sessions);
  }, [api]);

  const monitorStart = useCallback(async () => {
    const r = await api("POST", "/api/monitor/start", { interface:monitorIface, target_ip:monitorTarget });
    if (r) { setMonitorStatus(s=>({...s, running:r.ok||false, mode:r.mode||"starting"})); monitorPoll(); }
  }, [api, monitorIface, monitorTarget, monitorPoll]);

  const monitorStop = useCallback(async () => {
    const r = await api("POST", "/api/monitor/stop");
    if (r) { setMonitorStatus(s=>({...s, running:false, mode:"idle"})); }
  }, [api]);

  const mitmStart = useCallback(async () => {
    if (!mitmTarget || !mitmGateway) return;
    const r = await api("POST", "/api/monitor/mitm/start", { target_ip:mitmTarget, gateway_ip:mitmGateway, interface:monitorIface });
    if (r?.ok) { monitorPoll(); }
  }, [api, mitmTarget, mitmGateway, monitorIface, monitorPoll]);

  const mitmStop = useCallback(async (ip) => {
    await api("POST", "/api/monitor/mitm/stop", { target_ip:ip });
    monitorPoll();
  }, [api, monitorPoll]);

  const clearDnsLeaks = useCallback(async () => {
    await api("DELETE", "/api/monitor/dns/leaks");
    setDnsLeaks([]); setDnsLeakSummary({ known_public:0, unknown_external:0, unique_sources:0, unique_resolvers:0 });
  }, [api]);

  // ── ANDROID / MOBILE IDENTIFICATION API ACTIONS ───────────────────────────
  const androidPoll = useCallback(async () => {
    const [status, devices, macRand] = await Promise.all([
      api("GET", "/api/monitor/android/status"),
      api("GET", "/api/monitor/android/devices"),
      api("GET", "/api/monitor/android/mac-randomisation?limit=50"),
    ]);
    if (status)           setAndroidStatus(status);
    if (devices?.devices) setAndroidDevices(devices.devices);
    if (macRand?.alerts)  setMacRandAlerts(macRand.alerts);
  }, [api]);

  const androidStart = useCallback(async () => {
    const r = await api("POST", "/api/monitor/android/start", { interface: androidIface });
    if (r?.ok) { setAndroidStatus(s=>({...s, mdns_listener:true, ssdp_listener:true})); androidPoll(); }
  }, [api, androidIface, androidPoll]);

  const androidStop = useCallback(async () => {
    await api("POST", "/api/monitor/android/stop");
    setAndroidStatus(s=>({...s, mdns_listener:false, ssdp_listener:false}));
  }, [api]);

  const clearAndroid = useCallback(async () => {
    await api("DELETE", "/api/monitor/android/devices");
    setAndroidDevices([]); setMacRandAlerts([]);
    setAndroidStatus(s=>({...s, mdns_devices:0, ssdp_devices:0, mac_rand_alerts:0, unique_android:0}));
  }, [api]);

  // Poll android data every 4s when on monitor panel → android tab
  useEffect(() => {
    if (nav !== "monitor" || monitorTab !== "android") return;
    androidPoll();
    const id = setInterval(androidPoll, 4000);
    return () => clearInterval(id);
  }, [nav, monitorTab, androidPoll]);

  // Auto-poll monitor status every 3s when on that panel
  useEffect(() => {
    if (nav !== "monitor") return;
    monitorPoll();
    const id = setInterval(monitorPoll, 3000);
    return () => clearInterval(id);
  }, [nav, monitorPoll]);

  const startHoneypot = useCallback(() => {
    api("POST","/api/honeypot/start");
    setHoneypotStat(prev=>({...prev,running:true}));
  },[api]);

  const generateReport = useCallback(async () => {
    const r = await api("GET","/api/compliance/report");
    if (r) setCompReport(r);
    await api("POST","/api/report/generate");
  },[api]);

  // ── DERIVED ────────────────────────────────────────────────────────────────
  const openAlerts = alerts.filter(a=>!acked.has(a.id)&&a.status!=="BLOCKED");
  const criticalCount = openAlerts.filter(a=>a.severity==="CRITICAL").length;

  // ── DISCONNECTED BANNER ────────────────────────────────────────────────────
  const DisconnectedBanner = () => !wsConnected ? (
    <div style={{ margin:"0 0 12px",padding:"10px 14px",background:"rgba(255,214,10,.06)",
      border:"1px solid rgba(255,214,10,.2)",borderRadius:6,
      display:"flex",alignItems:"center",gap:10,fontSize:10,color:"#ffd60a",
      fontFamily:"'JetBrains Mono',monospace" }}>
      <span style={{ fontSize:14 }}>◌</span>
      <span>
        <strong>Backend not connected</strong> — make sure CyberRemedy is running:&nbsp;
        <span style={{ color:"#c8dde8" }}>sudo python3 main.py</span>
        &nbsp;then data will populate automatically via WebSocket.
      </span>
    </div>
  ) : null;

  // ── RENDER HELPERS ─────────────────────────────────────────────────────────
  const SevBadge = ({sev}) => (
    <span style={{ fontSize:9,padding:"2px 7px",borderRadius:3,fontWeight:700,letterSpacing:"1px",
      background:SEV_BG[sev],color:SEV_COLOR[sev],border:`1px solid ${SEV_COLOR[sev]}33` }}>{sev}</span>
  );

  const StatCard = ({label,val,sub,color="#00c2ff",icon}) => (
    <div style={{ background:"#070e17",border:"1px solid #0d1a26",borderRadius:8,padding:"14px 16px",
      borderTop:`2px solid ${color}` }}>
      <div style={{ fontSize:9,color:"#3a5a6a",letterSpacing:"1.5px",fontFamily:"'JetBrains Mono',monospace",marginBottom:8 }}>{label.toUpperCase()}</div>
      <div style={{ fontSize:28,fontWeight:800,color,fontFamily:"'JetBrains Mono',monospace",textShadow:`0 0 20px ${color}44` }}>{val}</div>
      {sub && <div style={{ fontSize:10,color:"#4a6a7a",marginTop:4 }}>{sub}</div>}
    </div>
  );

  // ══════════════════════════════════════════════════════════════════════════
  return (
    <div style={{ display:"grid",gridTemplateRows:"52px 1fr",gridTemplateColumns:"220px 1fr 300px",
      gridTemplateAreas:`"hdr hdr hdr" "nav main side"`,
      height:"100vh",background:"#04080f",color:"#c8dde8",
      fontFamily:"'Syne','Segoe UI',sans-serif",overflow:"hidden" }}>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar { width:4px; } ::-webkit-scrollbar-track { background:#060d15; } ::-webkit-scrollbar-thumb { background:#1a2a3a; border-radius:2px; }
        .nav-item { display:flex;align-items:center;gap:8px;padding:8px 14px;font-size:11px;font-weight:600;
          letter-spacing:0.5px;cursor:pointer;border-radius:0;color:#4a6a7a;transition:all .15s;position:relative; }
        .nav-item:hover { background:rgba(0,194,255,.06);color:#8aaabb; }
        .nav-item.active { background:rgba(0,194,255,.1);color:#00c2ff;border-left:2px solid #00c2ff; }
        .nav-item.active.danger { background:rgba(255,59,92,.08);color:#ff3b5c;border-left-color:#ff3b5c; }
        .nav-badge { margin-left:auto;background:rgba(255,59,92,.2);color:#ff3b5c;border-radius:9px;
          padding:1px 6px;font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace; }
        .nav-badge.green { background:rgba(48,209,88,.2);color:#30d158; }
        .nav-sec { padding:10px 14px 4px;font-size:9px;color:#1a3a4a;letter-spacing:"2px";font-weight:700;
          font-family:'JetBrains Mono',monospace;text-transform:uppercase; }
        .panel { background:#060d15;border:1px solid #0d1a26;border-radius:8px;padding:14px;margin-bottom:12px;position:relative; }
        .panel-title { font-size:10px;font-weight:700;color:#2a4a5a;letter-spacing:"2px";
          text-transform:uppercase;font-family:'JetBrains Mono',monospace;margin-bottom:12px; }
        .tbl { width:100%;border-collapse:collapse; }
        .tbl th { font-size:9px;color:#2a4a5a;font-weight:700;letter-spacing:"1.5px";padding:8px 10px;
          border-bottom:1px solid #0a1520;text-transform:uppercase;font-family:'JetBrains Mono',monospace;text-align:left; }
        .tbl td { font-size:11px;padding:8px 10px;border-bottom:1px solid #060d14;vertical-align:middle; }
        .tbl tr:hover td { background:rgba(0,194,255,.03); }
        .btn { padding:5px 12px;border-radius:5px;border:1px solid;font-size:10px;font-weight:700;
          cursor:pointer;font-family:'Syne',sans-serif;letter-spacing:".5px";transition:all .15s; }
        .btn-cyan { background:rgba(0,194,255,.1);border-color:rgba(0,194,255,.3);color:#00c2ff; }
        .btn-cyan:hover { background:rgba(0,194,255,.2); }
        .btn-red  { background:rgba(255,59,92,.1);border-color:rgba(255,59,92,.3);color:#ff3b5c; }
        .btn-red:hover { background:rgba(255,59,92,.2); }
        .btn-green { background:rgba(48,209,88,.1);border-color:rgba(48,209,88,.3);color:#30d158; }
        .btn-green:hover { background:rgba(48,209,88,.2); }
        .btn-amber { background:rgba(255,165,0,.1);border-color:rgba(255,165,0,.3);color:#ffa500; }
        .input { background:#070e17;border:1px solid #1a2a3a;border-radius:5px;color:#c8dde8;
          padding:7px 10px;font-size:11px;font-family:inherit;outline:none;width:100%; }
        .input:focus { border-color:rgba(0,194,255,.4); }
        .textarea { background:#070e17;border:1px solid #1a2a3a;border-radius:5px;color:#c8dde8;
          padding:7px 10px;font-size:10px;font-family:'JetBrains Mono',monospace;outline:none;width:100%;resize:vertical; }
        .textarea:focus { border-color:rgba(0,194,255,.4); }
        .chip { display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:9px;
          font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:"1px"; }
        .tag-sec { display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px; }
        .pulse { animation:pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        .slide-in { animation:slideIn .3s ease; }
        @keyframes slideIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
      `}</style>

      {/* ── HEADER ── */}
      <header style={{ gridArea:"hdr",background:"#050c15",borderBottom:"1px solid #0d1a26",
        display:"flex",alignItems:"center",justifyContent:"space-between",padding:"0 18px",gap:12 }}>
        <div style={{ display:"flex",alignItems:"center",gap:12 }}>
          <div style={{ width:32,height:32,borderRadius:8,background:"rgba(0,194,255,.12)",border:"1px solid rgba(0,194,255,.25)",
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:16 }}>⬡</div>
          <div>
            <div style={{ fontSize:13,fontWeight:800,letterSpacing:"1px",color:"#e8f4ff" }}>AID-ARS</div>
            <div style={{ fontSize:8,color:"#1a4a5a",letterSpacing:"2px",fontFamily:"'JetBrains Mono',monospace" }}>SOC PLATFORM v3.0</div>
          </div>
        </div>

        <div style={{ display:"flex",gap:16,alignItems:"center",flex:1,justifyContent:"center" }}>
          {[["PACKETS",pipeline.packets_processed||0,"#00c2ff"],["FLOWS",pipeline.flows_analyzed||0,"#30d158"],
            ["ALERTS",pipeline.alerts_total||0,"#ffd60a"],["CASES",caseStats.total||0,"#ff6b35"],
            ["BLOCKED",blockedIPs.length,"#ff3b5c"]].map(([l,v,c])=>(
            <div key={l} style={{ textAlign:"center" }}>
              <div style={{ fontSize:14,fontWeight:800,color:c,fontFamily:"'JetBrains Mono',monospace" }}>{v}</div>
              <div style={{ fontSize:8,color:"#2a4a5a",letterSpacing:"1.5px" }}>{l}</div>
            </div>
          ))}
        </div>

        <div style={{ display:"flex",alignItems:"center",gap:10 }}>
          {criticalCount>0 && (
            <div style={{ background:"rgba(255,59,92,.2)",border:"1px solid rgba(255,59,92,.4)",
              borderRadius:5,padding:"3px 10px",fontSize:11,fontWeight:700,color:"#ff3b5c" }}
              className="pulse">⚠ {criticalCount} CRITICAL</div>
          )}
          <div style={{ padding:"3px 10px",borderRadius:4,fontSize:9,fontWeight:700,letterSpacing:"1.5px",
            fontFamily:"'JetBrains Mono',monospace",
            background:wsConnected?"rgba(48,209,88,.12)":"rgba(255,214,10,.12)",
            color:wsConnected?"#30d158":"#ffd60a",
            border:`1px solid ${wsConnected?"rgba(48,209,88,.3)":"rgba(255,214,10,.3)"}` }}>
            {wsConnected?"● LIVE":"◌ DISCONNECTED"}
          </div>
          <span style={{ fontSize:9,color:"#2a4a5a",fontFamily:"'JetBrains Mono',monospace" }}>
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* ── NAV ── */}
      <nav style={{ gridArea:"nav",background:"#050c15",borderRight:"1px solid #0d1a26",
        overflowY:"auto",display:"flex",flexDirection:"column",gap:1 }}>

        <div className="nav-sec">Detection</div>
        {[
          { id:"alerts",    icon:"⚡", label:"Live Alerts",    badge:openAlerts.length, badgeStyle:"" },
          { id:"chains",    icon:"🔗", label:"Attack Chains",  badge:chains.length||undefined },
          { id:"ueba",      icon:"👤", label:"UEBA",           badge:uebaAnomaly.length||undefined },
          { id:"honeypot",  icon:"🍯", label:"Honeypot",       badge:honeypotEvts.length||undefined },
          { id:"mitre",     icon:"🗺",  label:"MITRE ATT&CK" },
        ].map(n=>(
          <div key={n.id} className={`nav-item${nav===n.id?" active":""}`} onClick={()=>setNav(n.id)}>
            <span style={{ fontSize:13 }}>{n.icon}</span>{n.label}
            {n.badge ? <span className="nav-badge">{n.badge}</span> : null}
          </div>
        ))}

        <div className="nav-sec">Response</div>
        {[
          { id:"response",  icon:"🛡", label:"Auto-Response",  badge:responses.length||undefined },
          { id:"blocked",   icon:"🚫", label:"Blocked IPs",    badge:blockedIPs.length||undefined },
          { id:"cases",     icon:"📁", label:"Case Mgmt",      badge:caseStats.open||undefined },
          { id:"playbooks", icon:"▶",  label:"Playbooks" },
        ].map(n=>(
          <div key={n.id} className={`nav-item${nav===n.id?" active":""}`} onClick={()=>setNav(n.id)}>
            <span style={{ fontSize:13 }}>{n.icon}</span>{n.label}
            {n.badge ? <span className="nav-badge">{n.badge}</span> : null}
          </div>
        ))}

        <div className="nav-sec">Intelligence</div>
        {[
          { id:"intel",      icon:"🔍", label:"Threat Intel",  badge:iocStats.hits_today||undefined, badgeStyle:"green" },
          { id:"sigma",      icon:"Σ",  label:"Sigma Rules" },
          { id:"yara",       icon:"✦",  label:"YARA Rules" },
          { id:"traffic",    icon:"📊", label:"Traffic" },
          { id:"forensics",  icon:"🔬", label:"Forensics" },
        ].map(n=>(
          <div key={n.id} className={`nav-item${nav===n.id?" active":""}`} onClick={()=>setNav(n.id)}>
            <span style={{ fontSize:13 }}>{n.icon}</span>{n.label}
            {n.badge ? <span className={`nav-badge ${n.badgeStyle||""}`}>{n.badge}</span> : null}
          </div>
        ))}

        <div className="nav-sec">Platform</div>
        {[
          { id:"monitor", icon:"📡", label:"Monitor Tools", badge: (dnsLeaks.length + (androidStatus.unique_android||0)) || undefined },
          { id:"compliance", icon:"✅", label:"Compliance" },
          { id:"datalake",   icon:"🗄",  label:"Data Lake" },
          { id:"reports",    icon:"📋", label:"Reports" },
        ].map(n=>(
          <div key={n.id} className={`nav-item${nav===n.id?" active":""}`} onClick={()=>setNav(n.id)}>
            <span style={{ fontSize:13 }}>{n.icon}</span>{n.label}
            {n.badge ? <span className="nav-badge">{n.badge}</span> : null}
          </div>
        ))}

        <div style={{ flex:1 }} />
        {/* Pipeline controls */}
        <div style={{ padding:"10px 10px",borderTop:"1px solid #0d1a26" }}>
          <button className={`btn ${pipeline.running?"btn-red":"btn-green"}`} style={{ width:"100%",marginBottom:4 }}
            onClick={()=>api("POST", pipeline.running?"/api/pipeline/stop":"/api/pipeline/start")}>
            {pipeline.running?"⏹ Stop Pipeline":"▶ Start Pipeline"}
          </button>
          <div style={{ fontSize:9,color:"#2a4a5a",textAlign:"center",fontFamily:"'JetBrains Mono',monospace" }}>
            MODE: {pipeline.mode?.toUpperCase()||"IDLE"}
          </div>
        </div>
      </nav>

      {/* ── MAIN ── */}
      <main style={{ gridArea:"main",overflowY:"auto",padding:"16px",background:"#04080f" }}>
        <DisconnectedBanner />

        {/* ALERTS */}
        {nav==="alerts" && (
          <div className="slide-in">
            <div className="tag-sec">
              <StatCard label="Open Alerts"    val={openAlerts.length}  color="#ff3b5c" />
              <StatCard label="Critical"        val={criticalCount}      color="#ff3b5c" />
              <StatCard label="Correlated"      val={alerts.filter(a=>a.correlated).length} color="#ffd60a" />
              <StatCard label="Total Today"     val={stats.total_alerts||alerts.length} color="#00c2ff" />
            </div>
            <div className="panel">
              <div className="panel-title">Live Alert Feed</div>
              <div style={{ display:"flex",gap:6,marginBottom:10 }}>
                {["live","critical","correlated","all"].map(t=>(
                  <button key={t} className={`btn ${tab===t?"btn-cyan":""}`}
                    style={{ border:tab===t?"1px solid rgba(0,194,255,.4)":"1px solid #1a2a3a",
                      color:tab===t?"#00c2ff":"#4a6a7a",background:tab===t?"rgba(0,194,255,.08)":"transparent" }}
                    onClick={()=>setTab(t)}>{t.toUpperCase()}</button>
                ))}
              </div>
              <table className="tbl">
                <thead><tr>
                  <th>TIME</th><th>SEV</th><th>TYPE</th><th>SRC IP</th><th>DST</th>
                  <th>MITRE</th><th>CONF</th><th>ACTIONS</th>
                </tr></thead>
                <tbody>
                  {alerts
                    .filter(a => {
                      if (tab==="critical") return a.severity==="CRITICAL"||a.severity==="HIGH";
                      if (tab==="correlated") return a.correlated;
                      if (tab==="live") return !acked.has(a.id)&&a.status!=="BLOCKED";
                      return true;
                    })
                    .slice(0,50)
                    .map(a=>(
                    <tr key={a.id} onClick={()=>setSelAlert(a===selAlert?null:a)}
                      style={{ cursor:"pointer", background:selAlert?.id===a.id?"rgba(0,194,255,.05)":"" }}>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#4a6a7a" }}>
                        {new Date(a.timestamp).toLocaleTimeString()}</td>
                      <td><SevBadge sev={a.severity} /></td>
                      <td style={{ fontSize:11,color:"#c8dde8" }}>{a.type}</td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#8aaabb" }}>{a.src_ip}</td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#4a6a7a" }}>:{a.dst_port}</td>
                      <td>
                        <span style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                          color:"#00c2ff",background:"rgba(0,194,255,.08)",padding:"2px 6px",borderRadius:3 }}>
                          {a.mitre_id}
                        </span>
                      </td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,
                        color:a.confidence>85?"#30d158":a.confidence>70?"#ffd60a":"#ff3b5c" }}>{a.confidence}%</td>
                      <td>
                        <div style={{ display:"flex",gap:4 }}>
                          <button className="btn btn-red" onClick={e=>{e.stopPropagation();blockAlert(a);}}>Block</button>
                          <button className="btn btn-cyan" onClick={e=>{e.stopPropagation();createCase(a);}}>Case</button>
                          <button className="btn" style={{ border:"1px solid #1a2a3a",color:"#4a6a7a",background:"transparent" }}
                            onClick={e=>{e.stopPropagation();ackAlert(a.id);}}>Ack</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ATTACK CHAINS */}
        {nav==="chains" && (
          <div className="slide-in">
            <div className="panel-title" style={{ marginBottom:12 }}>Active Attack Chains ({chains.length})</div>
            {chains.length===0&&<div style={{ color:"#2a4a5a",fontFamily:"'JetBrains Mono',monospace",fontSize:11 }}>No active chains detected</div>}
            {chains.map((ch,i)=>(
              <div key={ch.id||i} className="panel">
                <div style={{ display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10 }}>
                  <div>
                    <div style={{ fontSize:13,fontWeight:700,color:"#e8f4ff" }}>{ch.id||`CHAIN-${i+1}`}</div>
                    <div style={{ fontSize:10,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace",marginTop:2 }}>
                      Source: <span style={{ color:"#ff6b35" }}>{ch.source_ip}</span> | Events: {ch.event_count||ch.alerts?.length||0}
                    </div>
                  </div>
                  <div style={{ textAlign:"right" }}>
                    <div style={{ fontSize:22,fontWeight:800,color:"#ff3b5c",fontFamily:"'JetBrains Mono',monospace" }}>
                      {ch.risk_score||0}
                    </div>
                    <div style={{ fontSize:8,color:"#3a5a6a" }}>RISK</div>
                  </div>
                </div>
                <div style={{ display:"flex",flexWrap:"wrap",gap:4 }}>
                  {(ch.stages||ch.kill_chain_stages||[]).map(s=>(
                    <span key={s} style={{ fontSize:9,padding:"2px 8px",borderRadius:3,
                      background:"rgba(124,92,191,.15)",color:"#9b7cdf",border:"1px solid rgba(124,92,191,.25)",
                      fontFamily:"'JetBrains Mono',monospace" }}>{s}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* UEBA */}
        {nav==="ueba" && (
          <div className="slide-in">
            <div className="tag-sec">
              <StatCard label="Entities Tracked" val={uebaStats.entities_tracked||12} color="#7c5cbf" />
              <StatCard label="Anomalies Today"  val={uebaStats.anomalies_today||uebaAnomaly.length} color="#ff6b35" />
              <StatCard label="Learning Mode"    val={uebaStats.learning?"ON":"OFF"} color="#ffd60a"
                sub={uebaStats.learning?"Building baselines":"Active scoring"} />
              <StatCard label="IOC Hits Today"   val={iocStats.hits_today||0} color="#ff3b5c" />
            </div>
            <div className="panel">
              <div className="panel-title">Behavioral Anomalies</div>
              {uebaAnomaly.length===0&&<div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>No anomalies detected — baselines nominal</div>}
              {uebaAnomaly.map((a,i)=>(
                <div key={i} style={{ display:"flex",alignItems:"center",justifyContent:"space-between",
                  padding:"10px 12px",background:"#070e17",borderRadius:6,marginBottom:6,
                  borderLeft:"2px solid #ff6b35" }}>
                  <div>
                    <div style={{ fontSize:12,fontWeight:600,color:"#e8f4ff" }}>{a.type}</div>
                    <div style={{ fontSize:10,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace",marginTop:2 }}>
                      Entity: <span style={{ color:"#00c2ff" }}>{a.entity}</span> · {new Date(a.ts).toLocaleTimeString()}
                    </div>
                  </div>
                  <div style={{ textAlign:"right" }}>
                    <div style={{ fontSize:18,fontWeight:800,color:"#ff6b35",fontFamily:"'JetBrains Mono',monospace" }}>
                      {(a.deviation||0).toFixed(1)}σ
                    </div>
                    <div style={{ fontSize:8,color:"#3a5a6a" }}>DEVIATION</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* HONEYPOT */}
        {nav==="honeypot" && (
          <div className="slide-in">
            <div className="tag-sec">
              <StatCard label="Status" val={honeypotStat.running?"ACTIVE":"STOPPED"} color={honeypotStat.running?"#30d158":"#ff3b5c"} />
              <StatCard label="Connections" val={honeypotStat.connections||honeypotEvts.length} color="#ff3b5c" />
              <StatCard label="Unique Attackers" val={honeypotStat.unique_attackers||0} color="#ff6b35" />
              <StatCard label="Services" val={4} sub="SSH · HTTP · FTP · Telnet" color="#ffd60a" />
            </div>
            <div style={{ display:"flex",gap:8,marginBottom:12 }}>
              <button className="btn btn-green" onClick={startHoneypot}>▶ Start Honeypot</button>
              <button className="btn btn-red"   onClick={()=>api("POST","/api/honeypot/stop")}>⏹ Stop</button>
            </div>
            <div className="panel">
              <div className="panel-title">Connection Log — Any hit = 100% confidence CRITICAL alert</div>
              {honeypotEvts.length===0&&<div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>No honeypot connections yet</div>}
              <table className="tbl">
                <thead><tr><th>TIME</th><th>SRC IP</th><th>SERVICE</th><th>PORT</th><th>ACTION</th></tr></thead>
                <tbody>
                  {honeypotEvts.map((e,i)=>(
                    <tr key={i}>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#4a6a7a" }}>{new Date(e.ts).toLocaleTimeString()}</td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#ff3b5c",fontWeight:700 }}>{e.src_ip}</td>
                      <td><span style={{ fontSize:9,padding:"2px 7px",borderRadius:3,background:"rgba(255,107,53,.12)",color:"#ff6b35",border:"1px solid rgba(255,107,53,.3)" }}>{e.service}</span></td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#4a6a7a" }}>{e.port}</td>
                      <td><button className="btn btn-red" onClick={()=>blockAlert({src_ip:e.src_ip,id:-i,type:"Honeypot Hit",severity:"CRITICAL"})}>Block</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* MITRE */}
        {nav==="mitre" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">ATT&CK Coverage — {mitreCov.techniques_detected||0} techniques detected</div>
              <div style={{ display:"flex",flexWrap:"wrap",gap:5 }}>
                {MITRE_FALLBACK.map(t=>{
                  const active = alerts.some(a=>a.mitre_id===t.id);
                  return (
                    <div key={t.id} style={{ padding:"6px 10px",borderRadius:5,border:`1px solid ${active?"rgba(0,194,255,.4)":"#0d1a26"}`,
                      background:active?"rgba(0,194,255,.08)":"#060d15",cursor:"pointer" }}>
                      <div style={{ fontSize:9,color:active?"#00c2ff":"#2a4a5a",fontFamily:"'JetBrains Mono',monospace",fontWeight:700 }}>{t.id}</div>
                      <div style={{ fontSize:9,color:active?"#c8dde8":"#3a5a6a",marginTop:2 }}>{t.name}</div>
                      <div style={{ fontSize:8,color:"#2a4a5a",marginTop:1 }}>{t.tactic}</div>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="panel">
              <div className="panel-title">Tactic Coverage</div>
              <div style={{ height:180 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={Object.entries(mitreCov.tactics_coverage||{
                    Discovery:3,Credential Access:2,"C2":2,Exfiltration:1,"Lateral Movement":1,"Defense Evasion":1,
                  }).map(([k,v])=>({ name:k.replace(" ","\n"),count:v }))} margin={{ top:5,right:10,bottom:15,left:0 }}>
                    <XAxis dataKey="name" tick={{ fontSize:8,fill:"#3a5a6a" }} />
                    <YAxis tick={{ fontSize:8,fill:"#3a5a6a" }} />
                    <Tooltip contentStyle={{ background:"#070e17",border:"1px solid #1a2a3a",borderRadius:4,fontSize:10 }} />
                    <Bar dataKey="count" fill="#00c2ff" radius={[3,3,0,0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* AUTO RESPONSE */}
        {nav==="response" && (
          <div className="slide-in">
            <div className="tag-sec">
              <StatCard label="Actions Taken" val={responses.length} color="#30d158" />
              <StatCard label="Auto-Blocked"  val={responses.filter(r=>r.action_type==="BLOCK_IP").length} color="#ff3b5c" />
              <StatCard label="Rate Limited"  val={responses.filter(r=>r.action_type==="RATE_LIMIT").length} color="#ffd60a" />
              <StatCard label="Mode"          val="AUTO" sub={`${blockedIPs.length} IPs blocked`} color="#00c2ff" />
            </div>
            <div className="panel">
              <div className="panel-title">Response Log</div>
              {responses.map((r,i)=>(
                <div key={i} style={{ display:"flex",alignItems:"center",gap:10,padding:"8px 10px",
                  background:"#070e17",borderRadius:5,marginBottom:5,
                  borderLeft:`2px solid ${r.action_type==="BLOCK_IP"?"#ff3b5c":r.action_type==="RATE_LIMIT"?"#ffd60a":"#30d158"}` }}>
                  <span style={{ fontSize:14 }}>{r.action_type==="BLOCK_IP"?"🚫":r.action_type==="RATE_LIMIT"?"⏱":"📝"}</span>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:11,color:"#c8dde8" }}>{r.detail||r.action_type}</div>
                    <div style={{ fontSize:9,color:"#3a5a6a",fontFamily:"'JetBrains Mono',monospace" }}>{new Date(r.timestamp).toLocaleTimeString()}</div>
                  </div>
                  <span style={{ fontSize:9,padding:"2px 7px",borderRadius:3,
                    background:r.success?"rgba(48,209,88,.12)":"rgba(255,59,92,.12)",
                    color:r.success?"#30d158":"#ff3b5c",border:`1px solid ${r.success?"rgba(48,209,88,.3)":"rgba(255,59,92,.3)"}`
                  }}>{r.success?"SUCCESS":"FAILED"}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* BLOCKED IPs */}
        {nav==="blocked" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">Blocked IPs ({blockedIPs.length})</div>
              {blockedIPs.length===0&&<div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>No IPs currently blocked</div>}
              <table className="tbl">
                <thead><tr><th>IP ADDRESS</th><th>REASON</th><th>BLOCKED AT</th><th>TTL</th><th>ACTION</th></tr></thead>
                <tbody>
                  {blockedIPs.map((b,i)=>(
                    <tr key={i}>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ff3b5c",fontWeight:700 }}>{b.ip}</td>
                      <td style={{ fontSize:10,color:"#8aaabb" }}>{b.reason}</td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#4a6a7a" }}>{new Date(b.blocked_at).toLocaleTimeString()}</td>
                      <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#ffd60a" }}>3600s</td>
                      <td><button className="btn btn-green" onClick={()=>unblockIP(b.ip)}>Unblock</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* CASE MANAGEMENT */}
        {nav==="cases" && (
          <div className="slide-in">
            {selCase ? (
              <div>
                <button className="btn btn-cyan" style={{ marginBottom:12 }} onClick={()=>setSelCase(null)}>← Back to Cases</button>
                <div className="panel">
                  <div style={{ display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:12 }}>
                    <div>
                      <div style={{ fontSize:14,fontWeight:700,color:"#e8f4ff",marginBottom:4 }}>{selCase.title}</div>
                      <div style={{ fontSize:10,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace" }}>{selCase.id}</div>
                    </div>
                    <SevBadge sev={selCase.severity} />
                  </div>
                  <div style={{ display:"flex",gap:6,marginBottom:14 }}>
                    {["OPEN","INVESTIGATING","PENDING_REVIEW","RESOLVED","CLOSED"].map(s=>(
                      <button key={s} className="btn"
                        style={{ border:selCase.status===s?"1px solid rgba(0,194,255,.4)":"1px solid #1a2a3a",
                          background:selCase.status===s?"rgba(0,194,255,.12)":"transparent",
                          color:selCase.status===s?"#00c2ff":"#4a6a7a",fontSize:9 }}
                        onClick={()=>transitionCase(selCase.id,s)}>{s}</button>
                    ))}
                  </div>
                  <div style={{ marginBottom:14 }}>
                    <div className="panel-title">Comments ({selCase.comments?.length||0})</div>
                    {selCase.comments?.map((c,i)=>(
                      <div key={i} style={{ padding:"8px 10px",background:"#070e17",borderRadius:5,marginBottom:5,
                        borderLeft:"2px solid #1a3a5a" }}>
                        <div style={{ fontSize:11,color:"#c8dde8" }}>{c.text}</div>
                        <div style={{ fontSize:9,color:"#3a5a6a",marginTop:3,fontFamily:"'JetBrains Mono',monospace" }}>
                          {c.author} · {new Date(c.created_at).toLocaleTimeString()}
                        </div>
                      </div>
                    ))}
                    <div style={{ display:"flex",gap:6,marginTop:8 }}>
                      <input className="input" placeholder="Add comment…" value={newComment} onChange={e=>setNewComment(e.target.value)}
                        onKeyDown={e=>e.key==="Enter"&&addCaseComment()} />
                      <button className="btn btn-cyan" onClick={addCaseComment}>Add</button>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div>
                <div className="tag-sec">
                  <StatCard label="Total Cases"    val={Math.max(cases.length,caseStats.total)} color="#00c2ff" />
                  <StatCard label="Open"           val={cases.filter(c=>c.status==="OPEN").length||caseStats.open} color="#ff3b5c" />
                  <StatCard label="Critical Open"  val={cases.filter(c=>c.status==="OPEN"&&c.severity==="CRITICAL").length||caseStats.critical_open} color="#ff3b5c" />
                  <StatCard label="SLA Breached"   val={cases.filter(c=>c.sla_breached).length||caseStats.sla_breached} color="#ffd60a" />
                </div>
                <div className="panel">
                  <div className="panel-title">Case List</div>
                  {cases.length===0&&<div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>No cases yet. Block or investigate an alert to create one.</div>}
                  <table className="tbl">
                    <thead><tr><th>CASE ID</th><th>SEV</th><th>STATUS</th><th>TITLE</th><th>CREATED</th><th>ACTION</th></tr></thead>
                    <tbody>
                      {cases.slice(0,30).map(c=>(
                        <tr key={c.id}>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#4a6a7a" }}>{c.id}</td>
                          <td><SevBadge sev={c.severity} /></td>
                          <td>
                            <span className="chip" style={{ background:`${STATUS_COLOR[c.status]||"#2a4a5a"}18`,
                              color:STATUS_COLOR[c.status]||"#4a6a7a",border:`1px solid ${STATUS_COLOR[c.status]||"#1a2a3a"}33` }}>
                              {c.status}
                            </span>
                          </td>
                          <td style={{ fontSize:11,color:"#c8dde8",maxWidth:220,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{c.title}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#4a6a7a" }}>{new Date(c.created_at).toLocaleTimeString()}</td>
                          <td><button className="btn btn-cyan" onClick={()=>setSelCase(c)}>Open</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* PLAYBOOKS */}
        {nav==="playbooks" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">SOAR Playbooks ({playbooks.length})</div>
              {playbooks.map(pb=>(
                <div key={pb.id} style={{ display:"flex",alignItems:"center",gap:10,padding:"10px 12px",
                  background:"#070e17",borderRadius:6,marginBottom:6,
                  borderLeft:`2px solid ${pb.enabled?"#30d158":"#2a4a5a"}` }}>
                  <span style={{ fontSize:16 }}>▶</span>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:12,fontWeight:600,color:"#e8f4ff" }}>{pb.name}</div>
                    <div style={{ display:"flex",gap:4,marginTop:4 }}>
                      {(pb.trigger_severity||[]).map(s=><SevBadge key={s} sev={s} />)}
                    </div>
                  </div>
                  <div style={{ textAlign:"right" }}>
                    <div style={{ fontSize:14,fontWeight:700,color:"#ffd60a",fontFamily:"'JetBrains Mono',monospace" }}>{pb.run_count||0}</div>
                    <div style={{ fontSize:8,color:"#3a5a6a" }}>RUNS</div>
                  </div>
                  <button className={`btn ${pb.enabled?"btn-red":"btn-green"}`}
                    onClick={()=>{ setPlaybooks(prev=>prev.map(p=>p.id===pb.id?{...p,enabled:!p.enabled}:p)); api("PATCH",`/api/playbooks/${pb.id}/enable`,{ enabled:!pb.enabled }); }}>
                    {pb.enabled?"Disable":"Enable"}
                  </button>
                  <button className="btn btn-cyan"
                    onClick={()=>{ sendWS({ cmd:"run_playbook",playbook_id:pb.id,alert:alerts[0]||{} }); }}>
                    Run
                  </button>
                </div>
              ))}
              {playbooks.length===0&&<div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>No playbooks configured</div>}
            </div>
          </div>
        )}

        {/* THREAT INTEL */}
        {nav==="intel" && (
          <div className="slide-in">
            <div className="tag-sec">
              <StatCard label="Total IOCs"  val={iocStats.total_iocs||0} color="#00c2ff" />
              <StatCard label="Hits Today"  val={iocStats.hits_today||0} color="#ff3b5c" />
              <StatCard label="Sources"     val={3}  sub="Manual · OTX · MISP" color="#ffd60a" />
              <StatCard label="Auto-Enriched" val={alerts.filter(a=>a.ioc_match).length} color="#30d158" />
            </div>
            <div className="panel">
              <div className="panel-title">Add Manual IOC</div>
              <div style={{ display:"flex",gap:8 }}>
                <input className="input" placeholder="IP, domain, or hash…" value={iocInput} onChange={e=>setIocInput(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&addIOC()} />
                <button className="btn btn-cyan" onClick={addIOC}>Add IOC</button>
                <button className="btn btn-amber" onClick={()=>api("POST","/api/intel/feeds/refresh")}>Refresh Feeds</button>
              </div>
            </div>
            <div className="panel">
              <div className="panel-title">IOC-Matched Alerts</div>
              {alerts.filter(a=>a.ioc_match).length===0&&
                <div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>No IOC matches yet</div>}
              {alerts.filter(a=>a.ioc_match).slice(0,20).map(a=>(
                <div key={a.id} style={{ display:"flex",gap:10,padding:"8px 10px",background:"#070e17",
                  borderRadius:5,marginBottom:5,borderLeft:"2px solid #ff3b5c" }}>
                  <SevBadge sev={a.severity} />
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:11,color:"#e8f4ff" }}>{a.type}</div>
                    <div style={{ fontSize:9,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace" }}>
                      {a.src_ip} — IOC score: {a.ioc_match?.score||"?"}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SIGMA RULES */}
        {nav==="sigma" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">Sigma Rules ({sigmaRules.length})</div>
              {sigmaRules.map(r=>(
                <div key={r.id} style={{ display:"flex",alignItems:"center",gap:10,padding:"8px 12px",
                  background:"#070e17",borderRadius:5,marginBottom:5,borderLeft:`2px solid ${r.enabled?"#ffd60a":"#2a4a5a"}` }}>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:11,fontWeight:600,color:"#e8f4ff" }}>{r.name}</div>
                    <div style={{ fontSize:9,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace" }}>
                      Source: {r.source} · Hits: <span style={{ color:"#ffd60a" }}>{r.hits}</span>
                    </div>
                  </div>
                  <span className="chip" style={{ background:r.enabled?"rgba(255,214,10,.1)":"rgba(42,74,90,.1)",
                    color:r.enabled?"#ffd60a":"#3a5a6a",border:`1px solid ${r.enabled?"rgba(255,214,10,.3)":"#1a2a3a"}` }}>
                    {r.enabled?"ACTIVE":"DISABLED"}
                  </span>
                </div>
              ))}
            </div>
            <div className="panel">
              <div className="panel-title">Import Sigma Rule (YAML)</div>
              <textarea className="textarea" rows={8} placeholder={"title: Suspicious PowerShell\nstatus: experimental\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains: 'Invoke-WebRequest'\n  condition: selection"}
                value={sigmaInput} onChange={e=>setSigmaInput(e.target.value)} />
              <button className="btn btn-cyan" style={{ marginTop:8 }} onClick={importSigma}>Import Rule</button>
            </div>
          </div>
        )}

        {/* YARA RULES */}
        {nav==="yara" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">YARA Rules ({yaraRules.length})</div>
              {yaraRules.map(r=>(
                <div key={r.id} style={{ display:"flex",alignItems:"center",gap:10,padding:"8px 12px",
                  background:"#070e17",borderRadius:5,marginBottom:5,borderLeft:`2px solid ${r.hits>0?"#ff3b5c":"#2a4a5a"}` }}>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:11,fontWeight:600,color:"#e8f4ff" }}>{r.name}</div>
                    <div style={{ fontSize:9,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace" }}>
                      Matches: <span style={{ color:r.hits>0?"#ff3b5c":"#4a6a7a" }}>{r.hits}</span>
                    </div>
                  </div>
                  <span className="chip" style={{ background:"rgba(0,194,255,.08)",color:"#00c2ff",border:"1px solid rgba(0,194,255,.2)" }}>
                    ACTIVE
                  </span>
                </div>
              ))}
            </div>
            <div className="panel">
              <div className="panel-title">Add YARA Rule</div>
              <input className="input" placeholder="Rule name…" value={yaraName} onChange={e=>setYaraName(e.target.value)} style={{ marginBottom:6 }} />
              <textarea className="textarea" rows={8} placeholder={"rule MiraiBot {\n  strings:\n    $a = \"/bin/busybox\"\n    $b = \"MIRAI\"\n  condition:\n    any of them\n}"}
                value={yaraInput} onChange={e=>setYaraInput(e.target.value)} />
              <button className="btn btn-cyan" style={{ marginTop:8 }} onClick={addYara}>Add Rule</button>
            </div>
          </div>
        )}

        {/* TRAFFIC */}
        {nav==="traffic" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">Network Traffic — Last 60s</div>
              <div style={{ height:220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={traffic} margin={{ top:5,right:10,bottom:0,left:0 }}>
                    <defs>
                      <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#00c2ff" stopOpacity={0.2}/><stop offset="95%" stopColor="#00c2ff" stopOpacity={0}/></linearGradient>
                      <linearGradient id="gM" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ff3b5c" stopOpacity={0.3}/><stop offset="95%" stopColor="#ff3b5c" stopOpacity={0}/></linearGradient>
                    </defs>
                    <XAxis dataKey="t" tick={{ fontSize:8,fill:"#2a4a5a" }} />
                    <YAxis tick={{ fontSize:8,fill:"#2a4a5a" }} />
                    <Tooltip contentStyle={{ background:"#070e17",border:"1px solid #1a2a3a",borderRadius:4,fontSize:10 }} />
                    <Area type="monotone" dataKey="benign" stroke="#00c2ff" fill="url(#gB)" strokeWidth={1.5} dot={false} name="Benign" />
                    <Area type="monotone" dataKey="malicious" stroke="#ff3b5c" fill="url(#gM)" strokeWidth={1.5} dot={false} name="Malicious" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* FORENSICS */}
        {nav==="forensics" && (
          <div className="slide-in">
            <div className="panel">
              <div className="panel-title">Forensic Event Timeline</div>
              <div style={{ marginBottom:10,display:"flex",gap:8,alignItems:"center" }}>
                <input className="input" style={{ maxWidth:200 }} placeholder="Filter by IP…"
                  onChange={e=>{ if(wsConnected) api("GET",`/api/forensics/timeline?src_ip=${e.target.value}&limit=100`).then(r=>{ if(r?.events)setTimeline(r.events); }); }} />
              </div>
              {(timeline.length>0?timeline:alerts.slice(0,20)).map((e,i)=>(
                <div key={i} style={{ display:"flex",gap:12,padding:"8px 10px",borderBottom:"1px solid #070e17",
                  alignItems:"flex-start" }}>
                  <div style={{ fontSize:9,color:"#2a4a5a",fontFamily:"'JetBrains Mono',monospace",
                    width:70,flexShrink:0,paddingTop:2 }}>{new Date(e.timestamp||e.ts).toLocaleTimeString()}</div>
                  <div style={{ width:3,borderRadius:2,background:SEV_COLOR[e.severity]||"#1a3a5a",alignSelf:"stretch",flexShrink:0 }} />
                  <div>
                    <div style={{ fontSize:11,color:"#e8f4ff",fontWeight:600 }}>{e.type||e.event_type}</div>
                    <div style={{ fontSize:9,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace",marginTop:2 }}>
                      {e.src_ip} → {e.dst_ip} {e.mitre_id&&`· ${e.mitre_id}`}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* COMPLIANCE */}
        {nav==="compliance" && (
          <div className="slide-in">
            <div style={{ display:"flex",gap:8,marginBottom:12,flexWrap:"wrap" }}>
              {["pci_dss","hipaa","nist_800_53","cis_controls"].map(fw=>(
                <button key={fw} className="btn btn-cyan"
                  onClick={()=>api("POST",`/api/compliance/check/${fw}`).then(r=>{ if(r?.result)setCompReport(r.result); })}>
                  Check {fw.toUpperCase().replace("_"," ")}
                </button>
              ))}
            </div>
            {compReport ? (
              <div className="panel">
                <div className="panel-title">Compliance Report — {compReport.framework||"All Frameworks"}</div>
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:10 }}>
                  {Object.entries(compReport.checks||{
                    "Audit Logging":true,"Alert Retention":true,"Access Controls":false,
                    "Encryption at Rest":false,"Incident Response Plan":true
                  }).map(([k,v])=>(
                    <div key={k} style={{ display:"flex",justifyContent:"space-between",alignItems:"center",
                      padding:"8px 12px",background:"#070e17",borderRadius:5,
                      borderLeft:`2px solid ${v?"#30d158":"#ff3b5c"}` }}>
                      <div style={{ fontSize:11,color:"#c8dde8" }}>{k}</div>
                      <span className="chip" style={{ background:v?"rgba(48,209,88,.12)":"rgba(255,59,92,.12)",
                        color:v?"#30d158":"#ff3b5c",border:`1px solid ${v?"rgba(48,209,88,.3)":"rgba(255,59,92,.3)"}` }}>
                        {v?"PASS":"FAIL"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="panel">
                <div style={{ color:"#2a4a5a",fontSize:11,fontFamily:"'JetBrains Mono',monospace" }}>
                  Click a framework above to run a compliance check. Available: PCI DSS · HIPAA · NIST 800-53 · CIS Controls
                </div>
              </div>
            )}
          </div>
        )}

        {/* DATA LAKE */}
        {nav==="datalake" && (
          <div className="slide-in">
            <div className="tag-sec">
              <StatCard label="Total Records" val={lakeStats.total_records||alerts.length*12||"—"} color="#00c2ff" sub="All categories" />
              <StatCard label="Storage"       val={`${lakeStats.size_mb||"0.8"} MB`} color="#30d158" sub="JSONL compressed" />
              <StatCard label="Retention"     val="365d" color="#ffd60a" sub="Configurable" />
              <StatCard label="Format"        val="JSONL" color="#7c5cbf" sub="Parquet available" />
            </div>
            <div className="panel">
              <div className="panel-title">Query Data Lake</div>
              <div style={{ display:"flex",gap:8,alignItems:"center",marginBottom:8 }}>
                {["alert","response","honeypot","ueba"].map(cat=>(
                  <button key={cat} className="btn btn-cyan" style={{ fontSize:9 }}
                    onClick={()=>api("GET",`/api/datalake/query?category=${cat}&limit=20`).then(r=>{ if(r?.records)setTimeline(r.records); setNav("forensics"); })}>
                    Query: {cat}
                  </button>
                ))}
                <button className="btn btn-red" style={{ fontSize:9 }}
                  onClick={()=>api("DELETE","/api/datalake/prune?older_than_days=90")}>
                  Prune &gt;90d
                </button>
              </div>
              <div style={{ fontSize:10,color:"#3a5a6a",fontFamily:"'JetBrains Mono',monospace" }}>
                Query results appear in the Forensics view. All events are automatically archived.
              </div>
            </div>
          </div>
        )}

        {/* MONITOR TOOLS — Agentless fallback capture (no agent on Laptop B) */}
        {nav==="monitor" && (
          <div className="slide-in">

            {/* Status bar */}
            <div className="tag-sec" style={{ gridTemplateColumns:"repeat(5,1fr)" }}>
              <StatCard label="Capture Mode"    val={monitorStatus.mode?.toUpperCase()||"IDLE"}   color={monitorStatus.running?"#30d158":"#4a6a7a"} />
              <StatCard label="Packets Seen"    val={monitorStatus.packet_count||0}               color="#00c2ff" />
              <StatCard label="DNS Leaks"       val={monitorStatus.dns_leaks_detected||dnsLeaks.length||0} color={dnsLeaks.length>0?"#ff3b5c":"#30d158"} />
              <StatCard label="MITM Sessions"   val={mitmSessions.length}                         color={mitmSessions.length>0?"#ffd60a":"#4a6a7a"} />
              <StatCard label="Android/Mobile"  val={androidStatus.unique_android||androidDevices.length||0} color={androidDevices.length>0?"#30d158":"#4a6a7a"} />
            </div>

            {/* Sub-tabs */}
            <div style={{ display:"flex",gap:6,marginBottom:12 }}>
              {[["capture","📡 Passive Capture"],["mitm","🎯 ARP MITM Fallback"],["dns","🔍 DNS Leak Monitor"],["android","📱 Android / Mobile"]].map(([t,l])=>(
                <button key={t} className={`btn ${monitorTab===t?"btn-cyan":""}`}
                  style={{ border:monitorTab===t?"1px solid rgba(0,194,255,.4)":"1px solid #1a2a3a",
                    color:monitorTab===t?"#00c2ff":"#4a6a7a",
                    background:monitorTab===t?"rgba(0,194,255,.08)":"transparent",
                    fontSize:10,padding:"5px 14px" }}
                  onClick={()=>setMonitorTab(t)}>{l}</button>
              ))}
            </div>

            {/* ── TAB: Passive Monitor Capture ── */}
            {monitorTab==="capture" && (<>
              <div className="panel">
                <div className="panel-title">Option 1 — Monitor-Mode Passive Capture</div>
                <div style={{ fontSize:10,color:"#4a6a7a",marginBottom:12,lineHeight:1.6 }}>
                  Captures <strong style={{ color:"#c8dde8" }}>all traffic</strong> on the local interface including Laptop B (Windows 10, no agent).
                  Requires a Wi-Fi adapter capable of monitor mode, or a switched network with port mirroring.
                  Falls back automatically: <span style={{ color:"#00c2ff",fontFamily:"'JetBrains Mono',monospace" }}>scapy → AF_PACKET → tcpdump</span>
                </div>
                <div style={{ display:"flex",gap:8,flexWrap:"wrap",marginBottom:10 }}>
                  <div style={{ flex:1,minWidth:140 }}>
                    <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:4,letterSpacing:"1px" }}>INTERFACE</div>
                    <input className="input" placeholder="wlan0mon / eth0 / auto"
                      value={monitorIface} onChange={e=>setMonitorIface(e.target.value)} />
                  </div>
                  <div style={{ flex:1,minWidth:140 }}>
                    <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:4,letterSpacing:"1px" }}>TARGET IP (optional)</div>
                    <input className="input" placeholder="192.168.1.105 — leave blank for all"
                      value={monitorTarget} onChange={e=>setMonitorTarget(e.target.value)} />
                  </div>
                </div>
                <div style={{ display:"flex",gap:8 }}>
                  {!monitorStatus.running ? (
                    <button className="btn btn-green" onClick={monitorStart}>▶ Start Capture</button>
                  ) : (
                    <button className="btn btn-red" onClick={monitorStop}>⏹ Stop Capture</button>
                  )}
                  <div style={{ display:"flex",alignItems:"center",gap:6,fontSize:10,
                    color:monitorStatus.running?"#30d158":"#4a6a7a",
                    fontFamily:"'JetBrains Mono',monospace" }}>
                    <div style={{ width:6,height:6,borderRadius:"50%",
                      background:monitorStatus.running?"#30d158":"#3a5a6a",
                      boxShadow:monitorStatus.running?"0 0 8px #30d158":undefined }}
                      className={monitorStatus.running?"pulse":""} />
                    {monitorStatus.running ? `LIVE · ${monitorStatus.mode}` : "IDLE"}
                  </div>
                </div>
              </div>

              {/* Packet buffer */}
              <div className="panel">
                <div className="panel-title" style={{ display:"flex",justifyContent:"space-between" }}>
                  <span>Captured Packets ({monitorPackets.length} buffered)</span>
                  <span style={{ fontSize:9,color:"#3a5a6a",fontFamily:"'JetBrains Mono',monospace" }}>feeds detection pipeline</span>
                </div>
                {monitorPackets.length === 0 ? (
                  <div style={{ color:"#2a4a5a",fontSize:10,fontFamily:"'JetBrains Mono',monospace",padding:"10px 0" }}>
                    No packets captured yet. Start capture above.
                  </div>
                ) : (
                  <table className="tbl">
                    <thead><tr>
                      <th>TIME</th><th>SRC</th><th>DST</th><th>PROTO</th><th>DIR</th><th>LEN</th>
                    </tr></thead>
                    <tbody>
                      {monitorPackets.slice(0,40).map((p,i)=>(
                        <tr key={i}>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#3a5a6a" }}>
                            {p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : "—"}
                          </td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#ff6b35" }}>{p.src_ip}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#8aaabb"  }}>{p.dst_ip}</td>
                          <td><span className="chip" style={{ background:"rgba(0,194,255,.08)",color:"#00c2ff",border:"1px solid rgba(0,194,255,.2)" }}>{p.protocol}</span></td>
                          <td><span className="chip" style={{
                            background:p.direction==="monitored"?"rgba(124,92,191,.15)":
                                       p.direction==="outgoing" ?"rgba(255,107,53,.1)":"rgba(48,209,88,.08)",
                            color:     p.direction==="monitored"?"#7c5cbf":
                                       p.direction==="outgoing" ?"#ff6b35":"#30d158",
                            border:`1px solid ${p.direction==="monitored"?"rgba(124,92,191,.3)":
                                                p.direction==="outgoing"?"rgba(255,107,53,.3)":"rgba(48,209,88,.2)"}` }}>
                            {(p.direction||"—").toUpperCase()}
                          </span></td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"#4a6a7a" }}>{p.length||"—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>)}

            {/* ── TAB: ARP MITM Fallback ── */}
            {monitorTab==="mitm" && (<>
              <div className="panel">
                <div className="panel-title">Option 2 — ARP Poisoning MITM (Fallback)</div>
                <div style={{ fontSize:10,color:"#4a6a7a",marginBottom:12,lineHeight:1.6 }}>
                  When monitor mode fails, redirect Laptop B's traffic through Laptop A using ARP cache poisoning.
                  Works on wired and wireless networks — <strong style={{ color:"#ffd60a" }}>no agent required on Laptop B</strong>.
                  IP forwarding is enabled automatically so Laptop B stays connected.
                  <div style={{ marginTop:6,padding:"6px 10px",background:"rgba(255,214,10,.06)",
                    border:"1px solid rgba(255,214,10,.15)",borderRadius:4,color:"#ffd60a",fontSize:9,fontFamily:"'JetBrains Mono',monospace" }}>
                    ⚠ Only use on networks you own and have permission to test.
                    Does NOT decrypt HTTPS/TLS or VPN tunnels — metadata + DNS still visible.
                  </div>
                </div>
                <div style={{ display:"flex",gap:8,flexWrap:"wrap",marginBottom:10 }}>
                  <div style={{ flex:1,minWidth:140 }}>
                    <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:4,letterSpacing:"1px" }}>TARGET IP (Laptop B)</div>
                    <input className="input" placeholder="192.168.1.105"
                      value={mitmTarget} onChange={e=>setMitmTarget(e.target.value)} />
                  </div>
                  <div style={{ flex:1,minWidth:140 }}>
                    <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:4,letterSpacing:"1px" }}>GATEWAY IP (router)</div>
                    <input className="input" placeholder="192.168.1.1"
                      value={mitmGateway} onChange={e=>setMitmGateway(e.target.value)} />
                  </div>
                </div>
                <button className="btn btn-amber" onClick={mitmStart}
                  disabled={!mitmTarget||!mitmGateway}
                  style={{ opacity:(!mitmTarget||!mitmGateway)?0.4:1 }}>
                  🎯 Start ARP MITM
                </button>
              </div>

              {/* Active sessions */}
              <div className="panel">
                <div className="panel-title">Active MITM Sessions ({mitmSessions.length})</div>
                {mitmSessions.length === 0 ? (
                  <div style={{ color:"#2a4a5a",fontSize:10,fontFamily:"'JetBrains Mono',monospace",padding:"10px 0" }}>
                    No active sessions. Configure target + gateway above.
                  </div>
                ) : (
                  <table className="tbl">
                    <thead><tr><th>TARGET</th><th>GATEWAY</th><th>MAC</th><th>PKTS</th><th>STATUS</th><th></th></tr></thead>
                    <tbody>
                      {mitmSessions.map((s,i)=>(
                        <tr key={i}>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ff6b35",fontSize:10 }}>{s.target_ip}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#8aaabb",fontSize:10  }}>{s.gateway_ip}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#4a6a7a",fontSize:9   }}>{s.target_mac||"—"}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#00c2ff",fontSize:11  }}>{s.packet_count||0}</td>
                          <td>
                            <span className={`chip ${s.running?"pulse":""}`} style={{
                              background:s.running?"rgba(48,209,88,.12)":"rgba(255,59,92,.1)",
                              color:s.running?"#30d158":"#ff3b5c",
                              border:`1px solid ${s.running?"rgba(48,209,88,.3)":"rgba(255,59,92,.3)"}` }}>
                              {s.running?"ACTIVE":"STOPPED"}
                            </span>
                          </td>
                          <td><button className="btn btn-red" style={{ fontSize:9,padding:"3px 8px" }}
                            onClick={()=>mitmStop(s.target_ip)}>Stop</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>)}

            {/* ── TAB: DNS Leak Monitor ── */}
            {monitorTab==="dns" && (<>
              <div className="tag-sec" style={{ gridTemplateColumns:"repeat(4,1fr)" }}>
                <StatCard label="Known Public"     val={dnsLeakSummary.known_public||0}     color="#ff3b5c"  sub="8.8.8.8 / 1.1.1.1 etc" />
                <StatCard label="Unknown External" val={dnsLeakSummary.unknown_external||0} color="#ff6b35"  sub="Custom resolvers" />
                <StatCard label="Unique Sources"   val={dnsLeakSummary.unique_sources||0}   color="#ffd60a"  sub="Leaking devices" />
                <StatCard label="Unique Resolvers" val={dnsLeakSummary.unique_resolvers||0} color="#7c5cbf"  sub="External resolvers seen" />
              </div>

              <div className="panel">
                <div className="panel-title" style={{ display:"flex",justifyContent:"space-between",alignItems:"center" }}>
                  <span>DNS Resolver Bypass Log — T1071</span>
                  <div style={{ display:"flex",gap:6 }}>
                    <button className="btn btn-cyan" style={{ fontSize:9 }} onClick={monitorPoll}>↻ Refresh</button>
                    <button className="btn btn-red"  style={{ fontSize:9 }} onClick={clearDnsLeaks}>Clear Log</button>
                  </div>
                </div>
                <div style={{ fontSize:10,color:"#4a6a7a",marginBottom:10,lineHeight:1.5 }}>
                  Detects DNS queries sent directly to public resolvers (8.8.8.8, 1.1.1.1 etc.) instead of the LAN gateway.
                  Indicates VPN misconfiguration, split-tunnel leak, or deliberate policy bypass.
                  Alerts are also raised in the main detection pipeline (MITRE T1071).
                </div>
                {dnsLeaks.length === 0 ? (
                  <div style={{ color:"#30d158",fontSize:10,fontFamily:"'JetBrains Mono',monospace",
                    padding:"12px",textAlign:"center",background:"rgba(48,209,88,.04)",
                    border:"1px solid rgba(48,209,88,.1)",borderRadius:4 }}>
                    ✓ No DNS leaks detected — all queries going to expected resolver
                  </div>
                ) : (
                  <table className="tbl">
                    <thead><tr><th>TIME</th><th>SOURCE</th><th>RESOLVER</th><th>QUERY</th><th>TYPE</th><th>SEV</th></tr></thead>
                    <tbody>
                      {dnsLeaks.slice(0,60).map((e,i)=>(
                        <tr key={i}>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#3a5a6a" }}>
                            {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "—"}
                          </td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ff6b35",fontSize:10 }}>{e.src_ip}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ff3b5c",fontSize:10 }}>{e.dst_ip}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#8aaabb",fontSize:9,maxWidth:140,overflow:"hidden",textOverflow:"ellipsis" }}>
                            {e.dns_query||"—"}
                          </td>
                          <td><span className="chip" style={{
                            background:e.leak_type==="known_public"?"rgba(255,59,92,.1)":"rgba(255,107,53,.1)",
                            color:e.leak_type==="known_public"?"#ff3b5c":"#ff6b35",
                            border:`1px solid ${e.leak_type==="known_public"?"rgba(255,59,92,.3)":"rgba(255,107,53,.3)"}` }}>
                            {e.leak_type==="known_public"?"PUBLIC":"UNKNOWN"}
                          </span></td>
                          <td><span className="chip" style={{
                            background:SEV_BG[e.severity]||SEV_BG.LOW,
                            color:SEV_COLOR[e.severity]||SEV_COLOR.LOW,
                            border:`1px solid ${SEV_COLOR[e.severity]||SEV_COLOR.LOW}33` }}>
                            {e.severity}
                          </span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Context */}
              <div className="panel">
                <div className="panel-title">How DNS Leaks Are Detected</div>
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:10 }}>
                  {[
                    ["Rule",       "rule_dns_leak() in detection/signature.py"],
                    ["MITRE",      "T1071 — Application Layer Protocol"],
                    ["Severity",   "MEDIUM (public DNS) / LOW (unknown external)"],
                    ["Trigger",    "Any DNS UDP/53 to non-LAN resolver"],
                    ["Also fires", "Alerts in Live Alerts panel + Case auto-create"],
                    ["Fix",        "Force DNS to LAN gateway or use DoH on VPN"],
                  ].map(([k,v])=>(
                    <div key={k} style={{ padding:"8px 10px",background:"#070e17",borderRadius:5,
                      borderLeft:"2px solid #1a3a4a" }}>
                      <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:3,letterSpacing:"1px" }}>{k.toUpperCase()}</div>
                      <div style={{ fontSize:10,color:"#8aaabb",fontFamily:"'JetBrains Mono',monospace" }}>{v}</div>
                    </div>
                  ))}
                </div>
              </div>
            </>)}

            {/* ── TAB: Android / Mobile ── */}
            {monitorTab==="android" && (<>

              {/* Status cards */}
              <div className="tag-sec" style={{ gridTemplateColumns:"repeat(4,1fr)" }}>
                <StatCard label="Android Devices" val={androidStatus.unique_android||0}   color="#30d158"  sub="mDNS + SSDP identified" />
                <StatCard label="mDNS Devices"    val={androidStatus.mdns_devices||0}    color="#00c2ff"  sub="via DNS-SD :5353" />
                <StatCard label="SSDP Devices"    val={androidStatus.ssdp_devices||0}    color="#7c5cbf"  sub="via UPnP :1900" />
                <StatCard label="MAC Randomised"  val={androidStatus.mac_rand_alerts||0} color={androidStatus.mac_rand_alerts>0?"#ffd60a":"#4a6a7a"} sub="Android 10+ / iOS 14+" />
              </div>

              {/* Listener controls */}
              <div className="panel">
                <div className="panel-title">mDNS + SSDP Listeners — Android Identification</div>
                <div style={{ fontSize:10,color:"#4a6a7a",marginBottom:12,lineHeight:1.6 }}>
                  Android broadcasts its <strong style={{ color:"#c8dde8" }}>real device name</strong> over mDNS (port 5353)
                  and its <strong style={{ color:"#c8dde8" }}>Android version</strong> over SSDP (port 1900) regardless of MAC randomisation.
                  These are multicast protocols — no agent, no root, no touch required on the handset.
                  <div style={{ marginTop:6,display:"flex",gap:16,fontSize:9,fontFamily:"'JetBrains Mono',monospace",color:"#3a5a6a" }}>
                    <span style={{ color:androidStatus.mdns_listener?"#30d158":"#3a5a6a" }}>
                      {androidStatus.mdns_listener?"● mDNS :5353 ACTIVE":"○ mDNS :5353 IDLE"}
                    </span>
                    <span style={{ color:androidStatus.ssdp_listener?"#30d158":"#3a5a6a" }}>
                      {androidStatus.ssdp_listener?"● SSDP :1900 ACTIVE":"○ SSDP :1900 IDLE"}
                    </span>
                  </div>
                </div>
                <div style={{ display:"flex",gap:8,alignItems:"center",flexWrap:"wrap" }}>
                  <div style={{ minWidth:140 }}>
                    <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:4,letterSpacing:"1px" }}>INTERFACE</div>
                    <input className="input" style={{ width:140 }} placeholder="wlan0"
                      value={androidIface} onChange={e=>setAndroidIface(e.target.value)} />
                  </div>
                  {!androidStatus.mdns_listener ? (
                    <button className="btn btn-green" style={{ marginTop:14 }} onClick={androidStart}>▶ Start Listeners</button>
                  ) : (
                    <button className="btn btn-red" style={{ marginTop:14 }} onClick={androidStop}>⏹ Stop Listeners</button>
                  )}
                  <button className="btn btn-cyan" style={{ marginTop:14 }} onClick={androidPoll}>↻ Refresh</button>
                  <button className="btn btn-red"  style={{ marginTop:14, fontSize:9 }} onClick={clearAndroid}>Clear All</button>
                </div>
              </div>

              {/* Device table — mDNS + SSDP merged */}
              <div className="panel">
                <div className="panel-title" style={{ display:"flex",justifyContent:"space-between",alignItems:"center" }}>
                  <span>Identified Devices ({androidDevices.length})</span>
                  <span style={{ fontSize:9,color:"#3a5a6a",fontFamily:"'JetBrains Mono',monospace" }}>
                    hostname + USN survive MAC randomisation
                  </span>
                </div>
                {androidDevices.length === 0 ? (
                  <div style={{ color:"#2a4a5a",fontSize:10,fontFamily:"'JetBrains Mono',monospace",padding:"12px 0" }}>
                    No devices detected yet. Start listeners and wait for the Android device to broadcast.
                    Most Android devices broadcast mDNS/SSDP within 30s of joining the network.
                  </div>
                ) : (
                  <table className="tbl">
                    <thead><tr>
                      <th>IP</th><th>HOSTNAME / USN</th><th>OS</th><th>SERVER</th><th>MAC</th><th>SRC</th><th>SEEN</th>
                    </tr></thead>
                    <tbody>
                      {androidDevices.map((d,i)=>{
                        const macRand = d.mac && parseInt(d.mac.split(":")[0]||"0",16) & 0x02;
                        const osColor = d.os_hint?.toLowerCase().includes("android") ? "#30d158"
                                      : d.os_hint?.toLowerCase().includes("ios")     ? "#7c5cbf"
                                      : "#4a6a7a";
                        return (
                          <tr key={i}>
                            <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ff6b35",fontSize:10 }}>{d.ip||"—"}</td>
                            <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#c8dde8",fontSize:10,maxWidth:160,overflow:"hidden",textOverflow:"ellipsis" }}>
                              {d.hostname || d.usn?.slice(0,32) || "—"}
                            </td>
                            <td>
                              <span className="chip" style={{
                                background:`${osColor}18`,color:osColor,
                                border:`1px solid ${osColor}44` }}>
                                {d.os_hint||"Unknown"}
                              </span>
                            </td>
                            <td style={{ fontSize:9,color:"#4a6a7a",fontFamily:"'JetBrains Mono',monospace",maxWidth:140,overflow:"hidden",textOverflow:"ellipsis" }}>
                              {d.server||"—"}
                            </td>
                            <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9 }}>
                              {d.mac ? (
                                <span style={{ color:macRand?"#ffd60a":"#8aaabb" }}>
                                  {d.mac} {macRand?"⚠":""}
                                </span>
                              ) : <span style={{ color:"#2a4a5a" }}>randomised</span>}
                            </td>
                            <td>
                              <span className="chip" style={{
                                background:d.source==="mdns"?"rgba(0,194,255,.08)":"rgba(124,92,191,.1)",
                                color:d.source==="mdns"?"#00c2ff":"#7c5cbf",
                                border:`1px solid ${d.source==="mdns"?"rgba(0,194,255,.2)":"rgba(124,92,191,.3)"}` }}>
                                {(d.source||"?").toUpperCase()}
                              </span>
                            </td>
                            <td style={{ fontSize:9,color:"#3a5a6a",fontFamily:"'JetBrains Mono',monospace" }}>
                              {d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>

              {/* MAC Randomisation alerts */}
              <div className="panel">
                <div className="panel-title">MAC Randomisation Alerts — rule_mac_randomised</div>
                <div style={{ fontSize:10,color:"#4a6a7a",marginBottom:10,lineHeight:1.5 }}>
                  Fired when a device with a locally-administered MAC (bit 1 of first octet set) appears.
                  Android 10+ assigns a unique random MAC per network. The OUI vendor table will not
                  identify these devices — use hostname (mDNS) or USN (SSDP) as stable identifiers.
                </div>
                {macRandAlerts.length === 0 ? (
                  <div style={{ color:"#30d158",fontSize:10,fontFamily:"'JetBrains Mono',monospace",
                    padding:"10px",textAlign:"center",background:"rgba(48,209,88,.04)",
                    border:"1px solid rgba(48,209,88,.1)",borderRadius:4 }}>
                    ✓ No randomised MACs detected yet
                  </div>
                ) : (
                  <table className="tbl">
                    <thead><tr><th>TIME</th><th>IP</th><th>MAC</th><th>DETAIL</th><th>CONF</th></tr></thead>
                    <tbody>
                      {macRandAlerts.slice(0,30).map((a,i)=>(
                        <tr key={i}>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:"#3a5a6a" }}>
                            {new Date(a.timestamp).toLocaleTimeString()}
                          </td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ff6b35",fontSize:10 }}>{a.src_ip||"—"}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#ffd60a",fontSize:9 }}>{a.mac||"—"}</td>
                          <td style={{ fontSize:9,color:"#8aaabb",maxWidth:200,overflow:"hidden",textOverflow:"ellipsis" }}>{a.detail}</td>
                          <td style={{ fontFamily:"'JetBrains Mono',monospace",color:"#00c2ff",fontSize:10 }}>{a.confidence||90}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Reference card */}
              <div className="panel">
                <div className="panel-title">Why These Methods Work on Android</div>
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:10 }}>
                  {[
                    ["mDNS :5353",        "Android broadcasts real hostname regardless of MAC randomisation. Galaxy-S24.local, Pixel-8.local visible in plain text."],
                    ["SSDP :1900",        "UPnP NOTIFY packets contain Android version in SERVER header and stable UUID in USN field."],
                    ["MAC randomisation", "Android 10+ default. Second hex digit of MAC is 2/6/A/E. Detected by rule_mac_randomised in signature.py."],
                    ["DoT :853",          "Android Private DNS (port 853 TCP). Detected by rule_dot_leak — invisible to plain UDP-53 DNS monitoring."],
                    ["ARP MITM",          "Still works — Android is just another IP on the LAN. All metadata visible even on WPA2/WPA3."],
                    ["No agent needed",   "mDNS + SSDP are multicast — no touch on device. ARP MITM needs root on Laptop A only."],
                  ].map(([k,v])=>(
                    <div key={k} style={{ padding:"8px 10px",background:"#070e17",borderRadius:5,borderLeft:"2px solid #1a3a4a" }}>
                      <div style={{ fontSize:9,color:"#2a4a5a",marginBottom:3,letterSpacing:"1px",fontFamily:"'JetBrains Mono',monospace" }}>{k.toUpperCase()}</div>
                      <div style={{ fontSize:10,color:"#8aaabb",lineHeight:1.5 }}>{v}</div>
                    </div>
                  ))}
                </div>
              </div>

            </>)}

          </div>
        )}
        {nav==="reports" && (
          <div className="slide-in">
            <div style={{ marginBottom:12,display:"flex",gap:8 }}>
              <button className="btn btn-cyan" onClick={generateReport}>Generate HTML Report</button>
              <button className="btn btn-amber" onClick={()=>api("POST","/api/pipeline/start")}>Start Pipeline</button>
            </div>
            <div className="panel">
              <div className="panel-title">Report Contents</div>
              {[["Total Alerts",alerts.length],["CRITICAL",alerts.filter(a=>a.severity==="CRITICAL").length],
                ["Attack Chains",chains.length],["Blocked IPs",blockedIPs.length],
                ["Cases",cases.length],["Playbook Runs",playbooks.reduce((s,p)=>s+(p.run_count||0),0)]
              ].map(([l,v])=>(
                <div key={l} style={{ display:"flex",justifyContent:"space-between",padding:"8px 10px",
                  borderBottom:"1px solid #070e17" }}>
                  <div style={{ fontSize:11,color:"#8aaabb" }}>{l}</div>
                  <div style={{ fontSize:13,fontWeight:700,color:"#00c2ff",fontFamily:"'JetBrains Mono',monospace" }}>{v}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* ── SIDE PANEL ── */}
      <aside style={{ gridArea:"side",background:"#050c15",borderLeft:"1px solid #0d1a26",
        overflowY:"auto",padding:"12px" }}>

        {/* System Health */}
        <div className="panel" style={{ marginBottom:10 }}>
          <div className="panel-title">System Health</div>
          {[
            ["Monitor Capture",  monitorStatus.running?"active":"idle",    monitorStatus.running?"#30d158":"#4a6a7a"],
            ["ARP MITM",         mitmSessions.length>0?"active":"idle",    mitmSessions.length>0?"#ffd60a":"#4a6a7a"],
            ["DNS Leak Detect",  "ready",                                   "#30d158"],
            ["mDNS Listener",    androidStatus.mdns_listener?"active":"idle", androidStatus.mdns_listener?"#30d158":"#4a6a7a"],
            ["SSDP Listener",    androidStatus.ssdp_listener?"active":"idle", androidStatus.ssdp_listener?"#30d158":"#4a6a7a"],
            ["ML Anomaly",       "heuristic", "heuristic"==="ml"?"#30d158":"#ffd60a"],
            ["Correlation",      "ready", "#30d158"],
            ["UEBA",             uebaStats.learning?"learning":"active", uebaStats.learning?"#ffd60a":"#30d158"],
            ["Honeypot",         honeypotStat.running?"active":"stopped", honeypotStat.running?"#30d158":"#ff3b5c"],
            ["Case Manager",     "ready", "#30d158"],
            ["Responder",        "ready", "#30d158"],
            ["Data Lake",        "ready", "#30d158"],
          ].map(([k,v,c])=>(
            <div key={k} style={{ display:"flex",justifyContent:"space-between",alignItems:"center",
              padding:"5px 0",borderBottom:"1px solid #060d14" }}>
              <div style={{ fontSize:10,color:"#4a6a7a" }}>{k}</div>
              <span style={{ fontSize:9,fontWeight:700,color:c,fontFamily:"'JetBrains Mono',monospace" }}>
                {v.toUpperCase()}
              </span>
            </div>
          ))}
        </div>

        {/* Live Stats */}
        <div className="panel" style={{ marginBottom:10 }}>
          <div className="panel-title">Live Stats</div>
          {[
            ["Alerts/min",   (alerts.filter(a=>Date.now()-new Date(a.timestamp).getTime()<60000).length)||"—"],
            ["Open Cases",   cases.filter(c=>c.status==="OPEN").length],
            ["DNS Leaks",    dnsLeaks.length],
            ["MITM Sessions",mitmSessions.length],
            ["Android/Mobile",androidStatus.unique_android||0],
            ["MAC Randomised",androidStatus.mac_rand_alerts||0],
            ["UEBA Entities",uebaStats.entities_tracked||12],
            ["IOC DB Size",  iocStats.total_iocs||0],
            ["Sigma Rules",  sigmaRules.length],
            ["YARA Rules",   yaraRules.length],
            ["Honeypot Hits",honeypotEvts.length],
          ].map(([l,v])=>(
            <div key={l} style={{ display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 0",borderBottom:"1px solid #060d14" }}>
              <div style={{ fontSize:10,color:"#4a6a7a" }}>{l}</div>
              <div style={{ fontSize:12,fontWeight:700,color:"#00c2ff",fontFamily:"'JetBrains Mono',monospace" }}>{v}</div>
            </div>
          ))}
        </div>

        {/* Top Sources */}
        <div className="panel" style={{ marginBottom:10 }}>
          <div className="panel-title">Top Threat Sources</div>
          {(() => {
            const counts = {};
            alerts.forEach(a=>{ counts[a.src_ip]=(counts[a.src_ip]||0)+1; });
            return Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([ip,n])=>(
              <div key={ip} style={{ display:"flex",justifyContent:"space-between",alignItems:"center",
                padding:"5px 0",borderBottom:"1px solid #060d14" }}>
                <div style={{ fontSize:10,color:"#ff6b35",fontFamily:"'JetBrains Mono',monospace" }}>{ip}</div>
                <div style={{ display:"flex",gap:5,alignItems:"center" }}>
                  <div style={{ width:40,height:4,background:"#0d1a26",borderRadius:2 }}>
                    <div style={{ width:`${Math.min(100,(n/Math.max(...Object.values(counts)))*100)}%`,
                      height:"100%",background:"#ff6b35",borderRadius:2 }} />
                  </div>
                  <div style={{ fontSize:10,color:"#ff6b35",fontFamily:"'JetBrains Mono',monospace" }}>{n}</div>
                </div>
              </div>
            ));
          })()}
        </div>

        {/* Alert Detail Sidebar */}
        {selAlert && (
          <div className="panel slide-in">
            <div className="panel-title">Alert Detail</div>
            <div style={{ marginBottom:6 }}><SevBadge sev={selAlert.severity} /></div>
            <div style={{ fontSize:12,fontWeight:700,color:"#e8f4ff",marginBottom:8 }}>{selAlert.type}</div>
            {[
              ["SRC", selAlert.src_ip],["DST", selAlert.dst_ip],
              ["PORT", selAlert.dst_port],["PROTO", selAlert.protocol],
              ["MITRE",`${selAlert.mitre_id} — ${selAlert.mitre_name}`],
              ["TACTIC", selAlert.mitre_tactic],
              ["CONF", `${selAlert.confidence}%`],
              ["RISK",`${selAlert.risk_score}/100`],
            ].map(([k,v])=>(
              <div key={k} style={{ display:"flex",justifyContent:"space-between",padding:"4px 0",borderBottom:"1px solid #060d14" }}>
                <div style={{ fontSize:9,color:"#2a4a5a",letterSpacing:"1px" }}>{k}</div>
                <div style={{ fontSize:10,color:"#8aaabb",fontFamily:"'JetBrains Mono',monospace",textAlign:"right",maxWidth:140,overflow:"hidden",textOverflow:"ellipsis" }}>{v}</div>
              </div>
            ))}
            <div style={{ display:"flex",gap:4,marginTop:10 }}>
              <button className="btn btn-red" onClick={()=>{blockAlert(selAlert);setSelAlert(null);}}>Block IP</button>
              <button className="btn btn-cyan" onClick={()=>{createCase(selAlert);setSelAlert(null);}}>Create Case</button>
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}
