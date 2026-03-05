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

function r(a,b){ return Math.floor(Math.random()*(b-a+1))+a; }
const RIP = () => `${r(10,192)}.${r(0,255)}.${r(0,255)}.${r(1,254)}`;
let _sid = 1000;
function genAlert(){
  const mit = MITRE_FALLBACK[r(0,MITRE_FALLBACK.length-1)];
  const sev = SEVERITIES[r(0,3)];
  return { id:_sid++, timestamp:new Date().toISOString(), severity:sev,
    type:ATTACK_TYPES[r(0,ATTACK_TYPES.length-1)], src_ip:RIP(), dst_ip:RIP(),
    dst_port:r(1,1024), protocol:["TCP","UDP","DNS","ICMP"][r(0,3)],
    mitre_id:mit.id, mitre_name:mit.name, mitre_tactic:mit.tactic,
    confidence:r(68,99), risk_score:r(30,95), status:"OPEN", source:"simulation",
    correlated:Math.random()>0.6 };
}
function genCase(a){
  const id = `CASE-${new Date().toISOString().slice(0,10).replace(/-/g,"")}-${Math.random().toString(36).slice(2,8).toUpperCase()}`;
  return { id, title:`[${a.severity}] ${a.type} — ${a.src_ip}`, severity:a.severity,
    status:"OPEN", created_at:new Date().toISOString(), assigned_to:null,
    alert_ids:[a.id], comments:[], sla_breached:false, escalation_count:0 };
}

// ─── APP ──────────────────────────────────────────────────────────────────────
export default function App() {
  // connection
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);
  const simRef = useRef(null);
  const tickRef = useRef(0);

  // core pipeline state
  const [alerts,       setAlerts]       = useState([]);
  const [responses,    setResponses]    = useState([]);
  const [chains,       setChains]       = useState([]);
  const [blockedIPs,   setBlockedIPs]   = useState([]);
  const [traffic,      setTraffic]      = useState([]);
  const [pipeline,     setPipeline]     = useState({ running:false,mode:"simulation",alerts_total:0,flows_analyzed:0,packets_processed:0 });
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
    ws.onopen = () => { setWsConnected(true); if (simRef.current) { clearInterval(simRef.current); simRef.current=null; } };
    ws.onmessage = e => { try { handleMsg(JSON.parse(e.data)); } catch(_){} };
    ws.onclose = () => { setWsConnected(false); startSim(); setTimeout(connectWS, RECONNECT_DELAY); };
    ws.onerror = () => ws.close();
  }, [handleMsg]);

  // ── SIMULATION FALLBACK ────────────────────────────────────────────────────
  const startSim = useCallback(() => {
    if (simRef.current) return;
    setAlerts(Array.from({length:15}, genAlert).reverse());
    setTraffic(Array.from({length:40},(_,i)=>({ t:i,benign:r(200,1200),malicious:r(0,150),total:r(600,1800) })));
    setCases(Array.from({length:3},(_,i)=>genCase(genAlert())));
    setPlaybooks([
      { id:"pb-001",name:"Auto Block CRITICAL",trigger_severity:["CRITICAL"],enabled:true,run_count:12 },
      { id:"pb-002",name:"Rate Limit HIGH",trigger_severity:["HIGH"],enabled:true,run_count:5 },
    ]);
    setSigmaRules([
      { id:"sr-001",name:"PowerShell Download Cradle",source:"SigmaHQ",enabled:true,hits:3 },
      { id:"sr-002",name:"Suspicious Network Scan",source:"manual",enabled:true,hits:7 },
    ]);
    setYaraRules([
      { id:"yr-001",name:"Mirai Botnet Payload",enabled:true,hits:0 },
      { id:"yr-002",name:"Cobalt Strike Beacon",enabled:true,hits:1 },
    ]);
    setUebaAnomaly([
      { entity:"10.0.0.5",type:"Off-hours access",deviation:3.2,ts:new Date().toISOString() },
      { entity:"192.168.1.100",type:"Port sweep anomaly",deviation:4.7,ts:new Date().toISOString() },
    ]);
    setHoneypotEvts([
      { src_ip:"203.0.113.5",service:"SSH",port:2222,ts:new Date().toISOString() },
    ]);
    setHoneypotStat({ connections:3,unique_attackers:2,running:true });

    simRef.current = setInterval(() => {
      tickRef.current++;
      if (tickRef.current % 4 === 0) {
        const a = genAlert();
        setAlerts(prev=>[a,...prev].slice(0,200));
        if (a.severity === "CRITICAL") {
          const c = genCase(a); setCases(prev=>[c,...prev].slice(0,50));
          setResponses(prev=>[{ action_type:"BLOCK_IP",detail:`Auto-blocked ${a.src_ip}`,timestamp:new Date().toISOString(),success:true,target_ip:a.src_ip },...prev].slice(0,50));
          setHoneypotEvts(prev=>[{ src_ip:a.src_ip,service:"HTTP",port:8080,ts:new Date().toISOString() },...prev].slice(0,30));
        }
      }
      setTraffic(prev=>[...prev.slice(-59),{ t:tickRef.current,benign:r(200,1200),malicious:r(0,150),total:r(600,1800) }]);
    },1000);
  },[]);

  useEffect(() => { startSim(); connectWS(); return () => { if(simRef.current)clearInterval(simRef.current); wsRef.current?.close(); }; },[]);

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
    const c = genCase(a);
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
            {wsConnected?"● LIVE":"◌ SIMULATION"}
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
          { id:"compliance", icon:"✅", label:"Compliance" },
          { id:"datalake",   icon:"🗄",  label:"Data Lake" },
          { id:"reports",    icon:"📋", label:"Reports" },
        ].map(n=>(
          <div key={n.id} className={`nav-item${nav===n.id?" active":""}`} onClick={()=>setNav(n.id)}>
            <span style={{ fontSize:13 }}>{n.icon}</span>{n.label}
          </div>
        ))}

        <div style={{ flex:1 }} />
        {/* Pipeline controls */}
        <div style={{ padding:"10px 10px",borderTop:"1px solid #0d1a26" }}>
          <button className={`btn ${pipeline.running?"btn-red":"btn-green"}`} style={{ width:"100%",marginBottom:4 }}
            onClick={()=>api("POST", pipeline.running?"/api/pipeline/stop":"/api/pipeline/start?mode=simulation")}>
            {pipeline.running?"⏹ Stop Pipeline":"▶ Start Pipeline"}
          </button>
          <div style={{ fontSize:9,color:"#2a4a5a",textAlign:"center",fontFamily:"'JetBrains Mono',monospace" }}>
            MODE: {pipeline.mode?.toUpperCase()||"IDLE"}
          </div>
        </div>
      </nav>

      {/* ── MAIN ── */}
      <main style={{ gridArea:"main",overflowY:"auto",padding:"16px",background:"#04080f" }}>

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

        {/* REPORTS */}
        {nav==="reports" && (
          <div className="slide-in">
            <div style={{ marginBottom:12,display:"flex",gap:8 }}>
              <button className="btn btn-cyan" onClick={generateReport}>Generate HTML Report</button>
              <button className="btn btn-amber" onClick={()=>api("POST","/api/pipeline/start?mode=simulation")}>Start Pipeline</button>
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
            ["Signature Detect", "ready", "#30d158"],
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
