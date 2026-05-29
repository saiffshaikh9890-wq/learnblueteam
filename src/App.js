import { useState, useEffect, useRef } from "react";

// ── colour helpers ────────────────────────────────────────────────────────────
function sc(s) {
  if (s==="Critical") return {dot:"#dc2626",bg:"rgba(220,38,38,0.08)",cl:"#dc2626",br:"rgba(220,38,38,0.22)"};
  if (s==="High")     return {dot:"#ea580c",bg:"rgba(234,88,12,0.08)", cl:"#ea580c",br:"rgba(234,88,12,0.22)"};
  if (s==="Medium")   return {dot:"#d97706",bg:"rgba(217,119,6,0.08)", cl:"#b45309",br:"rgba(217,119,6,0.22)"};
  if (s==="Low")      return {dot:"#16a34a",bg:"rgba(22,163,74,0.08)", cl:"#16a34a",br:"rgba(22,163,74,0.22)"};
  return                     {dot:"#2563eb",bg:"rgba(37,99,235,0.07)", cl:"#2563eb",br:"rgba(37,99,235,0.2)"};
}
function phC(p) {
  if (p==="TRIAGE")        return "#2563eb";
  if (p==="INVESTIGATION") return "#b45309";
  if (p==="CONTAINMENT")   return "#dc2626";
  if (p==="ERADICATION")   return "#16a34a";
  if (p==="RECOVERY")      return "#7c3aed";
  return "#6b7280";
}
const phaseColor = phC;
function tlC(s) {
  if (s==="crit") return "#dc2626";
  if (s==="high") return "#ea580c";
  if (s==="med")  return "#d97706";
  return "#16a34a";
}
function getGrade(pct) {
  if (pct>=96) return "S";
  if (pct>=82) return "A";
  if (pct>=67) return "B";
  if (pct>=50) return "C";
  return "F";
}
function gradeColor(g) {
  if (g==="S") return "#7c3aed";
  if (g==="A") return "#16a34a";
  if (g==="B") return "#2563eb";
  if (g==="C") return "#b45309";
  return "#dc2626";
}
function lvlTitle(l) {
  if (l>=20) return "Elite Analyst";
  if (l>=15) return "Senior Analyst";
  if (l>=10) return "Analyst L2";
  if (l>=5)  return "Analyst L1";
  return "Junior Analyst";
}

// ── persistence ───────────────────────────────────────────────────────────────
function useApp() {
  const load = (k,d) => { try { const v=localStorage.getItem(k); return v?JSON.parse(v):d; } catch { return d; } };
  const save = (k,v) => { try { localStorage.setItem(k,JSON.stringify(v)); } catch {} };
  const [user,setUser]   = useState(()=>load("lbt_u",null));
  const [prog,setProg]   = useState(()=>load("lbt_p",{xp:0,level:1,done:{},streak:0}));
  const saveUser  = u => { setUser(u); save("lbt_u",u); };
  const addXP     = n => { const nx=prog.xp+n, nl=Math.max(1,Math.floor(nx/500)+1); const np={...prog,xp:nx,level:nl}; setProg(np); save("lbt_p",np); };
  const finishSim = (id,score,gr,sec) => { const np={...prog,done:{...prog.done,[id]:{score,grade:gr,sec,at:Date.now(),attempts:(prog.done[id]?.attempts||0)+1}}}; setProg(np); save("lbt_p",np); };
  const lvlPct    = () => Math.min(99,Math.round(((prog.xp%500)/500)*100));
  return { user,saveUser,prog,addXP,finishSim,lvlPct };
}


// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS & HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// ── responsive hook ───────────────────────────────────────────────────────────
function useWidth() {
  const [w, setW] = useState(() => typeof window !== "undefined" ? window.innerWidth : 1200);
  useEffect(() => {
    const fn = () => setW(window.innerWidth);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  }, []);
  return w;
}


// ── scenario data (card display only) ────────────────────────────────────────
const SCENARIOS = {
  "phishing-c2":{
    id:"phishing-c2",title:"CrowdStrike Falcon — Spear Phishing to C2",
    difficulty:"Easy",duration:25,xpReward:120,category:"Endpoint Detection",
    tags:["Phishing","C2","EDR","Credential Theft"],
    brief:"Finance analyst opened a macro-enabled doc. EDR detected C2 beacon to 185.220.101.47. LSASS credential dump in progress. Investigate and contain.",
  },
  "ransomware":{
    id:"ransomware",title:"Ransomware Staging Detected",
    difficulty:"Medium",duration:40,xpReward:200,category:"Ransomware / IR",
    tags:["Ransomware","Lateral Movement","EDR","SIEM"],
    brief:"Mass file encryption detected on FILE-SRV-01. Extension .locked spreading across shares. Three endpoints actively encrypting. Narrow window to stop it.",
  },
  "sentinel-aad":{
    id:"sentinel-aad",title:"Azure AD Identity Attack — MFA Fatigue",
    difficulty:"Medium",duration:30,xpReward:180,category:"Identity Security",
    tags:["Azure AD","MFA Fatigue","Account Takeover","Sentinel"],
    brief:"47 MFA push notifications in 8 minutes. One approved. User session active from Amsterdam. Impossible travel alert fired. Active ATO in progress.",
  },
};



const SHIFT_START = "08:00";
const ANALYST = { name:"Saif Al-Rashid", tier:"SOC Analyst I", id:"ANLST-047", team:"Blue Team Alpha" };

function tsNow(offset=0){
  const d = new Date("2026-05-28T08:00:00Z");
  d.setMinutes(d.getMinutes()+offset);
  return d.toISOString().replace("T"," ").slice(0,19)+" UTC";
}
// ─────────────────────────────────────────────────────────────────────────────
// INCIDENT DATA
// ─────────────────────────────────────────────────────────────────────────────

const INCIDENTS = {
"INC-2026-0441":{
  id:"INC-2026-0441",
  title:"Suspected Spear-Phishing → C2 Beacon",
  severity:"Critical",
  status:"New",
  created: tsNow(0),
  host:"WS-CORP-FIN-044",
  user:"kiran.mehta@corp.internal",
  srcIp:"10.10.44.112",
  c2Ip:"185.220.101.47",
  assignee:null,
  tags:["Phishing","C2","Credential Theft","LSASS"],
  summary:"BlueTrace SIEM correlated 4 rules on WS-CORP-FIN-044. Finance user opened macro-enabled document at 08:17. EDR detected process injection into lsass.exe. Outbound beacon to 185.220.101.47:443 (geo: RU, Tor exit). Incident auto-promoted to Critical by correlation engine.",
  mitre:["T1566.001","T1059.001","T1071.001","T1003.001","T1547.001"],

  // ── BLUETRACE SIEM ─────────────────────────────────────────────────────────
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-4471 — Macro Document + Child Process + Outbound C2",
    fired_at: tsNow(0),
    risk_score:97,
    alerts:[
      {id:"BT-9901",time:"08:17:33",sev:"Critical",rule:"OUTBOUND_C2_BEACON",src:"EDR",msg:"svchost32.exe beaconing 185.220.101.47:443 every 30s — process parent chain: OUTLOOK→WINWORD→cmd→powershell→svchost32.exe"},
      {id:"BT-9902",time:"08:18:12",sev:"Critical",rule:"LSASS_MEMORY_ACCESS",src:"EDR",msg:"Process svchost32.exe (PID:4612) opened lsass.exe with GrantedAccess=0x1fffff — credential theft in progress"},
      {id:"BT-9903",time:"08:17:14",sev:"High",   rule:"ENCODED_POWERSHELL",src:"EDR",msg:"powershell.exe -WindowStyle Hidden -Enc SUVYKEkuTihuZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZy — AMSI bypass detected"},
      {id:"BT-9904",time:"08:16:55",sev:"High",   rule:"PHISHING_MACRO_DELIVERY",src:"Email GW",msg:"Email delivered from hr-payroll@corp-financegroup.com — attachment: INV_Q4_2026_FINAL.docm — macro content detected"},
      {id:"BT-9905",time:"08:18:44",sev:"High",   rule:"REGISTRY_PERSISTENCE",src:"EDR",msg:"RegKey write: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate = svchost32.exe --server 185.220.101.47"},
      {id:"BT-9906",time:"08:19:01",sev:"Medium", rule:"SMB_LATERAL_ATTEMPT",src:"NDR",msg:"WS-CORP-FIN-044 → FS-CORP-01:445 SMB connection attempt — blocked by FW ACL RULE-2291"},
    ],
    raw_search:`index=corp_events host=WS-CORP-FIN-044 earliest=08:00 latest=08:30
| eval risk = case(rule="OUTBOUND_C2_BEACON", 97, rule="LSASS_MEMORY_ACCESS", 99, 1=1, 50)
| stats max(risk) as max_risk, values(rule) as rules by host
| where max_risk > 75`,
    correlated_hosts:["WS-CORP-FIN-044"],
    previous_incidents:["INC-2026-0388 (Low, closed — same user, failed login x3, 6 days ago)"],
  },

  // ── SENTINEL EDR ───────────────────────────────────────────────────────────
  edr:{
    tool:"SentinelEDR",
    sensor_id:"7a8b9c0d1e2f",
    sensor_version:"7.14.17706",
    prevention_policy:"CORP-DETECT-ONLY",
    policy_note:"⚠ Prevention policy is DETECT-ONLY on this host group — no auto-kill",
    process_tree:[
      {pid:"3201",ppid:"804",  depth:0,name:"OUTLOOK.EXE",   sha256:"",score:0, bad:false,time:"08:16:50",user:"CORP\\kiran.mehta",cmd:"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""},
      {pid:"4102",ppid:"3201", depth:1,name:"WINWORD.EXE",   sha256:"",score:8, bad:false,time:"08:17:01",user:"CORP\\kiran.mehta",cmd:"WINWORD.EXE /n /dde \"C:\\Users\\kiran.mehta\\Downloads\\INV_Q4_2026_FINAL.docm\""},
      {pid:"4398",ppid:"4102", depth:2,name:"cmd.exe",        sha256:"",score:91,bad:true, time:"08:17:09",user:"CORP\\kiran.mehta",cmd:"C:\\Windows\\System32\\cmd.exe /c powershell.exe -WindowStyle Hidden -NonI -Enc SUVYKEkuTihu..."},
      {pid:"4501",ppid:"4398", depth:3,name:"powershell.exe", sha256:"",score:97,bad:true, time:"08:17:14",user:"CORP\\kiran.mehta",cmd:"powershell.exe -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Enc SUVYKEku..."},
      {pid:"4612",ppid:"4501", depth:4,name:"svchost32.exe",  sha256:"a3f19c2d8e4b7f1c",score:99,bad:true,time:"08:17:33",user:"CORP\\kiran.mehta",cmd:"C:\\Users\\kiran.mehta\\AppData\\Local\\Temp\\svchost32.exe --server 185.220.101.47 --port 443 --interval 30"},
      {pid:"4701",ppid:"4612", depth:5,name:"lsass.exe",      sha256:"",score:99,bad:true, time:"08:18:12",user:"NT AUTHORITY\\SYSTEM",cmd:"[OpenProcess] GrantedAccess=0x1fffff — called by PID:4612 (svchost32.exe)"},
    ],
    network:[
      {time:"08:17:33",proto:"HTTPS",src:"10.10.44.112:51234",dst:"185.220.101.47:443",proc:"svchost32.exe",bytes:"3,840 out / 142 in",state:"ESTABLISHED",bad:true},
      {time:"08:17:34",proto:"HTTPS",src:"10.10.44.112:51241",dst:"185.220.101.47:443",proc:"svchost32.exe",bytes:"1,120 out / 98 in", state:"ESTABLISHED",bad:true},
      {time:"08:19:01",proto:"SMB",  src:"10.10.44.112:49411",dst:"10.10.44.60:445",   proc:"svchost32.exe",bytes:"0",             state:"RESET — FW",  bad:true},
      {time:"08:17:55",proto:"DNS",  src:"10.10.44.112:54321",dst:"10.10.1.5:53",      proc:"svchost.exe",  bytes:"62",             state:"CLOSED",      bad:false},
    ],
    timeline:[
      {time:"08:16:50",sev:"info",src:"SentinelEDR",event:"OUTLOOK.EXE launched — user: kiran.mehta — PID:3201"},
      {time:"08:17:01",sev:"med", src:"SentinelEDR",event:"WINWORD.EXE opened macro-enabled doc: INV_Q4_2026_FINAL.docm — VBA AutoOpen() triggered"},
      {time:"08:17:09",sev:"high",src:"SentinelEDR",event:"cmd.exe (PID:4398) spawned from WINWORD.EXE — score:91 — unusual parent-child"},
      {time:"08:17:14",sev:"high",src:"SentinelEDR",event:"powershell.exe (PID:4501) — -Enc flag — AMSI bypass in process memory — score:97"},
      {time:"08:17:33",sev:"crit",src:"SentinelEDR",event:"svchost32.exe dropped to AppData\\Temp — SHA256: a3f19c2d — VT: 48/72 — beacon started"},
      {time:"08:18:12",sev:"crit",src:"SentinelEDR",event:"LSASS memory access — GrantedAccess=0x1fffff — full credential access — Cobalt Strike pattern"},
      {time:"08:18:44",sev:"high",src:"SentinelEDR",event:"Registry Run key written — HKCU\\Run\\WindowsUpdate — persistence established"},
      {time:"08:19:01",sev:"high",src:"SentinelEDR",event:"SMB lateral attempt: 10.10.44.112 → 10.10.44.60:445 — blocked by FW ACL"},
    ],
    file_events:[
      {time:"08:17:33",action:"CREATE",path:"C:\\Users\\kiran.mehta\\AppData\\Local\\Temp\\svchost32.exe",sha256:"a3f19c2d8e4b7f1c9d2e",size:"284KB",signed:false},
      {time:"08:17:01",action:"CREATE",path:"C:\\Users\\kiran.mehta\\AppData\\Local\\Temp\\~$INV_Q4_2026_FINAL.docm",sha256:"",size:"2KB",signed:false},
    ],
  },

  // ── THREATLENS ─────────────────────────────────────────────────────────────
  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {
        type:"IP",value:"185.220.101.47",
        vt_score:"reported by 67 engines",
        abuse_score:100,
        categories:["Tor Exit Node","C2 Infrastructure","Malware Distribution"],
        country:"RU",asn:"AS204957 — GreenFloid LLC",
        last_seen:"2026-05-28",
        campaigns:["Cobalt Strike Campaigns 2024-2026","APT29 Infrastructure (low confidence)"],
        passive_dns:["update.corp-financegroup.com","cdn.doc-secure.net"],
        first_seen:"2024-11-03",
        verdict:"MALICIOUS — block immediately",
        verdictColor:"#dc2626",
      },
      {
        type:"Hash",value:"a3f19c2d8e4b7f1c9d2e",
        vt_score:"48/72 detections",
        abuse_score:0,
        categories:["Cobalt Strike Beacon","RAT","C2 Client"],
        country:"",asn:"",
        last_seen:"2026-05-27",
        campaigns:["Cobalt Strike — beacon.dll packed with UPX","Finance sector targeting 2026"],
        passive_dns:[],
        first_seen:"2026-05-01",
        verdict:"MALICIOUS — 48/72 AV detections — Cobalt Strike Beacon",
        verdictColor:"#dc2626",
      },
      {
        type:"Domain",value:"corp-financegroup.com",
        vt_score:"23/90 reported",
        abuse_score:87,
        categories:["Phishing","Brand Impersonation","Malware Distribution"],
        country:"US",asn:"AS13335 — Cloudflare (fronted)",
        last_seen:"2026-05-28",
        campaigns:["Finance sector phishing wave May 2026","Domain registered 2026-05-01 — 27 days old"],
        passive_dns:["hr-payroll.corp-financegroup.com","invoice.corp-financegroup.com"],
        first_seen:"2026-05-01",
        verdict:"MALICIOUS — phishing domain targeting finance teams",
        verdictColor:"#dc2626",
      },
    ],
  },

  // ── INCIDENT DESK ──────────────────────────────────────────────────────────
  desk:{
    tool:"IncidentDesk",
    ticket_id:"INC-2026-0441",
    sla_minutes:60,
    priority:"P1",
    category:"Malware — C2 Beacon",
    subcategory:"Credential Access",
    assignee:null,
    watchers:["soc-lead@corp.internal","ciso@corp.internal"],
    escalation_path:"SOC L1 → SOC L2 → IR Team → CISO",
    updates:[],
    ir_template:{
      executive_summary:"",
      attack_vector:"",
      blast_radius:"",
      actions_taken:"",
      outstanding:"",
      recommendations:"",
    },
  },

  // ── GUIDED STEPS ───────────────────────────────────────────────────────────
  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",
      title:"Read the SIEM Alert",
      instruction:"Your shift just started. BlueTrace SIEM has a new Critical alert. Before you touch anything — read it completely. Check: what rules fired, what host, what user, what time. Then decide: is this a True Positive or a noisy False Positive?",
      analyst_note:"A Critical with 97/100 risk score + C2 beacon rule + LSASS rule firing together at 08:17 — this is not a false positive. Open the incident. You have 60 minutes SLA.",
      action_label:"Classify TRUE POSITIVE — Open Incident",
      action_result:"INC-2026-0441 opened\nAssigned: "+ANALYST.name+"\nSLA timer: 60:00 started\nStatus: In Progress\nNext: Pivot to SentinelEDR to read the process tree",
    },
    {
      id:1,phase:"INVESTIGATION",xp:30,
      tool:"SentinelEDR",toolIcon:"🖥",
      title:"Read the Process Tree",
      instruction:"Switch to SentinelEDR. Find WS-CORP-FIN-044. Open the process tree for the detection. You need to trace the full kill chain from the initial process all the way to the beacon. What spawned what? Where did legitimate execution stop and malicious begin?",
      analyst_note:"OUTLOOK → WINWORD → cmd.exe is your red flag. A Word document should NEVER spawn cmd.exe. That's a macro executing. Trace it: cmd → powershell (-Enc means encoded, AMSI bypass) → svchost32.exe (that's NOT the real svchost — it's in AppData\\Temp). Score: 99/100.",
      action_label:"Document Kill Chain: Macro → PowerShell → C2 Beacon",
      action_result:"Kill chain confirmed:\nT1566.001 — Phishing macro document (INV_Q4_2026_FINAL.docm)\nT1059.001 — powershell.exe -Enc -WindowStyle Hidden (AMSI bypass)\nT1071.001 — svchost32.exe beaconing 185.220.101.47:443\nT1003.001 — LSASS GrantedAccess=0x1fffff (credential dump)\nT1547.001 — HKCU Run key persistence\nT1021.002 — SMB lateral attempt (blocked)\nPatient zero: kiran.mehta — Finance team",
    },
    {
      id:2,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",
      title:"Enrich IOCs — Scope the Threat",
      instruction:"You have 3 IOCs from the EDR: IP 185.220.101.47, hash a3f19c2d..., and domain corp-financegroup.com. Look each one up in ThreatLens. What are you looking for: (1) Is this IP known malicious? (2) Is the hash a known malware family? (3) How old is the phishing domain? This tells you if this is targeted or opportunistic.",
      analyst_note:"AbuseIPDB: 100/100 — this IP is a Tor exit node actively used for C2. Hash: 48/72 AV detections — Cobalt Strike Beacon. Domain: 27 days old — registered specifically for this campaign. This is targeted, not mass phishing.",
      action_label:"IOCs Enriched — Targeted Cobalt Strike Campaign",
      action_result:"IOC Enrichment complete:\n[IP] 185.220.101.47 — Tor exit / C2 infra — AbuseIPDB: 100/100 — BLOCK\n[Hash] a3f19c2d — Cobalt Strike Beacon — 48/72 VT — BLOCK+KILL\n[Domain] corp-financegroup.com — 27 days old — targeted phishing — SINKHOLE\nAssessment: Targeted attack against Finance team\nBlast radius check needed: is this email in other inboxes?",
    },
    {
      id:3,phase:"CONTAINMENT",xp:30,
      tool:"SentinelEDR",toolIcon:"🖥",
      title:"Contain WS-CORP-FIN-044",
      instruction:"You've confirmed it. Active C2 sessions are live. LSASS was dumped — kiran.mehta's credentials are compromised and potentially in use right now. You need to cut this host from the network IMMEDIATELY. In SentinelEDR — find the host — click Network Containment. The sensor stays connected for forensics. Do NOT power off.",
      analyst_note:"Network Containment in EDR is NOT the same as shutdown. The sensor stays cloud-connected. You can still run RTR commands, pull files, do memory forensics. The host just can't talk to anything else. This is the correct move — shut it down and you lose volatile memory (the beacon process, creds in RAM).",
      action_label:"Execute Network Containment — WS-CORP-FIN-044",
      action_result:"WS-CORP-FIN-044 — Network Containment: ACTIVE\nSentinel sensor: CONNECTED (forensics available)\nActive C2 sessions to 185.220.101.47: TERMINATED\nSMB lateral path: SEVERED\nHost state: PRESERVED (memory intact for forensics)\nNext: Reset kiran.mehta credentials immediately",
    },
    {
      id:4,phase:"ERADICATION",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",
      title:"Scope Blast Radius — Any Other Victims?",
      instruction:"WS-CORP-FIN-044 is contained. But did any other host beacon to 185.220.101.47? Did anyone else open the same phishing email? Run the blast radius search in BlueTrace SIEM. Search all hosts for the C2 IP and the malware hash in the last 24h. If you find another hit — you have a bigger problem.",
      analyst_note:"Always check blast radius BEFORE closing. A single endpoint SOC response that misses a second compromised host becomes a full incident the next morning. The SIEM correlated search will tell you in 30 seconds.",
      action_label:"Run Blast Radius Search — 847 Endpoints Scanned",
      action_result:"Blast radius search complete:\nC2 IP 185.220.101.47 — contacted by: 1 host (WS-CORP-FIN-044 only)\nHash a3f19c2d — found on: 1 host (WS-CORP-FIN-044 only)\nPhishing email — delivered to: 3 recipients\n  → kiran.mehta: OPENED attachment ✗\n  → rahul.singh: email in inbox, attachment NOT opened ✓\n  → priya.das: out of office (email quarantined) ✓\nAction: Quarantine emails from corp-financegroup.com for rahul.singh + priya.das",
    },
    {
      id:5,phase:"CLOSE",xp:20,
      tool:"IncidentDesk",toolIcon:"📋",
      title:"Document and Close INC-2026-0441",
      instruction:"Incident contained. Blast radius confirmed. Now write the incident report in IncidentDesk. The CISO needs the executive summary. The SOC lead needs the full technical timeline. Your future self needs the recommendations. Be specific — what was the root cause? What's still pending?",
      analyst_note:"Root cause: Prevention policy was DETECT-ONLY on Finance host group. That's why the process chain ran instead of being auto-killed. That goes in your recommendation. Also: phishing email bypassed email gateway because the domain was 27 days old — under the age threshold for sandboxing.",
      action_label:"Submit IR Report — Close INC-2026-0441",
      action_result:"INC-2026-0441 — CLOSED ✓\n\nEXEC SUMMARY: Targeted Cobalt Strike phishing attack against Finance. One endpoint compromised. C2 active for 4 minutes before containment. Credentials exposed, not yet used.\n\nRESPONSE TIME: 31 minutes (P1 SLA: 60 min) ✓\nBLAST RADIUS: 1 host, credentials exposed (not used)\n\nROOT CAUSE: EDR in DETECT-ONLY mode on finance VMs\n\nPENDING: Reimage WS-CORP-FIN-044 | Rotate kiran.mehta creds | EDR policy → PREVENT | Email GW: reduce domain age threshold | GPO: block macro execution for Finance OU",
    },
  ],
},
};

// ─────────────────────────────────────────────────────────────────────────────
// CSS
// ─────────────────────────────────────────────────────────────────────────────


// ─────────────────────────────────────────────────────────────────────────────
// SMALL UI COMPONENTS
// ─────────────────────────────────────────────────────────────────────────────

function SevBadge({s}){
  const cls=s==="Critical"?"sev-crit":s==="High"?"sev-high":s==="Medium"?"sev-med":"sev-low";
  return <span className={cls} style={{padding:"1px 7px",borderRadius:3,fontSize:9,fontWeight:700,fontFamily:"var(--mo)",letterSpacing:0.5,whiteSpace:"nowrap"}}>{s.toUpperCase()}</span>;
}
function Badge({children,color}){
  const c={blue:{bg:"var(--acl)",cl:"var(--ac)",br:"var(--acb)"},green:{bg:"var(--okl)",cl:"var(--ok)",br:"var(--okb)"},amber:{bg:"var(--warnl)",cl:"var(--warn)",br:"var(--warnb)"},red:{bg:"var(--errl)",cl:"var(--err)",br:"var(--errb)"},gray:{bg:"var(--bg4)",cl:"var(--tx3)",br:"var(--bd)"}};
  const t=c[color]||c.gray;
  return <span style={{background:t.bg,color:t.cl,border:"1px solid "+t.br,padding:"1px 8px",borderRadius:3,fontSize:10,fontWeight:600,fontFamily:"var(--mo)",letterSpacing:0.3,whiteSpace:"nowrap"}}>{children}</span>;
}
function Panel({children,title,tool,flex}){
  return(
    <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,display:"flex",flexDirection:"column",flex:flex||undefined,overflow:"hidden"}}>
      {title&&<div style={{padding:"8px 13px",borderBottom:"1px solid var(--bd)",display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
        {tool&&<span style={{fontSize:9,fontWeight:700,padding:"1px 6px",borderRadius:3,background:"var(--acl)",color:"var(--ac)",fontFamily:"var(--mo)",letterSpacing:0.4}}>{tool}</span>}
        <span style={{fontSize:11,fontWeight:600,color:"var(--tx2)",fontFamily:"var(--mo)",letterSpacing:0.2,textTransform:"uppercase"}}>{title}</span>
      </div>}
      <div style={{flex:1,overflow:"auto"}}>{children}</div>
    </div>
  );
}
function Dot({color,pulse}){
  return <div style={{width:7,height:7,borderRadius:"50%",background:color,flexShrink:0,animation:pulse?"pulse 1.8s ease-in-out infinite":"none"}}/>;
}

// ─────────────────────────────────────────────────────────────────────────────
// SCORE MODAL
// ─────────────────────────────────────────────────────────────────────────────

function ScoreModal({inc,steps,elapsed,hintCount,onBack}){
  const mm=String(Math.floor(elapsed/60)).padStart(2,"0");
  const ss=String(elapsed%60).padStart(2,"0");
  const totalXP=steps.reduce((a,s)=>a+s.xp,0);
  const penalty=hintCount*15;
  const timeBonus=Math.max(0,300-elapsed);
  const final=Math.max(0,totalXP-penalty+timeBonus);
  const pct=Math.round(final/(totalXP+300)*100);
  const grade=pct>=96?"S":pct>=82?"A":pct>=67?"B":pct>=50?"C":"F";
  const gc=grade==="S"?"#a855f7":grade==="A"?"#22c55e":grade==="B"?"#3b82f6":grade==="C"?"#f59e0b":"#ef4444";
  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.8)",backdropFilter:"blur(8px)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:16,padding:36,maxWidth:480,width:"100%",boxShadow:"var(--sh3)",animation:"fadeUp 0.4s ease"}}>
        <div style={{textAlign:"center",marginBottom:24}}>
          <div style={{fontSize:64,fontWeight:800,color:gc,fontFamily:"var(--mo)",lineHeight:1,marginBottom:8}}>{grade}</div>
          <div style={{fontSize:18,fontWeight:700,color:"var(--tx)"}}>Incident Closed</div>
          <div style={{fontSize:13,color:"var(--tx3)",marginTop:4}}>{inc.id} — {inc.title}</div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:20}}>
          {[["XP Earned",final,"var(--ac)"],["Time",mm+":"+ss,pct>=60?"var(--ok)":"var(--warn)"],["Hints Used",hintCount,hintCount===0?"var(--ok)":"var(--warn)"]].map(([l,v,c])=>(
            <div key={l} style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:10,padding:"14px 8px",textAlign:"center"}}>
              <div style={{fontSize:20,fontWeight:700,color:c,fontFamily:"var(--mo)",marginBottom:2}}>{v}</div>
              <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em",textTransform:"uppercase"}}>{l}</div>
            </div>
          ))}
        </div>
        <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px 14px",marginBottom:20}}>
          {[["Steps completed",steps.length+"/"+steps.length],["Base XP",totalXP],["Hint penalty","-"+penalty],["Time bonus","+"+timeBonus]].map(([l,v])=>(
            <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",fontSize:12,color:"var(--tx3)",fontFamily:"var(--mo)"}}>
              <span>{l}</span><span style={{color:"var(--tx)",fontWeight:600}}>{v}</span>
            </div>
          ))}
        </div>
        <div style={{background:"var(--okl)",border:"1px solid var(--okb)",borderRadius:8,padding:"10px 14px",marginBottom:16,fontSize:12.5,color:"var(--ok)",lineHeight:1.7,fontFamily:"var(--mo)"}}>
          P1 SLA: 60 min | Your time: {mm}:{ss} {elapsed<3600?"✓ WITHIN SLA":"✗ SLA BREACHED"}
        </div>
        <button onClick={onBack} style={{width:"100%",background:"var(--ac)",color:"#fff",padding:"13px",borderRadius:9,fontSize:14,fontWeight:600,border:"none",cursor:"pointer"}}>
          Back to SOC Dashboard
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// COACH POPUP — the guided instruction overlay per step
// ─────────────────────────────────────────────────────────────────────────────

function CoachPopup({step,onClose,onHint,hintUsed,stepsDone,totalSteps}){
  const pc=phaseColor(step.phase);
  const [showHint,setShowHint]=useState(hintUsed);
  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",backdropFilter:"blur(4px)",zIndex:500,display:"flex",alignItems:"flex-end",justifyContent:"center",padding:"0 0 80px"}}>
      <div style={{background:"var(--bg2)",border:"1px solid "+pc+"60",borderRadius:16,padding:24,maxWidth:560,width:"100%",margin:"0 16px",boxShadow:"0 0 40px "+pc+"20",animation:"fadeUp 0.3s ease"}}>
        {/* header */}
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:16}}>
          <div style={{width:36,height:36,borderRadius:"50%",background:pc+"20",border:"2px solid "+pc+"60",display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,flexShrink:0}}>{step.toolIcon}</div>
          <div style={{flex:1}}>
            <div style={{fontSize:10,fontWeight:700,color:pc,letterSpacing:"0.12em",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:2}}>{step.phase} — Step {step.id+1} of {totalSteps}</div>
            <div style={{fontSize:16,fontWeight:700,color:"var(--tx)",lineHeight:1.2}}>{step.title}</div>
          </div>
          <div style={{background:pc+"20",border:"1px solid "+pc+"40",borderRadius:6,padding:"4px 10px",textAlign:"center",flexShrink:0}}>
            <div style={{fontSize:14,fontWeight:800,color:pc,fontFamily:"var(--mo)"}}>+{step.xp}</div>
            <div style={{fontSize:8,color:pc,fontFamily:"var(--mo)"}}>XP</div>
          </div>
        </div>

        {/* progress track */}
        <div style={{display:"flex",gap:3,marginBottom:14}}>
          {Array.from({length:totalSteps}).map((_,i)=>(
            <div key={i} style={{flex:1,height:3,borderRadius:2,background:i<stepsDone?"var(--ac)":i===step.id?pc+"80":"var(--bg4)",transition:"background 0.3s"}}/>
          ))}
        </div>

        {/* tool badge */}
        <div style={{display:"inline-flex",alignItems:"center",gap:6,background:"var(--bg4)",border:"1px solid var(--bd)",borderRadius:6,padding:"4px 10px",marginBottom:12}}>
          <span style={{fontSize:10,color:"var(--tx3)",fontFamily:"var(--mo)"}}>🛠</span>
          <span style={{fontSize:10,fontWeight:700,color:"var(--tx2)",fontFamily:"var(--mo)",letterSpacing:0.3}}>{step.tool}</span>
        </div>

        {/* instruction */}
        <div style={{background:"var(--acl)",border:"1px solid var(--acb)",borderRadius:10,padding:"12px 14px",marginBottom:12}}>
          <div style={{fontSize:9,fontWeight:700,color:"var(--ac)",letterSpacing:"0.12em",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>Your Task</div>
          <div style={{fontSize:13.5,color:"var(--tx2)",lineHeight:1.7}}>{step.instruction}</div>
        </div>

        {/* hint */}
        {!showHint&&(
          <button onClick={()=>{setShowHint(true);onHint();}} style={{background:"var(--bg3)",border:"1px solid var(--warnb)",color:"var(--warn)",padding:"8px 14px",borderRadius:8,fontSize:12.5,cursor:"pointer",marginBottom:12,width:"100%",textAlign:"left",display:"flex",alignItems:"center",gap:8}}>
            <span>💡</span><span>Analyst tip (−15 XP penalty)</span>
          </button>
        )}
        {showHint&&(
          <div style={{background:"rgba(245,158,11,0.08)",border:"1px solid var(--warnb)",borderRadius:8,padding:"10px 14px",marginBottom:12}}>
            <div style={{fontSize:9,fontWeight:700,color:"var(--warn)",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:5,textTransform:"uppercase"}}>Analyst Tip</div>
            <div style={{fontSize:13,color:"#fcd34d",lineHeight:1.7}}>{step.analyst_note}</div>
          </div>
        )}

        <button onClick={onClose} style={{width:"100%",background:pc,color:"#fff",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px "+pc+"40"}}>
          Got it — Show me the evidence →
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ACTION CONFIRMATION OVERLAY
// ─────────────────────────────────────────────────────────────────────────────

function ActionOverlay({step,onConfirm,isRunning,isDone,xpBurst}){
  const pc=phaseColor(step.phase);
  return(
    <div style={{position:"fixed",bottom:0,left:0,right:0,background:"var(--bg2)",borderTop:"1px solid "+pc+"40",padding:"16px 20px",zIndex:400,boxShadow:"0 -8px 32px rgba(0,0,0,0.5)"}}>
      {isDone?(
        <div style={{animation:"fadeUp 0.3s ease"}}>
          <div style={{background:"var(--okl)",border:"1px solid var(--okb)",borderRadius:10,padding:"12px 16px",marginBottom:10}}>
            <div style={{fontSize:10,fontWeight:700,color:"var(--ok)",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>✓ Action Confirmed</div>
            <div style={{fontSize:12.5,color:"var(--ok)",lineHeight:1.75,whiteSpace:"pre-line",fontFamily:"var(--mo)"}}>{step.action_result}</div>
          </div>
          <button onClick={onConfirm} style={{width:"100%",background:"var(--ac)",color:"#fff",padding:"13px",borderRadius:9,fontSize:14,fontWeight:700,border:"none",cursor:"pointer"}}>
            {xpBurst?"Next Step →":"Continue →"}
          </button>
        </div>
      ):isRunning?(
        <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:12,padding:"10px",color:"var(--tx3)",fontFamily:"var(--mo)",fontSize:13}}>
          <div style={{width:16,height:16,border:"2px solid var(--bd2)",borderTop:"2px solid "+pc,borderRadius:"50%",animation:"spin 0.7s linear infinite"}}/>
          Executing action...
        </div>
      ):(
        <div>
          <div style={{fontSize:11,color:"var(--tx3)",marginBottom:8,fontFamily:"var(--mo)"}}>
            <span style={{color:pc,fontWeight:700}}>{step.tool}</span> — {step.phase}
          </div>
          <button onClick={onConfirm} style={{width:"100%",background:pc,color:"#fff",padding:"14px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",gap:8,boxShadow:"0 4px 16px "+pc+"50"}}>
            <span style={{fontSize:18}}>{step.toolIcon}</span>{step.action_label}
          </button>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TOOL: BLUETRACE SIEM
// ─────────────────────────────────────────────────────────────────────────────

function BlueTraceSIEM({inc,activeStep}){
  const [tab,setTab]=useState("alerts");
  const [sel,setSel]=useState(inc.siem.alerts[0].id);
  const selAlert=inc.siem.alerts.find(a=>a.id===sel);
  const stepTool=activeStep?.tool==="BlueTrace SIEM";

  return(
    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",background:"var(--bg)"}}>
      {/* SIEM topbar */}
      <div style={{background:"#0a0e1a",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:42,display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:7}}>
          <div style={{width:20,height:20,borderRadius:4,background:"linear-gradient(135deg,#3b82f6,#1d4ed8)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:9,fontWeight:800,color:"#fff",fontFamily:"var(--mo)"}}>BT</div>
          <span style={{fontSize:12,fontWeight:700,color:"#60a5fa",fontFamily:"var(--mo)",letterSpacing:0.5}}>BlueTrace SIEM</span>
          <span style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)"}}>v4.2.1</span>
        </div>
        <div style={{flex:1,background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:5,padding:"4px 10px",display:"flex",alignItems:"center",gap:6}}>
          <span style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)"}}>🔍</span>
          <span style={{fontSize:11,color:"var(--tx4)",fontFamily:"var(--mo)"}}>index=corp_events host={inc.host} | head 100</span>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <div style={{display:"flex",alignItems:"center",gap:5}}>
            <Dot color="#22c55e" pulse/>
            <span style={{fontSize:9.5,color:"var(--tx3)",fontFamily:"var(--mo)"}}>LIVE</span>
          </div>
          <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)"}}>Corp · Primary Cluster</div>
        </div>
      </div>

      {/* tabs */}
      <div className="tool-row" style={{background:"var(--bg2)"}}>
        {[["alerts","Alert Queue"],["correlation","Correlation Rule"],["raw","Raw Search"],["timeline","Timeline"]].map(([id,label])=>(
          <button key={id} onClick={()=>setTab(id)} className={"tool-tab"+(tab===id?" on":"")}>{label}</button>
        ))}
        <div style={{flex:1}}/>
        {stepTool&&<div style={{padding:"0 12px",display:"flex",alignItems:"center"}}><Badge color="blue">ACTIVE TOOL</Badge></div>}
      </div>

      <div style={{flex:1,overflow:"auto",padding:"14px",display:"flex",flexDirection:"column",gap:10}}>

        {tab==="alerts"&&(
          <>
            {/* incident banner */}
            <div style={{background:"var(--critl)",border:"1px solid rgba(220,38,38,0.4)",borderRadius:8,padding:"10px 14px",display:"flex",gap:12,alignItems:"center"}}>
              <Dot color="#dc2626" pulse/>
              <div style={{flex:1}}>
                <div style={{fontSize:11,fontWeight:700,color:"#fca5a5",fontFamily:"var(--mo)",marginBottom:2}}>{inc.id} — {inc.title}</div>
                <div style={{fontSize:10.5,color:"#f87171",fontFamily:"var(--mo)"}}>Risk Score: <strong>{inc.siem.risk_score}/100</strong> · Rule: {inc.siem.correlation_rule} · Fired: {inc.siem.fired_at}</div>
              </div>
              <SevBadge s="Critical"/>
            </div>

            {/* alert table */}
            <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,overflow:"hidden"}}>
              <div style={{display:"grid",gridTemplateColumns:"70px 1fr 90px 80px 55px",background:"var(--bg3)",padding:"6px 12px",borderBottom:"1px solid var(--bd)"}}>
                {["TIME","ALERT NAME","RULE","SOURCE","SEV"].map(h=>(
                  <span key={h} style={{fontSize:8.5,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em"}}>{h}</span>
                ))}
              </div>
              {inc.siem.alerts.map((a,i)=>(
                <div key={a.id} className={"clickrow"+(sel===a.id?" sel":"")} onClick={()=>setSel(a.id)}
                  style={{display:"grid",gridTemplateColumns:"70px 1fr 90px 80px 55px",padding:"7px 12px",borderBottom:i<inc.siem.alerts.length-1?"1px solid var(--bd)":"none",alignItems:"center",borderLeft:"2px solid "+(sel===a.id?"var(--ac)":"transparent")}}>
                  <span style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{a.time}</span>
                  <span style={{fontSize:12,color:sel===a.id?"var(--tx)":"var(--tx2)",fontWeight:sel===a.id?600:400,paddingRight:8}}>{a.msg.slice(0,52)+(a.msg.length>52?"...":"")}</span>
                  <span style={{fontSize:9.5,color:"var(--ac)",fontFamily:"var(--mo)"}}>{a.rule.slice(0,14)}</span>
                  <span style={{fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{a.src}</span>
                  <SevBadge s={a.sev}/>
                </div>
              ))}
            </div>

            {/* selected alert detail */}
            {selAlert&&(
              <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px 14px",animation:"slideIn 0.2s ease"}}>
                <div style={{fontSize:9,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:8,letterSpacing:"0.1em",textTransform:"uppercase"}}>Alert Detail — {selAlert.id}</div>
                <div style={{fontSize:12.5,color:"var(--tx2)",lineHeight:1.75,fontFamily:"var(--mo)",marginBottom:10}}>{selAlert.msg}</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                  <Badge color="gray">Rule: {selAlert.rule}</Badge>
                  <Badge color="blue">Source: {selAlert.src}</Badge>
                  <Badge color="gray">Host: {inc.host}</Badge>
                  <Badge color="gray">User: {inc.user}</Badge>
                </div>
              </div>
            )}
          </>
        )}

        {tab==="correlation"&&(
          <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,overflow:"hidden"}}>
            <div style={{padding:"10px 14px",borderBottom:"1px solid var(--bd)",background:"var(--bg3)"}}>
              <div style={{fontSize:11,fontWeight:700,color:"var(--tx2)",fontFamily:"var(--mo)"}}>{inc.siem.correlation_rule}</div>
            </div>
            <div style={{padding:"14px"}}>
              <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:8,letterSpacing:"0.1em",textTransform:"uppercase"}}>Matched Conditions</div>
              {[
                ["Condition 1","EDR alert: OUTBOUND_C2_BEACON fired on same host","MATCH ✓"],
                ["Condition 2","EDR alert: LSASS_MEMORY_ACCESS fired within 5 min","MATCH ✓"],
                ["Condition 3","Email GW: macro attachment delivered to same user","MATCH ✓"],
                ["Condition 4","Risk score > 90 on correlated host","MATCH ✓ (97)"],
              ].map(([k,v,r])=>(
                <div key={k} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 10px",marginBottom:4,background:"var(--bg3)",borderRadius:5,border:"1px solid var(--bd)"}}>
                  <div>
                    <span style={{fontSize:10,fontWeight:700,color:"var(--tx3)",fontFamily:"var(--mo)",marginRight:8}}>{k}</span>
                    <span style={{fontSize:12,color:"var(--tx2)"}}>{v}</span>
                  </div>
                  <span style={{fontSize:10,fontWeight:700,color:"var(--ok)",fontFamily:"var(--mo)"}}>{r}</span>
                </div>
              ))}
              <div style={{marginTop:12,padding:"10px 12px",background:"var(--critl)",border:"1px solid rgba(220,38,38,0.3)",borderRadius:6}}>
                <span style={{fontSize:11,fontWeight:700,color:"#fca5a5",fontFamily:"var(--mo)"}}>FINAL SCORE: 97/100 — Auto-promoted to CRITICAL</span>
              </div>
            </div>
          </div>
        )}

        {tab==="raw"&&(
          <div>
            <div style={{background:"#0a0e1a",border:"1px solid var(--bd)",borderRadius:8,overflow:"hidden"}}>
              <div style={{padding:"8px 12px",borderBottom:"1px solid var(--bd)",fontSize:10,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em"}}>SEARCH — Last 24h — Corp Index</div>
              <pre style={{padding:"12px",fontSize:11.5,color:"#93c5fd",fontFamily:"var(--mo)",lineHeight:1.8,overflow:"auto",whiteSpace:"pre-wrap"}}>{inc.siem.raw_search}</pre>
            </div>
            <div style={{marginTop:10,background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px"}}>
              <div style={{fontSize:10,fontWeight:700,color:"var(--ok)",fontFamily:"var(--mo)",marginBottom:8}}>RESULTS — 1 host matched</div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 80px 1fr",background:"var(--bg3)",padding:"5px 10px",borderRadius:4,marginBottom:4,fontSize:9,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)"}}>
                <span>HOST</span><span>MAX_RISK</span><span>RULES</span>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 80px 1fr",padding:"6px 10px",background:"rgba(220,38,38,0.06)",border:"1px solid rgba(220,38,38,0.2)",borderRadius:4,fontSize:11.5,fontFamily:"var(--mo)"}}>
                <span style={{color:"var(--err)"}}>{inc.host}</span>
                <span style={{color:"var(--err)",fontWeight:700}}>97</span>
                <span style={{color:"var(--tx3)",fontSize:10}}>OUTBOUND_C2_BEACON, LSASS_MEMORY_ACCESS, +4</span>
              </div>
            </div>
          </div>
        )}

        {tab==="timeline"&&(
          <div>
            {inc.edr.timeline.map((ev,i)=>{
              const c=ev.sev==="crit"?"#ef4444":ev.sev==="high"?"#f97316":ev.sev==="med"?"#eab308":"#6b7280";
              return(
                <div key={i} style={{display:"flex",gap:10,marginBottom:10,position:"relative",paddingLeft:20}}>
                  <div style={{position:"absolute",left:0,top:4,width:10,height:10,borderRadius:"50%",background:c,boxShadow:"0 0 6px "+c+"60"}}/>
                  {i<inc.edr.timeline.length-1&&<div style={{position:"absolute",left:4,top:14,bottom:-10,width:2,background:"var(--bd)",borderRadius:1}}/>}
                  <div style={{flex:1}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}>
                      <span style={{fontSize:10,fontFamily:"var(--mo)",color:"var(--tx4)"}}>{ev.time}</span>
                      <span style={{fontSize:9,fontWeight:700,padding:"0 5px",borderRadius:3,background:"var(--acl)",color:"var(--ac)",fontFamily:"var(--mo)"}}>{ev.src}</span>
                    </div>
                    <div style={{fontSize:12.5,color:ev.sev==="crit"?"#fca5a5":ev.sev==="high"?"#fdba74":"var(--tx2)",lineHeight:1.5}}>{ev.event}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TOOL: SENTINEL EDR
// ─────────────────────────────────────────────────────────────────────────────

function SentinelEDR({inc,activeStep,isContained}){
  const [tab,setTab]=useState("process");
  const stepTool=activeStep?.tool==="SentinelEDR";

  return(
    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",background:"var(--bg)"}}>
      <div style={{background:"#0d0f1a",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:42,display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:7}}>
          <div style={{width:20,height:20,borderRadius:4,background:"linear-gradient(135deg,#dc2626,#991b1b)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:9,fontWeight:800,color:"#fff",fontFamily:"var(--mo)"}}>SE</div>
          <span style={{fontSize:12,fontWeight:700,color:"#f87171",fontFamily:"var(--mo)",letterSpacing:0.5}}>SentinelEDR</span>
        </div>
        <div style={{flex:1}}/>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <div style={{background:isContained?"rgba(34,197,94,0.15)":"rgba(239,68,68,0.12)",border:"1px solid "+(isContained?"rgba(34,197,94,0.4)":"rgba(239,68,68,0.35)"),borderRadius:5,padding:"3px 9px",fontSize:9.5,fontFamily:"var(--mo)",fontWeight:700,color:isContained?"#86efac":"#fca5a5"}}>
            {isContained?"CONTAINED":"ACTIVE THREAT"}
          </div>
          <span style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)"}}>Sensor: {inc.edr.sensor_id}</span>
          {stepTool&&<Badge color="red">ACTIVE TOOL</Badge>}
        </div>
      </div>

      <div className="tool-row" style={{background:"var(--bg2)"}}>
        {[["process","Process Tree"],["network","Network"],["files","File Events"],["contain","Containment"]].map(([id,label])=>(
          <button key={id} onClick={()=>setTab(id)} className={"tool-tab"+(tab===id?" on":"")}>{label}</button>
        ))}
      </div>

      <div style={{flex:1,overflow:"auto",padding:"14px"}}>

        {tab==="process"&&(
          <div>
            <div style={{background:"rgba(239,68,68,0.06)",border:"1px solid rgba(239,68,68,0.2)",borderRadius:7,padding:"8px 12px",marginBottom:12,fontSize:11,color:"#fca5a5",fontFamily:"var(--mo)"}}>
              ⚠ Policy: {inc.edr.prevention_policy} — {inc.edr.policy_note}
            </div>
            {inc.edr.process_tree.map((p,i)=>{
              const indent=p.depth*20;
              return(
                <div key={p.pid} style={{marginBottom:6,paddingLeft:indent}}>
                  <div style={{display:"flex",alignItems:"flex-start",gap:6}}>
                    {p.depth>0&&<span style={{color:"var(--bd2)",flexShrink:0,paddingTop:3,fontFamily:"var(--mo)",fontSize:12,lineHeight:1}}>└─</span>}
                    <div style={{background:p.bad?"rgba(239,68,68,0.06)":"var(--bg2)",border:"1px solid "+(p.bad?"rgba(239,68,68,0.3)":"var(--bd)"),borderRadius:7,padding:"8px 12px",flex:1}}>
                      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:4}}>
                        <div style={{display:"flex",alignItems:"center",gap:7}}>
                          <span style={{fontSize:12,fontWeight:700,color:p.bad?"#fca5a5":"var(--tx)",fontFamily:"var(--mo)"}}>{p.name}</span>
                          {p.bad&&<span style={{background:"rgba(239,68,68,0.15)",color:"#f87171",border:"1px solid rgba(239,68,68,0.3)",padding:"0 5px",borderRadius:3,fontSize:8.5,fontWeight:700}}>MALICIOUS</span>}
                          {p.score>0&&<span style={{background:p.score>80?"rgba(239,68,68,0.12)":p.score>50?"rgba(245,158,11,0.1)":"var(--bg4)",color:p.score>80?"#fca5a5":p.score>50?"var(--warn)":"var(--tx4)",border:"1px solid "+(p.score>80?"rgba(239,68,68,0.3)":p.score>50?"var(--warnb)":"var(--bd)"),padding:"0 5px",borderRadius:3,fontSize:8.5,fontWeight:700,fontFamily:"var(--mo)"}}>
                            Score:{p.score}
                          </span>}
                        </div>
                        <span style={{fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{p.time}</span>
                      </div>
                      <div style={{fontSize:10,color:"var(--tx3)",lineHeight:1.55,wordBreak:"break-all",fontFamily:"var(--mo)",marginBottom:4}}>{p.cmd.length>80?p.cmd.slice(0,80)+"...":p.cmd}</div>
                      <div style={{display:"flex",gap:10,fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)",flexWrap:"wrap"}}>
                        <span>PID: {p.pid}</span>
                        <span>PPID: {p.ppid}</span>
                        <span>User: {p.user.split("\\").pop()}</span>
                        {p.sha256&&<span style={{color:"#f87171"}}>SHA256: {p.sha256}...</span>}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {tab==="network"&&(
          <div>
            {isContained&&<div style={{background:"var(--okl)",border:"1px solid var(--okb)",borderRadius:7,padding:"8px 12px",marginBottom:10,fontSize:11,color:"var(--ok)",fontFamily:"var(--mo)",fontWeight:600}}>HOST CONTAINED — All external network traffic blocked</div>}
            <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,overflow:"hidden"}}>
              <div style={{display:"grid",gridTemplateColumns:"72px 1fr 1fr 70px 100px",background:"var(--bg3)",padding:"6px 12px",borderBottom:"1px solid var(--bd)"}}>
                {["TIME","SOURCE","DESTINATION","PROTO","STATE"].map(h=>(
                  <span key={h} style={{fontSize:8.5,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.08em"}}>{h}</span>
                ))}
              </div>
              {inc.edr.network.map((c,i)=>(
                <div key={i} style={{display:"grid",gridTemplateColumns:"72px 1fr 1fr 70px 100px",padding:"7px 12px",borderBottom:i<inc.edr.network.length-1?"1px solid var(--bd)":"none",background:c.bad?"rgba(239,68,68,0.04)":"transparent",alignItems:"center"}}>
                  <span style={{fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{c.time}</span>
                  <span style={{fontSize:10.5,color:"var(--tx3)",fontFamily:"var(--mo)"}}>{c.src}</span>
                  <span style={{fontSize:10.5,color:c.bad?"#fca5a5":"var(--tx3)",fontFamily:"var(--mo)",fontWeight:c.bad?600:400}}>{c.dst}</span>
                  <span style={{fontSize:10.5,color:"#60a5fa",fontFamily:"var(--mo)",fontWeight:600}}>{c.proto}</span>
                  <span style={{fontSize:10,fontWeight:700,padding:"1px 6px",borderRadius:3,fontFamily:"var(--mo)",background:(isContained&&c.state==="ESTABLISHED")?"var(--bg4)":c.state==="ESTABLISHED"?"rgba(239,68,68,0.12)":"var(--bg4)",color:(isContained&&c.state==="ESTABLISHED")?"var(--tx4)":c.state==="ESTABLISHED"?"#fca5a5":"var(--tx4)"}}>
                    {isContained&&c.state==="ESTABLISHED"?"TERMINATED":c.state}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab==="files"&&(
          <div>
            {inc.edr.file_events.map((f,i)=>(
              <div key={i} style={{background:f.signed===false?"rgba(239,68,68,0.05)":"var(--bg2)",border:"1px solid "+(f.signed===false?"rgba(239,68,68,0.25)":"var(--bd)"),borderRadius:8,padding:"10px 14px",marginBottom:8}}>
                <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:5}}>
                  <span style={{fontSize:10,fontWeight:700,padding:"1px 6px",borderRadius:3,background:f.action==="CREATE"?"rgba(239,68,68,0.1)":"var(--bg4)",color:f.action==="CREATE"?"#f87171":"var(--tx4)",fontFamily:"var(--mo)"}}>{f.action}</span>
                  <span style={{fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{f.time}</span>
                  <span style={{fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{f.size}</span>
                  {!f.signed&&<span style={{fontSize:9,fontWeight:700,color:"#fca5a5",fontFamily:"var(--mo)"}}>UNSIGNED</span>}
                </div>
                <div style={{fontSize:11,color:f.signed===false?"#fca5a5":"var(--tx2)",fontFamily:"var(--mo)",wordBreak:"break-all",lineHeight:1.5}}>{f.path}</div>
                {f.sha256&&<div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",marginTop:4}}>SHA256: {f.sha256}</div>}
              </div>
            ))}
          </div>
        )}

        {tab==="contain"&&(
          <div>
            <div style={{background:isContained?"var(--okl)":"rgba(239,68,68,0.06)",border:"1px solid "+(isContained?"var(--okb)":"rgba(239,68,68,0.3)"),borderRadius:10,padding:"16px",marginBottom:14,textAlign:"center"}}>
              <div style={{fontSize:28,marginBottom:6}}>{isContained?"🔒":"⚠️"}</div>
              <div style={{fontSize:15,fontWeight:700,color:isContained?"var(--ok)":"#fca5a5",marginBottom:4}}>{isContained?"Network Containment ACTIVE":"Host NOT Contained"}</div>
              <div style={{fontSize:12,color:"var(--tx3)"}}>{isContained?"All external traffic blocked. Sensor connected. Forensics available.":"Host is live on network. C2 sessions active."}</div>
            </div>
            {[["Hostname",inc.host],["Sensor ID",inc.edr.sensor_id],["Sensor Version",inc.edr.sensor_version],["Policy",inc.edr.prevention_policy],["OS","Windows 10 Enterprise 22H2"],["Last Seen","08:19:01 UTC (live)"]].map(([k,v])=>(
              <div key={k} style={{display:"flex",justifyContent:"space-between",padding:"7px 12px",borderBottom:"1px solid var(--bd)",fontSize:12}}>
                <span style={{color:"var(--tx4)",fontFamily:"var(--mo)"}}>{k}</span>
                <span style={{color:"var(--tx2)",fontFamily:"var(--mo)",fontWeight:500}}>{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TOOL: THREATLENS
// ─────────────────────────────────────────────────────────────────────────────

function ThreatLens({inc,activeStep}){
  const [selIdx,setSelIdx]=useState(0);
  const stepTool=activeStep?.tool==="ThreatLens";
  const item=inc.threatintel.lookups[selIdx];

  return(
    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",background:"var(--bg)"}}>
      <div style={{background:"#0a0d18",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:42,display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:7}}>
          <div style={{width:20,height:20,borderRadius:4,background:"linear-gradient(135deg,#7c3aed,#5b21b6)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:9,fontWeight:800,color:"#fff",fontFamily:"var(--mo)"}}>TL</div>
          <span style={{fontSize:12,fontWeight:700,color:"#c4b5fd",fontFamily:"var(--mo)",letterSpacing:0.5}}>ThreatLens</span>
          <span style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)"}}>IOC Intelligence</span>
        </div>
        <div style={{flex:1}}/>
        {stepTool&&<Badge color="blue">ACTIVE TOOL</Badge>}
      </div>

      <div style={{flex:1,overflow:"auto",padding:"14px",display:"flex",gap:12}}>
        {/* IOC selector */}
        <div style={{width:180,flexShrink:0,display:"flex",flexDirection:"column",gap:6}}>
          <div style={{fontSize:9,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:4}}>IOCs from Incident</div>
          {inc.threatintel.lookups.map((item,i)=>(
            <div key={i} onClick={()=>setSelIdx(i)} style={{background:selIdx===i?"var(--acl)":"var(--bg2)",border:"1px solid "+(selIdx===i?"var(--acb)":"var(--bd)"),borderRadius:7,padding:"8px 10px",cursor:"pointer",transition:"all 0.13s"}}>
              <div style={{fontSize:9,fontWeight:700,color:selIdx===i?"var(--ac)":"var(--tx4)",fontFamily:"var(--mo)",marginBottom:3,textTransform:"uppercase"}}>{item.type}</div>
              <div style={{fontSize:10.5,color:"var(--tx2)",fontFamily:"var(--mo)",wordBreak:"break-all",lineHeight:1.4}}>{item.value}</div>
            </div>
          ))}
        </div>

        {/* IOC detail */}
        <div style={{flex:1,display:"flex",flexDirection:"column",gap:10,minWidth:0}}>
          {/* verdict */}
          <div style={{background:item.verdictColor+"15",border:"1px solid "+item.verdictColor+"40",borderRadius:9,padding:"12px 16px",display:"flex",gap:12,alignItems:"center"}}>
            <div style={{fontSize:26}}>🔴</div>
            <div>
              <div style={{fontSize:14,fontWeight:700,color:item.verdictColor,marginBottom:3}}>{item.verdict}</div>
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>{item.categories.map(c=><Badge key={c} color="red">{c}</Badge>)}</div>
            </div>
          </div>

          {/* scores */}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
            <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px"}}>
              <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase",letterSpacing:"0.1em"}}>Detection</div>
              <div style={{fontSize:14,fontWeight:700,color:"#ef4444",fontFamily:"var(--mo)",marginBottom:2}}>{item.vt_score}</div>
              <div style={{fontSize:10,color:"var(--tx4)"}}>VirusTotal</div>
            </div>
            <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px"}}>
              <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase",letterSpacing:"0.1em"}}>Abuse Score</div>
              <div style={{fontSize:14,fontWeight:700,color:item.abuse_score>80?"#ef4444":item.abuse_score>50?"var(--warn)":"var(--ok)",fontFamily:"var(--mo)",marginBottom:2}}>{item.abuse_score}/100</div>
              <div style={{fontSize:10,color:"var(--tx4)"}}>AbuseIPDB</div>
            </div>
          </div>

          {/* metadata */}
          <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,overflow:"hidden"}}>
            {[
              item.country&&["Country / ASN",item.country+" — "+item.asn],
              ["First Seen",item.first_seen],
              ["Last Seen",item.last_seen],
            ].filter(Boolean).map(([k,v])=>(
              <div key={k} style={{display:"flex",justifyContent:"space-between",padding:"7px 12px",borderBottom:"1px solid var(--bd)",fontSize:12}}>
                <span style={{color:"var(--tx4)",fontFamily:"var(--mo)"}}>{k}</span>
                <span style={{color:"var(--tx2)",fontFamily:"var(--mo)"}}>{v}</span>
              </div>
            ))}
          </div>

          {/* campaigns */}
          <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px 14px"}}>
            <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase",letterSpacing:"0.1em"}}>Associated Campaigns</div>
            {item.campaigns.map((c,i)=>(
              <div key={i} style={{display:"flex",gap:8,alignItems:"flex-start",marginBottom:5}}>
                <span style={{color:"var(--err)",fontSize:10,marginTop:2,flexShrink:0}}>▸</span>
                <span style={{fontSize:12,color:"var(--tx2)",lineHeight:1.5}}>{c}</span>
              </div>
            ))}
          </div>

          {/* passive DNS */}
          {item.passive_dns.length>0&&(
            <div style={{background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"12px 14px"}}>
              <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase",letterSpacing:"0.1em"}}>Passive DNS</div>
              {item.passive_dns.map((d,i)=>(
                <div key={i} style={{fontSize:11.5,color:"var(--err)",fontFamily:"var(--mo)",marginBottom:4,padding:"4px 8px",background:"var(--bg3)",borderRadius:4}}>{d}</div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TOOL: INCIDENT DESK
// ─────────────────────────────────────────────────────────────────────────────

function IncidentDesk({inc,activeStep,stepsDone,analyst,elapsed}){
  const [tab,setTab]=useState("ticket");
  const [report,setReport]=useState({exec:"",vector:"",blast:"",actions:"",pending:"",rec:""});
  const stepTool=activeStep?.tool==="IncidentDesk";
  const mm=String(Math.floor(elapsed/60)).padStart(2,"0");
  const ss=String(elapsed%60).padStart(2,"0");
  const slaLeft=Math.max(0,inc.desk.sla_minutes*60-elapsed);
  const slaMinLeft=Math.floor(slaLeft/60);
  const slaSec=slaLeft%60;
  const slaOk=slaLeft>0;

  return(
    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",background:"var(--bg)"}}>
      <div style={{background:"#0e1219",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:42,display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:7}}>
          <div style={{width:20,height:20,borderRadius:4,background:"linear-gradient(135deg,#059669,#047857)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:9,fontWeight:800,color:"#fff",fontFamily:"var(--mo)"}}>ID</div>
          <span style={{fontSize:12,fontWeight:700,color:"#34d399",fontFamily:"var(--mo)",letterSpacing:0.5}}>IncidentDesk</span>
        </div>
        <div style={{flex:1}}/>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <div style={{background:slaOk?"rgba(34,197,94,0.1)":"rgba(239,68,68,0.1)",border:"1px solid "+(slaOk?"rgba(34,197,94,0.3)":"rgba(239,68,68,0.3)"),borderRadius:5,padding:"2px 9px",fontSize:10,fontFamily:"var(--mo)",fontWeight:700,color:slaOk?"#86efac":"#fca5a5"}}>
            SLA: {slaMinLeft}:{String(slaSec).padStart(2,"0")} {slaOk?"remaining":"BREACHED"}
          </div>
          {stepTool&&<Badge color="green">ACTIVE TOOL</Badge>}
        </div>
      </div>

      <div className="tool-row" style={{background:"var(--bg2)"}}>
        {[["ticket","Ticket"],["timeline","Audit Log"],["report","IR Report"],["escalation","Escalation"]].map(([id,label])=>(
          <button key={id} onClick={()=>setTab(id)} className={"tool-tab"+(tab===id?" on":"")}>{label}</button>
        ))}
      </div>

      <div style={{flex:1,overflow:"auto",padding:"14px"}}>

        {tab==="ticket"&&(
          <div style={{display:"flex",flexDirection:"column",gap:10}}>
            <div style={{display:"flex",gap:10,alignItems:"flex-start"}}>
              <div style={{flex:1}}>
                <div style={{fontSize:11,fontWeight:600,color:"var(--tx4)",marginBottom:4,fontFamily:"var(--mo)"}}>TICKET ID</div>
                <div style={{fontSize:16,fontWeight:700,color:"var(--tx)",fontFamily:"var(--mo)"}}>{inc.desk.ticket_id}</div>
              </div>
              <SevBadge s={inc.severity}/>
              <Badge color={stepsDone>=inc.steps.length?"green":stepsDone>0?"amber":"red"}>
                {stepsDone>=inc.steps.length?"CLOSED":stepsDone>0?"IN PROGRESS":"NEW"}
              </Badge>
            </div>
            <div style={{fontSize:14,fontWeight:600,color:"var(--tx)",lineHeight:1.4,padding:"10px 0",borderBottom:"1px solid var(--bd)"}}>{inc.title}</div>

            {[["Priority",<Badge color="red">{inc.desk.priority}</Badge>],["Category",inc.desk.category],["Subcategory",inc.desk.subcategory],["Assignee",analyst.name+" ("+analyst.id+")"],["Host",inc.host],["User",inc.user],["Created",inc.created],["SLA",inc.desk.sla_minutes+" minutes (P1)"],["Escalation",inc.desk.escalation_path]].map(([k,v])=>(
              <div key={k} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 0",borderBottom:"1px solid var(--bd)",fontSize:12}}>
                <span style={{color:"var(--tx4)",fontFamily:"var(--mo)",minWidth:90}}>{k}</span>
                <span style={{color:"var(--tx2)",fontFamily:"var(--mo)",textAlign:"right",fontWeight:typeof v==="string"?400:500}}>{v}</span>
              </div>
            ))}

            <div>
              <div style={{fontSize:11,fontWeight:600,color:"var(--tx4)",marginBottom:6,fontFamily:"var(--mo)"}}>INCIDENT SUMMARY</div>
              <div style={{fontSize:12.5,color:"var(--tx2)",lineHeight:1.75,background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:7,padding:"10px 12px"}}>{inc.summary}</div>
            </div>

            <div>
              <div style={{fontSize:11,fontWeight:600,color:"var(--tx4)",marginBottom:6,fontFamily:"var(--mo)"}}>MITRE ATT&CK</div>
              <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>{inc.mitre.map(t=><Badge key={t} color="blue">{t}</Badge>)}</div>
            </div>
          </div>
        )}

        {tab==="timeline"&&(
          <div>
            <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:10,letterSpacing:"0.1em",textTransform:"uppercase"}}>Audit Log — Analyst Actions</div>
            {[
              {t:inc.created,action:"Incident created by BlueTrace SIEM correlation engine",by:"System"},
              stepsDone>=1&&{t:tsNow(5),action:"Classified TRUE POSITIVE — Incident opened",by:analyst.name},
              stepsDone>=2&&{t:tsNow(8),action:"Kill chain documented: Macro→PS→C2→LSASS",by:analyst.name},
              stepsDone>=3&&{t:tsNow(12),action:"IOCs enriched: IP/Hash/Domain — all MALICIOUS",by:analyst.name},
              stepsDone>=4&&{t:tsNow(15),action:"WS-CORP-FIN-044 Network Containment executed",by:analyst.name},
              stepsDone>=5&&{t:tsNow(20),action:"Blast radius confirmed: 1 host, 3 email recipients",by:analyst.name},
              stepsDone>=6&&{t:tsNow(31),action:"IR Report submitted — Incident CLOSED",by:analyst.name},
            ].filter(Boolean).map((ev,i)=>(
              <div key={i} style={{display:"flex",gap:10,marginBottom:8}}>
                <div style={{width:8,height:8,borderRadius:"50%",background:"var(--ac)",flexShrink:0,marginTop:4}}/>
                <div>
                  <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:2}}>{ev.t}</div>
                  <div style={{fontSize:12.5,color:"var(--tx2)",marginBottom:1}}>{ev.action}</div>
                  <div style={{fontSize:10,color:"var(--ac)",fontFamily:"var(--mo)"}}>{ev.by}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {tab==="report"&&(
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            <div style={{background:"rgba(59,130,246,0.08)",border:"1px solid var(--acb)",borderRadius:8,padding:"10px 14px",fontSize:12,color:"var(--ac)"}}>
              Complete the IR report below. This goes to the CISO, SOC lead, and your incident log.
            </div>
            {[
              {key:"exec",label:"Executive Summary (3 sentences max for CISO)",rows:3,ph:"What happened, what was taken, what you did. Non-technical, concise."},
              {key:"vector",label:"Attack Vector (technical)",rows:2,ph:"e.g. T1566.001 phishing email → T1059.001 PowerShell → T1071.001 C2..."},
              {key:"blast",label:"Blast Radius",rows:2,ph:"Hosts affected, users compromised, data exposed..."},
              {key:"actions",label:"Actions Taken",rows:3,ph:"Containment steps, IOC blocks, credential resets..."},
              {key:"pending",label:"Pending Items",rows:2,ph:"Reimage, GPO changes, awaiting items..."},
              {key:"rec",label:"Recommendations",rows:3,ph:"Root cause fix, policy changes, tool gaps..."},
            ].map(f=>(
              <div key={f.key}>
                <label style={{fontSize:11,fontWeight:600,color:"var(--tx3)",display:"block",marginBottom:5,fontFamily:"var(--mo)"}}>{f.label}</label>
                <textarea rows={f.rows} placeholder={f.ph} value={report[f.key]} onChange={e=>setReport(r=>({...r,[f.key]:e.target.value}))}
                  style={{width:"100%",resize:"vertical",lineHeight:1.6,fontSize:12.5,background:"var(--bg3)",border:"1px solid var(--bd)",color:"var(--tx)",borderRadius:6,padding:"8px 10px"}}/>
              </div>
            ))}
          </div>
        )}

        {tab==="escalation"&&(
          <div>
            <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:10,textTransform:"uppercase",letterSpacing:"0.1em"}}>Escalation Path</div>
            {inc.desk.escalation_path.split(" → ").map((t,i,arr)=>(
              <div key={i} style={{display:"flex",gap:10,alignItems:"center",marginBottom:i<arr.length-1?4:0}}>
                <div style={{width:28,height:28,borderRadius:"50%",background:i===0?"var(--acl)":"var(--bg3)",border:"1px solid "+(i===0?"var(--ac)":"var(--bd)"),display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:i===0?"var(--ac)":"var(--tx4)",flexShrink:0,fontFamily:"var(--mo)"}}>{i+1}</div>
                <div style={{flex:1,background:i===0?"var(--acl)":"var(--bg2)",border:"1px solid "+(i===0?"var(--acb)":"var(--bd)"),borderRadius:6,padding:"8px 12px",fontSize:12.5,color:i===0?"var(--ac)":"var(--tx3)",fontWeight:i===0?600:400}}>{t}</div>
              </div>
            ))}
            <div style={{marginTop:16,fontSize:11,color:"var(--tx4)",fontFamily:"var(--mo)"}}>Watchers: {inc.desk.watchers.join(" · ")}</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

function SOCDashboard({onAssign,onOpen,assigned,prog,analyst}){
  const inc=INCIDENTS["INC-2026-0441"];
  const [tick,setTick]=useState(0);
  useEffect(()=>{const t=setInterval(()=>setTick(s=>s+1),1000);return()=>clearInterval(t);},[]);
  const now=new Date("2026-05-28T08:00:00Z");
  now.setSeconds(now.getSeconds()+tick);
  const timeStr=now.toISOString().replace("T"," ").slice(0,19)+" UTC";

  return(
    <div className="soc-root" style={{background:"var(--bg)",minHeight:"100vh",display:"flex",flexDirection:"column"}}>
      {/* HEADER */}
      <div style={{background:"var(--bg2)",borderBottom:"1px solid var(--bd)",padding:"0 20px",height:52,display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0,boxShadow:"var(--sh)"}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:28,height:28,borderRadius:6,background:"linear-gradient(135deg,#3b82f6,#7c3aed)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:800,color:"#fff",fontFamily:"var(--mo)"}}>LBT</div>
          <div>
            <span style={{fontSize:14,fontWeight:700,color:"var(--tx)"}}>LEARN</span>
            <span style={{fontSize:14,fontWeight:700,color:"#60a5fa"}}>BLUETEAM</span>
            <span style={{fontSize:9,color:"var(--tx4)",marginLeft:8,fontFamily:"var(--mo)"}}>SOC Operations Center</span>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:14}}>
          <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{timeStr}</div>
          <div style={{display:"flex",alignItems:"center",gap:5}}>
            <Dot color="#22c55e" pulse/>
            <span style={{fontSize:10,color:"#86efac",fontFamily:"var(--mo)",fontWeight:600}}>SHIFT ACTIVE</span>
          </div>
          <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:7,padding:"5px 12px",display:"flex",alignItems:"center",gap:8}}>
            <div style={{width:24,height:24,borderRadius:"50%",background:"var(--acl)",border:"1px solid var(--acb)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:"var(--ac)",fontFamily:"var(--mo)"}}>L1</div>
            <div>
              <div style={{fontSize:11,fontWeight:600,color:"var(--tx)"}}>{analyst.name}</div>
              <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{analyst.tier} · {analyst.team}</div>
            </div>
          </div>
        </div>
      </div>

      <div style={{display:"flex",flex:1,overflow:"hidden"}}>
        {/* LEFT SIDEBAR */}
        <div style={{width:200,background:"var(--bg2)",borderRight:"1px solid var(--bd)",display:"flex",flexDirection:"column",flexShrink:0}}>
          <div style={{padding:"14px 14px 8px"}}>
            <div style={{fontSize:8.5,fontWeight:700,color:"var(--tx4)",letterSpacing:"0.14em",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:10}}>Navigation</div>
            {[["📊","Dashboard",true],["🔔","Alert Queue",false],["📁","My Cases",false],["🔍","Threat Hunt",false],["📈","Reports",false],["⚙️","Settings",false]].map(([ic,l,on])=>(
              <div key={l} style={{display:"flex",gap:8,alignItems:"center",padding:"7px 9px",borderRadius:6,marginBottom:2,background:on?"var(--acl)":"transparent",border:on?"1px solid var(--acb)":"1px solid transparent",cursor:"pointer"}}>
                <span style={{fontSize:13}}>{ic}</span>
                <span style={{fontSize:12,color:on?"var(--ac)":"var(--tx3)",fontWeight:on?600:400}}>{l}</span>
              </div>
            ))}
          </div>
          <div style={{padding:"14px",borderTop:"1px solid var(--bd)",marginTop:"auto"}}>
            <div style={{fontSize:8.5,fontWeight:700,color:"var(--tx4)",letterSpacing:"0.14em",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:8}}>Analyst XP</div>
            <div style={{fontSize:18,fontWeight:700,color:"var(--ac)",fontFamily:"var(--mo)",marginBottom:4}}>{prog.xp} XP</div>
            <div style={{fontSize:10,color:"var(--tx4)",marginBottom:6}}>Level {prog.level} — {prog.level<5?"Junior Analyst":prog.level<10?"SOC Analyst I":prog.level<15?"SOC Analyst II":"Threat Hunter"}</div>
            <div style={{height:4,background:"var(--bg4)",borderRadius:2,overflow:"hidden"}}>
              <div style={{height:"100%",width:Math.min(99,((prog.xp%500)/500)*100)+"%",background:"var(--ac)",borderRadius:2}}/>
            </div>
          </div>
        </div>

        {/* MAIN */}
        <div style={{flex:1,overflow:"auto",padding:"20px"}}>
          {/* shift greeting */}
          <div style={{marginBottom:20}}>
            <div style={{fontSize:11,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:3}}>Good morning, {analyst.name.split(" ")[0]} — Shift started 08:00 UTC</div>
            <div style={{fontSize:22,fontWeight:700,color:"var(--tx)"}}>SOC Operations Dashboard</div>
          </div>

          {/* severity counters */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:20}}>
            {[["CRITICAL","1","#dc2626","rgba(220,38,38,0.12)"],["HIGH","3","#ea580c","rgba(234,88,12,0.1)"],["MEDIUM","7","#ca8a04","rgba(202,138,4,0.1)"],["LOW","12","#16a34a","rgba(22,163,74,0.08)"]].map(([l,n,c,bg])=>(
              <div key={l} style={{background:bg,border:"1px solid "+c+"30",borderRadius:10,padding:"14px 16px",textAlign:"center",animation:l==="CRITICAL"?"glow 3s ease-in-out infinite":"none"}}>
                <div style={{fontSize:28,fontWeight:800,color:c,fontFamily:"var(--mo)",lineHeight:1,marginBottom:4}}>{n}</div>
                <div style={{fontSize:9,color:c,fontFamily:"var(--mo)",fontWeight:700,letterSpacing:"0.12em"}}>{l}</div>
              </div>
            ))}
          </div>

          {/* ACTIVE INCIDENT */}
          <div style={{marginBottom:14}}>
            <div style={{fontSize:10,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:8}}>My Cases — Assigned to Me</div>
            {/* My Cases — only assigned ones */}
            {assigned.includes("INC-2026-0441") ? (
              <div style={{background:"var(--bg2)",border:"1px solid rgba(220,38,38,0.4)",borderRadius:10,padding:"16px 18px",cursor:"pointer",boxShadow:"0 0 20px rgba(220,38,38,0.1)"}} onClick={()=>onOpen("INC-2026-0441")}>
                <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:10}}>
                  <div>
                    <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:3}}>{inc.id} · {inc.created}</div>
                    <div style={{fontSize:15,fontWeight:700,color:"var(--tx)",lineHeight:1.3}}>{inc.title}</div>
                  </div>
                  <div style={{display:"flex",gap:6,flexDirection:"column",alignItems:"flex-end"}}>
                    <SevBadge s={inc.severity}/>
                    <Badge color="amber">P1 · ASSIGNED</Badge>
                  </div>
                </div>
                <div style={{fontSize:12.5,color:"var(--tx3)",lineHeight:1.65,marginBottom:10}}>{inc.summary.slice(0,160)}...</div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
                  {inc.tags.map(t=><span key={t} className="tag">{t}</span>)}
                </div>
                <div style={{display:"flex",gap:10,alignItems:"center"}}>
                  <div style={{flex:1,height:3,background:"var(--bg4)",borderRadius:2}}/>
                  <span style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)"}}>0/6 steps</span>
                  <button onClick={(e)=>{e.stopPropagation();onOpen("INC-2026-0441");}} style={{background:"var(--ac)",color:"#fff",padding:"7px 16px",borderRadius:7,fontSize:12,fontWeight:700,border:"none",cursor:"pointer"}}>
                    Open Ticket →
                  </button>
                </div>
              </div>
            ) : (
              <div style={{background:"var(--bg3)",border:"1px dashed var(--bd)",borderRadius:10,padding:"24px",textAlign:"center",color:"var(--tx4)",fontSize:13}}>
                No cases assigned yet — assign from the queue below
              </div>
            )}
          </div>

          {/* alert queue — unassigned */}
          <div>
            <div style={{fontSize:10,fontWeight:700,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:8}}>Alert Queue — Unassigned ({assigned.includes("INC-2026-0441")?3:4} open)</div>
            {/* Real incident — INC-2026-0441 — only show if not yet assigned */}
            {!assigned.includes("INC-2026-0441")&&(
              <div style={{background:"var(--bg2)",border:"1px solid rgba(220,38,38,0.35)",borderRadius:10,padding:"14px 16px",marginBottom:8,animation:"glow 3s ease-in-out infinite"}}>
                <div style={{display:"flex",alignItems:"flex-start",gap:10,marginBottom:8}}>
                  <Dot color="#dc2626" pulse/>
                  <div style={{flex:1}}>
                    <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:2}}>{inc.id} · {inc.created} · {inc.host}</div>
                    <div style={{fontSize:13.5,fontWeight:700,color:"var(--tx)",lineHeight:1.3,marginBottom:4}}>{inc.title}</div>
                    <div style={{fontSize:12,color:"var(--tx3)",lineHeight:1.6,marginBottom:7}}>{inc.summary.slice(0,130)}...</div>
                    <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>{inc.tags.map(t=><span key={t} className="tag">{t}</span>)}</div>
                  </div>
                  <div style={{display:"flex",flexDirection:"column",gap:5,alignItems:"flex-end",flexShrink:0}}>
                    <SevBadge s="Critical"/>
                    <Badge color="red">UNASSIGNED</Badge>
                  </div>
                </div>
                <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
                  <button style={{background:"var(--bg3)",border:"1px solid var(--bd)",color:"var(--tx3)",padding:"6px 12px",borderRadius:6,fontSize:11,cursor:"pointer"}}>View Details</button>
                  <button onClick={()=>onAssign("INC-2026-0441")} style={{background:"var(--err)",color:"#fff",padding:"6px 16px",borderRadius:6,fontSize:11,fontWeight:700,border:"none",cursor:"pointer"}}>
                    ＋ Assign to Me
                  </button>
                </div>
              </div>
            )}
            {/* Other placeholder incidents */}
            {[
              {id:"INC-2026-0442",sev:"High",   title:"Suspicious PowerShell on Finance DC",host:"DC-CORP-FIN-01",time:tsNow(2)},
              {id:"INC-2026-0443",sev:"Medium",  title:"Impossible Travel — M365 Login",    host:"Azure AD",      time:tsNow(4)},
              {id:"INC-2026-0444",sev:"Medium",  title:"DNS Tunneling — HR Workstation",    host:"WS-CORP-HR-012",time:tsNow(7)},
            ].map(item=>(
              <div key={item.id} style={{display:"flex",gap:12,alignItems:"center",padding:"10px 14px",background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,marginBottom:6}}>
                <Dot color={item.sev==="High"?"#ea580c":"#ca8a04"} pulse={item.sev==="High"}/>
                <div style={{flex:1}}>
                  <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:2}}>{item.id} · {item.host}</div>
                  <div style={{fontSize:12.5,color:"var(--tx2)"}}>{item.title}</div>
                </div>
                <div style={{display:"flex",gap:7,alignItems:"center"}}>
                  <SevBadge s={item.sev}/>
                  <span style={{fontSize:9.5,color:"var(--tx4)",fontFamily:"var(--mo)"}}>{item.time.slice(11,16)}</span>
                  <button style={{fontSize:10,color:"var(--tx4)",background:"var(--bg3)",border:"1px solid var(--bd)",padding:"4px 10px",borderRadius:4,cursor:"pointer"}}>Assign</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC CONSOLE — main investigation view
// ─────────────────────────────────────────────────────────────────────────────

function SOCConsole({incId,prog,addXP,finishSim,onBack,analyst:analystProp}){
  const inc=INCIDENTS[incId];
  const [activeTool,setActiveTool]=useState("desk"); // Start on ticket
  const [si,setSi]=useState(0);
  const [status,setStatus]=useState("ticket_review"); // ticket_review | coach | action_idle | action_running | action_done
  const [doneSteps,setDoneSteps]=useState([]);
  const [hintCount,setHintCount]=useState(0);
  const [contained,setContained]=useState(false);
  const [elapsed,setElapsed]=useState(0);
  const [showScore,setShowScore]=useState(false);
  const [xpBurstAmt,setXpBurstAmt]=useState(null);

  useEffect(()=>{const t=setInterval(()=>setElapsed(s=>s+1),1000);return()=>clearInterval(t);},[]);

  const step=inc.steps[si];
  const pct=doneSteps.length===0?0:Math.round((doneSteps.length/inc.steps.length)*100);

  const toolMap={
    "BlueTrace SIEM":"siem",
    "SentinelEDR":"edr",
    "ThreatLens":"ti",
    "IncidentDesk":"desk",
  };

  const handleCoachClose=()=>{
    setActiveTool(toolMap[step.tool]||"siem");
    setStatus("action_idle");
  };

  const handleAction=async()=>{
    setStatus("action_running");
    await new Promise(r=>setTimeout(r,1400));
    if(step.phase==="CONTAINMENT") setContained(true);
    setDoneSteps(p=>[...p,si]);
    setXpBurstAmt(step.xp);
    setStatus("action_done");
    setTimeout(()=>setXpBurstAmt(null),2000);
  };

  const handleNext=()=>{
    if(si<inc.steps.length-1){
      setSi(s=>s+1);
      setStatus("coach");
    } else {
      addXP(doneSteps.reduce((a,i)=>a+inc.steps[i].xp,0));
      finishSim(inc.id,doneSteps.length*100,"A",elapsed);
      setShowScore(true);
    }
  };

  const mm=String(Math.floor(elapsed/60)).padStart(2,"0");
  const ss2=String(elapsed%60).padStart(2,"0");

  return(
    <div className="soc-root" style={{height:"100vh",display:"flex",flexDirection:"column",background:"var(--bg)",overflow:"hidden"}}>
      {showScore&&<ScoreModal inc={inc} steps={inc.steps} elapsed={elapsed} hintCount={hintCount} onBack={onBack}/>}
      {/* Ticket Review Overlay — first thing analyst sees */}
      {status==="ticket_review"&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",backdropFilter:"blur(6px)",zIndex:500,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
          <div style={{background:"var(--bg2)",border:"1px solid rgba(220,38,38,0.4)",borderRadius:16,padding:28,maxWidth:540,width:"100%",boxShadow:"var(--sh3)",animation:"fadeUp 0.3s ease"}}>
            <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:16}}>
              <div style={{width:36,height:36,borderRadius:8,background:"rgba(220,38,38,0.15)",border:"1px solid rgba(220,38,38,0.4)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,flexShrink:0}}>🎫</div>
              <div>
                <div style={{fontSize:10,fontWeight:700,color:"#f87171",letterSpacing:"0.1em",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:2}}>New Ticket Assigned — {inc.desk.priority} Priority</div>
                <div style={{fontSize:16,fontWeight:700,color:"var(--tx)"}}>{inc.id}</div>
              </div>
              <SevBadge s={inc.severity}/>
            </div>
            <div style={{fontSize:14,fontWeight:700,color:"var(--tx)",marginBottom:10,lineHeight:1.35}}>{inc.title}</div>
            <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:8,padding:"11px 13px",marginBottom:12,fontSize:12.5,color:"var(--tx2)",lineHeight:1.75}}>{inc.summary}</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:14}}>
              {[["Host",inc.host],["User",inc.user],["SLA",inc.desk.sla_minutes+" minutes"],["Priority",inc.desk.priority]].map(([k,v])=>(
                <div key={k} style={{background:"var(--bg3)",borderRadius:6,padding:"8px 10px"}}>
                  <div style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:2,textTransform:"uppercase",letterSpacing:"0.08em"}}>{k}</div>
                  <div style={{fontSize:12,color:"var(--tx2)",fontFamily:"var(--mo)",fontWeight:600}}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",borderRadius:8,padding:"10px 13px",marginBottom:16,fontSize:12,color:"#93c5fd",lineHeight:1.6}}>
              📋 Read the ticket carefully. Understand what happened and what tools detected it. Then start your investigation.
            </div>
            <button onClick={()=>setStatus("coach")} style={{width:"100%",background:"var(--err)",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(239,68,68,0.4)"}}>
              Ticket Acknowledged — Start Investigation →
            </button>
          </div>
        </div>
      )}
      {status==="coach"&&<CoachPopup step={step} onClose={handleCoachClose} onHint={()=>setHintCount(h=>h+1)} hintUsed={false} stepsDone={doneSteps.length} totalSteps={inc.steps.length}/>}
      {(status==="action_idle"||status==="action_running"||status==="action_done")&&(
        <ActionOverlay step={step} onConfirm={status==="action_done"?handleNext:handleAction} isRunning={status==="action_running"} isDone={status==="action_done"} xpBurst={xpBurstAmt}/>
      )}

      {/* XP burst */}
      {xpBurstAmt&&(
        <div style={{position:"fixed",top:"40%",left:"50%",transform:"translateX(-50%)",zIndex:600,animation:"xpburst 2s ease forwards",pointerEvents:"none",fontSize:20,fontWeight:800,color:"#22c55e",fontFamily:"var(--mo)",textShadow:"0 0 20px rgba(34,197,94,0.8)"}}>
          +{xpBurstAmt} XP ⚡
        </div>
      )}

      {/* TOP BAR */}
      <div style={{background:"var(--bg2)",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:48,display:"flex",alignItems:"center",gap:12,flexShrink:0,boxShadow:"var(--sh)"}}>
        <button onClick={onBack} style={{background:"var(--bg3)",color:"var(--tx3)",padding:"5px 10px",borderRadius:5,fontSize:11,border:"1px solid var(--bd)",cursor:"pointer"}}>← Dashboard</button>
        <div style={{flex:1,overflow:"hidden"}}>
          <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:1}}>{inc.id} · {(analystProp?.name||ANALYST.name)} · P1-Critical</div>
          <div style={{fontSize:13,fontWeight:700,color:"var(--tx)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{inc.title}</div>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flexShrink:0}}>
          <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:5,padding:"3px 9px",fontSize:10.5,fontFamily:"var(--mo)",color:"var(--tx2)",fontWeight:600}}>{mm}:{ss2}</div>
          <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:5,padding:"3px 9px",fontSize:10.5,fontFamily:"var(--mo)",color:"var(--ac)",fontWeight:600}}>Step {si+1}/{inc.steps.length}</div>
          <div style={{background:contained?"var(--okl)":"var(--errl)",border:"1px solid "+(contained?"var(--okb)":"var(--errb)"),borderRadius:5,padding:"3px 9px",fontSize:10.5,fontFamily:"var(--mo)",fontWeight:600,color:contained?"var(--ok)":"var(--err)"}}>
            {contained?"CONTAINED":"LIVE THREAT"}
          </div>
        </div>
      </div>

      {/* PROGRESS */}
      <div style={{height:3,background:"var(--bg3)",flexShrink:0}}>
        <div style={{height:"100%",width:pct+"%",background:"linear-gradient(90deg,var(--ac),#7c3aed)",transition:"width 0.6s ease"}}/>
      </div>

      {/* TOOL SWITCHER */}
      <div style={{background:"#0a0d14",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:40,display:"flex",alignItems:"center",gap:0,flexShrink:0}}>
        <span style={{fontSize:9,color:"var(--tx4)",fontFamily:"var(--mo)",marginRight:12,letterSpacing:"0.1em",textTransform:"uppercase",flexShrink:0}}>Tools</span>
        {[
          {id:"siem",label:"BlueTrace SIEM",color:"#3b82f6",shortLabel:"SIEM"},
          {id:"edr",label:"SentinelEDR",color:"#ef4444",shortLabel:"EDR"},
          {id:"ti",label:"ThreatLens",color:"#8b5cf6",shortLabel:"INTEL"},
          {id:"desk",label:"IncidentDesk",color:"#10b981",shortLabel:"DESK"},
        ].map(t=>{
          const isActive=activeTool===t.id;
          const isStepTool=toolMap[step?.tool]===t.id;
          return(
            <button key={t.id} onClick={()=>setActiveTool(t.id)}
              style={{padding:"0 14px",height:40,fontSize:11,fontWeight:isActive?700:500,color:isActive?t.color:"var(--tx4)",background:isActive?t.color+"18":"none",border:"none",borderBottom:isActive?"2px solid "+t.color:"2px solid transparent",cursor:"pointer",fontFamily:"var(--mo)",letterSpacing:"0.05em",transition:"all 0.13s",position:"relative",display:"flex",alignItems:"center",gap:5}}>
              {t.shortLabel}
              {isStepTool&&<span style={{width:6,height:6,borderRadius:"50%",background:t.color,animation:"pulse 1.5s ease-in-out infinite"}}/>}
            </button>
          );
        })}
        <div style={{flex:1}}/>
        <div style={{display:"flex",gap:6}}>
          {inc.steps.map((_,i)=>{
            const d=doneSteps.includes(i),active=i===si;
            const pc=phaseColor(inc.steps[i].phase);
            return(
              <div key={i} style={{width:8,height:8,borderRadius:"50%",background:d?pc:active?pc+"60":"var(--bg4)",border:"1px solid "+(d?pc:active?pc+"80":"var(--bd)"),transition:"all 0.3s"}}/>
            );
          })}
        </div>
      </div>

      {/* TOOL CONTENT */}
      <div style={{flex:1,overflow:"hidden",display:"flex",paddingBottom:(status==="action_idle"||status==="action_running"||status==="action_done")?90:0}}>
        {activeTool==="siem"&&<BlueTraceSIEM inc={inc} activeStep={status!=="coach"?step:null}/>}
        {activeTool==="edr"&&<SentinelEDR inc={inc} activeStep={status!=="coach"?step:null} isContained={contained}/>}
        {activeTool==="ti"&&<ThreatLens inc={inc} activeStep={status!=="coach"?step:null}/>}
        {activeTool==="desk"&&<IncidentDesk inc={inc} activeStep={status!=="coach"?step:null} stepsDone={doneSteps.length} analyst={analystProp||ANALYST} elapsed={elapsed}/>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT APP
// ─────────────────────────────────────────────────────────────────────────────





function Pill({children,color,sm}) {
  const cols={
    blue: {bg:"var(--acl)",  cl:"var(--ac)",  br:"var(--acb)" },
    green:{bg:"var(--okl)",  cl:"var(--ok)",  br:"var(--okb)" },
    amber:{bg:"var(--warnl)",cl:"var(--warn)",br:"var(--warnb)"},
    red:  {bg:"var(--errl)", cl:"var(--err)", br:"var(--errb)" },
    gray: {bg:"rgba(107,114,128,0.07)",cl:"var(--tx4)",br:"rgba(107,114,128,0.18)"},
  };
  const c=cols[color]||cols.gray;
  return (
    <span style={{background:c.bg,color:c.cl,border:"1px solid "+c.br,
      padding:sm?"1px 7px":"2px 9px",borderRadius:20,
      fontSize:sm?9:10.5,fontWeight:600,fontFamily:"var(--mo)",
      letterSpacing:0.3,whiteSpace:"nowrap"}}>
      {children}
    </span>
  );
}


function Tag({c}) {
  return (
    <span style={{background:"var(--bg2)",border:"1px solid var(--bd)",
      color:"var(--tx3)",padding:"2px 7px",borderRadius:4,
      fontSize:10,fontFamily:"var(--mo)",fontWeight:500}}>
      {c}
    </span>
  );
}


function Ey({t,center}) {
  return (
    <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",
      color:"var(--ac)",fontFamily:"var(--mo)",marginBottom:10,
      textTransform:"uppercase",textAlign:center?"center":undefined}}>
      {t}
    </div>
  );
}

function ContactPage({nav}) {
  const [form,setForm] = useState({name:"",email:"",subject:"",message:""});
  const [sent,setSent] = useState(false);
  const inp = {width:"100%",padding:"11px 13px",border:"1px solid var(--bd)",borderRadius:8,fontSize:14,fontFamily:"var(--fn)",outline:"none",background:"var(--w)",color:"var(--tx)"};
  return (
    <div style={{maxWidth:600,margin:"0 auto",padding:"32px 20px 60px"}}>
      <button onClick={()=>nav("landing")} style={{background:"var(--w)",border:"1px solid var(--bd)",color:"var(--tx3)",padding:"6px 12px",borderRadius:6,fontSize:12,marginBottom:24,cursor:"pointer"}}>← Home</button>
      <Ey t="Contact Us"/>
      <h1 style={{fontSize:"clamp(22px,4vw,30px)",fontWeight:700,color:"var(--tx)",marginBottom:6}}>Get in Touch</h1>
      <p style={{fontSize:14,color:"var(--tx3)",lineHeight:1.7,marginBottom:28}}>Questions, feedback, or support? We reply within 24 hours.</p>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:10,marginBottom:28}}>
        {[["📧","Email","support.learnblueteam@gmail.com"],["🌐","Website","www.learnblueteam.cloud"],["📍","Based in","Mumbai, India"]].map(([ic,l,v])=>(
          <div key={l} style={{background:"var(--w)",border:"1px solid var(--bd)",borderRadius:10,padding:"14px",boxShadow:"var(--sh)"}}>
            <div style={{fontSize:20,marginBottom:7}}>{ic}</div>
            <div style={{fontSize:10,fontWeight:700,color:"var(--tx4)",letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:3,fontFamily:"var(--mo)"}}>{l}</div>
            <div style={{fontSize:12.5,color:"var(--tx2)",wordBreak:"break-all"}}>{v}</div>
          </div>
        ))}
      </div>
      {sent ? (
        <div style={{background:"var(--okl)",border:"1px solid var(--okb)",borderRadius:12,padding:"28px",textAlign:"center"}}>
          <div style={{fontSize:32,marginBottom:10}}>✅</div>
          <div style={{fontSize:17,fontWeight:700,color:"var(--ok)",marginBottom:5}}>Message sent!</div>
          <div style={{fontSize:13,color:"var(--tx3)"}}>We will reply to {form.email} within 24 hours.</div>
        </div>
      ) : (
        <div style={{background:"var(--w)",border:"1px solid var(--bd)",borderRadius:14,padding:"24px",boxShadow:"var(--sh2)"}}>
          <form onSubmit={e=>{e.preventDefault();setSent(true);}}>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
              <div>
                <label style={{fontSize:12,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:6}}>Name</label>
                <input style={inp} placeholder="Your name" value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} required/>
              </div>
              <div>
                <label style={{fontSize:12,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:6}}>Email</label>
                <input style={inp} type="email" placeholder="you@example.com" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} required/>
              </div>
            </div>
            <div style={{marginBottom:12}}>
              <label style={{fontSize:12,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:6}}>Subject</label>
              <select style={{...inp,cursor:"pointer"}} value={form.subject} onChange={e=>setForm(f=>({...f,subject:e.target.value}))} required>
                <option value="">Select a topic...</option>
                <option>General Inquiry</option>
                <option>Technical Support</option>
                <option>Billing / Refund</option>
                <option>Bug Report</option>
                <option>Feature Request</option>
                <option>Partnership</option>
              </select>
            </div>
            <div style={{marginBottom:18}}>
              <label style={{fontSize:12,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:6}}>Message</label>
              <textarea style={{...inp,minHeight:110,resize:"vertical",lineHeight:1.6}} placeholder="Describe your question or issue..." value={form.message} onChange={e=>setForm(f=>({...f,message:e.target.value}))} required/>
            </div>
            <button type="submit" style={{width:"100%",background:"var(--ac)",color:"#fff",padding:"13px",borderRadius:9,fontSize:14,fontWeight:600,border:"none",cursor:"pointer",boxShadow:"0 3px 12px rgba(26,86,219,0.3)"}}>
              Send Message
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

const CSS = `

@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --w:#fff;--bg:#f7f8fa;--bg2:#f0f2f6;--bg3:#e8eaef;--bg4:#dde0e9;
  --bd:#e1e4ed;--bd2:#c8cdd9;
  --tx:#111318;--tx2:#2d3241;--tx3:#5a6272;--tx4:#8892a4;
  --ac:#1a56db;--acl:rgba(26,86,219,0.07);--acb:rgba(26,86,219,0.18);
  --ok:#166534;--okl:rgba(22,101,52,0.08);--okb:rgba(22,101,52,0.2);
  --warn:#92400e;--warnl:rgba(146,64,14,0.07);--warnb:rgba(146,64,14,0.18);
  --err:#991b1b;--errl:rgba(153,27,27,0.07);--errb:rgba(153,27,27,0.2);
  --fn:'IBM Plex Sans',sans-serif;--mo:'IBM Plex Mono',monospace;
  --sh:0 1px 3px rgba(17,19,24,0.06);
  --sh2:0 3px 12px rgba(17,19,24,0.08);
  --sh3:0 8px 32px rgba(17,19,24,0.10);
}
html,body,#root{height:100%}
body{background:var(--bg);color:var(--tx);font-family:var(--fn);-webkit-font-smoothing:antialiased}
button{font-family:var(--fn);cursor:pointer;border:none;transition:all 0.13s}
button:active{transform:scale(0.97)!important}
@keyframes blink{0%,49%{opacity:1}50%,100%{opacity:0}}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.2;transform:scale(2.2)}}
@keyframes ticker{from{transform:translateX(0)}to{transform:translateX(-50%)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}


/* SOC Console Dark Theme - scoped */
/* SOC Dark Theme */

500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

.soc-root{
  --bg:#0f1117;--bg2:#161b27;--bg3:#1e2535;--bg4:#252d3d;
  --bd:#2a3348;--bd2:#374056;
  --tx:#e8ecf4;--tx2:#b8c0d4;--tx3:#7a8499;--tx4:#4a5568;
  --ac:#3b82f6;--acl:rgba(59,130,246,0.12);--acb:rgba(59,130,246,0.3);
  --ok:#22c55e;--okl:rgba(34,197,94,0.1);--okb:rgba(34,197,94,0.3);
  --warn:#f59e0b;--warnl:rgba(245,158,11,0.1);--warnb:rgba(245,158,11,0.3);
  --err:#ef4444;--errl:rgba(239,68,68,0.1);--errb:rgba(239,68,68,0.3);
  --crit:#dc2626;--critl:rgba(220,38,38,0.12);
  --fn:'IBM Plex Sans',sans-serif;--mo:'IBM Plex Mono',monospace;
  --sh:0 1px 4px rgba(0,0,0,0.4);
  --sh2:0 4px 16px rgba(0,0,0,0.5);
  --sh3:0 8px 32px rgba(0,0,0,0.6);
}


button{font-family:var(--fn);cursor:pointer;border:none;transition:all 0.13s}
button:active{transform:scale(0.97)}
input,select,textarea{font-family:var(--fn);background:var(--bg3);border:1px solid var(--bd);color:var(--tx);border-radius:6px;padding:8px 10px;font-size:13px;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--ac)}
@keyframes blink{0%,49%{opacity:1}50%,100%{opacity:0}}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.15;transform:scale(2.4)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
@keyframes glow{0%,100%{box-shadow:0 0 8px rgba(220,38,38,0.4)}50%{box-shadow:0 0 18px rgba(220,38,38,0.7)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes xpburst{0%{opacity:1;transform:translateY(0) scale(1)}100%{opacity:0;transform:translateY(-40px) scale(1.4)}}
.sev-crit{background:rgba(220,38,38,0.12);color:#fca5a5;border:1px solid rgba(220,38,38,0.35);animation:glow 2s ease-in-out infinite}
.sev-high{background:rgba(234,88,12,0.12);color:#fdba74;border:1px solid rgba(234,88,12,0.35)}
.sev-med{background:rgba(234,179,8,0.12);color:#fde047;border:1px solid rgba(234,179,8,0.35)}
.sev-low{background:rgba(34,197,94,0.1);color:#86efac;border:1px solid rgba(34,197,94,0.25)}
.tool-row{display:flex;gap:0;border-bottom:1px solid var(--bd)}
.tool-tab{padding:10px 16px;font-size:11px;font-weight:600;color:var(--tx3);background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;font-family:var(--mo);letter-spacing:0.08em;text-transform:uppercase;transition:all 0.13s;white-space:nowrap}
.tool-tab:hover{color:var(--tx2)}
.tool-tab.on{color:var(--ac);border-bottom-color:var(--ac);background:var(--acl)}
.mono{font-family:var(--mo)}
.tag{background:var(--bg4);border:1px solid var(--bd);color:var(--tx3);padding:1px 7px;border-radius:3px;font-size:10px;font-family:var(--mo)}
.clickrow{cursor:pointer;transition:background 0.1s}
.clickrow:hover{background:var(--bg4)!important}
.clickrow.sel{background:rgba(59,130,246,0.08)!important;border-left:2px solid var(--ac)!important}

`;

// ── logo component ────────────────────────────────────────────────────────────
function Logo({size=32}) {
  // LB monogram matching the uploaded logo: dark L + blue B with terminal prompt
  const s = size;
  return (
    <svg width={s} height={s} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
      {/* Dark L */}
      <path d="M18 14 L18 72 L58 72 L58 86 L8 86 L8 14 Z" fill="#2d3748"/>
      {/* Blue B */}
      <path d="M38 14 L38 86 L65 86 C80 86 92 76 92 62 C92 54 88 48 82 44 C86 40 89 35 89 28 C89 20 82 14 70 14 Z M50 26 L66 26 C71 26 75 30 75 35 C75 40 71 44 66 44 L50 44 Z M50 56 L68 56 C74 56 79 60 79 66 C79 72 74 76 68 76 L50 76 Z" fill="#2563eb"/>
      {/* Terminal prompt > _ inside B */}
      <text x="49" y="55" fontSize="14" fontFamily="monospace" fill="white" fontWeight="bold">{">"}_</text>
    </svg>
  );
}

// ── policy page data (replaces 7 separate components) ────────────────────────
const POLICIES = {
  privacy:{title:"Privacy Policy",sections:[
    ["Information We Collect","We collect name, email, and password when you register. We collect usage data: simulations completed, XP earned, scores, time spent. No payment info is stored directly — handled by third-party processors."],
    ["How We Use Your Data","To operate the platform, personalise your experience, track progress, issue certificates, send service updates, and respond to support. We never sell your data."],
    ["Data Storage & Security","Stored securely with HTTPS encryption in transit and encryption at rest. Progress also saved in localStorage for offline access."],
    ["Cookies","Essential cookies only — login state and preferences. No advertising or tracking cookies."],
    ["Your Rights","You can request access, correction, or deletion of your data anytime. Email support.learnblueteam@gmail.com. We process within 30 days."],
    ["Children","Platform is for users 16+. We do not knowingly collect data from children under 16."],
    ["Changes","We will notify registered users of significant changes via email."],
  ]},
  terms:{title:"Terms of Service",sections:[
    ["Acceptance","By using www.learnblueteam.cloud you agree to these Terms. If you disagree, please do not use the platform."],
    ["Platform Use","LearnBlueTeam provides simulated defensive security exercises for education only. You may not use knowledge gained here to attack systems you do not own or have explicit permission to test."],
    ["Account Responsibility","You are responsible for all activity under your account. Do not share credentials. Notify us immediately of any unauthorised use."],
    ["Acceptable Use","Do not reverse-engineer platform content, scrape data, impersonate others, post harmful content, or circumvent security measures."],
    ["Intellectual Property","All content — simulations, scenarios, UI, logos — is owned by LearnBlueTeam and protected by copyright. No reproduction without written permission."],
    ["Limitation of Liability","Platform is provided as-is. We are not liable for indirect or consequential damages. Total liability shall not exceed amounts paid in the prior 12 months."],
    ["Governing Law","Governed by the laws of India. Disputes resolved in courts of Mumbai, Maharashtra."],
  ]},
  refund:{title:"Refund Policy",sections:[
    ["Free Tier","No payment, no refund consideration."],
    ["Pro Monthly","Full refund within 7 days of initial purchase. After 7 days, no refund for current period but cancel anytime to prevent future charges."],
    ["Annual","Refund within 14 days if less than 10% content used. After 14 days, prorated credits at our discretion."],
    ["Certification Exam","Non-refundable once started. Refundable within 7 days if not started."],
    ["How to Request","Email support.learnblueteam@gmail.com with subject 'Refund Request'. Include registered email, order details, and reason. Processed within 7-10 business days."],
    ["Exceptions","No refunds for accounts suspended due to ToS violations."],
  ]},
  "ai-disclaimer":{title:"AI Disclaimer",sections:[
    ["AI-Assisted Content","LBT uses AI to generate scenario variations, coaching hints, and threat summaries. This content is educational simulation — not real threat intelligence."],
    ["Not Real Security Advice","All AI content is for educational simulation only. Do not rely on it for real-world security decisions or incident response."],
    ["Accuracy","AI content may contain errors, outdated information, or simplified representations of real attack techniques. ATT&CK mappings are approximations for training."],
    ["MITRE ATT&CK","References to MITRE ATT&CK are educational. MITRE ATT&CK is a registered trademark of The MITRE Corporation. LBT is not affiliated with MITRE."],
    ["Data for AI","Anonymised usage data may improve our AI coaching models. No PII used for AI training without consent."],
  ]},
  "data-policy":{title:"Data Policy",sections:[
    ["What We Store","Account: name, email, hashed password. Progress: XP, level, scores, grades, time. Certificates: completion records with unique IDs. Sessions: login timestamps."],
    ["Local Storage","Progress also saved in browser localStorage. Creating an account backs up your progress to our servers."],
    ["Data Retention","Active account data retained for account lifetime. On deletion, all personal data removed within 30 days."],
    ["Security","Passwords hashed with bcrypt. HTTPS for all data in transit. Regular security reviews."],
    ["Third Parties","We use Railway (hosting), Gmail (email), analytics. Minimum necessary data shared under strict agreements."],
    ["Portability","Request a data export anytime at support.learnblueteam@gmail.com. Delivered in 14 days."],
  ]},
  rules:{title:"Community Rules",sections:[
    ["Be Respectful","Treat all community members, staff, and content with respect. Harassment, hate speech, or personal attacks result in immediate suspension."],
    ["No Real-World Attacks","Knowledge from this platform must only be used defensively and on systems you own or have explicit permission to test. Using techniques learned here illegally is strictly prohibited."],
    ["No Cheating","Do not manipulate scores, exploit bugs, or share scenario answers publicly. Shortcuts undermine your own growth."],
    ["Privacy","Do not share other users' personal information without consent."],
    ["Responsible Disclosure","If you find a security vulnerability in our platform, report it to support.learnblueteam@gmail.com before public disclosure."],
    ["Consequences","Violations result in warnings, suspension, or permanent ban depending on severity."],
  ]},
};

function PolicyPage({policyKey,nav}) {
  const p = POLICIES[policyKey];
  if (!p) return null;
  return (
    <div style={{maxWidth:720,margin:"0 auto",padding:"28px 20px 60px"}}>
      <button onClick={()=>nav("landing")} style={{background:"var(--w)",border:"1px solid var(--bd)",color:"var(--tx3)",padding:"6px 12px",borderRadius:6,fontSize:12,marginBottom:22,cursor:"pointer",boxShadow:"var(--sh)"}}>Home</button>
      <h1 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:700,color:"var(--tx)",marginBottom:5,lineHeight:1.2}}>{p.title}</h1>
      <div style={{fontSize:12,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:28}}>Updated May 2026 · www.learnblueteam.cloud</div>
      <div style={{display:"flex",flexDirection:"column",gap:22}}>
        {p.sections.map(([title,body],i)=>(
          <div key={i}>
            <h2 style={{fontSize:15,fontWeight:700,color:"var(--tx)",marginBottom:7}}>{i+1}. {title}</h2>
            <p style={{fontSize:14,color:"var(--tx2)",lineHeight:1.8}}>{body}</p>
          </div>
        ))}
      </div>
      <div style={{marginTop:40,padding:"18px",background:"var(--bg)",border:"1px solid var(--bd)",borderRadius:10,textAlign:"center"}}>
        <div style={{fontSize:13,color:"var(--tx3)",marginBottom:5}}>Questions?</div>
        <a href="mailto:support.learnblueteam@gmail.com" style={{fontSize:14,fontWeight:600,color:"var(--ac)"}}>support.learnblueteam@gmail.com</a>
      </div>
    </div>
  );
}


// ── landing ───────────────────────────────────────────────────────────────────
function FAQItem({q,a}) {
  const [open,setOpen] = useState(false);
  return (
    <div style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:10,overflow:"hidden"}}>
      <button onClick={()=>setOpen(o=>!o)} style={{width:"100%",padding:"14px 16px",background:"none",border:"none",cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",textAlign:"left",gap:10}}>
        <span style={{fontSize:14,fontWeight:600,color:"#111318",lineHeight:1.4}}>{q}</span>
        <span style={{fontSize:18,color:"#1a56db",flexShrink:0,transform:open?"rotate(45deg)":"none",transition:"transform 0.2s"}}>+</span>
      </button>
      {open&&<div style={{padding:"0 16px 14px",fontSize:13.5,color:"#5a6272",lineHeight:1.75,borderTop:"1px solid #e1e4ed",paddingTop:12}}>{a}</div>}
    </div>
  );
}

function OnboardingModal({onStart}) {
  const [step,setStep] = useState(0);
  const tools = [
    {color:"#1a56db",icon:"📊",name:"BlueTrace SIEM",desc:"Detects suspicious activity across your network. This is where alerts fire and investigations begin."},
    {color:"#dc2626",icon:"🖥",name:"SentinelEDR",desc:"Shows exactly what happened on the endpoint — process tree, network connections, files created."},
    {color:"#7c3aed",icon:"🔍",name:"ThreatLens",desc:"Checks whether IPs, domains, and file hashes are known malicious. Your threat intelligence tool."},
    {color:"#059669",icon:"📋",name:"IncidentDesk",desc:"Where you manage the ticket, write your IR report, and close the incident."},
  ];
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(17,19,24,0.6)",backdropFilter:"blur(6px)",zIndex:2000,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <div style={{background:"#fff",borderRadius:16,padding:28,maxWidth:480,width:"100%",boxShadow:"0 8px 32px rgba(17,19,24,0.15)",animation:"fadeUp 0.3s ease"}}>
        {step===0 ? (
          <>
            <div style={{textAlign:"center",marginBottom:20}}>
              <div style={{fontSize:32,marginBottom:10}}>👋</div>
              <h2 style={{fontSize:20,fontWeight:800,color:"#111318",marginBottom:6}}>Welcome to LearnBlueTeam</h2>
              <p style={{fontSize:14,color:"#5a6272",lineHeight:1.7}}>You are about to investigate a real-world security incident. You will use the same tools professional SOC analysts use every day.</p>
            </div>
            <div style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:10,padding:"14px",marginBottom:16,fontSize:13,color:"#5a6272",lineHeight:1.7}}>
              <strong style={{color:"#111318"}}>No experience required.</strong> Your analyst coach will guide you through every step and explain why each action matters.
            </div>
            <button onClick={()=>setStep(1)} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)"}}>
              Show Me the Tools →
            </button>
          </>
        ) : (
          <>
            <div style={{marginBottom:16}}>
              <div style={{fontSize:10,fontWeight:700,color:"#1a56db",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:4,textTransform:"uppercase"}}>Tools You'll Use — {step}/{tools.length}</div>
              <div style={{height:3,background:"#f0f2f6",borderRadius:2,overflow:"hidden"}}>
                <div style={{height:"100%",width:(step/tools.length*100)+"%",background:"#1a56db",transition:"width 0.3s"}}/>
              </div>
            </div>
            {tools.slice(0,step).map((t,i)=>(
              <div key={t.name} style={{display:"flex",gap:12,alignItems:"flex-start",padding:"12px",background:i===step-1?"rgba(26,86,219,0.04)":"#f7f8fa",border:"1px solid "+(i===step-1?"#1a56db30":"#e1e4ed"),borderRadius:10,marginBottom:8}}>
                <div style={{width:36,height:36,borderRadius:8,background:t.color+"15",border:"1px solid "+t.color+"30",display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,flexShrink:0}}>{t.icon}</div>
                <div>
                  <div style={{fontSize:13,fontWeight:700,color:t.color,marginBottom:2}}>{t.name}</div>
                  <div style={{fontSize:12.5,color:"#5a6272",lineHeight:1.6}}>{t.desc}</div>
                </div>
              </div>
            ))}
            {step < tools.length
              ? <button onClick={()=>setStep(s=>s+1)} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",marginTop:4}}>
                  Next Tool →
                </button>
              : <button onClick={onStart} style={{width:"100%",background:"#16a34a",color:"#fff",padding:"13px",borderRadius:10,fontSize:15,fontWeight:700,border:"none",cursor:"pointer",marginTop:4,boxShadow:"0 4px 14px rgba(22,163,74,0.3)"}}>
                  ✓ I'm Ready — Start Investigation
                </button>
            }
          </>
        )}
      </div>
    </div>
  );
}


function Landing({nav,appUser}) {
  const [typed,setTyped] = useState("");
  const tRef = useRef();
  const [ti,setTi] = useState(0);
  const [ci,setCi] = useState(0);
  const [del,setDel] = useState(false);
  const titles = ["Defensive Security Professional","SOC Analyst","Incident Responder","Threat Hunter","Blue Team Specialist"];
  useEffect(()=>{
    const cur=titles[ti];
    tRef.current=setTimeout(()=>{
      if(!del){setTyped(cur.slice(0,ci+1));if(ci+1===cur.length)setTimeout(()=>setDel(true),2200);else setCi(c=>c+1);}
      else{setTyped(cur.slice(0,ci-1));if(ci===0){setDel(false);setTi(i=>(i+1)%titles.length);}else setCi(c=>c-1);}
    },del?28:72);
    return()=>clearTimeout(tRef.current);
  },[ci,del,ti]);

  return (
    <div>
      {/* ── HERO ── */}
      <div style={{minHeight:"92vh",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:"60px 20px 48px",textAlign:"center",background:"#f7f8fa",position:"relative",overflow:"hidden"}}>
        <div style={{position:"absolute",inset:0,backgroundImage:"linear-gradient(#e1e4ed 1px,transparent 1px),linear-gradient(90deg,#e1e4ed 1px,transparent 1px)",backgroundSize:"40px 40px",opacity:0.5,pointerEvents:"none"}}/>
        {/* Logo */}
        <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:12,marginBottom:20,position:"relative",zIndex:1}}>
          <Logo size={44}/>
          <div style={{textAlign:"left"}}>
            <div style={{fontSize:20,fontWeight:800,color:"#111318",letterSpacing:"0.01em",lineHeight:1}}>LEARN<span style={{color:"#1a56db"}}>BLUETEAM</span></div>
            <div style={{fontSize:9,color:"#8892a4",letterSpacing:"0.18em",fontFamily:"var(--mo)",textTransform:"uppercase"}}>Defensive · Security · Reimagined</div>
          </div>
        </div>
        {/* Beta badge */}
        <div style={{display:"inline-flex",alignItems:"center",gap:7,background:"#fff",border:"1px solid #e1e4ed",color:"#5a6272",padding:"5px 13px",borderRadius:100,fontSize:11,fontWeight:600,marginBottom:20,position:"relative",zIndex:1,fontFamily:"var(--mo)",boxShadow:"0 1px 3px rgba(17,19,24,0.06)"}}>
          <div style={{width:6,height:6,borderRadius:"50%",background:"#16a34a",animation:"pulse 2s infinite"}}/>
          BETA — FREE ACCESS OPEN
        </div>
        {/* Headline */}
        <h1 style={{fontSize:"clamp(26px,5vw,54px)",fontWeight:800,lineHeight:1.1,letterSpacing:"-0.03em",marginBottom:14,color:"#111318",position:"relative",zIndex:1}}>
          Become a<br/>
          <span style={{color:"#1a56db"}}>{typed}</span>
          <span style={{display:"inline-block",width:2,height:"0.85em",background:"#1a56db",borderRadius:1,verticalAlign:"text-bottom",marginLeft:2,animation:"blink 1s infinite"}}/>
        </h1>
        <p style={{fontSize:"clamp(14px,3vw,17px)",color:"#5a6272",lineHeight:1.75,maxWidth:520,margin:"0 auto 28px",position:"relative",zIndex:1}}>
          Investigate phishing, malware, ransomware, and cloud attacks using realistic SIEM, EDR, Threat Intelligence, and Incident Response workflows.<br/>
          <strong style={{color:"#111318"}}>No VMs. No setup. Just start investigating.</strong>
        </p>
        {/* CTAs */}
        <div style={{display:"flex",gap:10,justifyContent:"center",flexWrap:"wrap",position:"relative",zIndex:1,width:"100%",maxWidth:400}}>
          {appUser
            ?<button onClick={()=>nav("dash")} style={{flex:1,background:"#1a56db",color:"#fff",fontSize:14,fontWeight:700,padding:"13px 20px",borderRadius:10,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)",minWidth:160}}>Go to Dashboard</button>
            :<button onClick={()=>nav("signup")} style={{flex:1,background:"#1a56db",color:"#fff",fontSize:14,fontWeight:700,padding:"13px 20px",borderRadius:10,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)",minWidth:160}}>Start Free Investigation</button>
          }
          <button onClick={()=>nav("sim-phishing-c2")} style={{flex:1,background:"#fff",color:"#2d3241",fontSize:14,fontWeight:500,padding:"13px 20px",borderRadius:10,border:"1px solid #e1e4ed",cursor:"pointer",boxShadow:"0 1px 3px rgba(17,19,24,0.06)",minWidth:160}}>Watch Demo →</button>
        </div>
        {/* Live alert ticker */}
        <div style={{marginTop:24,display:"flex",alignItems:"center",gap:9,padding:"10px 14px",background:"#fff",borderRadius:10,border:"1px solid #e1e4ed",maxWidth:480,width:"100%",boxShadow:"0 1px 3px rgba(17,19,24,0.06)",position:"relative",zIndex:1}}>
          <div style={{width:7,height:7,borderRadius:"50%",background:"#dc2626",animation:"pulse 1.5s infinite",flexShrink:0}}/>
          <Pill color="red" sm>CRITICAL</Pill>
          <span style={{fontSize:12,color:"#5a6272",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>C2 beacon detected — WS-CORP-FIN-044 → 185.220.101.47:443</span>
          <span style={{fontSize:10,color:"#8892a4",flexShrink:0,fontFamily:"var(--mo)"}}>08:17</span>
        </div>
        {/* Disclaimer */}
        <div style={{marginTop:14,fontSize:10,color:"#8892a4",position:"relative",zIndex:1,maxWidth:480}}>
          ⚠ All scenarios, users, domains, and alerts are fictional and created for educational purposes only.
        </div>
      </div>

      {/* ── MARQUEE — removed company names per compliance ── */}
      <div style={{overflow:"hidden",borderTop:"1px solid #e1e4ed",borderBottom:"1px solid #e1e4ed",background:"#fff",padding:"12px 0"}}>
        <div style={{textAlign:"center",fontSize:9,fontWeight:700,letterSpacing:"0.2em",color:"#8892a4",fontFamily:"var(--mo)",marginBottom:10,textTransform:"uppercase"}}>
          Analysts training for roles in
        </div>
        <div style={{display:"flex",width:"max-content",animation:"ticker 30s linear infinite"}}>
          {["SOC Operations","Incident Response","Threat Hunting","Digital Forensics","Cloud Security","Email Security","Malware Analysis","Identity Security","Detection Engineering","Security Operations",
            "SOC Operations","Incident Response","Threat Hunting","Digital Forensics","Cloud Security","Email Security","Malware Analysis","Identity Security","Detection Engineering","Security Operations"
          ].map((c,i)=>(
            <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"0 24px",fontSize:12.5,fontWeight:500,color:"#8892a4",whiteSpace:"nowrap",fontFamily:"var(--mo)"}}>
              {c}<div style={{width:3,height:3,borderRadius:"50%",background:"#dde0e9"}}/>
            </div>
          ))}
        </div>
      </div>

      {/* ── CHOOSE YOUR PATH ── */}
      <div style={{padding:"48px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Defensive Security Paths</div>
          <h2 style={{fontSize:"clamp(20px,4vw,30px)",fontWeight:800,color:"#111318",marginBottom:8,lineHeight:1.2}}>Choose Your Defensive Security Path</h2>
          <p style={{fontSize:14,color:"#5a6272",maxWidth:480,margin:"0 auto"}}>LearnBlueTeam covers the full spectrum of defensive security careers.</p>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:12,maxWidth:1060,margin:"0 auto"}}>
          {[
            {icon:"🔵",title:"SOC Analyst",desc:"Investigate alerts, triage incidents, and respond to threats using SIEM and EDR tools.",status:"Available Now",available:true,cta:"Start Learning"},
            {icon:"🔴",title:"Incident Responder",desc:"Contain and recover from active security incidents including ransomware and breaches.",status:"Coming Soon",available:false},
            {icon:"🟣",title:"Threat Hunter",desc:"Proactively search for hidden threats using behavioral analytics and threat intelligence.",status:"Coming Soon",available:false},
            {icon:"☁️",title:"Cloud Security Analyst",desc:"Investigate cloud incidents, IAM abuse, and exposed credentials in AWS and Azure.",status:"Coming Soon",available:false},
            {icon:"⚙️",title:"Detection Engineer",desc:"Build detection rules, tune alerts, and improve your organisation's security posture.",status:"Coming Soon",available:false},
          ].map(p=>(
            <div key={p.title} style={{background:p.available?"#fff":"#f7f8fa",border:"1px solid "+(p.available?"#1a56db":"#e1e4ed"),borderRadius:14,padding:"20px",opacity:p.available?1:0.7,boxShadow:p.available?"0 2px 12px rgba(26,86,219,0.1)":"none"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:12}}>
                <span style={{fontSize:28}}>{p.icon}</span>
                <span style={{fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:100,background:p.available?"rgba(26,86,219,0.08)":"rgba(107,114,128,0.08)",color:p.available?"#1a56db":"#6b7280",fontFamily:"var(--mo)"}}>{p.status}</span>
              </div>
              <div style={{fontSize:15,fontWeight:700,color:"#111318",marginBottom:6}}>{p.title}</div>
              <div style={{fontSize:13,color:"#5a6272",lineHeight:1.65,marginBottom:14}}>{p.desc}</div>
              {p.available
                ?<button onClick={()=>nav("signup")} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"10px",borderRadius:8,fontSize:13,fontWeight:600,border:"none",cursor:"pointer"}}>
                  {p.cta} →
                </button>
                :<div style={{fontSize:12,color:"#8892a4",textAlign:"center",padding:"8px",border:"1px dashed #e1e4ed",borderRadius:6}}>Notify me when available</div>
              }
            </div>
          ))}
        </div>
      </div>

      {/* ── CAREER ROADMAP ── */}
      <div style={{padding:"48px 20px",background:"#f7f8fa",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:36}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Career Roadmap</div>
          <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#111318",marginBottom:8}}>Your Journey from Beginner to Specialist</h2>
          <p style={{fontSize:14,color:"#5a6272"}}>Every level unlocks new scenarios and skills.</p>
        </div>
        <div style={{maxWidth:700,margin:"0 auto",display:"flex",flexDirection:"column",gap:0}}>
          {[
            {level:"Level 0",title:"Complete Beginner",color:"#6b7280",learn:["What is a SIEM","What is EDR","What is an IOC","Alert vs Incident"],xp:"0 XP",icon:"🌱"},
            {level:"SOC Analyst L1",title:"Junior Analyst",color:"#1a56db",learn:["Alert Triage","Phishing Analysis","IOC Validation","True/False Positive"],xp:"500 XP",icon:"🔵"},
            {level:"SOC Analyst L2",title:"Mid-Level Analyst",color:"#7c3aed",learn:["Malware Investigation","Correlation Analysis","Threat Hunting Basics","Incident Validation"],xp:"1,500 XP",icon:"🟣"},
            {level:"Incident Responder",title:"IR Specialist",color:"#dc2626",learn:["Containment & Eradication","Ransomware Response","Recovery Planning","Crisis Management"],xp:"3,000 XP",icon:"🔴"},
            {level:"Blue Team Specialist",title:"Senior Specialist",color:"#059669",learn:["Advanced Investigations","Detection Engineering","Enterprise SecOps","Team Leadership"],xp:"5,000 XP",icon:"🏆"},
          ].map((s,i,arr)=>(
            <div key={s.level} style={{display:"flex",gap:0,position:"relative"}}>
              {/* Line */}
              {i<arr.length-1&&<div style={{position:"absolute",left:27,top:56,width:2,height:"calc(100% - 20px)",background:"#e1e4ed",zIndex:0}}/>}
              <div style={{display:"flex",gap:14,alignItems:"flex-start",padding:"0 0 28px 0",flex:1}}>
                {/* Circle */}
                <div style={{width:56,height:56,borderRadius:"50%",background:s.color+"15",border:"2px solid "+s.color,display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,flexShrink:0,position:"relative",zIndex:1,background:"#fff",boxShadow:"0 2px 8px "+s.color+"20"}}>
                  {s.icon}
                </div>
                <div style={{flex:1,background:"#fff",border:"1px solid #e1e4ed",borderRadius:12,padding:"16px",boxShadow:"0 1px 3px rgba(17,19,24,0.04)"}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                    <div>
                      <div style={{fontSize:10,fontWeight:700,color:s.color,fontFamily:"var(--mo)",letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:2}}>{s.level}</div>
                      <div style={{fontSize:15,fontWeight:700,color:"#111318"}}>{s.title}</div>
                    </div>
                    <div style={{fontSize:11,fontWeight:700,color:s.color,fontFamily:"var(--mo)",background:s.color+"10",padding:"3px 10px",borderRadius:6,border:"1px solid "+s.color+"25"}}>{s.xp}</div>
                  </div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {s.learn.map(l=>(
                      <span key={l} style={{fontSize:11.5,color:"#5a6272",background:"#f7f8fa",border:"1px solid #e1e4ed",padding:"2px 9px",borderRadius:4,fontFamily:"var(--mo)"}}>✓ {l}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── HOW IT WORKS ── */}
      <div style={{padding:"48px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>How It Works</div>
          <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#111318",marginBottom:8}}>Real Investigation Workflow</h2>
          <p style={{fontSize:14,color:"#5a6272",maxWidth:460,margin:"0 auto"}}>Every scenario follows the exact workflow used by real SOC analysts.</p>
        </div>
        <div style={{maxWidth:600,margin:"0 auto",display:"flex",flexDirection:"column",gap:0}}>
          {[
            {n:1,icon:"🚨",title:"Receive Security Alert",desc:"SIEM detects suspicious activity and fires a correlated alert.",tool:"BlueTrace SIEM",color:"#1a56db"},
            {n:2,icon:"📊",title:"Review SIEM Evidence",desc:"Analyse the correlated alert, check rules fired, and read the timeline.",tool:"BlueTrace SIEM",color:"#1a56db"},
            {n:3,icon:"🖥",title:"Investigate Endpoint Activity",desc:"Open the EDR to read the process tree, network connections, and file events.",tool:"SentinelEDR",color:"#dc2626"},
            {n:4,icon:"🔍",title:"Validate IOC Intelligence",desc:"Look up IPs, hashes, and domains to confirm if they are malicious.",tool:"ThreatLens",color:"#7c3aed"},
            {n:5,icon:"🔒",title:"Contain the Threat",desc:"Isolate the endpoint, block IOCs, and reset compromised credentials.",tool:"SentinelEDR",color:"#dc2626"},
            {n:6,icon:"📋",title:"Close the Incident",desc:"Write the IR report, document findings, and close the ticket.",tool:"IncidentDesk",color:"#059669"},
            {n:7,icon:"⚡",title:"Earn XP and Level Up",desc:"Every completed investigation earns XP and progresses your career path.",tool:"",color:"#f59e0b"},
          ].map((s,i,arr)=>(
            <div key={s.n} style={{display:"flex",gap:14,position:"relative",paddingBottom:i<arr.length-1?24:0}}>
              {i<arr.length-1&&<div style={{position:"absolute",left:20,top:44,width:2,height:"calc(100% - 16px)",background:"#e1e4ed"}}/>}
              <div style={{width:42,height:42,borderRadius:"50%",background:s.color+"12",border:"2px solid "+s.color+"40",display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,flexShrink:0,zIndex:1,background:"#fff"}}>
                {s.icon}
              </div>
              <div style={{flex:1,paddingTop:4}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3}}>
                  <div style={{fontSize:14,fontWeight:700,color:"#111318"}}>{s.title}</div>
                  {s.tool&&<span style={{fontSize:10,fontWeight:600,color:s.color,background:s.color+"10",padding:"1px 7px",borderRadius:3,fontFamily:"var(--mo)",border:"1px solid "+s.color+"25"}}>{s.tool}</span>}
                </div>
                <div style={{fontSize:13,color:"#5a6272",lineHeight:1.6}}>{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── FEATURED SCENARIOS ── */}
      <div style={{padding:"48px 20px",background:"#f7f8fa",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Live Simulations</div>
          <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#111318",marginBottom:6}}>Real Incidents. Real Investigations.</h2>
          <p style={{fontSize:14,color:"#5a6272"}}>Free during Beta. No signup required to try.</p>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:12,maxWidth:760,margin:"0 auto"}}>
          {[
            {id:"phishing-c2",icon:"🎣",title:"Spear-Phishing to C2 Beacon",diff:"Beginner",time:"25 min",xp:120,tags:["Phishing","C2","EDR","SIEM"],desc:"Finance analyst opened a macro-enabled document. EDR detected C2 beacon. LSASS credential dump in progress. Investigate and contain.",free:true},
            {id:"ransomware",icon:"💀",title:"Ransomware Staging Detected",diff:"Intermediate",time:"40 min",xp:200,tags:["Ransomware","Lateral Movement","IR"],desc:"Mass file encryption on FILE-SRV-01. Extension .locked spreading. Three endpoints actively encrypting. Stop it before backups are hit.",free:true},
            {id:"sentinel-aad",icon:"☁️",title:"Azure AD Identity Attack — MFA Fatigue",diff:"Intermediate",time:"30 min",xp:180,tags:["Identity","MFA","Cloud","ATO"],desc:"47 MFA push notifications in 8 minutes. One approved. Attacker session active from Amsterdam. Impossible travel. Active ATO.",free:false,soon:true},
          ].map(s=>(
            <div key={s.id} style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:14,padding:"18px",boxShadow:"0 1px 3px rgba(17,19,24,0.06)",cursor:s.soon?undefined:"pointer",opacity:s.soon?0.6:1}} onClick={()=>!s.soon&&nav("sim-"+s.id)}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <span style={{fontSize:24}}>{s.icon}</span>
                  <div>
                    <div style={{fontSize:15,fontWeight:700,color:"#111318",lineHeight:1.3}}>{s.title}</div>
                    <div style={{display:"flex",gap:8,marginTop:4,flexWrap:"wrap"}}>
                      <span style={{fontSize:11,color:s.diff==="Beginner"?"#16a34a":"#b45309",fontWeight:600,fontFamily:"var(--mo)"}}>{s.diff}</span>
                      <span style={{fontSize:11,color:"#8892a4",fontFamily:"var(--mo)"}}>⏱ {s.time}</span>
                      <span style={{fontSize:11,color:"#1a56db",fontWeight:600,fontFamily:"var(--mo)"}}>⚡ {s.xp} XP</span>
                    </div>
                  </div>
                </div>
                <div>{s.soon?<Pill color="gray" sm>SOON</Pill>:<Pill color="green" sm>FREE</Pill>}</div>
              </div>
              <div style={{fontSize:13,color:"#5a6272",lineHeight:1.65,marginBottom:10}}>{s.desc}</div>
              <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>{s.tags.map(t=><Tag key={t} c={t}/>)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── WHAT YOU'LL LEARN ── */}
      <div style={{padding:"48px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Curriculum</div>
          <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#111318",marginBottom:6}}>What You'll Learn</h2>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:8,maxWidth:760,margin:"0 auto"}}>
          {["Alert Triage & Classification","Phishing Investigation","Malware Analysis Basics","Threat Hunting Foundations","Threat Intelligence Lookup","Incident Response Process","Cloud Security Fundamentals","Identity Attack Investigation","EDR Investigation Techniques","SIEM Correlation Analysis","IOC Validation & Enrichment","Security Operations Reporting"].map(item=>(
            <div key={item} style={{display:"flex",gap:9,alignItems:"center",padding:"10px 12px",background:"#f7f8fa",borderRadius:8,border:"1px solid #e1e4ed"}}>
              <span style={{color:"#16a34a",fontWeight:700,fontSize:14,flexShrink:0}}>✓</span>
              <span style={{fontSize:13,color:"#2d3241",fontWeight:500}}>{item}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── WHY LEARNBLUETEAM ── */}
      <div style={{background:"#f7f8fa",borderTop:"1px solid #e1e4ed",borderBottom:"1px solid #e1e4ed",padding:"48px 20px"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Why LearnBlueTeam</div>
          <h2 style={{fontSize:"clamp(20px,4vw,26px)",fontWeight:800,color:"#111318",marginBottom:6}}>Different from everything else</h2>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(260px,1fr))",gap:12,maxWidth:860,margin:"0 auto"}}>
          {[
            ["🖥","Real SOC Workstation","Full SIEM, EDR, and Threat Intel tools on every investigation. Not a quiz. Not a video."],
            ["🎯","Step-by-Step Coaching","Your analyst coach guides every decision — what to look for, why it matters."],
            ["📱","Zero Setup","Runs in your browser in seconds. Mobile-friendly. No VMs, no downloads."],
            ["🏆","Blue Team Focused","100% defensive security. SOC, DFIR, Threat Hunting, Cloud Security."],
            ["📊","Career Progression","XP, levels, badges. A clear path from beginner to senior analyst."],
            ["📜","Verified Certificates","LearnBlueTeam Certificate of Completion. Unique verifiable ID."],
          ].map(([ic,tl,ds])=>(
            <div key={tl} style={{display:"flex",gap:13,alignItems:"flex-start",padding:"16px",background:"#fff",borderRadius:12,border:"1px solid #e1e4ed",boxShadow:"0 1px 3px rgba(17,19,24,0.04)"}}>
              <span style={{fontSize:22,flexShrink:0,marginTop:1}}>{ic}</span>
              <div>
                <div style={{fontSize:14,fontWeight:700,color:"#111318",marginBottom:3}}>{tl}</div>
                <div style={{fontSize:12.5,color:"#5a6272",lineHeight:1.6}}>{ds}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── TESTIMONIALS ── */}
      <div style={{padding:"48px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Early Access Feedback</div>
          <h2 style={{fontSize:"clamp(20px,4vw,26px)",fontWeight:800,color:"#111318"}}>What Analysts Say</h2>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:12,maxWidth:900,margin:"0 auto"}}>
          {[
            {q:"Finally understood how SIEM and EDR work together in a real investigation. No other platform shows this.",name:"Arjun M.",role:"Fresher → SOC Analyst L1",loc:"Bangalore"},
            {q:"The guided walkthrough feels like having a senior analyst sitting next to you. This is what was missing.",name:"Priya S.",role:"IT Graduate",loc:"Mumbai"},
            {q:"I've tried TryHackMe and LetsDefend. LBT is different — it's defensive, realistic, and career-focused.",name:"Rohan K.",role:"SOC Analyst",loc:"Delhi"},
          ].map(t=>(
            <div key={t.name} style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:14,padding:"20px",boxShadow:"0 1px 3px rgba(17,19,24,0.04)"}}>
              <div style={{fontSize:20,color:"#1a56db",marginBottom:8}}>❝</div>
              <div style={{fontSize:13.5,color:"#2d3241",lineHeight:1.7,marginBottom:14,fontStyle:"italic"}}>{t.q}</div>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <div style={{fontSize:13,fontWeight:700,color:"#111318"}}>{t.name}</div>
                  <div style={{fontSize:11.5,color:"#5a6272"}}>{t.role}</div>
                </div>
                <div style={{fontSize:11,color:"#8892a4",fontFamily:"var(--mo)"}}>{t.loc}</div>
              </div>
            </div>
          ))}
        </div>
        <div style={{textAlign:"center",marginTop:14,fontSize:12,color:"#8892a4"}}>
          * Testimonials from Beta access users. Names used with permission.
        </div>
      </div>

      {/* ── PRICING ── */}
      <div style={{padding:"48px 20px",background:"#f7f8fa",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:24}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Pricing</div>
          <h2 style={{fontSize:"clamp(20px,4vw,26px)",fontWeight:800,color:"#111318",marginBottom:4}}>Start free. Upgrade when ready.</h2>
          <p style={{color:"#5a6272",fontSize:13,marginBottom:14}}>UPI · Cards · Cancel anytime</p>
          <div style={{display:"inline-flex",alignItems:"center",gap:10,background:"linear-gradient(135deg,#7c3aed,#4f46e5)",borderRadius:10,padding:"10px 18px"}}>
            <span style={{fontSize:16}}>🎓</span>
            <span style={{fontSize:13,fontWeight:700,color:"#fff"}}>Students get 60% OFF on all paid plans</span>
            <span style={{background:"#fff",color:"#7c3aed",fontSize:11,fontWeight:800,padding:"2px 8px",borderRadius:5}}>60% OFF</span>
          </div>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:12,maxWidth:500,margin:"0 auto"}}>
          <div style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:14,padding:"20px"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <div><div style={{fontSize:10,fontWeight:700,letterSpacing:"0.15em",color:"#8892a4",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:2}}>FREE</div><div style={{fontSize:28,fontWeight:800,color:"#111318",fontFamily:"var(--mo)"}}>₹0</div></div>
              <div style={{fontSize:12,color:"#5a6272",textAlign:"right"}}>Try it out<br/>No credit card</div>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:5,marginBottom:14}}>
              {["2 SOC investigations (preview)","Real SOC workstation","AI coaching + XP system"].map(f=>(
                <div key={f} style={{display:"flex",gap:8}}><span style={{color:"#16a34a",fontWeight:700}}>✓</span><span style={{fontSize:13,color:"#2d3241"}}>{f}</span></div>
              ))}
              {["All 6 modules","50+ simulations","Certificates","Leaderboard"].map(f=>(
                <div key={f} style={{display:"flex",gap:8}}><span style={{color:"#d1d5db",fontWeight:700}}>✕</span><span style={{fontSize:13,color:"#9ca3af"}}>{f}</span></div>
              ))}
            </div>
            <button onClick={()=>nav("signup")} style={{width:"100%",background:"#f0f2f6",color:"#2d3241",padding:"12px",borderRadius:9,fontSize:14,fontWeight:600,border:"1px solid #e1e4ed",cursor:"pointer"}}>Get Started Free</button>
          </div>
          <div style={{background:"#fff",border:"2px solid #1a56db",borderRadius:14,padding:"20px",position:"relative",boxShadow:"0 0 0 4px rgba(26,86,219,0.07)"}}>
            <div style={{position:"absolute",top:-12,left:"50%",transform:"translateX(-50%)",background:"#1a56db",color:"#fff",padding:"2px 14px",borderRadius:100,fontSize:10,fontWeight:700,letterSpacing:"0.1em",whiteSpace:"nowrap",fontFamily:"var(--mo)"}}>MOST POPULAR</div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
              <div><div style={{fontSize:10,fontWeight:700,letterSpacing:"0.15em",color:"#1a56db",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:2}}>PRO</div><div style={{display:"flex",alignItems:"baseline",gap:5}}><span style={{fontSize:28,fontWeight:800,color:"#1a56db",fontFamily:"var(--mo)"}}>₹399</span><span style={{fontSize:13,color:"#8892a4"}}>/month</span></div><div style={{fontSize:11,color:"#7c3aed",fontWeight:600,marginTop:3}}>🎓 ₹160/mo for students</div></div>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:5,marginBottom:14}}>
              {["All 6 modules","50+ simulations","Certificate of completion","National leaderboard","Badges + achievements","Priority support"].map(f=>(
                <div key={f} style={{display:"flex",gap:8}}><span style={{color:"#16a34a",fontWeight:700}}>✓</span><span style={{fontSize:13,color:"#2d3241"}}>{f}</span></div>
              ))}
            </div>
            <button onClick={()=>nav("signup")} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"13px",borderRadius:9,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)"}}>Start Pro — ₹399/mo</button>
          </div>
          <div style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:14,padding:"20px",position:"relative"}}>
            <div style={{position:"absolute",top:-10,right:16,background:"#16a34a",color:"#fff",padding:"2px 10px",borderRadius:100,fontSize:10,fontWeight:700,fontFamily:"var(--mo)"}}>SAVE 44%</div>
            <div style={{marginBottom:4}}><div style={{fontSize:10,fontWeight:700,letterSpacing:"0.15em",color:"#8892a4",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:2}}>ANNUAL</div><div style={{display:"flex",alignItems:"baseline",gap:5}}><span style={{fontSize:28,fontWeight:800,color:"#111318",fontFamily:"var(--mo)"}}>₹2,699</span><span style={{fontSize:13,color:"#8892a4"}}>/year</span></div></div>
            <div style={{fontSize:11,color:"#16a34a",fontWeight:600,marginBottom:12}}>vs ₹4,788/yr monthly · Save ₹2,089</div>
            <div style={{fontSize:13,color:"#2d3241",marginBottom:14}}>Everything in Pro + Certification exam + LinkedIn badge + Team access (3 seats)</div>
            <button onClick={()=>nav("signup")} style={{width:"100%",background:"#f0f2f6",color:"#2d3241",padding:"12px",borderRadius:9,fontSize:14,fontWeight:600,border:"1px solid #e1e4ed",cursor:"pointer"}}>Get Annual — ₹2,699/yr</button>
            <div style={{textAlign:"center",marginTop:8,fontSize:11,color:"#8892a4"}}>🎓 Students: ₹1,079/yr</div>
          </div>
        </div>
        <div style={{background:"#fffbeb",border:"1px solid #fde68a",borderRadius:10,padding:"12px 16px",marginTop:14,display:"flex",gap:10,alignItems:"center",maxWidth:500,margin:"14px auto 0"}}>
          <span style={{fontSize:18,flexShrink:0}}>⏰</span>
          <div><div style={{fontSize:12,fontWeight:700,color:"#92400e",marginBottom:1}}>Beta pricing ends soon</div><div style={{fontSize:11.5,color:"#b45309"}}>Lock in current rates before launch pricing.</div></div>
        </div>
      </div>

      {/* ── FAQ ── */}
      <div style={{padding:"48px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>FAQ</div>
          <h2 style={{fontSize:"clamp(20px,4vw,26px)",fontWeight:800,color:"#111318"}}>Frequently Asked Questions</h2>
        </div>
        <div style={{maxWidth:660,margin:"0 auto",display:"flex",flexDirection:"column",gap:8}}>
          {[
            ["Do I need cybersecurity experience?","No. LearnBlueTeam is designed for complete beginners. Every scenario includes step-by-step coaching that explains what to do and why."],
            ["Do I need a VM or special software?","No. Everything runs in your browser. No downloads, no VMs, no Kali Linux required. Works on any device."],
            ["Can I use this on mobile?","Yes. The platform is mobile-optimised. You can investigate incidents on your phone or tablet."],
            ["How is this different from TryHackMe?","TryHackMe focuses on offensive security (hacking). LearnBlueTeam is 100% defensive — SOC, DFIR, Threat Hunting, and Incident Response."],
            ["How is this different from LetsDefend?","LetsDefend shows you alerts to classify. LearnBlueTeam simulates the full investigation workflow across multiple tools (SIEM, EDR, Threat Intel, Incident Desk)."],
            ["Do I receive a certificate?","Yes. Pro and Annual plans include a LearnBlueTeam Certificate of Completion with a unique verifiable ID."],
            ["What career path should I start with?","Start with SOC Analyst. It covers the foundational skills every defensive security professional needs regardless of their target role."],
            ["Is LearnBlueTeam affiliated with any vendor?","No. LearnBlueTeam is an independent training platform. All tool names are fictional. We are not affiliated with any cybersecurity vendor or certification body."],
          ].map(([q,a],i)=>(
            <FAQItem key={i} q={q} a={a}/>
          ))}
        </div>
      </div>

      {/* ── CTA ── */}
      <div style={{background:"#1a56db",padding:"48px 20px",textAlign:"center"}}>
        <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#fff",marginBottom:10,lineHeight:1.2}}>Start Your Investigation.<br/>No setup required.</h2>
        <p style={{color:"rgba(255,255,255,0.75)",fontSize:14,marginBottom:22}}>Join analysts training for SOC, IR, and Threat Hunting roles.</p>
        <button onClick={()=>nav("sim-phishing-c2")} style={{background:"#fff",color:"#1a56db",fontSize:15,fontWeight:700,padding:"14px 32px",borderRadius:12,border:"none",cursor:"pointer",boxShadow:"0 4px 16px rgba(0,0,0,0.15)"}}>
          Open Live Investigation →
        </button>
      </div>

      {/* ── FOOTER ── */}
      <div style={{background:"#fff",borderTop:"1px solid #e1e4ed",padding:"36px 20px 24px"}}>
        <div style={{maxWidth:900,margin:"0 auto"}}>
          <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:8,justifyContent:"center"}}>
            <Logo size={36}/>
            <div>
              <div style={{fontSize:16,fontWeight:800,color:"#111318",letterSpacing:"0.01em"}}>LEARN<span style={{color:"#1a56db"}}>BLUETEAM</span></div>
              <div style={{fontSize:9,color:"#8892a4",letterSpacing:"0.18em",fontFamily:"var(--mo)",textTransform:"uppercase"}}>Defensive · Security · Reimagined</div>
            </div>
          </div>
          <div style={{textAlign:"center",marginBottom:16}}>
            <a href="mailto:support.learnblueteam@gmail.com" style={{fontSize:13,color:"#1a56db",fontWeight:500}}>support.learnblueteam@gmail.com</a>
            <span style={{color:"#8892a4",margin:"0 8px"}}>·</span>
            <span style={{fontSize:13,color:"#8892a4"}}>www.learnblueteam.cloud</span>
          </div>
          <div style={{display:"flex",flexWrap:"wrap",justifyContent:"center",gap:"4px 0",marginBottom:16}}>
            {[["Privacy Policy","privacy"],["Terms of Service","terms"],["Refund Policy","refund"],["AI Disclaimer","ai-disclaimer"],["Data Policy","data-policy"],["Community Rules","rules"],["Contact Us","contact"]].map(([l,p],i,arr)=>(
              <span key={p} style={{display:"flex",alignItems:"center"}}>
                <button onClick={()=>nav(p)} style={{background:"none",border:"none",color:"#5a6272",fontSize:12,cursor:"pointer",padding:"4px 8px"}}>{l}</button>
                {i<arr.length-1&&<span style={{color:"#dde0e9",fontSize:10}}>·</span>}
              </span>
            ))}
          </div>
          <div style={{textAlign:"center",fontSize:11,color:"#8892a4",lineHeight:1.7}}>
            © 2026 LearnBlueTeam · All rights reserved · Mumbai, India<br/>
            LearnBlueTeam is an independent cybersecurity training platform. All scenarios, users, domains, hostnames, alerts, and environments are fictional and created for educational purposes. Any resemblance to real organisations or incidents is coincidental.<br/>
            LearnBlueTeam is not affiliated with, endorsed by, or associated with any cybersecurity vendor, certification body, or employer.
          </div>
        </div>
      </div>
    </div>
  );
}


// ── dashboard ─────────────────────────────────────────────────────────────────
function Dashboard({nav,appUser,prog,lvlPct}) {
  const allSims=Object.values(SCENARIOS);
  return (
    <div style={{padding:"20px"}}>
      <div style={{marginBottom:24}}>
        <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.15em",color:"var(--ac)",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:4}}>Welcome back</div>
        <div style={{fontSize:24,fontWeight:700,color:"var(--tx)",marginBottom:2}}>{appUser?.name||"Analyst"}</div>
        <div style={{fontSize:13,color:"var(--tx3)"}}>{lvlTitle(prog.level)} · Level {prog.level} · {prog.xp} XP</div>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
        {[["XP",prog.xp.toLocaleString(),"var(--ac)"],["Level",prog.level,"var(--ok)"],["Done",Object.keys(prog.done).length+"/"+allSims.length,"#7c3aed"],["Streak",(prog.streak||0)+"d","var(--warn)"]].map(([l,v,c])=>(
          <div key={l} style={{background:"var(--w)",border:"1px solid var(--bd)",borderRadius:12,padding:"16px",boxShadow:"var(--sh)"}}>
            <div style={{fontSize:24,fontWeight:700,color:c,fontFamily:"var(--mo)",marginBottom:3}}>{v}</div>
            <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",letterSpacing:"0.1em",textTransform:"uppercase"}}>{l}</div>
          </div>
        ))}
      </div>

      <div style={{background:"var(--w)",border:"1px solid var(--bd)",borderRadius:12,padding:"16px",marginBottom:24,boxShadow:"var(--sh)"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
          <span style={{fontSize:13,fontWeight:600,color:"var(--tx)"}}>Level {prog.level} → {prog.level+1}</span>
          <span style={{fontSize:11,color:"var(--tx3)",fontFamily:"var(--mo)"}}>{500-(prog.xp%500)} XP to go</span>
        </div>
        <div style={{height:8,background:"var(--bg3)",borderRadius:4,overflow:"hidden"}}>
          <div style={{height:"100%",width:lvlPct()+"%",background:"var(--ac)",borderRadius:4,transition:"width 0.5s"}}/>
        </div>
      </div>

      <div style={{fontSize:12,fontWeight:700,color:"var(--tx)",marginBottom:14,letterSpacing:"0.05em",textTransform:"uppercase"}}>Simulations</div>
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        {allSims.map(s=>{
          const d=prog.done[s.id];
          return (
            <div key={s.id} onClick={()=>nav("sim-"+s.id)} style={{background:"var(--w)",border:"1px solid var(--bd)",borderRadius:14,padding:"18px",cursor:"pointer",boxShadow:"var(--sh)",position:"relative",transition:"all 0.13s"}}>
              <div style={{position:"absolute",top:16,right:16}}>
                {d?<Pill color="green" sm>Done · {d.grade}</Pill>:<Pill color="blue" sm>Play</Pill>}
              </div>
              <div style={{marginBottom:8}}><Pill color={s.difficulty==="Easy"?"green":"amber"} sm>{s.difficulty}</Pill></div>
              <div style={{fontSize:16,fontWeight:700,color:"var(--tx)",marginBottom:4,paddingRight:70,lineHeight:1.3}}>{s.title}</div>
              <div style={{fontSize:12.5,color:"var(--tx3)",lineHeight:1.6,marginBottom:12}}>{s.brief.slice(0,80)}...</div>
              <div style={{display:"flex",gap:14,fontSize:11.5,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:10}}>
                <span>⏱ {s.duration}m</span><span>⭐ {s.xpReward} XP</span>
              </div>
              <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>{s.tags.map(t=><Tag key={t} c={t}/>)}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── auth ──────────────────────────────────────────────────────────────────────
function AuthPage({nav,mode,saveUser}) {
  const [form,setForm]=useState({name:"",email:"",password:""});
  const [err,setErr]=useState("");
  const [loading,setLoading]=useState(false);
  const handle=async(e)=>{
    e.preventDefault();
    if(mode==="signup"&&!form.name.trim()){setErr("Name is required");return;}
    if(!form.email.includes("@")){setErr("Enter a valid email");return;}
    if(form.password.length<6){setErr("Password must be at least 6 characters");return;}
    setLoading(true);
    await new Promise(r=>setTimeout(r,700));
    setLoading(false);
    saveUser({name:form.name||form.email.split("@")[0],email:form.email});
    nav("dash");
  };
  const inp={width:"100%",padding:"12px 14px",border:"1px solid #d1d5db",borderRadius:8,fontSize:14,fontFamily:"var(--fn)",outline:"none",background:"#fff",color:"#111318"};
  return (
    <div style={{minHeight:"80vh",display:"flex",alignItems:"center",justifyContent:"center",padding:20,background:"var(--bg)"}}>
      <div style={{width:"100%",maxWidth:400}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{margin:"0 auto 14px",width:48,height:48,display:"flex",alignItems:"center",justifyContent:"center"}}><Logo size={48}/></div>
          <div style={{fontSize:22,fontWeight:700,color:"var(--tx)",marginBottom:5}}>{mode==="login"?"Welcome back":"Create your account"}</div>
          <div style={{color:"var(--tx3)",fontSize:14}}>{mode==="login"?"Continue your training":"Free access during Beta"}</div>
        </div>
        <div style={{background:"var(--w)",border:"1px solid var(--bd)",borderRadius:16,padding:24,boxShadow:"var(--sh2)"}}>
          <form onSubmit={handle}>
            {mode==="signup"&&(
              <div style={{marginBottom:14}}>
                <label style={{fontSize:13,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:7}}>Full Name</label>
                <input style={inp} placeholder="Your name" value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))}/>
              </div>
            )}
            <div style={{marginBottom:14}}>
              <label style={{fontSize:13,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:7}}>Email</label>
              <input style={inp} type="email" placeholder="you@example.com" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))}/>
            </div>
            <div style={{marginBottom:20}}>
              <label style={{fontSize:13,fontWeight:600,color:"var(--tx2)",display:"block",marginBottom:7}}>Password</label>
              <input style={inp} type="password" placeholder="Min 6 characters" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))}/>
            </div>
            {err&&<div style={{background:"var(--errl)",border:"1px solid var(--errb)",color:"var(--err)",padding:"10px 13px",borderRadius:8,fontSize:13,marginBottom:14}}>{err}</div>}
            <button type="submit" disabled={loading} style={{width:"100%",background:"var(--ac)",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:600,border:"none",cursor:"pointer",opacity:loading?0.7:1,boxShadow:"0 4px 14px rgba(26,86,219,0.3)"}}>
              {loading?"Loading...":mode==="login"?"Login →":"Create Account — Free →"}
            </button>
          </form>
          <div style={{textAlign:"center",marginTop:16,fontSize:13.5,color:"var(--tx3)"}}>
            {mode==="login"
              ?<span>No account? <button onClick={()=>nav("signup")} style={{background:"none",border:"none",color:"var(--ac)",fontWeight:600,cursor:"pointer",fontSize:13.5}}>Sign up free</button></span>
              :<span>Have an account? <button onClick={()=>nav("login")} style={{background:"none",border:"none",color:"var(--ac)",fontWeight:600,cursor:"pointer",fontSize:13.5}}>Login</button></span>
            }
          </div>
        </div>
      </div>
    </div>
  );
}

// ── app shell ─────────────────────────────────────────────────────────────────
export default function App() {
  const [page,setPage]=useState("landing");
  const [simId,setSimId]=useState("phishing-c2");
  const {user,saveUser,prog,addXP,finishSim,lvlPct}=useApp();
  const SCENARIO_TO_INC={"phishing-c2":"INC-2026-0441","ransomware":"INC-2026-0441"};
  const nav=p=>{
    if(p.startsWith("sim-")){
      const key=p.replace("sim-","");
      setSimId(SCENARIO_TO_INC[key]||key);
      setPage("sim");
    } else setPage(p);
    window.scrollTo(0,0);
  };
  const isSim=page==="sim";
  return (
    <div style={{fontFamily:"var(--fn)",background:"var(--bg)",color:"var(--tx)",minHeight:"100vh"}}>
      <style>{CSS}</style>
      {!isSim&&(
        <nav style={{position:"sticky",top:0,zIndex:100,background:"rgba(255,255,255,0.96)",backdropFilter:"blur(12px)",borderBottom:"1px solid var(--bd)",padding:"0 16px",height:54,display:"flex",alignItems:"center",justifyContent:"space-between",boxShadow:"var(--sh)"}}>
          <div onClick={()=>nav("landing")} style={{cursor:"pointer",display:"flex",alignItems:"center",gap:8}}>
            <Logo size={28}/>
            <div><span style={{fontSize:13,fontWeight:800,color:"var(--tx)"}}>LEARN</span><span style={{fontSize:13,fontWeight:800,color:"var(--ac)"}}>BLUETEAM</span></div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            {user?(
              <button onClick={()=>nav("dash")} style={{display:"flex",alignItems:"center",gap:6,background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"7px 12px",cursor:"pointer"}}>
                <div style={{width:22,height:22,borderRadius:"50%",background:"var(--acl)",border:"1.5px solid var(--ac)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:"var(--ac)",fontFamily:"var(--mo)"}}>{prog.level}</div>
                <span style={{fontSize:13,color:"var(--tx2)",fontWeight:500}}>{user.name.split(" ")[0]}</span>
              </button>
            ):(
              <button onClick={()=>nav("login")} style={{background:"none",border:"1px solid var(--bd)",color:"var(--tx2)",fontSize:13,fontWeight:500,padding:"7px 12px",borderRadius:8,cursor:"pointer"}}>Login</button>
            )}
            <button onClick={()=>nav("sim-phishing-c2")} style={{background:"var(--ac)",color:"#fff",fontSize:13,fontWeight:600,padding:"8px 14px",borderRadius:8,border:"none",cursor:"pointer",boxShadow:"0 2px 8px rgba(26,86,219,0.3)"}}>Open SOC</button>
          </div>
        </nav>
      )}
      {page==="landing"      && <Landing nav={nav} appUser={user}/>}
      {page==="sim"          && <SOCConsole incId={simId} prog={prog} addXP={addXP} finishSim={finishSim} onBack={()=>nav("dash")} analyst={{name:user?.name||"Analyst",tier:"SOC Analyst I",id:"ANLST-"+(user?.email?.slice(0,3).toUpperCase()||"047"),team:"Blue Team Alpha"}}/>}
      {page==="dash"         && (user?<Dashboard nav={nav} appUser={user} prog={prog} lvlPct={lvlPct}/>:<AuthPage nav={nav} mode="signup" saveUser={saveUser}/>)}
      {page==="login"        && <AuthPage nav={nav} mode="login"  saveUser={saveUser}/>}
      {page==="signup"       && <AuthPage nav={nav} mode="signup" saveUser={saveUser}/>}
      {["privacy","terms","refund","ai-disclaimer","data-policy","rules"].includes(page) && <PolicyPage policyKey={page} nav={nav}/>}
      {page==="contact" && <ContactPage nav={nav}/>}
    </div>
  );
}
