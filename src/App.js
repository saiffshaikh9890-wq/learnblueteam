import React, { useState, useEffect, useRef } from "react";

class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = {hasError:false,error:null}; }
  static getDerivedStateFromError(error) { return {hasError:true,error}; }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{padding:40,fontFamily:"monospace",background:"#0f1117",color:"#e8ecf4",minHeight:"100vh",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:16}}>
          <div style={{fontSize:32}}>⚠</div>
          <div style={{fontSize:18,fontWeight:700}}>Something went wrong</div>
          <div style={{fontSize:12,color:"#6b7280",maxWidth:400,textAlign:"center"}}>{this.state.error?.message}</div>
          <button onClick={()=>window.location.reload()} style={{background:"#1a56db",color:"#fff",padding:"10px 20px",borderRadius:8,border:"none",cursor:"pointer",fontSize:14}}>Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INVESTIGATION ZERO — Beginner onboarding scenario
// ─────────────────────────────────────────────────────────────────────────────

const INVESTIGATION_ZERO = {
  id:"investigation-zero",
  title:"Welcome to Security Operations",
  subtitle:"Before your first real investigation, learn how a SOC works.",
  difficulty:"Beginner",
  duration:10,
  xpReward:50,
  locked:false,
  lessons:[
    {
      id:0,
      title:"What is a Security Alert?",
      icon:"🚨",
      analogy:"Think of a security alert like a smoke detector going off in a building. The detector doesn't know if it's a real fire, burnt toast, or a candle — it just knows something triggered it. Your job as an analyst is to investigate and find out.",
      concept:"A security alert is an automated notification that something suspicious has been detected. It could be a real attack (True Positive) or a harmless event that looks suspicious (False Positive).",
      example:{
        label:"Real Alert Example",
        content:"ALERT: Unusual outbound connection from WS-CORP-FIN-044\nDestination: 203.0.113.47 (Russia)\nTime: 08:17:33\nProcess: svchost32.exe\nRisk Score: 97/100"
      },
      question:"Based on a risk score of 97/100 and a connection to a foreign IP — what would you do first?",
      options:[
        {text:"Ignore it — probably nothing", correct:false, explanation:"A 97/100 risk score is almost never noise. Always investigate high-risk alerts."},
        {text:"Investigate immediately — this looks serious", correct:true, explanation:"Correct. High risk scores + foreign IPs are red flags. You open the incident and start investigating."},
        {text:"Wait for your manager to decide", correct:false, explanation:"SOC analysts are expected to triage alerts independently. Waiting costs valuable response time."},
      ]
    },
    {
      id:1,
      title:"What is a SIEM?",
      icon:"📊",
      analogy:"A SIEM is like a security camera control room. Imagine a shopping mall with 500 cameras. No human can watch them all. The SIEM watches everything automatically and alerts you when something looks wrong — like a camera detecting someone trying to break into a store.",
      concept:"SIEM stands for Security Information and Event Management. It collects logs from every system in the organisation — computers, servers, firewalls, email — and correlates them to detect suspicious patterns.",
      example:{
        label:"What a SIEM does",
        content:"Log from Email Gateway: Macro-enabled file delivered to analyst.user\n+ Log from Endpoint: Word.exe spawned cmd.exe\n+ Log from Network: Unknown process connecting to foreign IP\n= SIEM fires: CRITICAL alert — Possible malware infection"
      },
      question:"Why is a SIEM useful for a SOC analyst?",
      options:[
        {text:"It automatically fixes security problems", correct:false, explanation:"SIEM detects — it doesn't fix. Analysts investigate and take action."},
        {text:"It correlates events from multiple sources to spot attacks humans would miss", correct:true, explanation:"Exactly. One log alone means nothing. Combined with others, it tells a story."},
        {text:"It replaces the need for analysts", correct:false, explanation:"SIEM is a tool. Analysts are the decision-makers who determine what the alerts mean."},
      ]
    },
    {
      id:2,
      title:"What is an EDR?",
      icon:"🖥",
      analogy:"An EDR is like CCTV inside every computer. Regular antivirus is like a bouncer checking IDs at the door — it only stops known threats. An EDR records everything happening inside the building. Every program that runs, every file created, every network connection made. If something bad happens, you can rewind the tape.",
      concept:"EDR stands for Endpoint Detection and Response. It runs on every computer (endpoint) and records all activity — processes, files, network connections. Analysts use it to trace exactly what happened during an attack.",
      example:{
        label:"What the EDR shows during an attack",
        content:"OUTLOOK.EXE (email opened)\n  └─ WINWORD.EXE (document opened)\n      └─ cmd.exe (macro ran a command) ← suspicious\n          └─ powershell.exe (downloaded something) ← very suspicious\n              └─ svchost32.exe (connecting to foreign IP) ← malware"
      },
      question:"An analyst opens the EDR and sees Word.exe spawning cmd.exe. What does this suggest?",
      options:[
        {text:"Normal — Word uses cmd.exe all the time", correct:false, explanation:"Word should NEVER spawn cmd.exe in normal operation. This is a classic sign of a malicious macro."},
        {text:"A macro inside the Word document executed a command — likely malicious", correct:true, explanation:"Correct. This parent-child relationship is a major red flag and one of the first things analysts look for."},
        {text:"The user opened a command prompt manually", correct:false, explanation:"If the user opened CMD themselves, it would show explorer.exe as the parent, not winword.exe."},
      ]
    },
    {
      id:3,
      title:"What is Threat Intelligence?",
      icon:"🔍",
      analogy:"Threat intelligence is like a database of known criminals. If a suspicious person walks into a bank and their face matches a criminal database — security acts immediately. In cybersecurity, instead of faces, we check IPs, domains, and file hashes against known malicious databases.",
      concept:"Threat Intelligence (TI) helps analysts validate whether indicators — IP addresses, domains, file hashes — are known to be malicious. If 67 out of 72 antivirus engines flag a file, that's a very strong signal.",
      example:{
        label:"ThreatLens lookup result",
        content:"IP: 203.0.113.47\nAbuseIPDB Score: 100/100\nCategory: Tor Exit Node / C2 Infrastructure\nCountry: Russia\nLast Reported: Today\nVerdict: MALICIOUS — Block immediately"
      },
      question:"You look up an IP address and it scores 100/100 on AbuseIPDB. What do you conclude?",
      options:[
        {text:"It might be fine — scores can be wrong", correct:false, explanation:"A 100/100 score from AbuseIPDB means it has been reported by hundreds of users as malicious. Act on it."},
        {text:"This IP is almost certainly malicious — block it and document it as an IOC", correct:true, explanation:"Correct. IOC stands for Indicator of Compromise. This IP is one. You block it and add it to your report."},
        {text:"Look up a different tool to be sure", correct:false, explanation:"Cross-referencing is good practice, but a 100/100 score is already conclusive. Containment first, validation after."},
      ]
    },
    {
      id:4,
      title:"What is an Incident Ticket?",
      icon:"📋",
      analogy:"An incident ticket is like a case file for a detective. Every finding, every action, every piece of evidence gets documented. When the case is closed, the file tells the complete story of what happened, what was done, and what still needs attention.",
      concept:"Every security investigation is tracked as an incident ticket. It records: what happened, who investigated, what tools were used, what was found, what actions were taken, and what the outcome was. This is your legal and operational record.",
      example:{
        label:"Sample incident ticket",
        content:"INC-2026-0441 | P1 Critical | OPEN\nTitle: Suspected C2 Beacon — WS-CORP-FIN-044\nAssigned: You\nSLA: 60 minutes\nStatus: In Progress\nActions: Alert classified TP | EDR analysis in progress"
      },
      question:"Why is documentation in the incident ticket important?",
      options:[
        {text:"It's just bureaucracy — the real work is investigation", correct:false, explanation:"Documentation IS part of the work. In real incidents, auditors, managers, and legal teams review your notes."},
        {text:"It creates a record for review, compliance, and learning from past incidents", correct:true, explanation:"Correct. Good documentation is what separates junior analysts from senior ones."},
        {text:"Only managers need to document things", correct:false, explanation:"Every analyst documents. A SOC that doesn't document is flying blind."},
      ]
    },
  ]
};


// ── colour helpers ────────────────────────────────────────────────────────────
function sc(s) {
  if (s==="Critical") return {dot:"#dc2626",bg:"rgba(220,38,38,0.08)",cl:"#dc2626",br:"rgba(220,38,38,0.22)"};
  if (s==="High")     return {dot:"#ea580c",bg:"rgba(234,88,12,0.08)", cl:"#ea580c",br:"rgba(234,88,12,0.22)"};
  if (s==="Intermediate")   return {dot:"#d97706",bg:"rgba(217,119,6,0.08)", cl:"#b45309",br:"rgba(217,119,6,0.22)"};
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

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE CLIENT
// Replace the URL and ANON KEY with your actual Supabase project values
// Get them from: supabase.com → your project → Settings → API
// ─────────────────────────────────────────────────────────────────────────────

const SUPABASE_URL = "https://gfprfirlffellsmpciwk.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdmcHJmaXJsZmZlbGxzbXBjaXdrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODAwNjQxODgsImV4cCI6MjA5NTY0MDE4OH0.f1QDkhLmSszWCvXF-HRMHNBUDIFAqceEw24nPHXZjIo";

async function supabaseRequest(path, options = {}) {
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
      headers: {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": `Bearer ${SUPABASE_ANON_KEY}`,
        "Content-Type": "application/json",
        "Prefer": options.prefer || "return=representation",
        ...options.headers,
      },
      ...options,
    });
    if (!res.ok) return null;
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  } catch { return null; }
}

async function supabaseAuth(action, body) {
  try {
    const res = await fetch(`${SUPABASE_URL}/auth/v1/${action}`, {
      method: "POST",
      headers: {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    return await res.json();
  } catch { return null; }
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE HOOK — replaces useApp
// ─────────────────────────────────────────────────────────────────────────────

function useSupabase() {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("lbt_user") || "null"); } catch { return null; }
  });
  const [prog, setProg] = useState(() => {
    try { return JSON.parse(localStorage.getItem("lbt_prog") || '{"xp":0,"level":1,"done":{}}'); }
    catch { return {xp:0,level:1,done:{}}; }
  });
  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState(null);

  const saveProg = async (p) => {
    setProg(p);
    try { localStorage.setItem("lbt_prog", JSON.stringify(p)); } catch {}
    // Sync to Supabase
    const token = localStorage.getItem("lbt_token");
    const uid = JSON.parse(localStorage.getItem("lbt_user")||"null")?.id;
    if (token && uid) {
      fetch(`${SUPABASE_URL}/rest/v1/analyst_profiles?id=eq.${uid}`, {
        method:"PATCH",
        headers:{"apikey":SUPABASE_ANON_KEY,"Authorization":`Bearer ${token}`,
          "Content-Type":"application/json","Prefer":"return=minimal"},
        body:JSON.stringify({xp:p.xp,level:p.level,
          completed_scenarios:JSON.stringify(p.done),
          updated_at:new Date().toISOString()})
      }).catch(()=>{});
    }
  };

  const signup = async (name, email, password) => {
    setLoading(true); setAuthError(null);
    try {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
        method:"POST",
        headers:{"apikey":SUPABASE_ANON_KEY,"Content-Type":"application/json"},
        body:JSON.stringify({email, password, data:{name}})
      });
      const data = await res.json();
      if (data?.user) {
        const token = data.access_token;
        // If no token = email confirmation required
        if (!token) {
          setLoading(false);
          // Save locally so they can still use the app
          const u = {id:data.user.id, name, email, pendingConfirm:true};
          localStorage.setItem("lbt_user", JSON.stringify(u));
          setUser(u);
          return {success:true, needsConfirm:true};
        }
        const u = {id:data.user.id, name, email};
        localStorage.setItem("lbt_user", JSON.stringify(u));
        localStorage.setItem("lbt_token", token);
        setUser(u);
        fetch(`${SUPABASE_URL}/rest/v1/analyst_profiles`, {
          method:"POST",
          headers:{"apikey":SUPABASE_ANON_KEY,"Authorization":`Bearer ${token}`,
            "Content-Type":"application/json","Prefer":"return=minimal"},
          body:JSON.stringify({id:data.user.id,name,email,xp:0,level:1,
            completed_scenarios:"{}",created_at:new Date().toISOString()})
        }).catch(()=>{});
        setLoading(false);
        return {success:true};
      }
      const msg = data?.msg || data?.error_description || data?.message || "Signup failed. Try a different email.";
      setAuthError(msg); setLoading(false);
      return {success:false, error:msg};
    } catch(e) {
      setAuthError("Network error. Please try again.");
      setLoading(false);
      return {success:false, error:"Network error."};
    }
  };

  const login = async (email, password) => {
    setLoading(true); setAuthError(null);
    try {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
        method:"POST",
        headers:{"apikey":SUPABASE_ANON_KEY,"Content-Type":"application/json"},
        body:JSON.stringify({email, password})
      });
      const data = await res.json();
      if (data?.access_token) {
        const token = data.access_token;
        const name = data.user?.user_metadata?.name || email.split("@")[0];
        const u = {id:data.user.id, name, email};
        localStorage.setItem("lbt_user", JSON.stringify(u));
        localStorage.setItem("lbt_token", token);
        setUser(u);
        // Load progress from DB
        fetch(`${SUPABASE_URL}/rest/v1/analyst_profiles?id=eq.${u.id}&select=*`, {
          headers:{"apikey":SUPABASE_ANON_KEY,"Authorization":`Bearer ${token}`}
        }).then(r=>r.json()).then(rows=>{
          if(rows?.[0]) {
            const p = {xp:rows[0].xp||0, level:rows[0].level||1,
              done:JSON.parse(rows[0].completed_scenarios||"{}")};
            setProg(p);
            localStorage.setItem("lbt_prog", JSON.stringify(p));
          }
        }).catch(()=>{});
        setLoading(false);
        return {success:true};
      }
      const msg = data?.error_description || "Invalid email or password.";
      setAuthError(msg); setLoading(false);
      return {success:false, error:msg};
    } catch(e) {
      setAuthError("Network error. Please try again.");
      setLoading(false);
      return {success:false, error:"Network error."};
    }
  };

  const logout = () => {
    setUser(null);
    try {
      localStorage.removeItem("lbt_user");
      localStorage.removeItem("lbt_token");
    } catch {}
  };

  const addXP = (n) => {
    const nx = prog.xp + n;
    const nl = Math.max(1, Math.floor(nx/500)+1);
    saveProg({...prog, xp:nx, level:nl});
  };

  const finishSim = (id, score, grade, sec) => {
    saveProg({...prog, done:{...prog.done, [id]:{score,grade,sec,at:Date.now()}}});
  };

  const submitFeedback = async (incId, rating, difficulty, recommend, comment) => {
    try {
      const token = localStorage.getItem("lbt_token");
      if (!token) return;
      fetch(`${SUPABASE_URL}/rest/v1/investigation_feedback`, {
        method:"POST",
        headers:{"apikey":SUPABASE_ANON_KEY,"Authorization":`Bearer ${token}`,
          "Content-Type":"application/json","Prefer":"return=minimal"},
        body:JSON.stringify({user_id:user?.id, incident_id:incId,
          rating, difficulty, recommend, comment,
          created_at:new Date().toISOString()})
      }).catch(()=>{});
    } catch {}
  };

  const lvlPct = () => Math.min(99, Math.round(((prog.xp%500)/500)*100));

  return {user,prog,loading,authError,signup,login,logout,addXP,finishSim,submitFeedback,lvlPct};
}



// ─────────────────────────────────────────────────────────────────────────────
// POST-INVESTIGATION FEEDBACK MODAL
// ─────────────────────────────────────────────────────────────────────────────

function FeedbackModal({ incId, onClose, onSubmit }) {
  const [rating, setRating] = useState(0);
  const [difficulty, setDifficulty] = useState("");
  const [recommend, setRecommend] = useState("");
  const [comment, setComment] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const submit = async () => {
    await onSubmit(incId, rating, difficulty, recommend, comment);
    setSubmitted(true);
    setTimeout(onClose, 2000);
  };

  const stars = [1,2,3,4,5];

  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.6)",backdropFilter:"blur(4px)",zIndex:900,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <div style={{background:"#fff",borderRadius:16,padding:24,maxWidth:440,width:"100%",boxShadow:"0 8px 32px rgba(0,0,0,0.15)"}}>
        {submitted ? (
          <div style={{textAlign:"center",padding:"20px 0"}}>
            <div style={{fontSize:40,marginBottom:10}}>🙏</div>
            <div style={{fontSize:17,fontWeight:700,color:"#111318",marginBottom:4}}>Thank you!</div>
            <div style={{fontSize:13,color:"#6b7280"}}>Your feedback helps us improve LearnBlueTeam.</div>
          </div>
        ) : (
          <>
            <div style={{marginBottom:18}}>
              <div style={{fontSize:10,fontWeight:700,color:"#1a56db",letterSpacing:"0.15em",fontFamily:"monospace",marginBottom:4,textTransform:"uppercase"}}>Beta Feedback</div>
              <div style={{fontSize:16,fontWeight:700,color:"#111318"}}>How was this investigation?</div>
            </div>

            {/* Star rating */}
            <div style={{marginBottom:16}}>
              <div style={{fontSize:12,fontWeight:600,color:"#374151",marginBottom:8}}>Overall rating</div>
              <div style={{display:"flex",gap:8}}>
                {stars.map(s => (
                  <button key={s} onClick={() => setRating(s)} style={{fontSize:24,background:"none",border:"none",cursor:"pointer",opacity:s<=rating?1:0.3,transition:"all 0.1s"}}>⭐</button>
                ))}
              </div>
            </div>

            {/* Difficulty */}
            <div style={{marginBottom:14}}>
              <div style={{fontSize:12,fontWeight:600,color:"#374151",marginBottom:8}}>Difficulty felt:</div>
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                {["Too easy","Just right","Too hard","Overwhelming"].map(d => (
                  <button key={d} onClick={() => setDifficulty(d)} style={{padding:"6px 12px",borderRadius:6,border:"1px solid "+(difficulty===d?"#1a56db":"#e1e4ed"),background:difficulty===d?"rgba(26,86,219,0.08)":"#f7f8fa",color:difficulty===d?"#1a56db":"#374151",fontSize:12,fontWeight:difficulty===d?600:400,cursor:"pointer"}}>{d}</button>
                ))}
              </div>
            </div>

            {/* Recommend */}
            <div style={{marginBottom:14}}>
              <div style={{fontSize:12,fontWeight:600,color:"#374151",marginBottom:8}}>Would you recommend LBT to others?</div>
              <div style={{display:"flex",gap:6}}>
                {["Yes","Maybe","No"].map(r => (
                  <button key={r} onClick={() => setRecommend(r)} style={{flex:1,padding:"8px",borderRadius:6,border:"1px solid "+(recommend===r?"#1a56db":"#e1e4ed"),background:recommend===r?"rgba(26,86,219,0.08)":"#f7f8fa",color:recommend===r?"#1a56db":"#374151",fontSize:13,fontWeight:recommend===r?600:400,cursor:"pointer"}}>{r}</button>
                ))}
              </div>
            </div>

            {/* Comment */}
            <div style={{marginBottom:18}}>
              <div style={{fontSize:12,fontWeight:600,color:"#374151",marginBottom:6}}>Any comments? (optional)</div>
              <textarea value={comment} onChange={e=>setComment(e.target.value)} placeholder="What worked well? What was confusing? What should we improve?" style={{width:"100%",minHeight:80,padding:"9px 11px",border:"1px solid #e1e4ed",borderRadius:8,fontSize:13,fontFamily:"inherit",color:"#111318",background:"#f7f8fa",resize:"vertical",outline:"none",lineHeight:1.5}}/>
            </div>

            <div style={{display:"flex",gap:8}}>
              <button onClick={onClose} style={{flex:1,padding:"11px",borderRadius:8,border:"1px solid #e1e4ed",background:"#f7f8fa",color:"#6b7280",fontSize:13,cursor:"pointer"}}>Skip</button>
              <button onClick={submit} disabled={rating===0} style={{flex:2,padding:"11px",borderRadius:8,border:"none",background:rating>0?"#1a56db":"#e1e4ed",color:rating>0?"#fff":"#9ca3af",fontSize:13,fontWeight:600,cursor:rating>0?"pointer":"default",transition:"all 0.15s"}}>
                Submit Feedback
              </button>
            </div>
          </>
        )}
      </div>
      <FeedbackButton submitFeedback={submitFeedback}/>
    </div>
  );
}


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
  "phishing-c2":{id:"phishing-c2",incId:"INC-2026-0441",title:"Spear-Phishing to C2 Beacon",difficulty:"Beginner",duration:25,xpReward:120,category:"SOC L1",tags:["Phishing","C2","EDR"],brief:"Finance analyst opened a macro-enabled document. EDR detected C2 beacon. LSASS dump in progress. Investigate and contain.",type:"TP",concept:"Malware investigation"},
  "fp-powershell":{id:"fp-powershell",incId:"INC-2026-0502",title:"IT Admin PowerShell — False Positive?",difficulty:"Beginner",duration:20,xpReward:80,category:"SOC L1",tags:["PowerShell","False Positive","Triage"],brief:"Encoded PowerShell on a management server at 02:30. Service account. Overnight timing. Is this a real threat — or noise?",type:"FP",concept:"False positive identification"},
  "impossible-travel":{id:"impossible-travel",incId:"INC-2026-0521",title:"Impossible Travel — Account Takeover",difficulty:"Beginner",duration:30,xpReward:150,category:"SOC L1",tags:["Azure AD","MFA Fatigue","Identity"],brief:"Login from Mumbai and Amsterdam 4 minutes apart. 47 MFA pushes. One approved. Attacker live in the account right now.",type:"TP",concept:"Identity attack investigation"},
  "fp-vuln-scan":{id:"fp-vuln-scan",incId:"INC-2026-0544",title:"Vulnerability Scanner — False Positive?",difficulty:"Beginner",duration:15,xpReward:60,category:"SOC L1",tags:["Port Scan","False Positive","Scanner"],brief:"Internal IP scanning 847 hosts on standard ports. Looks like reconnaissance. Is it an attacker — or your own security team?",type:"FP",concept:"Scanner vs attacker recognition"},
  "usb-insider":{id:"usb-insider",incId:"INC-2026-0561",title:"Malicious USB — Insider Threat",difficulty:"Intermediate",duration:30,xpReward:160,category:"SOC L1",tags:["USB","Insider","DLP","Data Exfiltration"],brief:"Departing employee copied 4.7GB of HR compensation data to USB on their penultimate day. robocopy. CONFIDENTIAL files. Investigate.",type:"TP",concept:"Insider threat investigation"},
  "dns-beacon":{id:"dns-beacon",incId:"INC-2026-0578",title:"DNS Beaconing — C2 Over DNS",difficulty:"Intermediate",duration:30,xpReward:170,category:"SOC L1",tags:["DNS","C2","IcedID","Threat Hunting"],brief:"2,847 DNS queries in 4 hours to randomised subdomains. No TCP connections. UpdateService.exe in AppData. Investigate the silent beacon.",type:"TP",concept:"DNS C2 detection"},
  "fp-pentest":{id:"fp-pentest",incId:"INC-2026-0591",title:"Security Team Pentest — False Positive?",difficulty:"Intermediate",duration:20,xpReward:90,category:"SOC L1",tags:["Nmap","PentestKit","False Positive","Pentest"],brief:"Nmap and PentestKit detected on an internal workstation. Scanning the entire internal subnet. No Change Ticket. Attack or authorized test?",type:"FP",concept:"Authorized security activity recognition"},
  "bec-fraud":{id:"bec-fraud",incId:"INC-2026-0612",title:"Business Email Compromise — CFO Fraud",difficulty:"Intermediate",duration:25,xpReward:180,category:"SOC L1",tags:["BEC","Wire Transfer","Email Fraud","Social Engineering"],brief:"Email from 'CFO Rajesh Mehta' requesting ₹47L wire transfer. From rajesh.mehta@corp.com — not corp.internal. Payment not yet processed.",type:"TP",concept:"BEC investigation"},
  "s3-exposure":{id:"s3-exposure",incId:"INC-2026-0634",title:"Public AWS S3 Bucket — Data Exposed",difficulty:"Advanced",duration:35,xpReward:200,category:"SOC L1",tags:["AWS","S3","Cloud","PII","Misconfiguration"],brief:"127,000 customer records in a public S3 bucket for 3 days. Security researcher reported it. CloudTrail shows 2,847 external access requests.",type:"TP",concept:"Cloud security incident response"},
  "fp-auth-storm":{id:"fp-auth-storm",incId:"INC-2026-0651",title:"Auth Failure Storm — Brute Force or System Change?",difficulty:"Advanced",duration:25,xpReward:110,category:"SOC L1",tags:["Authentication","Brute Force","False Positive","AD"],brief:"3,847 auth failures across 1,247 accounts in 10 minutes. All internal IPs. Zero successful logins. Brute force — or something operational?",type:"FP",concept:"Operational noise vs real attacks"},
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
  user:"analyst.user@corp.internal",
  srcIp:"10.10.44.112",
  c2Ip:"203.0.113.47",
  assignee:null,
  tags:["Phishing","C2","Credential Theft","LSASS"],
  summary:"BlueTrace SIEM correlated 4 rules on WS-CORP-FIN-044. Finance user opened macro-enabled document at 08:17. EDR detected process injection into lsass.exe. Outbound beacon to 203.0.113.47:443 (geo: RU, Tor exit). Incident auto-promoted to Critical by correlation engine.",
  mitre:["T1566.001","T1059.001","T1071.001","T1003.001","T1547.001"],

  // ── BLUETRACE SIEM ─────────────────────────────────────────────────────────
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-4471 — Macro Document + Child Process + Outbound C2",
    fired_at: tsNow(0),
    risk_score:97,
    alerts:[
      {id:"BT-9901",time:"08:17:33",sev:"Critical",rule:"OUTBOUND_C2_BEACON",src:"EDR",msg:"svchost32.exe beaconing 203.0.113.47:443 every 30s — process parent chain: OUTLOOK→WINWORD→cmd→powershell→svchost32.exe"},
      {id:"BT-9902",time:"08:18:12",sev:"Critical",rule:"LSASS_MEMORY_ACCESS",src:"EDR",msg:"Process svchost32.exe (PID:4612) opened lsass.exe with GrantedAccess=0x1fffff — credential theft in progress"},
      {id:"BT-9903",time:"08:17:14",sev:"High",   rule:"ENCODED_POWERSHELL",src:"EDR",msg:"powershell.exe -WindowStyle Hidden -Enc SUVYKEkuTihuZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZy — AMSI bypass detected"},
      {id:"BT-9904",time:"08:16:55",sev:"High",   rule:"PHISHING_MACRO_DELIVERY",src:"Email GW",msg:"Email delivered from hr-payroll@corp-example.com — attachment: INV_Q4_2026_FINAL.docm — macro content detected"},
      {id:"BT-9905",time:"08:18:44",sev:"High",   rule:"REGISTRY_PERSISTENCE",src:"EDR",msg:"RegKey write: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate = svchost32.exe --server 203.0.113.47"},
      {id:"BT-9906",time:"08:19:01",sev:"Intermediate", rule:"SMB_LATERAL_ATTEMPT",src:"NDR",msg:"WS-CORP-FIN-044 → FS-CORP-01:445 SMB connection attempt — blocked by FW ACL RULE-2291"},
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
      {pid:"3201",ppid:"804",  depth:0,name:"OUTLOOK.EXE",   sha256:"",score:0, bad:false,time:"08:16:50",user:"CORP\\analyst.user",cmd:"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""},
      {pid:"4102",ppid:"3201", depth:1,name:"WINWORD.EXE",   sha256:"",score:8, bad:false,time:"08:17:01",user:"CORP\\analyst.user",cmd:"WINWORD.EXE /n /dde \"C:\\Users\\analyst.user\\Downloads\\INV_Q4_2026_FINAL.docm\""},
      {pid:"4398",ppid:"4102", depth:2,name:"cmd.exe",        sha256:"",score:91,bad:true, time:"08:17:09",user:"CORP\\analyst.user",cmd:"C:\\Windows\\System32\\cmd.exe /c powershell.exe -WindowStyle Hidden -NonI -Enc SUVYKEkuTihu..."},
      {pid:"4501",ppid:"4398", depth:3,name:"powershell.exe", sha256:"",score:97,bad:true, time:"08:17:14",user:"CORP\\analyst.user",cmd:"powershell.exe -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Enc SUVYKEku..."},
      {pid:"4612",ppid:"4501", depth:4,name:"svchost32.exe",  sha256:"a3f19c2d8e4b7f1c",score:99,bad:true,time:"08:17:33",user:"CORP\\analyst.user",cmd:"C:\\Users\\analyst.user\\AppData\\Local\\Temp\\svchost32.exe --server 203.0.113.47 --port 443 --interval 30"},
      {pid:"4701",ppid:"4612", depth:5,name:"lsass.exe",      sha256:"",score:99,bad:true, time:"08:18:12",user:"NT AUTHORITY\\SYSTEM",cmd:"[OpenProcess] GrantedAccess=0x1fffff — called by PID:4612 (svchost32.exe)"},
    ],
    network:[
      {time:"08:17:33",proto:"HTTPS",src:"10.10.44.112:51234",dst:"203.0.113.47:443",proc:"svchost32.exe",bytes:"3,840 out / 142 in",state:"ESTABLISHED",bad:true},
      {time:"08:17:34",proto:"HTTPS",src:"10.10.44.112:51241",dst:"203.0.113.47:443",proc:"svchost32.exe",bytes:"1,120 out / 98 in", state:"ESTABLISHED",bad:true},
      {time:"08:19:01",proto:"SMB",  src:"10.10.44.112:49411",dst:"10.10.44.60:445",   proc:"svchost32.exe",bytes:"0",             state:"RESET — FW",  bad:true},
      {time:"08:17:55",proto:"DNS",  src:"10.10.44.112:54321",dst:"10.10.1.5:53",      proc:"svchost.exe",  bytes:"62",             state:"CLOSED",      bad:false},
    ],
    timeline:[
      {time:"08:16:50",sev:"info",src:"SentinelEDR",event:"OUTLOOK.EXE launched — user: analyst.user — PID:3201"},
      {time:"08:17:01",sev:"med", src:"SentinelEDR",event:"WINWORD.EXE opened macro-enabled doc: INV_Q4_2026_FINAL.docm — VBA AutoOpen() triggered"},
      {time:"08:17:09",sev:"high",src:"SentinelEDR",event:"cmd.exe (PID:4398) spawned from WINWORD.EXE — score:91 — unusual parent-child"},
      {time:"08:17:14",sev:"high",src:"SentinelEDR",event:"powershell.exe (PID:4501) — -Enc flag — AMSI bypass in process memory — score:97"},
      {time:"08:17:33",sev:"crit",src:"SentinelEDR",event:"svchost32.exe dropped to AppData\\Temp — SHA256: a3f19c2d — VT: 48/72 — beacon started"},
      {time:"08:18:12",sev:"crit",src:"SentinelEDR",event:"LSASS memory access — GrantedAccess=0x1fffff — full credential access — Cobalt Strike-type pattern [fictional simulation]"},
      {time:"08:18:44",sev:"high",src:"SentinelEDR",event:"Registry Run key written — HKCU\\Run\\WindowsUpdate — persistence established"},
      {time:"08:19:01",sev:"high",src:"SentinelEDR",event:"SMB lateral attempt: 10.10.44.112 → 10.10.44.60:445 — blocked by FW ACL"},
    ],
    file_events:[
      {time:"08:17:33",action:"CREATE",path:"C:\\Users\\analyst.user\\AppData\\Local\\Temp\\svchost32.exe",sha256:"a3f19c2d8e4b7f1c9d2e",size:"284KB",signed:false},
      {time:"08:17:01",action:"CREATE",path:"C:\\Users\\analyst.user\\AppData\\Local\\Temp\\~$INV_Q4_2026_FINAL.docm",sha256:"",size:"2KB",signed:false},
    ],
  },

  // ── THREATLENS ─────────────────────────────────────────────────────────────
  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {
        type:"IP",value:"203.0.113.47",
        vt_score:"reported by 67 engines",
        abuse_score:100,
        categories:["Tor Exit Node","C2 Infrastructure","Malware Distribution"],
        country:"RU",asn:"AS204957 — GreenFloid LLC",
        last_seen:"2026-05-28",
        campaigns:["Cobalt Strike-type Campaigns (fictional simulation)","APT29 Infrastructure (low confidence)"],
        passive_dns:["update.corp-example.com","phishing-example.net"],
        first_seen:"2024-11-03",
        verdict:"MALICIOUS — block immediately",
        verdictColor:"#dc2626",
      },
      {
        type:"Hash",value:"a3f19c2d8e4b7f1c9d2e",
        vt_score:"48/72 detections",
        abuse_score:0,
        categories:["Cobalt Strike-type beacon","RAT","C2 Client"],
        country:"",asn:"",
        last_seen:"2026-05-27",
        campaigns:["Cobalt Strike — beacon.dll packed with UPX","Finance sector targeting 2026"],
        passive_dns:[],
        first_seen:"2026-05-01",
        verdict:"MALICIOUS — 48/72 AV detections — Cobalt Strike-type beacon",
        verdictColor:"#dc2626",
      },
      {
        type:"Domain",value:"corp-example.com",
        vt_score:"23/90 reported",
        abuse_score:87,
        categories:["Phishing","Brand Impersonation","Malware Distribution"],
        country:"US",asn:"AS13335 — Cloudflare (fronted)",
        last_seen:"2026-05-28",
        campaigns:["Finance sector phishing wave May 2026","Domain registered 2026-05-01 — 27 days old"],
        passive_dns:["hr-payroll.corp-example.com","invoice.corp-example.com"],
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
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Read the SIEM Alert",
      objective:"A new alert has landed in your queue. Before clicking anything — read the full alert. Think: What rules fired? Which host? Which user? What time? Once you have read it, decide whether this is worth investigating.",
      lookFor:["The risk score — higher means more suspicious","Multiple rules firing on the same host confirms each other","The hostname and username — who is affected?","The timestamp — during business hours or at suspicious timing?"],
      seniorThinking:"When I see multiple rules firing together on the same host within minutes, I treat it as a True Positive until proven otherwise. A 97/100 score with a C2 beacon rule AND an LSASS rule is not a coincidence — that is a pattern.",
      instruction:"Your shift just started. BlueTrace SIEM has a new Critical alert. Read it completely. Check: what rules fired, what host, what user, what time. Then decide: True Positive or False Positive?",
      analyst_note:"A Critical with 97/100 risk score + C2 beacon rule + LSASS rule firing together at 08:17 — this is not a false positive. Open the incident. You have 60 minutes SLA.",
      decision:{
        question:"You have reviewed the alert. What is your next action?",
        options:[
          {text:"Open incident — classify True Positive",correct:true,why:"Correct. A 97/100 score with multiple correlated rules is a confirmed True Positive. Open the incident and investigate."},
          {text:"Close alert — probably a false positive",correct:false,why:"Incorrect. Multiple correlated rules with a 97/100 score is not noise. Closing this lets an active C2 beacon run undetected."},
          {text:"Wait for more alerts before deciding",correct:false,why:"Incorrect. Waiting costs response time. P1 alerts require immediate action."},
          {text:"Assign to another analyst",correct:false,why:"Incorrect. The alert is assigned to you. You investigate first, escalate later if needed."},
        ]
      },
      evidence_bullets:["Risk Score: 97/100 — High Confidence","Rules: OUTBOUND_C2_BEACON + LSASS_MEMORY_ACCESS","Host: WS-CORP-FIN-044 (Finance workstation)","User: analyst.user@corp.internal","Time: 08:17 IST — business hours"],
      action_label:"Classify TRUE POSITIVE — Open Incident",
      action_result:"INC-2026-0441 opened\nAssigned: "+ANALYST.name+"\nSLA timer: 60:00 started\nStatus: In Progress\nNext: Pivot to SentinelEDR",
    },
    {
      id:1,phase:"INVESTIGATION",xp:30,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Read the Process Tree",
      objective:"Switch to SentinelEDR. Look at the process tree for WS-CORP-FIN-044. It shows every program that ran and what started it. Think: does this chain make sense for a normal Finance workstation?",
      lookFor:["Parent-child relationships — what program started what?","Programs running from AppData or Temp folders","Risk scores above 80 — highly suspicious","The LSASS entry — if something accessed lsass.exe, credentials may be stolen"],
      seniorThinking:"Word documents should never spawn cmd.exe. That one relationship tells me almost everything. A macro ran a command. The command ran PowerShell with encoded content — how attackers hide their code. The chain tells the story.",
      instruction:"Switch to SentinelEDR. Open the process tree for WS-CORP-FIN-044. Trace the full execution chain. What spawned what? Where did legitimate execution stop and malicious begin?",
      analyst_note:"OUTLOOK → WINWORD → cmd.exe is your red flag. Word should NEVER spawn cmd.exe. That is a macro executing. Trace: cmd → powershell (-Enc) → svchost32.exe in AppData/Temp. Score: 99/100.",
      decision:{
        question:"You see WINWORD.EXE spawning cmd.exe in the process tree. What does this indicate?",
        options:[
          {text:"Normal — Word sometimes uses cmd.exe",correct:false,why:"Incorrect. Word.exe should never spawn cmd.exe in normal operation. This is a textbook sign of a VBA macro executing a command."},
          {text:"A macro inside the Word document executed a command",correct:true,why:"Correct. WINWORD.EXE spawning cmd.exe is the classic macro execution pattern. The document contained malicious VBA code."},
          {text:"The user opened a command prompt manually",correct:false,why:"Incorrect. If the user opened CMD themselves, the parent would be explorer.exe, not winword.exe."},
          {text:"An IT admin ran a script on this machine",correct:false,why:"Incorrect. Admin scripts would show a different parent process and user context, not originate from Word."},
        ]
      },
      evidence_bullets:["OUTLOOK.EXE → WINWORD.EXE (doc opened via email)","WINWORD.EXE → cmd.exe ← Macro executed! Score: 91","cmd.exe → powershell.exe -Enc ← Encoded payload Score: 97","powershell.exe → svchost32.exe (AppData/Temp) Score: 99","svchost32.exe → lsass.exe (GrantedAccess=0x1fffff) Score: 99"],
      action_label:"Document Kill Chain — Macro to C2 to LSASS",
      action_result:"Kill chain confirmed:\nT1566.001 — Phishing macro document\nT1059.001 — PowerShell -Enc (AMSI bypass)\nT1071.001 — svchost32.exe beaconing 203.0.113.47\nT1003.001 — LSASS GrantedAccess=0x1fffff\nT1547.001 — Registry Run key persistence\nT1021.002 — SMB lateral attempt (blocked)",
    },
    {
      id:2,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Check the IOCs",
      objective:"You have 3 suspicious indicators. Look each one up in ThreatLens. Check the raw scores FIRST — form your own verdict before reading the tool's conclusion. This is how real analysts build judgment.",
      lookFor:["AbuseIPDB score — percentage of reporters flagging this IP","VirusTotal — how many out of 72 engines detect this file?","Domain age — how many days since registration?","Associated campaigns — linked to known threat actors?"],
      seniorThinking:"I check three things: IP reputation, file hash on VirusTotal, and domain age. If all three are bad, I have confirmation. A 27-day domain + 48/72 detections tells me this was purpose-built for this campaign.",
      instruction:"Look up 3 IOCs in ThreatLens: IP 203.0.113.47, hash a3f19c2d, domain corp-example.com. Check raw scores first — form your own verdict.",
      analyst_note:"AbuseIPDB: 100/100 — Tor exit for C2. Hash: 48/72 — Cobalt Strike-type beacon. Domain: 27 days old — created for this campaign.",
      decision:{
        question:"IP 203.0.113.47 scores 100/100 on AbuseIPDB. What action do you take?",
        options:[
          {text:"Block the IP estate-wide and document as IOC",correct:true,why:"Correct. 100/100 on AbuseIPDB is conclusive. Block perimeter-wide — any host could receive the same phishing email."},
          {text:"Wait for more data before blocking",correct:false,why:"Incorrect. A 100/100 score means hundreds of researchers flagged this IP. Waiting gives the attacker more time."},
          {text:"The score might be wrong — ignore it",correct:false,why:"Incorrect. AbuseIPDB aggregates thousands of reports. A 100/100 score is reliable."},
          {text:"Only block it on the affected host",correct:false,why:"Partially correct but incomplete. Block estate-wide — other hosts could be targeted by the same campaign."},
        ]
      },
      evidence_bullets:["IP 203.0.113.47 — AbuseIPDB: 100/100 — Tor Exit Node","Hash a3f19c2d — VirusTotal: 48/72 — Cobalt Strike","Domain corp-example.com — Age: 27 days — Newly registered","All 3 IOCs: Confirmed malicious","Campaign type: Targeted — not mass phishing"],
      action_label:"Block IOCs Estate-Wide — Cobalt Strike Confirmed",
      action_result:"IOC actions applied:\n[IP] 203.0.113.47 — BLOCKED estate-wide\n[Hash] a3f19c2d — BLOCK+KILL on all endpoints\n[Domain] corp-example.com — DNS SINKHOLE\nAssessment: Targeted Cobalt Strike — Finance team",
    },
    {
      id:3,phase:"CONTAINMENT",xp:30,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Contain the Endpoint",
      objective:"The C2 beacon is live right now. LSASS was accessed — the attacker may already have credentials. Every second increases risk. You must act — but think carefully about HOW you act. The wrong containment method loses forensic evidence.",
      lookFor:["Network tab — are C2 sessions still ESTABLISHED?","Containment tab — what does isolation do vs shutdown?","Does isolation keep the EDR sensor connected?","What volatile evidence is lost if you power off?"],
      seniorThinking:"Isolation is not shutdown. I always isolate first. Why? Because the malware is still running in memory. Isolate and the sensor stays connected — I can pull files, run commands, take a memory dump. Shut down and all that volatile evidence is gone.",
      instruction:"Confirmed compromise. Active C2 sessions live. Credentials potentially stolen. Cut the host from the network IMMEDIATELY — but preserve forensic state. Use Network Containment, not shutdown.",
      analyst_note:"Network Containment keeps the EDR sensor cloud-connected. You can still investigate and collect forensics. Shutdown loses volatile memory — the malware process, credentials in RAM.",
      decision:{
        question:"What is the correct way to stop the active C2 beacon while preserving forensics?",
        options:[
          {text:"Network Containment — isolate network, keep EDR connected",correct:true,why:"Correct. Network Containment cuts all network traffic while keeping the EDR sensor cloud-connected. You can still investigate and collect evidence."},
          {text:"Power off the computer immediately",correct:false,why:"Incorrect. Powering off destroys volatile memory — the malware process, cached credentials, and network state are all lost."},
          {text:"Delete the malware file and reboot",correct:false,why:"Incorrect. Deleting the file does not remove Registry persistence. The malware reruns on reboot. The host is still on the network during this process."},
          {text:"Change the user password and monitor",correct:false,why:"Partially correct but insufficient. Password rotation is needed, but the host is still compromised and the C2 beacon is still active."},
        ]
      },
      evidence_bullets:["C2 Sessions: 2x ESTABLISHED to 203.0.113.47:443","LSASS accessed — credentials potentially stolen","Registry Run key — persistence established","SMB lateral attempt — blocked by firewall","EDR Policy: DETECT-ONLY — no auto-kill running"],
      action_label:"Execute Network Containment — WS-CORP-FIN-044",
      action_result:"WS-CORP-FIN-044 — Network Containment: ACTIVE\nEDR sensor: CONNECTED (forensics available)\nC2 sessions: TERMINATED\nSMB lateral: SEVERED\nMemory: PRESERVED for forensics\nNext: Check blast radius",
    },
    {
      id:4,phase:"ERADICATION",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Check the Blast Radius",
      objective:"One host is contained. But what if the attacker already spread to a second machine in those 14 minutes? If you close this case now without checking, you could wake up tomorrow with a second active breach — and no idea it started here. Search every endpoint, every mailbox. Find out before you close.",
      lookFor:["Other hosts connecting to 203.0.113.47 in the last 24 hours","Other recipients of email from corp-example.com","Whether the same file hash appeared on any other endpoint","Lateral movement activity from WS-CORP-FIN-044 before containment"],
      seniorThinking:"I have been caught out before — closed a one-host incident, found a second host the next morning. Now I always run the blast radius search before writing my report. Takes 30 seconds. Saves hours.",
      instruction:"WS-CORP-FIN-044 is contained. Run the blast radius search in BlueTrace SIEM. Search all hosts for the C2 IP and malware hash. Check who else received the phishing email.",
      analyst_note:"Always check blast radius before closing. A missed second host becomes a full incident the next morning.",
      decision:{
        question:"The phishing email was also delivered to rahul.singh (not yet opened). What do you do?",
        options:[
          {text:"Quarantine the email from rahul.singh's inbox now",correct:true,why:"Correct. Even though rahul.singh has not opened it yet, the threat exists in their inbox. Quarantine it immediately through the email gateway."},
          {text:"Nothing — they did not open it so it is fine",correct:false,why:"Incorrect. The email is still in their inbox. They could open it tomorrow morning. Remove the threat before it can be triggered."},
          {text:"Email rahul.singh to warn them",correct:false,why:"Partially helpful but not sufficient. User notification is useful but manual — email gateway quarantine is immediate and reliable."},
          {text:"Wait and monitor if they open it",correct:false,why:"Incorrect. Waiting is not a containment action. Remove the threat proactively."},
        ]
      },
      evidence_bullets:["C2 IP — connected by: 1 host only (contained)","Malware hash — found on: 1 host only","Phishing email — delivered to 3 recipients","analyst.user: Opened — compromised (contained) ✗","rahul.singh: Not opened — still in inbox ⚠","priya.das: OOO — auto-quarantined ✓"],
      action_label:"Quarantine Emails + Confirm Blast Radius Clean",
      action_result:"Blast radius confirmed: 1 host compromised\nrahul.singh inbox: QUARANTINED\npriya.das: Already quarantined\n847 endpoints checked: CLEAN\nBlast radius: CONTAINED",
    },
    {
      id:5,phase:"CLOSE",xp:20,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Write the Incident Report",
      objective:"Threat is contained. Document what happened. Your report goes to the CISO, SOC lead, and your ticket history. Think: what was the root cause — not just WHAT happened, but WHY the attack was able to succeed.",
      lookFor:["Root cause — what security gap allowed this?","Timeline — attack start, detection, containment times","Actions taken — be specific, not vague","Outstanding items — what still needs to happen after this closes?"],
      seniorThinking:"The best IR reports state root cause clearly. Not just what happened — but why. Here: the EDR prevention policy was in detect-only mode. That is an operational failure, not just an attacker success. That gets fixed after this incident.",
      instruction:"Incident contained. Write the IR report in IncidentDesk. Fill the report form — exec summary, root cause, actions taken, and recommendations.",
      analyst_note:"Root cause: EDR in DETECT-ONLY mode on Finance host group. That is why the malicious process chain ran instead of being auto-killed. Goes in recommendations.",
      decision:{
        question:"What was the ROOT CAUSE of this incident succeeding?",
        options:[
          {text:"The user opened a phishing email",correct:false,why:"This is the attack vector, not the root cause. Users will occasionally click phishing emails. The question is: what security control failed to stop the consequences?"},
          {text:"EDR was in detect-only mode — no auto-prevention on this host group",correct:true,why:"Correct. The root cause was an operational gap. If EDR prevention mode was enabled, the malicious process chain would have been auto-killed at the PowerShell stage."},
          {text:"The email gateway missed the attachment",correct:false,why:"Contributing factor, but not the primary root cause. The EDR should have caught this regardless of email gateway performance."},
          {text:"The user had too many permissions",correct:false,why:"Not the root cause here. The primary failure was the EDR not blocking the malicious process chain."},
        ]
      },
      evidence_bullets:["Response time: 31 min (SLA: 60 min) ✓","Blast radius: 1 host, credentials exposed but not used","C2 active window: 14 minutes before containment","Root cause: EDR DETECT-ONLY on Finance VMs","Remaining: Reimage | Rotate creds | Fix EDR policy"],
      action_label:"Submit IR Report — Close INC-2026-0441",
      action_result:"INC-2026-0441 — CLOSED ✓\n\nEXEC SUMMARY: Targeted Cobalt Strike phishing. 1 endpoint compromised, contained in 31 min.\n\nRESPONSE: 31 min vs 60 min SLA ✓\nBLAST RADIUS: 1 host, creds exposed (not used)\n\nROOT CAUSE: EDR DETECT-ONLY mode on Finance VMs\n\nPENDING: Reimage | Rotate analyst.user creds | EDR PREVENT mode | Email GW tuning",
    },
  ],
},

"INC-2026-0442":{
  id:"INC-2026-0442",
  title:"Suspicious PowerShell — Finance Domain Controller",
  severity:"High",
  status:"New",
  created:tsNow(2),
  host:"DC-CORP-FIN-01",
  user:"svc_backup@corp.internal",
  srcIp:"10.10.1.20",
  c2Ip:"198.51.100.48",
  assignee:null,
  tags:["PowerShell","Encoded Command","Scheduled Task","C2"],
  concept:"False Positive vs True Positive — PowerShell",
  version:"TP",
  summary:"BlueTrace SIEM fired rule ENCODED_POWERSHELL_DC on DC-CORP-FIN-01. Service account svc_backup ran powershell.exe with -EncodedCommand flag at 02:14 AM. No change window open. No IT admin ticket for this host tonight. Risk score: 84/100.",

  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-2291 — Encoded PowerShell on Domain Controller outside change window",
    fired_at:tsNow(2),
    risk_score:84,
    alerts:[
      {id:"BT-4401",time:"02:14:11",sev:"High",  rule:"ENCODED_POWERSHELL_DC",    src:"EDR",     msg:"powershell.exe -EncodedCommand on DC-CORP-FIN-01 — service account svc_backup — outside change window"},
      {id:"BT-4402",time:"02:14:33",sev:"High",  rule:"SCHEDULED_TASK_CREATED",   src:"EDR",     msg:"New scheduled task 'WindowsDefenderUpdate' created — runs C:\\Windows\\Temp\\wdu.exe at logon"},
      {id:"BT-4403",time:"02:15:01",sev:"High",  rule:"OUTBOUND_CONN_UNUSUAL_PORT",src:"NDR",    msg:"wdu.exe outbound connection to 198.51.100.48:8080 — no DNS resolution — direct IP"},
      {id:"BT-4404",time:"02:14:05",sev:"Intermediate",rule:"OFF_HOURS_DC_ACTIVITY",     src:"SIEM",   msg:"Domain Controller activity at 02:14 AM — no approved change window — last window closed 6 days ago"},
      {id:"BT-4405",time:"02:13:58",sev:"Low",   rule:"SERVICE_ACCOUNT_INTERACTIVE",src:"Windows",msg:"svc_backup logged in interactively to DC-CORP-FIN-01 — service accounts should not log in interactively"},
    ],
    raw_search:`index=corp_events host=DC-CORP-FIN-01 earliest=-30m
| eval suspicious = if(match(CommandLine,"-Enc|-EncodedCommand|-encoded"),1,0)
| where suspicious=1
| stats count by user, CommandLine, ParentProcessName
| sort -count`,
    previous_incidents:["No previous incidents for this host in 90 days"],
    change_windows:["Last approved change window: 2026-05-22 23:00-03:00 UTC (6 days ago)","Next approved window: 2026-06-02 23:00 UTC"],
  },

  edr:{
    tool:"SentinelEDR",
    sensor_id:"9f2a8c1d3e4b",
    prevention_policy:"DC-STRICT-POLICY-v2",
    policy_note:"Domain Controller policy — all detections logged, high-risk auto-quarantine enabled",
    process_tree:[
      {pid:"1204",ppid:"508", depth:0,name:"services.exe",     sha256:"",score:0, bad:false,time:"02:13:55",user:"NT AUTHORITY\\SYSTEM",    cmd:"C:\\Windows\\System32\\services.exe"},
      {pid:"3841",ppid:"1204",depth:1,name:"svchost.exe",      sha256:"",score:2, bad:false,time:"02:13:58",user:"CORP\\svc_backup",         cmd:"C:\\Windows\\System32\\svchost.exe -k netsvcs -p"},
      {pid:"4102",ppid:"3841",depth:2,name:"powershell.exe",   sha256:"",score:81,bad:true, time:"02:14:05",user:"CORP\\svc_backup",         cmd:"powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn"},
      {pid:"4299",ppid:"4102",depth:3,name:"wdu.exe",          sha256:"b7e2f1a9c4d3",score:97,bad:true, time:"02:14:33",user:"CORP\\svc_backup",         cmd:"C:\\Windows\\Temp\\wdu.exe --server 198.51.100.48 --port 8080 --persist"},
      {pid:"4411",ppid:"4299",depth:4,name:"schtasks.exe",     sha256:"",score:88,bad:true, time:"02:14:38",user:"CORP\\svc_backup",         cmd:'schtasks /create /tn "WindowsDefenderUpdate" /tr "C:\\Windows\\Temp\\wdu.exe" /sc onlogon /ru SYSTEM /f'},
    ],
    network:[
      {time:"02:15:01",proto:"HTTP", src:"10.10.1.20:52341",dst:"198.51.100.48:8080",proc:"wdu.exe",bytes:"1,240 out / 88 in",state:"ESTABLISHED",bad:true},
      {time:"02:15:32",proto:"HTTP", src:"10.10.1.20:52341",dst:"198.51.100.48:8080",proc:"wdu.exe",bytes:"880 out / 44 in", state:"ESTABLISHED",bad:true},
      {time:"02:14:01",proto:"LDAP", src:"10.10.1.20:49281",dst:"10.10.1.5:389",   proc:"svchost.exe",bytes:"2,440",         state:"CLOSED",    bad:false},
    ],
    timeline:[
      {time:"02:13:55",sev:"info",src:"SentinelEDR",event:"services.exe normal activity — DC service startup pattern"},
      {time:"02:13:58",sev:"med", src:"SentinelEDR",event:"svc_backup: Interactive logon to DC-CORP-FIN-01 — service accounts should use non-interactive sessions"},
      {time:"02:14:05",sev:"high",src:"SentinelEDR",event:"powershell.exe -EncodedCommand launched by svc_backup — score: 81 — decoded: IEX (New-Object Net.WebClient).DownloadString('...'}"},
      {time:"02:14:33",sev:"crit",src:"SentinelEDR",event:"wdu.exe dropped to C:\\Windows\\Temp — SHA256: b7e2f1a9c4d3 — VT: 41/72 — connects to 198.51.100.48:8080"},
      {time:"02:14:38",sev:"crit",src:"SentinelEDR",event:"Scheduled task created: WindowsDefenderUpdate — runs wdu.exe at SYSTEM logon — persistence"},
      {time:"02:15:01",sev:"high",src:"SentinelEDR",event:"wdu.exe HTTP beacon to 198.51.100.48:8080 — no DNS — direct IP connection — C2 pattern"},
    ],
    file_events:[
      {time:"02:14:33",action:"CREATE",path:"C:\\Windows\\Temp\\wdu.exe",sha256:"b7e2f1a9c4d3ee7f2a1b",size:"318KB",signed:false},
      {time:"02:14:38",action:"CREATE",path:"C:\\Windows\\System32\\Tasks\\WindowsDefenderUpdate",sha256:"",size:"3KB",signed:false},
    ],
  },

  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {type:"IP",   value:"198.51.100.48",
       vt_score:"flagged by 54 engines",abuse_score:96,
       categories:["C2 Server","Malware Distribution","Bulletproof Hosting"],
       country:"RU",asn:"AS197695 — Reg.ru Hosting",
       last_seen:"2026-05-28",campaigns:["Cobalt Strike C2 — multiple finance sector victims 2026","Linked to TA505 infrastructure (low confidence)"],
       passive_dns:["update.windefender-cdn.com","c2-example.net"],
       first_seen:"2026-02-14",verdict:"MALICIOUS — block immediately",verdictColor:"#dc2626"},
      {type:"Hash",value:"b7e2f1a9c4d3ee7f",
       vt_score:"41/72 detections",abuse_score:0,
       categories:["RAT","C2 Client","Persistence Dropper"],
       country:"",asn:"",last_seen:"2026-05-27",
       campaigns:["Custom RAT — finance sector targeting — Q1-Q2 2026"],
       passive_dns:[],first_seen:"2026-03-01",verdict:"MALICIOUS — 41/72 AV detections",verdictColor:"#dc2626"},
    ],
  },

  desk:{
    tool:"IncidentDesk",ticket_id:"INC-2026-0442",sla_minutes:60,priority:"P1",
    category:"Malware — Persistence",subcategory:"Scheduled Task Backdoor",
    assignee:null,watchers:["soc-lead@corp.internal","dc-admin@corp.internal"],
    escalation_path:"SOC L1 → SOC L2 → DC Admin Team → CISO",
    updates:[],
  },

  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Read the Alert — Off-Hours DC Activity",
      objective:"Domain Controller activity at 02:14 AM. No approved change window. Service account used encoded PowerShell. Before classifying — think: is there any legitimate reason this could happen? How would you check?",
      lookFor:["Is there an open change window for this host tonight?","Is svc_backup a legitimate service account — or does it look suspicious?","What does encoded PowerShell on a Domain Controller mean?","The time — 02:14 AM is the classic attacker window. But it is also when some backup jobs run."],
      seniorThinking:"Every time I see encoded PowerShell, I ask myself one question first: is there a change window? If yes — call the on-call admin and verify. If no — it is almost certainly malicious. A Domain Controller running unknown encoded commands at 2AM with no ticket is a five-alarm fire.",
      instruction:"Review the SIEM alert. Check: is there an approved change window for DC-CORP-FIN-01 tonight? What rules fired? Should this trigger immediate investigation?",
      analyst_note:"No change window in the last 6 days. svc_backup is a backup service account — it should never run encoded PowerShell. Risk score 84/100. This is a True Positive.",
      decision:{
        question:"It is 02:14 AM. Encoded PowerShell fired on a Domain Controller. No change window is open. What is your first action?",
        options:[
          {text:"Open P1 incident — no change window means this is unauthorised",correct:true,why:"Correct. No approved change window + encoded PowerShell on a DC at 2AM = unauthorised activity. This is P1. Open the incident and start investigating immediately."},
          {text:"Check with the on-call admin before escalating — could be a backup job",correct:false,why:"Partially correct thinking but wrong timing. You check the change window system first — it already says no window open. You open the incident now and contact the admin in parallel, not before."},
          {text:"Wait until morning shift to investigate — probably a false alarm",correct:false,why:"Incorrect. Domain Controllers are the crown jewels of Active Directory. Unknown activity on a DC at 2AM is never 'wait until morning'. SOC L1 responds immediately."},
          {text:"Close the alert — service accounts often run PowerShell",correct:false,why:"Incorrect. Service accounts running encoded PowerShell on DCs at 2AM with no change window is not normal. This reasoning is exactly how attacker persistence goes undetected for weeks."},
        ]
      },
      evidence_bullets:["Time: 02:14 AM — outside all approved change windows","Host: DC-CORP-FIN-01 — Domain Controller (critical asset)","User: svc_backup — service account (interactive logon is abnormal)","Rules fired: ENCODED_POWERSHELL_DC + SCHEDULED_TASK_CREATED","Risk score: 84/100 — High confidence"],
      action_label:"Open P1 Incident — Unauthorised DC Activity",
      action_result:"INC-2026-0442 opened\nPriority: P1 — Domain Controller\nSLA: 60 minutes\nOn-call DC Admin: notified\nNext: Pivot to SentinelEDR — read the process tree",
    },
    {
      id:1,phase:"INVESTIGATION",xp:30,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Decode the PowerShell Command",
      objective:"Switch to SentinelEDR. The process tree shows powershell.exe ran with -EncodedCommand. That base64 string hides the actual command. Analysts can decode it. Look at the decoded command — what is it doing? Then trace the full chain down to wdu.exe.",
      lookFor:["The encoded command — what does it decode to?","Where was wdu.exe dropped? Legitimate programs live in Program Files — not Temp","The scheduled task name — does 'WindowsDefenderUpdate' seem designed to blend in?","The SHA256 of wdu.exe — is it signed by a legitimate vendor?"],
      seniorThinking:"Attackers love three tricks: encoded PowerShell to hide the download command, dropping payloads to Temp folders, and naming their malware after legitimate Windows processes. 'WindowsDefenderUpdate' is classic camouflage. If I ever see a file in Temp with a name that sounds like a Windows component but is NOT signed by Microsoft — that is malware.",
      instruction:"Read the process tree in SentinelEDR. Find the encoded PowerShell command. Trace what it drops. Check where wdu.exe lives and whether it is signed.",
      analyst_note:"Decoded command: IEX (New-Object Net.WebClient).DownloadString — classic download cradle. wdu.exe in C:\\Windows\\Temp — unsigned — SHA256: b7e2f1a9c4d3. Scheduled task for persistence. This is a RAT.",
      decision:{
        question:"wdu.exe was dropped to C:\\Windows\\Temp and is NOT digitally signed. What does this tell you?",
        options:[
          {text:"Probably a Windows update utility — Microsoft uses Temp sometimes",correct:false,why:"Incorrect. Legitimate Microsoft executables are always digitally signed by Microsoft Corporation. An unsigned file named 'wdu.exe' in Temp is not from Microsoft — it is malware masquerading as one."},
          {text:"This is malware — legitimate software is signed and does not live in Temp",correct:true,why:"Correct. Any unsigned executable in C:\\Windows\\Temp should be treated as malicious until proven otherwise. Legitimate software has valid digital signatures. Temp-dropped unsigned files are a classic malware pattern."},
          {text:"Check VirusTotal before deciding — the file might be clean",correct:false,why:"VirusTotal is useful, but an unsigned file dropped to Temp by an encoded PowerShell command at 2AM on a DC is already suspicious enough to act. Do not wait for VT when containment is needed."},
          {text:"It is a false positive — backup agents drop files to Temp sometimes",correct:false,why:"Legitimate backup agents are signed by their vendor and do not use encoded PowerShell download cradles. The context makes this clearly malicious."},
        ]
      },
      evidence_bullets:["PowerShell decoded: IEX(New-Object Net.WebClient).DownloadString — download cradle","wdu.exe dropped to: C:\\Windows\\Temp (not Program Files)","wdu.exe: UNSIGNED — no valid digital signature","SHA256 b7e2f1a9c4d3: 41/72 VT detections","Scheduled task 'WindowsDefenderUpdate': disguised persistence"],
      action_label:"Document Kill Chain — Download Cradle → RAT → Persistence",
      action_result:"Kill chain:\nT1059.001 — PowerShell -EncodedCommand download cradle\nT1105 — wdu.exe dropped from remote server\nT1053.005 — Scheduled task persistence (SYSTEM level)\nT1071.001 — HTTP C2 beacon to 198.51.100.48:8080\nHost: DC-CORP-FIN-01 (Domain Controller — CRITICAL)",
    },
    {
      id:2,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Validate the C2 Infrastructure",
      objective:"Look up the C2 IP and the file hash in ThreatLens. Before reading the verdict — check the raw evidence. Look at: abuse score, passive DNS domains (they often reveal the attacker's naming patterns), and the campaign history. What kind of attacker uses this infrastructure?",
      lookFor:["The passive DNS names — do they all impersonate Microsoft security products?","The campaign history — has this IP been used in similar finance sector attacks?","The file hash campaign description — does it match what you are seeing?","The hosting provider — bulletproof hosters are used by advanced threat actors"],
      seniorThinking:"When I see passive DNS names like 'windefender-cdn.com' and 'ms-security-patch.net' — I know this is a sophisticated attacker. They register domains that sound like legitimate Microsoft infrastructure specifically to bypass email security filters and fool analysts. This is not a script kiddie.",
      instruction:"Look up 198.51.100.48 and hash b7e2f1a9c4d3 in ThreatLens. Read the passive DNS carefully — what pattern do you see?",
      analyst_note:"IP: 96/100 abuse score — bulletproof hosting in Russia. Passive DNS names impersonate Microsoft security services. Campaign linked to finance sector targeting. Sophisticated actor.",
      decision:{
        question:"Passive DNS shows domains like 'windefender-cdn.com' and 'ms-security-patch.net'. What does this reveal about the attacker?",
        options:[
          {text:"These are legitimate Microsoft domains — the alert might be a false positive",correct:false,why:"Incorrect. Microsoft domains end in microsoft.com or windowsupdate.com. Domains like 'windefender-cdn.com' are typosquats — specifically registered to look like Microsoft services but are attacker-controlled."},
          {text:"The attacker deliberately chose domain names that look like Microsoft services to avoid detection",correct:true,why:"Correct. This is a classic advanced threat tactic called domain mimicry. Domains designed to look legitimate help bypass email filters, fool analysts, and blend into network traffic. This indicates a sophisticated, targeted attacker."},
          {text:"The passive DNS is probably outdated — ignore it",correct:false,why:"Incorrect. Passive DNS is one of the most reliable IOC signals. Attackers reuse infrastructure across campaigns. These domains confirm this IP is part of a deliberate Microsoft-impersonation campaign."},
          {text:"Any domain can end up in threat intel by mistake",correct:false,why:"Incorrect. An abuse score of 96/100 combined with domain names specifically designed to mimic Microsoft security products is not a coincidence or a false positive."},
        ]
      },
      evidence_bullets:["IP 198.51.100.48 — AbuseIPDB: 96/100 — Bulletproof hosting","Passive DNS: 'windefender-cdn.com', 'ms-security-patch.net' — Microsoft impersonation","Hash b7e2f1a9c4d3 — 41/72 VT — custom RAT, finance targeting","Campaign: TA505-linked (low confidence) — Q1-Q2 2026 finance sector","Assessment: Sophisticated targeted threat — not opportunistic"],
      action_label:"IOCs Confirmed — Sophisticated Finance-Sector Targeting",
      action_result:"IOCs documented:\n[IP] 198.51.100.48 — BLOCK estate-wide — 96/100\n[Hash] b7e2f1a9c4d3 — BLOCK+KILL all endpoints\n[Domains] windefender-cdn.com, ms-security-patch.net — DNS SINKHOLE\nThreat level: SOPHISTICATED — escalate to SOC L2",
    },
    {
      id:3,phase:"CONTAINMENT",xp:35,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Contain the Domain Controller",
      objective:"This is a Domain Controller. Containing a DC is more complex than containing a workstation. If you isolate a DC from the network, authentication for the entire domain may break. What is the correct containment approach for this critical asset?",
      lookFor:["Is this the ONLY domain controller, or are there replicas?","How long has the C2 been active — can you act in the next few minutes?","What does the DC admin team need to do before you isolate?","Can you kill the malicious process without full network isolation?"],
      seniorThinking:"Isolating a Domain Controller can bring down authentication for hundreds of users. I never isolate a DC without checking how many DCs are in the domain first. If there are replicas, isolation is safe. If it is the only DC, I kill the malicious process via RTR, block the C2 IP at the firewall, and get the DC admin team on the phone before doing anything else.",
      instruction:"Decide on the correct containment for DC-CORP-FIN-01. Check if replicas exist. Then take the right action — do not blindly isolate.",
      analyst_note:"The domain has 3 DCs. DC-CORP-FIN-01 is not the primary. Safe to isolate. Kill wdu.exe via RTR first, then isolate.",
      decision:{
        question:"DC-CORP-FIN-01 has 2 replica DCs available. What is the correct containment action?",
        options:[
          {text:"Isolate immediately — same as any other endpoint",correct:false,why:"Partially correct — isolation is valid here because replicas exist. But 'same as any other endpoint' is wrong thinking. Always check for DC replicas before isolating. If this were the only DC, you would bring down domain authentication."},
          {text:"Kill wdu.exe via RTR + block C2 IP at firewall + then isolate — replicas confirmed",correct:true,why:"Correct. The sequence matters: kill the active process first to stop C2 communication, block the IP at the firewall to prevent reconnection, then isolate the DC knowing replicas will handle authentication. This is the right order."},
          {text:"Do nothing — wait for the DC admin team before touching a Domain Controller",correct:false,why:"Incorrect. The C2 beacon is active right now. Waiting 30+ minutes for the admin team while an attacker has access to a Domain Controller is unacceptable. Kill the process first, then call the admin team."},
          {text:"Reboot the DC to clear the malware",correct:false,why:"Incorrect. Rebooting does not remove the scheduled task persistence — wdu.exe will rerun at next login. Also, you lose forensic evidence. Never reboot a compromised host as a containment strategy."},
        ]
      },
      evidence_bullets:["Domain has 3 DCs — DC-CORP-FIN-01 is not primary — safe to isolate","wdu.exe C2 sessions: 2x ESTABLISHED to 198.51.100.48:8080","Scheduled task 'WindowsDefenderUpdate': SYSTEM-level persistence active","svc_backup credentials: potentially stolen (service account)","On-call DC admin: notified and standing by"],
      action_label:"Kill Process + Block C2 + Isolate DC-CORP-FIN-01",
      action_result:"wdu.exe (PID:4299) — KILLED via RTR\nC2 IP 198.51.100.48 — BLOCKED at perimeter firewall\nScheduled task 'WindowsDefenderUpdate' — DELETED via RTR\nDC-CORP-FIN-01 — Network Containment: ACTIVE\nReplica DCs: handling authentication\nDC Admin team: active on call",
    },
    {
      id:4,phase:"CLOSE",xp:20,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Escalate and Document",
      objective:"Domain Controller compromise requires escalation to SOC L2 and the DC Admin team. Write the IR summary. Focus on: what was the initial access vector? How did the attacker get svc_backup credentials? That question is still unanswered — document it as outstanding.",
      lookFor:["How did the attacker obtain svc_backup credentials in the first place?","Were any AD queries made from the compromised DC before containment?","Should all service account passwords be rotated as a precaution?","What is the recommended remediation for the DC?"],
      seniorThinking:"A compromised DC is never just one incident. The attacker had service account credentials. How? Probably from a previous compromise we have not found yet. I escalate to L2 immediately and request a full AD audit — check for new admin accounts, group policy changes, and any accounts added in the last 30 days.",
      instruction:"Write the IR summary. Document the outstanding question — how did the attacker get svc_backup credentials? Escalate to L2.",
      analyst_note:"Outstanding: initial access vector unknown. svc_backup credentials source unclear. Escalate to L2 for full AD audit. Recommend: rotate all service account passwords, audit AD for changes.",
      decision:{
        question:"The attacker used svc_backup credentials. After containment, what is the most important outstanding question?",
        options:[
          {text:"How did the attacker obtain svc_backup credentials in the first place?",correct:true,why:"Correct. This is the root question. If you do not find how the credentials were stolen, the attacker still has them and can reenter via a different path. This requires a full AD audit and a hunt for the original compromise."},
          {text:"Why did the EDR not auto-block the PowerShell?",correct:false,why:"Valid operational question but not the most important. The EDR was in detection mode — you can fix that. The credential theft question is more urgent because it implies a prior undetected compromise."},
          {text:"The incident is contained — no outstanding questions needed",correct:false,why:"Incorrect. Containment is not closure. You have a DC-level compromise with unknown initial access. The attacker still has credentials. This is an open investigation that requires L2 escalation."},
          {text:"Whether to reimage the DC immediately",correct:false,why:"Important operational decision but not the most urgent outstanding question. The DC admin team makes that call. The critical intelligence gap is: how did the attacker get in?"},
        ]
      },
      evidence_bullets:["DC-CORP-FIN-01: contained — replicas handling auth","wdu.exe and scheduled task: removed","C2 sessions: terminated","svc_backup credentials: source unknown — full AD audit required","Escalation: SOC L2 + DC Admin team — active"],
      action_label:"Escalate to SOC L2 + Submit IR Summary",
      action_result:"INC-2026-0442 — ESCALATED TO SOC L2\n\nSUMMARY: RAT deployed on Domain Controller via svc_backup service account. Encoded PowerShell download cradle + scheduled task persistence. Contained in 47 min.\n\nOUTSTANDING: How were svc_backup credentials obtained? Full AD audit initiated.\n\nRECOMMENDED: Rotate all svc_* passwords | Audit AD group membership | Check for new admin accounts | Review GPO changes",
    },
  ]
},

// ─── SCENARIO 2 FALSE POSITIVE VERSION ───────────────────────────────────────
// Same initial alert — but this time it IS the IT admin running a legitimate script
// Analyst must investigate fully before closing — not close it immediately

"INC-2026-0445":{
  id:"INC-2026-0445",
  title:"Suspicious PowerShell on Finance DC — Is This Legitimate?",
  severity:"High",
  status:"New",
  created:tsNow(8),
  host:"DC-CORP-FIN-01",
  user:"adm_patching@corp.internal",
  srcIp:"10.10.1.20",
  c2Ip:null,
  assignee:null,
  tags:["PowerShell","False Positive","Patch Management","IT Admin"],
  concept:"False Positive recognition — patch management activity",
  version:"FP",
  summary:"BlueTrace SIEM fired rule ENCODED_POWERSHELL_DC on DC-CORP-FIN-01. Admin account adm_patching ran powershell.exe with -EncodedCommand flag at 23:45. Risk score: 72/100. Change window INC-CHG-2026-0112 approved for tonight 23:00-03:00.",

  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-2291 — Encoded PowerShell on Domain Controller",
    fired_at:tsNow(8),
    risk_score:72,
    alerts:[
      {id:"BT-7701",time:"23:45:11",sev:"High",  rule:"ENCODED_POWERSHELL_DC",     src:"EDR",     msg:"powershell.exe -EncodedCommand on DC-CORP-FIN-01 — account adm_patching — change window active"},
      {id:"BT-7702",time:"23:44:55",sev:"Low",   rule:"ADMIN_LOGON_DC",            src:"Windows", msg:"adm_patching logged onto DC-CORP-FIN-01 — admin account — within change window"},
      {id:"BT-7703",time:"23:46:01",sev:"Low",   rule:"WSUS_UPDATE_ACTIVITY",      src:"SIEM",    msg:"Windows Update service activity on DC-CORP-FIN-01 — consistent with patch deployment"},
    ],
    raw_search:`index=corp_events host=DC-CORP-FIN-01 earliest=-30m
| eval suspicious = if(match(CommandLine,"-Enc|-EncodedCommand"),1,0)
| where suspicious=1
| stats count by user, CommandLine, ParentProcessName`,
    previous_incidents:["No previous incidents for adm_patching in 180 days"],
    change_windows:["ACTIVE change window: INC-CHG-2026-0112 — approved 23:00-03:00 — DC patching — approver: IT Manager"],
  },

  edr:{
    tool:"SentinelEDR",
    sensor_id:"9f2a8c1d3e4b",
    prevention_policy:"DC-STRICT-POLICY-v2",
    policy_note:"Domain Controller policy — all detections logged",
    process_tree:[
      {pid:"2201",ppid:"508", depth:0,name:"services.exe",   sha256:"",score:0,bad:false,time:"23:44:50",user:"NT AUTHORITY\\SYSTEM",    cmd:"C:\\Windows\\System32\\services.exe"},
      {pid:"4881",ppid:"2201",depth:1,name:"WSUSClient.exe", sha256:"",score:0,bad:false,time:"23:44:55",user:"CORP\\adm_patching",       cmd:"C:\\Program Files\\WSUS\\WSUSClient.exe -runpatch"},
      {pid:"5102",ppid:"4881",depth:2,name:"powershell.exe", sha256:"",score:42,bad:false,time:"23:45:05",user:"CORP\\adm_patching",      cmd:"powershell.exe -NonInteractive -EncodedCommand cABhAHQAYwBoAC0AdQBwAGQAYQB0AGUAIAAtAEsAQgAgAEsAQgA1ADMANwA4ADkAMAA1AA=="},
      {pid:"5298",ppid:"5102",depth:3,name:"wusa.exe",       sha256:"",score:0,bad:false,time:"23:45:44",user:"CORP\\adm_patching",       cmd:"C:\\Windows\\System32\\wusa.exe /install C:\\Windows\\SoftwareDistribution\\KB5378905.msu /quiet /norestart"},
    ],
    network:[
      {time:"23:45:50",proto:"HTTPS",src:"10.10.1.20:51234",dst:"10.10.1.100:8530",proc:"WSUSClient.exe",bytes:"4,200 out / 88,400 in",state:"CLOSED",bad:false},
      {time:"23:44:58",proto:"LDAP", src:"10.10.1.20:49281",dst:"10.10.1.5:389",   proc:"services.exe", bytes:"1,240",               state:"CLOSED",bad:false},
    ],
    timeline:[
      {time:"23:44:50",sev:"info",src:"SentinelEDR",event:"WSUS patching client started — scheduled maintenance window"},
      {time:"23:44:55",sev:"info",src:"SentinelEDR",event:"adm_patching logon — admin account — within INC-CHG-2026-0112 change window"},
      {time:"23:45:05",sev:"med", src:"SentinelEDR",event:"powershell.exe -EncodedCommand launched — parent: WSUSClient.exe — score: 42"},
      {time:"23:45:44",sev:"info",src:"SentinelEDR",event:"wusa.exe installing KB5378905 — Windows Server patch — legitimate WSUS activity"},
      {time:"23:45:50",sev:"info",src:"SentinelEDR",event:"WSUS client connected to internal update server 10.10.1.100:8530 — no external connections"},
    ],
    file_events:[
      {time:"23:45:44",action:"CREATE",path:"C:\\Windows\\SoftwareDistribution\\KB5378905.msu",sha256:"",size:"48MB",signed:true},
    ],
  },

  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {type:"IP",value:"10.10.1.100",
       vt_score:"No detections",abuse_score:0,
       categories:["Internal Infrastructure","WSUS Server"],
       country:"INT",asn:"Corp Internal",
       last_seen:"N/A",campaigns:["Internal WSUS update server — corp.internal"],
       passive_dns:["wsus.corp.internal"],
       first_seen:"N/A",verdict:"CLEAN — internal WSUS server",verdictColor:"#16a34a"},
    ],
  },

  desk:{
    tool:"IncidentDesk",ticket_id:"INC-2026-0445",sla_minutes:60,priority:"P2",
    category:"Security Alert — Pending Review",subcategory:"Encoded PowerShell",
    assignee:null,watchers:["soc-lead@corp.internal"],
    escalation_path:"SOC L1 → SOC L2 (if escalation needed)",
    updates:[],
  },

  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Read the Alert — Change Window Check",
      objective:"Same rule fired: ENCODED_POWERSHELL_DC. Before you do anything — check the change window system. Is there an approved change window for tonight? This is the first question every analyst asks. The answer changes everything.",
      lookFor:["Is there an active change window for DC-CORP-FIN-01 tonight?","What account triggered the alert — a service account or an admin account?","What is the risk score compared to a typical malicious alert?","Are there other alerts corroborating malicious activity — or is this the only one?"],
      seniorThinking:"Change windows are your first filter. If an alert fires inside an approved change window and the account is a legitimate admin account — my suspicion drops significantly. I still investigate fully, but I am looking for evidence of legitimacy, not just evidence of malice. Never close without investigating — but context matters.",
      instruction:"Check the SIEM. Is there an approved change window? What account triggered this? Does anything else look suspicious?",
      analyst_note:"ACTIVE change window INC-CHG-2026-0112 — approved tonight. Account adm_patching is a legitimate admin patching account. Risk score 72 vs 84 in the malicious version. One rule fired vs four. Context shifts significantly.",
      decision:{
        question:"An active change window is open for DC-CORP-FIN-01 tonight. An admin patching account ran encoded PowerShell. What is your approach?",
        options:[
          {text:"Close the alert — change window is open, nothing to investigate",correct:false,why:"Incorrect. A change window reduces suspicion but does not eliminate the need to investigate. You still need to confirm the activity matches what was approved. Attackers can abuse legitimate change windows."},
          {text:"Investigate fully — confirm the activity matches the approved change window before closing",correct:true,why:"Correct. You investigate every alert. A change window means you approach the evidence looking for legitimacy — but you verify it. Check: does the activity match the change ticket? Is the account the approved one? Are there any external connections?"},
          {text:"Escalate to P1 immediately — encoded PowerShell is always malicious",correct:false,why:"Incorrect. Encoded PowerShell is often used by legitimate tools including patch management systems. The encoded flag alone is not sufficient to declare P1. Context and evidence determine severity."},
          {text:"Call the IT admin to confirm before investigating",correct:false,why:"Partially correct but wrong order. Investigate first — you should have evidence before you call. When you call the admin with specific details about what you found, you get a much more useful confirmation."},
        ]
      },
      evidence_bullets:["Active change window: INC-CHG-2026-0112 (23:00-03:00) — approved tonight","Account: adm_patching — admin patching account (not service account)","Only 1 rule fired (vs 4 in a typical malicious case)","Risk score: 72/100 (lower than typical malware alerts)","No beaconing or lateral movement alerts"],
      action_label:"Investigate Fully — Verify Against Change Window",
      action_result:"INC-2026-0445 opened for investigation\nPriority: P2 (change window context reduces urgency)\nApproach: verify activity against approved change ticket\nNext: Pivot to SentinelEDR — read the process tree",
    },
    {
      id:1,phase:"INVESTIGATION",xp:30,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Check the Process Tree — What Spawned PowerShell?",
      objective:"In the malicious scenario, powershell.exe was spawned by svchost.exe. In this scenario — look at what spawned powershell.exe. The parent process tells you almost everything. Then check where the child process went — wusa.exe or wdu.exe?",
      lookFor:["What is the PARENT of powershell.exe — a WSUS client or an unknown process?","What does powershell.exe spawn — wusa.exe (Windows Update) or an unknown .exe?","Where does the child process connect to — internal WSUS server or external IP?","Is the file downloaded signed by Microsoft or unsigned?"],
      seniorThinking:"Parent process analysis is the single most powerful technique for distinguishing legitimate from malicious activity. WSUSClient.exe spawning powershell.exe is expected during patch deployment. Compare that to svchost.exe spawning powershell.exe at 2AM with an encoded download cradle — completely different risk profile.",
      instruction:"Open the process tree. Focus on the PARENT of powershell.exe. Then trace what it spawned. Look at the network connection destination.",
      analyst_note:"Parent: WSUSClient.exe — a legitimate WSUS patch management client. Child: wusa.exe (Windows Update Standalone Installer) — built-in Windows tool. Network: connects to 10.10.1.100:8530 — internal WSUS server. No external connections.",
      decision:{
        question:"powershell.exe was spawned by WSUSClient.exe and it ran wusa.exe to install KB5378905. What is your assessment?",
        options:[
          {text:"Still suspicious — encoded PowerShell is always a red flag regardless of parent",correct:false,why:"Incorrect. Context overrides the single indicator. WSUS patch clients commonly use encoded PowerShell to pass parameters. The parent process is a legitimate patch tool, the child is a built-in Windows installer, the network goes to an internal server. This is expected."},
          {text:"This looks legitimate — WSUS client spawning PowerShell for patch installation is expected",correct:true,why:"Correct. The process chain is consistent with legitimate patch management: WSUS client → PowerShell (to pass installation parameters) → wusa.exe (Windows Update tool) → internal WSUS server. No external connections, file is signed by Microsoft."},
          {text:"Cannot determine from process tree alone — need more evidence",correct:false,why:"You actually have enough evidence here. The complete chain — legitimate parent, legitimate child, internal network destination, signed file — is sufficient for your assessment. Good analysts know when they have enough evidence."},
          {text:"Escalate to SOC L2 — any encoded PowerShell on a DC needs L2 review",correct:false,why:"Incorrect escalation. SOC L1 can close False Positives. Escalating every encoded PowerShell alert regardless of context would overwhelm L2 with noise. Your job is to assess the context and make the call."},
        ]
      },
      evidence_bullets:["Parent: WSUSClient.exe — legitimate patch management client","Child: wusa.exe — built-in Windows Update installer","Network: 10.10.1.100:8530 — INTERNAL WSUS server only","No external connections whatsoever","KB5378905.msu — signed by Microsoft Corporation ✓"],
      action_label:"Assess Evidence — Process Chain Looks Legitimate",
      action_result:"Process chain assessment:\nWSUSClient.exe → powershell.exe → wusa.exe (installing KB5378905)\nNetwork: internal WSUS server only — no external connections\nFile: signed by Microsoft ✓\nPreliminary assessment: Likely FALSE POSITIVE\nNext: Verify in ThreatLens + confirm with change ticket",
    },
    {
      id:2,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Check the Network Destination",
      objective:"The WSUS client connected to 10.10.1.100:8530. Before closing this investigation — look up that IP in ThreatLens. It should come back as an internal WSUS server. If it does — that confirms your assessment. If it does not — something is wrong with your analysis.",
      lookFor:["Is 10.10.1.100 an internal IP? (10.x.x.x = RFC1918 private range)","Does ThreatLens show this as a known internal infrastructure IP?","Are there any external connections in the network logs that you missed?","Does the threat intel confirm or contradict your preliminary assessment?"],
      seniorThinking:"I always check even the IPs that look clean. Once I found a legitimate-looking internal IP that had been reassigned to a VPN endpoint that was actually routing to an external server. Ten minutes of checking saved a major incident. Trust the process, not your gut.",
      instruction:"Look up 10.10.1.100 in ThreatLens. Confirm it is the internal WSUS server. Check the network logs for any connections you may have missed.",
      analyst_note:"10.10.1.100 = clean, internal WSUS server. No external connections in any log. The investigation confirms this is a False Positive.",
      decision:{
        question:"ThreatLens confirms 10.10.1.100 is the internal WSUS server. No external connections found. Change window confirmed. What is your final verdict?",
        options:[
          {text:"True Positive — close and escalate",correct:false,why:"Incorrect. All evidence points to legitimate activity: approved change window, legitimate admin account, WSUS client parent process, internal-only network connections, Microsoft-signed file. This is a False Positive."},
          {text:"False Positive — close alert with full documentation",correct:true,why:"Correct. You have done a complete investigation: change window verified, account confirmed legitimate, process chain consistent with WSUS patching, network connections internal only, file signed by Microsoft. Close with thorough documentation explaining your reasoning."},
          {text:"Inconclusive — leave open for L2 to decide",correct:false,why:"Incorrect. You have sufficient evidence to make a clear determination. SOC L1 analysts are expected to close False Positives independently. Leaving clear FPs open creates noise in the queue and erodes confidence in the SOC."},
          {text:"Close immediately without full documentation",correct:false,why:"Incorrect. Always document your investigation reasoning before closing — even for False Positives. The documentation explains why you closed it, which is important for audits and for analysts who review the ticket later."},
        ]
      },
      evidence_bullets:["10.10.1.100 — Internal WSUS server — clean ✓","No external network connections in any log ✓","Change window INC-CHG-2026-0112 — verified active and approved ✓","adm_patching — confirmed legitimate IT admin account ✓","KB5378905 — Microsoft-signed, legitimate Windows Server patch ✓"],
      action_label:"Close as False Positive — Document Investigation",
      action_result:"INC-2026-0445 — CLOSED as FALSE POSITIVE\n\nINVESTIGATION SUMMARY:\nTriggered by: WSUS patch deployment during approved change window\nAccount: adm_patching — confirmed legitimate IT admin\nActivity: Installing KB5378905 via WSUS — entirely consistent with approved change\nNetworking: Internal WSUS server only — no external connections\n\nRECOMMENDATION: Add WSUS activity during approved change windows to allowlist in SIEM rule CORP-RULE-2291 to reduce future noise",
    },
  ]
},

// ─── SCENARIO 3: Impossible Travel — TRUE POSITIVE ────────────────────────────
// Concept taught: identity-based detection, MFA fatigue awareness
// One concept only: impossible travel + account takeover response

"INC-2026-0447":{
  id:"INC-2026-0447",
  title:"Impossible Travel — M365 Account — Active Session",
  severity:"Critical",
  status:"New",
  created:tsNow(12),
  host:"Azure AD / M365",
  user:"priya.sharma@corp.onmicrosoft.com",
  srcIp:"198.51.100.47",
  c2Ip:null,
  assignee:null,
  tags:["Impossible Travel","Account Takeover","Azure AD","Identity","MFA"],
  concept:"Identity-based detection — impossible travel + account takeover",
  version:"TP",
  summary:"Sentinel SIEM fired IMPOSSIBLE_TRAVEL_M365. priya.sharma logged in from Mumbai (09:20) then from Amsterdam (09:24) — 7,200km in 4 minutes. Physically impossible. Active session ongoing. User is in office right now — confirmed by badge reader. Someone else is using her account remotely.",

  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-5501 — Impossible Travel — M365 Authentication",
    fired_at:tsNow(12),
    risk_score:99,
    alerts:[
      {id:"BT-8801",time:"09:24:11",sev:"Critical",rule:"IMPOSSIBLE_TRAVEL_M365",     src:"Azure AD",  msg:"priya.sharma: login from IN/Mumbai (09:20) then NL/Amsterdam (09:24) — 7,200km in 4 min — impossible travel"},
      {id:"BT-8802",time:"09:24:44",sev:"Critical",rule:"SIMULTANEOUS_SESSIONS_M365", src:"Azure AD",  msg:"priya.sharma: 2 concurrent active sessions — IP 10.10.5.22 (Mumbai office) and 198.51.100.47 (Amsterdam)"},
      {id:"BT-8803",time:"09:25:14",sev:"High",    rule:"SHAREPOINT_MASS_DOWNLOAD",   src:"M365",      msg:"priya.sharma: 23 files downloaded from SharePoint /sites/Finance in 3 minutes from 198.51.100.47"},
      {id:"BT-8804",time:"09:25:55",sev:"High",    rule:"MFA_PUSH_BURST",             src:"Azure AD",  msg:"priya.sharma: 31 MFA push notifications sent in 7 minutes — 30 denied — 1 approved at 09:23:58"},
      {id:"BT-8805",time:"09:26:01",sev:"High",    rule:"NEW_MFA_DEVICE_REGISTERED",  src:"Azure AD",  msg:"priya.sharma: new Authenticator device registered from 198.51.100.47 — persistence attempt"},
    ],
    raw_search:`index=azure_ad sourcetype=azure:aad:signin
UserPrincipalName="priya.sharma@corp.onmicrosoft.com"
earliest=-30m
| eval distance = haversine(prev_lat,prev_lon,lat,lon)
| where distance > 500 AND time_diff_min < 60
| table _time, IPAddress, Location, distance, time_diff_min`,
    previous_incidents:["No previous incidents for priya.sharma in 90 days"],
    change_windows:[],
  },

  edr:{
    tool:"SentinelEDR",
    sensor_id:"N/A — cloud identity incident",
    prevention_policy:"N/A",
    policy_note:"This is an identity incident — no endpoint EDR data. Investigate via Azure AD sign-in logs and M365 audit log.",
    process_tree:[],
    network:[
      {time:"09:20:02",proto:"HTTPS",src:"10.10.5.22",      dst:"login.example-corp.com",proc:"Chrome",bytes:"normal",state:"SUCCESS — Mumbai office",bad:false},
      {time:"09:23:58",proto:"HTTPS",src:"198.51.100.47",   dst:"login.example-corp.com",proc:"Chrome",bytes:"normal",state:"SUCCESS — Amsterdam (attacker)",bad:true},
      {time:"09:25:14",proto:"HTTPS",src:"198.51.100.47",   dst:"corp.sharepoint.com",       proc:"Browser",bytes:"142MB out",state:"ACTIVE — downloading",bad:true},
    ],
    timeline:[
      {time:"09:20:02",sev:"info",src:"Azure AD",event:"priya.sharma: normal login from Mumbai office — IP 10.10.5.22 — MFA approved on registered device"},
      {time:"09:15:00",sev:"high",src:"Azure AD",event:"[PRECURSOR] 31 MFA push notifications to priya.sharma in 7 minutes from 198.51.100.47 (Amsterdam)"},
      {time:"09:23:58",sev:"crit",src:"Azure AD",event:"priya.sharma: login approved from 198.51.100.47 (Amsterdam) — MFA fatigue attack — user approved push after 31 attempts"},
      {time:"09:24:11",sev:"crit",src:"Azure AD",event:"IMPOSSIBLE TRAVEL: 7,200km in 4 minutes — same user active in Mumbai AND Amsterdam simultaneously"},
      {time:"09:24:44",sev:"crit",src:"Azure AD",event:"Attacker session active — accessing M365 apps from Amsterdam"},
      {time:"09:25:14",sev:"high",src:"M365",    event:"Mass download: 23 files from SharePoint /sites/Finance — including Q4 payroll, HR records"},
      {time:"09:25:55",sev:"crit",src:"Azure AD",event:"New MFA device registered from attacker IP — persistence attempt"},
    ],
    file_events:[
      {time:"09:25:14",action:"DOWNLOAD",path:"/sites/Finance/Q4_Payroll_2026.xlsx",sha256:"",size:"47MB",signed:false},
      {time:"09:25:22",action:"DOWNLOAD",path:"/sites/Finance/HR_Employee_Records_Q2.csv",sha256:"",size:"12MB",signed:false},
      {time:"09:25:31",action:"DOWNLOAD",path:"/sites/HR/Compensation_Review_2026.xlsx",sha256:"",size:"8MB",signed:false},
    ],
  },

  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {type:"IP",value:"198.51.100.47",
       vt_score:"reported by 41 engines",abuse_score:89,
       categories:["Residential Proxy","Account Takeover Infrastructure","MFA Fatigue Tooling"],
       country:"NL",asn:"AS50673 — Serverius Datacenter",
       last_seen:"2026-05-28",campaigns:["MFA Fatigue ATO campaigns — Microsoft 365 targeting 2025-2026","Residential proxy network — used by multiple threat actors"],
       passive_dns:["No consistent domains — residential proxy rotation"],
       first_seen:"2024-08-15",verdict:"MALICIOUS — residential proxy used for ATO attacks",verdictColor:"#dc2626"},
    ],
  },

  desk:{
    tool:"IncidentDesk",ticket_id:"INC-2026-0447",sla_minutes:30,priority:"P1",
    category:"Identity — Account Takeover",subcategory:"Impossible Travel + MFA Fatigue",
    assignee:null,watchers:["soc-lead@corp.internal","ciso@corp.internal","hr-manager@corp.internal"],
    escalation_path:"SOC L1 → Identity Team → CISO → Legal/Privacy",
    updates:[],
  },

  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Read the Impossible Travel Alert",
      objective:"The SIEM fired: same user logged in from Mumbai at 09:20 and from Amsterdam at 09:24. 7,200 kilometres. 4 minutes. The question you need to answer is: is this physically possible? If not — one of those sessions is an attacker.",
      lookFor:["The distance and time — is 7,200km in 4 minutes physically possible?","Are BOTH sessions currently active at the same time?","Was MFA approved for the Amsterdam login — and how?","Is priya.sharma physically in the office right now?"],
      seniorThinking:"Impossible travel is one of the clearest True Positive signals in identity security. A human being cannot be in two places simultaneously. When I see this alert I immediately check: (1) are both sessions still active, (2) what is the user doing on each session. Active sessions mean active damage. Speed matters here more than any other incident type.",
      instruction:"Read the SIEM alert carefully. Confirm both sessions are simultaneously active. Understand the MFA fatigue component — how did the attacker get past MFA?",
      analyst_note:"priya.sharma is in the Mumbai office (badge reader confirms). Amsterdam session is an attacker. MFA fatigue: 31 push notifications in 7 minutes — user approved the 31st to stop the notifications. Active session downloading Finance data right now.",
      decision:{
        question:"priya.sharma is physically in the Mumbai office. There is an active M365 session from Amsterdam. What is this?",
        options:[
          {text:"Probably a VPN — users sometimes connect through different regions",correct:false,why:"Incorrect. A VPN would show the VPN server's IP — but the SAME user cannot physically be in Mumbai AND authenticate from Amsterdam simultaneously. VPN does not explain the Mumbai login 4 minutes earlier. This is account takeover."},
          {text:"Active account takeover — revoke the Amsterdam session immediately",correct:true,why:"Correct. priya.sharma is in the Mumbai office — confirmed by badge reader. An active session from Amsterdam is an attacker using her credentials. Revoke immediately — every second of delay means more data exfiltration."},
          {text:"Check with priya.sharma before acting — she might have authorised this",correct:false,why:"Incorrect prioritisation. The session is actively downloading Finance data right now. You revoke the session immediately and then check with priya.sharma. Do not let an active exfiltration continue while you make calls."},
          {text:"Escalate to identity team and wait for their decision",correct:false,why:"Incorrect. SOC L1 can and must revoke M365 sessions. Waiting for another team while an attacker downloads Finance and HR data is not acceptable."},
        ]
      },
      evidence_bullets:["priya.sharma: in Mumbai office — badge reader confirmed 09:17","Amsterdam session: active — 4 minutes after Mumbai login","MFA fatigue: 31 pushes in 7 minutes — user approved 31st to stop alerts","Mass download: 23 Finance/HR files in progress from Amsterdam session","New MFA device registered from attacker IP — persistence attempt"],
      action_label:"Confirm Active ATO — Open P1 Incident",
      action_result:"INC-2026-0447 opened — Active Account Takeover\nPriority: P1-Critical — SLA: 30 minutes\npriya.sharma: physically confirmed in office\nAttacker session: ACTIVE — downloading data\nNext: Revoke session IMMEDIATELY",
    },
    {
      id:1,phase:"CONTAINMENT",xp:35,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Revoke the Attacker Session — Stop the Exfiltration",
      objective:"The attacker is downloading Finance data right now. You have one priority: kill the session. In Azure AD, this is a single action — Revoke all sessions. Once you do this, the attacker's access token is immediately invalidated and they are logged out. Act before they finish downloading.",
      lookFor:["The 'Revoke all sessions' function in Azure AD — this invalidates refresh tokens","Do you also need to remove the new MFA device the attacker registered?","Should you force a password reset — or wait until after forensics?","What happens to the legitimate Mumbai session when you revoke all sessions?"],
      seniorThinking:"Revoke all sessions in Azure AD is immediate. The attacker loses access within seconds. The legitimate user (priya.sharma in Mumbai) also gets logged out — that is acceptable. You can call her and have her log back in. The cost of 2 minutes of disruption is much less than the cost of continued data exfiltration.",
      instruction:"Take the containment action — revoke all sessions for priya.sharma. Then remove the attacker-registered MFA device. Then force a password reset.",
      analyst_note:"Revoke → remove rogue MFA device → force password reset. This sequence ensures the attacker cannot re-authenticate using the new MFA device they registered.",
      decision:{
        question:"After revoking sessions, the attacker had registered a new MFA device. What must you do next?",
        options:[
          {text:"Nothing — revoking the session already removed their access",correct:false,why:"Incorrect. Session revocation removes the current access token. But the attacker registered a new MFA device — if they try to log in again with the (currently still valid) password, they can approve the MFA push on their registered device. Remove the rogue MFA device AND force a password reset."},
          {text:"Remove the rogue MFA device AND force a password reset",correct:true,why:"Correct. Three-step containment: (1) Revoke sessions — removes current access. (2) Remove rogue MFA device — prevents re-authentication via attacker's device. (3) Force password reset — invalidates the credential entirely. All three steps are required."},
          {text:"Only force a password reset — that invalidates everything",correct:false,why:"Partially correct. Password reset does invalidate the credential. But the rogue MFA device remains registered — if the user resets their password and the device is still there, it creates confusion and a potential backdoor for re-registration attacks."},
          {text:"Lock the account permanently until IT can review",correct:false,why:"Unnecessary. Full account lockout stops the attacker but also stops the legitimate user from working. Targeted containment (revoke + remove device + reset password) achieves security without permanent disruption."},
        ]
      },
      evidence_bullets:["Session revoked: attacker logged out within seconds","Downloads stopped: 23 files downloaded before containment (partial exfiltration)","Rogue MFA device 'Samsung Galaxy Unknown': removed","Password reset: forced — priya.sharma notified via SMS to office phone","priya.sharma: informed — logging back in from Mumbai session"],
      action_label:"Revoke Session + Remove Rogue MFA + Force Password Reset",
      action_result:"priya.sharma — all sessions REVOKED (09:31:44)\nAttacker session: TERMINATED — active download stopped\nRogue MFA device: REMOVED\nPassword: FORCE RESET — notified via secondary channel\nTime attacker had access: 7 minutes 46 seconds\nFiles downloaded before containment: 23 files (Finance + HR)",
    },
    {
      id:2,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Profile the Attacker Infrastructure",
      objective:"Look up the Amsterdam IP in ThreatLens. You are looking for: what type of infrastructure is this (VPN? Tor? Residential proxy?)? Has this IP been used in other ATO attacks? Understanding the attacker helps you assess: is priya.sharma targeted, or is this mass credential stuffing?",
      lookFor:["The IP type — residential proxy means the attacker is hiding behind real users' IPs","Has this IP been seen in other Microsoft 365 ATO campaigns?","What does the campaign description tell you about attacker sophistication?","Is this likely targeted or opportunistic?"],
      seniorThinking:"Residential proxies are the hardest to block. Unlike Tor or VPN ranges, residential proxy IPs look like real users — they route traffic through compromised home routers. The fact that this attacker used a residential proxy + ran a 31-push MFA fatigue attack tells me this was deliberate, not a basic credential stuffing attack.",
      instruction:"Look up 198.51.100.47 in ThreatLens. Determine: targeted attack or opportunistic? What is the attacker's technique?",
      analyst_note:"Residential proxy network — used for targeted M365 ATO campaigns. MFA fatigue is a specific, deliberate technique. This was targeted. priya.sharma was likely selected because of her access to Finance SharePoint.",
      decision:{
        question:"The attacker used a residential proxy and ran a 31-push MFA fatigue attack. What does this tell you about the nature of the attack?",
        options:[
          {text:"Opportunistic — attackers just try everything and hope it works",correct:false,why:"Incorrect. A 31-push MFA fatigue attack is not opportunistic. It requires knowing the target's email and password (credential stuffing from a previous breach), then deliberately bombarding them with MFA notifications hoping they approve to stop the noise. This is targeted."},
          {text:"Targeted — the attacker knew priya.sharma's credentials and deliberately used MFA fatigue to bypass MFA",correct:true,why:"Correct. This attack required: (1) priya.sharma's valid credentials (from a prior breach or phishing), (2) knowledge that MFA fatigue would work on her, (3) deliberate targeting of her Finance SharePoint access. This is a sophisticated, targeted attack."},
          {text:"Automated — a bot just ran credential stuffing against the company",correct:false,why:"Credential stuffing bots do not run 31-push MFA fatigue attacks — that requires a human operator monitoring and timing the pushes. Automated credential stuffing moves on after the first MFA prompt."},
          {text:"Insider — priya.sharma may have shared her credentials",correct:false,why:"The evidence does not support this. priya.sharma is confirmed in the Mumbai office, did not log in from Amsterdam, and had 31 MFA notifications before the attacker got in. She was the victim, not a participant."},
        ]
      },
      evidence_bullets:["IP 198.51.100.47 — AbuseIPDB: 89/100 — residential proxy","Proxy type: residential — hides attacker behind real home IPs","Campaign: M365 MFA fatigue ATO — targeted Finance sector","Technique: credential stuffing + MFA fatigue — not opportunistic","Implication: priya.sharma's credentials were previously compromised elsewhere"],
      action_label:"Profile Complete — Targeted Finance Attack",
      action_result:"Attacker profile:\nInfrastructure: residential proxy (high stealth)\nTechnique: credential stuffing + MFA fatigue\nTarget: Finance SharePoint access (priya.sharma)\nAssessment: TARGETED — credentials likely from prior breach\nAction required: check HaveIBeenPwned for priya.sharma email",
    },
    {
      id:3,phase:"CLOSE",xp:20,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Document + Data Breach Assessment",
      objective:"23 files were downloaded before containment — Finance payroll and HR records. This is a data breach. In India, DPDPA 2023 may require notification. Internationally, GDPR may apply if EU employee data was exposed. Document the breach scope carefully — Legal needs this.",
      lookFor:["What data was downloaded — is it PII? Payroll? HR records?","How many individuals are affected?","What are the DPDPA/GDPR notification obligations?","What recommendations prevent this class of attack in future?"],
      seniorThinking:"Every ATO with data exfiltration is potentially a notifiable data breach. I never decide alone whether notification is required — I document the facts and escalate to Legal. What I do provide is precise scope: which files, how many records, what data classification. Legal uses that to make the notification decision.",
      instruction:"Write the IR report. Document the exfiltrated files. Assess data sensitivity. Flag to Legal for DPDPA/GDPR assessment. Recommend controls to prevent MFA fatigue attacks.",
      analyst_note:"23 files downloaded — payroll and HR records — likely PII. DPDPA 2023 notification assessment required. Key recommendation: enable MFA number matching — eliminates MFA fatigue attacks entirely.",
      decision:{
        question:"23 Finance and HR files were downloaded before containment. What is the most critical recommendation to prevent this attack class?",
        options:[
          {text:"Block all overseas IP ranges from accessing M365",correct:false,why:"Too broad and impractical. Legitimate employees travel internationally. Blocking all overseas IPs would stop legitimate business. Use conditional access policies targeting high-risk sign-ins instead."},
          {text:"Enable MFA number matching — eliminates MFA fatigue attacks entirely",correct:true,why:"Correct. MFA number matching requires the user to enter a specific number displayed on their screen into the Authenticator app — they cannot blindly approve a push notification. This single control completely eliminates MFA fatigue attacks. It should have been enabled already."},
          {text:"Remove MFA entirely — it clearly failed here",correct:false,why:"Incorrect. MFA did not fail — MFA fatigue exploits user behaviour, not MFA itself. The fix is number matching, not removal. Removing MFA would make the account takeover trivial on the first attempt."},
          {text:"Require complex passwords and regular rotation",correct:false,why:"Not relevant here. The attacker already had the correct password — complexity and rotation are not the solution to this attack class. The vulnerability was MFA without number matching."},
        ]
      },
      evidence_bullets:["Files exfiltrated: 23 files — payroll, HR records — probable PII","Attacker access window: 7 minutes 46 seconds","Affected individuals: estimated 200+ (payroll data)","Legal referral: DPDPA 2023 + GDPR assessment required","Key control gap: MFA number matching not enabled"],
      action_label:"Submit IR Report — Refer to Legal for Breach Assessment",
      action_result:"INC-2026-0447 — CLOSED\n\nEXEC SUMMARY: Targeted MFA fatigue attack on priya.sharma. 23 Finance/HR files exfiltrated. Session revoked in 7m 46s.\n\nDATA BREACH: 23 files including payroll + HR records — Legal referral sent\nDPDPA 2023 + GDPR assessment: INITIATED\n\nROOT CAUSE: MFA number matching not enabled — MFA fatigue possible\n\nRECOMMENDATION: Enable MFA number matching IMMEDIATELY for all 8,241 users | Conditional Access: block high-risk sign-ins | User awareness: MFA fatigue training",
    },
  ]
},



// ── SCENARIO 02: IT Admin PowerShell — FALSE POSITIVE ─────────────────────
"INC-2026-0502":{
  id:"INC-2026-0502",
  title:"Suspicious PowerShell Execution — MGMT-SRV-01",
  severity:"High",
  status:"New",
  created:tsNow(0),
  host:"MGMT-SRV-01",
  user:"svc_backup@corp.internal",
  srcIp:"10.10.1.88",
  c2Ip:null,
  assignee:null,
  tags:["PowerShell","Encoded Command","Service Account","False Positive"],
  summary:"BlueTrace SIEM triggered ENCODED_POWERSHELL rule on MGMT-SRV-01. Service account svc_backup executed powershell.exe with -EncodedCommand flag at 02:30 IST. EDR score: 62/100. No network beaconing observed. Investigate before escalating.",
  mitre:["T1059.001"],
  isTP:false,

  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-1122 — Encoded PowerShell on Server",
    fired_at:tsNow(0),
    risk_score:62,
    alerts:[
      {id:"BT-5501",time:"02:30:11",sev:"High",rule:"ENCODED_POWERSHELL",src:"EDR",msg:"svc_backup executed powershell.exe -EncodedCommand on MGMT-SRV-01 — Score: 62/100"},
      {id:"BT-5502",time:"02:30:14",sev:"Intermediate",rule:"SERVICE_ACCOUNT_INTERACTIVE",src:"EDR",msg:"Service account svc_backup running interactive process — unusual for service accounts"},
      {id:"BT-5503",time:"02:30:45",sev:"Low",rule:"LARGE_FILE_READ",src:"EDR",msg:"svc_backup read 47GB from \\\\FS-CORP-01\\Backups in 30 seconds — backup job pattern"},
    ],
    raw_search:`index=corp_events host=MGMT-SRV-01 user=svc_backup earliest=02:25 latest=02:40
| stats count by rule, CommandLine
| where rule="ENCODED_POWERSHELL"`,
    correlated_hosts:["MGMT-SRV-01"],
    previous_incidents:["INC-2026-0499 (Low, same host, same pattern, closed — confirmed backup job, 7 days ago)","INC-2026-0487 (Low, same host, same pattern, closed — confirmed backup job, 14 days ago)"],
  },

  edr:{
    tool:"SentinelEDR",
    sensor_id:"3c4d5e6f7a8b",
    sensor_version:"7.14.17706",
    prevention_policy:"CORP-SERVER-DETECT-ONLY",
    policy_note:"Server policy — detect only, no auto-kill",
    process_tree:[
      {pid:"1204",ppid:"652", depth:0,name:"services.exe",  sha256:"",score:0, bad:false,time:"00:00:01",user:"NT AUTHORITY\\SYSTEM",cmd:"C:\\Windows\\System32\\services.exe"},
      {pid:"4488",ppid:"1204",depth:1,name:"svchost.exe",   sha256:"",score:0, bad:false,time:"00:00:05",user:"NT AUTHORITY\\SYSTEM",cmd:"C:\\Windows\\System32\\svchost.exe -k netsvcs"},
      {pid:"5612",ppid:"4488",depth:2,name:"BackupAgent.exe",sha256:"",score:4,bad:false,time:"02:30:05",user:"CORP\\svc_backup",cmd:"\"C:\\Program Files\\CorpBackup\\BackupAgent.exe\" --schedule nightly --target \\\\FS-CORP-01\\Backups"},
      {pid:"5701",ppid:"5612",depth:3,name:"powershell.exe",sha256:"",score:62,bad:false,time:"02:30:11",user:"CORP\\svc_backup",cmd:"powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMwA="},
    ],
    network:[
      {time:"02:30:14",proto:"SMB",src:"10.10.1.88:49882",dst:"10.10.1.200:445",proc:"BackupAgent.exe",bytes:"47GB read",state:"COMPLETED",bad:false},
      {time:"02:30:45",proto:"HTTPS",src:"10.10.1.88:51001",dst:"10.10.1.50:443",proc:"BackupAgent.exe",bytes:"2.1GB sent",state:"COMPLETED",bad:false},
    ],
    timeline:[
      {time:"02:29:55",sev:"info",src:"SentinelEDR",event:"BackupAgent.exe started — scheduled task: NightlyBackup — running as svc_backup"},
      {time:"02:30:05",sev:"info",src:"SentinelEDR",event:"BackupAgent.exe connecting to FS-CORP-01 — SMB — reading backup source"},
      {time:"02:30:11",sev:"med", src:"SentinelEDR",event:"powershell.exe launched — parent: BackupAgent.exe — -EncodedCommand flag — score 62"},
      {time:"02:30:14",sev:"info",src:"SentinelEDR",event:"SMB read: 47GB from \\\\FS-CORP-01\\Backups — typical nightly backup volume"},
      {time:"02:30:45",sev:"info",src:"SentinelEDR",event:"HTTPS upload: 2.1GB to 10.10.1.50 (CORP-BACKUP-SRV) — internal backup destination"},
      {time:"02:31:12",sev:"info",src:"SentinelEDR",event:"BackupAgent.exe exited cleanly — exit code 0 — backup completed"},
    ],
    file_events:[],
  },

  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {
        type:"IP",value:"10.10.1.50",
        vt_score:"0/90 — clean",
        abuse_score:0,
        categories:["Internal IP — Corporate Backup Server"],
        country:"INT",asn:"Internal — Corp Network",
        last_seen:"",
        campaigns:[],
        passive_dns:["backup-srv.corp.internal","CORP-BACKUP-SRV"],
        first_seen:"",
        verdict:"INTERNAL — Corporate backup server 10.10.1.50 = CORP-BACKUP-SRV. Registered in IPAM. Known asset.",
        verdictColor:"#16a34a",
      },
      {
        type:"Process",value:"BackupAgent.exe",
        vt_score:"0/72 — clean",
        abuse_score:0,
        categories:["Legitimate backup software — CorpBackup v4.2"],
        country:"",asn:"",
        last_seen:"",
        campaigns:[],
        passive_dns:[],
        first_seen:"",
        verdict:"LEGITIMATE — CorpBackup v4.2. Signed by CorpBackup Ltd. Installed on 12 management servers. Approved software.",
        verdictColor:"#16a34a",
      },
    ],
  },

  desk:{
    tool:"IncidentDesk",
    ticket_id:"INC-2026-0502",
    sla_minutes:120,
    priority:"P3",
    category:"Suspicious Process",
    subcategory:"Encoded PowerShell",
    assignee:null,
    watchers:["soc-lead@corp.internal"],
    escalation_path:"SOC L1 → SOC L2 → IT Operations",
    updates:[],
  },

  steps:[
    {
      id:0,phase:"TRIAGE",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Read the Alert — Spot the Differences",
      objective:"This alert looks similar to the C2 beacon you investigated before — encoded PowerShell on a Windows host. But look more carefully. What is different about this alert compared to a real malware infection? What makes you pause before escalating?",
      lookFor:["The risk score — 62/100. Not 97. What does that tell you?","The user account — svc_backup. What kind of account is that?","The time — 02:30. Does backup software often run at night?","Previous incidents on the same host — read them carefully"],
      seniorThinking:"Before I escalate anything, I check previous incidents on the same host. Two closed Low incidents in the last 14 days with identical patterns, both confirmed backup jobs. That tells me this is probably the same thing. I still investigate — but my prior is False Positive.",
      instruction:"Read the alert carefully. Check the risk score, user, time, and especially the previous incidents on this host. What is your initial assessment before you even open the EDR?",
      analyst_note:"Risk score 62 is suspicious but not definitive. Service account running at 02:30 is expected for overnight jobs. Two previous identical incidents both closed as backup jobs. This pattern points strongly to False Positive.",
      decision:{
        question:"Based on the SIEM alert alone, what is your initial assessment?",
        options:[
          {text:"Likely False Positive — looks like scheduled backup activity",correct:true,why:"Good instinct. A 62/100 score, service account, overnight timing, and two previous identical closed incidents all point to legitimate activity. You still need to verify in the EDR — but your prior is correct."},
          {text:"Definitely malicious — encoded PowerShell is always bad",correct:false,why:"Not always. Encoded PowerShell is a technique attackers USE, but many legitimate tools also use it to pass complex commands. Always check context before concluding malicious."},
          {text:"Escalate immediately to P1",correct:false,why:"Premature. A P3 High with no network beaconing, a service account, overnight timing, and previous false positives on this host does not warrant P1 escalation without investigation."},
          {text:"Not enough information — need to see the EDR",correct:true,why:"Also correct. You cannot confirm without checking the process tree. Good analysts form a hypothesis from the SIEM and then verify in the EDR."},
        ]
      },
      evidence_bullets:["Risk Score: 62/100 — Medium confidence, not high","User: svc_backup (service account, not a human user)","Time: 02:30 IST — typical overnight maintenance window","Previous: 2 identical incidents closed as backup jobs in 14 days","No network beaconing alerts in correlated events"],
      action_label:"Investigate in SentinelEDR — Check Process Tree",
      action_result:"Moving to SentinelEDR to verify the process chain.\nHypothesis: Scheduled backup job\nStatus: Investigating",
    },
    {
      id:1,phase:"INVESTIGATION",xp:25,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Read the Process Tree — Who is the Parent?",
      objective:"Open the process tree for MGMT-SRV-01. Look at what launched the PowerShell process. The parent process tells you almost everything. In a real attack the chain usually starts with something user-facing — email, browser, document. What do you see here?",
      lookFor:["What is the IMMEDIATE parent of powershell.exe?","What is the grandparent — what started BackupAgent.exe?","Does the execution chain start from something a user touched?","Does BackupAgent.exe look like a known, legitimate application?"],
      seniorThinking:"When I see services.exe → svchost.exe → BackupAgent.exe → powershell.exe I am not worried. That chain starts from the Windows Service Control Manager — which means it is a scheduled service, not something a user or attacker triggered manually. If it started from OUTLOOK.EXE or explorer.exe, that is different.",
      instruction:"Open the process tree. Trace the execution chain from the top. Focus on what started BackupAgent.exe and what it spawned.",
      analyst_note:"services.exe → svchost.exe → BackupAgent.exe is a Windows Service startup chain. This is how scheduled services launch. No user interaction. No suspicious parent.",
      decision:{
        question:"The process tree shows: services.exe → svchost.exe → BackupAgent.exe → powershell.exe. What does this chain indicate?",
        options:[
          {text:"Scheduled service startup — BackupAgent ran as a Windows service",correct:true,why:"Correct. services.exe and svchost.exe are the Windows Service Control Manager stack. A chain starting from services.exe means this was a scheduled service, not a user action or malicious execution."},
          {text:"Malware — powershell.exe should never be spawned by backup software",correct:false,why:"Incorrect. Many legitimate backup tools use PowerShell for scripting tasks. The key question is not whether PowerShell was spawned — it is who spawned it and why."},
          {text:"Lateral movement — attacker used a service account to run PowerShell",correct:false,why:"Incorrect. Lateral movement usually involves network authentication and process execution on a REMOTE host. This chain is entirely local and starts from the Windows service stack — not from an incoming network connection."},
          {text:"The PowerShell score is 62 so it must be suspicious",correct:false,why:"Score alone is not a verdict. Context matters. A 62 on encoded PowerShell spawned from a known backup application running as a scheduled service is not the same as a 62 on encoded PowerShell spawned from WINWORD.EXE."},
        ]
      },
      evidence_bullets:["Parent chain: services.exe → svchost.exe → BackupAgent.exe","services.exe = Windows Service Control Manager (legitimate)","BackupAgent.exe signed by CorpBackup Ltd — score 4/100","Execution time: 02:30 matches backup schedule","No unexpected network destinations — all internal corporate IPs"],
      action_label:"Verify BackupAgent in ThreatLens",
      action_result:"Process chain analysis complete:\nParent: Windows Service Control Manager (legitimate)\nBackupAgent.exe: corporate backup software\nNetworks: all internal — no external C2\nStatus: Moving to ThreatLens to confirm software identity",
    },
    {
      id:2,phase:"INVESTIGATION",xp:15,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Confirm the Software Identity",
      objective:"Before closing this as a False Positive, confirm the binary. Look up BackupAgent.exe and the destination IP 10.10.1.50. Check if the software is known, signed, and legitimate. This is due diligence — not every backup alert is a false positive.",
      lookFor:["Is BackupAgent.exe a known, signed application?","Is 10.10.1.50 a known internal asset?","What does the passive DNS show for 10.10.1.50?","Does anything in ThreatLens contradict the process tree story?"],
      seniorThinking:"I always verify even when I am 90% sure it is a false positive. Why? Because attackers have been known to name malware after legitimate tools. Checking takes 30 seconds. Missing a real attack because I was lazy takes months to recover from.",
      instruction:"Look up BackupAgent.exe and 10.10.1.50 in ThreatLens. Confirm they are clean before closing.",
      analyst_note:"BackupAgent.exe — 0/72 VirusTotal, signed by CorpBackup Ltd, installed on 12 management servers. 10.10.1.50 = CORP-BACKUP-SRV — registered in internal IPAM. Both clean.",
      decision:{
        question:"ThreatLens shows BackupAgent.exe is clean, signed, and installed on 12 management servers. What is your final classification?",
        options:[
          {text:"False Positive — close the ticket with documentation",correct:true,why:"Correct. Clean binary, internal destination, legitimate service chain, overnight schedule, two previous identical FPs. This is a False Positive. Document your reasoning and close."},
          {text:"True Positive — still looks suspicious",correct:false,why:"Incorrect. You have verified: signed legitimate binary, internal destination, service startup chain, overnight schedule, consistent with two previous confirmed FPs. All evidence points to legitimate activity."},
          {text:"Escalate to SOC L2 for a second opinion",correct:false,why:"Unnecessary escalation. A well-documented investigation showing clean binary, internal traffic, scheduled service chain, and historical precedent is sufficient to close. Escalate only when evidence is ambiguous."},
          {text:"Block BackupAgent.exe just to be safe",correct:false,why:"Incorrect. Blocking a legitimate backup tool on 12 management servers would disrupt business operations significantly. Never block without confirmed evidence of malicious activity."},
        ]
      },
      evidence_bullets:["BackupAgent.exe — VirusTotal: 0/72 — CLEAN","Signed by: CorpBackup Ltd (valid signature)","Installed on: 12 management servers (known asset)","10.10.1.50 — IPAM: CORP-BACKUP-SRV — Internal","All network connections: internal corporate IPs only"],
      action_label:"Close as FALSE POSITIVE — Document Findings",
      action_result:"INC-2026-0502 — FALSE POSITIVE — CLOSED\n\nCLASSIFICATION: False Positive\nEVIDENCE: Scheduled backup job by CorpBackup v4.2\n  → Legitimate binary (0/72 VT, signed)\n  → Service account scheduled task\n  → All traffic internal\n  → 2 prior identical incidents confirmed FP\n\nACTION: Added exception rule for BackupAgent.exe + svc_backup\nRECOMMENDATION: Tune ENCODED_POWERSHELL rule to exclude approved backup service accounts during maintenance windows\n\n+20 XP for correct False Positive identification",
    },
  ],
},



// ── SCENARIO 03: Impossible Travel — Azure AD Account Takeover ─────────────
"INC-2026-0521":{
  id:"INC-2026-0521",
  title:"Impossible Travel — Azure AD Account Takeover",
  severity:"Critical",
  status:"New",
  created:tsNow(0),
  host:"Azure AD / M365",
  user:"priya.sharma@corp.onmicrosoft.com",
  srcIp:"203.0.113.23",
  c2Ip:null,
  assignee:null,
  tags:["Impossible Travel","MFA Fatigue","Account Takeover","Azure AD","Identity"],
  summary:"Sentinel fired Impossible Travel alert. priya.sharma authenticated from Mumbai at 11:20 UTC and from Amsterdam 4 minutes later — physically impossible. 47 MFA push notifications sent in 8 minutes. One was approved. Active session from NL IP. Investigate and contain immediately.",
  mitre:["T1621","T1078","T1528","T1098.005"],
  isTP:true,

  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-3381 — Impossible Travel + MFA Fatigue Pattern",
    fired_at:tsNow(0),
    risk_score:96,
    alerts:[
      {id:"BT-8801",time:"11:23:47",sev:"Critical",rule:"IMPOSSIBLE_TRAVEL",src:"Azure AD",msg:"priya.sharma — login from IN (Mumbai) at 11:20 then NL (Amsterdam) at 11:24 — distance 7,200km — travel time 4 min — physically impossible"},
      {id:"BT-8802",time:"11:23:47",sev:"Critical",rule:"MFA_FATIGUE_DETECTION",src:"Azure AD",msg:"47 MFA push notifications to priya.sharma in 8 minutes — 46 denied — 1 approved at 11:23:47 — attacker persistence pattern"},
      {id:"BT-8803",time:"11:24:58",sev:"High",rule:"NEW_MFA_DEVICE_REGISTERED",src:"Azure AD",msg:"New Authenticator app registered by priya.sharma from IP 203.0.113.23 — device: iPhone-Unknown — not corporate MDM enrolled"},
      {id:"BT-8804",time:"11:25:14",sev:"High",rule:"OAUTH_CONSENT_GRANT",src:"Azure AD",msg:"OAuth app 'OfficeExtension' granted Mail.Read + Files.ReadWrite.All by priya.sharma — unknown publisher"},
      {id:"BT-8805",time:"11:31:00",sev:"High",rule:"MASS_CLOUD_DOWNLOAD",src:"SharePoint",msg:"priya.sharma downloaded 2.3GB from SharePoint in 11 minutes — Finance + HR folders"},
    ],
    raw_search:`index=azure_ad sourcetype=azure:aad:signin
UserPrincipalName="priya.sharma@corp.onmicrosoft.com"
earliest=-30m
| table _time, IPAddress, Location, ResultType, AuthMethod, RiskLevel
| sort _time`,
    correlated_hosts:["Azure AD","SharePoint Online","Exchange Online"],
    previous_incidents:["No previous incidents for priya.sharma"],
  },

  edr:{
    tool:"IdentityVault",
    sensor_id:"AzureAD-Tenant-Corp",
    sensor_version:"Entra ID P2",
    prevention_policy:"Conditional Access — Standard",
    policy_note:"No high-risk sign-in block policy active — gap identified",
    process_tree:[],
    network:[
      {time:"11:20:11",proto:"HTTPS",src:"192.0.2.11:44201",dst:"login.example-corp.com:443",proc:"Azure AD Sign-in",bytes:"",state:"SUCCESS — Mumbai IN",bad:false},
      {time:"11:23:47",proto:"HTTPS",src:"203.0.113.23:42341",dst:"login.example-corp.com:443",proc:"Azure AD Sign-in",bytes:"",state:"SUCCESS — Amsterdam NL",bad:true},
      {time:"11:31:00",proto:"HTTPS",src:"192.0.2.10:55001",dst:"corp.sharepoint.com:443",proc:"SharePoint Download",bytes:"2.3GB",state:"COMPLETED",bad:true},
    ],
    timeline:[
      {time:"11:15:00",sev:"high",src:"Azure AD",event:"MFA push notifications begin for priya.sharma — source IP: 203.0.113.23 (NL)"},
      {time:"11:20:11",sev:"info",src:"Azure AD",event:"priya.sharma successful login — IP: 192.0.2.11 — Location: Mumbai IN — legitimate session"},
      {time:"11:22:55",sev:"crit",src:"Azure AD",event:"46 MFA denials in 7 minutes — priya.sharma device receiving constant push notifications"},
      {time:"11:23:47",sev:"crit",src:"Azure AD",event:"MFA APPROVED — priya.sharma approves push notification #47 — IP: 203.0.113.23 — Amsterdam NL"},
      {time:"11:24:02",sev:"crit",src:"Azure AD",event:"IMPOSSIBLE TRAVEL: previous login Mumbai IN 4 min ago — 7,200km distance — impossible"},
      {time:"11:24:58",sev:"crit",src:"Azure AD",event:"New Authenticator device registered — iPhone-Unknown — not in MDM — persistence established"},
      {time:"11:25:14",sev:"high",src:"Azure AD",event:"OAuth consent: 'OfficeExtension' (unknown publisher) — Mail.Read + Files.ReadWrite.All granted"},
      {time:"11:31:00",sev:"high",src:"Azure AD",event:"SharePoint mass download — 47 files — 2.3GB — /Finance/ and /HR/ folders"},
    ],
    file_events:[
      {time:"11:31:00",action:"DOWNLOAD",path:"SharePoint:/sites/Finance/Q4_2026_Payroll_Data.xlsx",sha256:"",size:"47MB",signed:false},
      {time:"11:31:12",action:"DOWNLOAD",path:"SharePoint:/sites/HR/Employee_Records_2026.csv",sha256:"",size:"12MB",signed:false},
      {time:"11:31:44",action:"DOWNLOAD",path:"SharePoint:/sites/Finance/Board_Strategy_2027.pptx",sha256:"",size:"8MB",signed:false},
    ],
  },

  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {
        type:"IP",value:"203.0.113.23",
        vt_score:"reported by 54 engines",
        abuse_score:97,
        categories:["MFA Fatigue Infrastructure","Telegram CDN — Proxy","Known ATO Tooling"],
        country:"NL",asn:"AS62041 — Telegram Messenger",
        last_seen:"2026-05-28",
        campaigns:["Lapsus$ MFA fatigue operations 2025-2026","Oktapus — SIM swap + MFA fatigue campaign","Multiple corporate ATO incidents Q1 2026"],
        passive_dns:["proxy.t.me","malware-example.net"],
        first_seen:"2024-08-14",
        verdict:"MALICIOUS — Known MFA fatigue attack infrastructure. This IP has been used in multiple ATO campaigns.",
        verdictColor:"#dc2626",
      },
      {
        type:"App",value:"OfficeExtension (AppId: f4d9e8c7...)",
        vt_score:"flagged by 12 engines",
        abuse_score:88,
        categories:["Malicious OAuth App","Data Harvesting","Unknown Publisher"],
        country:"",asn:"",
        last_seen:"2026-05-28",
        campaigns:["Pre-positioned phishing OAuth app — registered 2026-05-01"],
        passive_dns:[],
        first_seen:"2026-05-01",
        verdict:"MALICIOUS — Unknown publisher OAuth app requesting sensitive permissions. Pre-positioned for this attack.",
        verdictColor:"#dc2626",
      },
    ],
  },

  desk:{
    tool:"IncidentDesk",
    ticket_id:"INC-2026-0521",
    sla_minutes:60,
    priority:"P1",
    category:"Identity Attack — Account Takeover",
    subcategory:"MFA Fatigue / Impossible Travel",
    assignee:null,
    watchers:["soc-lead@corp.internal","ciso@corp.internal"],
    escalation_path:"SOC L1 → SOC L2 → IR Team → CISO → Legal",
    updates:[],
  },

  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Understand the Alert — Identity Attack Pattern",
      objective:"This is a different type of incident. No endpoint malware. No process tree. This is an identity attack — the attacker did not break into a computer, they broke into a person's account. Look at the alerts and think: what actually happened here? How did the attacker get in?",
      lookFor:["The MFA fatigue alert — what does 47 push notifications in 8 minutes mean?","The impossible travel alert — what does Mumbai to Amsterdam in 4 minutes mean?","The sequence of events — which alert came first, which came after?","Is the attacker still logged in right now?"],
      seniorThinking:"MFA fatigue is simple but effective. The attacker has the password — probably from a previous breach or phishing. They bombard the user with push notifications hoping the user approves one out of frustration or confusion. The impossible travel confirms a second person is logged in from a different country. This is active right now.",
      instruction:"Read all 5 alerts. Understand the sequence. The attacker is likely still in the account. What is the immediate priority?",
      analyst_note:"Active session. Attacker is logged in right now. Data exfiltration may still be in progress. Revoke the session immediately — investigate after containment.",
      decision:{
        question:"An attacker has an active session in priya.sharma's account right now. What do you do FIRST?",
        options:[
          {text:"Revoke all active sessions immediately, then investigate",correct:true,why:"Correct. An active attacker session means damage is happening in real time. Revoke first, investigate second. Every minute the session is active = more data exfiltrated."},
          {text:"Investigate all the evidence before taking any action",correct:false,why:"Incorrect for this situation. When an attacker has an active session, time matters. You do not have the luxury of a full investigation before acting. Revoke first."},
          {text:"Email priya.sharma to ask if she recognises the login",correct:false,why:"Too slow. Emailing the user takes time they may not have. Also, if the attacker controls her email (via the OAuth app), they might see your message. Act immediately."},
          {text:"Block the IP 203.0.113.23 at the firewall",correct:false,why:"Partially helpful but insufficient. Blocking the IP does not kill the existing authenticated session. The attacker can simply switch IPs. Revoke the session tokens directly."},
        ]
      },
      evidence_bullets:["47 MFA pushes in 8 min — 1 approved — MFA fatigue attack confirmed","Mumbai login at 11:20 + Amsterdam login at 11:24 — IMPOSSIBLE TRAVEL","Attacker session: ACTIVE — still logged in","New rogue MFA device registered at 11:24:58","Mass download: 2.3GB from Finance + HR SharePoint"],
      action_label:"Revoke Session + Disable Account Immediately",
      action_result:"priya.sharma — all sessions REVOKED (11:32:04 UTC)\nAccount: DISABLED temporarily\nAttacker session: TERMINATED\nActive time: 8 minutes 17 seconds\nNext: Remove persistence mechanisms",
    },
    {
      id:1,phase:"INVESTIGATION",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Understand What the Attacker Did",
      objective:"Session revoked. Now investigate the damage. In 8 minutes the attacker took several actions. Look at the timeline and audit logs. What persistence mechanisms did they establish? What data did they access? You need this for your report and for Legal.",
      lookFor:["The rogue MFA device — registered at 11:24:58 — still present","The OAuth app 'OfficeExtension' — what permissions does it have?","SharePoint downloads — which files? What classification?","Did the attacker set up any email forwarding rules?"],
      seniorThinking:"Attackers rarely just read data and leave. They plant persistence. In M365 attacks I always check: (1) new MFA methods registered, (2) OAuth app consents, (3) inbox forwarding rules, (4) mail delegate access. The 8 minutes was enough time for all four.",
      instruction:"Review the full timeline. Identify all persistence mechanisms the attacker established. Document every action for the Legal team — data exposure requires regulatory notification.",
      analyst_note:"Rogue MFA device + OAuth app = two persistence mechanisms. Both must be removed. 2.3GB download = likely PII (payroll, HR records). DPDPA 2023 breach notification may apply.",
      decision:{
        question:"The attacker registered a new MFA device and granted an OAuth app access. In what order should you remove these?",
        options:[
          {text:"Remove rogue MFA device first, then revoke OAuth app consent",correct:true,why:"Correct order. The rogue MFA device is an authentication backdoor — it lets the attacker log back in. Remove it first. Then revoke the OAuth app which has persistent API access even without an active session."},
          {text:"Revoke OAuth app first, MFA device second",correct:false,why:"Partially correct but wrong priority. The OAuth app can operate independently of sessions (via API tokens). But the MFA device is more dangerous — it lets the attacker create NEW sessions. Remove authentication persistence first."},
          {text:"Both at the same time — order does not matter",correct:false,why:"Incorrect. The MFA device allows re-authentication — if you revoke the OAuth app first but leave the MFA device, the attacker can log back in and re-grant the OAuth app. Sequence matters."},
          {text:"Neither — wait for the user to confirm what happened",correct:false,why:"Incorrect. You should not wait. Both mechanisms are active threats. Remove them immediately and notify the user afterward."},
        ]
      },
      evidence_bullets:["Rogue MFA device: iPhone-Unknown — not MDM enrolled — MUST REMOVE","OAuth app OfficeExtension: Mail.Read + Files.ReadWrite.All — MUST REVOKE","SharePoint: 47 files downloaded — 2.3GB — Finance + HR data (PII likely)","Email forwarding rules: checking audit log","Active time: 8 min 17 sec before containment"],
      action_label:"Remove Rogue MFA Device + Revoke OAuth App",
      action_result:"Persistence removed:\n[✓] Rogue MFA device iPhone-Unknown — DELETED\n[✓] OAuth app OfficeExtension consent — REVOKED\n[✓] All active refresh tokens — INVALIDATED\nEmail forwarding rules: NONE found\nDelegate access: NONE found\nStatus: Account persistence cleared",
    },
    {
      id:2,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Enrich the Attack Source",
      objective:"Look up the attacker's IP 203.0.113.23 in ThreatLens. Before you read the verdict — look at the raw data. What category is this IP in? What campaigns has it been seen in? How long has it been active? This tells you if this is a targeted attack or opportunistic.",
      lookFor:["What categories does ThreatLens assign to this IP?","Has this IP been seen in previous campaigns?","How long has this IP been active as a threat?","Does the campaign name tell you anything about the threat actor?"],
      seniorThinking:"Lapsus$ and Oktapus are known for exactly this — MFA fatigue against M365 and Okta environments. When I see this IP associated with those campaigns, I know this is not a random attack. This is a professional criminal group targeting corporate M365 tenants. That changes the severity of my report.",
      instruction:"Look up 203.0.113.23 in ThreatLens. Read the raw data before the verdict. What story does the threat intelligence tell?",
      analyst_note:"AbuseIPDB: 97/100. Associated with Lapsus$ and Oktapus MFA fatigue campaigns. This is a known criminal operation targeting M365 tenants.",
      decision:{
        question:"ThreatLens shows this IP is linked to Lapsus$/Oktapus MFA fatigue campaigns. What does this mean for your incident?",
        options:[
          {text:"This was a targeted professional attack — escalate to IR team and check for other victims",correct:true,why:"Correct. Lapsus$/Oktapus are organised criminal groups, not random script kiddies. If they targeted priya.sharma, they may have targeted others at Corp. Check if any other accounts received MFA fatigue attacks from this IP."},
          {text:"The campaign names are just labels — it does not change the response",correct:false,why:"Incorrect. Campaign attribution changes the threat model. A known professional group means: (1) they have your password from a prior breach, (2) they may have already targeted others, (3) IR team and CISO need to be briefed."},
          {text:"Block the IP and consider it contained",correct:false,why:"Insufficient. The attacker can change IPs. More importantly — they have the password. Password rotation and session revocation are more important than IP blocking."},
          {text:"Report to police immediately",correct:false,why:"Eventually, yes. But not your first action as an analyst. Your job right now is containment and investigation. Legal and compliance handle regulatory reporting."},
        ]
      },
      evidence_bullets:["IP 203.0.113.23 — AbuseIPDB: 97/100 — MFA fatigue tool","Associated: Lapsus$ + Oktapus campaigns (organised criminal groups)","Active since: 2024-08-14 (nearly 2 years of malicious activity)","Method: MFA fatigue — requires password to be already known","Implication: priya.sharma's password was previously compromised"],
      action_label:"Check Other Accounts + Brief IR Team",
      action_result:"Threat Intel briefing complete:\nAttacker: Lapsus$/Oktapus pattern — organised criminal group\nMethod: MFA fatigue (password already known — prior breach)\n\nBlast radius check: scanning 2,847 M365 accounts for same IP\nResults: 3 other accounts received push notifications — none approved\nAction: Force password reset on all 4 accounts\nIR team: BRIEFED\nCISO: NOTIFIED",
    },
    {
      id:3,phase:"CONTAINMENT",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Harden the Tenant — Close the Gap",
      objective:"You know how the attacker got in. There was no Conditional Access policy blocking high-risk sign-ins. There was no MFA number matching — just approve/deny push. These are the gaps. You need to fix them before this happens again tomorrow.",
      lookFor:["What Conditional Access policy was missing?","What is MFA Number Matching and why does it stop fatigue attacks?","Should high-risk sign-ins be blocked or just require MFA?","How do you prevent the same OAuth app trick again?"],
      seniorThinking:"Number Matching on Authenticator is the single most effective control against MFA fatigue. When enabled, the user must type a 2-digit code shown on the login screen into the Authenticator app. A tired or distracted user cannot accidentally approve a push they did not initiate — because they have to actively TYPE the number.",
      instruction:"Identify the two most important security controls that would have prevented this attack. Recommend them in your IncidentDesk ticket.",
      analyst_note:"Two controls: (1) CA policy blocking high-risk sign-ins. (2) MFA Number Matching. Either one alone would have stopped this attack.",
      decision:{
        question:"Which single change would have PREVENTED this MFA fatigue attack entirely?",
        options:[
          {text:"Enable MFA Number Matching on Authenticator push notifications",correct:true,why:"Correct. Number Matching requires the user to type a 2-digit code they see on the login screen into their Authenticator app. A fatigue attack relies on the user clicking Approve without thinking — Number Matching removes that possibility."},
          {text:"Block the IP 203.0.113.23 at the firewall",correct:false,why:"Ineffective. The attacker controls hundreds of IPs. Blocking one IP is playing whack-a-mole. Address the authentication weakness, not the source address."},
          {text:"Require the user to use a stronger password",correct:false,why:"Incorrect. The attacker already had the password. Password strength was not the issue — MFA approval was the issue."},
          {text:"Disable MFA and use password-only authentication",correct:false,why:"The opposite of the correct answer. MFA — even push-based — is still far better than no MFA. The fix is to make MFA stronger, not to remove it."},
        ]
      },
      evidence_bullets:["Control gap 1: No Conditional Access policy blocking high-risk sign-ins","Control gap 2: MFA push without Number Matching — auto-approve possible","Control gap 3: No OAuth app consent restriction — any publisher allowed","Control gap 4: No Impossible Travel policy requiring step-up auth","Root cause: All four gaps allowed together = complete account takeover"],
      action_label:"Implement Hardening + Force Password Reset",
      action_result:"Hardening applied:\n[✓] MFA Number Matching: ENABLED tenant-wide\n[✓] Conditional Access: Block sign-ins with High risk score\n[✓] OAuth consent: Restrict to verified publishers only\n[✓] Impossible Travel: Require FIDO2 key from non-IN IPs\n\npriya.sharma password: RESET (forced)\nAll 4 affected accounts: Passwords reset\nCISO: Briefed on tenant hardening",
    },
    {
      id:4,phase:"CLOSE",xp:15,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Document + Legal Notification",
      objective:"2.3GB of Finance and HR data was downloaded. This includes payroll data and employee records — that is PII. Under DPDPA 2023 (India) and potentially GDPR (EU employees), a data breach of this scale may require regulatory notification. Your IR report must document the data exposure clearly.",
      lookFor:["What data was actually downloaded? What is its classification?","Does this trigger DPDPA 2023 notification obligations?","What is the 72-hour notification clock for GDPR?","What should the executive summary say to the CISO?"],
      seniorThinking:"PII breach reporting is not optional. Once I confirm personal data was accessed by an unauthorised party, I flag it for Legal immediately. They determine whether notification is required — my job is to give them an accurate picture of what was accessed, when, and by whom.",
      instruction:"Write the IR report. Specifically note the data exposure. Flag for Legal team review. Include recommendations.",
      analyst_note:"Payroll data + HR records = PII. DPDPA 2023 notification assessment required. 72-hour GDPR clock may apply for EU data subjects. Document everything precisely.",
      decision:{
        question:"The attacker downloaded payroll data and HR records. Who must you notify immediately?",
        options:[
          {text:"Legal and Compliance team — for DPDPA/GDPR notification assessment",correct:true,why:"Correct. Once PII is confirmed compromised, Legal must assess regulatory notification obligations. DPDPA 2023 requires notification of significant data breaches. GDPR requires notification within 72 hours if EU data subjects are involved."},
          {text:"Only the CISO — keep it internal for now",correct:false,why:"Incorrect. A PII breach has legal notification obligations that are time-sensitive. Keeping it internal risks missing regulatory deadlines which can result in significant fines."},
          {text:"Only priya.sharma — it was her account",correct:false,why:"Incomplete. Affected individuals should be notified, but Legal must also be notified for regulatory obligations. It is not only about the account — it is about the data of all employees whose records were in those files."},
          {text:"No one — wait to see if the data appears publicly",correct:false,why:"Incorrect. Notification obligations exist regardless of whether the data is published. The breach occurred at the time of download, not when data appears publicly."},
        ]
      },
      evidence_bullets:["Data exposed: payroll records, HR employee data — PII confirmed","Volume: 2.3GB — 47 files — Finance + HR SharePoint","Attacker access window: 8 minutes 17 seconds","DPDPA 2023: significant breach threshold likely met","GDPR: EU data subjects in HR records — 72-hour clock started"],
      action_label:"Submit IR Report + Notify Legal",
      action_result:"INC-2026-0521 — CLOSED ✓\n\nATTACK: MFA Fatigue (Lapsus$/Oktapus pattern) → Azure AD ATO\nDATA EXPOSED: 47 files, 2.3GB — Payroll + HR (PII)\nRESPONSE TIME: 9 minutes (P1 SLA: 60 min) ✓\n\nROOT CAUSE: No Number Matching on MFA + No high-risk CA policy\n\nLEGAL: DPDPA 2023 assessment INITIATED\nGDPR: 72-hour clock STARTED\nHARDENING: Number Matching + CA policy live for 8,241 users\nPENDING: User notification | Regulatory filing | Forensic image of download logs",
    },
  ],
},



// ── SCENARIO 04: Vulnerability Scanner — FALSE POSITIVE ───────────────────
"INC-2026-0544":{
  id:"INC-2026-0544",
  title:"Network Port Scan — Vulnerability Assessment Activity",
  severity:"Medium",status:"New",created:tsNow(0),
  host:"Multiple — 192.168.1.0/24",user:"svc_scanner@corp.internal",
  srcIp:"10.10.5.20",c2Ip:null,assignee:null,
  tags:["Port Scan","Vulnerability Scanner","False Positive","Network"],
  summary:"BlueTrace SIEM fired INTERNAL_PORT_SCAN on 10.10.5.20. Source is scanning 847 internal hosts on ports 22,80,443,3389,445 sequentially. Pattern matches reconnaissance or lateral movement. Investigate before escalating.",
  mitre:["T1046"],isTP:false,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-0882 — Internal Host Port Scan",
    fired_at:tsNow(0),risk_score:58,
    alerts:[
      {id:"BT-4401",time:"10:15:00",sev:"Medium",rule:"INTERNAL_PORT_SCAN",src:"NDR",msg:"10.10.5.20 scanned 847 internal hosts on ports 22,80,443,3389,445 in 6 minutes — sequential sweep pattern"},
      {id:"BT-4402",time:"10:15:30",sev:"Low",rule:"EXCESSIVE_CONNECTIONS",src:"NDR",msg:"10.10.5.20 made 4,235 connection attempts in 6 minutes — automated tool pattern"},
    ],
    raw_search:`index=network src_ip=10.10.5.20 earliest=10:00 latest=10:30
| stats count by dest_port, dest_ip
| sort -count`,
    correlated_hosts:["10.10.5.20"],
    previous_incidents:["INC-2026-0512 (Low, same source, closed — vulnerability scan, 7 days ago)","INC-2026-0498 (Low, same source, closed — vulnerability scan, 14 days ago)"],
  },
  edr:{
    tool:"SentinelEDR",sensor_id:"",sensor_version:"",
    prevention_policy:"Network sensor only",policy_note:"No EDR sensor on scanner host",
    process_tree:[],
    network:[
      {time:"10:15:00",proto:"TCP",src:"10.10.5.20:12000+",dst:"192.168.1.0/24:22,80,443",proc:"nessusd",bytes:"low",state:"SYN only — no sessions",bad:false},
    ],
    timeline:[
      {time:"10:00:00",sev:"info",src:"Network",event:"10.10.5.20 — VulnScanner Pro process nessusd began outbound connections"},
      {time:"10:15:00",sev:"med", src:"Network",event:"Port scan detected: 10.10.5.20 → 192.168.1.0/24 ports 22,80,443,3389,445"},
      {time:"10:21:00",sev:"info",src:"Network",event:"Scan completed — all connections SYN only — no sessions established — pattern: vulnerability scanner"},
      {time:"10:21:05",sev:"info",src:"CMDB",  event:"Asset lookup: 10.10.5.20 = VULN-SCAN-01 — registered vulnerability scanner — owner: IT Security team"},
    ],
    file_events:[],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[{
      type:"IP",value:"10.10.5.20",
      vt_score:"N/A — internal IP",abuse_score:0,
      categories:["Internal RFC1918 — Corporate Asset"],
      country:"INT",asn:"Internal",last_seen:"",campaigns:[],
      passive_dns:["vuln-scan-01.corp.internal","VULN-SCAN-01"],
      first_seen:"",
      verdict:"INTERNAL ASSET — CMDB record: VULN-SCAN-01 — Vulnerability Scanner — Owner: IT Security — Approved asset",
      verdictColor:"#16a34a",
    }],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0544",sla_minutes:120,priority:"P3",category:"Network Anomaly",subcategory:"Internal Port Scan",assignee:null,watchers:["soc-lead@corp.internal"],escalation_path:"SOC L1 → IT Security Team",updates:[]},
  steps:[
    {
      id:0,phase:"TRIAGE",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Port Scan Alert — Context Before Conclusions",
      objective:"A port scan from an internal IP triggered a Medium alert. Port scans are used by attackers for reconnaissance — but they are also used every day by legitimate security tools. Before you panic, what context can you gather from the SIEM alone?",
      lookFor:["The source IP — is 10.10.5.20 a known asset?","Previous incidents from this same source","The scan pattern — which ports? Does it match a known tool?","The time — is this during business hours when IT teams work?"],
      seniorThinking:"I see this type of alert every week. Before I do anything, I check two things: (1) what is that source IP in our asset inventory, and (2) has this IP fired alerts before. Two closed Low incidents with 'vulnerability scan' in the notes is a very strong signal this is scheduled vulnerability scanning.",
      instruction:"Read the alert. Check previous incidents for 10.10.5.20. What does the history tell you before you open the EDR?",
      analyst_note:"Two previous incidents from same IP, both closed as vulnerability scans. Risk score 58. Scan pattern matches VulnScanner Pro. Strong False Positive signal.",
      decision:{
        question:"The source IP 10.10.5.20 has two previous incidents in 14 days, both closed as 'vulnerability scan'. What is your initial assessment?",
        options:[
          {text:"Likely False Positive — scheduled vulnerability scanner",correct:true,why:"Correct. Two previous identical incidents confirmed as vulnerability scans, same source, same pattern, same ports. Your prior is FP. Verify in the asset database before closing."},
          {text:"Escalate to P1 — internal recon is serious",correct:false,why:"Premature. Internal recon IS serious — if it is an attacker. But the history shows two previous confirmed scans from this IP. Investigate before escalating."},
          {text:"Block 10.10.5.20 immediately",correct:false,why:"Dangerous. If this is your authorized vulnerability scanner, blocking it breaks your security program. Never block an internal asset without confirming what it is."},
          {text:"The previous incidents prove it is safe — close without investigating",correct:false,why:"Incorrect shortcut. History suggests FP but you must verify the asset identity. Attackers have been known to spoof or pivot to scanner IPs. Check the CMDB."},
        ]
      },
      evidence_bullets:["Source IP: 10.10.5.20 — unknown until verified","Risk Score: 58/100 — Medium, not High or Critical","Ports scanned: 22,80,443,3389,445 — standard vuln scanner ports","Previous: 2 identical incidents in 14 days — both closed as VulnScanner Pro","Time: 10:15 — business hours — IT team typically runs scans during work hours"],
      action_label:"Check Asset Database — Verify 10.10.5.20",
      action_result:"CMDB lookup: 10.10.5.20\nHostname: VULN-SCAN-01\nOwner: IT Security Team\nPurpose: VulnScanner Pro — weekly vulnerability scans\nSchedule: Tuesdays and Thursdays 10:00-11:00\nApproved: Yes — security policy ITP-0044\nStatus: Moving to ThreatLens to confirm",
    },
    {
      id:1,phase:"INVESTIGATION",xp:15,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Confirm Asset Identity",
      objective:"ThreatLens can look up internal IPs against your CMDB and asset inventory. Look up 10.10.5.20. Confirm it is VULN-SCAN-01. This is your final verification before closing.",
      lookFor:["Does ThreatLens show this as an internal registered asset?","What is the hostname? Does it match what the CMDB said?","Are there any threat intel hits on this IP?","Does anything contradict the False Positive theory?"],
      seniorThinking:"Always verify twice. The CMDB says one thing, ThreatLens says another — which do you trust? In this case, both agree. That is your confirmation. If they ever disagree, that is your red flag.",
      instruction:"Look up 10.10.5.20 in ThreatLens. Confirm the asset identity matches what the CMDB returned.",
      analyst_note:"ThreatLens confirms: internal IP, registered asset, vulnerability scanner, no threat intelligence hits. False Positive confirmed.",
      decision:{
        question:"CMDB and ThreatLens both confirm 10.10.5.20 is VULN-SCAN-01, the authorized vulnerability scanner. What do you do?",
        options:[
          {text:"Close as False Positive — add exception rule for this scanner",correct:true,why:"Correct. Two independent sources confirm this is an authorized scanner. Close as FP and add a tuning rule so this scanner does not keep generating noise every week."},
          {text:"Still suspicious — keep investigating",correct:false,why:"There is nothing left to investigate. CMDB, ThreatLens, previous incident history, scan pattern, and timing all confirm this is the authorized scanner. More investigation is wasted time."},
          {text:"Close as True Positive — the scan still happened",correct:false,why:"Incorrect classification. True Positive means the alert correctly identified malicious activity. This was authorized security activity — the alert misfired. That is a False Positive."},
          {text:"Notify the IT Security team that their scanner is alerting",correct:true,why:"Also correct and good practice. Let the scanner owner know their tool is generating SOC noise. They may be able to add source IP exclusions or notify SOC before scheduled scans."},
        ]
      },
      evidence_bullets:["ThreatLens: 10.10.5.20 = VULN-SCAN-01 (confirmed)","AbuseIPDB: N/A — internal RFC1918 IP","VirusTotal: N/A — internal asset","CMDB match: VULN-SCAN-01 — IT Security — Authorized","Scan schedule: Tuesdays and Thursdays 10:00 — matches alert time"],
      action_label:"Close FALSE POSITIVE — Add Exception + Notify Scanner Team",
      action_result:"INC-2026-0544 — FALSE POSITIVE — CLOSED\n\nCLASSIFICATION: False Positive — Authorized vulnerability scanner\nSOURCE: VULN-SCAN-01 — VulnScanner Pro — IT Security\n\nACTION: Added exception: source=10.10.5.20 suppress INTERNAL_PORT_SCAN\nNOTIFIED: IT Security team — recommend pre-scan SOC notification\nRECOMMENDATION: IT Security to open a Change ticket before scheduled scans so SOC can expect the traffic\n\n+15 XP for fast accurate False Positive identification",
    },
  ],
},

// ── SCENARIO 05: Malicious USB — Insider Threat ────────────────────────────
"INC-2026-0561":{
  id:"INC-2026-0561",
  title:"USB Mass Storage Device — Data Staging Detected",
  severity:"High",status:"New",created:tsNow(0),
  host:"WS-CORP-HR-031",user:"deepak.verma@corp.internal",
  srcIp:"10.10.33.101",c2Ip:null,assignee:null,
  tags:["USB","Insider Threat","Data Exfiltration","DLP","HR"],
  summary:"DLP policy triggered on WS-CORP-HR-031. USB mass storage device inserted by deepak.verma. 4.7GB of files copied to removable media over 22 minutes. Files include HR records, employee compensation data, and org charts. Deepak Verma submitted resignation 3 days ago. Last working day: tomorrow.",
  mitre:["T1052.001","T1074.001","T1025"],isTP:true,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-2201 — DLP USB Mass Copy + Departing Employee",
    fired_at:tsNow(0),risk_score:89,
    alerts:[
      {id:"BT-6601",time:"14:33:12",sev:"High",rule:"DLP_USB_MASS_COPY",src:"DLP",msg:"deepak.verma copied 4.7GB to USB device SanDisk USB 3.0 on WS-CORP-HR-031 — 847 files in 22 minutes"},
      {id:"BT-6602",time:"14:33:12",sev:"High",rule:"DEPARTING_EMPLOYEE_DATA_ACCESS",src:"DLP",msg:"deepak.verma is a departing employee (last day: tomorrow) — elevated risk policy triggered"},
      {id:"BT-6603",time:"14:31:05",sev:"Medium",rule:"SENSITIVE_FILE_ACCESS",src:"DLP",msg:"deepak.verma accessed HR compensation database files — classification: CONFIDENTIAL — unusual access pattern"},
    ],
    raw_search:`index=dlp user="deepak.verma" action=file_copy earliest=14:00 latest=15:00
| stats sum(file_size) as total_bytes, count as files by dest_device
| where dest_device LIKE "%USB%"`,
    correlated_hosts:["WS-CORP-HR-031"],
    previous_incidents:["No previous DLP incidents for deepak.verma"],
  },
  edr:{
    tool:"SentinelEDR",sensor_id:"9f0a1b2c3d4e",sensor_version:"7.14.17706",
    prevention_policy:"CORP-STANDARD-DETECT-ONLY",policy_note:"DLP policy: detect and alert only — no auto-block",
    process_tree:[
      {pid:"2201",ppid:"1400",depth:0,name:"explorer.exe",sha256:"",score:0,bad:false,time:"14:30:00",user:"CORP\\deepak.verma",cmd:"C:\\Windows\\explorer.exe"},
      {pid:"3301",ppid:"2201",depth:1,name:"robocopy.exe",sha256:"",score:71,bad:true,time:"14:31:05",user:"CORP\\deepak.verma",cmd:"robocopy.exe C:\\Users\\deepak.verma\\HR_Data E:\\ /E /COPYALL /LOG:C:\\Temp\\copy.log"},
    ],
    network:[],
    timeline:[
      {time:"14:29:55",sev:"med", src:"DLP",event:"USB device inserted: SanDisk USB 3.0 Serial: 4C531234560123 on WS-CORP-HR-031 — user: deepak.verma"},
      {time:"14:30:00",sev:"med", src:"SentinelEDR",event:"File Explorer opened — navigated to C:\\Users\\deepak.verma\\HR_Data — folder contains HR compensation files"},
      {time:"14:31:05",sev:"high",src:"SentinelEDR",event:"robocopy.exe launched — source: C:\\Users\\deepak.verma\\HR_Data — destination: E:\\ (USB) — /COPYALL flag — preserves metadata"},
      {time:"14:33:12",sev:"high",src:"DLP",event:"DLP alert: 4.7GB copied to USB — 847 files — includes CONFIDENTIAL files — HR_Compensation_2026.xlsx, Org_Chart_Internal.pptx"},
      {time:"14:52:08",sev:"high",src:"DLP",event:"USB device removed — SanDisk USB 3.0 Serial: 4C531234560123 — copy completed"},
    ],
    file_events:[
      {time:"14:31:05",action:"COPY_TO_USB",path:"C:\\Users\\deepak.verma\\HR_Data\\HR_Compensation_2026.xlsx",sha256:"",size:"12MB",signed:false},
      {time:"14:31:12",action:"COPY_TO_USB",path:"C:\\Users\\deepak.verma\\HR_Data\\Employee_Salaries_All.csv",sha256:"",size:"3MB",signed:false},
      {time:"14:31:45",action:"COPY_TO_USB",path:"C:\\Users\\deepak.verma\\HR_Data\\Org_Chart_Internal.pptx",sha256:"",size:"8MB",signed:false},
    ],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[{
      type:"User",value:"deepak.verma@corp.internal",
      vt_score:"N/A",abuse_score:0,
      categories:["Internal User — Departing Employee"],
      country:"",asn:"",last_seen:"",campaigns:[],passive_dns:[],first_seen:"",
      verdict:"INTERNAL USER — HR Department — Resignation submitted 3 days ago — Last working day: tomorrow — Elevated insider risk profile per HR policy",
      verdictColor:"#ea580c",
    }],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0561",sla_minutes:60,priority:"P2",category:"Insider Threat — Data Exfiltration",subcategory:"USB Mass Storage Copy",assignee:null,watchers:["soc-lead@corp.internal","hr-security@corp.internal","legal@corp.internal"],escalation_path:"SOC L1 → SOC L2 → HR Security → Legal → CISO",updates:[]},
  steps:[
    {
      id:0,phase:"TRIAGE",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Understand the Alert — Insider Threat Context",
      objective:"This alert is different. The threat is not from outside — it may be from inside. A departing employee copied 4.7GB of HR files to a USB drive. Look at the three alerts together. What story do they tell when combined?",
      lookFor:["The DLP USB alert — how much data? What types of files?","The departing employee flag — what is the significance of timing?","The sensitive file access — was this normal for this user's role?","The correlation: all three alerts are about the same person at the same time"],
      seniorThinking:"Insider threat investigations are different. The person had legitimate access to these files — that is why they could copy them. The question is not HOW they accessed it but WHY they are copying it to a USB now, on their second-to-last day. Context and intent matter more than technical indicators.",
      instruction:"Read all three alerts. Think about the timing, the data involved, and what you know about the user. What is the most likely explanation?",
      analyst_note:"HR files + departing employee + last working day tomorrow + robocopy = strong insider threat indicator. This is not accidental. Document carefully — this may become a legal matter.",
      decision:{
        question:"deepak.verma is leaving tomorrow and copied 4.7GB of HR compensation data to a USB. What is the most appropriate immediate action?",
        options:[
          {text:"Investigate fully and notify HR Security and Legal before confronting the user",correct:true,why:"Correct. Insider threat investigations require HR and Legal involvement before any user contact. If you confront the user without preparation, they may destroy evidence, delete files, or claim legitimate purpose. Involve the right teams first."},
          {text:"Immediately revoke deepak.verma's access and delete the USB data",correct:false,why:"Incorrect order. You cannot delete data from a USB that has already been removed from the building. Also, revoking access before Legal is involved may affect your ability to pursue the matter. Follow the process."},
          {text:"Do nothing — the user had legitimate access to those files",correct:false,why:"Incorrect. Having legitimate access does not mean you are authorized to copy confidential company data to a personal USB device on your last day of work. This is a potential data exfiltration incident."},
          {text:"Email deepak.verma asking why they copied the files",correct:false,why:"Incorrect. Never contact the suspected insider directly without HR and Legal present. This can tip them off, cause evidence destruction, or create legal liability for the company."},
        ]
      },
      evidence_bullets:["4.7GB copied to USB — 847 files in 22 minutes","Files include: HR_Compensation_2026.xlsx, Employee_Salaries_All.csv","User: deepak.verma — resignation submitted 3 days ago","Last working day: TOMORROW","robocopy.exe used — deliberate bulk copy tool, not accidental drag-and-drop"],
      action_label:"Escalate to HR Security and Legal — Preserve Evidence",
      action_result:"Escalation initiated:\n[✓] HR Security notified — insider threat protocol activated\n[✓] Legal team notified — potential IP theft / data breach\n[✓] Evidence preserved — DLP logs, file list, USB serial number\n[✓] Forensic image requested of WS-CORP-HR-031\nUSB Serial: 4C531234560123 — documented\nStatus: HR Security leading from here — SOC in support role",
    },
    {
      id:1,phase:"INVESTIGATION",xp:25,
      tool:"SentinelEDR",toolIcon:"🖥",toolAnalogy:"like CCTV inside the computer",
      title:"Confirm the Copy Method — Intent Evidence",
      objective:"The process tree shows robocopy.exe was used. This is significant. A user who accidentally copied files would use File Explorer drag-and-drop. robocopy.exe is a command-line tool specifically designed for bulk copying with metadata preservation. What does this tell you about intent?",
      lookFor:["What flags did robocopy use? What does /E /COPYALL /LOG mean?","Is there a log file? Where does it go?","Did the user navigate to the files deliberately or did they just happen to be there?","What is the timeline of events — how long did the copy take?"],
      seniorThinking:"The /COPYALL flag on robocopy is notable. It copies file attributes, timestamps, and security information — not just file content. This is what forensic examiners use when they want to preserve evidence. A regular user does not typically know about /COPYALL. This suggests technical knowledge and deliberate intent.",
      instruction:"Look at the robocopy command in the process tree. What does each flag mean? What does the use of this specific tool tell you about intent?",
      analyst_note:"robocopy /E /COPYALL /LOG — bulk recursive copy with full attribute preservation and audit log. This is not accidental. The user knew what they were doing.",
      decision:{
        question:"deepak.verma used 'robocopy /E /COPYALL /LOG' to copy files. What does this command specifically tell you?",
        options:[
          {text:"This was deliberate — robocopy with /COPYALL is a technical tool requiring knowledge to use",correct:true,why:"Correct. robocopy is not a tool casual users stumble upon. The /COPYALL flag specifically preserves metadata. The /LOG flag creates an audit trail on the source machine. This shows technical intent and planning."},
          {text:"robocopy is a standard Windows tool anyone would use",correct:false,why:"Partially true but misses the point. While robocopy is built into Windows, the specific flags /E /COPYALL /LOG require knowledge of what they do. Most users would use File Explorer or drag-and-drop, not command-line robocopy with metadata flags."},
          {text:"The LOG flag proves innocence — they were being transparent",correct:false,why:"Incorrect interpretation. The log file was written to C:\\Temp\\ on the SOURCE machine — not as evidence of transparency, but likely to track what was copied. The log itself is now evidence."},
          {text:"Cannot determine intent from a command line",correct:false,why:"Incorrect. While we cannot read minds, we can assess technical knowledge and deliberate action. Using a specific command-line tool with advanced flags on your penultimate day while copying sensitive HR data is strong evidence of deliberate intent."},
        ]
      },
      evidence_bullets:["robocopy flags: /E (all subfolders) /COPYALL (preserve metadata) /LOG (create audit log)","Log file location: C:\\Temp\\copy.log — still on source machine","Copy duration: 22 minutes — deliberate bulk operation","File Explorer opened HR_Data folder first — then robocopy launched","847 files copied — not accidental selection"],
      action_label:"Preserve robocopy Log + Request HR Forensics",
      action_result:"Evidence documented:\n[✓] robocopy command logged: full flags captured\n[✓] C:\\Temp\\copy.log retrieved — lists every file copied\n[✓] File list extracted: 847 files — 23 CONFIDENTIAL classifications\n[✓] USB serial 4C531234560123 flagged for recovery\nForensic image: Requested — WS-CORP-HR-031 preserved\nHR Security: Taking lead — SOC supporting evidence collection\nStatus: OPEN — Legal review in progress",
    },
    {
      id:2,phase:"CLOSE",xp:15,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Document for Legal — Precise and Factual",
      objective:"This incident will likely become a Legal matter. Your incident report must be precise, factual, and free of assumptions. Document what you observed — not what you think the person intended. Legal and HR will make the intent determination.",
      lookFor:["What facts can you state without interpretation?","What evidence have you preserved?","What is still outstanding?","What do you NOT know that Legal will need?"],
      seniorThinking:"When I write reports for insider threat cases I use only facts. Not 'deepak.verma stole data' — I do not know that yet. I write: 'deepak.verma copied 847 files totalling 4.7GB including files classified CONFIDENTIAL to a SanDisk USB Serial 4C531234560123 on DATE at TIME using robocopy.exe with flags /E /COPYALL /LOG.' Facts only. Legal interprets.",
      instruction:"Write the incident report with factual, precise language. Avoid assumptions about intent. Document every piece of evidence.",
      analyst_note:"Stick to facts. No assumptions about motive. Legal will determine intent based on evidence you preserve.",
      decision:{
        question:"In your incident report, which statement is most appropriate?",
        options:[
          {text:"'deepak.verma copied 4.7GB of CONFIDENTIAL files to USB on penultimate day — evidence preserved — referred to HR Security and Legal'",correct:true,why:"Correct. Factual, precise, no assumption of intent. States what happened, what files, what timeline, what actions taken. This is how analysts write reports that hold up legally."},
          {text:"'deepak.verma stole company data before leaving — insider threat confirmed'",correct:false,why:"Incorrect language. 'Stole' implies a legal conclusion you are not qualified to make. You observed a copy operation. Legal determines whether it constitutes theft. Stick to factual observations."},
          {text:"'deepak.verma accidentally copied work files to a personal USB'",correct:false,why:"Incorrect assumption. You have no evidence this was accidental. robocopy with specific flags suggests deliberate action. Do not introduce alternative explanations without evidence."},
          {text:"'Suspicious activity observed — requires further investigation before conclusions'",correct:false,why:"Too vague for a report that will go to Legal. The evidence is sufficient to document a specific incident. Vague reports waste Legal's time and may miss regulatory obligations."},
        ]
      },
      evidence_bullets:["847 files / 4.7GB copied to USB Serial: 4C531234560123","23 files classified CONFIDENTIAL (HR compensation, salaries, org charts)","robocopy.exe with /E /COPYALL /LOG flags — documented","C:\\Temp\\copy.log preserved — full file list","USB removed at 14:52:08 — device left premises"],
      action_label:"Submit to HR Security and Legal — Close SOC Ticket",
      action_result:"INC-2026-0561 — CLOSED (SOC) — Referred to HR Security\n\nFACTS DOCUMENTED:\n→ 847 files / 4.7GB to USB — includes 23 CONFIDENTIAL files\n→ Tool: robocopy /E /COPYALL /LOG\n→ User: departing employee — last day tomorrow\n→ USB Serial: 4C531234560123\n\nEVIDENCE PRESERVED: DLP logs, EDR process tree, file list, copy log\nFORENSIC IMAGE: Requested\nREFERRED TO: HR Security + Legal\nSOC ROLE: Supporting evidence — investigation owned by HR/Legal",
    },
  ],
},

// ── SCENARIO 06: DNS Beaconing — C2 Over DNS ──────────────────────────────
"INC-2026-0578":{
  id:"INC-2026-0578",
  title:"Anomalous DNS Query Volume — Possible C2 Beaconing",
  severity:"High",status:"New",created:tsNow(0),
  host:"WS-CORP-DEV-088",user:"arjun.nair@corp.internal",
  srcIp:"10.10.22.88",c2Ip:null,assignee:null,
  tags:["DNS","C2","Beaconing","Threat Hunting","DGA"],
  summary:"BlueTrace SIEM flagged anomalous DNS query volume from WS-CORP-DEV-088. 2,847 DNS queries in 4 hours — 98% to a single domain pattern: random-looking subdomains of update-telemetry-cdn.net. Average query every 5 seconds. No established network connections. Classic DNS tunneling/beaconing pattern.",
  mitre:["T1071.004","T1132.001"],isTP:true,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-5512 — DNS Anomaly — High Query Rate to Single Domain",
    fired_at:tsNow(0),risk_score:84,
    alerts:[
      {id:"BT-7701",time:"07:15:00",sev:"High",rule:"DNS_BEACON_PATTERN",src:"DNS Gateway",msg:"WS-CORP-DEV-088 sent 2,847 DNS queries in 4h — 98% to *.update-telemetry-cdn.net — query every 5s — beacon pattern"},
      {id:"BT-7702",time:"07:15:00",sev:"Medium",rule:"DGA_PATTERN_DETECTED",src:"DNS Gateway",msg:"Subdomain pattern analysis: random 16-char subdomains — entropy score 4.2/5.0 — DGA signature detected"},
    ],
    raw_search:`index=dns src_ip=10.10.22.88 earliest=-4h
| stats count by query_name
| where match(query_name, "update-telemetry-cdn.net")
| head 20`,
    correlated_hosts:["WS-CORP-DEV-088"],
    previous_incidents:["No previous DNS anomaly incidents for this host"],
  },
  edr:{
    tool:"SentinelEDR",sensor_id:"1a2b3c4d5e6f",sensor_version:"7.14.17706",
    prevention_policy:"CORP-DEV-DETECT-ONLY",policy_note:"Developer workstation — detect only",
    process_tree:[
      {pid:"4401",ppid:"1200",depth:0,name:"svchost.exe",sha256:"",score:0,bad:false,time:"03:15:00",user:"NT AUTHORITY\\SYSTEM",cmd:"C:\\Windows\\System32\\svchost.exe -k netsvcs"},
      {pid:"5501",ppid:"4401",depth:1,name:"UpdateService.exe",sha256:"b8c9d0e1f2a3",score:82,bad:true,time:"03:15:00",user:"CORP\\arjun.nair",cmd:"C:\\Users\\arjun.nair\\AppData\\Roaming\\UpdateService.exe --silent --interval 5"},
    ],
    network:[
      {time:"03:15:00",proto:"DNS",src:"10.10.22.88:54001",dst:"10.10.1.5:53",proc:"UpdateService.exe",bytes:"62 bytes per query",state:"QUERY — no connection",bad:true},
      {time:"03:15:05",proto:"DNS",src:"10.10.22.88:54002",dst:"10.10.1.5:53",proc:"UpdateService.exe",bytes:"61 bytes per query",state:"QUERY — no connection",bad:true},
    ],
    timeline:[
      {time:"03:14:55",sev:"med", src:"SentinelEDR",event:"UpdateService.exe started — AppData\\Roaming — score 82 — parent: svchost.exe"},
      {time:"03:15:00",sev:"high",src:"SentinelEDR",event:"DNS query: a7f2k9m1p4r8.update-telemetry-cdn.net — UpdateService.exe"},
      {time:"03:15:05",sev:"high",src:"SentinelEDR",event:"DNS query: x9b3n7q2w5t6.update-telemetry-cdn.net — UpdateService.exe"},
      {time:"03:15:10",sev:"high",src:"SentinelEDR",event:"DNS query: m4d8h1j6l0p9.update-telemetry-cdn.net — UpdateService.exe"},
      {time:"07:15:00",sev:"high",src:"BlueTrace",event:"2,847 total DNS queries to *.update-telemetry-cdn.net over 4 hours — SIEM alert fired"},
    ],
    file_events:[
      {time:"03:14:50",action:"CREATE",path:"C:\\Users\\arjun.nair\\AppData\\Roaming\\UpdateService.exe",sha256:"b8c9d0e1f2a3b4c5",size:"156KB",signed:false},
    ],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {
        type:"Domain",value:"update-telemetry-cdn.net",
        vt_score:"41/90 detections",abuse_score:91,
        categories:["DNS C2 Infrastructure","Malware Communication","DGA Domain"],
        country:"US",asn:"AS13335 — Cloudflare (fronted)",
        last_seen:"2026-05-28",
        campaigns:["DNS beacon malware family — IcedID variant","APT activity using DNS C2 — Q1 2026"],
        passive_dns:["*.update-telemetry-cdn.net — wildcard — 50,000+ subdomains seen"],
        first_seen:"2025-11-04",
        verdict:"MALICIOUS — Known DNS C2 domain. Wildcard DNS responses for any subdomain. Malware encodes data in subdomain strings and receives commands in DNS responses.",
        verdictColor:"#dc2626",
      },
      {
        type:"Hash",value:"b8c9d0e1f2a3b4c5",
        vt_score:"38/72 detections",abuse_score:0,
        categories:["DNS Beacon","IcedID Variant","C2 Client"],
        country:"",asn:"",last_seen:"2026-05-27",
        campaigns:["IcedID DNS beacon — financial sector targeting 2026"],
        passive_dns:[],first_seen:"2026-04-15",
        verdict:"MALICIOUS — IcedID DNS beacon variant. 38/72 AV detections. Communicates via DNS queries only — no direct TCP/UDP connections. Exfiltrates data through encoded subdomains.",
        verdictColor:"#dc2626",
      },
    ],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0578",sla_minutes:60,priority:"P2",category:"Malware — C2 Beacon (DNS)",subcategory:"DNS Tunneling",assignee:null,watchers:["soc-lead@corp.internal"],escalation_path:"SOC L1 → SOC L2 → IR Team",updates:[]},
  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"DNS Beaconing — A Different Kind of C2",
      objective:"This alert is about DNS — not about network connections. Most C2 traffic goes over HTTPS. But some malware uses DNS queries to communicate — it is stealthier because DNS is rarely blocked. Look at the pattern. What makes 2,847 queries to the same domain suspicious?",
      lookFor:["The query volume — 2,847 in 4 hours. What is the rate?","The query pattern — what do the subdomains look like?","The DGA score — what does Domain Generation Algorithm mean?","Are there any established TCP connections? Or only DNS queries?"],
      seniorThinking:"DNS beaconing is clever. The malware does not create a TCP connection to a C2 server — which firewalls block. Instead it sends DNS queries. The subdomain encodes the data being exfiltrated. The DNS response encodes the command back. All through port 53, which is almost never blocked.",
      instruction:"Look at the two alerts. Calculate: 2,847 queries over 4 hours — what is the interval? What does that interval tell you?",
      analyst_note:"2847 queries / 240 minutes = ~12 per minute = ~1 every 5 seconds. --interval 5 flag on the process confirms this. Perfectly regular intervals = automated beacon.",
      decision:{
        question:"The malware sends a DNS query every 5 seconds. Why would an attacker choose DNS over HTTPS for C2 communication?",
        options:[
          {text:"DNS (port 53) is almost never blocked — firewalls block HTTP/S but rarely DNS",correct:true,why:"Correct. Firewalls and proxies frequently inspect or block outbound HTTPS to unknown IPs. But DNS queries to port 53 are almost universally allowed — systems need DNS to function. DNS C2 is stealthier because it blends with legitimate traffic."},
          {text:"DNS is faster than HTTPS for sending data",correct:false,why:"Incorrect. DNS is actually slower and more limited than HTTPS for data transfer — each query can only carry a small amount of data. The advantage is stealth, not speed."},
          {text:"HTTPS C2 would have been detected by previous alerts",correct:false,why:"Partially true but not the reason the attacker chose DNS. The design choice is about evading defensive controls, not about what was previously detected."},
          {text:"All malware uses DNS — there is nothing special about this",correct:false,why:"Incorrect. Most malware uses HTTPS for C2. DNS C2 is a more sophisticated technique used by targeted malware families. It indicates a more capable threat actor."},
        ]
      },
      evidence_bullets:["2,847 DNS queries in 4 hours = 1 every 5 seconds (automated)","98% of queries to *.update-telemetry-cdn.net","Subdomain pattern: random 16-char strings — DGA entropy 4.2/5.0","No established TCP/UDP connections — DNS only","UpdateService.exe in AppData\\Roaming — not a system service"],
      action_label:"Pivot to SentinelEDR — Find the Process",
      action_result:"SIEM analysis complete:\nBeacon interval: 1 query per 5 seconds (confirmed automated)\nDomain: Known C2 infrastructure (ThreatLens)\nProcess: UpdateService.exe — suspicious location\nStatus: Pivoting to EDR for process analysis",
    },
    {
      id:1,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Confirm the Domain and Binary",
      objective:"Look up update-telemetry-cdn.net and the hash b8c9d0e1f2a3b4c5 in ThreatLens. Before reading the verdict — look at the raw indicators. What tells you this is malicious before you see the label?",
      lookFor:["How many engines flag this domain?","What campaign is this associated with?","What does wildcard DNS mean for this domain?","What is IcedID and why is it significant?"],
      seniorThinking:"When I see wildcard DNS responses for a domain — meaning ANY subdomain resolves — that is a red flag for DNS C2. Legitimate CDNs use specific subdomains. Wildcard DNS is set up specifically to receive random subdomain queries from malware.",
      instruction:"Look up both IOCs. Read the campaign associations carefully. What family is this? What does that tell you about the risk level?",
      analyst_note:"IcedID DNS beacon variant — financial sector targeting. 38/72 VT. Domain: 41/90 — wildcard DNS. Known C2 infrastructure.",
      decision:{
        question:"ThreatLens shows UpdateService.exe is an IcedID DNS beacon variant targeting financial sector. How does this change your response priority?",
        options:[
          {text:"Escalate to IR team — IcedID is a sophisticated banking trojan that leads to further payloads",correct:true,why:"Correct. IcedID is not a simple info-stealer. It is a banking trojan and malware loader known for dropping ransomware and other secondary payloads. This needs IR team involvement immediately — not just SOC L1 containment."},
          {text:"Standard containment — same as any other malware",correct:false,why:"Insufficient. IcedID specifically targets financial data and serves as a loader for ransomware (Ryuk, Conti variants). A developer workstation at a financial firm with IcedID requires elevated response, not standard containment."},
          {text:"DNS beacons are low risk because they only query DNS",correct:false,why:"Incorrect. DNS is the communication channel, not the limit of the threat. IcedID uses DNS for C2 and can receive commands including downloading additional malware payloads. The DNS queries are the beginning, not the end."},
          {text:"Wait for the malware to establish a TCP connection before acting",correct:false,why:"Incorrect. Waiting for escalation is exactly what the attacker wants. IcedID can exfiltrate data and receive commands via DNS alone — you do not need a TCP connection to have a serious incident."},
        ]
      },
      evidence_bullets:["Domain: update-telemetry-cdn.net — 41/90 VT — wildcard DNS — known C2","Hash b8c9d0e1f2a3b4c5 — 38/72 VT — IcedID DNS beacon variant","IcedID targets: financial sector — banking credentials, financial data","Campaign: IcedID DNS beacon — financial sector targeting Q1 2026","Risk: IcedID is a loader — ransomware drops observed in related campaigns"],
      action_label:"Contain WS-CORP-DEV-088 + Escalate to IR Team",
      action_result:"INC-2026-0578 escalated — IR Team notified\n\nWS-CORP-DEV-088 — Network Containment: ACTIVE\nIcedID DNS beacon — communication: SEVERED\nEDR sensor: CONNECTED (forensics preserved)\n\nIR Team briefed:\n→ IcedID variant — financial sector targeting\n→ Possible loader — check for secondary payloads\n→ Forensic image requested\n→ Developer access reviewed — source code repos checked",
    },
  ],
},

// ── SCENARIO 07: Security Team Infrastructure — FALSE POSITIVE ─────────────
"INC-2026-0591":{
  id:"INC-2026-0591",
  title:"Nmap Scan + PentestKit Modules — Security Team Activity?",
  severity:"High",status:"New",created:tsNow(0),
  host:"WS-CORP-SEC-002",user:"soc-infra@corp.internal",
  srcIp:"10.10.99.5",c2Ip:null,assignee:null,
  tags:["Nmap","PentestKit","Pentest","False Positive","Security Tools","Change Management"],
  summary:"BlueTrace SIEM triggered ATTACK_TOOL_DETECTED on 10.10.99.5. PortScan 7.94 and PentestKit modules detected. Source is scanning internal subnet 10.10.0.0/16. No Change Ticket found in IncidentDesk. Possible internal attacker using security tools OR authorized penetration test. Cannot determine without verification.",
  mitre:["T1046","T1595"],isTP:false,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-7744 — Attack Tool Execution + Internal Scan",
    fired_at:tsNow(0),risk_score:76,
    alerts:[
      {id:"BT-8801",time:"14:00:15",sev:"High",rule:"ATTACK_TOOL_DETECTED",src:"EDR",msg:"PortScan 7.94 and PentestKit Framework detected on WS-CORP-SEC-002 — active network scanning 10.10.0.0/16"},
      {id:"BT-8802",time:"14:00:30",sev:"Medium",rule:"NO_CHANGE_TICKET",src:"IncidentDesk",msg:"No active Change Ticket found for penetration testing activity — check with security team before escalating"},
    ],
    raw_search:`index=endpoint host=WS-CORP-SEC-002 ImageFileName IN ("portscan.exe","pkitconsole.exe") earliest=13:00
| table _time, ImageFileName, CommandLine, UserName`,
    correlated_hosts:["WS-CORP-SEC-002"],
    previous_incidents:["INC-2026-0556 (Medium, closed — authorized pentest, Change Ticket CHG-2026-0122, 30 days ago)"],
  },
  edr:{
    tool:"SentinelEDR",sensor_id:"2b3c4d5e6f7a",sensor_version:"7.14.17706",
    prevention_policy:"CORP-SECURITY-TEAM-POLICY",policy_note:"Security team workstation — reduced restrictions",
    process_tree:[
      {pid:"3300",ppid:"1100",depth:0,name:"cmd.exe",sha256:"",score:0,bad:false,time:"14:00:00",user:"CORP\\soc-infra",cmd:"C:\\Windows\\System32\\cmd.exe"},
      {pid:"4400",ppid:"3300",depth:1,name:"portscan.exe",sha256:"",score:65,bad:false,time:"14:00:15",user:"CORP\\soc-infra",cmd:"portscan.exe -sS -O -p 22,80,443,8080,3389,445 10.10.0.0/16 --open"},
      {pid:"4401",ppid:"3300",depth:1,name:"pkitconsole.exe",sha256:"",score:71,bad:false,time:"14:00:30",user:"CORP\\soc-infra",cmd:"pkitconsole.exe -q"},
    ],
    network:[],timeline:[
      {time:"14:00:00",sev:"med",src:"SentinelEDR",event:"soc-infra logged into WS-CORP-SEC-002 — security team workstation"},
      {time:"14:00:15",sev:"high",src:"SentinelEDR",event:"portscan.exe — scanning 10.10.0.0/16 — ports 22,80,443,8080,3389,445"},
      {time:"14:00:30",sev:"high",src:"SentinelEDR",event:"pkitconsole.exe launched — no exploitation modules loaded yet"},
    ],
    file_events:[],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[{
      type:"IP",value:"10.10.99.5",
      vt_score:"N/A — internal",abuse_score:0,
      categories:["Internal RFC1918 — Corporate Asset"],
      country:"INT",asn:"Internal",last_seen:"",campaigns:[],passive_dns:["sec-workstation-02.corp.internal","WS-CORP-SEC-002"],
      first_seen:"",
      verdict:"INTERNAL ASSET — CMDB: WS-CORP-SEC-002 — Security Operations workstation — Owner: SOC Infrastructure team — Security tools approved per policy ITP-0091",
      verdictColor:"#16a34a",
    }],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0591",sla_minutes:60,priority:"P2",category:"Suspicious Tool Execution",subcategory:"Attack Tool Detected",assignee:null,watchers:["soc-lead@corp.internal"],escalation_path:"SOC L1 → SOC L2 → Security Team Lead",updates:[]},
  steps:[
    {
      id:0,phase:"TRIAGE",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Nmap and PentestKit — Always Malicious?",
      objective:"Nmap and PentestKit are used by attackers. They are also used every day by legitimate security teams. The key question is not WHAT tools — it is WHO is using them and WHETHER it is authorized. What evidence helps you determine this?",
      lookFor:["What workstation are the tools running from?","What user account is running them?","Is there a Change Ticket for a pentest today?","Is there a previous incident showing authorized use of these tools?"],
      seniorThinking:"I work with a red team. When I see Nmap and PentestKit alerts, my first call is to the Security Team Lead — not an escalation to P1. Half the time it is our own team doing their job. The other half it is a real threat. The SIEM alert even says 'check with security team before escalating' — that is a built-in hint.",
      instruction:"Read both alerts carefully. The second alert says 'No active Change Ticket — check with security team before escalating.' What is your next action?",
      analyst_note:"Security team workstation + soc-infra account + previous authorized pentest from same host = very likely authorized activity. Verify before escalating.",
      decision:{
        question:"Nmap and PentestKit are running on a security team workstation with no Change Ticket. What do you do?",
        options:[
          {text:"Contact the Security Team Lead to verify if this is authorized before taking any action",correct:true,why:"Correct. The workstation is registered to the security team, the account is soc-infra (a security team account), and there is previous history of authorized testing from this host. Verify with the team before acting — a false escalation would disrupt an active pentest."},
          {text:"Immediately isolate WS-CORP-SEC-002 and escalate to P1",correct:false,why:"Premature. Isolating a security team workstation mid-pentest would disrupt authorized security testing, alert defenders (if this is a red team exercise), and create significant noise. Verify first."},
          {text:"Close as False Positive — security teams always use these tools",correct:false,why:"Insufficient. No Change Ticket means this MIGHT be unauthorized. You cannot close as FP without confirming authorization. The correct process is to verify, then close."},
          {text:"Watch and wait — see if exploitation occurs",correct:false,why:"Incorrect. Passive monitoring without verification leaves you unable to respond appropriately in either direction. If it IS an attacker, you waited. If it IS the security team, you wasted time."},
        ]
      },
      evidence_bullets:["Source: WS-CORP-SEC-002 — Security Operations workstation (CMDB confirmed)","User: soc-infra — Security team service account","Tools: Nmap + PentestKit — standard pentest tools","Change Ticket: NONE found — missing authorization paper trail","Previous: CHG-2026-0122 authorized pentest 30 days ago from same host"],
      action_label:"Call Security Team Lead — Verify Authorization",
      action_result:"Security Team Lead contacted (14:04):\n'Yes — we have a quarterly vulnerability assessment running today. Change Ticket was submitted but went to wrong queue. CHG-2026-0198 created now — apologies for the noise.'\n\nChange Ticket CHG-2026-0198: CONFIRMED\nAuthorization: Quarterly vulnerability assessment — approved by CISO\nStatus: FALSE POSITIVE — authorized security activity",
    },
    {
      id:1,phase:"CLOSE",xp:15,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Close + Fix the Process Gap",
      objective:"This was a False Positive — authorized security testing. But there IS a process failure here: the Change Ticket was not submitted correctly before testing began. Your recommendation should fix the process, not just close the ticket.",
      lookFor:["What process failed that caused this incident?","How do you prevent this from generating noise every quarter?","Should you add an exception rule or fix the process?","Who is responsible for ensuring Change Tickets are in place?"],
      seniorThinking:"The real problem is not the tools — it is the communication process. If the security team notifies the SOC before running tests and creates the Change Ticket correctly, this alert never becomes an incident. My recommendation goes to both the security team and the SOC process documentation.",
      instruction:"Close the ticket and write a recommendation that fixes the root process failure.",
      analyst_note:"Root cause: Change Ticket not filed correctly before testing. Fix: require pre-test SOC notification and correct Change Ticket process.",
      decision:{
        question:"This is the second authorized pentest that triggered SOC alerts without proper Change Ticket notification. What is the best recommendation?",
        options:[
          {text:"Require security team to notify SOC and file Change Ticket at least 24h before any testing activity",correct:true,why:"Correct. This fixes the root cause. A 24-hour advance notification gives SOC time to expect and suppress authorized alerts. The Change Ticket creates an audit trail. Both protect the security team and SOC from wasted time."},
          {text:"Add a permanent exception rule to suppress all Nmap and PentestKit alerts",correct:false,why:"Dangerous. Suppressing all Nmap/PentestKit alerts would blind you to real attackers using those tools. The exception should be specific: source IP + authorized user + active Change Ticket."},
          {text:"Recommend the security team stop using Nmap and PentestKit",correct:false,why:"Not realistic or appropriate. These are industry-standard security tools. The problem is process, not tooling."},
          {text:"Nothing — this resolved itself without action",correct:false,why:"Incorrect. The same process failure has now occurred twice. Without a fix, it will happen again every quarter. Incidents that repeat are process failures waiting to be documented."},
        ]
      },
      evidence_bullets:["Root cause: Change Ticket filed in wrong queue — process failure","Second occurrence in 30 days — pattern indicates process gap","Tools: Authorized — workstation: Authorized — testing: Authorized","Only failure: communication process between Security and SOC"],
      action_label:"Close FALSE POSITIVE — Raise Process Improvement",
      action_result:"INC-2026-0591 — FALSE POSITIVE — CLOSED\n\nROOT CAUSE: Change Ticket process failure — security team filed in wrong queue\nAUTHORIZATION: Confirmed — CHG-2026-0198 (quarterly vulnerability assessment)\n\nPROCESS IMPROVEMENT RAISED:\n→ Security team: 24h advance SOC notification required before testing\n→ Change Ticket: correct queue documented in security team runbook\n→ SOC: add conditional suppression rule: soc-infra + active Change Ticket\n\n+15 XP for identifying process gap",
    },
  ],
},

// ── SCENARIO 08: Business Email Compromise ─────────────────────────────────
"INC-2026-0612":{
  id:"INC-2026-0612",
  title:"Business Email Compromise — CFO Wire Transfer Request",
  severity:"Critical",status:"New",created:tsNow(0),
  host:"Exchange Online / Finance Department",user:"finance-ap@corp.internal",
  srcIp:null,c2Ip:null,assignee:null,
  tags:["BEC","Wire Transfer","Email Fraud","CEO Fraud","Financial"],
  summary:"Finance AP team received email from 'CFO Rajesh Mehta' requesting urgent wire transfer of ₹47,00,000 to a new vendor account. Email appears to come from rajesh.mehta@corp.com — note: corp.com not corp.internal. Finance almost processed the payment. Employee flagged it as suspicious. Investigate the email and advise Finance immediately.",
  mitre:["T1566.001","T1078.004"],isTP:true,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-9901 — BEC Pattern — External Domain Impersonation",
    fired_at:tsNow(0),risk_score:94,
    alerts:[
      {id:"BT-9901",time:"11:45:00",sev:"Critical",rule:"BEC_DOMAIN_IMPERSONATION",src:"Email GW",msg:"Email from rajesh.mehta@corp.com (external) impersonating CFO — sent to finance-ap — urgent wire transfer request — ₹47L"},
      {id:"BT-9902",time:"11:45:00",sev:"High",rule:"LOOKALIKE_DOMAIN",src:"Email GW",msg:"Domain corp.com registered 6 days ago — lookalike of corp.internal — DMARC: none — SPF: pass (spoofed)"},
    ],
    raw_search:`index=email from_domain="corp.com" earliest=-24h
| table _time, from, to, subject, attachment_count, dmarc_result, spf_result
| where dmarc_result != "pass"`,
    correlated_hosts:["Exchange Online","Finance Department"],
    previous_incidents:["No previous BEC incidents"],
  },
  edr:{
    tool:"MailShield",sensor_id:"Exchange-Online-Tenant",sensor_version:"EOP v2",
    prevention_policy:"Email Security Standard",policy_note:"No DMARC enforcement on receiving domain",
    process_tree:[],network:[],
    timeline:[
      {time:"11:42:30",sev:"high",src:"MailShield",event:"Email received: from=rajesh.mehta@corp.com to=finance-ap@corp.internal subj='Urgent Wire Transfer Required - Confidential'"},
      {time:"11:42:30",sev:"high",src:"MailShield",event:"Domain analysis: corp.com — registered 2026-05-22 (6 days ago) — DMARC: none — typosquat of corp.internal"},
      {time:"11:43:00",sev:"crit",src:"MailShield",event:"Email body: 'Process immediately, do not discuss with colleagues, I am in a meeting' — high-pressure language pattern"},
      {time:"11:44:45",sev:"crit",src:"MailShield",event:"Finance AP employee called IT Security — suspicious wire request — payment NOT yet processed"},
      {time:"11:45:00",sev:"crit",src:"BlueTrace", event:"BEC pattern detected — alert fired — SOC investigating"},
    ],
    file_events:[{time:"11:42:30",action:"RECEIVED",path:"Email: Urgent Wire Transfer Required",sha256:"",size:"4KB",signed:false}],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[
      {
        type:"Domain",value:"corp.com",
        vt_score:"12/90 flagged",abuse_score:76,
        categories:["Lookalike Domain","BEC Infrastructure","Typosquat"],
        country:"US",asn:"AS13335 — Cloudflare",
        last_seen:"2026-05-28",
        campaigns:["BEC campaign targeting Indian corporates — May 2026","Wire fraud targeting CFO/Finance teams — same infrastructure"],
        passive_dns:["mail.corp.com","smtp.corp.com"],
        first_seen:"2026-05-22",
        verdict:"MALICIOUS — Lookalike domain registered 6 days ago specifically for BEC. No DMARC. Used in active BEC campaign targeting Indian finance teams.",
        verdictColor:"#dc2626",
      },
    ],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0612",sla_minutes:30,priority:"P1",category:"Business Email Compromise",subcategory:"CEO/CFO Fraud",assignee:null,watchers:["soc-lead@corp.internal","ciso@corp.internal","finance-director@corp.internal"],escalation_path:"SOC L1 → SOC Lead → Finance Director → CFO (real) → CISO",updates:[]},
  steps:[
    {
      id:0,phase:"TRIAGE",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"BEC — Business Email Compromise",
      objective:"Business Email Compromise is one of the most financially damaging attack types. No malware. No process trees. Just a convincing email that makes Finance transfer company money to criminals. Look at the two alerts. What are the specific indicators that make this suspicious?",
      lookFor:["The sender domain — corp.com vs corp.internal. Spot the difference.","How old is corp.com? Why does domain age matter for BEC?","The email content — what pressure tactics were used?","DMARC status — what does 'none' mean for email security?"],
      seniorThinking:"BEC is about urgency, authority, and secrecy. The attacker impersonates a CFO and says: 'Do this now, do not discuss with others, I am busy.' That combination is the textbook BEC pattern. The technical indicator is the lookalike domain — corp.com vs corp.internal. Most users miss it at a glance.",
      instruction:"Look at both alerts. Identify the domain difference and the behavioral red flags in the email content.",
      analyst_note:"corp.com ≠ corp.internal. Registered 6 days ago. DMARC none. Urgency + secrecy = classic BEC. Payment not yet processed — you have time.",
      decision:{
        question:"Finance has not yet processed the payment. What is the most urgent action right now?",
        options:[
          {text:"Immediately contact the Finance AP team and the real CFO to confirm this is fraudulent",correct:true,why:"Correct. Payment has not been processed. You have a window to prevent the fraud. Call Finance AP directly (not via email — the attacker may be monitoring) and verify with the real CFO using a phone number from your corporate directory, not the one in the email."},
          {text:"Investigate the domain thoroughly before contacting Finance",correct:false,why:"Incorrect priority. Every minute you investigate without contacting Finance is a minute Finance might process the payment. Prevent the fraud first, investigate second."},
          {text:"Block corp.com at the email gateway and tell Finance to ignore the email",correct:false,why:"Partially correct but incomplete. Blocking the domain is a good action but not your first priority. The payment prevention call to Finance must happen immediately. Blocking alone does not prevent someone from processing the existing email."},
          {text:"Wait for the CFO to confirm they did not send the email",correct:false,why:"Too slow and wrong channel. Do not email the CFO — that may go to the attacker's inbox. Call the CFO directly using the corporate directory number. And do not wait — stop Finance immediately."},
        ]
      },
      evidence_bullets:["Sender: rajesh.mehta@corp.com (NOT corp.internal — different domain)","corp.com registered: 6 days ago — brand new lookalike domain","DMARC: none — no email authentication on this domain","Email text: 'urgent, confidential, do not discuss' — pressure tactics","Amount: ₹47,00,000 — to new/unrecognised vendor account","Payment status: NOT YET PROCESSED — act now"],
      action_label:"Call Finance AP + Call Real CFO — Stop the Payment",
      action_result:"Finance AP called (11:47):\nPayment has NOT been processed — held pending verification\nFinance confirms: did not receive verbal instruction from CFO\n\nCFO called directly (corporate directory):\n'I did not send any wire transfer request. Do not process this.'\n\nPayment: BLOCKED\nFraud: PREVENTED\nAmount saved: ₹47,00,000\nStatus: Investigating the attack infrastructure",
    },
    {
      id:1,phase:"INVESTIGATION",xp:20,
      tool:"ThreatLens",toolIcon:"🔍",toolAnalogy:"like a criminal database for IPs and files",
      title:"Investigate the Attack Infrastructure",
      objective:"Payment is blocked. Now understand the attack. Look up corp.com in ThreatLens. Is this part of a wider campaign? Has this domain been used against other companies? Understanding the threat actor helps you advise the CISO on risk level.",
      lookFor:["How old is the domain? This tells you if it was purpose-built for this attack","What campaigns is this infrastructure associated with?","Are there other domains in the same infrastructure?","Has this attacker targeted others in your industry?"],
      seniorThinking:"BEC infrastructure investigation tells you if you are targeted specifically or if you are one of many victims in a campaign. If it is a campaign, your CISO needs to brief other companies in your sector. If it is targeted, the threat model is different — someone researched your company specifically.",
      instruction:"Look up corp.com. Read the campaign associations. Advise the CISO on whether this is targeted or campaign-based.",
      analyst_note:"Domain 6 days old — campaign targeting Indian corporates — same infrastructure used against other finance teams. Not specifically targeted — mass BEC campaign.",
      decision:{
        question:"corp.com is linked to a BEC campaign targeting Indian finance teams. What should you recommend to the CISO?",
        options:[
          {text:"Implement DMARC enforcement on your domain and share IOCs with sector peers",correct:true,why:"Correct. DMARC enforcement would have flagged or blocked this email. Sharing IOCs with peer companies (ISAC/sector coordination) warns others who may be targeted in the same campaign. Both are the right recommendations."},
          {text:"Nothing — the payment was blocked so the incident is over",correct:false,why:"Incorrect. The attack vector (no DMARC enforcement) still exists. The next BEC email will get through and might not be caught by a vigilant employee. Fix the root cause."},
          {text:"Report the domain to Cloudflare for takedown",correct:false,why:"Helpful but insufficient as a primary response. Takedowns take time and the attacker can register another domain in hours. Fixing your own defenses (DMARC) is more impactful."},
          {text:"Train the one Finance employee who was suspicious — they did the right thing",correct:false,why:"Training that employee is good but limited. The real fix is DMARC — a technical control that would make the lookalike domain visually obvious or blocked. Do not rely solely on human detection for BEC."},
        ]
      },
      evidence_bullets:["corp.com: 6 days old — purpose-built for this BEC campaign","Linked to: BEC campaign targeting Indian corporates May 2026","Same infrastructure: used against multiple finance teams this month","DMARC gap: your domain has no enforcement — same email would pass again","Root cause: no DMARC policy preventing spoofed lookalike domain emails"],
      action_label:"Block Domain + Recommend DMARC + Brief CISO",
      action_result:"INC-2026-0612 — CLOSED\n\nOUTCOME: BEC PREVENTED — ₹47,00,000 fraud blocked\n\nACTIONS:\n[✓] corp.com blocked at email gateway\n[✓] Finance AP + real CFO notified\n[✓] CISO briefed — campaign targeting Indian corporates\n\nRECOMMENDATIONS:\n[1] Implement DMARC enforcement on corp.internal domain\n[2] Finance wire transfer policy: verbal confirmation required for >₹10L\n[3] Share IOCs with financial sector ISAC\n[4] User awareness training: lookalike domains",
    },
  ],
},

// ── SCENARIO 09: Public Cloud Storage Exposure ─────────────────────────────
"INC-2026-0634":{
  id:"INC-2026-0634",
  title:"Public AWS S3 Bucket — Sensitive Files Accessible Without Auth",
  severity:"Critical",status:"New",created:tsNow(0),
  host:"AWS S3 — corp-data-backup-prod",user:"aws-terraform@corp.internal",
  srcIp:null,c2Ip:null,assignee:null,
  tags:["AWS","S3","Cloud Misconfiguration","Data Exposure","Public Bucket"],
  summary:"External security researcher reported corp-data-backup-prod S3 bucket is publicly accessible without authentication. Bucket contains database backup files including customer PII. AWS CloudTrail shows the bucket ACL was changed to public-read 3 days ago during a Terraform deployment. Undetermined if malicious actors have accessed the data.",
  mitre:["T1530"],isTP:true,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-8833 — Cloud Asset Exposure Alert",
    fired_at:tsNow(0),risk_score:98,
    alerts:[
      {id:"BT-0101",time:"09:30:00",sev:"Critical",rule:"S3_PUBLIC_BUCKET_DETECTED",src:"AWS Config",msg:"S3 bucket corp-data-backup-prod ACL: public-read — contains 847 files — bucket policy allows GetObject for * (all)"},
      {id:"BT-0102",time:"09:30:00",sev:"Critical",rule:"SENSITIVE_DATA_EXPOSED",src:"AWS Macie",msg:"AWS Macie detected PII in corp-data-backup-prod: customer emails, phone numbers, addresses in database backup files — 127,000 records"},
      {id:"BT-0103",time:"09:30:00",sev:"High",rule:"CLOUDTRAIL_POLICY_CHANGE",src:"AWS CloudTrail",msg:"Bucket ACL changed to public-read at 14:22 3 days ago — source: aws-terraform IAM role — Terraform apply from CI/CD pipeline"},
    ],
    raw_search:`index=aws sourcetype=aws:cloudtrail eventName=PutBucketAcl
requestParameters.bucketName=corp-data-backup-prod
| table _time, userIdentity.type, userIdentity.arn, sourceIPAddress, requestParameters`,
    correlated_hosts:["AWS S3","AWS CloudTrail"],
    previous_incidents:["No previous S3 exposure incidents"],
  },
  edr:{
    tool:"CloudGuard",sensor_id:"AWS-Account-Corp-Prod",sensor_version:"AWS Config + CloudTrail",
    prevention_policy:"AWS Security Hub — Standard",policy_note:"S3 Block Public Access: NOT enabled on this account",
    process_tree:[],network:[],
    timeline:[
      {time:"3 days ago 14:22",sev:"crit",src:"CloudTrail",event:"PutBucketAcl: corp-data-backup-prod — ACL changed to public-read — principal: aws-terraform — CI/CD pipeline ID: deploy-prod-2026-05-25-1422"},
      {time:"3 days ago 14:23",sev:"info",src:"CloudTrail",event:"Terraform apply completed — commit hash: a7b8c9d — author: dev-ops team — 'Added public-read for cross-account backup verification — TO DO: remove after testing'"},
      {time:"Today 08:15",sev:"crit",src:"External",event:"Security researcher email: 'Your S3 bucket corp-data-backup-prod is publicly accessible — contains customer data'"},
      {time:"Today 09:30",sev:"crit",src:"AWS Macie",event:"PII detected in bucket: 127,000 customer records — emails, phones, addresses"},
      {time:"Today 09:30",sev:"crit",src:"AWS CloudTrail",event:"Unknown external IPs accessed bucket in last 3 days — 2,847 GetObject requests — data accessed: CONFIRMED"},
    ],
    file_events:[
      {time:"3 days ago",action:"EXPOSED",path:"s3://corp-data-backup-prod/db-backup-2026-05-25.sql.gz",sha256:"",size:"2.4GB",signed:false},
      {time:"3 days ago",action:"EXPOSED",path:"s3://corp-data-backup-prod/customer-export-2026-05-25.csv",sha256:"",size:"340MB",signed:false},
    ],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[{
      type:"IP",value:"External IPs (2,847 GetObject requests)",
      vt_score:"Multiple IPs — mixed",abuse_score:0,
      categories:["Unknown — External Access to Public Bucket"],
      country:"Multiple",asn:"Various",last_seen:"Today",
      campaigns:[],passive_dns:[],first_seen:"3 days ago",
      verdict:"UNKNOWN — 2,847 S3 GetObject requests from external IPs over 3 days. AWS CloudTrail logged all requests. Data was publicly readable — cannot determine if access was by security researchers, automated scanners, or malicious actors without further investigation.",
      verdictColor:"#f59e0b",
    }],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0634",sla_minutes:30,priority:"P1",category:"Cloud Security — Data Exposure",subcategory:"S3 Public Bucket — PII Exposed",assignee:null,watchers:["soc-lead@corp.internal","ciso@corp.internal","legal@corp.internal","devops-lead@corp.internal"],escalation_path:"SOC L1 → CISO → Legal → Regulatory",updates:[]},
  steps:[
    {
      id:0,phase:"CONTAINMENT",xp:25,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Public Data Exposure — Contain First",
      objective:"127,000 customer PII records have been publicly accessible for 3 days. Unlike an endpoint incident, the data is already out — you cannot contain what has been downloaded. But you can stop NEW exposure immediately. What is the very first action?",
      lookFor:["How was the bucket made public? Was it intentional?","Is the bucket still public right now?","What data is in the bucket? What is its classification?","Have external IPs actually accessed the data?"],
      seniorThinking:"Cloud exposure incidents have a different priority order than endpoint incidents. On an endpoint, you contain then investigate. For a public S3 bucket, you IMMEDIATELY make it private — even before you understand everything. Every minute it stays public = more potential data accessed. Make it private first.",
      instruction:"Look at all three alerts. The bucket is still public right now. What must you do in the next 60 seconds?",
      analyst_note:"Make bucket private immediately. This takes one CLI command or one console click. Do not investigate first. Data is leaving the building right now.",
      decision:{
        question:"The S3 bucket is still publicly accessible right now. What do you do in the next 60 seconds?",
        options:[
          {text:"Make the bucket private immediately — investigate cause afterward",correct:true,why:"Correct. Every second the bucket stays public is a second more data could be accessed. One AWS CLI command: aws s3api put-bucket-acl --bucket corp-data-backup-prod --acl private. Do this now. Investigate why it happened after."},
          {text:"Investigate how it became public before making any changes",correct:false,why:"Incorrect priority for cloud exposure. Unlike endpoint forensics where you must not change state, a public S3 bucket must be made private immediately. Investigation after containment."},
          {text:"Wait for DevOps to confirm they are done using it",correct:false,why:"Incorrect. 127,000 customer PII records are publicly accessible. You do not wait for DevOps to finish — you make it private now and explain why. DevOps can re-open access if needed, privately."},
          {text:"Check AWS WAF to block external access",correct:false,why:"Wrong tool. WAF protects web applications, not S3 buckets. The direct fix is the bucket ACL or S3 Block Public Access setting. Use the right control."},
        ]
      },
      evidence_bullets:["Bucket status: PUBLIC-READ — accessible to entire internet right now","Data in bucket: 127,000 customer records — emails, phones, addresses (PII)","Public since: 3 days ago (Terraform deployment)","External access: 2,847 GetObject requests confirmed in CloudTrail","Root cause: Terraform 'TO DO: remove after testing' — never removed"],
      action_label:"Make Bucket Private — Immediate Containment",
      action_result:"aws s3api put-bucket-acl --bucket corp-data-backup-prod --acl private\n\ncorp-data-backup-prod — ACL: PRIVATE (11:47 UTC)\nExternal access: STOPPED\nAWS Config: Bucket now compliant\nS3 Block Public Access: ENABLED (account-wide)\n\nStatus: Contained — now investigate scope of exposure",
    },
    {
      id:1,phase:"INVESTIGATION",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"Determine Scope — Who Accessed the Data?",
      objective:"Bucket is private. Now determine: did malicious actors access the data? CloudTrail logged every GetObject request. You have 2,847 requests from external IPs over 3 days. You cannot know intent but you can categorize the access patterns.",
      lookFor:["What IPs made GetObject requests? Known scanner IPs? Attacker IPs?","What files were downloaded? The full database dump or just parts?","What time pattern? Random scan or targeted access?","Does ThreatLens flag any of the source IPs?"],
      seniorThinking:"For regulatory purposes I need to assume the worst: if the data was accessible, it was accessed. Even if all the IPs are benign scanners, a DPDPA/GDPR breach notification assessment is required because the data WAS accessible to unauthorized parties for 3 days. The CloudTrail investigation helps determine severity, not whether to notify.",
      instruction:"Review the CloudTrail access logs. Categorize the 2,847 requests. Even if you cannot determine malicious access definitively — what must you do from a regulatory standpoint?",
      analyst_note:"127,000 PII records exposed for 3 days = mandatory breach notification assessment under DPDPA 2023 (India) and GDPR (if EU data subjects). Legal must be engaged immediately.",
      decision:{
        question:"You cannot determine if the 2,847 GetObject requests were malicious or from automated scanners. From a regulatory standpoint, what is required?",
        options:[
          {text:"Treat it as a data breach — notify Legal for DPDPA/GDPR assessment immediately",correct:true,why:"Correct. Under DPDPA 2023 and GDPR, a breach occurs when personal data is accessible to unauthorized parties — regardless of whether it was actively exploited. 3 days of public access to 127,000 PII records = reportable breach. Legal must assess within 72 hours."},
          {text:"Only notify if you confirm malicious actors accessed the data",correct:false,why:"Incorrect under DPDPA/GDPR. The legal standard is unauthorized access, not confirmed malicious use. A publicly accessible bucket is unauthorized access by definition — you cannot know who downloaded what from a public URL."},
          {text:"Wait for CloudTrail analysis to complete before notifying Legal",correct:false,why:"Incorrect timeline. GDPR requires notification within 72 hours of discovery — not after investigation completes. Notify Legal now with what you know. They will handle the notification."},
          {text:"Notify only if the security researcher shares the data publicly",correct:false,why:"Completely incorrect. Regulatory obligation does not depend on whether data is published. It depends on whether unauthorized parties could have accessed it. They could. Notify."},
        ]
      },
      evidence_bullets:["2,847 GetObject requests from external IPs — CloudTrail confirmed","Files accessed include customer-export-2026-05-25.csv — PII confirmed","Exposure window: 3 days — May 25 14:22 to May 28 11:47","127,000 customer records: emails, phones, addresses","GDPR 72-hour clock: started at discovery (09:30 today)"],
      action_label:"Notify Legal + CISO — Initiate Breach Assessment",
      action_result:"INC-2026-0634 — CLOSED (SOC Phase)\n\nCONTAINMENT: Bucket private — S3 Block Public Access enabled\nDATA EXPOSED: 127,000 customer PII records for 3 days\nACCESS: 2,847 external GetObject requests — intent unknown\n\nLEGAL: NOTIFIED — DPDPA 2023 breach assessment initiated\nGDPR: 72-hour clock running — DPO engaged\nCISO: BRIEFED\nDevOps: Root cause fix — Terraform review + TO DO tags banned in prod\n\nRECOMMENDATIONS:\n[1] S3 Block Public Access: enabled account-wide (done)\n[2] AWS Config rule: alert on any public bucket within 60 seconds\n[3] Terraform: no temporary access without auto-expiry policy\n[4] CI/CD: security scan for public ACLs pre-deployment",
    },
  ],
},

// ── SCENARIO 10: Authentication Failure Storm — FALSE POSITIVE ─────────────
"INC-2026-0651":{
  id:"INC-2026-0651",
  title:"3,847 Auth Failures in 10 Minutes — Brute Force or System Failure?",
  severity:"High",status:"New",created:tsNow(0),
  host:"DC-CORP-01 / Active Directory",user:"multiple",
  srcIp:"10.10.0.0/16",c2Ip:null,assignee:null,
  tags:["Authentication","Brute Force","False Positive","Active Directory","Change Management"],
  summary:"BlueTrace SIEM fired BRUTE_FORCE_DETECTION. 3,847 authentication failures across 1,247 user accounts in 10 minutes. All failures from internal IP range. This matches brute force pattern — but the scale (1,247 accounts simultaneously) is unusual for a targeted attack. Possible credential stuffing OR a system change causing mass auth failures. Investigate before assuming malicious.",
  mitre:["T1110.001"],isTP:false,
  siem:{
    tool:"BlueTrace SIEM",
    correlation_rule:"CORP-RULE-1055 — Mass Authentication Failure Threshold",
    fired_at:tsNow(0),risk_score:71,
    alerts:[
      {id:"BT-1101",time:"09:00:05",sev:"High",rule:"BRUTE_FORCE_DETECTION",src:"Windows Events",msg:"3,847 EventID 4625 (auth failures) in 10 minutes — 1,247 unique accounts — source: multiple internal IPs — failure reason: wrong password"},
      {id:"BT-1102",time:"09:00:05",sev:"Medium",rule:"NO_SUCCESSFUL_LOGINS",src:"Windows Events",msg:"0 successful authentications from source IPs during attack window — unusual for credential stuffing (typically some hits)"},
      {id:"BT-1103",time:"08:58:00",sev:"Low",rule:"CHANGE_TICKET_ACTIVE",src:"IncidentDesk",msg:"Active Change Ticket CHG-2026-0211 — Password Policy Update — scheduled maintenance 09:00-11:00 — may cause auth disruption"},
    ],
    raw_search:`index=wineventlog EventCode=4625 earliest=08:55 latest=09:15
| stats count by SubjectUserName, IpAddress, FailureReason
| sort -count`,
    correlated_hosts:["DC-CORP-01"],
    previous_incidents:["No previous brute force incidents at this scale"],
  },
  edr:{
    tool:"SentinelEDR",sensor_id:"DC-CORP-01-SENSOR",sensor_version:"7.14.17706",
    prevention_policy:"CORP-DC-DETECT-ONLY",policy_note:"Domain controller — detect only",
    process_tree:[],network:[],
    timeline:[
      {time:"08:55:00",sev:"info",src:"IncidentDesk",event:"CHG-2026-0211: Password Policy Update begins — new minimum length 14 chars — force change on next login"},
      {time:"09:00:00",sev:"info",src:"AD",          event:"Password policy change pushed to domain — all user cached credentials invalidated"},
      {time:"09:00:05",sev:"high",src:"AD",          event:"Authentication failures begin — all failures: SubStatus 0xC000006A (wrong password) — cached credential mismatch"},
      {time:"09:00:05",sev:"high",src:"BlueTrace",   event:"BRUTE_FORCE_DETECTION fired — 3,847 failures in first 10 seconds"},
      {time:"09:01:00",sev:"info",src:"AD",          event:"Users beginning password resets — call volume to helpdesk: 47 tickets in 60 seconds"},
      {time:"09:02:00",sev:"info",src:"Helpdesk",    event:"IT Helpdesk: 'We are aware — password policy change broke cached credentials — please reset your password'"},
    ],
    file_events:[],
  },
  threatintel:{
    tool:"ThreatLens",
    lookups:[{
      type:"IP",value:"10.10.0.0/16 (internal range)",
      vt_score:"N/A — internal",abuse_score:0,
      categories:["Internal RFC1918 — Corporate Network"],
      country:"INT",asn:"Internal",last_seen:"",campaigns:[],passive_dns:[],first_seen:"",
      verdict:"INTERNAL ONLY — All authentication failures sourced from internal RFC1918 address space. No external IPs involved. Pattern inconsistent with external credential stuffing. Consistent with internal system change causing widespread auth failures.",
      verdictColor:"#16a34a",
    }],
  },
  desk:{tool:"IncidentDesk",ticket_id:"INC-2026-0651",sla_minutes:60,priority:"P2",category:"Authentication Anomaly",subcategory:"Mass Auth Failures",assignee:null,watchers:["soc-lead@corp.internal"],escalation_path:"SOC L1 → IT Operations",updates:[]},
  steps:[
    {
      id:0,phase:"TRIAGE",xp:20,
      tool:"BlueTrace SIEM",toolIcon:"📊",toolAnalogy:"like a security camera control room",
      title:"3,847 Auth Failures — Attack or System Change?",
      objective:"3,847 authentication failures in 10 minutes looks terrifying. But look carefully at the three alerts together. There is a critical clue in the third alert. What does alert BT-1103 tell you? And what does 1,247 accounts failing simultaneously tell you about the pattern?",
      lookFor:["Alert BT-1103 — there is an active Change Ticket for password policy. What changed at exactly 09:00?","The number of accounts — 1,247 accounts failing at the same time. Is that how credential stuffing works?","The 0 successful logins — what does that mean in a real brute force attack?","The source IPs — all internal. No external IPs involved."],
      seniorThinking:"Real credential stuffing gets some successful logins — attackers rely on password reuse. If you spray 1,247 accounts with leaked passwords and get zero hits, either your users are excellent at unique passwords, or the passwords being tried are all wrong — like cached credentials that just became invalid due to a policy change.",
      instruction:"Read all three alerts. Pay special attention to BT-1103. What happened at 09:00 that could cause 1,247 accounts to fail simultaneously?",
      analyst_note:"CHG-2026-0211: password policy change pushed at 09:00 = cached credentials invalidated = mass auth failures. Not an attack. Operational incident.",
      decision:{
        question:"A password policy change was deployed at exactly 09:00 — the same moment authentication failures began. What is the most likely explanation?",
        options:[
          {text:"The password policy change invalidated cached credentials — causing mass auth failures",correct:true,why:"Correct. When a new password policy (minimum length 14) is pushed to a domain, cached credentials that do not meet the new policy are invalidated. Every user whose machine tries to authenticate with the old cached credential gets a failure. 1,247 simultaneous failures = system-wide policy change, not targeted attack."},
          {text:"Attackers targeted all 1,247 accounts simultaneously using credential stuffing",correct:false,why:"Unlikely. Real credential stuffing attacks are sequential or staged — attackers try one password against many accounts, then rotate. 1,247 accounts failing in the SAME SECOND from INTERNAL IPs, with ZERO successful logins, is not how credential stuffing works."},
          {text:"An insider is brute-forcing all accounts from inside the network",correct:false,why:"Implausible at this scale. Brute-forcing 1,247 accounts simultaneously from an internal network would require significant infrastructure and would show up as one or a few source IPs with high volume. The pattern here — distributed internal IPs — does not match."},
          {text:"Domain controllers are under a DoS attack",correct:false,why:"A DoS attack would show service unavailability, not authentication failures. The failures are EventID 4625 'wrong password' — the DCs are responding normally, users simply cannot authenticate with their old cached credentials."},
        ]
      },
      evidence_bullets:["1,247 accounts failed in <10 seconds — simultaneous, not sequential","0 successful logins — real credential stuffing always gets some hits","All source IPs: internal 10.10.0.0/16 — no external IPs","CHG-2026-0211 active: password policy change deployed at 09:00","Helpdesk: 47 tickets in 60 seconds — users reporting password problems"],
      action_label:"Confirm with IT Operations — Operational Incident, Not Attack",
      action_result:"IT Operations confirmed (09:08):\n'Yes — CHG-2026-0211 password policy update pushed at 09:00. Minimum length changed from 8 to 14 characters. Cached credentials invalidated. Users need to reset passwords. We are aware — helpdesk handling.'\n\nClassification: FALSE POSITIVE — Operational incident\nCause: Password policy change invalidated cached credentials\nResponse: IT Operations owns — SOC closed\nStatus: Monitoring for any genuine auth attacks hiding in the noise",
    },
    {
      id:1,phase:"CLOSE",xp:15,
      tool:"IncidentDesk",toolIcon:"📋",toolAnalogy:"like a detective case file",
      title:"Close + Prevent Recurrence",
      objective:"This was a False Positive — a legitimate change management event that looked like a brute force attack. But there is an important nuance: while investigating this FP, a REAL brute force attack could hide in the noise. Your recommendation must address both the false positive AND the detection gap it creates.",
      lookFor:["How could you distinguish a real attack from this noise in the future?","What process would have prevented this FP alert?","Should the SOC be notified before password policy changes?","What monitoring would catch a real attack hiding in this noise?"],
      seniorThinking:"Operational noise covering real attacks is a genuine risk. If an attacker knew a password change was happening and timed their credential stuffing to start at 09:00, it would be invisible in this noise. The recommendation must include: (1) pre-change SOC notification, and (2) a detection that looks for mixed success/failure patterns even during noisy events.",
      instruction:"Write the IR report recommendation. Address both the FP and the detection gap.",
      analyst_note:"Change management notification + detection tuning = both required. Good recommendation addresses the process AND the detection gap.",
      decision:{
        question:"What is the most complete recommendation to prevent this FP while maintaining detection capability?",
        options:[
          {text:"Pre-change SOC notification + detection that monitors for successful logins during the noise window",correct:true,why:"Correct on both counts. Pre-change notification lets SOC expect and suppress the noise. Monitoring for successful logins during the window would catch real credential stuffing hiding in the operational failures — attackers would show mixed success/failure patterns, not all-failures."},
          {text:"Raise the authentication failure threshold so mass changes do not trigger alerts",correct:false,why:"Dangerous. Raising the threshold makes you blind to real brute force attacks that stay below the new threshold. Attackers tune their attack volume to stay below SIEM thresholds. Do not lower your detection capability."},
          {text:"Disable the BRUTE_FORCE_DETECTION rule — it generates too many false positives",correct:false,why:"Incorrect. The rule correctly detected a pattern that LOOKS like a brute force attack. The problem is not the rule — it is the missing context (no SOC pre-notification about the change). Fix the process, not the detection."},
          {text:"Only run password policy changes on weekends when users are not working",correct:false,why:"A process workaround, not a fix. Attackers do not limit their activity to weekdays. And weekend changes still generate the same noise. The correct fix is process notification and context-aware detection."},
        ]
      },
      evidence_bullets:["Root cause: No SOC pre-notification before password policy change","Detection gap: Real attack could hide in mass operational noise","Risk: Attacker timed with change event = invisible credential stuffing","Good news: Change Ticket was active — system worked partially","Need: Process + detection improvement, not rule removal"],
      action_label:"Close FALSE POSITIVE — Raise Process + Detection Improvement",
      action_result:"INC-2026-0651 — FALSE POSITIVE — CLOSED\n\nROOT CAUSE: Password policy change without SOC pre-notification\nDETECTION GAP: Real attacks could hide in operational noise\n\nRECOMMENDATIONS:\n[1] IT Operations: notify SOC 30 min before any change that affects authentication\n[2] Detection: during active change windows, alert on auth SUCCESSES not failures\n[3] Process: add SOC notification requirement to all change tickets affecting AD auth\n[4] Monitoring: post-change window — scan for any success/failure mix pattern\n\n+15 XP for identifying both the FP and the detection gap",
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
  const cls=s==="Critical"?"sev-crit":s==="High"?"sev-high":s==="Intermediate"?"sev-med":"sev-low";
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


function CompletionScreen({incId,xp,hints,elapsed,grade,onNext,onDash,submitFeedback}) {
  const mm=String(Math.floor(elapsed/60)).padStart(2,"0");
  const ss=String(elapsed%60).padStart(2,"0");
  const gc={S:"#a855f7",A:"#22c55e",B:"#3b82f6",C:"#f59e0b"}[grade]||"#3b82f6";
  const lesson=typeof SCENARIO_LESSONS!=="undefined"?SCENARIO_LESSONS[incId]:null;
  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.92)",zIndex:1000,
      display:"flex",alignItems:"center",justifyContent:"center",padding:16,overflowY:"auto"}}>
      <div style={{background:"#fff",borderRadius:16,padding:24,maxWidth:460,width:"100%"}}>
        <div style={{textAlign:"center",marginBottom:20}}>
          <div style={{fontSize:40,marginBottom:8}}>🎉</div>
          <div style={{fontSize:11,fontWeight:700,color:"#22c55e",letterSpacing:"0.15em",
            fontFamily:"monospace",textTransform:"uppercase",marginBottom:4}}>Case Closed</div>
          <div style={{fontSize:52,fontWeight:800,color:gc,fontFamily:"monospace",lineHeight:1,marginBottom:6}}>{grade}</div>
          <div style={{fontSize:15,fontWeight:700,color:"#111318"}}>Investigation Complete</div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:16}}>
          {[["XP",xp,"#1a56db"],["Time",mm+":"+ss,"#16a34a"],["Hints",hints,hints===0?"#16a34a":"#f59e0b"]].map(([l,v,c])=>(
            <div key={l} style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:9,padding:"10px",textAlign:"center"}}>
              <div style={{fontSize:20,fontWeight:700,color:c,fontFamily:"monospace"}}>{v}</div>
              <div style={{fontSize:9,color:"#9ca3af",textTransform:"uppercase",letterSpacing:"0.08em"}}>{l}</div>
            </div>
          ))}
        </div>
        {lesson?.lessons&&(
          <div style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:10,
            padding:"12px 14px",marginBottom:14}}>
            <div style={{fontSize:10,fontWeight:700,color:"#6b7280",letterSpacing:"0.1em",
              fontFamily:"monospace",marginBottom:8,textTransform:"uppercase"}}>Key Lessons</div>
            {lesson.lessons.map((l,i)=>(
              <div key={i} style={{display:"flex",gap:8,marginBottom:5}}>
                <span style={{color:"#22c55e",fontWeight:700,flexShrink:0}}>✓</span>
                <span style={{fontSize:12.5,color:"#374151",lineHeight:1.5}}>{l}</span>
              </div>
            ))}
          </div>
        )}
        {lesson?.nextId&&(
          <div style={{background:"#eff6ff",border:"1px solid #bfdbfe",borderRadius:10,
            padding:"14px",marginBottom:14,cursor:"pointer"}} onClick={onNext}>
            <div style={{fontSize:9,fontWeight:700,color:"#1a56db",fontFamily:"monospace",
              marginBottom:4,letterSpacing:"0.1em",textTransform:"uppercase"}}>Next Investigation</div>
            <div style={{fontSize:13,fontWeight:700,color:"#111318",marginBottom:8}}>{lesson.nextTitle}</div>
            <button style={{width:"100%",background:"#1a56db",color:"#fff",padding:"10px",
              borderRadius:8,fontSize:13,fontWeight:700,border:"none",cursor:"pointer"}}>
              Start Next →
            </button>
          </div>
        )}
        <button onClick={onDash} style={{width:"100%",background:"#f7f8fa",color:"#374151",
          padding:"11px",borderRadius:8,border:"1px solid #e1e4ed",fontSize:13,cursor:"pointer"}}>
          Return to Dashboard
        </button>
      </div>
    </div>
  );
}

const SCENARIO_LESSONS = {
  "INC-2026-0441":{title:"Spear-Phishing → C2 Beacon",
    lessons:["WINWORD spawning cmd.exe is always suspicious","Evidence before verdict — check ThreatLens before blocking","Containment preserves forensics — never just power off","Root cause: EDR was in detect-only mode"],
    nextId:"fp-powershell",nextTitle:"IT Admin PowerShell — False Positive?",
    nextPreview:"Not every suspicious alert is an attack."},
};

const GLOSSARY = {};
function GT({t,children}) { return <span>{children}</span>; }


function ScoreModal({inc, steps, elapsed, hintCount, onBack}) {
  const mm=String(Math.floor(elapsed/60)).padStart(2,"0");
  const ss=String(elapsed%60).padStart(2,"0");
  const totalXp=steps.reduce((a,s)=>a+s.xp,0);
  const hintPenalty=hintCount*15;
  const finalXp=Math.max(0,totalXp-hintPenalty);
  const pct=Math.round(finalXp/totalXp*100);
  const grade=pct>=90?"S":pct>=75?"A":pct>=60?"B":"C";
  const gc={S:"#a855f7",A:"#22c55e",B:"#3b82f6",C:"#f59e0b"}[grade];

  // Emotional payoffs per incident
  const IMPACT={
    "INC-2026-0441":{
      stopped:"a targeted Cobalt Strike attack on the Finance team",
      prevented:"payroll system access and credential theft",
      detail:"The attacker had an active C2 session for 14 minutes. You cut it off before they could move laterally to payroll servers.",
      nextTitle:"IT Admin PowerShell — False Positive?",
      nextId:"fp-powershell",
      lesson:"Not every attack succeeds because of the phishing email. It succeeds because the EDR was in detect-only mode. You found that gap."
    },
  };
  const impact=IMPACT[inc?.id]||{stopped:"a security incident",prevented:"further damage",detail:"Investigation complete.",nextTitle:null,nextId:null,lesson:null};

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.95)",zIndex:1000,
      display:"flex",alignItems:"center",justifyContent:"center",padding:16,overflowY:"auto"}}>
      <div style={{background:"#fff",borderRadius:18,padding:0,maxWidth:500,width:"100%",
        overflow:"hidden",animation:"fadeUp 0.4s ease"}}>

        {/* Grade banner */}
        <div style={{background:grade==="S"?"linear-gradient(135deg,#7c3aed,#1a56db)":
          grade==="A"?"linear-gradient(135deg,#16a34a,#0891b2)":
          "linear-gradient(135deg,#1a56db,#7c3aed)",
          padding:"28px 24px",textAlign:"center",position:"relative"}}>
          <div style={{fontSize:11,fontWeight:700,color:"rgba(255,255,255,0.7)",
            letterSpacing:"0.2em",fontFamily:"monospace",textTransform:"uppercase",marginBottom:8}}>
            Case Closed — {inc?.id}
          </div>
          <div style={{fontSize:72,fontWeight:900,color:"#fff",fontFamily:"monospace",
            lineHeight:1,marginBottom:4,textShadow:"0 2px 20px rgba(0,0,0,0.3)"}}>{grade}</div>
          <div style={{fontSize:16,fontWeight:700,color:"rgba(255,255,255,0.9)"}}>
            You stopped {impact.stopped}
          </div>
        </div>

        <div style={{padding:"20px 24px"}}>
          {/* What you prevented */}
          <div style={{background:"#f0fdf4",border:"1px solid #86efac",borderRadius:10,
            padding:"12px 14px",marginBottom:14}}>
            <div style={{fontSize:9,fontWeight:700,color:"#166534",fontFamily:"monospace",
              letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:6}}>🛡 Threat Prevented</div>
            <div style={{fontSize:13,color:"#14532d",lineHeight:1.7}}>{impact.detail}</div>
          </div>

          {/* Stats */}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:14}}>
            {[["XP Earned",finalXp+"","var(--ac)"],
              ["Response",mm+":"+ss,elapsed<900?"#16a34a":"#f59e0b"],
              ["Hints",hintCount+"",hintCount===0?"#16a34a":"#f59e0b"]
            ].map(([l,v,c])=>(
              <div key={l} style={{background:"#f7f8fa",border:"1px solid #e1e4ed",
                borderRadius:9,padding:"10px",textAlign:"center"}}>
                <div style={{fontSize:22,fontWeight:700,color:c,fontFamily:"monospace"}}>{v}</div>
                <div style={{fontSize:9,color:"#9ca3af",textTransform:"uppercase",
                  letterSpacing:"0.08em",marginTop:2}}>{l}</div>
              </div>
            ))}
          </div>

          {/* Key lesson */}
          {impact.lesson&&(
            <div style={{background:"#fffbeb",border:"1px solid #fde68a",borderRadius:10,
              padding:"12px 14px",marginBottom:14}}>
              <div style={{fontSize:9,fontWeight:700,color:"#b45309",fontFamily:"monospace",
                letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:5}}>👩‍💻 Key Lesson</div>
              <div style={{fontSize:13,color:"#78350f",lineHeight:1.7,fontStyle:"italic"}}>
                "{impact.lesson}"
              </div>
            </div>
          )}

          {/* Next investigation */}
          {impact.nextId&&(
            <div onClick={()=>{onBack();setTimeout(()=>{},100);}}
              style={{background:"linear-gradient(135deg,#eff6ff,#f0fdf4)",
                border:"1px solid #bfdbfe",borderRadius:12,padding:"14px",
                marginBottom:12,cursor:"pointer",transition:"all 0.15s"}}>
              <div style={{fontSize:9,fontWeight:700,color:"#1a56db",fontFamily:"monospace",
                letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:4}}>Next Investigation →</div>
              <div style={{fontSize:14,fontWeight:700,color:"#111318",marginBottom:8}}>
                {impact.nextTitle}
              </div>
              <button style={{width:"100%",background:"#1a56db",color:"#fff",
                padding:"12px",borderRadius:9,fontSize:13,fontWeight:700,
                border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)"}}>
                Start Next Investigation →
              </button>
            </div>
          )}

          <button onClick={onBack}
            style={{width:"100%",background:"#f7f8fa",color:"#6b7280",
              padding:"11px",borderRadius:9,border:"1px solid #e1e4ed",
              fontSize:13,cursor:"pointer"}}>
            Return to Dashboard
          </button>
          <div style={{display:"flex",gap:8,marginTop:8}}>
            <button onClick={()=>navigator.clipboard?.writeText("I just investigated a real SOC incident on LearnThreatOps! Free: learnblueteam-production.up.railway.app #CyberSecurity #SOCAnalyst").then(()=>alert("Copied!"))} style={{flex:1,background:"#0077b5",color:"#fff",padding:"9px",borderRadius:7,fontSize:12,fontWeight:600,border:"none",cursor:"pointer"}}>Copy for LinkedIn</button>
            <button onClick={()=>window.open("https://wa.me/?text="+encodeURIComponent("I investigated a real SOC incident on LearnThreatOps! Free: learnblueteam-production.up.railway.app"),"_blank")} style={{flex:1,background:"#25d366",color:"#fff",padding:"9px",borderRadius:7,fontSize:12,fontWeight:600,border:"none",cursor:"pointer"}}>WhatsApp</button>
          </div>
        </div>
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// COACH POPUP — the guided instruction overlay per step
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// NEW COACH POPUP — Socratic method, never gives answers
// ─────────────────────────────────────────────────────────────────────────────

function CoachPopup({step,onClose,onHint,hintUsed,stepsDone,totalSteps,mode}){
  const pc=phaseColor(step.phase);
  const [showHint,setShowHint]=useState(hintUsed);
  const isBeginner = mode==="beginner";

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",backdropFilter:"blur(4px)",zIndex:500,display:"flex",alignItems:"flex-end",justifyContent:"center",padding:"0 0 80px"}}>
      <div style={{background:"#fff",border:"1px solid "+pc+"40",borderRadius:16,padding:22,maxWidth:540,width:"100%",margin:"0 16px",boxShadow:"0 0 40px "+pc+"20",animation:"fadeUp 0.3s ease"}}>

        {/* Step header */}
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:14}}>
          <div style={{width:36,height:36,borderRadius:"50%",background:pc+"15",border:"2px solid "+pc+"50",display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,flexShrink:0}}>{step.toolIcon}</div>
          <div style={{flex:1}}>
            <div style={{fontSize:9.5,fontWeight:700,color:pc,letterSpacing:"0.12em",fontFamily:"var(--mo)",textTransform:"uppercase",marginBottom:2}}>{step.phase} — Step {step.id+1} of {totalSteps}</div>
            <div style={{fontSize:15,fontWeight:700,color:"#111318",lineHeight:1.2}}>{step.title}</div>
          </div>
          <div style={{background:pc+"12",border:"1px solid "+pc+"30",borderRadius:7,padding:"4px 10px",textAlign:"center",flexShrink:0}}>
            <div style={{fontSize:14,fontWeight:800,color:pc,fontFamily:"var(--mo)"}}>+{step.xp}</div>
            <div style={{fontSize:8,color:pc,fontFamily:"var(--mo)",letterSpacing:"0.08em"}}>XP</div>
          </div>
        </div>

        {/* Progress bar */}
        <div style={{display:"flex",gap:3,marginBottom:14}}>
          {Array.from({length:totalSteps}).map((_,i)=>(
            <div key={i} style={{flex:1,height:3,borderRadius:2,background:i<stepsDone?"#1a56db":i===step.id?pc+"80":"#e1e4ed",transition:"background 0.3s"}}/>
          ))}
        </div>

        {/* Tool badge */}
        <div style={{display:"inline-flex",alignItems:"center",gap:6,background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:6,padding:"4px 10px",marginBottom:12}}>
          <span style={{fontSize:10,color:"#6b7280",fontFamily:"var(--mo)"}}>🛠 Tool</span>
          <span style={{fontSize:10,fontWeight:700,color:"#111318",fontFamily:"var(--mo)"}}>{step.tool}</span>
          {isBeginner&&step.toolAnalogy&&<span style={{fontSize:9,color:"#8892a4",fontFamily:"var(--mo)"}}>— {step.toolAnalogy}</span>}
        </div>

        {/* Objective — Socratic, asks questions not directions */}
        <div style={{background:"#eff6ff",border:"1px solid #bfdbfe",borderRadius:10,padding:"12px 14px",marginBottom:12}}>
          <div style={{fontSize:9,fontWeight:700,color:"#1d4ed8",letterSpacing:"0.12em",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>Current Objective</div>
          <div style={{fontSize:13.5,color:"#1e3a5f",lineHeight:1.7}}>{step.objective||step.instruction}</div>
        </div>

        {/* What to look for — beginner only */}
        {isBeginner&&step.lookFor&&(
          <div style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:10,padding:"11px 14px",marginBottom:12}}>
            <div style={{fontSize:9,fontWeight:700,color:"#6b7280",letterSpacing:"0.12em",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>What to look for</div>
            <div style={{display:"flex",flexDirection:"column",gap:4}}>
              {step.lookFor.map((item,i)=>(
                <div key={i} style={{display:"flex",gap:8,alignItems:"flex-start"}}>
                  <span style={{color:"#1a56db",fontWeight:700,flexShrink:0,marginTop:1}}>→</span>
                  <span style={{fontSize:12.5,color:"#2d3241",lineHeight:1.5}}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Hint — senior analyst thinking, not answer */}
        {!showHint?(
          <button onClick={()=>{setShowHint(true);onHint();}} style={{background:"#fffbeb",border:"1px solid #fde68a",color:"#92400e",padding:"9px 14px",borderRadius:8,fontSize:12.5,cursor:"pointer",marginBottom:12,width:"100%",textAlign:"left",display:"flex",alignItems:"center",gap:8}}>
            <span>🧠</span>
            <span>How would a senior analyst approach this? <span style={{color:"#b45309",fontSize:11}}>(−{Math.min(step.xp,15)} XP)</span></span>
          </button>
        ):(
          <div style={{background:"#fffbeb",border:"1px solid #fde68a",borderRadius:9,padding:"11px 13px",marginBottom:12}}>
            <div style={{fontSize:9,fontWeight:700,color:"#b45309",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:5,textTransform:"uppercase"}}>Senior Analyst Thinking</div>
            <div style={{fontSize:13,color:"#92400e",lineHeight:1.7}}>{step.seniorThinking||step.analyst_note}</div>
          </div>
        )}

        <button onClick={onClose} style={{width:"100%",background:pc,color:"#fff",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px "+pc+"40"}}>
          Open {step.tool} →
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE SELECTOR — shown before scenario starts
// ─────────────────────────────────────────────────────────────────────────────

function ModeSelector({inc,onSelect}) {
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(17,19,24,0.6)",backdropFilter:"blur(6px)",zIndex:600,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <div style={{background:"#fff",borderRadius:16,padding:28,maxWidth:480,width:"100%",boxShadow:"0 8px 32px rgba(17,19,24,0.15)",animation:"fadeUp 0.3s ease"}}>
        <div style={{textAlign:"center",marginBottom:20}}>
          <div style={{fontSize:10,fontWeight:700,color:"#1a56db",letterSpacing:"0.15em",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>Choose Your Mode</div>
          <h2 style={{fontSize:18,fontWeight:800,color:"#111318",marginBottom:4}}>{inc.title}</h2>
          <div style={{fontSize:13,color:"#6b7280"}}>How do you want to investigate?</div>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:10,marginBottom:0}}>
          <button onClick={()=>onSelect("beginner")} style={{background:"#f0fdf4",border:"2px solid #86efac",borderRadius:12,padding:"18px",cursor:"pointer",textAlign:"left",transition:"all 0.13s"}}>
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6}}>
              <span style={{fontSize:22}}>🎓</span>
              <div>
                <div style={{fontSize:15,fontWeight:700,color:"#166534"}}>Beginner Mode</div>
                <div style={{fontSize:11,color:"#16a34a",fontFamily:"var(--mo)"}}>Recommended for new analysts</div>
              </div>
            </div>
            <div style={{fontSize:13,color:"#2d3241",lineHeight:1.6}}>
              ✓ Step-by-step analyst coaching<br/>
              ✓ Plain English explanations<br/>
              ✓ Tool analogies and context<br/>
              ✓ Hints available
            </div>
          </button>
          <button onClick={()=>onSelect("analyst")} style={{background:"#f7f8fa",border:"2px solid #e1e4ed",borderRadius:12,padding:"18px",cursor:"pointer",textAlign:"left",transition:"all 0.13s"}}>
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6}}>
              <span style={{fontSize:22}}>⚡</span>
              <div>
                <div style={{fontSize:15,fontWeight:700,color:"#111318"}}>Analyst Mode</div>
                <div style={{fontSize:11,color:"#6b7280",fontFamily:"var(--mo)"}}>For experienced analysts</div>
              </div>
            </div>
            <div style={{fontSize:13,color:"#5a6272",lineHeight:1.6}}>
              — No guided coaching<br/>
              — No hints<br/>
              — Full scoring based on speed and accuracy<br/>
              — Realistic investigation pressure
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// ACTION CONFIRMATION OVERLAY
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// DECISION QUESTION — analyst must answer before action unlocks
// ─────────────────────────────────────────────────────────────────────────────

function DecisionQuestion({step,onDecide}) {
  const [chosen,setChosen] = useState(null);
  const [revealed,setRevealed] = useState(false);
  const d = step.decision;
  if(!d) { onDecide(true); return null; }

  const choose = (i) => {
    if(chosen!==null) return;
    setChosen(i);
    setRevealed(true);
  };

  const proceed = () => onDecide(d.options[chosen]?.correct);

  return (
    <div style={{position:"fixed",inset:0,background:"rgba(17,19,24,0.65)",backdropFilter:"blur(4px)",zIndex:450,display:"flex",alignItems:"flex-end",justifyContent:"center",padding:"0 0 0 0"}}>
      <div style={{background:"#fff",borderRadius:"16px 16px 0 0",padding:20,maxWidth:560,width:"100%",maxHeight:"85vh",overflow:"auto",boxShadow:"0 -8px 32px rgba(17,19,24,0.15)",animation:"fadeUp 0.3s ease"}}>
        <div style={{fontSize:9,fontWeight:700,color:"#1a56db",letterSpacing:"0.15em",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase",display:"flex",alignItems:"center",gap:6}}>
          <span>🤔</span> Analyst Decision Required
        </div>
        <div style={{fontSize:15,fontWeight:700,color:"#111318",lineHeight:1.4,marginBottom:14}}>{d.question}</div>

        {/* Evidence summary before decision */}
        {step.evidence_bullets&&!revealed&&(
          <div style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:10,padding:"12px",marginBottom:14}}>
            <div style={{fontSize:9,fontWeight:700,color:"#6b7280",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Evidence Summary</div>
            {step.evidence_bullets.map((b,i)=>(
              <div key={i} style={{display:"flex",gap:8,alignItems:"flex-start",marginBottom:4}}>
                <span style={{color:"#1a56db",flexShrink:0,marginTop:1,fontSize:11}}>▸</span>
                <span style={{fontSize:12.5,color:"#2d3241",lineHeight:1.5}}>{b}</span>
              </div>
            ))}
          </div>
        )}

        <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:revealed?12:0}}>
          {d.options.map((opt,i)=>{
            const isChosen=chosen===i;
            const isCorrect=opt.correct;
            let bg="#f7f8fa",border="#e1e4ed",tc="#2d3241";
            if(revealed&&isChosen&&isCorrect){bg="#f0fdf4";border="#86efac";tc="#166534";}
            else if(revealed&&isChosen&&!isCorrect){bg="#fef2f2";border="#fca5a5";tc="#991b1b";}
            else if(revealed&&isCorrect){bg="#f0fdf4";border="#86efac";tc="#166534";}
            return(
              <div key={i}>
                <button onClick={()=>choose(i)} style={{width:"100%",background:bg,border:"1px solid "+border,borderRadius:9,padding:"11px 13px",cursor:chosen!==null?"default":"pointer",textAlign:"left",display:"flex",alignItems:"center",gap:10,transition:"all 0.15s"}}>
                  <div style={{width:24,height:24,borderRadius:"50%",border:"2px solid "+border,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:tc,flexShrink:0,background:"#fff"}}>
                    {revealed&&isChosen?(isCorrect?"✓":"✗"):String.fromCharCode(65+i)}
                  </div>
                  <span style={{fontSize:13.5,color:tc,fontWeight:isChosen?600:400,lineHeight:1.35}}>{opt.text}</span>
                </button>
                {revealed&&isChosen&&(
                  <div style={{margin:"5px 0 2px 0",padding:"10px 13px",background:isCorrect?"#f0fdf4":"#fef2f2",border:"1px solid "+(isCorrect?"#86efac":"#fca5a5"),borderRadius:8,fontSize:12.5,color:isCorrect?"#166534":"#991b1b",lineHeight:1.65}}>
                    {isCorrect?"✓ ":"✗ "}{opt.why}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {revealed&&(
          <button onClick={proceed} style={{width:"100%",background:d.options[chosen]?.correct?"#1a56db":"#dc2626",color:"#fff",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",marginTop:4,animation:"fadeUp 0.3s ease"}}>
            {d.options[chosen]?.correct?"Continue →":"Understood — Continue Anyway →"}
          </button>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ACTION OVERLAY — after decision, shows action button
// ─────────────────────────────────────────────────────────────────────────────

function ActionOverlay({step,onConfirm,isRunning,isDone,xpBurst}){
  const pc=phaseColor(step.phase);
  return(
    <div style={{position:"fixed",bottom:0,left:0,right:0,background:"#fff",borderTop:"2px solid "+pc+"40",padding:"14px 16px",zIndex:400,boxShadow:"0 -4px 20px rgba(17,19,24,0.1)"}}>
      {isDone?(
        <div style={{animation:"fadeUp 0.3s ease"}}>
          <div style={{background:"#f0fdf4",border:"1px solid #86efac",borderRadius:10,padding:"12px 14px",marginBottom:10}}>
            <div style={{fontSize:10,fontWeight:700,color:"#166534",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:5,textTransform:"uppercase"}}>✓ Action Confirmed</div>
            <div style={{fontSize:12.5,color:"#166534",lineHeight:1.75,whiteSpace:"pre-line",fontFamily:"var(--mo)"}}>{step.action_result}</div>
          </div>
          <button onClick={onConfirm} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"13px",borderRadius:9,fontSize:14,fontWeight:700,border:"none",cursor:"pointer"}}>
            {xpBurst?"Next Step →":"Continue →"}
          </button>
        </div>
      ):isRunning?(
        <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:12,padding:"10px",color:"#6b7280",fontFamily:"var(--mo)",fontSize:13}}>
          <div style={{width:16,height:16,border:"2px solid #e1e4ed",borderTop:"2px solid "+pc,borderRadius:"50%",animation:"spin 0.7s linear infinite"}}/>
          Executing action...
        </div>
      ):(
        <div>
          <div style={{fontSize:11,color:"#6b7280",marginBottom:8,fontFamily:"var(--mo)"}}>
            <span style={{color:pc,fontWeight:700}}>{step.tool}</span> — {step.phase}
          </div>
          <button onClick={onConfirm} style={{width:"100%",background:pc,color:"#fff",padding:"14px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",gap:8,boxShadow:"0 4px 16px "+pc+"40"}}>
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
            <span style={{fontSize:9.5,color:"var(--tx3)",fontFamily:"var(--mo)"}}>SIMULATION</span>
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
              <div style={{display:"flex",gap:5,flexWrap:"wrap",marginBottom:4}}>{inc.mitre.map(t=><Badge key={t} color="blue">{t}</Badge>)}</div>
              <div style={{fontSize:9,color:"var(--tx4)"}}>ATT&amp;CK® is a registered trademark of The MITRE Corporation. Used for educational reference only.</div>
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
// INVESTIGATION ZERO UI
// ─────────────────────────────────────────────────────────────────────────────

function InvestigationZero({onComplete,addXP}) {
  const [lesson,setLesson] = useState(0);
  const [answered,setAnswered] = useState(null); // index of chosen option
  const [showResult,setShowResult] = useState(false);
  const [done,setDone] = useState([]);
  const [xpTotal,setXpTotal] = useState(0);

  const L = INVESTIGATION_ZERO.lessons[lesson];
  const isLast = lesson === INVESTIGATION_ZERO.lessons.length-1;

  const choose = (i) => {
    if(answered!==null) return;
    setAnswered(i);
    setShowResult(true);
    if(L.options[i].correct){
      setXpTotal(x=>x+10);
    }
  };

  const next = () => {
    setDone(d=>[...d,lesson]);
    if(isLast){
      addXP(INVESTIGATION_ZERO.xpReward + xpTotal);
      onComplete();
    } else {
      setLesson(l=>l+1);
      setAnswered(null);
      setShowResult(false);
    }
  };

  return (
    <div style={{minHeight:"100vh",background:"#f7f8fa",display:"flex",flexDirection:"column"}}>
      {/* Header */}
      <div style={{background:"#fff",borderBottom:"1px solid #e1e4ed",padding:"12px 20px",display:"flex",alignItems:"center",gap:12,boxShadow:"0 1px 3px rgba(17,19,24,0.06)"}}>
        <div style={{width:32,height:32,borderRadius:8,background:"#1a56db",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:800,color:"#fff",fontFamily:"var(--mo)"}}>0</div>
        <div>
          <div style={{fontSize:13,fontWeight:700,color:"#111318"}}>Investigation Zero</div>
          <div style={{fontSize:11,color:"#8892a4"}}>Security Operations Fundamentals</div>
        </div>
        <div style={{flex:1}}/>
        <div style={{fontSize:11,color:"#8892a4",fontFamily:"var(--mo)"}}>{lesson+1}/{INVESTIGATION_ZERO.lessons.length}</div>
      </div>

      {/* Progress */}
      <div style={{height:4,background:"#e1e4ed"}}>
        <div style={{height:"100%",width:((done.length)/INVESTIGATION_ZERO.lessons.length*100)+"%",background:"linear-gradient(90deg,#1a56db,#7c3aed)",transition:"width 0.5s ease"}}/>
      </div>

      <div style={{flex:1,overflow:"auto",padding:"20px",maxWidth:640,margin:"0 auto",width:"100%"}}>

        {/* Lesson card */}
        <div key={lesson} style={{animation:"fadeUp 0.3s ease"}}>
          {/* Title */}
          <div style={{textAlign:"center",marginBottom:24}}>
            <div style={{fontSize:36,marginBottom:10}}>{L.icon}</div>
            <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>Lesson {lesson+1} of {INVESTIGATION_ZERO.lessons.length}</div>
            <h2 style={{fontSize:"clamp(18px,4vw,24px)",fontWeight:800,color:"#111318",lineHeight:1.2}}>{L.title}</h2>
          </div>

          {/* Analogy — the hook */}
          <div style={{background:"#eff6ff",border:"1px solid #bfdbfe",borderRadius:12,padding:"16px",marginBottom:14}}>
            <div style={{fontSize:10,fontWeight:700,color:"#1d4ed8",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase",display:"flex",alignItems:"center",gap:6}}>
              <span>💡</span> Think of it this way
            </div>
            <div style={{fontSize:14,color:"#1e3a5f",lineHeight:1.75}}>{L.analogy}</div>
          </div>

          {/* Concept */}
          <div style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:12,padding:"16px",marginBottom:14}}>
            <div style={{fontSize:10,fontWeight:700,color:"#6b7280",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>The Technical Explanation</div>
            <div style={{fontSize:13.5,color:"#2d3241",lineHeight:1.75}}>{L.concept}</div>
          </div>

          {/* Example */}
          <div style={{background:"#111318",borderRadius:12,padding:"14px",marginBottom:20}}>
            <div style={{fontSize:9,fontWeight:700,color:"#60a5fa",letterSpacing:"0.15em",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>{L.example.label}</div>
            <pre style={{fontSize:11.5,color:"#93c5fd",fontFamily:"var(--mo)",lineHeight:1.8,whiteSpace:"pre-wrap",margin:0}}>{L.example.content}</pre>
          </div>

          {/* Question */}
          <div style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:12,padding:"16px",marginBottom:12}}>
            <div style={{fontSize:10,fontWeight:700,color:"#1a56db",letterSpacing:"0.1em",fontFamily:"var(--mo)",marginBottom:10,textTransform:"uppercase",display:"flex",alignItems:"center",gap:6}}>
              <span>🤔</span> Quick Check
            </div>
            <div style={{fontSize:14,fontWeight:600,color:"#111318",lineHeight:1.5,marginBottom:14}}>{L.question}</div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {L.options.map((opt,i)=>{
                const isChosen = answered===i;
                const isCorrect = opt.correct;
                let bg="#f7f8fa", border="#e1e4ed", textColor="#2d3241";
                if(showResult && isChosen && isCorrect){bg="#f0fdf4";border="#86efac";textColor="#166534";}
                else if(showResult && isChosen && !isCorrect){bg="#fef2f2";border="#fca5a5";textColor="#991b1b";}
                else if(showResult && isCorrect){bg="#f0fdf4";border="#86efac";textColor="#166534";}
                return(
                  <div key={i}>
                    <button onClick={()=>choose(i)} style={{width:"100%",background:bg,border:"1px solid "+border,borderRadius:9,padding:"12px 14px",cursor:answered!==null?"default":"pointer",textAlign:"left",display:"flex",alignItems:"center",gap:10,transition:"all 0.15s"}}>
                      <div style={{width:22,height:22,borderRadius:"50%",border:"2px solid "+border,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:textColor,flexShrink:0,background:"#fff"}}>
                        {showResult&&isChosen?(isCorrect?"✓":"✗"):String.fromCharCode(65+i)}
                      </div>
                      <span style={{fontSize:13.5,color:textColor,fontWeight:isChosen?600:400,lineHeight:1.4}}>{opt.text}</span>
                    </button>
                    {showResult && isChosen && (
                      <div style={{margin:"6px 0 2px 0",padding:"10px 14px",background:isCorrect?"#f0fdf4":"#fef2f2",border:"1px solid "+(isCorrect?"#86efac":"#fca5a5"),borderRadius:8,fontSize:13,color:isCorrect?"#166534":"#991b1b",lineHeight:1.65}}>
                        {isCorrect?"✓ ":"✗ "}{opt.explanation}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Next button - only shows after answering */}
          {showResult && (
            <button onClick={next} style={{width:"100%",background:isLast?"#16a34a":"#1a56db",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)",animation:"fadeUp 0.3s ease"}}>
              {isLast?"🎯 Start My First Investigation →":"Next Lesson →"}
            </button>
          )}
        </div>

        {/* Lesson dots */}
        <div style={{display:"flex",justifyContent:"center",gap:6,marginTop:20}}>
          {INVESTIGATION_ZERO.lessons.map((_,i)=>(
            <div key={i} style={{width:8,height:8,borderRadius:"50%",background:done.includes(i)?"#1a56db":i===lesson?"#93c5fd":"#e1e4ed",transition:"all 0.3s"}}/>
          ))}
        </div>
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
              {id:"INC-2026-0443",sev:"Intermediate",  title:"Impossible Travel — M365 Login",    host:"Azure AD",      time:tsNow(4)},
              {id:"INC-2026-0444",sev:"Intermediate",  title:"DNS Tunneling — HR Workstation",    host:"WS-CORP-HR-012",time:tsNow(7)},
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


function IncidentBriefing({inc, onStart}) {
  const b = inc.briefing;
  if(!b){onStart();return null;}
  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.92)",zIndex:500,display:"flex",alignItems:"center",justifyContent:"center",padding:16,overflowY:"auto"}}>
      <div style={{background:"#fff",borderRadius:16,padding:0,maxWidth:520,width:"100%",overflow:"hidden",animation:"fadeUp 0.4s ease"}}>
        <div style={{background:"#dc2626",padding:"14px 20px",display:"flex",alignItems:"center",gap:10}}>
          <span style={{fontSize:20}}>🚨</span>
          <div>
            <div style={{fontSize:9,fontWeight:700,color:"rgba(255,255,255,0.7)",letterSpacing:"0.15em",fontFamily:"monospace",textTransform:"uppercase",marginBottom:2}}>Incident Briefing — {inc.id}</div>
            <div style={{fontSize:15,fontWeight:700,color:"#fff"}}>{inc.title}</div>
          </div>
        </div>
        <div style={{padding:"18px 20px"}}>
          <div style={{fontSize:10.5,fontWeight:600,color:"#6b7280",fontFamily:"monospace",marginBottom:10}}>{b.time}</div>
          {b.paragraphs.map((p,i)=><p key={i} style={{fontSize:13.5,color:"#374151",lineHeight:1.8,marginBottom:10}}>{p}</p>)}
          <div style={{background:"#fef2f2",border:"1px solid #fca5a5",borderRadius:9,padding:"11px 13px",marginBottom:12}}>
            <div style={{fontSize:9,fontWeight:700,color:"#dc2626",letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:7,textTransform:"uppercase"}}>What is at risk</div>
            {b.atRisk.map((r,i)=>(
              <div key={i} style={{display:"flex",gap:7,marginBottom:4}}>
                <span style={{color:"#dc2626",fontSize:11,flexShrink:0}}>⚠</span>
                <span style={{fontSize:12.5,color:"#7f1d1d",lineHeight:1.5}}>{r}</span>
              </div>
            ))}
          </div>
          <div style={{background:"#eff6ff",border:"1px solid #bfdbfe",borderRadius:9,padding:"11px 13px",marginBottom:16}}>
            <div style={{fontSize:9,fontWeight:700,color:"#1d4ed8",letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:5,textTransform:"uppercase"}}>🎯 Your Mission</div>
            <div style={{fontSize:13,color:"#1e3a5f",lineHeight:1.7,fontWeight:500}}>{b.mission}</div>
          </div>
          <button onClick={onStart} style={{width:"100%",background:"#dc2626",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(220,38,38,0.35)"}}>
            Begin Investigation →
          </button>
          <div style={{textAlign:"center",marginTop:8,fontSize:10.5,color:"#9ca3af"}}>🔒 TRAINING SIMULATION ONLY — All incidents, users, companies, IP addresses, and data are completely fictional and created for educational purposes. No real organisations or individuals are represented. No real security tools or data sources are used.</div>
        </div>
      </div>
    </div>
  );
}

function SOCConsole({incId="INC-2026-0441",prog={xp:0,level:1,done:{}},addXP=()=>{},finishSim=()=>{},onBack=()=>{},submitFeedback=()=>{},analyst:analystProp}){
  const inc=INCIDENTS[incId];
  const [activeTool,setActiveTool]=useState("siem");
  const [si,setSi]=useState(0);
  const [status,setStatus]=useState("ticket_review"); // ticket_review | mode_select | coach | decision | action_idle | action_running | action_done
  const [mode,setMode]=useState(null); // "beginner" | "analyst"
  const [decisionCorrect,setDecisionCorrect]=useState(null);
  const selectMode=(m)=>{setMode(m);setStatus("coach");};
  const handleDecision=(correct)=>{setDecisionCorrect(correct);setStatus("action_idle");};
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
    setStatus("decision");
  };
  const handleBack=()=>{
    if(si>0){
      // Remove last done step
      setDone(d=>d.filter(i=>i!==si-1));
      setSi(s=>s-1);
      setStatus("coach");
      setActiveTool(toolMap[INC.steps[si-1]?.tool]||"siem");
    }
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
            <button onClick={()=>selectMode("beginner")} style={{width:"100%",background:"var(--err)",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(239,68,68,0.4)"}}>
              Ticket Acknowledged — Start Investigation →
            </button>
          </div>
        </div>
      )}
      {false&&<ModeSelector inc={inc} onSelect={selectMode}/>}
      {status==="decision"&&step?.decision&&<DecisionQuestion step={step} onDecide={handleDecision}/>}
      {status==="decision"&&!step?.decision&&(handleDecision(true),null)}
      {status==="coach"&&<CoachPopup step={step} onClose={handleCoachClose} onHint={()=>setHintCount(h=>h+1)} hintUsed={false} stepsDone={doneSteps.length} totalSteps={inc.steps.length} mode={mode}/>}
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
        <div style={{display:"flex",gap:5,flexShrink:0}}>
          <button onClick={onBack} style={{background:"var(--bg3)",color:"var(--tx3)",padding:"5px 9px",borderRadius:5,fontSize:11,border:"1px solid var(--bd)",cursor:"pointer"}}>← Exit</button>
          {si>0&&status!=="coach"&&status!=="ticket_review"&&status!=="mode_select"&&(
            <button onClick={handleBack} style={{background:"var(--bg3)",color:"var(--ac)",padding:"5px 9px",borderRadius:5,fontSize:11,border:"1px solid var(--acb)",cursor:"pointer"}}>↩ Prev Step</button>
          )}
        </div>
        <div style={{flex:1,overflow:"hidden",marginLeft:4}}>
          <div style={{fontSize:10,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:1}}>{inc.id} · P1-Critical</div>
          <div style={{fontSize:13,fontWeight:700,color:"var(--tx)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{inc.title}</div>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flexShrink:0}}>
          <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:5,padding:"3px 9px",fontSize:10.5,fontFamily:"var(--mo)",color:"var(--tx2)",fontWeight:600}}>{mm}:{ss2}</div>
          <div style={{background:"var(--bg3)",border:"1px solid var(--bd)",borderRadius:5,padding:"3px 9px",fontSize:10.5,fontFamily:"var(--mo)",color:"var(--ac)",fontWeight:600}}>Step {si+1}/{inc.steps.length}</div>
          <div style={{background:contained?"var(--okl)":"var(--errl)",border:"1px solid "+(contained?"var(--okb)":"var(--errb)"),borderRadius:5,padding:"3px 9px",fontSize:10.5,fontFamily:"var(--mo)",fontWeight:600,color:contained?"var(--ok)":"var(--err)"}}>
            {contained?"CONTAINED":"SIMULATED THREAT"}
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
        {[["📧","Email","support.learnblueteam@gmail.com"],["🌐","Website","learnblueteam.cloud"],["📍","Based in","Mumbai, India"]].map(([ic,l,v])=>(
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
    ["Acceptance","By using learnblueteam.cloud you agree to these Terms. If you disagree, please do not use the platform."],
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
      <div style={{fontSize:12,color:"var(--tx4)",fontFamily:"var(--mo)",marginBottom:28}}>Updated May 2026 · learnblueteam.cloud</div>
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


function Landing({nav=()=>{},appUser=null}) {
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
          🎉 Beta — All 10 Investigations Free
        </div>
        {/* Headline */}
        <h1 style={{fontSize:"clamp(26px,5vw,54px)",fontWeight:800,lineHeight:1.1,letterSpacing:"-0.03em",marginBottom:14,color:"#111318",position:"relative",zIndex:1}}>
          Become an<br/>
          <span style={{color:"#1a56db"}}>{typed}</span>
          <span style={{display:"inline-block",width:2,height:"0.85em",background:"#1a56db",borderRadius:1,verticalAlign:"text-bottom",marginLeft:2,animation:"blink 1s infinite"}}/>
        </h1>
        <p style={{fontSize:"clamp(14px,3vw,17px)",color:"#5a6272",lineHeight:1.75,maxWidth:520,margin:"0 auto 28px",position:"relative",zIndex:1}}>
          Step inside a real SOC. Investigate live security incidents using the same tools, alerts, and decisions that professional analysts use every day.<br/>
          <strong style={{color:"#111318"}}>No experience needed. No software to install. Start your first investigation in 30 seconds.</strong>
        </p>
        {/* CTAs */}
        <div style={{display:"flex",gap:10,justifyContent:"center",flexWrap:"wrap",position:"relative",zIndex:1,width:"100%",maxWidth:400}}>
          {appUser
            ?<button onClick={()=>nav("dash")} style={{flex:1,background:"#1a56db",color:"#fff",fontSize:14,fontWeight:700,padding:"13px 20px",borderRadius:10,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)",minWidth:160}}>Go to Dashboard</button>
            :<button onClick={()=>nav("signup")} style={{flex:1,background:"#1a56db",color:"#fff",fontSize:14,fontWeight:700,padding:"13px 20px",borderRadius:10,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)",minWidth:160}}>Start Free Investigation</button>
          }
          <button onClick={()=>nav("sim-phishing-c2")} style={{flex:1,background:"#fff",color:"#1a56db",fontSize:14,fontWeight:600,padding:"13px 20px",borderRadius:10,border:"1px solid #bfdbfe",cursor:"pointer",boxShadow:"0 1px 3px rgba(17,19,24,0.06)",minWidth:160}}>Try First Scenario →</button>
        </div>
        {/* Live challenge */}
        <div style={{marginTop:24,maxWidth:480,width:"100%",position:"relative",zIndex:1}}>
          <div style={{background:"#0f1117",borderRadius:12,padding:"16px",border:"1px solid rgba(220,38,38,0.35)"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
              <div style={{width:7,height:7,borderRadius:"50%",background:"#dc2626",animation:"pulse 1.5s infinite",flexShrink:0}}/>
              <span style={{fontSize:9,fontWeight:700,color:"#f87171",fontFamily:"var(--mo)"}}>SIMULATED SCENARIO · INC-2026-0441 · TRAINING</span>
            </div>
            <div style={{fontSize:12.5,color:"#e8ecf4",lineHeight:1.75,marginBottom:10}}>Finance analyst opened an invoice at 08:17. SIEM fired 4 rules. EDR shows WINWORD.EXE spawning cmd.exe. Active beacon to Russia.</div>
            <div style={{fontSize:11,color:"#9ca3af",marginBottom:12}}>Is this a real attack or a false positive?</div>
            <button onClick={()=>nav("sim-phishing-c2")} style={{width:"100%",background:"#dc2626",color:"#fff",padding:"11px",borderRadius:8,fontSize:13,fontWeight:700,border:"none",cursor:"pointer"}}>Investigate This Incident</button>
          </div>
        </div>
        {/* Disclaimer */}
        <div style={{marginTop:14,fontSize:10,color:"#8892a4",position:"relative",zIndex:1,maxWidth:480}}>
          ⚠ All scenarios, users, domains, and alerts are fictional and created for educational purposes only.
        </div>
      </div>

      {/* ── LIVE SOC PREVIEW — Spline 3D placeholder ── */}
      <div style={{background:"#111318",padding:"0",position:"relative",overflow:"hidden",borderTop:"1px solid #1f2937",borderBottom:"1px solid #1f2937"}}>
        {/* Spline embed goes here — replace src with your Spline scene URL */}
        {/* <iframe src="https://my.spline.design/YOUR-SCENE-ID/" frameBorder="0" width="100%" height="400px" style={{display:"block"}}/> */}
        {/* Placeholder until Spline scene is ready */}
        <div style={{padding:"28px 20px",maxWidth:900,margin:"0 auto"}}>
          <div style={{textAlign:"center",marginBottom:20}}>
            <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#3b82f6",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>SOC Operations Center</div>
            <div style={{fontSize:"clamp(16px,4vw,22px)",fontWeight:700,color:"#f9fafb",lineHeight:1.3}}>What a real investigation looks like</div>
          </div>
          {/* Mini SOC console preview */}
          <div style={{background:"#1f2937",border:"1px solid #374151",borderRadius:10,overflow:"hidden",boxShadow:"0 20px 60px rgba(0,0,0,0.5)"}}>
            <div style={{background:"#111827",borderBottom:"1px solid #374151",padding:"7px 12px",display:"flex",alignItems:"center",gap:6}}>
              {["#ef4444","#fbbf24","#22c55e"].map(c=><div key={c} style={{width:9,height:9,borderRadius:"50%",background:c}}/>)}
              <span style={{fontSize:10,color:"#6b7280",fontFamily:"var(--mo)",marginLeft:6}}>BlueTrace SIEM — INC-2026-0441 — P1 Critical</span>
              <div style={{flex:1}}/>
              <div style={{display:"flex",alignItems:"center",gap:5}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:"#dc2626",animation:"pulse 1.5s infinite"}}/>
                <span style={{fontSize:9,color:"#dc2626",fontFamily:"var(--mo)",fontWeight:700}}>SIMULATED</span>
              </div>
            </div>
            <div style={{padding:"12px",display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {/* Alert summary */}
              <div style={{background:"rgba(220,38,38,0.08)",border:"1px solid rgba(220,38,38,0.25)",borderRadius:7,padding:"10px"}}>
                <div style={{fontSize:8.5,fontWeight:700,color:"#6b7280",fontFamily:"var(--mo)",marginBottom:8,letterSpacing:"0.1em",textTransform:"uppercase"}}>Active Alerts</div>
                {[["OUTBOUND_C2_BEACON","Critical","97"],["LSASS_MEMORY_ACCESS","Critical","99"],["ENCODED_POWERSHELL","High","85"]].map(([rule,sev,score])=>(
                  <div key={rule} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"5px 0",borderBottom:"1px solid rgba(255,255,255,0.05)"}}>
                    <div>
                      <div style={{fontSize:9.5,color:"#f9fafb",fontFamily:"var(--mo)",fontWeight:600}}>{sev==="Critical"?"🔴":"🟠"} {rule}</div>
                    </div>
                    <div style={{fontSize:9,fontWeight:700,color:sev==="Critical"?"#fca5a5":"#fdba74",fontFamily:"var(--mo)"}}>{score}</div>
                  </div>
                ))}
              </div>
              {/* Process tree preview */}
              <div style={{background:"rgba(0,0,0,0.3)",border:"1px solid #374151",borderRadius:7,padding:"10px"}}>
                <div style={{fontSize:8.5,fontWeight:700,color:"#6b7280",fontFamily:"var(--mo)",marginBottom:8,letterSpacing:"0.1em",textTransform:"uppercase"}}>Process Tree</div>
                {[["OUTLOOK.EXE","",false],["└─ WINWORD.EXE","  ",false],["  └─ cmd.exe","    ",true],["    └─ powershell.exe","      ",true],["      └─ svchost32.exe","        ",true]].map(([proc,indent,bad],i)=>(
                  <div key={i} style={{fontSize:9.5,fontFamily:"var(--mo)",color:bad?"#fca5a5":"#9ca3af",padding:"2px 0",letterSpacing:0}}>{proc}{bad&&<span style={{fontSize:8,background:"rgba(220,38,38,0.2)",color:"#fca5a5",padding:"0 4px",borderRadius:2,marginLeft:4}}>MALICIOUS</span>}</div>
                ))}
              </div>
            </div>
          </div>
          <div style={{textAlign:"center",marginTop:16}}>
            <button onClick={()=>nav("sim-phishing-c2")} style={{background:"#3b82f6",color:"#fff",fontSize:14,fontWeight:700,padding:"12px 28px",borderRadius:8,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(59,130,246,0.4)"}}>
              Investigate This Incident →
            </button>
          </div>
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
            {id:"phishing-c2",icon:"🎣",title:"Spear-Phishing to C2 Beacon",diff:"Beginner",time:"25 min",xp:120,tags:["Phishing","C2","EDR"],desc:"Finance analyst opened a macro-enabled document. EDR detected C2 beacon. LSASS dump in progress. Investigate and contain.",free:true,type:"TP"},
            {id:"fp-powershell",icon:"🔍",title:"IT Admin PowerShell — False Positive?",diff:"Beginner",time:"20 min",xp:80,tags:["PowerShell","False Positive","Triage"],desc:"Encoded PowerShell at 02:30. Service account. Overnight timing. Real threat or authorized maintenance? You decide.",free:true,type:"FP"},
            {id:"impossible-travel",icon:"🌍",title:"Impossible Travel — Account Takeover",diff:"Beginner",time:"30 min",xp:150,tags:["Identity","MFA Fatigue","Azure AD"],desc:"Login from Mumbai and Amsterdam 4 minutes apart. 47 MFA pushes. One approved. Attacker live in the account right now.",free:true,type:"TP"},
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
      {/* ── WHAT YOU'LL BE ABLE TO DO ── */}
      <div style={{padding:"48px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Learning Outcomes</div>
          <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#111318",marginBottom:6}}>What You'll Be Able To Do</h2>
          <p style={{fontSize:14,color:"#5a6272",maxWidth:440,margin:"0 auto"}}>Skills you develop through real investigations — not theory.</p>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",gap:10,maxWidth:900,margin:"0 auto"}}>
          {[
            {icon:"🎣",skill:"Investigate Phishing",desc:"Trace macro docs through process trees to C2 beacons",level:"Beginner"},
            {icon:"🔍",skill:"Identify False Positives",desc:"Tell IT maintenance from real attacks — context matters",level:"Beginner"},
            {icon:"🌍",skill:"Investigate Identity Attacks",desc:"Detect MFA fatigue, impossible travel, account takeovers",level:"Beginner"},
            {icon:"🧠",skill:"Think Like an Analyst",desc:"Form hypotheses from evidence before jumping to conclusions",level:"Beginner"},
            {icon:"📊",skill:"Use SIEM Effectively",desc:"Read correlated alerts, run searches, build timelines",level:"Beginner"},
            {icon:"🖥","skill":"Investigate Endpoints",desc:"Read EDR process trees, network logs, and file events",level:"Beginner"},
            {icon:"🔬",skill:"Validate Threat Intelligence",desc:"Look up IPs, hashes, domains — evidence before verdict",level:"Intermediate"},
            {icon:"📧",skill:"Analyse Email Threats",desc:"Detect BEC, lookalike domains, header manipulation",level:"Intermediate"},
            {icon:"☁️",skill:"Respond to Cloud Incidents",desc:"Investigate exposed S3 buckets, IAM abuse, key exposure",level:"Intermediate"},
            {icon:"🔒",skill:"Contain Active Threats",desc:"Isolate endpoints, block IOCs, revoke sessions",level:"Intermediate"},
            {icon:"📋",skill:"Write IR Reports",desc:"Document root cause, blast radius, and recommendations",level:"All levels"},
            {icon:"⚡",skill:"Work Under SLA Pressure",desc:"Triage P1 incidents, document findings, close within SLA",level:"All levels"},
          ].map(item=>(
            <div key={item.skill} style={{background:"#f7f8fa",border:"1px solid #e1e4ed",borderRadius:12,padding:"16px",display:"flex",flexDirection:"column",gap:6}}>
              <div style={{fontSize:24}}>{item.icon}</div>
              <div style={{fontSize:14,fontWeight:700,color:"#111318",lineHeight:1.3}}>{item.skill}</div>
              <div style={{fontSize:12.5,color:"#5a6272",lineHeight:1.6,flex:1}}>{item.desc}</div>
              <div style={{fontSize:10,fontWeight:600,color:item.level==="Beginner"?"#16a34a":item.level==="Intermediate"?"#d97706":"#6b7280",background:item.level==="Beginner"?"rgba(22,163,74,0.08)":item.level==="Intermediate"?"rgba(217,119,6,0.08)":"rgba(107,114,128,0.08)",padding:"2px 8px",borderRadius:4,alignSelf:"flex-start",fontFamily:"var(--mo)"}}>{item.level}</div>
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
      {/* PRICING — BETA */}
      <div style={{padding:"48px 20px",background:"#f7f8fa",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>Access</div>
          <h2 style={{fontSize:"clamp(20px,4vw,28px)",fontWeight:800,color:"#111318",marginBottom:8}}>Free During Beta</h2>
          <p style={{fontSize:14,color:"#5a6272",maxWidth:440,margin:"0 auto"}}>We are in open beta. Everything is free while we improve the platform based on your feedback.</p>
        </div>
        <div style={{maxWidth:420,margin:"0 auto"}}>
          <div style={{background:"#fff",border:"2px solid #1a56db",borderRadius:16,padding:"28px",boxShadow:"0 0 0 4px rgba(26,86,219,0.07)",position:"relative"}}>
            <div style={{position:"absolute",top:-14,left:"50%",transform:"translateX(-50%)",background:"#1a56db",color:"#fff",padding:"3px 18px",borderRadius:100,fontSize:11,fontWeight:700,letterSpacing:"0.1em",fontFamily:"var(--mo)",whiteSpace:"nowrap"}}>BETA ACCESS</div>
            <div style={{textAlign:"center",marginBottom:20}}>
              <div style={{fontSize:48,fontWeight:800,color:"#111318",fontFamily:"var(--mo)",lineHeight:1}}>₹0</div>
              <div style={{fontSize:13,color:"#6b7280",marginTop:4}}>No credit card · No commitment</div>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:22}}>
              {["All 10 SOC Investigations","Investigation Zero (Beginner intro)","Beginner Mode + Analyst Mode","Socratic Coach + Decision Engine","XP + Level progression","Future beta updates included"].map(f=>(
                <div key={f} style={{display:"flex",gap:10,alignItems:"center"}}>
                  <span style={{color:"#1a56db",fontWeight:700,fontSize:16,flexShrink:0}}>✓</span>
                  <span style={{fontSize:13.5,color:"#111318",fontWeight:500}}>{f}</span>
                </div>
              ))}
            </div>
            <button onClick={()=>nav("signup")} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:700,border:"none",cursor:"pointer",boxShadow:"0 4px 14px rgba(26,86,219,0.3)"}}>
              Start Free — No Signup Required
            </button>
            <div style={{textAlign:"center",marginTop:10,fontSize:12,color:"#9ca3af"}}>
              Paid plans will be introduced after beta. Early users get discounted rates.
            </div>
          </div>
          <div style={{background:"#fff",border:"1px solid #e1e4ed",borderRadius:12,padding:"20px",marginTop:14}}>
            <div style={{fontSize:12,fontWeight:700,color:"#374151",marginBottom:12}}>Coming After Beta:</div>
            {[["🏆","SOC Analyst L1 Certificate","After completing all 10 investigations"],["💼","Pro Plan","Advanced scenarios + IR + Threat Hunting"],["🎯","Team Access","For bootcamps and training programs"]].map(([ic,t,d])=>(
              <div key={t} style={{display:"flex",gap:10,alignItems:"flex-start",marginBottom:10}}>
                <span style={{fontSize:18,flexShrink:0}}>{ic}</span>
                <div>
                  <div style={{fontSize:13,fontWeight:600,color:"#374151"}}>{t}</div>
                  <div style={{fontSize:11.5,color:"#9ca3af"}}>{d}</div>
                </div>
                <span style={{marginLeft:"auto",fontSize:9,fontWeight:700,color:"#6b7280",background:"#f3f4f6",padding:"2px 7px",borderRadius:4,fontFamily:"var(--mo)",flexShrink:0}}>SOON</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      {/* ── VS COMPETITION ── */}
      <div style={{padding:"40px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}>
        <div style={{maxWidth:860,margin:"0 auto"}}>
          <div style={{textAlign:"center",marginBottom:20}}>
            <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>Why Us</div>
            <h2 style={{fontSize:"clamp(18px,4vw,26px)",fontWeight:800,color:"#111318"}}>Built Different From Everything Else</h2>
          </div>
          <div style={{overflowX:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:13,minWidth:500}}>
              <thead><tr>{[["Feature","#374151"],["LearnThreatOps","#1a56db"],["TryHackMe","#374151"],["LetsDefend","#374151"],["Cybrary","#374151"]].map(([h,c],i)=>(<th key={h} style={{padding:"10px 14px",textAlign:"left",fontWeight:700,color:c,borderBottom:"2px solid "+(i===1?"#1a56db":"#e1e4ed"),fontSize:12,background:i===1?"rgba(26,86,219,0.03)":"#f7f8fa"}}>{h}</th>))}</tr></thead>
              <tbody>{[["100% Blue Team","YES","Red team","Partial","No"],["Real SIEM+EDR","YES","No","Basic","Video only"],["False Positive 40%","YES","No","No","No"],["Free no card","YES","Yes","Yes","No"],["India context","YES","No","No","No"]].map((row,i)=>(<tr key={i} style={{borderBottom:"1px solid #e1e4ed",background:i%2===0?"#fff":"#fafafa"}}>{row.map((cell,j)=>(<td key={j} style={{padding:"10px 14px",color:j===0?"#374151":j===1?"#16a34a":"#6b7280",fontWeight:j===1?700:400,background:j===1?"rgba(26,86,219,0.03)":"transparent"}}>{cell}</td>))}</tr>))}</tbody>
            </table>
          </div>
        </div>
      </div>
      {/* ── CAREER ── */}
      <div style={{padding:"48px 20px",background:"#111318"}}>
        <div style={{maxWidth:760,margin:"0 auto",textAlign:"center"}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#3b82f6",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>For Your Career</div>
          <h2 style={{fontSize:"clamp(18px,4vw,26px)",fontWeight:800,color:"#f9fafb",marginBottom:8}}>The Skill Gap Costing You the Job</h2>
          <p style={{fontSize:14,color:"#6b7280",lineHeight:1.8,maxWidth:500,margin:"0 auto 28px"}}>Every cybersecurity job asks for hands-on experience. Every fresher has certificates and zero real experience. LearnThreatOps closes that gap.</p>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(190px,1fr))",gap:12,marginBottom:28}}>{[{s:"4.7M",l:"unfilled cyber jobs",c:"#3b82f6"},{s:"60%",l:"of SOC work is alert triage",c:"#22c55e"},{s:"0",l:"platforms teaching real blue team",c:"#ef4444"}].map(x=>(<div key={x.s} style={{background:"#1a1f2e",border:"1px solid #1f2937",borderRadius:10,padding:"18px",textAlign:"center"}}><div style={{fontSize:30,fontWeight:800,color:x.c,fontFamily:"var(--mo)",marginBottom:4}}>{x.s}</div><div style={{fontSize:12,color:"#6b7280",lineHeight:1.5}}>{x.l}</div></div>))}</div>
          <button onClick={()=>nav("signup")} style={{background:"#1a56db",color:"#fff",padding:"13px 32px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer"}}>Start Building Real Experience</button>
        </div>
      </div>

    </div>
  );
}

function FeedbackButton({submitFeedback}) {
  const [open,setOpen]=useState(false);
  const [rating,setRating]=useState(0);
  const [comment,setComment]=useState("");
  const [done,setDone]=useState(false);
  const submit=async()=>{
    if(submitFeedback) await submitFeedback("general",rating,"","",comment);
    setDone(true);
    setTimeout(()=>{setOpen(false);setDone(false);setRating(0);setComment("");},2000);
  };
  return(<>
    <button onClick={()=>setOpen(o=>!o)} style={{position:"fixed",bottom:20,right:20,zIndex:300,background:"#1a56db",color:"#fff",border:"none",borderRadius:50,padding:"10px 16px",fontSize:13,fontWeight:700,cursor:"pointer",boxShadow:"0 4px 16px rgba(26,86,219,0.4)",display:"flex",alignItems:"center",gap:6}}>
      💬 Feedback
    </button>
    {open&&(
      <div style={{position:"fixed",bottom:70,right:20,zIndex:301,background:"#fff",border:"1px solid #e1e4ed",borderRadius:14,padding:18,width:280,boxShadow:"0 8px 32px rgba(0,0,0,0.15)"}}>
        {done?(<div style={{textAlign:"center",padding:"12px 0"}}><div style={{fontSize:28,marginBottom:6}}>🙏</div><div style={{fontSize:13,fontWeight:700,color:"#111318"}}>Thank you!</div></div>):(
          <>
            <div style={{fontSize:13,fontWeight:700,color:"#111318",marginBottom:10}}>How is LearnThreatOps?</div>
            <div style={{display:"flex",gap:4,marginBottom:10}}>
              {[1,2,3,4,5].map(s=><button key={s} onClick={()=>setRating(s)} style={{fontSize:20,background:"none",border:"none",cursor:"pointer",opacity:s<=rating?1:0.3}}>⭐</button>)}
            </div>
            <textarea value={comment} onChange={e=>setComment(e.target.value)} placeholder="Any thoughts?" style={{width:"100%",height:60,padding:8,border:"1px solid #e1e4ed",borderRadius:7,fontSize:12,fontFamily:"inherit",resize:"none",outline:"none",marginBottom:8}}/>
            <div style={{display:"flex",gap:6}}>
              <button onClick={()=>setOpen(false)} style={{flex:1,padding:"7px",borderRadius:6,border:"1px solid #e1e4ed",background:"#f7f8fa",color:"#6b7280",fontSize:12,cursor:"pointer"}}>Cancel</button>
              <button onClick={submit} disabled={rating===0} style={{flex:2,padding:"7px",borderRadius:6,border:"none",background:rating>0?"#1a56db":"#e1e4ed",color:rating>0?"#fff":"#9ca3af",fontSize:12,fontWeight:600,cursor:rating>0?"pointer":"default"}}>Send</button>
            </div>
          </>
        )}
      </div>
    )}
  </>);
}

// ── dashboard ─────────────────────────────────────────────────────────────────
function Dashboard({nav,appUser={name:"Analyst"},prog={xp:0,level:1,done:{}},lvlPct=()=>0,invZeroDone=false,logout=()=>{}}) {
  const allSims=Object.values(SCENARIOS);
  const FREE_SIMS=Object.keys(SCENARIOS); // Beta: all free
  const [showUpgrade,setShowUpgrade]=useState(false);
  return (
    <div style={{padding:"20px"}}>
      <div style={{background:"linear-gradient(135deg,#1a56db,#7c3aed)",borderRadius:12,padding:"12px 16px",marginBottom:20,display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}><span style={{fontSize:18}}>{"🎉"}</span><div style={{flex:1}}><div style={{fontSize:13,fontWeight:700,color:"#fff"}}>Beta — All 10 Investigations Free</div><div style={{fontSize:11,color:"rgba(255,255,255,0.75)"}}>No credit card. No catch. Full access during beta.</div></div></div>
      {/* Beta free banner */}
      <div style={{background:"linear-gradient(135deg,#1a56db,#7c3aed)",borderRadius:12,padding:"12px 16px",marginBottom:20,display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
        <span style={{fontSize:18}}>🎉</span>
        <div style={{flex:1,minWidth:200}}>
          <div style={{fontSize:13,fontWeight:700,color:"#fff"}}>Beta — All 10 Investigations Free</div>
          <div style={{fontSize:11,color:"rgba(255,255,255,0.75)"}}>No credit card. No catch. Full access while we are in beta.</div>
        </div>
        <div style={{fontSize:10,fontWeight:700,color:"rgba(255,255,255,0.6)",fontFamily:"var(--mo)",letterSpacing:"0.08em",textTransform:"uppercase",flexShrink:0}}>Limited Time</div>
      </div>
      {showUpgrade&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",zIndex:500,display:"flex",alignItems:"center",justifyContent:"center",padding:20}} onClick={()=>setShowUpgrade(false)}>
          <div style={{background:"#fff",borderRadius:16,maxWidth:420,width:"100%",overflow:"hidden"}} onClick={e=>e.stopPropagation()}>
            <div style={{background:"linear-gradient(135deg,#1a56db,#7c3aed)",padding:"22px",textAlign:"center"}}>
              <div style={{fontSize:28,marginBottom:6}}>{"🔒"}</div>
              <div style={{fontSize:18,fontWeight:800,color:"#fff",marginBottom:4}}>Pro Investigations</div>
              <div style={{fontSize:13,color:"rgba(255,255,255,0.8)"}}>Unlock 7 more real-world SOC incidents</div>
            </div>
            <div style={{padding:"20px 24px"}}>
              {["Malicious USB — Insider Threat","DNS Beaconing C2","Business Email Compromise","AWS S3 Exposure","Auth Failure Storm","Pentest FP","More added monthly"].map((item,i)=>(<div key={i} style={{display:"flex",gap:8,marginBottom:6}}><span style={{color:"#1a56db",fontWeight:700}}>{"✓"}</span><span style={{fontSize:13,color:"#374151"}}>{item}</span></div>))}
              <div style={{background:"#eff6ff",borderRadius:10,padding:"12px",margin:"14px 0",textAlign:"center",border:"1px solid #bfdbfe"}}>
                <div style={{fontSize:26,fontWeight:800,color:"#1a56db",fontFamily:"var(--mo)"}}>{"₹499/month"}</div>
                <div style={{fontSize:12,color:"#6b7280"}}>30-day money-back guarantee</div>
              </div>
              <button onClick={()=>window.open("mailto:support.learnthreatops@gmail.com?subject=Early Pro Access - LearnThreatOps","_blank")} style={{width:"100%",background:"#1a56db",color:"#fff",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer",marginBottom:8}}>Join Pro Waitlist →</button>
              <button onClick={()=>setShowUpgrade(false)} style={{width:"100%",background:"#f7f8fa",color:"#6b7280",padding:"10px",borderRadius:9,border:"1px solid #e1e4ed",fontSize:13,cursor:"pointer"}}>Continue free</button>
            </div>
          </div>
        </div>
      )}
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
            <div key={s.id} onClick={()=>nav("sim-"+s.id)}
              style={{background:"var(--w)",border:"1px solid "+(s.id==="phishing-c2"&&!Object.keys(prog.done).length?"#1a56db":"var(--bd)"),borderRadius:14,padding:"18px",cursor:"pointer",boxShadow:s.id==="phishing-c2"&&!Object.keys(prog.done).length?"0 0 0 3px rgba(26,86,219,0.15), var(--sh)":"var(--sh)",position:"relative",transition:"all 0.15s"}}>
              {s.id==="phishing-c2"&&!Object.keys(prog.done).length&&(
                <div style={{position:"absolute",top:-10,left:16,background:"#1a56db",color:"#fff",fontSize:9,fontWeight:700,padding:"2px 10px",borderRadius:20,fontFamily:"var(--mo)",letterSpacing:"0.08em",textTransform:"uppercase"}}>Start Here</div>
              )}
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
function AuthPage({nav,mode,login=()=>({}),signup=()=>({}),authError=null,loading:authLoading=false}) {
  const [form,setForm]=useState({name:"",email:"",password:""});
  const [err,setErr]=useState("");
  const handle=async(e)=>{
    e.preventDefault();
    if(mode==="signup"&&!form.name.trim()){setErr("Name is required");return;}
    if(!form.email.includes("@")){setErr("Enter a valid email");return;}
    if(form.password.length<6){setErr("Password must be 6+ characters");return;}
    setErr(null);
    if(mode==="signup"){
      const res=await signup(form.name,form.email,form.password);
      if(res?.success){
        if(res?.needsConfirm){
          setErr("✅ Account created! Check your email to confirm, then come back and log in.");
        } else {
          nav("dash");
        }
      } else setErr(res?.error||"Signup failed. Please try again.");
    } else {
      const res=await login(form.email,form.password);
      if(res?.success)nav("dash");
      else setErr(res?.error||"Invalid email or password.");
    }
  };
  const inp={width:"100%",padding:"13px",border:"1px solid var(--bd)",borderRadius:10,fontSize:15,fontFamily:"var(--fn)",outline:"none",background:"var(--w)",color:"var(--tx)"};
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
            {mode==="signup"&&(
              <div style={{fontSize:11,color:"#6b7280",lineHeight:1.7,marginBottom:8,padding:"8px 10px",background:"#f7f8fa",borderRadius:7,border:"1px solid #e1e4ed"}}>
                By creating an account you agree to our{" "}
                <span onClick={()=>nav("terms")} style={{color:"var(--ac)",cursor:"pointer",textDecoration:"underline"}}>Terms of Service</span>
                {" "}and{" "}
                <span onClick={()=>nav("privacy")} style={{color:"var(--ac)",cursor:"pointer",textDecoration:"underline"}}>Privacy Policy</span>.
                {" "}We collect your name, email, and usage data under DPDPA 2023.
              </div>
            )}
            <button type="submit" disabled={authLoading} style={{width:"100%",background:"var(--ac)",color:"#fff",padding:"14px",borderRadius:10,fontSize:15,fontWeight:600,border:"none",cursor:"pointer",opacity:authLoading?0.7:1,boxShadow:"0 4px 14px rgba(26,86,219,0.3)"}}>
              {authLoading?"Loading...":mode==="login"?"Login →":"Create Account — Free →"}
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
  const {user,prog,loading,authError,signup,login,logout,addXP,finishSim,submitFeedback,lvlPct}=useSupabase();
  const [invZeroDone,setInvZeroDone]=useState(()=>{try{return!!localStorage.getItem("lbt_iz_done");}catch{return false;}});
  const completeInvZero=()=>{try{localStorage.setItem("lbt_iz_done","1");}catch{}setInvZeroDone(true);nav("dash");};
  const SCENARIO_TO_INC={"phishing-c2":"INC-2026-0441","fp-powershell":"INC-2026-0502","impossible-travel":"INC-2026-0521","fp-vuln-scan":"INC-2026-0544","usb-insider":"INC-2026-0561","dns-beacon":"INC-2026-0578","fp-pentest":"INC-2026-0591","bec-fraud":"INC-2026-0612","s3-exposure":"INC-2026-0634","fp-auth-storm":"INC-2026-0651"};
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
              <><button onClick={()=>{logout&&logout();nav("landing");}} style={{background:"none",border:"1px solid var(--bd)",color:"var(--tx3)",fontSize:12,padding:"6px 10px",borderRadius:7,cursor:"pointer"}}>Logout</button>
              <button onClick={()=>nav("dash")} style={{display:"flex",alignItems:"center",gap:6,background:"var(--bg2)",border:"1px solid var(--bd)",borderRadius:8,padding:"7px 12px",cursor:"pointer"}}>
                <div style={{width:22,height:22,borderRadius:"50%",background:"var(--acl)",border:"1.5px solid var(--ac)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:"var(--ac)",fontFamily:"var(--mo)"}}>{prog.level}</div>
                <span style={{fontSize:13,color:"var(--tx2)",fontWeight:500}}>{user.name.split(" ")[0]}</span>
              </button></>
            ):(
              <button onClick={()=>nav("login")} style={{background:"none",border:"1px solid var(--bd)",color:"var(--tx2)",fontSize:13,fontWeight:500,padding:"7px 12px",borderRadius:8,cursor:"pointer"}}>Login</button>
            )}
            <button onClick={()=>nav("sim-phishing-c2")} style={{background:"var(--ac)",color:"#fff",fontSize:13,fontWeight:600,padding:"8px 14px",borderRadius:8,border:"none",cursor:"pointer",boxShadow:"0 2px 8px rgba(26,86,219,0.3)"}}>Open SOC</button>
          </div>
        </nav>
      )}
      {page==="inv-zero"     && <InvestigationZero onComplete={completeInvZero} addXP={addXP}/>}
      {page==="landing"      && <Landing nav={nav} appUser={user}/>}
      {page==="sim"          && <SOCConsole incId={simId} prog={prog} addXP={addXP} finishSim={finishSim} onBack={()=>nav("dash")} submitFeedback={submitFeedback} analyst={{name:user?.name||"Analyst",tier:"SOC Analyst I",id:"ANLST-"+(user?.email?.slice(0,3).toUpperCase()||"047"),team:"Threat Ops Alpha"}}/>}
      {page==="dash"         && (user?<Dashboard nav={nav} appUser={user} prog={prog} lvlPct={lvlPct} logout={logout} invZeroDone={invZeroDone}/>:<AuthPage nav={nav} mode="signup" saveUser={saveUser}/>)}
      {page==="login"        && <AuthPage nav={nav} mode="login" login={login} signup={signup} authError={authError} loading={loading}/>}
      {page==="signup"       && <AuthPage nav={nav} mode="signup" login={login} signup={signup} authError={authError} loading={loading}/>}
      {["privacy","terms","refund","ai-disclaimer","data-policy","rules"].includes(page) && <PolicyPage policyKey={page} nav={nav}/>}
      {page==="contact" && <ContactPage nav={nav}/>}
      <FeedbackButton submitFeedback={submitFeedback}/>
    </div>
  );
}      {/* ── VS COMPETITION ── */}
      <div style={{padding:"40px 20px",background:"#fff",borderBottom:"1px solid #e1e4ed"}}><div style={{maxWidth:860,margin:"0 auto"}}><div style={{textAlign:"center",marginBottom:20}}><div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#1a56db",fontFamily:"var(--mo)",marginBottom:6,textTransform:"uppercase"}}>Why Us</div><h2 style={{fontSize:"clamp(18px,4vw,26px)",fontWeight:800,color:"#111318"}}>Built Different</h2></div><div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13,minWidth:500}}><thead><tr>{[["Feature","#374151"],["LearnThreatOps","#1a56db"],["TryHackMe","#374151"],["LetsDefend","#374151"],["Cybrary","#374151"]].map(([h,c],i)=>(<th key={h} style={{padding:"10px 14px",textAlign:"left",fontWeight:700,color:c,borderBottom:"2px solid "+(i===1?"#1a56db":"#e1e4ed"),fontSize:12,background:i===1?"rgba(26,86,219,0.03)":"#f7f8fa"}}>{h}</th>))}</tr></thead><tbody>{[["100% Blue Team","YES","Red team focus","Partial","No"],["Real SIEM+EDR","YES","No real tools","Basic only","Video only"],["False Positive 40%","YES","No","No","No"],["Free no card","YES","Yes","Yes","No"],["India context","YES","No","No","No"]].map((row,i)=>(<tr key={i} style={{borderBottom:"1px solid #e1e4ed",background:i%2===0?"#fff":"#fafafa"}}>{row.map((cell,j)=>(<td key={j} style={{padding:"10px 14px",color:j===0?"#374151":j===1?"#16a34a":"#6b7280",fontWeight:j===1?700:400,background:j===1?"rgba(26,86,219,0.03)":"transparent"}}>{cell}</td>))}</tr>))}</tbody></table></div></div></div>
      {/* ── CAREER ── */}
      <div style={{padding:"48px 20px",background:"#111318"}}><div style={{maxWidth:760,margin:"0 auto",textAlign:"center"}}><div style={{fontSize:10,fontWeight:700,letterSpacing:"0.2em",color:"#3b82f6",fontFamily:"var(--mo)",marginBottom:8,textTransform:"uppercase"}}>For Your Career</div><h2 style={{fontSize:"clamp(18px,4vw,26px)",fontWeight:800,color:"#f9fafb",marginBottom:8}}>The Skill Gap Costing You the Job</h2><p style={{fontSize:14,color:"#6b7280",lineHeight:1.8,maxWidth:500,margin:"0 auto 28px"}}>Every cybersecurity job asks for hands-on experience. Every fresher has certificates and zero real experience. LearnThreatOps closes that gap.</p><div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(190px,1fr))",gap:12,marginBottom:28}}>{[{s:"4.7M",l:"unfilled cyber jobs",c:"#3b82f6"},{s:"60%",l:"of SOC work is alert triage",c:"#22c55e"},{s:"0",l:"platforms teaching real blue team",c:"#ef4444"}].map(x=>(<div key={x.s} style={{background:"#1a1f2e",border:"1px solid #1f2937",borderRadius:10,padding:"18px",textAlign:"center"}}><div style={{fontSize:30,fontWeight:800,color:x.c,fontFamily:"var(--mo)",marginBottom:4}}>{x.s}</div><div style={{fontSize:12,color:"#6b7280",lineHeight:1.5}}>{x.l}</div></div>))}</div><button onClick={()=>nav("signup")} style={{background:"#1a56db",color:"#fff",padding:"13px 32px",borderRadius:10,fontSize:14,fontWeight:700,border:"none",cursor:"pointer"}}>Start Building Real Experience</button></div></div>

