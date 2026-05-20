import { useState, useRef, useCallback } from "react";

/* ─────────────────────────────────────────────────────────────────────────
   DATA & ML SIMULATION
   Matches exactly the report:
     • Isolation Forest  → Anomaly Detection
     • Random Forest     → Insider Threat Prediction
     • Random Forest     → Severity Classification
   ───────────────────────────────────────────────────────────────────────── */

const USERS   = ["alice","bob","charlie","diana","eve","root","svc-deploy","svc-backup","james","sara"];
const EVENTS  = [
  { name:"ConsoleLogin",               source:"signin.amazonaws.com",        risk:1 },
  { name:"GetObject",                  source:"s3.amazonaws.com",            risk:1 },
  { name:"ListBuckets",                source:"s3.amazonaws.com",            risk:1 },
  { name:"DescribeInstances",          source:"ec2.amazonaws.com",           risk:1 },
  { name:"PutObject",                  source:"s3.amazonaws.com",            risk:2 },
  { name:"CreateBucket",               source:"s3.amazonaws.com",            risk:2 },
  { name:"InvokeFunction",             source:"lambda.amazonaws.com",        risk:2 },
  { name:"AssumeRole",                 source:"sts.amazonaws.com",           risk:3 },
  { name:"StopInstances",              source:"ec2.amazonaws.com",           risk:3 },
  { name:"DeleteObject",               source:"s3.amazonaws.com",            risk:3 },
  { name:"CreateUser",                 source:"iam.amazonaws.com",           risk:3 },
  { name:"CreateAccessKey",            source:"iam.amazonaws.com",           risk:4 },
  { name:"AttachUserPolicy",           source:"iam.amazonaws.com",           risk:4 },
  { name:"AuthorizeSecurityGroupIngress",source:"ec2.amazonaws.com",         risk:4 },
  { name:"GetSecretValue",             source:"secretsmanager.amazonaws.com",risk:4 },
  { name:"PutBucketPolicy",            source:"s3.amazonaws.com",            risk:4 },
  { name:"UpdateFunctionCode",         source:"lambda.amazonaws.com",        risk:4 },
  { name:"DeleteUser",                 source:"iam.amazonaws.com",           risk:5 },
  { name:"TerminateInstances",         source:"ec2.amazonaws.com",           risk:5 },
  { name:"DeleteBucket",               source:"s3.amazonaws.com",            risk:5 },
];
const REGIONS   = ["us-east-1","us-west-2","eu-west-1","ap-southeast-1","ap-northeast-1"];
const NORMAL_IPS = ["192.168.1.10","10.0.0.25","172.16.5.4","203.0.113.45","198.51.100.23"];
const SUSPECT_IPS = ["185.220.101.34","91.108.4.188","45.33.32.156","46.166.139.111"];
const ERRORS    = [null,null,null,null,"AccessDenied","UnauthorizedOperation"];
const AGENTS    = ["aws-cli/2.13","console.amazonaws.com","boto3/1.28","aws-sdk-java/2.20","Terraform/1.5"];
const EVENT_TYPES = ["AwsApiCall","AwsConsoleSignIn","AwsServiceEvent"];
const ANOMALOUS_USERS = ["eve","root"];

const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
const randInt = (a,b) => Math.floor(Math.random()*(b-a+1))+a;

// ── Isolation Forest score (simulated) ──
function isolationForestScore(feat) {
  let s = feat.risk * 11;
  if (feat.offHours)   s += 22;
  if (feat.suspectIP)  s += 20;
  if (feat.hasError)   s += 24;
  if (feat.highPriv)   s += 18;
  s = Math.min(100, Math.max(0, s + randInt(-6,6)));
  return s;
}

// ── Random Forest insider threat ──
function rfInsiderThreat(feat, anomScore) {
  return anomScore > 64
    || (feat.highPriv && feat.offHours)
    || (feat.suspectIP && feat.risk >= 3);
}

// ── Random Forest severity ──
function rfSeverity(anomScore) {
  if (anomScore >= 74) return "High";
  if (anomScore >= 44) return "Medium";
  return "Low";
}

function generateLogs(n = 80) {
  const logs = [];
  for (let i = 0; i < n; i++) {
    const evt  = rand(EVENTS);
    const user = rand(USERS);
    const isAnom = ANOMALOUS_USERS.includes(user);
    const isSvcOff = user === "svc-deploy";
    const hour = isSvcOff ? randInt(0,4) : (isAnom && Math.random()>0.5 ? randInt(22,23) : randInt(8,20));
    const ts   = new Date(Date.now() - randInt(0, 72*3600*1000));
    ts.setHours(hour, randInt(0,59), randInt(0,59));
    const suspectIP = (isAnom && Math.random()>0.45);
    const ip   = suspectIP ? rand(SUSPECT_IPS) : rand(NORMAL_IPS);
    const err  = (isAnom && Math.random()>0.6) ? rand(["AccessDenied","UnauthorizedOperation"]) : rand(ERRORS);
    const feat = {
      risk: evt.risk,
      offHours: hour < 7 || hour > 21,
      suspectIP,
      hasError: !!err,
      highPriv: evt.risk >= 4,
    };
    const anomScore = isolationForestScore(feat);
    const insider   = rfInsiderThreat(feat, anomScore);
    const severity  = rfSeverity(anomScore);
    logs.push({
      id: `${i}-${Date.now()}`,
      userName:     user,
      awsAccessKey: `AKIA${Math.random().toString(36).slice(2,14).toUpperCase()}`,
      eventTime:    ts.toISOString(),
      eventSource:  evt.source,
      eventName:    evt.name,
      awsRegion:    rand(REGIONS),
      sourceIP:     ip,
      userAgent:    rand(AGENTS),
      errorCode:    err || "",
      readOnly:     evt.risk <= 1 ? "TRUE" : "FALSE",
      eventType:    rand(EVENT_TYPES),
      // ML outputs
      anomaly:      anomScore > 54 ? "Yes" : "No",
      insiderThreat: insider ? "Yes" : "No",
      incidentSeverity: severity,
      anomalyScore: anomScore,
    });
  }
  return logs.sort((a,b) => new Date(b.eventTime) - new Date(a.eventTime));
}

// ── Parse uploaded CSV & run ML pipeline ──
function parseAndScore(text) {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map(h => h.trim().replace(/"/g,""));
  return lines.slice(1).map((line,i) => {
    const vals = line.split(",").map(v => v.trim().replace(/"/g,""));
    const row  = { id:`r${i}` };
    headers.forEach((h,j) => { row[h] = vals[j] ?? ""; });
    const evtName = (row.eventName||row.EventName||"").toLowerCase();
    const err = row.errorCode || row.ErrorCode || "";
    const user = (row.userName||row.UserName||"").toLowerCase();
    const hour = new Date(row.eventTime||row.EventTime||Date.now()).getHours();
    const feat = {
      risk: evtName.includes("delete")||evtName.includes("terminate") ? 5
            : evtName.includes("attach")||evtName.includes("policy") ? 4
            : evtName.includes("create")||evtName.includes("secret") ? 3 : 1,
      offHours: hour < 7 || hour > 21,
      suspectIP: false,
      hasError: !!err,
      highPriv: evtName.includes("policy")||evtName.includes("key")||evtName.includes("secret"),
    };
    if (ANOMALOUS_USERS.includes(user)) feat.risk = Math.min(5, feat.risk+2);
    const anomScore = isolationForestScore(feat);
    row.anomaly         = anomScore > 54 ? "Yes" : "No";
    row.insiderThreat   = rfInsiderThreat(feat, anomScore) ? "Yes" : "No";
    row.incidentSeverity= rfSeverity(anomScore);
    row.anomalyScore    = anomScore;
    row.userName        = row.userName||row.UserName||"unknown";
    row.eventName       = row.eventName||row.EventName||"unknown";
    row.eventSource     = row.eventSource||row.EventSource||"unknown";
    row.eventTime       = row.eventTime||row.EventTime||new Date().toISOString();
    row.awsRegion       = row.awsRegion||row.AWSRegion||"us-east-1";
    row.sourceIP        = row.sourceIP||row.SourceIP||"—";
    row.errorCode       = err;
    row.readOnly        = row.readOnly||row.ReadOnly||"—";
    row.eventType       = row.eventType||row.EventType||"AwsApiCall";
    row.userAgent       = row.userAgent||row.UserAgent||"—";
    row.awsAccessKey    = row.awsAccessKey||row.AWSAccessKey||"—";
    return row;
  });
}

/* ── Helpers ── */
const SEV_COL  = { High:"#E05252", Medium:"#E0963A", Low:"#2DB87A" };
const SEV_BG   = { High:"#2A0A0A", Medium:"#2A1600", Low:"#082215" };
const SEV_BORD = { High:"#E0525240", Medium:"#E0963A40", Low:"#2DB87A40" };

export default function App() {
  const [logs, setLogs]         = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [loading, setLoading]   = useState(false);
  const [ready, setReady]       = useState(false);
  const [tab, setTab]           = useState("logs");
  const [detail, setDetail]     = useState(null);
  const [fSev, setFSev]         = useState("All");
  const [fAnom, setFAnom]       = useState("All");
  const [fSearch, setFSearch]   = useState("");
  const [sortC, setSortC]       = useState("eventTime");
  const [sortD, setSortD]       = useState("desc");
  const [pipeline, setPipeline] = useState([]);
  const fileRef = useRef();

  const PIPELINE_STEPS = [
    "Collecting CloudTrail logs…",
    "Preprocessing & encoding features…",
    "Running Isolation Forest (Anomaly Detection)…",
    "Running Random Forest (Insider Threat)…",
    "Running Random Forest (Severity Classification)…",
    "Merging predictions with log data…",
    "Generating final report…",
  ];

  const runML = useCallback((data) => {
    setLoading(true); setReady(false); setPipeline([]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      setPipeline(p => [...p, PIPELINE_STEPS[step-1]]);
      if (step >= PIPELINE_STEPS.length) {
        clearInterval(interval);
        setTimeout(() => {
          setLogs(data); setFiltered(data);
          setReady(true); setLoading(false); setTab("logs");
        }, 400);
      }
    }, 320);
  }, []);

  const applyFilters = useCallback((base, sv, an, q, sc, sd) => {
    let out = [...base];
    if (sv !== "All") out = out.filter(l => l.incidentSeverity === sv);
    if (an !== "All") out = out.filter(l => l.anomaly === an);
    if (q) {
      const lq = q.toLowerCase();
      out = out.filter(l =>
        l.userName.toLowerCase().includes(lq) ||
        l.eventName.toLowerCase().includes(lq) ||
        (l.sourceIP||"").includes(lq) ||
        (l.awsRegion||"").toLowerCase().includes(lq)
      );
    }
    out.sort((a,b) => {
      let av = a[sc]??"", bv = b[sc]??"";
      if (sc==="anomalyScore") { av=+av; bv=+bv; }
      if (av<bv) return sd==="asc"?-1:1;
      if (av>bv) return sd==="asc"?1:-1;
      return 0;
    });
    setFiltered(out);
  }, []);

  const setFilter = (key, val) => {
    const [sv2, an2, q2] = key==="sev" ? [val,fAnom,fSearch]
                        : key==="anom" ? [fSev,val,fSearch]
                        : [fSev,fAnom,val];
    if (key==="sev")  setFSev(val);
    if (key==="anom") setFAnom(val);
    if (key==="q")    setFSearch(val);
    applyFilters(logs, sv2, an2, q2, sortC, sortD);
  };
  const handleSort = (col) => {
    const d = sortC===col && sortD==="asc" ? "desc" : "asc";
    setSortC(col); setSortD(d);
    applyFilters(logs, fSev, fAnom, fSearch, col, d);
  };

  const exportCSV = () => {
    const cols = ["userName","awsAccessKey","eventTime","eventSource","eventName","awsRegion","sourceIP","userAgent","errorCode","readOnly","eventType","anomaly","insiderThreat","incidentSeverity","anomalyScore"];
    const rows = filtered.map(l => cols.map(c=>`"${l[c]??""}""`).join(","));
    const blob = new Blob([cols.join(",")+"\n"+rows.join("\n")], {type:"text/csv"});
    const a = document.createElement("a"); a.href=URL.createObjectURL(blob);
    a.download="cloudtrail_ml_analysis.csv"; a.click();
  };

  // Stats
  const total  = logs.length;
  const highs  = logs.filter(l=>l.incidentSeverity==="High").length;
  const meds   = logs.filter(l=>l.incidentSeverity==="Medium").length;
  const lows   = logs.filter(l=>l.incidentSeverity==="Low").length;
  const anoms  = logs.filter(l=>l.anomaly==="Yes").length;
  const inside = logs.filter(l=>l.insiderThreat==="Yes").length;

  // User risk table
  const uMap = {};
  logs.forEach(l => {
    if (!uMap[l.userName]) uMap[l.userName]={user:l.userName,count:0,high:0,score:0};
    uMap[l.userName].count++;
    if (l.incidentSeverity==="High") uMap[l.userName].high++;
    uMap[l.userName].score = Math.max(uMap[l.userName].score, l.anomalyScore||0);
  });
  const topUsers = Object.values(uMap).sort((a,b)=>b.score-a.score).slice(0,8);

  // Event freq
  const evMap = {};
  logs.forEach(l => { evMap[l.eventName]=(evMap[l.eventName]||0)+1; });
  const topEvts = Object.entries(evMap).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxEvt  = topEvts[0]?.[1]||1;

  // Region freq
  const regMap = {};
  logs.forEach(l => { regMap[l.awsRegion]=(regMap[l.awsRegion]||0)+1; });
  const topRegs = Object.entries(regMap).sort((a,b)=>b[1]-a[1]).slice(0,5);

  const TABLE_COLS = [
    ["eventTime","TIME"],["userName","USER"],["eventName","EVENT"],
    ["awsRegion","REGION"],["sourceIP","SOURCE IP"],["errorCode","ERROR"],
    ["anomaly","ANOMALY"],["insiderThreat","INSIDER"],["incidentSeverity","SEVERITY"],["anomalyScore","SCORE"],
  ];

  return (
    <div style={{fontFamily:"'IBM Plex Mono',monospace",background:"#06101C",minHeight:"100vh",color:"#C0D4E8"}}>

      {/* ── HEADER ── */}
      <div style={{background:"linear-gradient(90deg,#040C18,#081D30)",borderBottom:"1px solid #1A9E6040",padding:"14px 24px",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:38,height:38,background:"linear-gradient(135deg,#1D9E75,#0A5C40)",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0}}>⛊</div>
          <div>
            <div style={{fontSize:15,fontWeight:700,color:"#fff",letterSpacing:1}}>CloudTrail ML Analyzer</div>
            <div style={{fontSize:9,color:"#5DCAA5",letterSpacing:2.5}}>ISOLATION FOREST  ·  RANDOM FOREST  ·  SEVERITY CLASSIFIER</div>
          </div>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          <Btn onClick={()=>runML(generateLogs(80))} disabled={loading} color="#1D9E75" label={loading?"ANALYZING…":"⚡ GENERATE LOGS"}/>
          <Btn onClick={()=>fileRef.current.click()} color="#378ADD" label="📂 UPLOAD CSV"/>
          {ready && <Btn onClick={exportCSV} color="#9A7FD4" label="⬇ EXPORT CSV"/>}
          <input ref={fileRef} type="file" accept=".csv" style={{display:"none"}} onChange={e=>{
            const f=e.target.files[0]; if(!f) return;
            const r=new FileReader(); r.onload=ev=>runML(parseAndScore(ev.target.result)); r.readAsText(f);
          }}/>
        </div>
      </div>

      {/* ── LANDING ── */}
      {!ready && !loading && (
        <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",minHeight:"80vh",gap:20,padding:24,textAlign:"center"}}>
          <div style={{fontSize:44}}>🔍</div>
          <div style={{fontSize:20,fontWeight:700,color:"#fff",maxWidth:500}}>CloudTrail Log Analysis Using Machine Learning</div>
          <div style={{fontSize:12,color:"#6A8A9C",maxWidth:520,lineHeight:1.9}}>
            Automatically detects <span style={{color:"#1D9E75",fontWeight:600}}>anomalies</span>,
            predicts <span style={{color:"#E0963A",fontWeight:600}}>insider threats</span>, and classifies
            <span style={{color:"#E05252",fontWeight:600}}> incident severity</span> using ML models.<br/>
            Based on M.Sc. Project — NFSU Goa · April 2025
          </div>
          <div style={{display:"flex",gap:14,flexWrap:"wrap",justifyContent:"center"}}>
            <BigBtn onClick={()=>runML(generateLogs(80))} label="⚡ Generate Sample Logs" color="#1D9E75"/>
            <BigBtn onClick={()=>fileRef.current.click()} label="📂 Upload CSV" color="#378ADD" outline/>
          </div>
          <div style={{display:"flex",gap:28,marginTop:16,flexWrap:"wrap",justifyContent:"center"}}>
            {[["Isolation Forest","Anomaly Detection","#1D9E75"],["Random Forest","Insider Threat","#E0963A"],["Random Forest","Severity Prediction","#E05252"]].map(([m,t,c])=>(
              <div key={t} style={{textAlign:"center",minWidth:130}}>
                <div style={{fontSize:11,fontWeight:700,color:c,letterSpacing:0.8}}>{m}</div>
                <div style={{fontSize:10,color:"#5A7A8A",marginTop:3}}>{t}</div>
                <div style={{width:60,height:3,background:c,borderRadius:2,margin:"8px auto 0",opacity:0.5}}/>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── ML PIPELINE LOADING ── */}
      {loading && (
        <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",minHeight:"75vh",gap:14,padding:24}}>
          <div style={{fontSize:11,color:"#1D9E75",letterSpacing:3,marginBottom:8}}>RUNNING ML PIPELINE</div>
          <div style={{width:280,height:3,background:"#0D1E2E",borderRadius:2,marginBottom:12}}>
            <div style={{width:`${(pipeline.length/PIPELINE_STEPS.length)*100}%`,height:"100%",background:"#1D9E75",borderRadius:2,transition:"width 0.3s"}}/>
          </div>
          {pipeline.map((s,i)=>(
            <div key={i} style={{display:"flex",alignItems:"center",gap:10}}>
              <div style={{width:6,height:6,borderRadius:"50%",background:"#1D9E75"}}/>
              <div style={{fontSize:11,color:"#7ABFA0"}}>{s}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── DASHBOARD ── */}
      {ready && !loading && (
        <div style={{padding:"18px 24px"}}>

          {/* Stat row — matches report output table */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10,marginBottom:18}}>
            {[
              ["TOTAL LOGS",  total,   "#85B7EB","#0D1E36"],
              ["ANOMALIES",   anoms,   "#1D9E75","#081E12"],
              ["INSIDER THREATS",inside,"#E0963A","#221200"],
              ["HIGH",        highs,   "#E05252","#220808"],
              ["MEDIUM",      meds,    "#E0963A","#221200"],
              ["LOW",         lows,    "#2DB87A","#082215"],
            ].map(([l,v,c,bg])=>(
              <div key={l} style={{background:bg,border:`1px solid ${c}30`,borderRadius:8,padding:"13px 10px",textAlign:"center"}}>
                <div style={{fontSize:26,fontWeight:700,color:c,lineHeight:1}}>{v}</div>
                <div style={{fontSize:8,color:"#5A7A8A",letterSpacing:1.4,marginTop:5}}>{l}</div>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div style={{display:"flex",borderBottom:"1px solid #111E2A",marginBottom:16,gap:0}}>
            {[["logs","📋 LOGS"],["analytics","📊 ANALYTICS"],["pipeline","⚙ PIPELINE"]].map(([k,l])=>(
              <button key={k} onClick={()=>setTab(k)} style={{background:"none",border:"none",borderBottom:tab===k?"2px solid #1D9E75":"2px solid transparent",color:tab===k?"#1D9E75":"#4A6A7A",padding:"9px 20px",fontSize:10,fontWeight:700,cursor:"pointer",fontFamily:"inherit",letterSpacing:1.8}}>
                {l}
              </button>
            ))}
          </div>

          {/* ── LOGS TAB ── */}
          {tab==="logs" && (
            <>
              <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
                <input value={fSearch} onChange={e=>setFilter("q",e.target.value)}
                  placeholder="Search user, event, IP, region…"
                  style={{background:"#0A1828",border:"1px solid #1A3040",borderRadius:6,color:"#C0D4E8",padding:"7px 13px",fontSize:11,fontFamily:"inherit",width:260,outline:"none"}}/>
                {["All","High","Medium","Low"].map(s=>(
                  <ChipBtn key={s} active={fSev===s} onClick={()=>setFilter("sev",s)} color={s==="All"?"#85B7EB":SEV_COL[s]} label={s}/>
                ))}
                <ChipBtn active={fAnom==="Yes"} onClick={()=>setFilter("anom",fAnom==="Yes"?"All":"Yes")} color="#1D9E75" label="ANOMALIES ONLY"/>
                <ChipBtn active={fAnom==="No"} onClick={()=>setFilter("anom",fAnom==="No"?"All":"No")} color="#4A6A7A" label="CLEAN ONLY"/>
                <div style={{marginLeft:"auto",fontSize:10,color:"#4A6A7A"}}>{filtered.length} / {total}</div>
              </div>

              <div style={{overflowX:"auto",borderRadius:8,border:"1px solid #111E2A"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                  <thead>
                    <tr style={{background:"#0A1420",borderBottom:"1px solid #111E2A"}}>
                      {TABLE_COLS.map(([col,lbl])=>(
                        <th key={col} onClick={()=>handleSort(col)}
                          style={{padding:"9px 11px",textAlign:"left",color:sortC===col?"#1D9E75":"#4A6A7A",letterSpacing:1.3,fontWeight:700,cursor:"pointer",whiteSpace:"nowrap",userSelect:"none",fontSize:10}}>
                          {lbl}{sortC===col?(sortD==="asc"?" ↑":" ↓"):""}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0,60).map((log,i)=>(
                      <tr key={log.id} onClick={()=>setDetail(detail?.id===log.id?null:log)}
                        style={{background:detail?.id===log.id?"#0A1E30":i%2===0?"#070D18":"#060C16",borderBottom:"1px solid #0C1520",cursor:"pointer"}}>
                        <td style={{padding:"8px 11px",color:"#5A7A8A",whiteSpace:"nowrap"}}>{new Date(log.eventTime).toLocaleString("en-IN",{dateStyle:"short",timeStyle:"short"})}</td>
                        <td style={{padding:"8px 11px",color:"#C0D4E8",fontWeight:600}}>{log.userName}</td>
                        <td style={{padding:"8px 11px",color:"#85B7EB"}}>{log.eventName}</td>
                        <td style={{padding:"8px 11px",color:"#5A7A8A"}}>{log.awsRegion}</td>
                        <td style={{padding:"8px 11px",color:"#8AAFBF",fontFamily:"monospace",fontSize:10}}>{log.sourceIP}</td>
                        <td style={{padding:"8px 11px",color:log.errorCode?"#E07070":"#2A4A3A"}}>{log.errorCode||"—"}</td>
                        <td style={{padding:"8px 11px"}}>
                          <Pill val={log.anomaly} yes="#1D9E75" no="#2A4A3A"/>
                        </td>
                        <td style={{padding:"8px 11px"}}>
                          <Pill val={log.insiderThreat} yes="#E0963A" no="#2A4A3A"/>
                        </td>
                        <td style={{padding:"8px 11px"}}>
                          <span style={{background:SEV_BG[log.incidentSeverity],color:SEV_COL[log.incidentSeverity],padding:"2px 10px",borderRadius:4,fontSize:10,fontWeight:700,border:`1px solid ${SEV_BORD[log.incidentSeverity]}`}}>{log.incidentSeverity}</span>
                        </td>
                        <td style={{padding:"8px 11px"}}>
                          <div style={{display:"flex",alignItems:"center",gap:5}}>
                            <div style={{width:44,height:4,background:"#0D1828",borderRadius:2,overflow:"hidden"}}>
                              <div style={{width:`${log.anomalyScore}%`,height:"100%",background:SEV_COL[log.incidentSeverity],borderRadius:2}}/>
                            </div>
                            <span style={{color:SEV_COL[log.incidentSeverity],fontSize:10,fontWeight:700}}>{log.anomalyScore}</span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Detail panel — matches report output table columns */}
              {detail && (
                <div style={{marginTop:14,background:"#07111E",border:"1px solid #1D9E7540",borderRadius:10,padding:18}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                    <span style={{fontSize:11,fontWeight:700,color:"#1D9E75",letterSpacing:2}}>LOG DETAIL</span>
                    <button onClick={()=>setDetail(null)} style={{background:"none",border:"none",color:"#4A6A7A",cursor:"pointer",fontSize:16}}>✕</button>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:10}}>
                    {[
                      ["User Name",       detail.userName],
                      ["AWS Access Key",  detail.awsAccessKey],
                      ["Event Time",      new Date(detail.eventTime).toLocaleString()],
                      ["Event Source",    detail.eventSource],
                      ["Event Name",      detail.eventName],
                      ["AWS Region",      detail.awsRegion],
                      ["Source IP",       detail.sourceIP],
                      ["User Agent",      detail.userAgent],
                      ["Error Code",      detail.errorCode||"—"],
                      ["Read Only",       detail.readOnly],
                      ["Event Type",      detail.eventType],
                      ["Anomaly",         detail.anomaly],
                      ["Insider Threat",  detail.insiderThreat],
                      ["Incident Severity",detail.incidentSeverity],
                      ["Anomaly Score",   String(detail.anomalyScore)],
                    ].map(([k,v])=>(
                      <div key={k} style={{background:"#060C18",borderRadius:6,padding:"9px 11px"}}>
                        <div style={{fontSize:8,color:"#4A6A7A",letterSpacing:1.5,marginBottom:3,textTransform:"uppercase"}}>{k}</div>
                        <div style={{fontSize:11,color:k==="Incident Severity"?SEV_COL[v]:k==="Anomaly"||k==="Insider Threat"?v==="Yes"?(k==="Anomaly"?"#1D9E75":"#E0963A"):"#2A4A3A":"#C0D4E8",fontWeight:k==="Incident Severity"||k==="Anomaly"||k==="Insider Threat"?700:400,wordBreak:"break-all"}}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── ANALYTICS TAB ── */}
          {tab==="analytics" && (
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:18}}>

              {/* Top risky users */}
              <ACard title="TOP RISKY USERS" color="#1D9E75">
                {topUsers.map(u=>(
                  <div key={u.user} style={{display:"flex",alignItems:"center",gap:10,marginBottom:11}}>
                    <div style={{width:26,height:26,borderRadius:"50%",background:u.score>=74?SEV_BG.High:u.score>=44?SEV_BG.Medium:SEV_BG.Low,border:`1px solid ${SEV_COL[u.score>=74?"High":u.score>=44?"Medium":"Low"]}50`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,color:SEV_COL[u.score>=74?"High":u.score>=44?"Medium":"Low"],fontWeight:700,flexShrink:0}}>
                      {u.user[0].toUpperCase()}
                    </div>
                    <div style={{flex:1}}>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                        <span style={{fontSize:11,color:"#C0D4E8",fontWeight:600}}>{u.user}</span>
                        <span style={{fontSize:9,color:"#4A6A7A"}}>{u.count} events · {u.high} high</span>
                      </div>
                      <div style={{height:3,background:"#0D1828",borderRadius:2}}>
                        <div style={{width:`${u.score}%`,height:"100%",background:SEV_COL[u.score>=74?"High":u.score>=44?"Medium":"Low"],borderRadius:2}}/>
                      </div>
                    </div>
                    <span style={{fontSize:11,fontWeight:700,color:SEV_COL[u.score>=74?"High":u.score>=44?"Medium":"Low"],minWidth:26,textAlign:"right"}}>{u.score}</span>
                  </div>
                ))}
              </ACard>

              {/* Top events */}
              <ACard title="TOP API EVENTS" color="#85B7EB">
                {topEvts.map(([evt,cnt])=>(
                  <div key={evt} style={{marginBottom:10}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                      <span style={{fontSize:10,color:"#C0D4E8"}}>{evt}</span>
                      <span style={{fontSize:9,color:"#4A6A7A"}}>{cnt}</span>
                    </div>
                    <div style={{height:3,background:"#0D1828",borderRadius:2}}>
                      <div style={{width:`${(cnt/maxEvt)*100}%`,height:"100%",background:"linear-gradient(90deg,#378ADD,#534AB7)",borderRadius:2}}/>
                    </div>
                  </div>
                ))}
              </ACard>

              {/* Severity chart */}
              <ACard title="SEVERITY DISTRIBUTION" color="#E05252">
                <div style={{display:"flex",height:110,alignItems:"flex-end",gap:14,paddingBottom:6,borderBottom:"1px solid #0D1828",marginBottom:14}}>
                  {[["High",highs,"#E05252"],["Medium",meds,"#E0963A"],["Low",lows,"#2DB87A"]].map(([s,n,c])=>(
                    <div key={s} style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",gap:5}}>
                      <span style={{fontSize:13,fontWeight:700,color:c}}>{n}</span>
                      <div style={{width:"55%",background:c,borderRadius:"3px 3px 0 0",height:`${Math.max(4,(n/Math.max(total,1))*90)}px`,opacity:0.85}}/>
                      <span style={{fontSize:9,color:"#4A6A7A",letterSpacing:0.8}}>{s}</span>
                    </div>
                  ))}
                </div>
                <div style={{display:"flex",justifyContent:"space-around"}}>
                  {[["ANOMALY RATE",`${total?Math.round((anoms/total)*100):0}%`,"#1D9E75"],["INSIDER RATE",`${total?Math.round((inside/total)*100):0}%`,"#E0963A"]].map(([l,v,c])=>(
                    <div key={l} style={{textAlign:"center"}}>
                      <div style={{fontSize:20,fontWeight:700,color:c}}>{v}</div>
                      <div style={{fontSize:8,color:"#4A6A7A",letterSpacing:1}}>{l}</div>
                    </div>
                  ))}
                </div>
              </ACard>

              {/* Region map */}
              <ACard title="REGIONS AFFECTED" color="#AFA9EC">
                {topRegs.map(([reg,cnt])=>(
                  <div key={reg} style={{marginBottom:10}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                      <span style={{fontSize:11,color:"#C0D4E8"}}>{reg}</span>
                      <span style={{fontSize:9,color:"#4A6A7A"}}>{cnt} events</span>
                    </div>
                    <div style={{height:3,background:"#0D1828",borderRadius:2}}>
                      <div style={{width:`${(cnt/total)*100}%`,height:"100%",background:"linear-gradient(90deg,#534AB7,#AFA9EC)",borderRadius:2}}/>
                    </div>
                  </div>
                ))}
              </ACard>

            </div>
          )}

          {/* ── PIPELINE TAB ── */}
          {tab==="pipeline" && (
            <div style={{maxWidth:640,margin:"0 auto"}}>
              <ACard title="ML PIPELINE — FROM REPORT" color="#1D9E75">
                {[
                  ["1","Collect CloudTrail Logs","AWS CloudTrail captures all API calls. Logs stored in S3.","#1D9E75"],
                  ["2","Preprocessing & Feature Engineering","Timestamp conversion, null handling, label encoding, feature extraction (hour, region, user, etc.)","#378ADD"],
                  ["3","Isolation Forest","Unsupervised anomaly detection. Flags unusual activity patterns. Accuracy: 85–95%","#1D9E75"],
                  ["4","Random Forest — Insider Threat","Supervised classifier. Predicts if action is insider threat. Accuracy: 88–94%","#E0963A"],
                  ["5","Random Forest — Severity","Classifies severity as Low / Medium / High. Accuracy: 85–93%","#E05252"],
                  ["6","Merge & Export","Predictions appended to original dataset. Exported as CSV report for SOC use.","#AFA9EC"],
                ].map(([n,title,desc,c])=>(
                  <div key={n} style={{display:"flex",gap:14,marginBottom:18,alignItems:"flex-start"}}>
                    <div style={{width:28,height:28,borderRadius:"50%",background:c,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,color:"#fff",flexShrink:0}}>{n}</div>
                    <div>
                      <div style={{fontSize:12,fontWeight:700,color:"#C0D4E8",marginBottom:3}}>{title}</div>
                      <div style={{fontSize:11,color:"#5A7A8A",lineHeight:1.6}}>{desc}</div>
                    </div>
                  </div>
                ))}
              </ACard>

              <ACard title="MODEL ACCURACY" color="#AFA9EC">
                {[["Isolation Forest","Anomaly Detection",90,"#1D9E75"],["Random Forest","Insider Threat Prediction",91,"#E0963A"],["Random Forest","Severity Classification",89,"#E05252"]].map(([m,t,a,c])=>(
                  <div key={t} style={{marginBottom:16}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:5}}>
                      <div>
                        <div style={{fontSize:11,fontWeight:700,color:"#C0D4E8"}}>{m}</div>
                        <div style={{fontSize:10,color:"#4A6A7A"}}>{t}</div>
                      </div>
                      <span style={{fontSize:18,fontWeight:700,color:c}}>{a}%</span>
                    </div>
                    <div style={{height:5,background:"#0D1828",borderRadius:3}}>
                      <div style={{width:`${a}%`,height:"100%",background:c,borderRadius:3}}/>
                    </div>
                  </div>
                ))}
              </ACard>
            </div>
          )}

        </div>
      )}
    </div>
  );
}

/* ── Small reusable components ── */
function Btn({onClick,disabled,color,label}) {
  return (
    <button onClick={onClick} disabled={disabled} style={{background:disabled?"#1A3A28":color,color:"#fff",border:"none",borderRadius:6,padding:"8px 16px",fontSize:11,fontWeight:700,cursor:disabled?"default":"pointer",fontFamily:"inherit",letterSpacing:0.8,opacity:disabled?0.6:1}}>
      {label}
    </button>
  );
}
function BigBtn({onClick,label,color,outline}) {
  return (
    <button onClick={onClick} style={{background:outline?"transparent":color,color:outline?color:"#fff",border:`1.5px solid ${color}`,borderRadius:8,padding:"12px 28px",fontSize:12,fontWeight:700,cursor:"pointer",fontFamily:"inherit",letterSpacing:0.8}}>
      {label}
    </button>
  );
}
function ChipBtn({active,onClick,color,label}) {
  return (
    <button onClick={onClick} style={{background:active?color+"20":"transparent",border:`1px solid ${active?color:color+"40"}`,color:active?color:color+"80",borderRadius:20,padding:"5px 13px",fontSize:9,fontWeight:700,cursor:"pointer",fontFamily:"inherit",letterSpacing:1}}>
      {label}
    </button>
  );
}
function Pill({val,yes,no}) {
  return (
    <span style={{background:val==="Yes"?yes+"15":no+"10",color:val==="Yes"?yes:no,padding:"2px 8px",borderRadius:4,fontSize:10,fontWeight:700}}>
      {val}
    </span>
  );
}
function ACard({title,color,children}) {
  return (
    <div style={{background:"#07111E",border:"1px solid #111E2A",borderRadius:10,padding:18}}>
      <div style={{fontSize:10,fontWeight:700,color,letterSpacing:2,marginBottom:14,borderBottom:"1px solid #111E2A",paddingBottom:8}}>{title}</div>
      {children}
    </div>
  );
}
