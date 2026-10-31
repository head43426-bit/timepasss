// Kill Chain Attack Path Reconstruction — FULL version
// Extends the simulation: same 3 demo scenarios, plus adapters, builder,
// mapping editor, computed scoring, and export. Synthetic by default.
// No live SIEM, no real key, no external call in this build.

const ALL_STAGES = ["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Lateral Movement","Collection","Exfiltration","Impact"];
const DEFAULT_MAPPING = {
  "Reconnaissance":"T1595.002 — Vulnerability Scanning",
  "Initial Access":"T1566.001 — Spearphishing Attachment",
  "Execution":"T1204.002 — Malicious File",
  "Persistence":"T1053.005 — Scheduled Task",
  "Privilege Escalation":"T1003.001 — LSASS Memory",
  "Defense Evasion":"T1071.001 — Web Protocols",
  "Lateral Movement":"T1021.002 — SMB/Windows Admin Shares",
  "Collection":"T1560.001 — Archive Collected Data",
  "Exfiltration":"T1048.003 — Exfiltration Over Unencrypted Protocol",
  "Impact":"T1485 — Data Destruction (demo)"
};

// Built-in demo scenarios, carried over from the simulation (synthetic).
const SCENARIOS = [
  { id:"phish-admin", title:"Phish → Domain Admin", subtitle:"A fake invoice email leads to credential theft and admin takeover.", summary:"Attacker starts with a phishing email, steals a session, plants persistence, escalates to domain admin, then moves laterally before staging data for exfiltration.", stages:["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Lateral Movement","Collection","Exfiltration"], logs:[
    {t:"09:12",host:"WS-041",user:"priya.sharma",src:"mail-gateway",action:"Phishing email delivered",detail:"Synthetic email 'Invoice_Q3.pdf' from a lookalike domain reached the inbox. Link domain was registered 2 days ago in this scenario.",stage:"Initial Access",mitre:"T1566.001 — Spearphishing Attachment",sev:"high"},
    {t:"09:14",host:"WS-041",user:"priya.sharma",src:"endpoint",action:"Macro-enabled document opened",detail:"User opened the attachment and enabled macros. A child process spawned from the office app — a classic execution signal.",stage:"Execution",mitre:"T1204.002 — Malicious File",sev:"critical"},
    {t:"09:17",host:"WS-041",user:"priya.sharma",src:"endpoint",action:"Credential dump attempt",detail:"Process accessed LSASS memory. In this synthetic set, the attempt was partially blocked, but a session token was still harvested.",stage:"Privilege Escalation",mitre:"T1003.001 — LSASS Memory",sev:"critical"},
    {t:"09:22",host:"WS-041",user:"priya.sharma",src:"endpoint",action:"Scheduled task created",detail:"A task named 'UpdateSvc' was created to re-run the payload at logon. This is the persistence anchor for the whole path.",stage:"Persistence",mitre:"T1053.005 — Scheduled Task",sev:"high"},
    {t:"09:31",host:"WS-041",user:"priya.sharma",src:"proxy",action:"C2 beacon over HTTPS",detail:"Beaconing every 60 seconds to a synthetic C2 host. Traffic was hidden inside normal-looking HTTPS, so no single request looked alarming.",stage:"Defense Evasion",mitre:"T1071.001 — Web Protocols",sev:"high"},
    {t:"09:48",host:"WS-041",user:"priya.sharma",src:"ad-log",action:"Kerberoasting attempt",detail:"Service ticket requests spiked for a high-privilege service account. This links the workstation compromise to domain privilege escalation.",stage:"Privilege Escalation",mitre:"T1558.003 — Kerberoasting",sev:"critical"},
    {t:"10:05",host:"SRV-FILE-02",user:"svc-backup",src:"ad-log",action:"Lateral movement via SMB",detail:"Same session pattern appeared on a file server 17 minutes later, using the escalated service account. Host + time + account link the two machines.",stage:"Lateral Movement",mitre:"T1021.002 — SMB/Windows Admin Shares",sev:"critical"},
    {t:"10:21",host:"SRV-FILE-02",user:"svc-backup",src:"dlp",action:"Sensitive files staged",detail:"Finance folders were copied to a staging folder and compressed. File names in this demo are invented: Q3_forecast, vendor_contracts.",stage:"Collection",mitre:"T1560.001 — Archive Collected Data",sev:"high"},
    {t:"10:34",host:"SRV-FILE-02",user:"svc-backup",src:"proxy",action:"Large outbound transfer",detail:"Compressed archive left via HTTPS to an external host. Volume was 4.2 GB in this synthetic scenario — far above the host baseline.",stage:"Exfiltration",mitre:"T1048.003 — Exfiltration Over Unencrypted Protocol",sev:"critical"},
    {t:"10:40",host:"WS-041",user:"priya.sharma",src:"endpoint",action:"Logs cleared on workstation",detail:"Event logs were cleared after exfiltration, which is itself evidence of defence evasion and a gap in later visibility.",stage:"Defense Evasion",mitre:"T1070.001 — Clear Logs",sev:"medium"}
  ]},
  { id:"web-shell", title:"Web Shell via Plugin", subtitle:"An unpatched web plugin becomes a backdoor, then a database breach.", summary:"No phishing here. The entry point is a vulnerable public-facing web app. The attacker uploads a web shell, harvests database credentials, and extracts customer-style records.", stages:["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Collection","Exfiltration"], logs:[
    {t:"13:02",host:"WEB-02",user:"anonymous",src:"waf",action:"Scanner probing plugin endpoints",detail:"Repeated requests to /wp-content/plugins/demo-upload/ from one synthetic IP. Reconnaissance pattern: same IP, many 404s, then one 200.",stage:"Reconnaissance",mitre:"T1595.002 — Vulnerability Scanning",sev:"medium"},
    {t:"13:19",host:"WEB-02",user:"anonymous",src:"waf",action:"Malicious file upload",detail:"A file disguised as an image was uploaded and executed as code. This is the initial access point for the whole scenario.",stage:"Initial Access",mitre:"T1190 — Exploit Public-Facing Application",sev:"critical"},
    {t:"13:21",host:"WEB-02",user:"www-data",src:"web",action:"Web shell command executed",detail:"Commands ran as the web user: whoami, id, and directory listings. The shell stayed resident for later use.",stage:"Execution",mitre:"T1059.004 — Unix Shell",sev:"critical"},
    {t:"13:35",host:"WEB-02",user:"www-data",src:"web",action:"Shell re-installed after restart",detail:"After a service restart, the shell reappeared from a hidden file. That reappearance is the persistence evidence.",stage:"Persistence",mitre:"T1505.003 — Web Shell",sev:"high"},
    {t:"13:52",host:"WEB-02",user:"www-data",src:"db-audit",action:"Database credentials read",detail:"A config file containing database credentials was read by the web user. No real credentials are used — these are invented demo strings.",stage:"Privilege Escalation",mitre:"T1552.001 — Credentials In Files",sev:"high"},
    {t:"14:10",host:"DB-01",user:"app-db-user",src:"db-audit",action:"Bulk SELECT from customers table",detail:"A single session ran bulk exports from a synthetic customers table. Row count in this demo: 48,200 invented records.",stage:"Collection",mitre:"T1005 — Data from Local System",sev:"critical"},
    {t:"14:27",host:"DB-01",user:"app-db-user",src:"proxy",action:"Data exfiltrated in chunks",detail:"Export was split into small chunks and sent out over HTTPS, likely to avoid a single large-transfer alert.",stage:"Exfiltration",mitre:"T1048 — Exfiltration Over C2 Channel",sev:"critical"}
  ]},
  { id:"vpn-cloud", title:"Stolen VPN → Cloud Exfil", subtitle:"Leaked VPN credentials open a remote door into cloud storage.", summary:"A remote worker's VPN credentials — leaked in this invented scenario — are reused from an unusual location, giving access to internal tools and then to cloud buckets.", stages:["Initial Access","Execution","Persistence","Lateral Movement","Collection","Exfiltration"], logs:[
    {t:"07:58",host:"VPN-GW-01",user:"rahul.mehta",src:"vpn",action:"VPN login from unusual location",detail:"Login succeeded, but from a new country and device in this synthetic scenario, 6 hours outside the user's normal pattern.",stage:"Initial Access",mitre:"T1078 — Valid Accounts",sev:"high"},
    {t:"08:11",host:"LAP-118",user:"rahul.mehta",src:"endpoint",action:"Remote session to internal jump host",detail:"The VPN session immediately connected to a jump host, then to an internal admin console. No malware was needed — valid access was abused.",stage:"Lateral Movement",mitre:"T1021.001 — Remote Desktop Protocol",sev:"high"},
    {t:"08:24",host:"LAP-118",user:"rahul.mehta",src:"cloud-audit",action:"New API key created",detail:"A new cloud API key was created for the user account. This is the persistence mechanism in a cloud context.",stage:"Persistence",mitre:"T1098.001 — Additional Cloud Credentials",sev:"critical"},
    {t:"08:39",host:"LAP-118",user:"rahul.mehta",src:"endpoint",action:"Script enumerated cloud buckets",detail:"A script listed storage buckets and permissions. Enumeration itself is not exfiltration, but it sets up the next step.",stage:"Execution",mitre:"T1580 — Cloud Infrastructure Discovery",sev:"medium"},
    {t:"08:57",host:"CLOUD-01",user:"rahul.mehta",src:"cloud-audit",action:"Bulk download from storage bucket",detail:"Objects were downloaded in bulk from a synthetic bucket named demo-backups-2026. Data in this demo is invented.",stage:"Collection",mitre:"T1530 — Data from Cloud Storage",sev:"critical"},
    {t:"09:12",host:"CLOUD-01",user:"rahul.mehta",src:"cloud-audit",action:"Bucket shared externally",detail:"Sharing settings were changed to allow external access, creating a second exfiltration path even after the download.",stage:"Exfiltration",mitre:"T1567.002 — Exfiltration to Cloud Storage",sev:"critical"}
  ]},
];

// Refinement Pass 1 fix: remember each demo event's original technique BEFORE
// any mapping edit, so Reset Mappings can restore demo scenarios too (previously
// _origMitre was only set for ingested/builder events, so demo reset silently failed).
SCENARIOS.forEach(s => s.logs.forEach(l => { if (!l._origMitre) l._origMitre = l.mitre; }));

let current = SCENARIOS[0];
let replayTimer = null, replayIndex = 0, selectedIndex = -1;
let mappingOverrides = {};
const $ = (id) => document.getElementById(id);
const A = window.KillChainAdapters;

function toMin(t){ const p = String(t).split(":"); const h = parseInt(p[0],10)||0, m = parseInt(p[1],10)||0; return h*60+m; }
function sevClass(sev){ return sev; }
function sevPill(sev){ const cls = sev==="critical"?"red":sev==="high"?"amber":"outline"; return `<span class="pill ${cls}">${String(sev).toUpperCase()}</span>`; }
function currentStages(){
  const present = new Set(current.logs.map(l=>l.stage));
  const ordered = ALL_STAGES.filter(s=>present.has(s));
  current.logs.forEach(l=>{ if(!ordered.includes(l.stage)) ordered.push(l.stage); });
  return ordered;
}
function computeRisk(){
  if(!current.logs.length) return 0;
  const w = {critical:40, high:25, medium:10, low:3};
  const sum = current.logs.reduce((a,l)=>a+w[l.sev]||10, 0);
  const coverage = currentStages().length / ALL_STAGES.length;
  const exfil = current.logs.some(l=>l.stage==="Exfiltration") ? 20 : 0;
  return Math.min(100, Math.round((sum/(current.logs.length*40))*50 + coverage*30 + exfil));
}
function confidenceFor(idx){
  if(idx<=0) return null;
  const prev = current.logs[idx-1], cur = current.logs[idx];
  let s = 0;
  if(prev.host===cur.host) s+=40;
  if(prev.user===cur.user) s+=30;
  const d = Math.abs(toMin(cur.t)-toMin(prev.t));
  if(d<=60) s+=20; else if(d<=180) s+=10;
  if(prev.src===cur.src) s+=10;
  return Math.min(100, s);
}
function escapeHtml(s){ return String(s).replace(/[&<>"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

function renderScenarios(){
  $("scenarioRow").innerHTML = SCENARIOS.map(s=>`
    <button class="sc-card ${s.id===current.id?"active":""}" data-id="${s.id}" aria-pressed="${s.id===current.id}">
      <b>${escapeHtml(s.title)}</b><p>${escapeHtml(s.subtitle)}</p>
      <p style="margin-top:8px"><span class="pill green">RISK ${computeRiskFor(s)}/100</span> <span class="pill outline">${s.logs.length} EVENTS</span></p>
    </button>`).join("");
  document.querySelectorAll(".sc-card").forEach(btn=>btn.addEventListener("click", ()=>{
    stopReplay(); current = SCENARIOS.find(s=>s.id===btn.dataset.id);
    selectedIndex=-1; replayIndex=0; buildStageFilter(); buildMappingEditor(); renderAll();
  }));
}
function computeRiskFor(s){ const saved=current; current=s; const r=computeRisk(); current=saved; return r; }
function buildStageFilter(){
  const sel=$("stageFilter");
  sel.innerHTML = `<option value="all">All stages</option>` + currentStages().map(st=>`<option value="${st}">${escapeHtml(st)}</option>`).join("");
}
function buildMappingEditor(){
  const stages = currentStages();
  $("mappingStage").innerHTML = stages.map(st=>`<option value="${st}">${escapeHtml(st)}</option>`).join("");
  const first = stages[0] || "Execution";
  $("mappingStage").value = first;
  syncMappingInput();
  $("mappingList").innerHTML = stages.map(st=>{
    const firstEvent = current.logs.find(l=>l.stage===st);
    const label = mappingOverrides[st] || (firstEvent?firstEvent.mitre:DEFAULT_MAPPING[st]||"—");
    return `<div class="mapping-row"><b>${escapeHtml(st)}</b><span>${escapeHtml(label)}</span></div>`;
  }).join("");
}
function syncMappingInput(){
  const st = $("mappingStage").value;
  const firstEvent = current.logs.find(l=>l.stage===st);
  $("mappingTechnique").value = mappingOverrides[st] || (firstEvent?firstEvent.mitre:DEFAULT_MAPPING[st]||"");
}
function filteredLogs(){
  const q=$("searchInput").value.toLowerCase();
  const stage=$("stageFilter").value, sev=$("sevFilter").value;
  return current.logs.map((log,idx)=>({...log,_idx:idx})).filter(log=>{
    const hay=[log.host,log.user,log.action,log.detail,log.stage,log.mitre].join(" ").toLowerCase();
    return (stage==="all"||log.stage===stage) && (sev==="all"||log.sev===sev) && (!q||hay.includes(q));
  });
}
function renderStats(){
  const hosts=new Set(current.logs.map(l=>l.host)).size;
  const users=new Set(current.logs.map(l=>l.user)).size;
  const covered=currentStages().length, gaps=ALL_STAGES.filter(s=>!currentStages().includes(s)).length;
  $("statGrid").innerHTML = `
    <div class="stat"><b>${current.logs.length}</b><span>EVENTS IN CASE</span></div>
    <div class="stat"><b>${computeRisk()}/100</b><span>COMPUTED RISK</span></div>
    <div class="stat"><b>${hosts} hosts • ${users} users</b><span>BLAST RADIUS</span></div>
    <div class="stat"><b>${covered} stages • ${gaps} gaps</b><span>COVERAGE</span></div>`;
  const exfil = current.logs.filter(l=>l.stage==="Exfiltration").length;
  const dwell = current.logs.length>1 ? (toMin(current.logs[current.logs.length-1].t)-toMin(current.logs[0].t)) : 0;
  $("blastLabel").textContent = `Blast radius: ${hosts} host(s), ${users} user(s), ${exfil} exfiltration event(s), dwell ${dwell} minute(s) from first to last event in this case.`;
}
function renderChain(){
  const stages = currentStages();
  $("chain").innerHTML = stages.map((stage,i)=>{
    const count=current.logs.filter(l=>l.stage===stage).length;
    const isActive = selectedIndex>=0 && current.logs[selectedIndex] && current.logs[selectedIndex].stage===stage;
    return `<div class="node ${isActive?"active":""}" data-stage="${stage}" tabindex="0" role="button" aria-label="Stage ${escapeHtml(stage)}, ${count} evidence event${count===1?"":"s"}"><div class="stage">STEP ${i+1}</div><b>${escapeHtml(stage)}</b><span>${count} evidence event${count===1?"":"s"}</span></div>`;
  }).join("");
  document.querySelectorAll(".node").forEach(node=>{
    const go=()=>{ const first=current.logs.findIndex(l=>l.stage===node.dataset.stage); if(first>=0) selectEvent(first); };
    node.addEventListener("click", go);
    node.addEventListener("keydown", (e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); go(); } });
  });
  const missing=ALL_STAGES.filter(s=>!stages.includes(s));
  $("gaps").innerHTML = missing.length
    ? `<span class="pill amber">⚠ GAPS FLAGGED — no evidence for:</span> ` + missing.map(m=>`<span class="pill outline">${escapeHtml(m)}</span>`).join(" ")
    : `<span class="pill green">✓ No gaps — all core stages have evidence.</span>`;
}
function renderTimeline(){
  const list=filteredLogs();
  $("timeline").innerHTML = list.length ? list.map(log=>{
    const conf=confidenceFor(log._idx);
    return `<li class="${log._idx===selectedIndex?"active":""} ${log._idx<replayIndex?"done":""}" data-idx="${log._idx}" tabindex="0" role="button" aria-label="Event: ${escapeHtml(log.action)} on ${escapeHtml(log.host)}">
      <div class="meta">${escapeHtml(log.t)} • ${escapeHtml(log.host)} • ${escapeHtml(log.user)} • ${escapeHtml(log.src)} • ${escapeHtml(log.mitre)}${conf===null?"":` • LINK CONF ${conf}%`}</div>
      <b>${escapeHtml(log.action)} ${sevPill(log.sev)}</b><p>${escapeHtml(log.detail)}</p></li>`;
  }).join("") : (current.logs.length ? `<li><b>No events match the current filters.</b><p>Clear the search or reset the stage / severity filters.</p></li>` : `<li><b>No events in this case.</b><p>Ingest logs above, or return to a built-in demo scenario.</p></li>`);
  document.querySelectorAll("#timeline li[data-idx]").forEach(li=>{
    const go=()=>selectEvent(parseInt(li.dataset.idx,10));
    li.addEventListener("click", go);
    li.addEventListener("keydown", (e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); go(); } });
  });
  const pctBar = current.logs.length ? (replayIndex/current.logs.length*100) : 0;
  $("progressBar").style.width = pctBar+"%";
  const wrap = $("progressBarWrap"); if (wrap) wrap.setAttribute("aria-valuenow", String(Math.round(pctBar)));
  $("progressLabel").textContent = replayIndex===0 ? "Ready — press Replay to walk the path."
    : replayIndex>=current.logs.length ? `Replay complete — ${current.logs.length} of ${current.logs.length} events walked.`
    : `Replay at event ${replayIndex} of ${current.logs.length} — ${current.logs[replayIndex-1].action} on ${current.logs[replayIndex-1].host}.`;
}
function storyData(){
  const byStage={}; current.logs.forEach(l=>{(byStage[l.stage]=byStage[l.stage]||[]).push(l);});
  return { title:current.title, summary:current.summary, risk:computeRisk(), stages:currentStages().map((stage,i)=>({step:i+1, stage, events:byStage[stage]||[]})), gaps:ALL_STAGES.filter(s=>!currentStages().includes(s)), totalEvents:current.logs.length };
}
function renderStory(){
  if (!current.logs.length){ $("story").innerHTML = `<p style="color:var(--muted);line-height:1.6">No events in this case yet, so there is no story to tell. Ingest logs, or return to a built-in demo scenario.</p>`; return; }
  const d=storyData();
  $("story").innerHTML = `<p style="color:var(--muted);line-height:1.6">${escapeHtml(d.summary)}</p>` + d.stages.map(s=>`<div class="story-step"><h4>${s.step}. ${escapeHtml(s.stage)} — ${s.events.length} evidence event${s.events.length===1?"":"s"}</h4><p>${s.events.map(e=>`${escapeHtml(e.t)} ${escapeHtml(e.host)}: ${escapeHtml(e.action)}.`).join(" ")}</p></div>`).join("");
}
function showDetail(idx){
  if(idx<0||idx>=current.logs.length) return;
  const log=current.logs[idx], conf=confidenceFor(idx), en=A.mockEnrich(log);
  $("detailCard").innerHTML = `
    <p class="eyebrow">SELECTED EVIDENCE • EVENT ${idx+1} OF ${current.logs.length}</p>
    <p><b>${escapeHtml(log.action)}</b> ${sevPill(log.sev)}</p><p>${escapeHtml(log.detail)}</p>
    <p><code>time</code> ${escapeHtml(log.t)} &nbsp; <code>host</code> ${escapeHtml(log.host)} &nbsp; <code>user</code> ${escapeHtml(log.user)} &nbsp; <code>source</code> ${escapeHtml(log.src)}<br>
    <code>stage</code> ${escapeHtml(log.stage)} &nbsp; <code>technique</code> ${escapeHtml(log.mitre)} &nbsp; <code>adapter</code> ${escapeHtml(log._adapter||"demo")}</p>
    <p><code>link confidence</code> ${conf===null?"First event — no previous link to score":conf+"% (host + user + time proximity)"}</p>
    <p style="color:var(--muted)"><code>enrichment</code> ${escapeHtml(en.mode)} — ${escapeHtml(en.techniqueNote)}</p>`;
}
function selectEvent(idx){ selectedIndex=idx; showDetail(idx); renderChain(); renderTimeline(); const el=document.querySelector(`#timeline li[data-idx="${idx}"]`); if(el) el.scrollIntoView({block:"nearest",behavior:"smooth"}); }
function renderAll(){ renderStats(); renderChain(); renderTimeline(); renderStory(); if(selectedIndex>=0) showDetail(selectedIndex); }
function stopReplay(){ if(replayTimer){clearInterval(replayTimer); replayTimer=null;} $("replayBtn").textContent="▶ REPLAY ATTACK PATH"; }
function startReplay(){ stopReplay(); replayIndex=0; selectedIndex=-1; renderAll(); const speed=parseInt($("speedSel").value,10); $("replayBtn").textContent="⏸ PAUSE REPLAY"; replayTimer=setInterval(()=>{ if(replayIndex>=current.logs.length){stopReplay(); renderAll(); return;} selectEvent(replayIndex); replayIndex++; renderTimeline(); renderChain(); }, speed); }
function setStatus(msg){ $("ingestStatus").textContent=msg; $("adapterStatus").textContent="Adapter: "+$("adapterSelect").value+" • Enrichment: mock fallback — no key configured."; }
function ensureCustom(){
  if(current.id==="custom") return;
  const copy={ id:"custom", title:"Custom case (from "+current.title+")", subtitle:"Built from a demo scenario, then edited / ingested in this session.", summary:current.summary, stages:[], logs:current.logs.map(l=>({...l,_origMitre:l.mitre})) };
  const existing=SCENARIOS.find(s=>s.id==="custom");
  if(existing){ Object.assign(existing, copy); } else { SCENARIOS.push(copy); }
  current=SCENARIOS.find(s=>s.id==="custom");
}
function dedupeKey(e){ return [String(e.t).trim().toLowerCase(), String(e.host).trim().toLowerCase(), String(e.user).trim().toLowerCase(), String(e.action).trim().toLowerCase()].join("|"); }
function loadCustomCase(logs, label){
  const seen = new Set(); let dupes = 0;
  const deduped = logs.filter(e => { const k = dedupeKey(e); if (seen.has(k)) { dupes++; return false; } seen.add(k); return true; });
  const sorted=[...deduped].sort((a,b)=>toMin(a.t)-toMin(b.t));
  const sc={ id:"custom", title:"Custom case — "+label, subtitle:"Ingested in this session. Synthetic / authorised demo logs only.", summary:"Custom case built from ingested logs. Stages, links and story are computed from the events below.", stages:[], logs:sorted.map(l=>({...l,_origMitre:l.mitre})) };
  const existing=SCENARIOS.find(s=>s.id==="custom");
  if(existing) Object.assign(existing, sc); else SCENARIOS.push(sc);
  current=SCENARIOS.find(s=>s.id==="custom");
  stopReplay(); selectedIndex=-1; replayIndex=0; buildStageFilter(); buildMappingEditor(); renderScenarios(); renderAll();
  setStatus(`Loaded ${sorted.length} event(s) from ${label}.` + (dupes ? ` ${dupes} exact duplicate event(s) removed (same time, host, user, action).` : ""));
}
function download(filename, text, type){
  const blob=new Blob([text],{type}); const a=document.createElement("a");
  a.href=URL.createObjectURL(blob); a.download=filename; a.click(); URL.revokeObjectURL(a.href);
}
function buildMarkdown(){
  const d=storyData();
  let md=`# Attack Story — ${d.title}\n\n> Synthetic / demo by default. No real logs, no live SIEM, no real key.\n\nRisk (computed): ${d.risk}/100 • Events: ${d.totalEvents}\n\n${d.summary}\n\n`;
  d.stages.forEach(s=>{ md+=`## ${s.step}. ${s.stage}\n`; s.events.forEach(e=>{ md+=`- ${e.t} ${e.host} (${e.user}): ${e.action} — ${e.mitre} [${e.sev}]\n`; }); md+=`\n`; });
  if(d.gaps.length) md+=`## Gaps flagged\n${d.gaps.map(g=>`- ${g}`).join("\n")}\n`;
  return md;
}

// Controls
$("replayBtn").addEventListener("click", ()=>{ if(replayTimer) stopReplay(); else startReplay(); });
$("resetBtn").addEventListener("click", ()=>{ stopReplay(); replayIndex=0; selectedIndex=-1; $("searchInput").value=""; $("stageFilter").value="all"; $("sevFilter").value="all"; $("detailCard").innerHTML=`<p class="eyebrow">SELECTED EVIDENCE</p><p>Click any timeline event or path node to see its full detail here.</p>`; renderAll(); });
$("cleanResetBtn").addEventListener("click", ()=>{
  // True clean state for a judge: drop the custom case, restore original
  // mappings, clear ingest/builder inputs, and return to demo scenario 1.
  stopReplay();
  const idx=SCENARIOS.findIndex(s=>s.id==="custom"); if(idx>=0) SCENARIOS.splice(idx,1);
  mappingOverrides={};
  SCENARIOS.forEach(s=>s.logs.forEach(l=>{ if(l._origMitre) l.mitre=l._origMitre; }));
  current=SCENARIOS[0];
  selectedIndex=-1; replayIndex=0;
  $("searchInput").value=""; $("pasteArea").value=""; $("fileInput").value="";
  $("adapterSelect").value="demo";
  $("detailCard").innerHTML=`<p class="eyebrow">SELECTED EVIDENCE</p><p>Click any timeline event or path node to see its full detail here.</p>`;
  $("builderStatus").textContent="Builder ready.";
  buildStageFilter(); buildMappingEditor(); renderScenarios(); renderAll();
  setStatus("Demo reset to clean state — back to built-in demo scenarios, original mappings restored.");
});
$("searchInput").addEventListener("input", renderTimeline);
$("stageFilter").addEventListener("change", renderTimeline);
$("sevFilter").addEventListener("change", renderTimeline);
$("adapterSelect").addEventListener("change", ()=>setStatus("Adapter selected: "+$("adapterSelect").value+". Load a file, paste logs, or use the mock SIEM button."));
$("fileInput").addEventListener("change", (e)=>{
  const file=e.target.files[0]; if(!file) return;
  const reader=new FileReader();
  reader.onload=()=>{ try{
    let logs;
    if(file.name.toLowerCase().endsWith(".csv")) logs=A.parseCSVLogs(reader.result);
    else logs=A.parseJSONLogs(reader.result);
    if(!logs.length) throw new Error("No events found in this file.");
    loadCustomCase(logs, "file: "+file.name);
  }catch(err){ setStatus("Could not load file: "+err.message); } };
  reader.readAsText(file);
});
$("loadPasteBtn").addEventListener("click", ()=>{
  try{ const logs=A.parsePastedLogs($("pasteArea").value); if(!logs.length) throw new Error("No events found. Paste a JSON array or pipe-separated lines."); loadCustomCase(logs, "pasted logs"); }
  catch(err){ setStatus("Could not load pasted logs: "+err.message); }
});
$("loadMockBtn").addEventListener("click", async ()=>{
  setStatus("Mock SIEM adapter: fetching synthetic incident… (simulated, no live connection)");
  const logs=await A.fetchMockSiemIncident();
  loadCustomCase(logs, "mock SIEM adapter");
});
$("clearCustomBtn").addEventListener("click", ()=>{
  const idx=SCENARIOS.findIndex(s=>s.id==="custom"); if(idx>=0) SCENARIOS.splice(idx,1);
  current=SCENARIOS[0]; stopReplay(); selectedIndex=-1; replayIndex=0; buildStageFilter(); buildMappingEditor(); renderScenarios(); renderAll(); setStatus("Custom case cleared. Back to built-in demo scenarios.");
});
$("bStage").innerHTML = ALL_STAGES.map(s=>`<option>${s}</option>`).join("");
$("addEventBtn").addEventListener("click", ()=>{
  const isDupe = current.logs.some(l => dedupeKey(l) === dedupeKey({ t:$("bTime").value, host:$("bHost").value, user:$("bUser").value, action:$("bAction").value }));
  if (isDupe){ $("builderStatus").textContent="Not added — an identical event (same time, host, user, action) already exists in this case. Change the time, host, user, or action to add a distinct event."; return; }
  ensureCustom();
  const ev=A.normaliseEvent({ t:$("bTime").value, host:$("bHost").value, user:$("bUser").value, src:$("bSrc").value, action:$("bAction").value, detail:$("bDetail").value, stage:$("bStage").value, mitre:$("bMitre").value, sev:$("bSev").value, _adapter:"builder" }, current.logs.length);
  ev._origMitre=ev.mitre;
  current.logs.push(ev); current.logs.sort((a,b)=>toMin(a.t)-toMin(b.t));
  stopReplay(); selectedIndex=-1; replayIndex=0; buildStageFilter(); buildMappingEditor(); renderScenarios(); renderAll();
  $("builderStatus").textContent="Event added: "+ev.action+" on "+ev.host+". Custom case updated.";
});
$("deleteEventBtn").addEventListener("click", ()=>{
  if(selectedIndex<0){ $("builderStatus").textContent="Select an event first, then delete it."; return; }
  ensureCustom(); const removed=current.logs.splice(selectedIndex,1)[0];
  selectedIndex=-1; buildStageFilter(); buildMappingEditor(); renderScenarios(); renderAll();
  $("builderStatus").textContent="Deleted: "+(removed?removed.action:"event")+".";
});
$("mappingStage").addEventListener("change", syncMappingInput);
$("saveMappingBtn").addEventListener("click", ()=>{
  const st=$("mappingStage").value, label=$("mappingTechnique").value.trim();
  if(!label) return;
  // Defensive: preserve the original technique if it was never recorded.
  current.logs.forEach(l=>{ if(l.stage===st && !l._origMitre) l._origMitre=l.mitre; });
  mappingOverrides[st]=label;
  current.logs.forEach(l=>{ if(l.stage===st) l.mitre=label; });
  buildMappingEditor(); renderAll();
});
$("resetMappingBtn").addEventListener("click", ()=>{
  mappingOverrides={};
  current.logs.forEach(l=>{ if(l._origMitre) l.mitre=l._origMitre; });
  buildMappingEditor(); renderAll();
});
$("exportJsonBtn").addEventListener("click", ()=>download("killchain-attack-story.json", JSON.stringify(storyData(), null, 2), "application/json"));
$("exportMdBtn").addEventListener("click", ()=>download("killchain-attack-story.md", buildMarkdown(), "text/markdown"));

// Init
buildStageFilter();
buildMappingEditor();
renderScenarios();
renderAll();
