"use strict";
var state = { incidents: [], selected: null, report: "", hindi: null, graphMode: "kill" };

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem("ask_theme", theme); } catch (e) {}
  var btn = document.getElementById("themeBtn");
  if (btn) btn.textContent = theme === "dark" ? "Light mode" : "Dark mode";
}
(function initTheme() {
  var saved = null;
  try { saved = localStorage.getItem("ask_theme"); } catch (e) {}
  applyTheme(saved === "dark" ? "dark" : "light");
  var btn = document.getElementById("themeBtn");
  if (btn) btn.addEventListener("click", function() {
    applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
  });
})();

function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

async function loadIncidents() {
  var res = await fetch("/incidents");
  var list = await res.json();
  state.incidents = list;
  var health = await (await fetch("/health")).json();
  state.lastHealth = health.detections + "/" + health.incidents;
  document.getElementById("stats").innerHTML =
    "<div class=stat><b>" + list.length + "</b><span>incidents</span></div>" +
    "<div class=stat><b>" + health.detections + "</b><span>detections</span></div>" +
    "<div class=stat><b>" + list.reduce(function(n, i) { return n + (i.merged_alerts || 0); }, 0) + "</b><span>raw alerts merged</span></div>";
  var ac = document.getElementById("activeCount");
  if (ac) ac.textContent = list.length + " active";
  document.getElementById("liveStatus").innerHTML = health.live_watch
    ? "● Live — watching " + esc(health.live_watch) + ". New log lines are detected and linked as they arrive, and this list refreshes every 5 seconds."
    : "○ Live off — start the server with --watch your.log to watch a live log file. Uploads still work normally.";
  // Live update: every 5 seconds, check only /health (one cheap count
  // query). If nothing changed, do nothing — no page reload, no
  // flicker, and the incident you are reading is never disturbed.
  if (!state.liveTimer) {
    state.liveTimer = setInterval(async function() {
      try {
        var h = await (await fetch("/health")).json();
        var sig = h.detections + "/" + h.incidents;
        if (sig !== state.lastHealth) {
          await loadIncidents();
          if (state.selected) {
            document.getElementById("liveNote").innerHTML =
              "New log lines arrived — <button class=btn onclick='selectIncident(" + state.selected.id + ")'>Refresh this incident</button>";
          }
        }
      } catch (e) { /* server down: keep the page, stop spamming */ }
    }, 5000);
  }
  // TIER FILTER (2026-11-01, user demand: 'keep it simple, don't
  // display so many'). Incidents are grouped by tier — Critical
  // (>=90), High (70-89), Medium (40-69), Low (<40) — with a button
  // per tier showing its count, plus All. List is sorted by risk
  // descending, then steps descending, so the worst incidents are
  // first instead of a flat 700-card wall in id order.
  // Screenshot tiers: Critical / High / Elevated (Medium + Low are
  // grouped as Elevated, so the queue stays at 4 buttons, not 5).
  function tierOf(s) { return s >= 90 ? "Critical" : s >= 70 ? "High" : "Elevated"; }
  var sorted = list.slice().sort(function(a, b) {
    return (b.risk_score - a.risk_score) || (b.detection_count - a.detection_count) || (a.id - b.id);
  });
  var counts = { All: sorted.length, Critical: 0, High: 0, Elevated: 0 };
  sorted.forEach(function(i) { counts[tierOf(i.risk_score)] += 1; });
  if (!state.tierFilter) state.tierFilter = "All";
  window.setTierFilter = function(t) { state.tierFilter = t; loadIncidents(); };
  var shown = state.tierFilter === "All" ? sorted : sorted.filter(function(i) { return tierOf(i.risk_score) === state.tierFilter; });
  var filterHtml = "<div style='margin:8px 0'>" + ["All", "Critical", "High", "Elevated"].map(function(t) {
    var sel = state.tierFilter === t ? " style='background:#f0a832;color:#000;font-weight:bold'" : "";
    return "<button class=btn onclick=\"setTierFilter('" + t + "')\"" + sel + ">" + t + " (" + counts[t] + ")</button> ";
  }).join("") + "</div>";
  document.getElementById("incidents").innerHTML = (filterHtml + (shown.length ? shown.map(function(inc) {
    return "<button class=inc data-id=" + inc.id + "><b>Incident " + inc.id + " — " + tierOf(inc.risk_score) + " · risk " + inc.risk_score + "/100</b> &middot; " +
      inc.detection_count + " steps &middot; " + inc.merged_alerts + " raw alerts merged<br><small>" +
      esc(inc.title) + " &middot; " + esc(inc.hosts.join(", ")) + "</small></button>";
  }).join("") : "<p>No " + esc(state.tierFilter) + " incidents in this file. Try All.</p>"));
  document.querySelectorAll(".inc").forEach(function(el) {
    el.addEventListener("click", function() { selectIncident(parseInt(el.getAttribute("data-id"), 10)); });
  });
}

async function selectIncident(id) {
  var path = await (await fetch("/incidents/" + id + "/path")).json();
  var rep = await (await fetch("/incidents/" + id + "/report")).json();
  var next = await (await fetch("/incidents/" + id + "/next")).json();
  state.selected = path; state.report = rep.report; state.hindi = rep.hindi || null;
  path.next_reach = next.next_reach || [];
  var banner = document.getElementById("pathBanner");
  if (banner) {
    banner.hidden = false;
    banner.textContent = "Showing incident #" + path.id + " — risk " + path.risk_score + "/100 — " + (path.hosts || []).join(", ");
  }
  var ap = document.getElementById("attackPaths");
  if (ap) {
    var ranked = (next.next_reach || []).slice().sort(function(a, b) { return (b.confidence || 0) - (a.confidence || 0); });
    ap.innerHTML = ranked.length
      ? "<ol>" + ranked.map(function(n, i) { return "<li><b>" + esc(n.host) + "</b> — watch score " + n.confidence + "/100 — " + esc(n.reason) + "</li>"; }).join("") + "</ol>"
      : "<p>No frontier paths yet for this incident.</p>";
  }
  var cb = document.getElementById("corridorBtn");
  if (cb) { cb.disabled = false; cb.textContent = "Execute Containment Isolator"; }
  var cn = document.getElementById("corridorNote");
  if (cn) cn.textContent = "Quarantine here is a dashboard simulation only — no real host is isolated and no firewall rule is changed.";
  var bs = document.getElementById("briefStatus");
  if (bs) bs.textContent = "Incident #" + path.id + " — " + esc(path.title);
  document.querySelectorAll(".inc").forEach(function(el) {
    el.classList.toggle("sel", parseInt(el.getAttribute("data-id"), 10) === id);
  });
  document.getElementById("detail").innerHTML =
    "<p><b>" + esc(path.title) + "</b><br>Risk " + path.risk_score + "/100 &middot; " + path.detection_count +
    " steps &middot; " + path.merged_alerts + " raw alerts merged<br>Hosts: " + esc(path.hosts.join(", ")) +
    "<br>Users: " + esc((path.users || []).filter(function(u) { return u; }).join(", ") || "Unknown — not recorded in the logs") + "</p>" +
    (path.timeline_sampled ? "<br><small>Showing a sample: first and last 200 of " + fmtNum(path.timeline_total) + " steps. " +
      (path.timeline_summary || []).map(function(s) { return esc(s.technique_name) + " (" + esc(s.technique_id) + ") × " + fmtNum(s.count); }).join(" · ") + "</small>" : "");
  // NetworkX graph map: nodes + edges from path.graph (built by the
  // backend with NetworkX, not drawn by hand). Nodes are placed on a
  // circle in first-seen order so every edge is visible at once.
  renderGraph(path);
  // Attack path canvas: see renderAttackPathCanvas — the old
  // flat arrow list invented a chain between unrelated nodes.
  renderAttackPathCanvas(path);
  // NEXT + BLAST (2026-11-01 fix): the old text said 'no topology was
  // supplied' and 'blast radius from the supplied topology: 0/100'
  // for every web upload, because both numbers only read a topology
  // that a web upload never supplies. Now the backend falls back to
  // the observed graph: next = destinations already contacted but
  // not yet used as a stepping stone (hosts to watch, not guessed
  // targets), blast = Reach + Spread + Depth + Severity from the
  // observed graph, with its basis stated plainly.
  var nextHtml = (next.next_reach && next.next_reach.length)
    ? "<p>Hosts to watch next, from the " + esc(next.next_basis || "observed graph") + " — already contacted, not yet used as a stepping stone (watch them for outbound movement; these are not guessed new targets):</p><ul>" + next.next_reach.map(function(n) {
        return "<li><b>" + esc(n.host) + "</b> (watch score " + n.confidence + "/100) — " + esc(n.reason) + ". Block it by: " + esc(n.block) + ".</li>";
      }).join("") + "</ul>" + ((next.next_frontier_total || 0) > next.next_reach.length ? "<p>And " + fmtNum(next.next_frontier_total - next.next_reach.length) + " more frontier destinations like this — see the graph map, Destinations column.</p>" : "")
    : "<p>No frontier host to watch: every destination in this incident was already used as a stepping stone, or there are no host-to-host edges at all. No new target is guessed.</p>";
  if (next.next_stages && next.next_stages.length) {
    nextHtml += "<p><b>Looking ahead in the kill chain</b> (stages, not guessed hosts): " +
      next.next_stages.map(function(s) { return esc(s.stage); }).join(" → ") +
      ". Watch for these stages next on the compromised host(s).</p>";
  }
  if (next.blast_radius !== undefined && next.blast_radius !== null) {
    var br = next.blast_breakdown;
    nextHtml += "<p>Blast radius, from the " + esc(next.blast_basis || "observed graph") + ": <b>" + next.blast_radius + "/100</b>" +
      (br ? " — Reach " + br.reach + " (destinations: " + fmtNum(br.dst_count) + ") + Spread " + br.spread + " (sources: " + fmtNum(br.src_count) + ") + Depth " + br.depth + " (stages: " + br.stage_count + ") + Severity " + br.severity + " (worst: " + esc(br.worst_severity) + ")." : ".") + "</p>";
  }
  document.getElementById("next").innerHTML = nextHtml;
  document.getElementById("protect").innerHTML = (rep.protections && rep.protections.length)
    ? "<ol>" + rep.protections.map(function(p) {
        return "<li><b>" + esc(p.technique_id) + " — " + esc(p.technique_name) + ":</b> " + esc(p.action) + "</li>";
      }).join("") + "</ol>"
    : "<p>No protection actions for this incident.</p>";
  showReport();
  document.getElementById("copyBtn").disabled = false;
  var pdf = document.getElementById("pdfBtn");
  if (pdf) pdf.disabled = false;
  if (path.timeline.length) showStep(path, 0);
  document.getElementById("detailSection").scrollIntoView({ behavior: "smooth" });
}

function renderGraph(path) {
  var box = document.getElementById("graphMap");
  var graph = path.graph || { nodes: [], edges: [] };
  var allNodes = graph.nodes || [], allEdges = graph.edges || [];
  if (!allNodes.length) { box.innerHTML = "<p>No graph nodes for this incident.</p>"; return; }
  // GRAPH REDESIGN (2026-11-01, user demand: 'not so cluttered, colour
  // by importance, filters, use the clean inspiration image'). The old
  // circle layout put 250 nodes on one ring with every label on top of
  // every other label — unreadable. The new layout is left-to-right
  // by role, like the inspiration: users, then sources, then pivots
  // (hosts that are both a destination and a source, in kill-chain
  // stage order), then destinations. Colour = worst severity on that
  // node (backend-enriched): Critical red, High orange, Medium amber,
  // Low grey, user blue, technique purple. Edge colour = destination
  // severity. Default shows the top 60 most-connected nodes, not 250.
  if (!state.graphFilter || state.graphIncident !== path.id) {
    state.graphFilter = { technique: "All", severity: "All", search: "", showAll: false, zoom: 1 };
    state.graphIncident = path.id;
  }
  var gf = state.graphFilter;
  window.setGraphFilter = function(field, val) { gf[field] = val; renderGraph(path); };
  window.setGraphZoom = function(d) {
    gf.zoom = Math.min(2, Math.max(0.6, Math.round((gf.zoom + d) * 10) / 10));
    renderGraph(path);
  };
  // Quantum Walk mode: show only the frontier subgraph — frontier
  // hosts from /next plus the hosts that reached them. Nothing here
  // is a guessed target or a simulated probability.
  if (state.graphMode === "quantum" && path.next_reach && path.next_reach.length) {
    var frontier = {};
    path.next_reach.forEach(function(n) { frontier[n.host] = true; });
    var keepEdge = allEdges.filter(function(e) { return frontier[e.to]; });
    var keepNode = {};
    keepEdge.forEach(function(e) { keepNode[e.from] = true; keepNode[e.to] = true; });
    allNodes = allNodes.filter(function(n) { return keepNode[n.id]; });
    allEdges = keepEdge;
  }
  var nodeSet = {};
  allNodes.forEach(function(n) { nodeSet[n.id] = true; });
  var realEdges = allEdges.filter(function(e) { return nodeSet[e.from] && nodeSet[e.to]; });
  // Old DBs (built before the technique fallback) have a single host
  // and no edges: build host -> technique here from the summary.
  if (!realEdges.length && path.timeline_summary && path.timeline_summary.length) {
    var hostId = (allNodes[0] && allNodes[0].id) || (path.hosts && path.hosts[0]);
    if (hostId) {
      path.timeline_summary.forEach(function(s) {
        allNodes.push({ id: s.technique_id, type: "technique", name: s.technique_name, count: s.count, severity: "Medium", stage: s.kill_chain_stage });
        realEdges.push({ from: hostId, to: s.technique_id, kind: "technique", technique_id: s.technique_id, time: "" });
      });
    }
  }
  if (!realEdges.length) {
    var only = allNodes[0];
    box.innerHTML = "<p><span class=node>" + esc(only.id) + "</span> <small>(" + esc(only.type) + ")</small></p>" +
      "<p class='hint'>No connections to draw: this incident has only this one host and no host-to-host or user-to-host move in the logs. " +
      "All " + fmtNum(path.detection_count) + " steps happened on the host above — see the step list and the grouped report for what actually happened, instead of an empty graph.</p>";
    return;
  }
  var sevColor = { Critical: "#e1251b", High: "#f97316", Medium: "#f0a832", Low: "#6b7280" };
  var sevFill = { Critical: "#fde8e8", High: "#fef3e2", Medium: "#fef9e0", Low: "#f3f4f6" };
  var sevOf = function(n) { return n.type === "user" ? "user" : n.type === "technique" ? "technique" : (n.severity || "Low"); };
  // Filters: technique (edges), severity (nodes), search (nodes).
  var fEdges = realEdges.filter(function(e) { return gf.technique === "All" || e.technique_id === gf.technique; });
  var fNodeIds = {};
  fEdges.forEach(function(e) { fNodeIds[e.from] = true; fNodeIds[e.to] = true; });
  var fNodes = allNodes.filter(function(n) {
    if (gf.technique !== "All" && !fNodeIds[n.id] && n.id !== gf.technique) return false;
    if (gf.severity !== "All" && sevOf(n) !== gf.severity) return false;
    if (gf.search && n.id.toLowerCase().indexOf(gf.search.toLowerCase()) < 0) return false;
    return true;
  });
  var fSet = {};
  fNodes.forEach(function(n) { fSet[n.id] = true; });
  fEdges = fEdges.filter(function(e) { return fSet[e.from] && fSet[e.to]; });
  // Cap: top 60 most-connected by default (was 250, still unreadable).
  var totalNodes = fNodes.length, totalEdges = fEdges.length;
  if (!gf.showAll && fNodes.length > 60) {
    var deg = {};
    fEdges.forEach(function(e) { deg[e.from] = (deg[e.from] || 0) + 1; deg[e.to] = (deg[e.to] || 0) + 1; });
    var keep = fNodes.slice().sort(function(a, b) { return (deg[b.id] || 0) - (deg[a.id] || 0); }).slice(0, 60);
    var keepSet = {};
    keep.forEach(function(n) { keepSet[n.id] = true; });
    fNodes = keep; fSet = keepSet;
    fEdges = fEdges.filter(function(e) { return keepSet[e.from] && keepSet[e.to]; });
  }
  // Columns by role: users | sources | pivots (stage order) |
  // destinations (severity, then id). Dedupe edges by pair+technique.
  var srcs = {}, dsts = {};
  fEdges.forEach(function(e) { srcs[e.from] = true; dsts[e.to] = true; });
  var stageOrder = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
  var stageIdx = function(n) { var i = stageOrder.indexOf(n.stage || ""); return i < 0 ? 99 : i; };
  var bySev = function(a, b) { var w = { Critical: 0, High: 1, Medium: 2, Low: 3, user: 4, technique: 5 }; return (w[sevOf(a)] - w[sevOf(b)]) || (a.id < b.id ? -1 : 1); };
  var cols = [[], [], [], []];
  fNodes.forEach(function(n) {
    if (n.type === "user") cols[0].push(n);
    else if (srcs[n.id] && dsts[n.id]) cols[2].push(n);
    else if (srcs[n.id]) cols[1].push(n);
    else cols[3].push(n);
  });
  cols[2].sort(function(a, b) { return stageIdx(a) - stageIdx(b) || bySev(a, b); });
  cols[1].sort(bySev); cols[3].sort(bySev); cols[0].sort(bySev);
  var colNames = ["Users", "Sources", "Pivots (moved through)", "Destinations"];
  var usedCols = [];
  cols.forEach(function(c, i) { if (c.length) usedCols.push(i); });
  var BW = 170, BH = 64, CW = 210, RH = 84;
  var maxRows = Math.max.apply(null, usedCols.map(function(i) { return cols[i].length; }));
  var W = usedCols.length * CW + 20, H = maxRows * RH + 20;
  var pos = {};
  usedCols.forEach(function(ci, colPos) {
    cols[ci].forEach(function(n, r) {
      pos[n.id] = { x: 10 + colPos * CW, y: 10 + r * RH };
    });
  });
  var nodeById = {};
  fNodes.forEach(function(n) { nodeById[n.id] = n; });
  var seenEdge = {};
  var svg = "<svg width='" + Math.round(W * gf.zoom) + "' height='" + Math.round(H * gf.zoom) + "' viewBox='0 0 " + W + " " + H + "' class='graph-svg' role='img' aria-label='Attack graph, left to right by role'>" +
    "<defs><marker id='arr2' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'><path d='M 0 0 L 10 5 L 0 10 z' fill='#6b7280'/></marker></defs>";
  fEdges.forEach(function(e) {
    var key = e.from + ">" + e.to + "|" + (e.technique_id || "");
    if (seenEdge[key]) return; seenEdge[key] = true;
    var a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    var col = sevColor[sevOf(nodeById[e.to])] || "#6b7280";
    if (nodeById[e.to] && nodeById[e.to].type === "user") col = "#2563eb";
    if (nodeById[e.to] && nodeById[e.to].type === "technique") col = "#7c3aed";
    svg += "<line x1='" + (a.x + BW) + "' y1='" + (a.y + BH / 2) + "' x2='" + b.x + "' y2='" + (b.y + BH / 2) + "' stroke='" + col + "' stroke-width='2' marker-end='url(#arr2)'/>";
    if (state.graphMode !== "quantum" && fEdges.length <= 60 && e.technique_id) {
      svg += "<text x='" + Math.round((a.x + BW + b.x) / 2) + "' y='" + Math.round((a.y + b.y) / 2 + BH / 2 - 4) + "' class='elabel'>" + esc(e.technique_id) + "</text>";
    }
  });
  fNodes.forEach(function(n) {
    var p = pos[n.id];
    var sev = sevOf(n);
    var stroke = n.type === "user" ? "#2563eb" : n.type === "technique" ? "#7c3aed" : (sevColor[sev] || "#6b7280");
    var fill = n.type === "user" ? "#e0efff" : n.type === "technique" ? "#f3e8ff" : (sevFill[sev] || "#fff");
    var label = n.id.length > 22 ? n.id.slice(0, 21) + "…" : n.id;
    var sub = n.type === "technique" && n.name ? n.name : (n.stage || n.type);
    svg += "<g class='gnode-wrap' data-node='" + esc(n.id) + "' tabindex='0' role='button' aria-label='Show steps for " + esc(n.id) + "'>" +
      "<title>" + esc(n.id) + " — " + esc(sub) + " — " + esc(sev) + "</title>" +
      "<rect x='" + p.x + "' y='" + p.y + "' width='" + BW + "' height='" + BH + "' rx='10' fill='" + fill + "' stroke='" + stroke + "' stroke-width='3'/>" +
      "<text x='" + (p.x + 10) + "' y='" + (p.y + 22) + "' class='nlabel'>" + esc(label) + "</text>" +
      "<text x='" + (p.x + 10) + "' y='" + (p.y + 40) + "' class='ntype'>" + esc(sub.length > 24 ? sub.slice(0, 23) + "…" : sub) + "</text>" +
      "<text x='" + (p.x + 10) + "' y='" + (p.y + 57) + "' class='nsev' fill='" + stroke + "'>" + esc(sev.toUpperCase()) + "</text></g>";
  });
  svg += "</svg>";
  var techOpts = ["All"];
  realEdges.forEach(function(e) { if (e.technique_id && techOpts.indexOf(e.technique_id) < 0) techOpts.push(e.technique_id); });
  var capNote = (!gf.showAll && totalNodes > 60) ? "<p class='hint'>Showing the 60 most-connected of " + fmtNum(totalNodes) + " nodes (" + fmtNum(fEdges.length) + " of " + fmtNum(totalEdges) + " edges). Use Show all below for the rest — the full step list and grouped report still cover everything.</p>" : "";
  var colNote = "<p class='hint'>Left to right: " + usedCols.map(function(i) { return colNames[i] + " (" + cols[i].length + ")"; }).join(" → ") + ".</p>";
  var zl = document.getElementById("zoomLabel");
  if (zl) zl.textContent = Math.round(gf.zoom * 100) + "%";
  box.innerHTML =
    "<div style='background:var(--canvas-bg);border:1px solid var(--border);border-radius:12px;padding:10px'>" +
    "<div style='margin-bottom:8px'>" +
    "<label>Technique: <select onchange=\"setGraphFilter('technique', this.value)\">" + techOpts.map(function(t) { return "<option" + (gf.technique === t ? " selected" : "") + ">" + esc(t) + "</option>"; }).join("") + "</select></label> " +
    "<label>Severity: <select onchange=\"setGraphFilter('severity', this.value)\">" + ["All", "Critical", "High", "Medium", "Low", "user", "technique"].map(function(t) { return "<option" + (gf.severity === t ? " selected" : "") + ">" + esc(t) + "</option>"; }).join("") + "</select></label> " +
    "<label>Find host/domain: <input value='" + esc(gf.search) + "' placeholder='e.g. 10.10.' onchange=\"setGraphFilter('search', this.value)\" style='width:140px'> (press Enter)</label> " +
    "<button class=btn onclick=\"setGraphFilter('showAll', " + (gf.showAll ? "false" : "true") + ")\">" + (gf.showAll ? "Show top 60" : "Show all") + "</button> " +
    "<button class=btn onclick=\"setGraphZoom(0.2)\">Zoom +</button> " +
    "<button class=btn onclick=\"setGraphZoom(-0.2)\">Zoom −</button> " +
    "<button class=btn onclick=\"setGraphFilter('zoom', 1)\">Reset zoom</button>" +
    "</div>" +
    "<p class='hint' style='margin:0 0 8px'>Colour = worst severity on that node — <span style='color:#e1251b'><b>Critical</b></span> · <span style='color:#f97316'><b>High</b></span> · <span style='color:#f0a832'><b>Medium</b></span> · <span style='color:#6b7280'><b>Low</b></span> · <span style='color:#2563eb'><b>user</b></span> · <span style='color:#7c3aed'><b>technique</b></span>. Edge label = MITRE technique (hidden when over 60 edges, to stay readable). Click a node to see its steps. Scroll inside the box to pan.</p>" +
    "<div style='overflow:auto;max-height:640px'>" + svg + "</div>" +
    capNote + colNote + "</div>";
  box.querySelectorAll(".gnode-wrap").forEach(function(el) {
    el.addEventListener("click", function() { showNodeSteps(path, el.getAttribute("data-node")); });
    el.addEventListener("keydown", function(e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showNodeSteps(path, el.getAttribute("data-node")); } });
  });
}

function renderAttackPathCanvas(path) {
  // ATTACK PATH CANVAS (2026-11-01, user demand: 'make this in canvas,
  // use the reference'). The old version listed the first 12 graph
  // nodes with arrows between them, which INVENTED a chain: for a star
  // incident those destinations are parallel, not sequential hops.
  // This canvas draws only real edges: sources on the left, pivots
  // (both a destination and a source, in stage order) in the middle,
  // destinations on the right as a fan-out, grouped by technique when
  // there are more than 8 of them. Annotation boxes on the right are
  // the real techniques/stages found in this incident (from the
  // timeline summary) — never invented CVEs, Kubernetes objects, or
  // hosts. Click a box to see its steps.
  var box = document.getElementById("path");
  var graph = path.graph || { nodes: [], edges: [] };
  var nodes = graph.nodes || [], edges = graph.edges || [];
  var nodeById = {};
  nodes.forEach(function(n) { nodeById[n.id] = n; });
  var pathEdges = edges.filter(function(e) { return e.kind === "path"; });
  var sevColor = { Critical: "#e1251b", High: "#f97316", Medium: "#f0a832", Low: "#6b7280" };
  var sevFill = { Critical: "#fde8e8", High: "#fef3e2", Medium: "#fef9e0", Low: "#f3f4f6" };
  var sevOf = function(n) { return n && n.type === "user" ? "user" : n && n.type === "technique" ? "technique" : (n && n.severity) || "Low"; };
  var techName = {};
  (path.timeline_summary || []).forEach(function(s) { techName[s.technique_id] = s.technique_name; });
  var stageOfTech = {};
  (path.timeline_summary || []).forEach(function(s) { stageOfTech[s.technique_id] = s.kill_chain_stage; });
  var srcs = {}, dsts = {};
  pathEdges.forEach(function(e) { srcs[e.from] = true; dsts[e.to] = true; });
  var sources = nodes.filter(function(n) { return n.type === "host" && srcs[n.id] && !dsts[n.id]; });
  var pivots = nodes.filter(function(n) { return n.type === "host" && srcs[n.id] && dsts[n.id]; });
  var dests = nodes.filter(function(n) { return n.type === "host" && dsts[n.id] && !srcs[n.id]; });
  var stageOrder = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
  pivots.sort(function(a, b) { var ia = stageOrder.indexOf(a.stage || ""), ib = stageOrder.indexOf(b.stage || ""); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  if (!pathEdges.length) {
    // No host-to-host edges (e.g. the sample): the honest path is the
    // STAGE PROGRESSION in time order, labelled as such — not host
    // hops. Draw one box per distinct stage, in kill-chain order.
    var stages = [];
    (path.timeline_summary || []).forEach(function(s) { if (s.kill_chain_stage && stages.indexOf(s.kill_chain_stage) < 0) stages.push(s.kill_chain_stage); });
    if (!stages.length) (path.timeline || []).forEach(function(s) { if (s.kill_chain_stage && stages.indexOf(s.kill_chain_stage) < 0) stages.push(s.kill_chain_stage); });
    var hostId = (nodes[0] && nodes[0].id) || (path.hosts && path.hosts[0]) || "Unknown host";
    box.innerHTML = "<canvas id='attackCanvas' width='1080' height='170' style='width:100%;height:auto;background:#f8f6f0;border:2px solid #333;border-radius:12px;display:block'></canvas>" +
      "<p class='hint'>No host-to-host movement in this incident — all steps happened on " + esc(hostId) + ". The canvas below shows the stage progression in time order, not host hops. Click a stage box to see its steps.</p>";
    var cv0 = document.getElementById("attackCanvas");
    var ctx0 = cv0.getContext("2d");
    drawAttackStageRow(ctx0, stages, path);
    return;
  }
  // Destination boxes: individual if few, grouped by technique if many.
  var destBoxes = [];
  if (dests.length <= 8) {
    dests.forEach(function(d) {
      var e = pathEdges.filter(function(x) { return x.to === d.id; })[0] || {};
      destBoxes.push({ id: d.id, label: d.id, sub: (stageOfTech[e.technique_id] || d.stage || "Destination"), sev: sevOf(d), tech: e.technique_id || "", count: 1 });
    });
  } else {
    var groups = {};
    dests.forEach(function(d) {
      var e = pathEdges.filter(function(x) { return x.to === d.id; })[0] || {};
      var key = e.technique_id || "unknown";
      if (!groups[key]) groups[key] = { tech: key, name: techName[key] || key, stage: stageOfTech[key] || d.stage || "", sev: "Low", count: 0, examples: [] };
      groups[key].count += 1;
      if (groups[key].examples.length < 3) groups[key].examples.push(d.id);
      var w = { Critical: 40, High: 25, Medium: 10, Low: 3 };
      if (w[sevOf(d)] > w[groups[key].sev]) groups[key].sev = sevOf(d);
    });
    Object.keys(groups).forEach(function(k) {
      var g = groups[k];
      destBoxes.push({ id: g.tech, label: g.name, sub: g.stage + " · " + g.count + " destinations", sev: g.sev, tech: g.tech, count: g.count, examples: g.examples });
    });
  }
  var srcBoxes = sources.slice(0, 5).map(function(n) { return { id: n.id, label: n.id, sub: n.stage || "Source", sev: sevOf(n), tech: "", count: 1 }; });
  var pivBoxes = pivots.slice(0, 5).map(function(n) { return { id: n.id, label: n.id, sub: n.stage || "Pivot", sev: sevOf(n), tech: "", count: 1 }; });
  var dstBoxes = destBoxes.slice(0, 6);
  var rows = Math.max(srcBoxes.length, pivBoxes.length, dstBoxes.length, 1);
  var H = rows * 92 + 30, W = 1080;
  box.innerHTML = "<canvas id='attackCanvas' width='" + W + "' height='" + H + "' style='width:100%;height:auto;background:#f8f6f0;border:2px solid #333;border-radius:12px;display:block'></canvas>" +
    "<p class='hint'>Arrows are real log edges only — destinations fan out in parallel from their source, they are NOT sequential hops unless a pivot connects them. " +
    (sources.length > 5 ? "Showing 5 of " + sources.length + " sources. " : "") +
    (pivots.length > 5 ? "Showing 5 of " + pivots.length + " pivots. " : "") +
    (destBoxes.length > 6 ? "Showing 6 of " + destBoxes.length + " destination groups. " : "") +
    "Full list: see the graph map and step list below. Click a box to see its steps.</p>";
  var cv = document.getElementById("attackCanvas");
  var isDark = document.documentElement.getAttribute("data-theme") === "dark";
  var dpr = window.devicePixelRatio || 1;
  cv.width = W * dpr; cv.height = H * dpr;
  var ctx = cv.getContext("2d");
  ctx.scale(dpr, dpr);
  // Dotted-paper background, like the reference canvas.
  ctx.fillStyle = isDark ? "#18181b" : "#f8f6f0"; ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = isDark ? "#3f3f46" : "#d8d2c2";
  for (var gx = 9; gx < W; gx += 18) for (var gy = 9; gy < H; gy += 18) { ctx.beginPath(); ctx.arc(gx, gy, 1, 0, 2 * Math.PI); ctx.fill(); }
  var BW = 230, BH = 68, cols = [{ x: 20, boxes: srcBoxes, name: "SOURCE" }, { x: 320, boxes: pivBoxes, name: "PIVOT" }, { x: 620, boxes: dstBoxes, name: "DESTINATIONS" }];
  if (!pivBoxes.length) cols = [{ x: 20, boxes: srcBoxes, name: "SOURCE" }, { x: 620, boxes: dstBoxes, name: "DESTINATIONS" }];
  var rects = [];
  var drawBox = function(x, y, b) {
    var stroke = b.sev === "user" ? "#2563eb" : b.sev === "technique" ? "#7c3aed" : (sevColor[b.sev] || "#6b7280");
    var fill = sevFill[b.sev] || "#fff";
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(x, y, BW, BH, 10); else ctx.rect(x, y, BW, BH);
    ctx.fillStyle = fill; ctx.fill(); ctx.strokeStyle = stroke; ctx.lineWidth = 3; ctx.stroke();
    ctx.fillStyle = isDark ? "#f4f4f5" : "#111"; ctx.font = "bold 13px system-ui, sans-serif";
    var lab = b.label.length > 26 ? b.label.slice(0, 25) + "…" : b.label;
    ctx.fillText(lab, x + 12, y + 24);
    ctx.fillStyle = isDark ? "#a1a1aa" : "#555"; ctx.font = "11px system-ui, sans-serif";
    var sub = (b.sub || "").length > 30 ? b.sub.slice(0, 29) + "…" : (b.sub || "");
    ctx.fillText(sub, x + 12, y + 42);
    ctx.fillStyle = stroke; ctx.font = "bold 11px system-ui, sans-serif";
    ctx.fillText((b.sev || "").toUpperCase() + (b.count > 1 ? " · ×" + b.count : ""), x + 12, y + 58);
    rects.push({ x: x, y: y, w: BW, h: BH, id: b.id });
    if (b.examples) {
      ctx.fillStyle = "#555"; ctx.font = "10px ui-monospace, monospace";
      ctx.fillText(b.examples.join(", "), x + 12, y + BH + 14);
    }
  };
  var drawArrow = function(x1, y1, x2, y2, col) {
    ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    ctx.fillStyle = col; ctx.beginPath(); ctx.moveTo(x2, y2); ctx.lineTo(x2 - 10, y2 - 4); ctx.lineTo(x2 - 10, y2 + 4); ctx.closePath(); ctx.fill();
  };
  cols.forEach(function(c) {
    ctx.fillStyle = isDark ? "#a1a1aa" : "#888"; ctx.font = "bold 11px system-ui, sans-serif";
    ctx.fillText(c.name, c.x, 18);
    c.boxes.forEach(function(b, i) { drawBox(c.x, 26 + i * 92, b); });
  });
  // Arrows: source -> pivot (if any) -> destinations, and source ->
  // destinations directly. One arrow per box pair, not per detection.
  var srcY = function(i) { return 26 + i * 92 + BH / 2; };
  var pivY = function(i) { return 26 + i * 92 + BH / 2; };
  var dstY = function(i) { return 26 + i * 92 + BH / 2; };
  if (pivBoxes.length) {
    srcBoxes.forEach(function(s, i) { drawArrow(20 + BW, srcY(i), 320, pivY(0), "#6b7280"); });
    pivBoxes.forEach(function(p, i) { dstBoxes.forEach(function(d, j) { drawArrow(320 + BW, pivY(i), 620, dstY(j), "#6b7280"); }); });
  } else {
    srcBoxes.forEach(function(s, i) { dstBoxes.forEach(function(d, j) { drawArrow(20 + BW, srcY(i), 620, dstY(j), "#6b7280"); }); });
  }
  state.attackRects = rects;
  cv.addEventListener("click", function(ev) {
    var r = cv.getBoundingClientRect();
    var x = (ev.clientX - r.left) * (W / r.width), y = (ev.clientY - r.top) * (H / r.height);
    var hit = null;
    rects.forEach(function(rc) { if (x >= rc.x && x <= rc.x + rc.w && y >= rc.y && y <= rc.y + rc.h) hit = rc; });
    if (hit) showNodeSteps(path, hit.id);
  });
}

function drawAttackStageRow(ctx, stages, path) {
  var isDark = document.documentElement.getAttribute("data-theme") === "dark";
  var W = 1080, BH = 64, gap = 30;
  var BW = Math.min(200, Math.floor((W - 40 - (stages.length - 1) * gap) / Math.max(1, stages.length)));
  ctx.fillStyle = isDark ? "#18181b" : "#f8f6f0"; ctx.fillRect(0, 0, W, 170);
  ctx.fillStyle = isDark ? "#3f3f46" : "#d8d2c2";
  for (var gx = 9; gx < W; gx += 18) for (var gy = 9; gy < 170; gy += 18) { ctx.beginPath(); ctx.arc(gx, gy, 1, 0, 2 * Math.PI); ctx.fill(); }
  var total = stages.length * (BW + gap) - gap;
  var x0 = Math.max(20, (W - total) / 2);
  var rects = [];
  stages.forEach(function(s, i) {
    var x = x0 + i * (BW + gap), y = 50;
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(x, y, BW, BH, 10); else ctx.rect(x, y, BW, BH);
    ctx.fillStyle = isDark ? "#27272a" : "#fff"; ctx.fill(); ctx.strokeStyle = "#e1251b"; ctx.lineWidth = 3; ctx.stroke();
    ctx.fillStyle = isDark ? "#f4f4f5" : "#111"; ctx.font = "bold 13px system-ui, sans-serif";
    ctx.fillText(s.length > 24 ? s.slice(0, 23) + "…" : s, x + 12, y + 28);
    ctx.fillStyle = "#555"; ctx.font = "11px system-ui, sans-serif";
    ctx.fillText("Stage " + (i + 1) + " of " + stages.length, x + 12, y + 48);
    rects.push({ x: x, y: y, w: BW, h: BH, id: s });
    if (i < stages.length - 1) {
      ctx.strokeStyle = "#f0a832"; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(x + BW, y + BH / 2); ctx.lineTo(x + BW + gap, y + BH / 2); ctx.stroke();
      ctx.fillStyle = "#f0a832"; ctx.beginPath(); ctx.moveTo(x + BW + gap, y + BH / 2); ctx.lineTo(x + BW + gap - 10, y + BH / 2 - 4); ctx.lineTo(x + BW + gap - 10, y + BH / 2 + 4); ctx.closePath(); ctx.fill();
    }
  });
  var cv = document.getElementById("attackCanvas");
  state.attackRects = rects;
  cv.addEventListener("click", function(ev) {
    var r = cv.getBoundingClientRect();
    var x = (ev.clientX - r.left) * (W / r.width), y = (ev.clientY - r.top) * (170 / r.height);
    rects.forEach(function(rc) {
      if (x >= rc.x && x <= rc.x + rc.w && y >= rc.y && y <= rc.y + rc.h) {
        var idx = (path.timeline || []).findIndex(function(s) { return s.kill_chain_stage === rc.id; });
        if (idx >= 0) showStep(path, idx);
      }
    });
  });
}

function showNodeSteps(path, nodeId) {
  document.querySelectorAll(".gnode-wrap").forEach(function(el) {
    el.classList.toggle("sel", el.getAttribute("data-node") === nodeId);
  });
  var steps = path.timeline.map(function(s, i) { return { s: s, i: i }; }).filter(function(x) {
    return x.s.host === nodeId || x.s.user === nodeId || x.s.technique_id === nodeId;
  });
  if (!steps.length) {
    document.getElementById("stepDetail").innerHTML = "<p>No steps on " + esc(nodeId) + ".</p>";
    return;
  }
  var shown = steps.slice(0, 100);
  document.getElementById("stepDetail").innerHTML =
    "<b>Node: " + esc(nodeId) + "</b> — " + steps.length + " step(s) in this incident" +
    (steps.length > 100 ? " (showing the first 100 — the rest repeat the same techniques)" : "") + ". Click a step to inspect it.<br>" +
    shown.map(function(x) {
      return "<button class='btn ghost step-link' data-i='" + x.i + "'>" + (x.i + 1) + ". " + esc(x.s.kill_chain_stage) + " — " +
        esc(x.s.technique_id) + " " + esc(x.s.technique_name) + " (" + esc(x.s.time) + ")</button>";
    }).join(" ");
  document.querySelectorAll(".step-link").forEach(function(el) {
    el.addEventListener("click", function() { showStep(path, parseInt(el.getAttribute("data-i"), 10)); });
  });
  document.getElementById("stepDetail").scrollIntoView({ behavior: "smooth", block: "center" });
}

function showStep(path, i) {
  var step = path.timeline[i];
  document.querySelectorAll(".pkg").forEach(function(el) {
    el.classList.toggle("sel", parseInt(el.getAttribute("data-i"), 10) === i);
    el.setAttribute("aria-pressed", parseInt(el.getAttribute("data-i"), 10) === i ? "true" : "false");
  });
  // Never show a blank User/Source, and never repeat the action as
  // the detail ("Phishing Attempts — Phishing Attempts /").
  var what = (step.action || "").trim();
  var det = (step.detail || "").trim();
  if (det && det !== what) {
    if (what && det.indexOf(what) === 0) det = det.slice(what.length).replace(/^[\s\/\-:]+/, "");
    what = what ? what + (det ? " — " + det : "") : det;
  }
  document.getElementById("stepDetail").innerHTML =
    "<b>Step " + (i + 1) + " — " + esc(step.kill_chain_stage) + "</b><br>" +
    esc(step.technique_id) + " — " + esc(step.technique_name) + " (" + step.confidence + "% confidence, " + esc(step.severity) + ")<br>" +
    esc(what || "No action text in the log") + "<br><small>Time: " + esc(step.time) + " &middot; Host: " + esc(step.host || "Unknown") +
    " &middot; User: " + esc(step.user || "Unknown") + " &middot; Source: " + esc(step.source || "Unknown") + "<br>Why this flagged: " + esc(step.reason) + "</small>";
  document.getElementById("stepDetail").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function showReport() {
  var langSel = document.getElementById("reportLang");
  var lang = langSel ? langSel.value : "en";
  var box = document.getElementById("report");
  var warn = document.getElementById("reportWarning");
  if (!state.selected) return;
  if (lang === "en") {
    box.textContent = state.report;
    if (warn) warn.hidden = true;
    return;
  }
  try {
    var rep = await (await fetch("/incidents/" + state.selected.id + "/report?lang=" + lang)).json();
    var tr = rep.translated || {};
    box.textContent = tr.text || state.report;
    if (warn) {
      if (tr.warning) { warn.hidden = false; warn.textContent = tr.warning; }
      else if (tr.source === "sarvam") { warn.hidden = false; warn.textContent = "Report — by Sarvam AI (" + lang + ")."; }
      else warn.hidden = true;
    }
  } catch (e) {
    box.textContent = state.report;
    if (warn) { warn.hidden = false; warn.textContent = "Translation could not be loaded — showing the English report."; }
  }
}
var reportLangSel = document.getElementById("reportLang");
if (reportLangSel) reportLangSel.addEventListener("change", showReport);
document.getElementById("copyBtn").addEventListener("click", function() {
  var txt = document.getElementById("report").textContent;
  if (txt) navigator.clipboard.writeText(txt).then(function() { alert("Report copied."); });
});
var pdfBtn = document.getElementById("pdfBtn");
if (pdfBtn) pdfBtn.addEventListener("click", function() {
  if (!state.selected) return;
  var langSel = document.getElementById("reportLang");
  var lang = langSel ? langSel.options[langSel.selectedIndex].text : "English";
  var txt = document.getElementById("report").textContent;
  var w = window.open("", "_blank");
  if (!w) { alert("Allow pop-ups for this page, then try Generate PDF again."); return; }
  w.document.write("<!doctype html><html><head><meta charset='utf-8'><title>ASK Incident Report</title>" +
    "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 20px;line-height:1.6}h1{font-size:22px}</style></head><body>" +
    "<h1>ASK — Incident #" + state.selected.id + " report (" + esc(lang) + ")</h1>" +
    "<p>" + esc(state.selected.title || "") + "</p><pre style='white-space:pre-wrap'>" + esc(txt) + "</pre>" +
    "<p>Generated from the ASK dashboard. Choose Save as PDF in the print dialog.</p>" +
    "<script>window.onload = function(){ window.print(); };<" + "/script></body></html>");
  w.document.close();
});

var drop = document.getElementById("drop"), fileInput = document.getElementById("file");
drop.addEventListener("click", function() { fileInput.click(); });
drop.addEventListener("keydown", function(e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
drop.addEventListener("dragover", function(e) { e.preventDefault(); });
drop.addEventListener("drop", function(e) { e.preventDefault(); if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); });
fileInput.addEventListener("change", function() { if (fileInput.files.length) handleFile(fileInput.files[0]); });

function fmtNum(n) { return Number(n || 0).toLocaleString("en-US"); }

function showBackendStatus(p, file) {
  var el = document.getElementById("backendStatus");
  el.hidden = false;
  var bar = document.getElementById("bar");
  // SYSTEM LINE (2026-11-01): elapsed/total time + CPU + RAM + ASK
  // memory, on every progress poll. Elapsed was tracked by the
  // backend all along but never shown; CPU/RAM were never shown at
  // all (only a CLI peak-RSS print at the end). RAM is system RAM
  // (the Task Manager number); ASK is the main server process only —
  // parallel workers are separate processes, so it is a lower bound.
  var sys = "";
  if (p.elapsed_text) sys += " · Elapsed " + p.elapsed_text;
  if (p.cpu_percent !== undefined && p.cpu_percent !== null) sys += " · CPU " + p.cpu_percent + "%";
  if (p.ram_total_mb) sys += " · RAM " + (p.ram_used_mb / 1024).toFixed(1) + "/" + (p.ram_total_mb / 1024).toFixed(1) + " GB (" + p.ram_percent + "%)";
  if (p.ask_rss_mb) sys += " · ASK (main) " + p.ask_rss_mb + " MB";
  if (p.stage === "generating" && p.bytes_total > 0) {
    var pct = Math.min(100, Math.round(100 * p.bytes_received / p.bytes_total));
    bar.style.width = pct + "%";
    el.textContent = p.stage_text + " · " + fmtNum(p.bytes_received) + " of " + fmtNum(p.bytes_total) + " bytes (" + pct + "%)" + sys + ".";
  } else if (p.stage === "uploading" && p.bytes_total > 0) {
    var pct = Math.min(100, Math.round(100 * p.bytes_received / p.bytes_total));
    bar.style.width = pct + "%";
    el.textContent = p.stage_text + " · " + fmtNum(p.bytes_received) + " of " + fmtNum(p.bytes_total) + " bytes (" + pct + "%)" + sys + ".";
  } else if (p.stage === "reading" && p.estimated_total_events > 0) {
    var pct2 = Math.min(99, Math.round(100 * p.events / p.estimated_total_events));
    bar.style.width = pct2 + "%";
    el.textContent = p.stage_text + " · " + fmtNum(p.events) + " lines (about " + pct2 + "% of an estimated " +
      fmtNum(p.estimated_total_events) + ") · " + fmtNum(p.detections) + " detections · " +
      fmtNum(Math.round(p.events_per_second)) + " lines/sec" +
      (p.eta_text ? " · ETA " + p.eta_text : " · ETA estimating…") + sys + ".";
  } else if (p.stage === "linking" || p.stage === "storing") {
    bar.style.width = "99%";
    el.textContent = p.stage_text + " · " + fmtNum(p.events) + " lines · " + fmtNum(p.detections) + " detections" + sys + ".";
  } else if (p.stage === "done") {
    bar.style.width = "100%";
    el.textContent = p.stage_text + sys + ".";
  } else if (p.error) {
    el.textContent = "Error: " + p.error;
  } else {
    el.textContent = p.stage_text + sys + ".";
  }
  if (file && file.size > 2 * 1024 * 1024 * 1024) {
    el.textContent += " This is a very large file — keep this tab open, it will take a while.";
  }
  // Dynamic live slab: the place itself is ALWAYS visible during a
  // run (uploading, reading, linking, storing, and after done), so
  // it can never look "not there". Before the first find it shows a
  // placeholder; once finds exist it lists them, updating every poll.
  var slab = document.getElementById("liveTells");
  var list = document.getElementById("liveTellsList");
  if (slab && (p.stage === "uploading" || p.stage === "reading" || p.stage === "linking" || p.stage === "storing" || p.stage === "done")) {
    slab.hidden = false;
    if (p.top_techniques && p.top_techniques.length) {
      // ONE FLOWING PARAGRAPH (2026-11-01, user demand, corrected:
      // heading WITH the rule number, then the MEANING of the attack
      // (from the MITRE index, not the old 'the attacker got in'
      // stage rhetoric), then how to prevent it — all in one flow,
      // no full stops or labels between the parts. Example:
      // 'Phishing (T1566.001) — adversaries may send spearphishing
      // emails with a malicious attachment in an attempt to gain
      // access to victim systems, block the sender domain, quarantine
      // the attachment, and reset the password of anyone who opened
      // it, turn on attachment sandboxing for mail.'
      list.innerHTML = p.top_techniques.map(function(t) {
        var shortName = (t.technique_name || "").split(":")[0].trim() || t.technique_name;
        var heading = shortName + (t.technique_id ? " (" + t.technique_id + ")" : "");
        var flow = function(s) {
          s = (s || "").replace(/\.\s+/g, ", ").replace(/\.$/, "");
          return s.split(", ").map(function(part) {
            return part.charAt(0).toLowerCase() + part.slice(1);
          }).join(", ");
        };
        var meaning = t.meaning || t.technique_name || "";
        return "<div class='card dark' style='margin:8px 0;padding:12px'><b>" + esc(heading) + "</b> — " +
          flow(meaning) + ", " + flow(t.help) + ".</div>";
      }).join("");
    } else if (p.stage === "uploading") {
      list.innerHTML = "<p class='hint'>Still receiving your file — no lines have been checked yet, so no finds to show. As soon as reading starts, the attacks found so far will appear here, one card per attack.</p>";
    } else if (p.stage === "reading") {
      list.innerHTML = "<p class='hint'>Reading… no attacks found yet in the lines checked so far. The first find will appear here as soon as it is detected.</p>";
    } else {
      list.innerHTML = "<p class='hint'>Linking the finds into incidents… the final top attacks will stay here when the run finishes.</p>";
    }
  }
}

function handleFile(file) {
  document.getElementById("bar").style.width = "5%";
  document.getElementById("fileinfo").textContent = "Uploading and processing " + file.name + " on the backend…";
  // Poll /progress while the upload request runs: the server answers
  // that endpoint from another thread, so the status stays live even
  // while the big upload itself is still being processed.
  var pollFails = 0;
  var poll = setInterval(function() {
    fetch("/progress").then(function(r) { return r.json(); }).then(function(p) {
      pollFails = 0;
      showBackendStatus(p, file);
    }).catch(function() {
      // Old behaviour was silence here: if the server died, the page
      // froze on the last progress text forever and looked "stuck".
      // After 3 failed polls, say so plainly instead.
      pollFails += 1;
      if (pollFails >= 3) {
        var el2 = document.getElementById("backendStatus");
        el2.hidden = false;
        el2.textContent = "Server not responding — the server may have stopped or crashed. Check the server window (run.bat / run.sh) and restart it if needed, then upload again. Your file was not lost from your computer, only this run did not finish.";
      }
    });
  }, 1000);
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/upload", true);
  xhr.setRequestHeader("X-Filename", file.name);
  xhr.upload.onprogress = function(e) {
    if (e.lengthComputable) {
      document.getElementById("bar").style.width = Math.round(100 * e.loaded / e.total) + "%";
      showBackendStatus({ stage: "uploading", stage_text: "Step 1 of 4 — Receiving",
        bytes_received: e.loaded, bytes_total: e.total }, file);
    }
  };
  xhr.onload = async function() {
    clearInterval(poll);
    var data = {};
    try { data = JSON.parse(xhr.responseText); } catch (e) { data = { error: "Bad response from server." }; }
    document.getElementById("bar").style.width = "100%";
    if (data.error) {
      document.getElementById("fileinfo").textContent = "Error: " + data.error;
      return;
    }
    document.getElementById("fileinfo").textContent = file.name + " — " + data.events + " lines, " + data.detections +
      " detections, " + data.incidents + " incidents, in " + data.seconds + "s. Nothing was stored except the database on this machine.";
    // Final line keeps the total time and peak memory — the old
    // 'Done — …' text that overwrote the poll's done line (and with
    // it the elapsed/CPU/RAM line) is removed, not kept.
    document.getElementById("backendStatus").textContent = "Done in " + data.seconds + "s — " + data.events + " lines, " + data.detections +
      " detections, " + data.incidents + " incidents. Peak ASK memory: " + (data.peak_rss_mb || 0) + " MB.";
    await loadIncidents();
    if (state.incidents.length) selectIncident(state.incidents[0].id);
  };
  xhr.onerror = function() {
    clearInterval(poll);
    document.getElementById("fileinfo").textContent = "Upload failed — the server could not be reached.";
  };
  xhr.send(file);
}

// Load Sample / Tiny Demo: POST /sample or /tiny, server runs that
// small file through the same pipeline, then the list refreshes.
function runServerJob(endpoint, infoText) {
  document.getElementById("bar").style.width = "5%";
  document.getElementById("fileinfo").textContent = infoText;
  var poll = setInterval(function() {
    fetch("/progress").then(function(r) { return r.json(); }).then(function(p) { showBackendStatus(p, null); }).catch(function() {});
  }, 1000);
  fetch(endpoint, { method: "POST" }).then(function(r) { return r.json(); }).then(async function(data) {
    clearInterval(poll);
    document.getElementById("bar").style.width = "100%";
    if (data.error) {
      document.getElementById("fileinfo").textContent = "Error: " + data.error;
      return;
    }
    document.getElementById("fileinfo").textContent = (data.events || 0) + " lines, " + (data.detections || 0) +
      " detections, " + (data.incidents || 0) + " incidents, in " + (data.seconds || 0) + "s.";
    await loadIncidents();
    if (state.incidents.length) selectIncident(state.incidents[0].id);
  }).catch(function() {
    clearInterval(poll);
    document.getElementById("fileinfo").textContent = "Failed — the server could not be reached.";
  });
}
var sampleBtn = document.getElementById("sampleBtn");
if (sampleBtn) sampleBtn.addEventListener("click", function() { runServerJob("/sample", "Loading the repo sample log…"); });
var tinyBtn = document.getElementById("tinyBtn");
if (tinyBtn) tinyBtn.addEventListener("click", function() { runServerJob("/tiny", "Loading the tiny demo (5 rows, synthetic)…"); });

/* Demo button (2026-11-01): POST /demo, server generates ~100 MB
   synthetic log and processes it like an upload. Polls /progress
   the same way handleFile does. */
var demoBtn = document.getElementById("demoBtn");
if (demoBtn) {
  demoBtn.addEventListener("click", async function() {
    demoBtn.disabled = true;
    document.getElementById("bar").style.width = "5%";
    document.getElementById("fileinfo").textContent = "Generating demo (synthetic, about 100 MB) on the backend…";
    var pollFails = 0;
    var poll = setInterval(function() {
      fetch("/progress").then(function(r) { return r.json(); }).then(function(p) {
        pollFails = 0;
        showBackendStatus(p, null);
      }).catch(function() {
        pollFails += 1;
        if (pollFails >= 3) {
          var el2 = document.getElementById("backendStatus");
          el2.hidden = false;
          el2.textContent = "Server not responding — check the server window (run.bat / run.sh) and restart it if needed, then try Demo again.";
        }
      });
    }, 1000);
    try {
      var res = await fetch("/demo", { method: "POST" });
      var data = await res.json();
      clearInterval(poll);
      document.getElementById("bar").style.width = "100%";
      if (data.error) {
        document.getElementById("fileinfo").textContent = "Demo error: " + data.error;
      } else {
        document.getElementById("fileinfo").textContent = "Demo (synthetic) — " + data.events + " lines, " + data.detections +
          " detections, " + data.incidents + " incidents, in " + data.seconds + "s. Nothing was stored except the database on this machine.";
        document.getElementById("backendStatus").textContent = "Done in " + data.seconds + "s — " + data.events + " lines, " + data.detections +
          " detections, " + data.incidents + " incidents. Peak ASK memory: " + (data.peak_rss_mb || 0) + " MB.";
        await loadIncidents();
        if (state.incidents.length) selectIncident(state.incidents[0].id);
      }
    } catch (e) {
      clearInterval(poll);
      document.getElementById("fileinfo").textContent = "Demo failed — the server could not be reached.";
    }
    demoBtn.disabled = false;
  });
}

loadIncidents();

// Left-panel search: hide incident buttons that do not match, without
// re-rendering the list (re-rendering on every keystroke used to
// steal focus from the search box).
var incidentSearch = document.getElementById("incidentSearch");
if (incidentSearch) {
  incidentSearch.addEventListener("input", function() {
    var q = incidentSearch.value.toLowerCase();
    document.querySelectorAll(".inc").forEach(function(el) {
      el.style.display = !q || el.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none";
    });
  });
}

// Mode toggle: Kill Chain (full graph) vs Quantum Walk (frontier
// subgraph only — see renderGraph). No invented probabilities.
document.querySelectorAll(".mode-btn").forEach(function(btn) {
  btn.addEventListener("click", function() {
    document.querySelectorAll(".mode-btn").forEach(function(b) { b.classList.remove("active"); });
    btn.classList.add("active");
    state.graphMode = btn.getAttribute("data-mode");
    var banner = document.getElementById("modeBanner");
    var plain = document.getElementById("modePlain");
    if (state.graphMode === "quantum") {
      if (banner) banner.textContent = "QUANTUM WALK: Classical look-ahead from the observed graph — frontier hosts, not a Qiskit simulation";
      if (plain) plain.textContent = "Quantum Walk graph, in plain words: the same computers, but now only the frontier is shown — hosts already contacted that the attacker could move to next, with the hosts they were reached from. It answers one question: where will the attacker go next, from what we actually observed?";
    } else {
      if (banner) banner.textContent = "KILL CHAIN ANALYSIS: Tracking MITRE ATT&CK progression & lateral traversal";
      if (plain) plain.textContent = "Kill Chain graph, in plain words: each box is a computer (IP). An arrow means traffic went from one computer to another. Amber arrows are attack steps, in order: first access, then running code, then stealing passwords, then moving sideways, then reaching the target. Follow the amber arrows to read the attack story.";
    }
    if (state.selected) renderGraph(state.selected);
  });
});

// Center zoom controls (graph zoom lives in renderGraph's state).
function zoomStep(d) { if (window.setGraphZoom) window.setGraphZoom(d); }
var zIn = document.getElementById("zoomIn");
if (zIn) zIn.addEventListener("click", function() { zoomStep(0.2); });
var zOut = document.getElementById("zoomOut");
if (zOut) zOut.addEventListener("click", function() { zoomStep(-0.2); });
var zReset = document.getElementById("zoomReset");
if (zReset) zReset.addEventListener("click", function() { if (window.setGraphFilter) window.setGraphFilter("zoom", 1); });

// Corridor button: dashboard simulation only, never a real isolation.
var corridorBtn = document.getElementById("corridorBtn");
if (corridorBtn) {
  corridorBtn.addEventListener("click", function() {
    corridorBtn.textContent = "Attack Path Severed & Quarantined";
    corridorBtn.disabled = true;
    var note = document.getElementById("corridorNote");
    if (note) note.textContent = "Incident marked contained in this dashboard only. No real host was isolated and no firewall rule was changed.";
  });
}

const clearBtn = document.getElementById("clearBtn");
const clearStatus = document.getElementById("clearStatus");
if (clearBtn) {
  clearBtn.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to completely clear the database?")) return;
    clearBtn.disabled = true;
    if (clearStatus) clearStatus.textContent = "Clearing...";
    try {
      const res = await fetch("/clear", { method: "POST" });
      const data = await res.json();
      if (data.status === "ok") {
        if (clearStatus) clearStatus.textContent = "Database cleared!";
        setTimeout(() => { window.location.reload(); }, 600);
      }
    } catch (e) {
      alert("Failed to clear database: " + e.message);
      clearBtn.disabled = false;
      if (clearStatus) clearStatus.textContent = "";
    }
  });
}
