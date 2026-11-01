"use strict";
var state = { incidents: [], selected: null, report: "", fullReport: "", fullTranslated: null, hindi: null };

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem("ask_theme", theme); } catch (e) {}
  var btn = document.getElementById("themeBtn");
  if (btn) btn.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
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

// HIDE-QUEUE BAR (2026-11-01, user: hide the whole incidents
// column): Hide in the queue head hides the whole left column
// and shows the slim left-edge bar; clicking that bar brings it
// back. Choice is saved, so a reload keeps it as you left it.
(function initQueueToggle() {
  var ws = document.getElementById("workspace");
  var hideBtn = document.getElementById("hideQueueBtn");
  var showBtn = document.getElementById("showQueueBtn");
  if (!ws || !hideBtn || !showBtn) return;
  var setHidden = function(hidden) {
    ws.classList.toggle("hide-left", hidden);
    showBtn.hidden = !hidden;
    try { localStorage.setItem("ask_hide_queue", hidden ? "1" : "0"); } catch (e) {}
  };
  hideBtn.addEventListener("click", function() { setHidden(true); });
  showBtn.addEventListener("click", function() { setHidden(false); });
  var saved = null;
  try { saved = localStorage.getItem("ask_hide_queue"); } catch (e) {}
  if (saved === "1") setHidden(true);
})();

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
  // Live update: every 5 seconds, check only /health (one cheap count
  // query). If nothing changed, do nothing - no page reload, no
  // flicker, and the incident you are reading is never disturbed.
  // No live-status text is shown on the page any more (2026-11-01):
  // the list itself refreshes silently when the counts change, which
  // is also how a finished Load Sample run appears.
  if (!state.liveTimer) {
    state.liveTimer = setInterval(async function() {
      try {
        var h = await (await fetch("/health")).json();
        var sig = h.detections + "/" + h.incidents;
        if (sig !== state.lastHealth) {
          await loadIncidents();
        }
      } catch (e) { /* server down: keep the page, stop spamming */ }
    }, 5000);
  }
  // TIER FILTER (2026-11-01, user demand: 'keep it simple, don't
  // display so many'). Incidents are grouped by tier - Critical
  // (>=90), High (70-89), Medium (40-69), Low (<40) - with a button
  // per tier showing its count, plus All. List is sorted by risk
  // descending, then steps descending, so the worst incidents are
  // first instead of a flat 700-card wall in id order.
  // Tiers match the backend risk_tier(): Critical 90-100, High
  // 70-89, Medium 40-69, Low 0-39. Low is its own tier now - a
  // Low-severity incident must never be folded into Medium/Elevated.
  function tierOf(s) { return s >= 90 ? "Critical" : s >= 70 ? "High" : s >= 40 ? "Medium" : "Low"; }
  var sorted = list.slice().sort(function(a, b) {
    return (b.risk_score - a.risk_score) || (b.detection_count - a.detection_count) || (a.id - b.id);
  });
  var counts = { All: sorted.length, Critical: 0, High: 0, Medium: 0, Low: 0 };
  sorted.forEach(function(i) { counts[tierOf(i.risk_score)] += 1; });
  if (!state.tierFilter) state.tierFilter = "All";
  window.setTierFilter = function(t) { state.tierFilter = t; loadIncidents(); };
  var shown = state.tierFilter === "All" ? sorted : sorted.filter(function(i) { return tierOf(i.risk_score) === state.tierFilter; });
  var filterHtml = "<div class=tier-track>" + ["All", "Critical", "High", "Medium", "Low"].map(function(t) {
    var sel = state.tierFilter === t ? " active" : "";
    return "<button class='tier-btn" + sel + "' onclick=\"setTierFilter('" + t + "')\">" + t + " (" + counts[t] + ")</button>";
  }).join("") + "</div>";
  function timeAgo(ts) {
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts || "";
    var mins = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
    if (mins < 1) return "just now";
    if (mins < 60) return mins + " min ago";
    if (mins < 1440) return Math.round(mins / 60) + " h ago";
    return Math.round(mins / 1440) + " d ago";
  }
  // Palette (2026-11-01): black, white and one green only, plus
  // black/white greys for the lower tiers - no red/orange/amber/blue.
  var _td = document.documentElement.getAttribute("data-theme") === "dark";
  var tierColor = _td ? { Critical: "#f4f4f5", High: "#34d399", Medium: "#a1a1aa", Low: "#57534e" } : { Critical: "#111111", High: "#00a66a", Medium: "#57534e", Low: "#a8a29e" };
  document.getElementById("incidents").innerHTML = (filterHtml + (shown.length ? shown.map(function(inc) {
    var tier = tierOf(inc.risk_score);
    return "<button class=inc data-id=" + inc.id + " data-tier=\"" + tier + "\" title=\"" + esc(inc.start_time || "") + "\">" +
      "<span class=inc-score style='color:" + tierColor[tier] + "'>" + (inc.risk_score / 10).toFixed(1) + "<small>/10</small></span>" +
      "<span class=inc-body><span class=inc-head><b>INC-" + inc.id + "</b><span class=inc-time>" + timeAgo(inc.start_time) + "</span></span>" +
      "<span class=inc-title>" + esc(inc.title) + "</span>" +
      "<span class=inc-meta>" + esc(inc.hosts.join(", ")) + " &middot; " + tier + " &middot; " +
      inc.detection_count + " steps &middot; " + inc.merged_alerts + " raw alerts merged</span></span></button>";
  }).join("") : "<p>No " + esc(state.tierFilter) + " incidents in this file. Try All.</p>"));
  document.querySelectorAll(".inc").forEach(function(el) {
    el.addEventListener("click", function() { selectIncident(parseInt(el.getAttribute("data-id"), 10)); });
  });
  // INVESTIGATION SPEED, SECOND CAUSE (2026-11-01): on page load
  // nothing ever selected an incident - the list rendered, but
  // selectIncident (the only place that sets the speed) ran only
  // after an upload/sample or a click. So opening /app on an
  // existing DB left the speed at "—" no matter how long ago the
  // run finished. Auto-select the first (highest-risk) incident
  // once, on the first list load only - later refreshes (live
  // timer, tier filter) must never steal the incident the user
  // is already reading.
  if (!state.autoSelected && shown.length) {
    state.autoSelected = true;
    selectIncident(shown[0].id);
  }
}

// RUN STATS (2026-11-01): the card at the top of the right column.
// Only two boxes remain (2026-11-01, user: delete the accuracy
// boxes - they are not necessary):
//  - Memory: live PC RAM meter at the top of the box, plus ASK
//    (main) memory below it. The old last-run peak GB value was
//    removed 2026-11-01, when the meter moved into its place.
//  - Investigation speed: time to open an incident (the three
//    detail fetches plus rendering), measured in the browser with
//    performance.now(), always shown in milliseconds (2026-11-01,
//    user: it should be in milliseconds - never converted to
//    seconds, even when it passes 1000 ms).
// Removed before this: Processing time, Lines / sec, and the four
// accuracy boxes (Detection %, Correct labels %, Attack path,
// False alarms %) - those four needed planted Load Sample ground
// truth and stayed "not available" after a plain upload, so the
// user asked to delete them rather than show them empty.
// The server still records evaluation in /run-stats JSON; nothing
// on the page displays it any more.
function fmtDur(ms) {
  // Always milliseconds, by user request - no seconds conversion.
  return Math.round(ms) + " ms";
}
async function loadStats() {
  var set = function(id, txt) { var el = document.getElementById(id); if (el) el.textContent = txt; };
  try {
    var s = await (await fetch("/run-stats")).json();
    // No accuracy sets here: those four boxes were deleted
    // 2026-11-01 at user request. Evaluation still arrives in
    // /run-stats JSON, but nothing on the page displays it.
    // LIVE PC MEMORY METER (2026-11-01, user: stats not loaded from
    // the PC, add a meter for memory): /run-stats now carries a
    // fresh system snapshot on every call, so this meter is live
    // from the machine running the server (your PC, when you run
    // it locally), even with no run yet. It is system RAM, not
    // ASK-only memory: ASK (main) is shown separately below it.
    // Investigation speed stays a last-run measurement - it cannot
    // exist before a run, and this meter does not invent it.
    var sys = s.system || {};
    var bar = document.getElementById("memBar");
    if (bar && sys.ram_percent !== undefined && sys.ram_percent !== null) {
      bar.style.width = Math.min(100, Math.max(0, sys.ram_percent)) + "%";
      bar.style.background = sys.ram_percent >= 90 ? "#dc2626" : (sys.ram_percent >= 70 ? "#d97706" : "#16a34a");
    }
    // MEMORY 0 GB FIX (2026-11-01, user: memory locked in 0 GB):
    // the old Memory box showed ASK's peak in GB, and ASK's peak is
    // tens/hundreds of MB, so it always rounded to 0.0 GB. That
    // value is gone: PC RAM is shown in GB (a real 7-8 GB total on
    // an 8 GB machine, never 0 - a 0/missing total means the
    // snapshot failed, so it says "processing" instead of
    // "0.0 / 0.0 GB"), and ASK is shown separately in MB.
    if (sys.ram_total_mb && sys.ram_used_mb !== undefined && sys.ram_used_mb !== null && sys.ram_percent !== undefined && sys.ram_percent !== null) {
      set("memLive", "PC RAM: " + (sys.ram_used_mb / 1024).toFixed(1) + " / " + (sys.ram_total_mb / 1024).toFixed(1) + " GB (" + sys.ram_percent + "%)" + (sys.cpu_percent !== undefined && sys.cpu_percent !== null ? " · CPU " + sys.cpu_percent + "%" : ""));
    } else {
      set("memLive", "PC RAM: processing");
    }
    // 0 MB is a failed read, not a real measurement (see sysstats
    // handle fix) - show "processing", never a lying 0 MB.
    if (sys.ask_rss_mb) set("memAsk", "ASK (main): " + sys.ask_rss_mb + " MB");
    else set("memAsk", "ASK (main): processing");
    // The duplicate hint below the boxes was removed 2026-11-01
    // (user: text is there twice) - the top hint under the
    // "Run stats" heading is the only copy now, so there is no
    // statBasis element left for loadStats to set.
  } catch (e) { /* server down: leave the dashes */ }
}

async function selectIncident(id) {
  // INVESTIGATION SPEED FIX (2026-11-01, user: speed not loaded):
  // the speed was set only at the very end of this function, so
  // any throw in the rendering above it (a missing timeline, a
  // graph/canvas error, a failed fetch) silently killed the whole
  // async function and the box stayed "—" forever, with no error
  // shown. The try/finally below guarantees the speed is set even
  // when a render step throws - the measurement is the time to
  // open the incident, whatever happened while opening it.
  var _t0 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
  try {
  var path = await (await fetch("/incidents/" + id + "/path")).json();
  var rep = await (await fetch("/incidents/" + id + "/report")).json();
  var next = await (await fetch("/incidents/" + id + "/next")).json();
  // REPORT SPLIT (2026-11-01, user option 1): rep.report is the
  // minimal 6-line brief for the webpage; rep.full_report is the
  // detailed 8-section brief, used only by Copy and Generate PDF.
  state.selected = path; state.report = rep.report; state.fullReport = rep.full_report || rep.report; state.fullTranslated = null; state.hindi = rep.hindi || null;
  path.next_reach = next.next_reach || [];
  // REPEATED INFO REMOVED (2026-11-01, user: remove any repeated
  // info): the pathBanner strip (incident # / risk / hosts) and the
  // right "Attack Paths - Ranked" card (same frontier hosts, scores
  // and reasons as the centre look-ahead) are gone - both were
  // already shown in the incident detail paragraph and in the
  // centre "What the attacker could reach next" section.
  var bs = document.getElementById("briefStatus");
  if (bs) bs.textContent = "Incident #" + path.id + " - " + esc(path.title);
  var br = document.getElementById("briefRisk");
  if (br) br.textContent = "Risk " + path.risk_score + "/100";
  var sn = document.getElementById("selectedNodeLabel");
  if (sn) sn.textContent = "None";
  // Flow Log Data table: real timeline steps only (first 20 shown).
  // Columns are Time / Src IP-or-Host / Technique / Stage / Flag -
  // the backend timeline has no destination port/protocol per step,
  // so those are not invented here.
  var fr = document.getElementById("flowRows");
  var fc = document.getElementById("flowRowCount");
  if (fr) {
    var rows = (path.timeline || []).slice(0, 20);
    fr.innerHTML = rows.length ? rows.map(function(s) {
      return "<tr><td>" + esc(s.time || "") + "</td><td>" + esc(s.ip || s.host || "") + "</td><td>" +
        esc(s.technique_id || "") + " " + esc(s.technique_name || "") + "</td><td>" +
        esc(s.kill_chain_stage || "") + "</td><td>" + esc(s.severity || "") + "</td></tr>";
    }).join("") : "<tr><td colspan=\"5\" class=\"hint\">No flow rows for this incident.</td></tr>";
    if (fc) fc.textContent = fmtNum(path.timeline_total || path.detection_count || 0) + " rows" +
      (rows.length < (path.timeline_total || path.detection_count || 0) ? " (first 20 shown)" : "");
  }
  document.querySelectorAll(".inc").forEach(function(el) {
    el.classList.toggle("sel", parseInt(el.getAttribute("data-id"), 10) === id);
  });
  document.getElementById("detail").innerHTML =
    "<p><b>" + esc(path.title) + "</b><br>Risk " + path.risk_score + "/100 &middot; " + path.detection_count +
    " steps &middot; " + path.merged_alerts + " raw alerts merged<br>Hosts: " + esc(path.hosts.join(", ")) +
    "<br>Users: " + esc((path.users || []).filter(function(u) { return u; }).join(", ") || "Unknown - not recorded in the logs") + "</p>" +
    (path.timeline_sampled ? "<br><small>Showing a sample: first and last 200 of " + fmtNum(path.timeline_total) + " steps. " +
      (path.timeline_summary || []).map(function(s) { return esc(s.technique_name) + " (" + esc(s.technique_id) + ") × " + fmtNum(s.count); }).join(" · ") + "</small>" : "");
  // NetworkX graph map: nodes + edges from path.graph (built by the
  // backend with NetworkX, not drawn by hand). Nodes are placed on a
  // circle in first-seen order so every edge is visible at once.
  renderGraph(path);
  // Attack path section removed 2026-11-01 at user request
  // ("remove the green shit") - the graph map above, with its
  // node popup, is the only path view now. No canvas is rendered.
  // LOOK AHEAD (restored 2026-11-01 at user request - it had been
  // removed with the old look-ahead panel, leaving only the right
  // Attack Paths card): "What the attacker could reach next" in
  // the centre column, from GET /incidents/{id}/next (already
  // fetched above as `next`). Frontier hosts are destinations
  // already contacted but not yet used as stepping stones - not
  // guessed hosts. Stages are predictions about stages, never
  // guessed hosts. Blast radius is from the observed graph unless
  // a topology was supplied.
  var la = document.getElementById("lookAhead");
  if (la) {
    var frontier = next.next_reach || [];
    var stages = next.next_stages || [];
    var total = next.next_frontier_total || frontier.length;
    var laHtml = "";
    if (frontier.length) {
      laHtml += "<p><b>Frontier hosts to watch (" + fmtNum(total) + " in total" + (total > frontier.length ? ", first " + frontier.length + " shown" : "") + "):</b></p>" +
        "<p class='hint'>Number in brackets, like (90), is the priority for that host: 90 = contacted via a Critical technique, 70 = High, 40 = Medium, 20 = Low. Higher means watch it first. It is not a probability, it comes from the worst severity used to contact that host.</p><ol>" + frontier.map(function(n) {
        return "<li><b>" + esc(n.host) + " (" + (n.confidence || 0) + ")</b> - " + esc(n.reason) + ". " + esc(n.block || "") + "</li>";
      }).join("") + "</ol>";
      laHtml += "<p class='hint'>Basis: " + esc(next.next_basis || "observed graph") + " - these are hosts the attacker has already contacted, not hosts guessed from nowhere. If one starts connecting onward, that is the next hop.</p>";
    } else {
      laHtml += "<p>No frontier host to watch: no new target is guessed.</p>";
    }
    if (stages.length) {
      laHtml += "<p><b>Next kill-chain stages to watch for:</b></p><ol>" + stages.map(function(s) {
        return "<li><b>" + esc(s.stage) + "</b> - " + esc(s.reason) + ". " + esc(s.block || "") + "</li>";
      }).join("") + "</ol>";
    }
    if (next.blast_radius !== undefined && next.blast_radius !== null) {
      laHtml += "<p><b>Blast radius: " + next.blast_radius + "/100</b>. This is a score from what the logs show, not a count of compromised hosts.</p>";
      var br = next.blast_breakdown;
      if (br) laHtml += "<details><summary>How this blast score is made up</summary><p>Observed graph - Reach " + br.reach + "/25 from " + br.dst_count + " destinations, Spread " + br.spread + "/25 from " + br.src_count + " sources, Depth " + br.depth + "/25 from " + br.stage_count + " stages, Severity " + br.severity + "/25, worst " + esc(br.worst_severity) + ".</p></details>";
      else if (next.blast_basis) laHtml += "<details><summary>How this blast score is made up</summary><p>" + esc(next.blast_basis) + "</p></details>";
    }
    la.innerHTML = laHtml;
  }
  document.getElementById("protect").innerHTML = (rep.protections && rep.protections.length)
    ? "<ol>" + rep.protections.map(function(p) {
        return "<li><b>" + esc(p.technique_id) + " - " + esc(p.technique_name) + ":</b> " + esc(p.action) + "</li>";
      }).join("") + "</ol>"
    : "<p>No protection actions for this incident.</p>";
  showReport();
  document.getElementById("copyBtn").disabled = false;
  var pdf = document.getElementById("pdfBtn");
  if (pdf) pdf.disabled = false;
  if ((path.timeline || []).length) showStep(path, 0);
  } finally {
    // Always in milliseconds (fmtDur never converts to seconds),
    // and always set - even if a render step above threw.
    var _t1 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
    var _inv = document.getElementById("statInvest");
    if (_inv) _inv.textContent = fmtDur(_t1 - _t0);
  }
  var _ds = document.getElementById("detailSection");
  if (_ds) _ds.scrollIntoView({ behavior: "smooth" });
}

function renderGraph(path) {
  var box = document.getElementById("graphMap");
  var graph = path.graph || { nodes: [], edges: [] };
  var allNodes = graph.nodes || [], allEdges = graph.edges || [];
  if (!allNodes.length) { box.innerHTML = "<p>No graph nodes for this incident.</p>"; return; }
  // GRAPH REDESIGN (2026-11-01, user demand: 'not so cluttered, colour
  // by importance, filters, use the clean inspiration image'). The old
  // circle layout put 250 nodes on one ring with every label on top of
  // every other label - unreadable. The new layout is left-to-right
  // by role, like the inspiration: users, then sources, then pivots
  // (hosts that are both a destination and a source, in kill-chain
  // stage order), then destinations. Colour = worst severity on that
  // node (backend-enriched): Critical black/white, High green,
  // Medium dark grey, Low light grey, user black/white, technique
  // green. Edge colour = destination severity. Default shows the
  // top 60 most-connected nodes, not 250.
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
  // Kill Chain is the only graph mode (2026-11-01): the old
  // frontier subgraph is gone, so the full graph is always
  // shown, filtered only by the technique / severity / search
  // controls below and capped at the 60 most-connected nodes.
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
      "All " + fmtNum(path.detection_count) + " steps happened on the host above - see the step list and the grouped report for what actually happened, instead of an empty graph.</p>";
    return;
  }
  var _gd = document.documentElement.getAttribute("data-theme") === "dark";
  var sevColor = _gd ? { Critical: "#f4f4f5", High: "#34d399", Medium: "#a1a1aa", Low: "#57534e" } : { Critical: "#111111", High: "#00a66a", Medium: "#57534e", Low: "#a8a29e" };
  var sevFill = _gd ? { Critical: "#27272a", High: "#064e3b", Medium: "#3f3f46", Low: "#18181b" } : { Critical: "#e7e5e4", High: "#ecfdf5", Medium: "#f5f5f4", Low: "#ffffff" };
  var userStroke = _gd ? "#f4f4f5" : "#111111"; var userFill = _gd ? "#27272a" : "#ffffff"; var techStroke = _gd ? "#34d399" : "#00a66a"; var techFill = _gd ? "#064e3b" : "#ecfdf5";
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
  // GRAPH LAYOUT (2026-11-01, user demand: 'display the canvas and
  // the graph properly, easy to understand'). The old layout put a
  // whole role column in one stack, so a fan-out incident with 60
  // destinations became a 5,000 px tall column of tiny boxes that
  // had to be scrolled through. Now each column wraps after 12
  // rows into a new sub-column, so the canvas grows wider (and the
  // pan control moves it) instead of endlessly taller. Column
  // headers are drawn, so it is clear which column is users,
  // sources, pivots or destinations.
  var BW = 170, BH = 64, CW = 210, RH = 84, MAX_ROWS = 12, HEAD = 26;
  var subCols = [];
  usedCols.forEach(function(ci) {
    for (var s = 0; s < cols[ci].length; s += MAX_ROWS) {
      subCols.push({ role: ci, cont: s > 0, nodes: cols[ci].slice(s, s + MAX_ROWS) });
    }
  });
  var rowsShown = Math.max.apply(null, subCols.map(function(sc) { return sc.nodes.length; }));
  var W = subCols.length * CW + 20, H = HEAD + 20 + rowsShown * RH;
  var pos = {};
  subCols.forEach(function(sc, colPos) {
    sc.nodes.forEach(function(n, r) {
      pos[n.id] = { x: 10 + colPos * CW, y: HEAD + 10 + r * RH };
    });
  });
  var nodeById = {};
  fNodes.forEach(function(n) { nodeById[n.id] = n; });
  var seenEdge = {};
  var svg = "<svg width='" + Math.round(W * gf.zoom) + "' height='" + Math.round(H * gf.zoom) + "' viewBox='0 0 " + W + " " + H + "' class='graph-svg' role='img' aria-label='Attack graph, left to right by role'>" +
    "<defs><marker id='arr2' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'><path d='M 0 0 L 10 5 L 0 10 z' fill='#00a66a'/></marker></defs>" +
    subCols.map(function(sc, colPos) {
      return "<text x='" + (10 + colPos * CW + 2) + "' y='20' class='colhead'>" + esc(colNames[sc.role]) + (sc.cont ? " (cont.)" : "") + "</text>";
    }).join("");
  fEdges.forEach(function(e) {
    var key = e.from + ">" + e.to + "|" + (e.technique_id || "");
    if (seenEdge[key]) return; seenEdge[key] = true;
    var a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    var col = sevColor[sevOf(nodeById[e.to])] || "#6b7280";
    if (nodeById[e.to] && nodeById[e.to].type === "user") col = userStroke;
    if (nodeById[e.to] && nodeById[e.to].type === "technique") col = techStroke;
    svg += "<line x1='" + (a.x + BW) + "' y1='" + (a.y + BH / 2) + "' x2='" + b.x + "' y2='" + (b.y + BH / 2) + "' stroke='" + col + "' stroke-width='2' marker-end='url(#arr2)'/>";
    if (fEdges.length <= 60 && e.technique_id) {
      svg += "<text x='" + Math.round((a.x + BW + b.x) / 2) + "' y='" + Math.round((a.y + b.y) / 2 + BH / 2 - 4) + "' class='elabel'>" + esc(e.technique_id) + "</text>";
    }
  });
  fNodes.forEach(function(n) {
    var p = pos[n.id];
    var sev = sevOf(n);
    var stroke = n.type === "user" ? userStroke : n.type === "technique" ? techStroke : (sevColor[sev] || "#57534e");
    var fill = n.type === "user" ? userFill : n.type === "technique" ? techFill : (sevFill[sev] || "#ffffff");
    var label = n.id.length > 22 ? n.id.slice(0, 21) + "…" : n.id;
    var sub = n.type === "technique" && n.name ? n.name : (n.stage || n.type);
    svg += "<g class='gnode-wrap' data-node='" + esc(n.id) + "' tabindex='0' role='button' aria-label='Show steps for " + esc(n.id) + "'>" +
      "<title>" + esc(n.id) + " - " + esc(sub) + " - " + esc(sev) + "</title>" +
      "<rect x='" + p.x + "' y='" + p.y + "' width='" + BW + "' height='" + BH + "' rx='10' fill='" + fill + "' stroke='" + stroke + "' stroke-width='3'/>" +
      "<text x='" + (p.x + 10) + "' y='" + (p.y + 22) + "' class='nlabel'>" + esc(label) + "</text>" +
      "<text x='" + (p.x + 10) + "' y='" + (p.y + 40) + "' class='ntype'>" + esc(sub.length > 24 ? sub.slice(0, 23) + "…" : sub) + "</text>" +
      "<text x='" + (p.x + 10) + "' y='" + (p.y + 57) + "' class='nsev' fill='" + stroke + "'>" + esc(sev.toUpperCase()) + "</text>" +
      (n.count ? "<text x='" + (p.x + BW - 10) + "' y='" + (p.y + 22) + "' class='nsev' fill='" + stroke + "' text-anchor='end'>×" + n.count + "</text>" : "") + "</g>";
  });
  svg += "</svg>";
  var techOpts = ["All"];
  realEdges.forEach(function(e) { if (e.technique_id && techOpts.indexOf(e.technique_id) < 0) techOpts.push(e.technique_id); });
  var capNote = (!gf.showAll && totalNodes > 60) ? "<p class='hint'>Showing the 60 most-connected of " + fmtNum(totalNodes) + " nodes (" + fmtNum(fEdges.length) + " of " + fmtNum(totalEdges) + " edges). Use Show all below for the rest - the full step list and grouped report still cover everything.</p>" : "";
  // Fan-out, not a chain: one source touching many destinations in
  // parallel is the shape live-mode sample incidents take (no pivot
  // connects the destinations), and reading it as a chain is the
  // misunderstanding the old tall column invited. Say so plainly.
  if (!cols[2].length && cols[3].length >= 20) {
    capNote += "<p class='hint'>Fan-out, not a chain: the destinations shown here were each contacted in parallel - they are not hops one after another.</p>";
  }
  var colNote = "";
  var zl = document.getElementById("zoomLabel");
  if (zl) zl.textContent = Math.round(gf.zoom * 100) + "%";
  // Keep the viewport where the user was across re-renders (zoom /
  // filter changes replace the whole innerHTML, which used to snap
  // the canvas back to the top-left every time).
  var keepSl = box.scrollLeft, keepSt = box.scrollTop;
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
    "<div class='graph-viewport'>" + svg + "</div>" +
    capNote + colNote + "</div>";
  box.scrollLeft = keepSl;
  box.scrollTop = keepSt;
  box.querySelectorAll(".gnode-wrap").forEach(function(el) {
    // HOVER = ATTACK PATH, CLICK = STEPS (2026-11-01, user:
    // "if i hover give me the attack path with all the boxes as
    // popup but if i click give me the second option"). The old
    // hover = steps wiring is gone - that was the "random
    // notification" bug: moving the mouse across the graph opened
    // a steps popup for every box passed over, and destination
    // domains like update-paypal.net have no steps to show, so it
    // could only say "No steps". Hover now waits 350 ms, so just
    // passing over a box while scrolling or panning opens nothing;
    // mouseleave cancels the wait, but never closes an open popup,
    // or the user could never move into it to click a box.
    var _hoverTimer = null;
    el.addEventListener("mouseenter", function() {
      if (_hoverTimer) clearTimeout(_hoverTimer);
      _hoverTimer = setTimeout(function() { showAttackPath(path, el.getAttribute("data-node")); }, 350);
    });
    el.addEventListener("mouseleave", function() { if (_hoverTimer) { clearTimeout(_hoverTimer); _hoverTimer = null; } });
    el.addEventListener("click", function() { if (_hoverTimer) { clearTimeout(_hoverTimer); _hoverTimer = null; } closePathModal(); showNodeSteps(path, el.getAttribute("data-node")); });
    el.addEventListener("keydown", function(e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); closePathModal(); showNodeSteps(path, el.getAttribute("data-node")); } });
  });
}

function closeNodeModal() {
  var m = document.getElementById("nodeModal");
  if (m) m.hidden = true;
}
(function initNodeModal() {
  document.addEventListener("click", function(e) {
    if (e.target && (e.target.id === "nodeModalClose" || e.target.id === "nodeModalBackdrop" || (e.target.closest && e.target.closest("#nodeModalClose")))) closeNodeModal();
  });
  document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closeNodeModal();
  });
})();

function closePathModal() {
  var m = document.getElementById("pathModal");
  if (m) m.hidden = true;
}
(function initPathModal() {
  document.addEventListener("click", function(e) {
    if (e.target && (e.target.id === "pathModalClose" || e.target.id === "pathModalBackdrop" || (e.target.closest && e.target.closest("#pathModalClose")))) closePathModal();
  });
  document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closePathModal();
  });
})();
function showAttackPath(path, nodeId) {
  // HOVER POPUP (2026-11-01): the full attack path with all boxes,
  // traced from REAL log edges only - never an invented hop. The
  // chain through the hovered node is built from path edges
  // (source -> destination), with event edges (user -> source) as
  // a fallback for user nodes. Backwards: first predecessor, up to
  // 20 hops, loop-guarded. Forwards: one successor at a time until
  // a branching point, where every successor is shown stacked as
  // destinations, like the reference preview. An "Internet" entry
  // box is added before a source, exactly as in the preview - it is
  // a label only, not a logged host. Clicking a box in this popup
  // closes it and opens the steps popup for that box (click =
  // second option, everywhere). Destinations do have a chain here,
  // unlike the steps popup, which matches no destination steps.
  closeNodeModal();
  var modal = document.getElementById("pathModal");
  var title = document.getElementById("pathModalTitle");
  var body = document.getElementById("pathModalBody");
  if (!modal || !title || !body) return;
  var graph = path.graph || { nodes: [], edges: [] };
  var nodeById = {};
  (graph.nodes || []).forEach(function(n) { nodeById[n.id] = n; });
  var pathEdges = (graph.edges || []).filter(function(e) { return e.kind === "path"; });
  var allEdges = graph.edges || [];
  var pred = {}, succ = {};
  pathEdges.forEach(function(e) { (pred[e.to] = pred[e.to] || []).push(e.from); (succ[e.from] = succ[e.from] || []).push(e.to); });
  var predAll = {}, succAll = {};
  allEdges.forEach(function(e) { (predAll[e.to] = predAll[e.to] || []).push(e.from); (succAll[e.from] = succAll[e.from] || []).push(e.to); });
  var P = function(id) { return pred[id] && pred[id].length ? pred[id] : (predAll[id] || []); };
  var S = function(id) { return succ[id] && succ[id].length ? succ[id] : (succAll[id] || []); };
  var srcSet = {}, dstSet = {};
  pathEdges.forEach(function(e) { srcSet[e.from] = true; dstSet[e.to] = true; });
  var roleOf = function(id) {
    var n = nodeById[id];
    if (n && n.type === "user") return "User";
    if (n && n.type === "technique") return "Technique";
    if (srcSet[id] && dstSet[id]) return "Pivot";
    if (srcSet[id]) return "Source";
    return "Destination";
  };
  var sevOfNode = function(id) { var n = nodeById[id]; return (n && n.severity) || "Low"; };
  var seen = {}; seen[nodeId] = true;
  var back = [], cur = nodeId, guard = 0;
  while (P(cur).length && guard++ < 20) {
    var prev = P(cur)[0];
    if (seen[prev]) break;
    seen[prev] = true; back.unshift(prev); cur = prev;
  }
  var fwd = [], dests = [], fcur = nodeId, fguard = 0;
  while (S(fcur).length && fguard++ < 20) {
    var nxt = S(fcur);
    if (nxt.length > 1) { dests = nxt; break; }
    if (seen[nxt[0]]) break;
    seen[nxt[0]] = true; fwd.push(nxt[0]); fcur = nxt[0];
  }
  var chain = back.concat([nodeId], fwd);
  var boxHtml = function(id, isSel) {
    var n = nodeById[id];
    var sev = sevOfNode(id);
    var sevCls = "ap-sev-" + sev.toLowerCase();
    var sub = (n && n.type === "technique" && n.name) ? n.name : (n && (n.stage || n.type)) || roleOf(id);
    return "<button class='ap-node" + (isSel ? " sel" : "") + "' data-node='" + esc(id) + "'><span class='role'>" + esc(roleOf(id)) + "</span><div class='ip'>" + esc(id) + "</div><div class='host'>" + esc(sub.length > 24 ? sub.slice(0, 23) + "…" : sub) + "</div><span class='sev " + sevCls + "'>" + esc(sev.toUpperCase()) + "</span></button>";
  };
  var html = "<div class='ap-row'>";
  if (chain.length && roleOf(chain[0]) === "Source") {
    html += "<button class='ap-node' data-node=''><span class='role'>Entry</span><div class='ip'>Internet</div><div class='host'>Outside the network</div></button><span class='ap-arrow'>→</span>";
  }
  chain.forEach(function(id, i) {
    html += boxHtml(id, id === nodeId);
    if (i < chain.length - 1) html += "<span class='ap-arrow'>→</span>";
  });
  if (dests.length) {
    html += "<span class='ap-arrow'>→</span><div class='ap-dests'>" + dests.map(function(id) { return boxHtml(id, false); }).join("") + "</div>";
  }
  html += "</div>";
  var extraPred = P(nodeId).length > 1 ? "<p class='hint'>Also reached from: " + esc(P(nodeId).slice(1).join(", ")) + " - the chain above shows the first hop only.</p>" : "";
  if (!back.length && !fwd.length && !dests.length) {
    html += "<p class='hint'>No host-to-host move in the logs for this node - all its steps happened on this host. Click it for its step list.</p>";
  } else {
    html += "<p class='hint'>Traced from real log edges only, through " + esc(nodeId) + ". Click a box for its step list, or close with X, outside, or Escape.</p>";
  }
  html += extraPred;
  title.textContent = "Attack path — " + nodeId;
  body.innerHTML = html;
  body.querySelectorAll(".ap-node[data-node]").forEach(function(el) {
    var nid = el.getAttribute("data-node");
    if (!nid) return;
    el.addEventListener("click", function() { closePathModal(); showNodeSteps(path, nid); });
  });
  modal.hidden = false;
}
function showNodeSteps(path, nodeId) {
  closePathModal();
  // NODE POPUP ONLY (2026-11-01): clicking a graph node opens a
  // real modal over the graph - not a side panel, not a scroll to
  // Step detail. Clicking a step inside the popup closes it and
  // shows that step in Step detail below, as before. Steps also
  // match by IP, so IP SOURCES boxes list their steps.
  document.querySelectorAll(".gnode-wrap").forEach(function(el) {
    el.classList.toggle("sel", el.getAttribute("data-node") === nodeId);
  });
  var sn = document.getElementById("selectedNodeLabel");
  if (sn) sn.textContent = nodeId;
  var modal = document.getElementById("nodeModal");
  var title = document.getElementById("nodeModalTitle");
  var body = document.getElementById("nodeModalBody");
  if (!modal || !title || !body) return;
  var steps = path.timeline.map(function(s, i) { return { s: s, i: i }; }).filter(function(x) {
    return x.s.host === nodeId || x.s.ip === nodeId || x.s.user === nodeId || x.s.technique_id === nodeId;
  });
  title.textContent = "Node: " + nodeId;
  if (!steps.length) {
    body.innerHTML = "<p>No steps on " + esc(nodeId) + " in the sampled timeline.</p>";
  } else {
    var shown = steps.slice(0, 100);
    body.innerHTML =
      "<p>" + steps.length + " step(s) in this incident" +
      (steps.length > 100 ? " (showing the first 100 - the rest repeat the same techniques)" : "") + ". Click a step to inspect it.</p>" +
      shown.map(function(x) {
        return "<button class='btn ghost step-link' data-i='" + x.i + "'>" + (x.i + 1) + ". " + esc(x.s.kill_chain_stage) + " - " +
          esc(x.s.technique_id) + " " + esc(x.s.technique_name) + " (" + esc(x.s.time) + ")</button>";
      }).join(" ");
    body.querySelectorAll(".step-link").forEach(function(el) {
      el.addEventListener("click", function() { closeNodeModal(); showStep(path, parseInt(el.getAttribute("data-i"), 10)); });
    });
  }
  modal.hidden = false;
}

function showStep(path, i) {
  var step = path.timeline[i];
  document.querySelectorAll(".pkg").forEach(function(el) {
    el.classList.toggle("sel", parseInt(el.getAttribute("data-i"), 10) === i);
    el.setAttribute("aria-pressed", parseInt(el.getAttribute("data-i"), 10) === i ? "true" : "false");
  });
  // Never show a blank User/Source, and never repeat the action as
  // the detail ("Phishing Attempts - Phishing Attempts /").
  var what = (step.action || "").trim();
  var det = (step.detail || "").trim();
  if (det && det !== what) {
    if (what && det.indexOf(what) === 0) det = det.slice(what.length).replace(/^[\s\/\-:]+/, "");
    what = what ? what + (det ? " - " + det : "") : det;
  }
  document.getElementById("stepDetail").innerHTML =
    "<b>Step " + (i + 1) + " - " + esc(step.kill_chain_stage) + "</b><br>" +
    esc(step.technique_id) + " - " + esc(step.technique_name) + " (" + step.confidence + "% confidence, " + esc(step.severity) + ")<br>" +
    esc(what || "No action text in the log") + "<br><small>Time: " + esc(step.time) + " &middot; Host: " + esc(step.host || "Unknown") +
    " &middot; User: " + esc(step.user || "Unknown") + " &middot; Source: " + esc(step.source || "Unknown") + "<br>Why this flagged: " + esc(step.reason) + "</small>";
  document.getElementById("stepDetail").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function showReport() {
  var langSel = document.getElementById("reportLang");
  var lang = langSel ? langSel.value : "en";
  var pdfLabel = document.getElementById("pdfLabel");
  if (pdfLabel && langSel) pdfLabel.textContent = "Generate Threat Report (PDF) - " + langSel.options[langSel.selectedIndex].text;
  var box = document.getElementById("report");
  var warn = document.getElementById("reportWarning");
  if (!state.selected) return;
  if (lang === "en") {
    box.textContent = state.report;
    state.fullTranslated = null;
    if (warn) warn.hidden = true;
    return;
  }
  try {
    var rep = await (await fetch("/incidents/" + state.selected.id + "/report?lang=" + lang)).json();
    var tr = rep.translated || {};
    box.textContent = tr.text || state.report;
    // Generated-file text in this language, if the backend
    // translated the detailed brief too; otherwise Copy/PDF fall
    // back to the English detailed brief below.
    state.fullTranslated = (rep.translated_full && rep.translated_full.text) ? rep.translated_full.text : null;
    if (warn) {
      if (tr.warning) { warn.hidden = false; warn.textContent = tr.warning; }
      else if (tr.source === "sarvam") { warn.hidden = false; warn.textContent = "Report - by Sarvam AI (" + lang + ")."; }
      else warn.hidden = true;
    }
  } catch (e) {
    box.textContent = state.report;
    state.fullTranslated = null;
    if (warn) { warn.hidden = false; warn.textContent = "Translation could not be loaded - showing the English report."; }
  }
}
var reportLangSel = document.getElementById("reportLang");
if (reportLangSel) reportLangSel.addEventListener("change", showReport);
// REPORT SPLIT: Copy and Generate PDF use the DETAILED brief,
// not the minimal text shown on the webpage. In a non-English
// language they use the translated detailed brief when one was
// fetched, otherwise the English detailed brief.
function fullReportText() {
  var langSel = document.getElementById("reportLang");
  var lang = langSel ? langSel.value : "en";
  if (lang && lang !== "en" && state.fullTranslated) return state.fullTranslated;
  return state.fullReport || document.getElementById("report").textContent;
}
document.getElementById("copyBtn").addEventListener("click", function() {
  var txt = fullReportText();
  if (txt) navigator.clipboard.writeText(txt).then(function() { alert("Full report copied."); });
});
var pdfBtn = document.getElementById("pdfBtn");
if (pdfBtn) pdfBtn.addEventListener("click", function() {
  if (!state.selected) return;
  var langSel = document.getElementById("reportLang");
  var lang = langSel ? langSel.options[langSel.selectedIndex].text : "English";
  var txt = fullReportText();
  var w = window.open("", "_blank");
  if (!w) { alert("Allow pop-ups for this page, then try Generate PDF again."); return; }
  w.document.write("<!doctype html><html><head><meta charset='utf-8'><title>ASK Incident Report</title>" +
    "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 20px;line-height:1.6}h1{font-size:22px}</style></head><body>" +
    "<h1>ASK - Incident #" + state.selected.id + " report (" + esc(lang) + ")</h1>" +
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
  // SYSTEM LINE (2026-11-01, CPU/RAM removed 2026-11-01 at user
  // request): elapsed/total time + ASK memory, on every progress
  // poll. CPU % and system RAM used to be appended here too, but
  // the user asked to remove just those two from this status line.
  // Live PC RAM/CPU now live in the memory meter in the Run stats
  // card (loadStats, /run-stats), not in this line. /progress JSON
  // still carries cpu_percent/ram_* for any other consumer; only
  // this display is changed. ASK is the main server process only -
  // parallel workers are separate processes, so it is a lower bound.
  var sys = "";
  if (p.detected_format) sys += " · Format " + p.detected_format;
  if (p.rule_pack) sys += " · Rules: " + p.rule_pack + " pack";
  if (p.detected_format_warning) sys += " · Warning: " + p.detected_format_warning;
  if (p.elapsed_text) sys += " · Elapsed " + p.elapsed_text;
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
    el.textContent += " This is a very large file - keep this tab open, it will take a while.";
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
      // stage rhetoric), then how to prevent it - all in one flow,
      // no full stops or labels between the parts. Example:
      // 'Phishing (T1566.001) - adversaries may send spearphishing
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
        return "<div class='card dark' style='margin:8px 0;padding:12px'><b>" + esc(heading) + "</b> - " +
          flow(meaning) + ", " + flow(t.help) + ".</div>";
      }).join("");
    } else if (p.stage === "uploading") {
      list.innerHTML = "<p class='hint'>Still receiving your file - no lines have been checked yet, so no finds to show. As soon as reading starts, the attacks found so far will appear here, one card per attack.</p>";
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
        el2.textContent = "Server not responding - the server may have stopped or crashed. Check the server window (run.bat / run.sh) and restart it if needed, then upload again. Your file was not lost from your computer, only this run did not finish.";
      }
    });
  }, 1000);
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/upload", true);
  xhr.setRequestHeader("X-Filename", file.name);
  var stopBox = document.getElementById("stopOnUnknown");
  if (stopBox && stopBox.checked) xhr.setRequestHeader("X-Stop-On-Unknown", "1");
  xhr.upload.onprogress = function(e) {
    if (e.lengthComputable) {
      document.getElementById("bar").style.width = Math.round(100 * e.loaded / e.total) + "%";
      showBackendStatus({ stage: "uploading", stage_text: "Step 1 of 4 - Receiving",
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
    document.getElementById("fileinfo").textContent = file.name + " - " + data.events + " lines, " + data.detections +
      " detections, " + data.incidents + " incidents, in " + data.seconds + "s. Nothing was stored except the database on this machine." +
      (data.detected_format ? " Detected format: " + data.detected_format.format + "." : "") +
      (data.rule_pack ? " Rules: " + data.rule_pack + " pack." : "") +
      (data.detected_format && data.detected_format.warning ? " " + data.detected_format.warning : "");
    // Final line keeps the total time and peak memory - the old
    // 'Done - …' text that overwrote the poll's done line (and with
    // it the elapsed/CPU/RAM line) is removed, not kept.
    document.getElementById("backendStatus").textContent = "Done in " + data.seconds + "s - " + data.events + " lines, " + data.detections +
      " detections, " + data.incidents + " incidents. Peak ASK memory: " + (data.peak_rss_mb || 0) + " MB.";
    await loadIncidents();
    await loadStats();
    if (state.incidents.length) selectIncident(state.incidents[0].id);
  };
  xhr.onerror = function() {
    clearInterval(poll);
    document.getElementById("fileinfo").textContent = "Upload failed - the server could not be reached.";
  };
  xhr.send(file);
}

// Load Sample: POST /sample, server generates ~250 MB of synthetic
// log from generate_logs.py and APPENDS it to the existing DB, then
// the list refreshes. /tiny and /demo buttons are removed (2026-11-01);
// their server endpoints still exist, but nothing on the page calls them.
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
    await loadStats();
    // LIVE MODE (2026-11-01 fix): after an append, show the NEWEST
    // incident, not the first in DB order. The old code selected
    // state.incidents[0], which is the oldest incident - so after
    // Load Sample the centre kept showing old data while the new
    // incidents sat in the queue, and the attack path the user saw
    // was not the new run's at all. Highest id = last appended.
    if (state.incidents.length) {
      var newest = state.incidents.reduce(function(a, b) { return b.id > a.id ? b : a; }, state.incidents[0]);
      selectIncident(newest.id);
    }
  }).catch(function() {
    clearInterval(poll);
    document.getElementById("fileinfo").textContent = "Failed - the server could not be reached.";
  });
}
var sampleBtn = document.getElementById("sampleBtn");
if (sampleBtn) sampleBtn.addEventListener("click", function() { runServerJob("/sample", "Generating about 250 MB of synthetic log and appending it to the existing data - this takes a couple of minutes, the progress bar above tracks it…"); });

loadIncidents();
loadStats();
// Live PC refresh: re-read /run-stats every 5 seconds so the memory
// meter (and CPU) move while the page is open, not just on page
// load or after a run. This does not touch investigation speed,
// which is only set when an incident is opened.
setInterval(loadStats, 5000);

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

// Graph mode (2026-11-01): Kill Chain only. There is no mode
// toggle any more - the mode button in the header is disabled and
// the banner always reads Kill Chain, so nothing here switches the
// graph to a frontier subgraph.

// Center zoom controls (graph zoom lives in renderGraph's state).
function zoomStep(d) { if (window.setGraphZoom) window.setGraphZoom(d); }
var zIn = document.getElementById("zoomIn");
if (zIn) zIn.addEventListener("click", function() { zoomStep(0.2); });
var zOut = document.getElementById("zoomOut");
if (zOut) zOut.addEventListener("click", function() { zoomStep(-0.2); });
var zReset = document.getElementById("zoomReset");
if (zReset) zReset.addEventListener("click", function() { if (window.setGraphFilter) window.setGraphFilter("zoom", 1); });

// Pan + zoom header (2026-11-01, matching the uploaded crop):
// one pill holding "< Pan >", a magnifier-minus button, the
// percentage, and a magnifier-plus button. Pan is a toggle: click
// "< Pan >" (it turns green) and dragging the canvas moves it, at
// any zoom level. The canvas itself is the only scroller - the old
// inner overflow box inside the graph is gone, because it swallowed
// the drag and the outer box never scrolled, which is why panning
// felt broken when zoomed in. A plain click on a node still selects
// it while Pan is on; only an actual drag (over 5 px) suppresses
// the click, so dragging never opens a node's steps by accident.
// Dragging never starts on a filter control (button, select, input).
var panBtn = document.getElementById("panBtn");
var graphBox = document.getElementById("graphMap");
var panState = null;
function setPan(on) {
  state.panMode = !!on;
  if (panBtn) {
    panBtn.classList.toggle("active", !!on);
    panBtn.setAttribute("aria-pressed", !!on ? "true" : "false");
  }
  if (graphBox) graphBox.classList.toggle("panning", !!on);
}
if (panBtn) {
  panBtn.addEventListener("click", function() { setPan(!state.panMode); });
}
if (graphBox) {
  graphBox.addEventListener("mousedown", function(e) {
    if (!state.panMode) return;
    if (e.target.closest && e.target.closest("button,select,input,textarea,a,label")) return;
    panState = { x: e.clientX, y: e.clientY, sl: graphBox.scrollLeft, st: graphBox.scrollTop, moved: false };
    graphBox.classList.add("dragging");
    e.preventDefault();
  });
  graphBox.addEventListener("mousemove", function(e) {
    if (!panState) return;
    var dx = e.clientX - panState.x, dy = e.clientY - panState.y;
    if (Math.abs(dx) > 5 || Math.abs(dy) > 5) panState.moved = true;
    graphBox.scrollLeft = panState.sl - dx;
    graphBox.scrollTop = panState.st - dy;
  });
  window.addEventListener("mouseup", function() {
    if (panState && panState.moved) {
      // The click that follows a drag must not select a node.
      state.suppressClick = true;
      setTimeout(function() { state.suppressClick = false; }, 0);
    }
    panState = null;
    if (graphBox) graphBox.classList.remove("dragging");
  });
  // Capture phase: stop a drag's click before it reaches a node.
  graphBox.addEventListener("click", function(e) {
    if (state.suppressClick) { e.stopPropagation(); e.preventDefault(); }
  }, true);
}
var refreshBtn = document.getElementById("refreshBtn");
if (refreshBtn) refreshBtn.addEventListener("click", function() { loadIncidents(); });
var uploadBtn = document.getElementById("uploadBtn");
if (uploadBtn) uploadBtn.addEventListener("click", function() { document.getElementById("file").click(); });
var flowFilter = document.getElementById("flowFilter");
if (flowFilter) {
  flowFilter.addEventListener("input", function() {
    var q = flowFilter.value.toLowerCase();
    document.querySelectorAll("#flowRows tr").forEach(function(row) {
      row.style.display = !q || row.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none";
    });
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
