"use strict";
var state = { incidents: [], selected: null, report: "", hindi: null };

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
  document.getElementById("incidents").innerHTML = list.length ? list.map(function(inc) {
    return "<button class=inc data-id=" + inc.id + "><b>Incident " + inc.id + " — risk " + inc.risk_score + "/100</b> &middot; " +
      inc.detection_count + " steps &middot; " + inc.merged_alerts + " raw alerts merged<br><small>" +
      esc(inc.title) + " &middot; " + esc(inc.hosts.join(", ")) + "</small></button>";
  }).join("") : "<p>No incidents found in this file. That may mean the log is clean, or its wording does not match the rules in rules/.</p>";
  document.querySelectorAll(".inc").forEach(function(el) {
    el.addEventListener("click", function() { selectIncident(parseInt(el.getAttribute("data-id"), 10)); });
  });
}

async function selectIncident(id) {
  var path = await (await fetch("/incidents/" + id + "/path")).json();
  var rep = await (await fetch("/incidents/" + id + "/report")).json();
  var next = await (await fetch("/incidents/" + id + "/next")).json();
  state.selected = path; state.report = rep.report; state.hindi = rep.hindi || null;
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
  var pathHosts = (path.hosts || []).filter(function(h) { return h; });
  document.getElementById("path").innerHTML = pathHosts.length > 1
    ? pathHosts.map(function(h) { return "<span class=node>" + esc(h) + "</span>"; }).join("<span class=arrow>&rarr;</span>")
    : pathHosts.length === 1
      ? "<span class=node>" + esc(pathHosts[0]) + "</span><p class='hint'>Single host — no host-to-host path in this incident. All steps happened on this one host, so there is no chain of hosts to draw.</p>"
      : "<p>Unknown host path.</p>";
  var nextHtml = (next.next_reach && next.next_reach.length)
    ? "<ul>" + next.next_reach.map(function(n) {
        return "<li><b>" + esc(n.host) + "</b> (score " + n.confidence + "/100 — admin rights 50 + same subnet 25, capped at 100) — " + esc(n.reason) + ". Block it by: " + esc(n.block) + ".</li>";
      }).join("") + "</ul>"
    : "<p>No next system is guessed here: no topology was supplied with this upload, so there is no list of other hosts or admin rights to check against. The attacker is not assumed to reach anything beyond what the logs actually show.</p>";
  if (next.next_stages && next.next_stages.length) {
    nextHtml += "<p><b>Looking ahead in the kill chain</b> (stages, not guessed hosts): " +
      next.next_stages.map(function(s) { return esc(s.stage); }).join(" → ") +
      ". Watch for these stages next on the compromised host(s).</p>";
  }
  if (next.blast_radius !== undefined && next.blast_radius !== null) {
    nextHtml += "<p>Blast radius from the supplied topology: <b>" + next.blast_radius + "/100</b>.</p>";
  }
  document.getElementById("next").innerHTML = nextHtml;
  document.getElementById("protect").innerHTML = (rep.protections && rep.protections.length)
    ? "<ol>" + rep.protections.map(function(p) {
        return "<li><b>" + esc(p.technique_id) + " — " + esc(p.technique_name) + ":</b> " + esc(p.action) + "</li>";
      }).join("") + "</ol>"
    : "<p>No protection actions for this incident.</p>";
  document.getElementById("report").textContent = state.report;
  document.getElementById("copyBtn").disabled = false;
  document.getElementById("hindiBtn").disabled = false;
  if (path.timeline.length) showStep(path, 0);
  document.getElementById("detailSection").scrollIntoView({ behavior: "smooth" });
}

function renderGraph(path) {
  var box = document.getElementById("graphMap");
  var graph = path.graph || { nodes: [], edges: [] };
  var nodes = graph.nodes || [], edges = graph.edges || [];
  if (!nodes.length) { box.innerHTML = "<p>No graph nodes for this incident.</p>"; return; }
  // Old DBs (built before the technique fallback) have a single host
  // and no edges: build the host -> technique graph here from the
  // timeline summary, so those incidents get a real graph too without
  // re-running the whole log. New runs already store these edges.
  var realEdges = edges.filter(function(e) { return posCheck(e); });
  function posCheck(e) { return nodes.some(function(n) { return n.id === e.from; }) && nodes.some(function(n) { return n.id === e.to; }); }
  if (!realEdges.length && path.timeline_summary && path.timeline_summary.length) {
    var hostId = (nodes[0] && nodes[0].id) || (path.hosts && path.hosts[0]);
    if (hostId) {
      path.timeline_summary.forEach(function(s) {
        nodes.push({ id: s.technique_id, type: "technique", name: s.technique_name, count: s.count });
        edges.push({ from: hostId, to: s.technique_id, kind: "technique", technique_id: s.technique_id, time: "" });
      });
      realEdges = edges;
    }
  }
  if (!nodes.length) { box.innerHTML = "<p>No graph nodes for this incident.</p>"; return; }
  if (!realEdges.length) {
    var only = nodes[0];
    box.innerHTML = "<p><span class=node>" + esc(only.id) + "</span> <small>(" + esc(only.type) + ")</small></p>" +
      "<p class='hint'>No connections to draw: this incident has only this one host and no host-to-host or user-to-host move in the logs. " +
      "All " + fmtNum(path.detection_count) + " steps happened on the host above — see the step list and the grouped report for what actually happened, instead of an empty graph.</p>";
    return;
  }
  var W = 1100, H = 440, cx = W / 2, cy = H / 2, R = 170;
  var pos = {};
  nodes.forEach(function(n, i) {
    var a = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    pos[n.id] = { x: Math.round(cx + R * Math.cos(a)), y: Math.round(cy + R * Math.sin(a)) };
  });
  var svg = "<svg viewBox='0 0 " + W + " " + H + "' class='graph-svg' role='img' aria-label='NetworkX attack graph'>" +
    "<defs><marker id='arr' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'><path d='M 0 0 L 10 5 L 0 10 z' fill='#f0a832'/></marker></defs>";
  edges.forEach(function(e) {
    var a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    var mx = Math.round((a.x + b.x) / 2), my = Math.round((a.y + b.y) / 2) - 12;
    svg += "<line x1='" + a.x + "' y1='" + a.y + "' x2='" + b.x + "' y2='" + b.y + "' class='gedge' marker-end='url(#arr)'/>" +
      "<text x='" + mx + "' y='" + my + "' class='elabel' data-edge='" + esc(e.technique_id) + "|" + esc(e.time) + "'>" + esc(e.technique_id) + "</text>";
  });
  nodes.forEach(function(n) {
    var p = pos[n.id];
    var shape = n.type === "host"
      ? "<rect x='" + (p.x - 34) + "' y='" + (p.y - 26) + "' width='68' height='52' rx='8' class='gnode host'/>"
      : n.type === "technique"
        ? "<polygon points='" + p.x + "," + (p.y - 30) + " " + (p.x + 34) + "," + p.y + " " + p.x + "," + (p.y + 30) + " " + (p.x - 34) + "," + p.y + "' class='gnode technique'/>"
        : "<circle cx='" + p.x + "' cy='" + p.y + "' r='30' class='gnode user'/>";
    // Labels go BELOW the shape, not inside it: a long hostname
    // (e.g. FGT60FTK00000000) is wider than a 68px square, so inside
    // labels overflowed and looked detached from the node.
    var nLabel = n.type === "technique" && n.name ? n.name + " (" + n.id + ")" : n.id;
    var nSub = n.type === "technique" && n.count ? n.type + " · ×" + fmtNum(n.count) : n.type;
    svg += "<g class='gnode-wrap' data-node='" + esc(n.id) + "' tabindex='0' role='button' aria-label='Show steps for " + esc(n.id) + "'>" +
      shape + "<text x='" + p.x + "' y='" + (p.y + 48) + "' class='nlabel'>" + esc(nLabel) + "</text>" +
      "<text x='" + p.x + "' y='" + (p.y + 66) + "' class='ntype'>" + esc(nSub) + "</text></g>";
  });
  svg += "</svg><p class='hint'>■ host &nbsp; ● user &nbsp; — arrow = NetworkX edge, label = MITRE technique. Click a node or an edge label.</p>";
  box.innerHTML = svg;
  box.querySelectorAll(".gnode-wrap").forEach(function(el) {
    el.addEventListener("click", function() { showNodeSteps(path, el.getAttribute("data-node")); });
    el.addEventListener("keydown", function(e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showNodeSteps(path, el.getAttribute("data-node")); } });
  });
  box.querySelectorAll(".elabel").forEach(function(el) {
    el.addEventListener("click", function() {
      var parts = el.getAttribute("data-edge").split("|");
      var idx = path.timeline.findIndex(function(s) { return s.technique_id === parts[0] && s.time === parts[1]; });
      if (idx >= 0) showStep(path, idx);
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

document.getElementById("copyBtn").addEventListener("click", function() {
  if (state.report) navigator.clipboard.writeText(state.report).then(function() { alert("Report copied."); });
});
document.getElementById("hindiBtn").addEventListener("click", async function() {
  if (!state.selected) return;
  var rep = await (await fetch("/incidents/" + state.selected.id + "/report?hindi=1")).json();
  document.getElementById("hindiNote").hidden = false;
  document.getElementById("report").textContent = (rep.hindi && rep.hindi.hindi) ? rep.hindi.hindi : "Hindi template not available.";
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
  if (p.stage === "uploading" && p.bytes_total > 0) {
    var pct = Math.min(100, Math.round(100 * p.bytes_received / p.bytes_total));
    bar.style.width = pct + "%";
    el.textContent = p.stage_text + " " + fmtNum(p.bytes_received) + " of " + fmtNum(p.bytes_total) + " bytes received (" + pct + "%).";
  } else if (p.stage === "reading" && p.estimated_total_events > 0) {
    var pct2 = Math.min(99, Math.round(100 * p.events / p.estimated_total_events));
    bar.style.width = pct2 + "%";
    el.textContent = p.stage_text + " " + fmtNum(p.events) + " lines read (about " + pct2 + "% of an estimated " +
      fmtNum(p.estimated_total_events) + "), " + fmtNum(p.detections) + " detections so far, at " +
      fmtNum(Math.round(p.events_per_second)) + " lines/sec. " +
      (p.eta_text ? "Estimated time left: " + p.eta_text + " (estimate — it updates as speed changes)." : "Estimating time left…");
  } else if (p.stage === "linking" || p.stage === "storing") {
    bar.style.width = "99%";
    el.textContent = p.stage_text + " " + fmtNum(p.events) + " lines read, " + fmtNum(p.detections) + " detections.";
  } else if (p.stage === "done") {
    bar.style.width = "100%";
    el.textContent = p.stage_text;
  } else if (p.error) {
    el.textContent = "Error: " + p.error;
  } else {
    el.textContent = p.stage_text;
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
      list.innerHTML = p.top_techniques.map(function(t) {
        return "<div class='card dark' style='margin:8px 0;padding:12px'><b>" + esc(t.technique_name) + " (" + esc(t.technique_id) + ")</b> — " +
          esc(t.kill_chain_stage) + " · ×" + fmtNum(t.count) + "<br>" +
          "<b>Tell (what gave it away):</b> a log line containing “" + esc(t.tell) + "”.<br>" +
          "<b>Why it matters:</b> " + esc(t.why) + "<br>" +
          "<b>How it helps you:</b> " + esc(t.help) + "</div>";
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
      showBackendStatus({ stage: "uploading", stage_text: "Step 1 of 4 — Receiving your file and saving it on this machine. It is not sent anywhere else.",
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
    document.getElementById("backendStatus").textContent = "Done — " + data.events + " lines read, " + data.detections +
      " detections, " + data.incidents + " incidents.";
    await loadIncidents();
    if (state.incidents.length) selectIncident(state.incidents[0].id);
  };
  xhr.onerror = function() {
    clearInterval(poll);
    document.getElementById("fileinfo").textContent = "Upload failed — the server could not be reached.";
  };
  xhr.send(file);
}

loadIncidents();

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
