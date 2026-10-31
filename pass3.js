// Kill Chain — Refinement Pass 3 (shared by simulation and full builds).
// Plain-language layer + what-if + animated graph + comparison + playbook.
// No new data source, no network call, no real logs/keys. All user text is
// rendered through the host build's existing escaper (esc / escapeHtml).
(function () {
  "use strict";
  var P3_ESC = (typeof escapeHtml === "function") ? escapeHtml : esc;
  var P3_RISK = function () { return (typeof computeRisk === "function") ? computeRisk() : current.risk; };
  var P3_RISK_FOR = function (s) { return (typeof computeRiskFor === "function") ? computeRiskFor(s) : s.risk; };
  var P3_STAGES = function () { return (typeof currentStages === "function") ? currentStages() : current.stages; };
  var $ = function (id) { return document.getElementById(id); };

  var PLAIN = {
    "Reconnaissance": "Someone was quietly looking around for a weak spot.",
    "Initial Access": "They got in — through a trick email, a website hole, or a stolen login.",
    "Execution": "They got a program running inside the computer.",
    "Persistence": "They planted a way back in, so they could return later.",
    "Privilege Escalation": "They grabbed higher permissions than they should have.",
    "Defense Evasion": "They tried to hide their tracks.",
    "Lateral Movement": "They moved from one computer to another inside the network.",
    "Collection": "They gathered the files they wanted to take.",
    "Exfiltration": "They sent those files out of the company.",
    "Impact": "They damaged, locked, or disrupted something."
  };
  var SHORT = {
    "Reconnaissance": "Look around", "Initial Access": "Get in", "Execution": "Run code",
    "Persistence": "Stay in", "Privilege Escalation": "Get power", "Defense Evasion": "Hide",
    "Lateral Movement": "Spread", "Collection": "Gather", "Exfiltration": "Steal out", "Impact": "Damage"
  };
  var PLAYBOOK = {
    "Reconnaissance": ["Block the probing source and patch the exposed service it was scanning.", "Turn on alerting for repeated failed probes from one source."],
    "Initial Access": ["Block the lookalike sender / malicious link and warn everyone who got it.", "Turn on multi-factor login so a stolen password alone is not enough."],
    "Execution": ["Block macros and untrusted files from running automatically.", "Quarantine the affected computer and check what the program touched."],
    "Persistence": ["Remove the hidden scheduled task, new account, or new API key.", "Search other computers for the same persistence trick."],
    "Privilege Escalation": ["Reset the affected passwords and revoke the escalated session.", "Remove admin rights the account should never have had."],
    "Defense Evasion": ["Restore logging and check what was cleared or hidden.", "Alert on log-clearing and beaconing to unknown hosts."],
    "Lateral Movement": ["Isolate the affected computers from the rest of the network.", "Block the shared-drive / remote-login route that was abused."],
    "Collection": ["Check exactly which folders and records were copied.", "Lock down access to those folders to only the people who need them."],
    "Exfiltration": ["Block the outside destination and revoke the shared / download link.", "Work out what left, tell the affected people, and preserve evidence."],
    "Impact": ["Restore from a clean backup and verify nothing is still locked or broken.", "Keep the system offline until the damage is fully checked."]
  };
  var SEV_W = { critical: 40, high: 25, medium: 10, low: 3 };

  var p3Blocked = -1;
  var p3Checked = new Set();
  var p3LastScenario = null;

  function sevWeight(s) { return SEV_W[s] || 10; }
  function stagesOf() { return P3_STAGES(); }
  function blockedStats() {
    var totalW = current.logs.reduce(function (a, l) { return a + sevWeight(l.sev); }, 0);
    if (p3Blocked < 0 || !current.logs.length) return null;
    var kept = current.logs.slice(0, p3Blocked);
    var keptW = kept.reduce(function (a, l) { return a + sevWeight(l.sev); }, 0);
    var prevented = current.logs.length - kept.length;
    var newRisk = totalW ? Math.round(P3_RISK() * keptW / totalW) : 0;
    return {
      kept: kept, prevented: prevented,
      hosts: new Set(kept.map(function (l) { return l.host; })).size,
      users: new Set(kept.map(function (l) { return l.user; })).size,
      newRisk: newRisk
    };
  }

  function renderPlain() {
    var el = $("plainStory"); if (!el) return;
    if (!current.logs.length) { el.innerHTML = "<p>No events yet, so there is no plain-English story yet.</p>"; return; }
    var byStage = {};
    current.logs.forEach(function (l) { (byStage[l.stage] = byStage[l.stage] || []).push(l); });
    var html = "<p class=\"p3-lead\">In short: <b>" + P3_ESC(current.title) + "</b> — " + P3_ESC(current.subtitle || current.summary) + "</p>";
    html += stagesOf().map(function (stage, i) {
      var ev = byStage[stage] || [];
      if (!ev.length) return "";
      return "<div class=\"p3-step\"><h4>Step " + (i + 1) + " — " + P3_ESC(SHORT[stage] || stage) + "</h4>" +
        "<p>" + P3_ESC(PLAIN[stage] || stage) + "</p>" +
        "<p class=\"p3-evidence\">Evidence: " + ev.map(function (e) { return P3_ESC(e.t) + " — " + P3_ESC(e.action) + " (" + P3_ESC(e.host) + ")"; }).join("; ") + ".</p></div>";
    }).join("");
    if (p3Blocked >= 0) html += "<p class=\"p3-note\">What-if is on: the step at " + P3_ESC(current.logs[p3Blocked].action) + " is treated as blocked — everything after it is shown as prevented below.</p>";
    el.innerHTML = html;
  }

  function renderSoWhat() {
    var el = $("soWhat"); if (!el) return;
    if (!current.logs.length) { el.innerHTML = "<p>No case loaded yet.</p>"; return; }
    var hosts = Array.from(new Set(current.logs.map(function (l) { return l.host; })));
    var users = Array.from(new Set(current.logs.map(function (l) { return l.user; })));
    var exf = current.logs.filter(function (l) { return l.stage === "Exfiltration"; });
    var taken = exf.length ? exf.map(function (e) { return P3_ESC(e.action); }).join("; ") + " — data could leave the company in this story." : "Nothing left in this case — there is no exfiltration step here.";
    var stops = [];
    stagesOf().slice(0, 3).forEach(function (st) { (PLAYBOOK[st] || []).slice(0, 1).forEach(function (a) { stops.push(a); }); });
    el.innerHTML =
      "<p><b>" + hosts.length + " computer(s) touched:</b> " + hosts.map(P3_ESC).join(", ") + "</p>" +
      "<p><b>" + users.length + " account(s) involved:</b> " + users.map(P3_ESC).join(", ") + "</p>" +
      "<p><b>What could be taken?</b> " + taken + "</p>" +
      "<p><b>What stops it next?</b> " + stops.map(P3_ESC).join(" ") + "</p>" +
      "<p class=\"p3-note\">Risk in this case: <b>" + P3_RISK() + "/100</b>. That is a demo score for comparing cases, not a real-world prediction.</p>";
  }

  function renderWhatIf() {
    var sel = $("whatifSelect"), out = $("whatifResult"); if (!sel || !out) return;
    var keep = sel.value;
    sel.innerHTML = "<option value=\"-1\">No step blocked — the full attack plays out</option>" +
      current.logs.map(function (l, i) { return "<option value=\"" + i + "\">Block step " + (i + 1) + ": " + P3_ESC(l.action) + " (" + P3_ESC(l.host) + ")</option>"; }).join("");
    sel.value = keep !== null && keep !== undefined ? keep : "-1";
    if (sel.value === "" || sel.value === null) sel.value = "-1";
    p3Blocked = parseInt(sel.value, 10);
    var origHosts = new Set(current.logs.map(function (l) { return l.host; })).size;
    var origUsers = new Set(current.logs.map(function (l) { return l.user; })).size;
    if (p3Blocked < 0 || !current.logs.length) {
      out.innerHTML = "<p>Nothing blocked yet. Pick a step above to see the attack shrink in real time.</p>" +
        "<p>Before: risk <b>" + P3_RISK() + "/100</b>, " + origHosts + " host(s), " + origUsers + " user(s).</p>";
    } else {
      var b = blockedStats();
      out.innerHTML = "<p><b>If you block \u2018" + P3_ESC(current.logs[p3Blocked].action) + "\u2019</b>, " + b.prevented + " later step(s) are prevented.</p>" +
        "<div class=\"p3-bars\"><div><span>Risk before</span><div class=\"p3-bar\"><i style=\"width:" + P3_RISK() + "%\"></i></div><b>" + P3_RISK() + "/100</b></div>" +
        "<div><span>Risk after</span><div class=\"p3-bar green\"><i style=\"width:" + b.newRisk + "%\"></i></div><b>" + b.newRisk + "/100</b></div></div>" +
        "<p>Blast radius falls from " + origHosts + " host(s) / " + origUsers + " user(s) to " + b.hosts + " host(s) / " + b.users + " user(s) in this what-if. This is a demo estimate, not a guarantee — a real attacker may try another route.</p>";
    }
    document.querySelectorAll("#timeline li[data-idx]").forEach(function (li) {
      var idx = parseInt(li.dataset.idx, 10);
      li.classList.toggle("p3-blocked", p3Blocked >= 0 && idx > p3Blocked);
      li.classList.toggle("p3-blocked-step", idx === p3Blocked);
    });
  }

  function renderGraph() {
    var wrap = $("graphWrap"); if (!wrap) return;
    var stages = stagesOf();
    if (!stages.length) { wrap.innerHTML = "<p>No stages to draw yet.</p>"; return; }
    var W = 900, H = 170, pad = 46;
    var step = stages.length > 1 ? (W - pad * 2) / (stages.length - 1) : 0;
    var blockedStage = p3Blocked >= 0 && current.logs[p3Blocked] ? current.logs[p3Blocked].stage : null;
    var blockedIdx = blockedStage ? stages.indexOf(blockedStage) : -1;
    var sevOf = function (stage) {
      var ev = current.logs.filter(function (l) { return l.stage === stage; });
      if (ev.some(function (e) { return e.sev === "critical"; })) return "#ff5a5a";
      if (ev.some(function (e) { return e.sev === "high"; })) return "#ffb020";
      return "#2bff88";
    };
    var edges = "", nodes = "";
    stages.forEach(function (stage, i) {
      var x = pad + i * step, y = 72;
      if (i > 0) {
        var px = pad + (i - 1) * step;
        var dim = blockedIdx >= 0 && i > blockedIdx;
        edges += "<line class=\"flow-edge" + (dim ? " dim" : "") + "\" x1=\"" + (px + 26) + "\" y1=\"" + y + "\" x2=\"" + (x - 26) + "\" y2=\"" + y + "\" />";
      }
      var count = current.logs.filter(function (l) { return l.stage === stage; }).length;
      nodes += "<g class=\"graph-node\" tabindex=\"0\" role=\"button\" data-stage=\"" + P3_ESC(stage) + "\" aria-label=\"Stage " + P3_ESC(stage) + ", " + count + " evidence events, plain meaning: " + P3_ESC(SHORT[stage] || stage) + "\">" +
        "<circle cx=\"" + x + "\" cy=\"" + y + "\" r=\"24\" fill=\"#0a0f0c\" stroke=\"" + sevOf(stage) + "\" stroke-width=\"2\" />" +
        "<text x=\"" + x + "\" y=\"" + (y + 5) + "\" text-anchor=\"middle\" fill=\"#e8f2ea\" font-size=\"13\" font-weight=\"800\">" + (i + 1) + "</text>" +
        "<text x=\"" + x + "\" y=\"" + (y + 44) + "\" text-anchor=\"middle\" fill=\"#93a89a\" font-size=\"11\">" + P3_ESC(SHORT[stage] || stage) + "</text>" +
        "<text x=\"" + x + "\" y=\"" + (y + 60) + "\" text-anchor=\"middle\" fill=\"#93a89a\" font-size=\"10\">" + count + " event" + (count === 1 ? "" : "s") + "</text></g>";
    });
    wrap.innerHTML = "<svg viewBox=\"0 0 " + W + " " + H + "\" role=\"img\" aria-label=\"Animated attack path: " + stages.map(function (s) { return SHORT[s] || s; }).join(" then ") + "\">" + edges + nodes + "</svg>" +
      "<p class=\"p3-note\">Tap a circle to jump to that step's evidence. Flowing lines are the attack moving; a dimmed line after a blocked step means that route is stopped in the what-if.</p>";
    wrap.querySelectorAll(".graph-node").forEach(function (g) {
      var go = function () {
        var first = current.logs.findIndex(function (l) { return l.stage === g.dataset.stage; });
        if (first >= 0 && typeof selectEvent === "function") selectEvent(first);
      };
      g.addEventListener("click", go);
      g.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
    });
  }

  function renderCompare() {
    var el = $("compareTable"); if (!el) return;
    var rows = SCENARIOS.map(function (s) {
      var hosts = new Set(s.logs.map(function (l) { return l.host; })).size;
      var users = new Set(s.logs.map(function (l) { return l.user; })).size;
      var exf = s.logs.some(function (l) { return l.stage === "Exfiltration"; });
      var active = s.id === current.id ? " class=\"active\"" : "";
      return "<tr" + active + "><td><button class=\"btn ghost small\" data-id=\"" + P3_ESC(s.id) + "\">Open</button></td>" +
        "<td><b>" + P3_ESC(s.title) + "</b></td><td>" + P3_RISK_FOR(s) + "/100</td><td>" + s.logs.length + "</td>" +
        "<td>" + hosts + "</td><td>" + users + "</td><td>" + (exf ? "Yes" : "No") + "</td></tr>";
    }).join("");
    el.innerHTML = "<table><thead><tr><th></th><th>Story</th><th>Risk</th><th>Events</th><th>Hosts</th><th>Users</th><th>Data leaves?</th></tr></thead><tbody>" + rows + "</tbody></table>";
    el.querySelectorAll("button[data-id]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        if (typeof stopReplay === "function") stopReplay();
        current = SCENARIOS.find(function (s) { return s.id === btn.dataset.id; });
        selectedIndex = -1; replayIndex = 0; p3Blocked = -1;
        if (typeof buildStageFilter === "function") buildStageFilter();
        if (typeof buildMappingEditor === "function") buildMappingEditor();
        renderAll();
        document.getElementById("scenarioRow").scrollIntoView({ block: "nearest", behavior: "smooth" });
      });
    });
  }

  function playbookItems() {
    var items = [];
    stagesOf().forEach(function (st) { (PLAYBOOK[st] || []).forEach(function (a) { if (items.indexOf(a) < 0) items.push(a); }); });
    items.push("Isolate affected computers, then reset passwords and revoke sessions for every involved account.");
    items.push("Tell the team what was found, in plain words, and keep the evidence before wiping anything.");
    return items;
  }
  function renderPlaybook() {
    var el = $("playbookList"), prog = $("playbookProgress"); if (!el) return;
    var items = playbookItems();
    el.innerHTML = items.map(function (a, i) {
      return "<label class=\"p3-check\"><input type=\"checkbox\" data-i=\"" + i + "\"" + (p3Checked.has(i) ? " checked" : "") + "> " + P3_ESC(a) + "</label>";
    }).join("");
    var done = items.filter(function (_, i) { return p3Checked.has(i); }).length;
    if (prog) {
      prog.innerHTML = "<div class=\"p3-bar green\"><i style=\"width:" + (items.length ? Math.round(done / items.length * 100) : 0) + "%\"></i></div><span>" + done + " of " + items.length + " containment steps ticked — ticking a box here is a demo checklist only, it does not change any real system.</span>";
    }
    el.querySelectorAll("input[type=checkbox]").forEach(function (cb) {
      cb.addEventListener("change", function () {
        var i = parseInt(cb.dataset.i, 10);
        if (cb.checked) p3Checked.add(i); else p3Checked.delete(i);
        renderPlaybook();
      });
    });
  }

  function renderScrubber() {
    var sc = $("scrubber"), lab = $("scrubberLabel"); if (!sc) return;
    sc.max = current.logs.length;
    if (document.activeElement !== sc) sc.value = replayIndex;
    if (lab) lab.textContent = replayIndex === 0 ? "Step 0 of " + current.logs.length + " — drag to walk the attack" :
      "Step " + replayIndex + " of " + current.logs.length + " — " + P3_ESC(current.logs[Math.min(replayIndex, current.logs.length) - 1].action);
  }

  function animateCounters() {
    if (p3LastScenario === current.id) return;
    p3LastScenario = current.id;
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    document.querySelectorAll("#statGrid .stat b").forEach(function (b, idx) {
      if (idx > 1) return;
      var m = b.textContent.match(/^(\d+)/); if (!m) return;
      var target = parseInt(m[1], 10), suffix = b.textContent.slice(m[1].length), start = null;
      var stepFn = function (ts) {
        if (!start) start = ts;
        var p = Math.min(1, (ts - start) / 600);
        b.textContent = Math.round(target * p) + suffix;
        if (p < 1) requestAnimationFrame(stepFn);
      };
      requestAnimationFrame(stepFn);
    });
  }

  var p3LastRenderScenario = null;
  function p3RenderAll() {
    // A what-if block belongs to one case only: switching scenario resets it,
    // otherwise a stale blocked index would silently apply to a new story.
    if (p3LastRenderScenario !== current.id) {
      p3LastRenderScenario = current.id; p3Blocked = -1;
      var ws0 = $("whatifSelect"); if (ws0) ws0.value = "-1";
    }
    renderPlain(); renderSoWhat(); renderWhatIf(); renderGraph(); renderCompare(); renderPlaybook(); renderScrubber(); animateCounters();
  }

  // Bind once (renderAll is re-entrant via the wrapper below, so guard).
  var p3OrigRenderAll = renderAll;
  renderAll = function () { p3OrigRenderAll(); p3RenderAll(); };

  document.addEventListener("DOMContentLoaded", function () { p3RenderAll(); });
  // If the host script already ran before this file loaded, render now.
  if (document.readyState !== "loading") p3RenderAll();

  var sc = $("scrubber");
  if (sc) sc.addEventListener("input", function () {
    if (typeof stopReplay === "function") stopReplay();
    replayIndex = parseInt(sc.value, 10);
    if (replayIndex <= 0) { selectedIndex = -1; renderChain(); renderTimeline(); }
    else if (typeof selectEvent === "function") selectEvent(replayIndex - 1);
    renderScrubber(); renderGraph(); renderWhatIf();
  });
  var ws = $("whatifSelect");
  if (ws) ws.addEventListener("change", function () { p3RenderAll(); });
  document.querySelectorAll(".tour-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var step = btn.dataset.tour, status = $("tourStatus");
      if (step === "1") {
        if (typeof startReplay === "function") startReplay();
        if (status) status.textContent = "Step 1 done: replay is walking the attack. Watch the circles light up, then try Step 2.";
      } else if (step === "2") {
        if (typeof stopReplay === "function") stopReplay();
        var mid = Math.max(1, Math.floor(current.logs.length / 2));
        replayIndex = mid;
        if (typeof selectEvent === "function") selectEvent(mid - 1);
        p3RenderAll();
        if (status) status.textContent = "Step 2 done: you jumped to the middle of the attack. Drag the scrubber under the timeline to walk it yourself.";
        document.getElementById("timeline").scrollIntoView({ block: "nearest", behavior: "smooth" });
      } else if (step === "3") {
        var sel2 = $("whatifSelect");
        if (sel2 && current.logs.length > 1) { sel2.value = "1"; p3RenderAll(); }
        if (status) status.textContent = "Step 3 done: the second step is now treated as blocked — see risk and blast radius drop in the What-if panel.";
        document.getElementById("whatifPanel").scrollIntoView({ block: "nearest", behavior: "smooth" });
      }
    });
  });
})();
