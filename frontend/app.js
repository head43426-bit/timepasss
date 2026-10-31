"use strict";
var state = { incidents: [], selected: null, report: "", hindi: null };

function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

async function loadIncidents() {
  var res = await fetch("/incidents");
  var list = await res.json();
  state.incidents = list;
  var health = await (await fetch("/health")).json();
  document.getElementById("stats").innerHTML =
    "<div class=stat><b>" + list.length + "</b><span>incidents</span></div>" +
    "<div class=stat><b>" + health.detections + "</b><span>detections</span></div>" +
    "<div class=stat><b>" + list.reduce(function(n, i) { return n + (i.merged_alerts || 0); }, 0) + "</b><span>raw alerts merged</span></div>";
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
    "<br>Users: " + esc(path.users.join(", ")) + "</p>";
  // Conveyor belt: EVERY package is a real <button> you press.
  document.getElementById("belt").innerHTML = path.timeline.map(function(step, i) {
    return "<button class=pkg type=button data-i=" + i + " aria-label='Inspect step " + (i + 1) + ": " + esc(step.kill_chain_stage) + "'>" +
      "<b>Package " + String(i + 1).padStart(2, "0") + " — " + esc(step.kill_chain_stage) + "</b>" +
      esc(step.technique_id) + " — " + esc(step.technique_name) + "<br><small>" +
      esc(step.host) + " &middot; " + esc(step.user) + "</small>" +
      "<span class=press>Press to inspect step " + (i + 1) + " &rarr;</span></button>";
  }).join("");
  document.querySelectorAll(".pkg").forEach(function(el) {
    el.addEventListener("click", function() { showStep(path, parseInt(el.getAttribute("data-i"), 10)); });
  });
  document.getElementById("path").innerHTML = path.hosts.map(function(h) {
    return "<span class=node>" + esc(h) + "</span>";
  }).join("<span class=arrow>&rarr;</span>") || "<p>Unknown host path.</p>";
  document.getElementById("next").innerHTML = (next.next_reach && next.next_reach.length)
    ? "<ul>" + next.next_reach.map(function(n) {
        return "<li><b>" + esc(n.host) + "</b> (" + n.confidence + "%) — " + esc(n.reason) + ". Block it by: " + esc(n.block) + ".</li>";
      }).join("") + "</ul>"
    : "<p>No next system could be identified from the supplied topology, so no next target is guessed. To get next-reach predictions, run the CLI with a topology file.</p>";
  document.getElementById("report").textContent = state.report;
  document.getElementById("copyBtn").disabled = false;
  document.getElementById("hindiBtn").disabled = false;
  if (path.timeline.length) showStep(path, 0);
  document.getElementById("detailSection").scrollIntoView({ behavior: "smooth" });
}

function showStep(path, i) {
  var step = path.timeline[i];
  document.querySelectorAll(".pkg").forEach(function(el) {
    el.classList.toggle("sel", parseInt(el.getAttribute("data-i"), 10) === i);
    el.setAttribute("aria-pressed", parseInt(el.getAttribute("data-i"), 10) === i ? "true" : "false");
  });
  document.getElementById("stepDetail").innerHTML =
    "<b>Step " + (i + 1) + " — " + esc(step.kill_chain_stage) + "</b><br>" +
    esc(step.technique_id) + " — " + esc(step.technique_name) + " (" + step.confidence + "% confidence, " + esc(step.severity) + ")<br>" +
    esc(step.action) + " — " + esc(step.detail) + "<br><small>Time: " + esc(step.time) + " &middot; Host: " + esc(step.host) +
    " &middot; User: " + esc(step.user) + " &middot; Source: " + esc(step.source) + "<br>Why this flagged: " + esc(step.reason) + "</small>";
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

async function handleFile(file) {
  document.getElementById("bar").style.width = "40%";
  document.getElementById("fileinfo").textContent = "Uploading and processing " + file.name + " on the backend…";
  var res = await fetch("/upload", { method: "POST", headers: { "X-Filename": file.name }, body: file });
  var data = await res.json();
  document.getElementById("bar").style.width = "100%";
  if (data.error) {
    document.getElementById("fileinfo").textContent = "Error: " + data.error;
    return;
  }
  document.getElementById("fileinfo").textContent = file.name + " — " + data.events + " lines, " + data.detections +
    " detections, " + data.incidents + " incidents, in " + data.seconds + "s. Nothing was stored except the database on this machine.";
  await loadIncidents();
  if (state.incidents.length) selectIncident(state.incidents[0].id);
}

loadIncidents();
