// Pluggable log-source adapters — FULL version.
// No adapter makes a live network call in this build. No real key is used.
// Future server-side enrichment would read keys from .env (see .env.example);
// in this browser build enrichment always falls back to clearly-labelled mock data.

const ADAPTERS = [
  { id: "demo", name: "Built-in demo scenarios", kind: "demo" },
  { id: "file", name: "File upload — JSON / CSV", kind: "file" },
  { id: "paste", name: "Paste logs — JSON or pipe-separated", kind: "paste" },
  { id: "mock-siem", name: "Mock SIEM adapter (simulated, no live connection)", kind: "mock" },
];

// Placeholder config only. Never put a real key here, in app.js, or in git.
// A future server build would load these from a local .env file that is git-ignored.
const ENRICHMENT_CONFIG = {
  provider: "mock", // mock | mitre | threat-intel  (mock is the only live mode in this build)
  mitreApiKey: "YOUR_MITRE_API_KEY_HERE",
  threatIntelApiKey: "YOUR_THREAT_INTEL_API_KEY_HERE",
  keyConfigured: false, // flip to true ONLY in a private server build after setting .env
};

function normaliseEvent(raw, i) {
  const sev = String(raw.sev || raw.severity || "medium").toLowerCase();
  return {
    t: String(raw.t || raw.time || "00:00"),
    host: String(raw.host || "UNKNOWN-HOST"),
    user: String(raw.user || "unknown"),
    src: String(raw.src || raw.source || "adapter"),
    action: String(raw.action || raw.event || "Unknown event"),
    detail: String(raw.detail || raw.description || "No detail supplied."),
    stage: String(raw.stage || "Execution"),
    mitre: String(raw.mitre || raw.technique || "T1000 — Unmapped (demo)"),
    sev: ["critical", "high", "medium", "low"].includes(sev) ? sev : "medium",
    _adapter: raw._adapter || "adapter",
    _index: i,
  };
}

// Very small CSV parser handling quoted commas. Header row expected:
// t,host,user,src,action,detail,stage,mitre,sev
function parseCSVLogs(text) {
  const rows = [];
  let row = [], field = "", inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { inQuotes = !inQuotes; continue; }
    if (c === "," && !inQuotes) { row.push(field); field = ""; continue; }
    if ((c === "\n" || c === "\r") && !inQuotes) {
      if (field !== "" || row.length) { row.push(field); rows.push(row); }
      row = []; field = "";
      if (c === "\r" && text[i + 1] === "\n") i++;
      continue;
    }
    field += c;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  const clean = rows.filter(r => r.some(v => String(v).trim() !== ""));
  if (!clean.length) return [];
  const header = clean[0].map(h => String(h).trim().toLowerCase());
  const hasHeader = header.includes("host") || header.includes("action");
  const data = hasHeader ? clean.slice(1) : clean;
  return data.map((r, i) => normaliseEvent({
    t: r[0], host: r[1], user: r[2], src: r[3], action: r[4],
    detail: r[5], stage: r[6], mitre: r[7], sev: r[8], _adapter: "file",
  }, i));
}

function parseJSONLogs(text) {
  const parsed = JSON.parse(text);
  const arr = Array.isArray(parsed) ? parsed : (parsed.logs || parsed.events || []);
  if (!Array.isArray(arr)) throw new Error("JSON must be an array, or an object with a logs/events array.");
  return arr.map((r, i) => normaliseEvent({ ...r, _adapter: "file" }, i));
}

function parsePastedLogs(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[" ) || trimmed.startsWith("{")) {
    return parseJSONLogs(trimmed).map(e => ({ ...e, _adapter: "paste" }));
  }
  // Pipe-separated lines: time | host | user | src | action | detail | stage | mitre | sev
  return trimmed.split(/\n+/).filter(l => l.trim()).map((line, i) => {
    const p = line.split("|").map(s => s.trim());
    if (p.length < 5 || !p[4]) throw new Error(`Line ${i + 1}: pipe-separated logs need at least time | host | user | src | action — got ${p.length} field(s). Check that line and try again; nothing was loaded.`);
    return normaliseEvent({
      t: p[0], host: p[1], user: p[2], src: p[3], action: p[4],
      detail: p[5], stage: p[6], mitre: p[7], sev: p[8], _adapter: "paste",
    }, i);
  });
}

// Mock SIEM: returns a synthetic incident after a short simulated delay.
// This is NOT a live SIEM connection and must never be presented as one.
function fetchMockSiemIncident() {
  return new Promise(resolve => setTimeout(() => resolve([
    { t: "11:02", host: "WS-102", user: "demo.analyst", src: "mock-siem", action: "Suspicious PowerShell download", detail: "Synthetic mock-SIEM alert: encoded PowerShell fetched a payload from a demo domain. No real host involved.", stage: "Execution", mitre: "T1059.001 — PowerShell", sev: "high", _adapter: "mock-siem" },
    { t: "11:09", host: "WS-102", user: "demo.analyst", src: "mock-siem", action: "Credential access via browser store", detail: "Synthetic mock-SIEM alert: browser credential store read by the same session.", stage: "Privilege Escalation", mitre: "T1555.003 — Credentials from Password Stores", sev: "critical", _adapter: "mock-siem" },
    { t: "11:21", host: "SRV-APP-07", user: "svc-demo", src: "mock-siem", action: "Lateral movement via WinRM", detail: "Synthetic mock-SIEM alert: WinRM session from WS-102 to an application server using a demo service account.", stage: "Lateral Movement", mitre: "T1021.006 — Windows Remote Management", sev: "critical", _adapter: "mock-siem" },
    { t: "11:38", host: "SRV-APP-07", user: "svc-demo", src: "mock-siem", action: "Archive staged for upload", detail: "Synthetic mock-SIEM alert: staging folder created with compressed demo data.", stage: "Collection", mitre: "T1560.001 — Archive Collected Data", sev: "high", _adapter: "mock-siem" },
  ].map((e, i) => normaliseEvent(e, i))), 500));
}

// Mock enrichment only. If a future build sets a real key server-side, that
// build should replace this function — never call a live API from this file.
function mockEnrich(event) {
  return {
    mode: ENRICHMENT_CONFIG.keyConfigured ? "key-configured (placeholder — no live call in this build)" : "mock fallback — no key configured",
    techniqueNote: "Technique label is illustrative. In a key-configured build, enrich this ID from the maintained MITRE dataset.",
    hostNote: "Host is synthetic. Do not treat this as a real asset or indicator.",
    eventAction: event.action,
  };
}

if (typeof window !== "undefined") {
  window.KillChainAdapters = { ADAPTERS, ENRICHMENT_CONFIG, normaliseEvent, parseCSVLogs, parseJSONLogs, parsePastedLogs, fetchMockSiemIncident, mockEnrich };
}
