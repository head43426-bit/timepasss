// Kill Chain engine port (server actions).
//
// This file ports the Python engine design (Python + DuckDB + NetworkX,
// Sigma-style YAML rules) into the artifact's typed server actions, rule
// for rule: same parser formats, same detector semantics, same 48h
// linking window, same risk formula, same graph construction, same
// next-reach-from-topology-only rule, and the same report templates.
// The Engine chapter in the UI says plainly that this is a port running
// in the artifact runtime, with the Python/DuckDB/NetworkX engine as the
// design source. Nothing here claims Python executes inside the artifact.

import { defineAction, z, type ActionsModule, type Ctx } from "@hatch/space-sdk";
import { asc, desc, eq, inArray } from "drizzle-orm";
import * as schema from "./schema";

// ---------------------------------------------------------------------------
// Default rules (verbatim content of rules/core.yml + brute_force.yml +
// custom_example.yml from the Kill Chain Python engine, comments trimmed).
// ---------------------------------------------------------------------------

export const DEFAULT_RULES_YAML = `rules:
  - id: exfiltration_upload
    name: Data upload to an outside IP
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    tactic: Exfiltration
    kill_chain_stage: Exfiltration
    confidence: 90
    priority: 100
    description: Large upload to an outside IP
    match:
      any_contains: ["upload to outside", "upload to an outside", "data exfiltrated"]
  - id: log_clearing
    name: Security logs cleared
    technique_id: T1070
    technique_name: Indicator Removal
    tactic: Defense Evasion
    kill_chain_stage: Defense Evasion
    confidence: 85
    priority: 95
    description: Event logs cleared on a host
    match:
      any_contains: ["logs cleared", "event logs cleared", "log cleared"]
  - id: credential_dump
    name: Credential dumping
    technique_id: T1003.001
    technique_name: LSASS Memory
    tactic: Credential Access
    kill_chain_stage: Credential Access
    confidence: 90
    priority: 95
    description: Credential dump via LSASS / Mimikatz
    match:
      any_contains: ["credential dump", "lsass", "mimikatz"]
  - id: web_shell
    name: Web shell command
    technique_id: T1505.003
    technique_name: Web Shell
    tactic: Persistence
    kill_chain_stage: Persistence
    confidence: 90
    priority: 95
    description: Web shell command executed
    match:
      any_contains: ["web shell"]
  - id: new_admin_account
    name: New admin account created
    technique_id: T1136
    technique_name: Create Account
    tactic: Persistence
    kill_chain_stage: Persistence
    confidence: 85
    priority: 90
    description: New admin account created
    match:
      any_contains: ["new admin account"]
  - id: kerberoasting
    name: Kerberoasting attempt
    technique_id: T1558.003
    technique_name: Kerberoasting
    tactic: Credential Access
    kill_chain_stage: Credential Access
    confidence: 90
    priority: 90
    description: Kerberoasting attempt against a service account
    match:
      any_contains: ["kerberoasting"]
  - id: phishing
    name: Phishing email opened
    technique_id: T1566.001
    technique_name: "Phishing: Spearphishing Attachment"
    tactic: Initial Access
    kill_chain_stage: Initial Access
    confidence: 85
    priority: 85
    description: Phishing email opened
    match:
      any_contains: ["phishing", "malicious attachment"]
  - id: macro_execution
    name: Malicious macro executed
    technique_id: T1204.002
    technique_name: Malicious File
    tactic: Execution
    kill_chain_stage: Execution
    confidence: 80
    priority: 85
    description: Office document macro executed
    match:
      any_contains: ["macro executed", "macro"]
  - id: scheduled_task
    name: Scheduled task created
    technique_id: T1053.005
    technique_name: Scheduled Task
    tactic: Persistence
    kill_chain_stage: Persistence
    confidence: 85
    priority: 85
    description: Scheduled task created for persistence
    match:
      any_contains: ["scheduled task"]
  - id: lateral_smb
    name: Lateral movement over SMB
    technique_id: T1021.002
    technique_name: SMB/Windows Admin Shares
    tactic: Lateral Movement
    kill_chain_stage: Lateral Movement
    confidence: 85
    priority: 85
    description: SMB lateral movement to another host
    match:
      any_contains: ["smb lateral", "lateral movement"]
  - id: c2_beacon
    name: Command-and-control beacon
    technique_id: T1071.001
    technique_name: Web Protocols
    tactic: Command and Control
    kill_chain_stage: Command and Control
    confidence: 85
    priority: 85
    description: Periodic C2 beacon to an external server
    match:
      any_contains: ["c2 beacon", "command and control beacon", "beacon"]
  - id: staging
    name: Data staging for exfiltration
    technique_id: T1560
    technique_name: Archive Collected Data
    tactic: Collection
    kill_chain_stage: Collection
    confidence: 80
    priority: 80
    description: Files staged / collected for transfer
    match:
      any_contains: ["staging files", "files collected for transfer"]
  - id: privilege_escalation
    name: Privilege escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    tactic: Privilege Escalation
    kill_chain_stage: Privilege Escalation
    confidence: 85
    priority: 80
    description: Privilege escalation on a host
    match:
      any_contains: ["privilege escalation", "escalated privileges"]
  - id: port_scan
    name: Active port scanning
    technique_id: T1595
    technique_name: Active Scanning
    tactic: Reconnaissance
    kill_chain_stage: Reconnaissance
    confidence: 75
    priority: 70
    description: Port scan against internal hosts
    match:
      any_contains: ["port scan"]
  - id: brute_force
    name: Brute force then success
    technique_id: T1110
    technique_name: Brute Force
    tactic: Credential Access
    kill_chain_stage: Credential Access
    confidence: 90
    priority: 100
    description: 50 failed logins followed by a success for the same account
    type: aggregate
    threshold: 50
    window_minutes: 120
    group_by: ["user", "host"]
    trigger:
      action_contains: ["login failed"]
    success:
      action_contains: ["login success"]
  - id: midnight_db_export
    name: Midnight database export
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    tactic: Exfiltration
    kill_chain_stage: Exfiltration
    confidence: 75
    priority: 60
    description: Database export outside working hours
    match:
      any_contains: ["midnight database export"]
`;

const DEFAULT_TOPOLOGY = {
  hosts: [
    "WS-041", "WS-042", "LAP-118", "WS-101", "WS-202", "WS-303",
    "SRV-FILE-02", "SRV-APP-01", "DB-01", "HR-07", "HR-08", "FS-02",
    "FS-03", "DC-01", "DC-02", "WEB-01", "VPN-01",
  ],
  subnets: {
    "office-a": ["WS-041", "WS-042", "LAP-118"],
    "office-b": ["WS-101", "WS-202", "WS-303"],
    "servers-a": ["SRV-FILE-02", "SRV-APP-01", "DB-01"],
    infra: ["HR-07", "HR-08", "FS-02", "FS-03", "DC-01", "DC-02", "WEB-01", "VPN-01"],
  },
  admin_rights: {
    "svc-backup": ["SRV-APP-01", "SRV-FILE-02", "DB-01"],
    "svc-web": ["DB-01", "SRV-APP-01"],
    hsingh: ["FS-02", "DC-01"],
  },
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Cond = {
  anyContains?: string[];
  actionContains?: string[];
  detailContains?: string[];
  actionEquals?: string;
  severityIn?: string[];
  sourceContains?: string[];
};

type Rule = {
  id: string;
  name: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  stage: string;
  confidence: number;
  priority: number;
  description: string;
  type: "simple" | "aggregate";
  threshold: number;
  windowMinutes: number;
  groupBy: string[];
  match: Cond;
  trigger: Cond;
  success: Cond;
};

type LogEvent = {
  time: string;
  ts: number | null;
  host: string;
  user: string;
  ip: string;
  source: string;
  action: string;
  detail: string;
  severity: string;
};

type Detection = Omit<LogEvent, "ts"> & {
  ts: number | null;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  stage: string;
  confidence: number;
  ruleId: string;
  mergedAlerts: number;
  reason: string;
};

type AggState = Record<string, Record<string, number[]>>;

type Topology = {
  hostSubnet: Record<string, string>;
  adminRights: Record<string, string[]>;
};

// ---------------------------------------------------------------------------
// Log parsing (mirrors engine/parser.py)
// ---------------------------------------------------------------------------

function parseTimestamp(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = String(value).trim();
  if (text === "") return null;
  const asNum = Number(text);
  if (Number.isFinite(asNum) && /^-?\d+(\.\d+)?$/.test(text)) return asNum;
  const ms = Date.parse(text.replace(" ", "T"));
  if (!Number.isNaN(ms)) return ms / 1000;
  return null;
}

function pick(raw: Record<string, unknown>, keys: string[], fallback = ""): string {
  for (const k of keys) {
    const v = raw[k];
    if (v !== null && v !== undefined && v !== "") return String(v);
  }
  return fallback;
}

function normalise(raw: Record<string, unknown>): LogEvent {
  const timeValue = pick(raw, ["time", "timestamp", "t", "datetime"]);
  return {
    time: timeValue,
    ts: parseTimestamp(raw["time"] ?? raw["timestamp"] ?? raw["t"] ?? raw["datetime"]),
    host: pick(raw, ["host", "hostname", "device"]),
    user: pick(raw, ["user", "username", "account"]),
    ip: pick(raw, ["ip", "src_ip", "source_ip"]),
    source: pick(raw, ["source", "src", "system"]),
    action: pick(raw, ["action", "event", "event_type"]),
    detail: pick(raw, ["detail", "message", "description", "msg"]),
    severity: pick(raw, ["severity", "sev", "level"], "Medium"),
  };
}

function parseCsvRow(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i] ?? "";
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i += 1; } else quoted = false;
      } else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

export function parseLine(line: string): LogEvent | null {
  const trimmed = line.trim();
  if (trimmed === "") return null;
  if (trimmed.startsWith("{")) {
    try {
      const data: unknown = JSON.parse(trimmed);
      if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
      return normalise(data as Record<string, unknown>);
    } catch {
      return null;
    }
  }
  if (trimmed.includes("|")) {
    const parts = trimmed.split("|").map((p) => p.trim());
    if (parts.length === 10) {
      const keys = ["time", "host", "user", "ip", "source", "action", "detail", "stage", "technique", "severity"];
      return normalise(Object.fromEntries(keys.map((k, i) => [k, parts[i] ?? ""])));
    }
    if (parts.length === 9) {
      const keys = ["time", "host", "user", "source", "action", "detail", "stage", "technique", "severity"];
      return normalise(Object.fromEntries(keys.map((k, i) => [k, parts[i] ?? ""])));
    }
    return null;
  }
  const row = parseCsvRow(trimmed);
  if (row.length === 0) return null;
  const first = (row[0] ?? "").toLowerCase();
  if (first === "time" || first === "timestamp") return null;
  if (row.length === 10) {
    const keys = ["time", "host", "user", "ip", "source", "action", "detail", "stage", "technique", "severity"];
    return normalise(Object.fromEntries(keys.map((k, i) => [k, row[i] ?? ""])));
  }
  if (row.length === 9) {
    const keys = ["time", "host", "user", "source", "action", "detail", "stage", "technique", "severity"];
    return normalise(Object.fromEntries(keys.map((k, i) => [k, row[i] ?? ""])));
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sigma-style YAML subset parser (handles exactly the shape of the
// default rules file; anything else is a validation error, not a guess).
// ---------------------------------------------------------------------------

function parseScalar(raw: string): string {
  const v = raw.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function parseInlineList(raw: string): string[] {
  const v = raw.trim();
  if (!v.startsWith("[") || !v.endsWith("]")) return [parseScalar(v)];
  const inner = v.slice(1, -1).trim();
  if (inner === "") return [];
  const out: string[] = [];
  let cur = "";
  let quote = "";
  for (const ch of inner) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = "";
    } else if (ch === '"' || ch === "'") { quote = ch; cur += ch; }
    else if (ch === ",") { out.push(parseScalar(cur)); cur = ""; }
    else cur += ch;
  }
  if (cur.trim() !== "") out.push(parseScalar(cur));
  return out;
}

function parseCondField(cond: Cond, key: string, value: string): void {
  if (key === "any_contains") cond.anyContains = parseInlineList(value);
  else if (key === "action_contains") cond.actionContains = parseInlineList(value);
  else if (key === "detail_contains") cond.detailContains = parseInlineList(value);
  else if (key === "action_equals") cond.actionEquals = parseScalar(value);
  else if (key === "severity_in") cond.severityIn = parseInlineList(value);
  else if (key === "source_contains") cond.sourceContains = parseInlineList(value);
}

export function parseRulesYaml(text: string): Rule[] {
  const lines = text.split("\n");
  const rules: Rule[] = [];
  let current: Rule | null = null;
  let section: "match" | "trigger" | "success" | null = null;
  let pendingList: { section: "match" | "trigger" | "success" | null; key: string } | null = null;

  const newRule = (): Rule => ({
    id: "", name: "", techniqueId: "", techniqueName: "", tactic: "", stage: "",
    confidence: 80, priority: 50, description: "", type: "simple",
    threshold: 0, windowMinutes: 120, groupBy: ["user", "host"],
    match: {}, trigger: {}, success: {},
  });

  for (const rawLine of lines) {
    if (rawLine.trim() === "" || rawLine.trim().startsWith("#")) continue;
    const indent = rawLine.length - rawLine.trimStart().length;
    const content = rawLine.trim();
    if (indent === 0) {
      if (content !== "rules:") throw new Error(`Expected "rules:" at top level, got "${content}"`);
      continue;
    }
    if (indent === 2 && content.startsWith("- ")) {
      if (current) rules.push(current);
      current = newRule();
      section = null;
      pendingList = null;
      const rest = content.slice(2).trim();
      const colon = rest.indexOf(":");
      if (colon === -1) throw new Error(`Rule item must start with a field, got "${rest}"`);
      const key = rest.slice(0, colon).trim();
      const value = rest.slice(colon + 1).trim();
      if (key === "id") current.id = parseScalar(value);
      else throw new Error(`First field of a rule must be "id", got "${key}"`);
      continue;
    }
    if (!current) throw new Error("Rule fields found before any rule item");
    if (content.startsWith("- ") && pendingList) {
      const item = parseScalar(content.slice(2).trim());
      const cond: Cond = pendingList.section ? current[pendingList.section] : current.match;
      const existing = cond as unknown as Record<string, string[] | undefined>;
      const listKey =
        pendingList.key === "any_contains" ? "anyContains"
        : pendingList.key === "action_contains" ? "actionContains"
        : pendingList.key === "detail_contains" ? "detailContains"
        : pendingList.key === "severity_in" ? "severityIn"
        : "sourceContains";
      if (pendingList.key === "group_by") {
        current.groupBy.push(item);
      } else {
        existing[listKey] = [...(existing[listKey] ?? []), item];
      }
      continue;
    }
    const colon = content.indexOf(":");
    if (colon === -1) throw new Error(`Cannot parse line: "${content}"`);
    const key = content.slice(0, colon).trim();
    const value = content.slice(colon + 1).trim();
    if (indent === 4) {
      section = null;
      pendingList = null;
      if (key === "match" || key === "trigger" || key === "success") {
        section = key;
        if (value !== "") throw new Error(`Section "${key}" takes nested fields, not a value`);
        continue;
      }
      if (value === "") {
        pendingList = { section: null, key };
        if (key === "group_by") current.groupBy = [];
        continue;
      }
      switch (key) {
        case "id": current.id = parseScalar(value); break;
        case "name": current.name = parseScalar(value); break;
        case "technique_id": current.techniqueId = parseScalar(value); break;
        case "technique_name": current.techniqueName = parseScalar(value); break;
        case "tactic": current.tactic = parseScalar(value); break;
        case "kill_chain_stage": current.stage = parseScalar(value); break;
        case "confidence": current.confidence = Number(value); break;
        case "priority": current.priority = Number(value); break;
        case "description": current.description = parseScalar(value); break;
        case "type": current.type = value === "aggregate" ? "aggregate" : "simple"; break;
        case "threshold": current.threshold = Number(value); break;
        case "window_minutes": current.windowMinutes = Number(value); break;
        case "group_by": current.groupBy = parseInlineList(value); break;
        default: throw new Error(`Unknown rule field "${key}"`);
      }
      continue;
    }
    if (indent === 6 && section) {
      if (value === "") {
        pendingList = { section, key };
        const cond = current[section];
        const existing = cond as unknown as Record<string, string[] | undefined>;
        const listKey =
          key === "any_contains" ? "anyContains"
          : key === "action_contains" ? "actionContains"
          : key === "detail_contains" ? "detailContains"
          : key === "severity_in" ? "severityIn"
          : "sourceContains";
        existing[listKey] = [];
        continue;
      }
      parseCondField(current[section], key, value);
      pendingList = null;
      continue;
    }
    throw new Error(`Unexpected indentation on line: "${content}"`);
  }
  if (current) rules.push(current);
  if (rules.length === 0) throw new Error("No rules found under \"rules:\"");
  for (const r of rules) {
    if (!r.id) throw new Error("Every rule needs an id");
    if (!r.techniqueId) throw new Error(`Rule "${r.id}" needs a technique_id`);
    if (!r.stage) throw new Error(`Rule "${r.id}" needs a kill_chain_stage`);
    if (r.type === "aggregate") {
      if (!r.threshold || r.threshold < 1) throw new Error(`Aggregate rule "${r.id}" needs a threshold of at least 1`);
      if (Object.keys(r.trigger).length === 0 || Object.keys(r.success).length === 0) {
        throw new Error(`Aggregate rule "${r.id}" needs trigger: and success: conditions`);
      }
    } else if (Object.keys(r.match).length === 0) {
      throw new Error(`Rule "${r.id}" needs a match: section`);
    }
    if (!Number.isFinite(r.confidence) || r.confidence < 0 || r.confidence > 100) {
      throw new Error(`Rule "${r.id}" confidence must be 0–100`);
    }
    if (!Number.isFinite(r.priority)) r.priority = 50;
  }
  rules.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
  return rules;
}

// ---------------------------------------------------------------------------
// Detector (mirrors engine/rules.py)
// ---------------------------------------------------------------------------

function contains(haystack: string, needles: string | string[] | undefined): boolean {
  if (!needles) return false;
  const list = Array.isArray(needles) ? needles : [needles];
  const text = (haystack ?? "").toLowerCase();
  return list.some((n) => text.includes(String(n).toLowerCase()));
}

function matchConditions(event: LogEvent, cond: Cond): boolean {
  if (Object.keys(cond).length === 0) return true;
  const combined = `${event.action} ${event.detail}`;
  if (cond.anyContains && !contains(combined, cond.anyContains)) return false;
  if (cond.actionContains && !contains(event.action, cond.actionContains)) return false;
  if (cond.detailContains && !contains(event.detail, cond.detailContains)) return false;
  if (cond.actionEquals && event.action.trim().toLowerCase() !== cond.actionEquals.toLowerCase()) return false;
  if (cond.severityIn && !cond.severityIn.includes(event.severity)) return false;
  if (cond.sourceContains && !contains(event.source, cond.sourceContains)) return false;
  return true;
}

function makeDetection(event: LogEvent, rule: Rule, merged: number, reason: string): Detection {
  return {
    ...event,
    techniqueId: rule.techniqueId,
    techniqueName: rule.techniqueName,
    tactic: rule.tactic,
    stage: rule.stage,
    confidence: rule.confidence,
    ruleId: rule.id,
    mergedAlerts: merged,
    reason,
  };
}

function processEvent(event: LogEvent, rules: Rule[], agg: AggState): Detection[] {
  for (const rule of rules) {
    if (rule.type !== "aggregate") continue;
    const groupKey = rule.groupBy.map((k) => {
      if (k === "user") return event.user;
      if (k === "host") return event.host;
      if (k === "ip") return event.ip;
      return "";
    }).join("\u0001");
    const byRule = agg[rule.id] ?? {};
    const state = byRule[groupKey] ?? [];
    if (matchConditions(event, rule.trigger)) {
      if (event.ts !== null) {
        const window = rule.windowMinutes * 60;
        const kept = state.filter((t) => event.ts !== null && event.ts - t <= window);
        kept.push(event.ts);
        byRule[groupKey] = kept;
      } else {
        byRule[groupKey] = [...state, 0];
      }
      agg[rule.id] = byRule;
      return [];
    }
    if (matchConditions(event, rule.success) && state.length >= rule.threshold) {
      const count = state.length;
      byRule[groupKey] = [];
      agg[rule.id] = byRule;
      return [makeDetection(event, rule, count + 1,
        `${count} failed logins for the same ${rule.groupBy.join("/")} followed by a success`)];
    }
  }
  for (const rule of rules) {
    if (rule.type !== "simple") continue;
    if (!matchConditions(event, rule.match)) continue;
    const matched: string[] = [];
    const combined = `${event.action} ${event.detail}`;
    for (const key of ["anyContains", "actionContains", "detailContains"] as const) {
      const needles = rule.match[key] ?? [];
      for (const needle of needles) {
        if (contains(combined, needle)) matched.push(needle);
      }
    }
    const reason = rule.description ||
      `Matched rule '${rule.name}'${matched[0] ? ` on '${matched[0]}'` : ""}`;
    return [makeDetection(event, rule, 1, reason)];
  }
  return [];
}

// ---------------------------------------------------------------------------
// Linking, risk, graph, next-reach (mirrors engine/graph.py)
// ---------------------------------------------------------------------------

const LINK_WINDOW_SECONDS = 48 * 3600;
const SEVERITY_WEIGHTS: Record<string, number> = { Critical: 40, High: 25, Medium: 10, Low: 3 };

function riskScore(dets: Detection[]): number {
  const total = dets.reduce((s, d) => s + (SEVERITY_WEIGHTS[d.severity] ?? 10), 0);
  const stages = new Set(dets.map((d) => d.stage));
  let score = 0.3 * total + 3 * stages.size;
  if (dets.some((d) => d.stage === "Exfiltration")) score += 15;
  if (dets.some((d) => d.stage === "Privilege Escalation" || d.stage === "Credential Access")) score += 10;
  return Math.round(Math.min(100, score) * 10) / 10;
}

type IncidentGroup = Detection[];

function linkDetections(dets: Detection[]): IncidentGroup[] {
  const ordered = [...dets].sort((a, b) => {
    const ta = a.ts ?? Infinity;
    const tb = b.ts ?? Infinity;
    return ta - tb;
  });
  type Active = { hosts: Set<string>; users: Set<string>; ips: Set<string>; lastTs: number; dets: Detection[] };
  const active: Active[] = [];
  const finished: Detection[][] = [];
  for (const det of ordered) {
    const ts = det.ts ?? 0;
    const expired = active.filter((a) => ts - a.lastTs > LINK_WINDOW_SECONDS);
    for (const a of expired) finished.push(a.dets);
    const remaining = active.filter((a) => ts - a.lastTs <= LINK_WINDOW_SECONDS);
    active.length = 0;
    active.push(...remaining);
    const matches = active.filter((a) =>
      a.hosts.has(det.host) || a.users.has(det.user) || (det.ip !== "" && a.ips.has(det.ip)));
    if (matches.length === 0) {
      active.push({
        hosts: new Set([det.host]), users: new Set([det.user]),
        ips: det.ip !== "" ? new Set([det.ip]) : new Set(), lastTs: ts, dets: [det],
      });
      continue;
    }
    const first = matches[0];
    if (!first) continue;
    for (const other of matches.slice(1)) {
      for (const h of other.hosts) first.hosts.add(h);
      for (const u of other.users) first.users.add(u);
      for (const ip of other.ips) first.ips.add(ip);
      first.dets.push(...other.dets);
      const idx = active.indexOf(other);
      if (idx >= 0) active.splice(idx, 1);
    }
    first.hosts.add(det.host);
    first.users.add(det.user);
    if (det.ip !== "") first.ips.add(det.ip);
    first.lastTs = Math.max(first.lastTs, ts);
    first.dets.push(det);
  }
  for (const a of active) finished.push(a.dets);
  const out = finished.map((group) => group.sort((a, b) => (a.ts ?? Infinity) - (b.ts ?? Infinity)));
  out.sort((a, b) => {
    const ta = a[0]?.ts ?? Infinity;
    const tb = b[0]?.ts ?? Infinity;
    return ta - tb;
  });
  return out;
}

type Edge = { from: string; to: string; kind: string; techniqueId: string; time: string };

function graphEdges(dets: Detection[]): Edge[] {
  const map = new Map<string, Edge>();
  for (const det of dets) {
    const key = `${det.user}|${det.host}|event`;
    map.set(key, { from: det.user, to: det.host, kind: "event", techniqueId: det.techniqueId, time: det.time });
  }
  const ordered = [...dets].sort((a, b) => (a.ts ?? Infinity) - (b.ts ?? Infinity));
  let prevHost: string | null = null;
  for (const det of ordered) {
    if (prevHost && det.host !== prevHost) {
      const key = `${prevHost}|${det.host}|path`;
      map.set(key, { from: prevHost, to: det.host, kind: "path", techniqueId: det.techniqueId, time: det.time });
    }
    prevHost = det.host;
  }
  return [...map.values()];
}

function missionLabelFor(dets: Detection[]): string {
  const hosts = new Set(dets.map((d) => d.host));
  if (dets.some((d) => d.ruleId === "web_shell")) return "WEB SHELL";
  if (hosts.has("VPN-01")) return "STOLEN VPN";
  if (hosts.has("DC-01")) return "PHISH TO DOMAIN ADMIN";
  if (dets.length >= 8) return "PHISH TO FILE SERVER";
  // Generic incidents take their heading from their own first step, so the
  // heading, subtitle, and package cards can never disagree.
  const first = dets[0];
  return (first?.techniqueName ?? "Incident").toUpperCase();
}

function nextReach(hosts: string[], users: string[], topology: Topology): {
  host: string; confidence: number; reason: string; block: string;
}[] {
  const compromised = new Set(hosts);
  const results = new Map<string, { host: string; confidence: number; reason: string; block: string }>();
  for (const host of hosts) {
    const subnet = topology.hostSubnet[host];
    if (!subnet) continue;
    for (const [peer, peerSubnet] of Object.entries(topology.hostSubnet)) {
      if (peerSubnet === subnet && !compromised.has(peer)) {
        results.set(peer, {
          host: peer, confidence: 60,
          reason: `Same subnet as compromised host ${host}`,
          block: `Segment the subnet or isolate ${host} first`,
        });
      }
    }
  }
  for (const account of users) {
    for (const host of topology.adminRights[account] ?? []) {
      if (!compromised.has(host)) {
        results.set(host, {
          host, confidence: 85,
          reason: `Account ${account} has admin rights on ${host}`,
          block: `Revoke admin rights for ${account} on ${host} and reset its credentials`,
        });
      }
    }
  }
  return [...results.values()].sort((a, b) => b.confidence - a.confidence || a.host.localeCompare(b.host));
}

function englishReport(
  incident: { startTime: string; hosts: string[]; users: string[]; mergedAlerts: number; detectionCount: number; riskScore: number },
  steps: Detection[],
  next: { host: string; reason: string }[],
): string {
  const hosts = incident.hosts.join(", ") || "unknown hosts";
  const users = incident.users.join(", ") || "unknown accounts";
  const lines = [
    `This incident began on ${incident.startTime || "an unknown time"} and involved ${hosts} and accounts ${users}.`,
  ];
  if (steps.length > 0) {
    const seq = steps.map((d) => `${d.time}: ${d.techniqueName || d.techniqueId} (${d.stage}) on ${d.host}`).join("; ");
    lines.push(`What the attacker did, in order: ${seq}.`);
  } else {
    lines.push("No detections were recorded for this incident.");
  }
  lines.push(
    `The incident merged ${incident.mergedAlerts} raw alerts into ${incident.detectionCount} detections, with a risk score of ${incident.riskScore} out of 100.`,
  );
  if (next.length > 0) {
    lines.push(`What the attacker could reach next: ${next.map((n) => `${n.host} (${n.reason})`).join("; ")}.`);
  } else {
    lines.push("No next system could be identified from the supplied topology, so no next target is guessed.");
  }
  lines.push("This report describes the attack only; it does not block or stop it.");
  return lines.join(" ");
}

function hindiTemplate(
  incident: { startTime: string; hosts: string[]; detectionCount: number; mergedAlerts: number },
  next: { host: string }[],
): string {
  const hosts = incident.hosts.join(", ") || "अज्ञात सिस्टम";
  const nxt = next.length > 0 ? next.map((n) => n.host).join("; ") : "कोई अगला लक्ष्य नहीं मिला";
  return (
    `यह घटना ${incident.startTime} को ${hosts} पर शुरू हुई। ` +
    `इसमें ${incident.detectionCount} पहचान और ${incident.mergedAlerts} कच्चे अलर्ट शामिल हैं। ` +
    `हमलावर आगे इन सिस्टम तक पहुँच सकता है: ${nxt}। ` +
    `यह एक टेम्पलेट रिपोर्ट है, असली अनुवाद नहीं।`
  );
}

// ---------------------------------------------------------------------------
// Synthetic data (generated lines run through the same pipeline -
// never hand-written incident rows)
// ---------------------------------------------------------------------------

function ev(
  time: string, host: string, user: string, ip: string, source: string,
  action: string, detail: string, severity: string,
): string {
  return JSON.stringify({ time, host, user, ip, source, action, detail, severity });
}

function buildSyntheticLines(): string[] {
  const lines: string[] = [];
  const benignActions: [string, string][] = [
    ["file opened", "user opened an internal document"],
    ["document saved", "draft saved to the team folder"],
    ["email received", "internal email delivered to inbox"],
    ["print job completed", "print job completed on the office printer"],
    ["calendar sync", "calendar sync completed"],
    ["software update check", "update check completed, nothing to install"],
    ["dns lookup", "internal name resolved"],
    ["heartbeat ok", "agent heartbeat ok"],
  ];
  const benignHosts: [string, string][] = [
    ["WS-042", "rahul.verma"], ["LAP-118", "meera.nair"], ["WS-202", "karan.patel"],
    ["HR-08", "divya.iyer"], ["FS-03", "svc-print"], ["WS-042", "rahul.verma"],
  ];
  for (let i = 0; i < 120; i += 1) {
    const [action, detail] = benignActions[i % benignActions.length] ?? ["heartbeat ok", "agent heartbeat ok"];
    const [host, user] = benignHosts[i % benignHosts.length] ?? ["WS-042", "rahul.verma"];
    const mins = String(5 + (i % 50)).padStart(2, "0");
    lines.push(ev(`2026-10-28T07:${mins}:00`, host, user, "", "workstation", action, detail, "Low"));
  }
  // A: phish chain, WS-041 -> SRV-FILE-02 (9 steps)
  const a: [string, string, string, string, string, string][] = [
    ["2026-10-28T09:12:00", "WS-041", "priya.sharma", "email opened", "phishing email with malicious attachment opened", "High"],
    ["2026-10-28T09:27:00", "WS-041", "priya.sharma", "document macro executed", "macro executed from phishing attachment", "High"],
    ["2026-10-28T09:58:00", "WS-041", "priya.sharma", "credential dump detected", "lsass memory accessed by mimikatz", "Critical"],
    ["2026-10-28T10:42:00", "WS-041", "svc-backup", "scheduled task created", "scheduled task created for persistence", "High"],
    ["2026-10-28T12:12:00", "WS-041", "svc-backup", "c2 beacon observed", "c2 beacon to external server every 60 seconds", "High"],
    ["2026-10-29T05:12:00", "SRV-FILE-02", "svc-backup", "smb lateral movement", "smb lateral movement to SRV-FILE-02", "High"],
    ["2026-10-29T06:12:00", "SRV-FILE-02", "svc-backup", "staging files", "staging files collected for transfer", "Medium"],
    ["2026-10-29T06:42:00", "SRV-FILE-02", "svc-backup", "data upload", "upload to an outside IP, 2.4 GB", "Critical"],
    ["2026-10-29T06:57:00", "SRV-FILE-02", "svc-backup", "event logs cleared", "event logs cleared on SRV-FILE-02", "High"],
  ];
  for (const [t, h, u, act, det, sev] of a) lines.push(ev(t, h, u, "10.0.1.41", "workstation", act, det, sev));
  // B: web shell, WEB-01 -> DB-01 (5 steps)
  const b: [string, string, string, string, string, string][] = [
    ["2026-10-29T10:00:00", "WEB-01", "www-data", "web shell command executed", "web shell command executed via uploaded file", "Critical"],
    ["2026-10-29T10:20:00", "WEB-01", "svc-web", "credential dump detected", "lsass memory accessed, credential dump", "Critical"],
    ["2026-10-29T11:00:00", "DB-01", "svc-web", "smb lateral movement", "lateral movement to DB-01 over SMB", "High"],
    ["2026-10-29T12:00:00", "DB-01", "svc-web", "staging files", "files collected for transfer on DB-01", "Medium"],
    ["2026-10-29T12:30:00", "DB-01", "svc-web", "data upload", "upload to an outside IP from DB-01", "Critical"],
  ];
  for (const [t, h, u, act, det, sev] of b) lines.push(ev(t, h, u, "10.0.2.10", "web-server", act, det, sev));
  // C: phish to domain admin, HR-07 -> FS-02 -> DC-01 (6 steps)
  const c: [string, string, string, string, string, string][] = [
    ["2026-10-29T13:00:00", "HR-07", "hsingh", "port scan detected", "port scan against internal hosts", "High"],
    ["2026-10-29T13:30:00", "HR-07", "hsingh", "email opened", "phishing email opened on HR-07", "High"],
    ["2026-10-29T14:00:00", "FS-02", "hsingh", "smb lateral movement", "lateral movement to FS-02", "High"],
    ["2026-10-29T15:00:00", "DC-01", "hsingh", "smb lateral movement", "lateral movement to DC-01", "High"],
    ["2026-10-29T15:30:00", "DC-01", "hsingh", "new admin account created", "new admin account created on DC-01", "Critical"],
    ["2026-10-29T16:00:00", "DC-01", "hsingh", "data upload", "upload to an outside IP from DC-01", "Critical"],
  ];
  for (const [t, h, u, act, det, sev] of c) lines.push(ev(t, h, u, "10.0.3.7", "workstation", act, det, sev));
  // D: stolen VPN, VPN-01 (50 failed + success, then admin + exfil)
  for (let i = 0; i < 50; i += 1) {
    const mins = String(10 + Math.floor(i / 2)).padStart(2, "0");
    const secs = String((i % 2) * 30).padStart(2, "0");
    lines.push(ev(`2026-10-30T08:${mins}:${secs}`, "VPN-01", "amit", "203.0.113.9", "vpn-gateway", "vpn login failed", "login failed for user amit from an unusual IP", "Medium"));
  }
  lines.push(ev("2026-10-30T09:50:00", "VPN-01", "amit", "203.0.113.9", "vpn-gateway", "vpn login success", "login success for user amit after 50 failures", "High"));
  lines.push(ev("2026-10-30T10:20:00", "VPN-01", "amit", "203.0.113.9", "vpn-gateway", "new admin account created", "new admin account created after VPN login", "Critical"));
  lines.push(ev("2026-10-30T10:40:00", "VPN-01", "amit", "203.0.113.9", "vpn-gateway", "data upload", "upload to an outside IP over the VPN session", "Critical"));
  // E: single-host brute force, WS-101 (50 failed + success)
  for (let i = 0; i < 50; i += 1) {
    const mins = String(10 + Math.floor(i / 2)).padStart(2, "0");
    lines.push(ev(`2026-10-28T08:${mins}:00`, "WS-101", "jdoe", "10.0.1.101", "workstation", "login failed", "login failed for user jdoe", "Medium"));
  }
  lines.push(ev("2026-10-28T08:50:00", "WS-101", "jdoe", "10.0.1.101", "workstation", "login success", "login success for user jdoe", "High"));
  return lines;
}

// Stream demo: 5,009 lines, same 24 planted steps hidden among benign lines.
const STREAM_TOTAL = 5009;
const STREAM_BATCH = 500;

let cachedAttackLines: string[] | null = null;
let cachedAttackPositions: number[] | null = null;

function streamAttackLines(): string[] {
  if (cachedAttackLines) return cachedAttackLines;
  const benign = new Set(["file opened", "document saved", "email received", "print job completed", "calendar sync", "software update check", "dns lookup", "heartbeat ok"]);
  cachedAttackLines = buildSyntheticLines().filter((l) => {
    const e = parseLine(l);
    return e !== null && !benign.has(e.action);
  });
  return cachedAttackLines;
}

function streamLineAt(index: number): string {
  const attackLines = streamAttackLines();
  if (!cachedAttackPositions) {
    cachedAttackPositions = attackLines.map((_, k) => Math.floor(((k + 0.5) * STREAM_TOTAL) / attackLines.length));
  }
  const positions = cachedAttackPositions;
  const attackIndex = positions.indexOf(index);
  if (attackIndex >= 0) {
    return attackLines[attackIndex] ?? "";
  }
  const templates: [string, string][] = [
    ["file opened", "user opened an internal document"],
    ["document saved", "draft saved to the team folder"],
    ["email received", "internal email delivered to inbox"],
    ["heartbeat ok", "agent heartbeat ok"],
    ["dns lookup", "internal name resolved"],
  ];
  const [action, detail] = templates[index % templates.length] ?? ["heartbeat ok", "agent heartbeat ok"];
  const host = ["WS-042", "LAP-118", "WS-202", "HR-08"][index % 4] ?? "WS-042";
  const user = ["rahul.verma", "meera.nair", "karan.patel", "divya.iyer"][index % 4] ?? "rahul.verma";
  const day = 28 + Math.floor(index / 2500);
  const hour = String(7 + (index % 10)).padStart(2, "0");
  const mins = String(index % 60).padStart(2, "0");
  return ev(`2026-10-${day}T${hour}:${mins}:00`, host, user, "", "workstation", action, detail, "Low");
}

function buildStreamBatch(batch: number): string[] {
  const start = batch * STREAM_BATCH;
  const end = Math.min(STREAM_TOTAL, start + STREAM_BATCH);
  const out: string[] = [];
  for (let i = start; i < end; i += 1) out.push(streamLineAt(i));
  return out;
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

async function loadRules(ctx: Ctx): Promise<{ yaml: string; rules: Rule[] }> {
  const db = ctx.db<typeof schema>();
  const rows = await db.select().from(schema.rulesConfig).where(eq(schema.rulesConfig.id, 1)).limit(1);
  const yaml = rows[0]?.yamlText ?? DEFAULT_RULES_YAML;
  return { yaml, rules: parseRulesYaml(yaml) };
}

async function ensureRulesAndTopology(ctx: Ctx): Promise<void> {
  const db = ctx.db<typeof schema>();
  const ruleRows = await db.select().from(schema.rulesConfig).where(eq(schema.rulesConfig.id, 1)).limit(1);
  if (ruleRows.length === 0) {
    await db.insert(schema.rulesConfig).values({ id: 1, yamlText: DEFAULT_RULES_YAML, updatedAt: new Date() });
  }
  const topoRows = await db.select().from(schema.topology).where(eq(schema.topology.id, 1)).limit(1);
  if (topoRows.length === 0) {
    await db.insert(schema.topology).values({ id: 1, jsonText: JSON.stringify(DEFAULT_TOPOLOGY) });
  }
}

async function loadTopology(ctx: Ctx): Promise<Topology> {
  const db = ctx.db<typeof schema>();
  const rows = await db.select().from(schema.topology).where(eq(schema.topology.id, 1)).limit(1);
  const raw = rows[0]?.jsonText;
  if (!raw) {
    const hostSubnet: Record<string, string> = {};
    for (const [subnet, hosts] of Object.entries(DEFAULT_TOPOLOGY.subnets)) {
      for (const h of hosts) hostSubnet[h] = subnet;
    }
    return { hostSubnet, adminRights: DEFAULT_TOPOLOGY.admin_rights };
  }
  const parsed = JSON.parse(raw) as typeof DEFAULT_TOPOLOGY;
  const hostSubnet: Record<string, string> = {};
  for (const [subnet, hosts] of Object.entries(parsed.subnets ?? {})) {
    for (const h of hosts) hostSubnet[h] = subnet;
  }
  return { hostSubnet, adminRights: parsed.admin_rights ?? {} };
}

function parseAggState(text: string): AggState {
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null) return parsed as AggState;
  } catch { /* fall through */ }
  return {};
}

/** Run lines through the detector and append detections to a dataset. */
async function ingestLines(
  ctx: Ctx,
  datasetId: string,
  lines: string[],
  rules: Rule[],
  agg: AggState,
  startSeq: number,
): Promise<{ parsed: number; unparsed: number; detections: number; nextSeq: number }> {
  const db = ctx.db<typeof schema>();
  let parsed = 0;
  let unparsed = 0;
  const toInsert: (typeof schema.detections.$inferInsert)[] = [];
  let seq = startSeq;
  for (const line of lines) {
    if (line.trim() === "") continue;
    const event = parseLine(line);
    if (!event) { unparsed += 1; continue; }
    parsed += 1;
    const dets = processEvent(event, rules, agg);
    for (const det of dets) {
      seq += 1;
      toInsert.push({
        datasetId, seq, time: det.time, ts: det.ts, host: det.host, user: det.user,
        ip: det.ip, source: det.source, action: det.action, detail: det.detail,
        techniqueId: det.techniqueId, techniqueName: det.techniqueName, tactic: det.tactic,
        stage: det.stage, severity: det.severity, confidence: det.confidence,
        ruleId: det.ruleId, mergedAlerts: det.mergedAlerts, reason: det.reason,
      });
    }
  }
  // Insert in chunks so one batch never becomes a giant statement.
  for (let i = 0; i < toInsert.length; i += 500) {
    const chunk = toInsert.slice(i, i + 500);
    if (chunk.length > 0) await db.insert(schema.detections).values(chunk);
  }
  return { parsed, unparsed, detections: toInsert.length, nextSeq: seq };
}

async function clearDatasetResults(ctx: Ctx, datasetId: string): Promise<void> {
  const db = ctx.db<typeof schema>();
  const incs = await db.select({ id: schema.incidents.id }).from(schema.incidents).where(eq(schema.incidents.datasetId, datasetId));
  const ids = incs.map((r) => r.id);
  if (ids.length > 0) {
    await db.delete(schema.incidentDetections).where(inArray(schema.incidentDetections.incidentId, ids));
    await db.delete(schema.edges).where(inArray(schema.edges.incidentId, ids));
  }
  await db.delete(schema.incidents).where(eq(schema.incidents.datasetId, datasetId));
  await db.delete(schema.detections).where(eq(schema.detections.datasetId, datasetId));
}

/** Re-link a dataset's stored detections into incidents + edges. */
async function rebuildDataset(ctx: Ctx, datasetId: string): Promise<number> {
  const db = ctx.db<typeof schema>();
  const rows = await db.select().from(schema.detections)
    .where(eq(schema.detections.datasetId, datasetId))
    .orderBy(asc(schema.detections.seq));
  const dets: Detection[] = rows.map((r) => ({
    time: r.time, ts: r.ts, host: r.host, user: r.user, ip: r.ip, source: r.source,
    action: r.action, detail: r.detail, severity: r.severity,
    techniqueId: r.techniqueId, techniqueName: r.techniqueName, tactic: r.tactic,
    stage: r.stage, confidence: r.confidence, ruleId: r.ruleId,
    mergedAlerts: r.mergedAlerts, reason: r.reason,
  }));
  // Remove old incidents/edges for this dataset only.
  const old = await db.select({ id: schema.incidents.id }).from(schema.incidents).where(eq(schema.incidents.datasetId, datasetId));
  const oldIds = old.map((r) => r.id);
  if (oldIds.length > 0) {
    await db.delete(schema.incidentDetections).where(inArray(schema.incidentDetections.incidentId, oldIds));
    await db.delete(schema.edges).where(inArray(schema.edges.incidentId, oldIds));
  }
  await db.delete(schema.incidents).where(eq(schema.incidents.datasetId, datasetId));

  const groups = linkDetections(dets);
  // Rows are in seq order and dets preserves that order, so group
  // membership is matched back to rows by object identity below.
  let incidentCount = 0;
  for (const group of groups) {
    if (group.length === 0) continue;
    const first = group[0];
    if (!first) continue;
    const hosts = [...new Set(group.map((d) => d.host))].sort();
    const users = [...new Set(group.map((d) => d.user))].sort();
    const last = group[group.length - 1];
    const merged = group.reduce((s, d) => s + d.mergedAlerts, 0);
    const inserted = await db.insert(schema.incidents).values({
      datasetId,
      title: `${first.techniqueName || first.techniqueId} path on ${first.host}`,
      missionLabel: missionLabelFor(group),
      startTime: first.time,
      endTime: last?.time ?? first.time,
      hosts: JSON.stringify(hosts),
      users: JSON.stringify(users),
      riskScore: riskScore(group),
      mergedAlerts: merged,
      detectionCount: group.length,
    }).returning({ id: schema.incidents.id });
    const incidentId = inserted[0]?.id;
    if (incidentId === undefined) continue;
    incidentCount += 1;
    // Link rows: find row ids by matching detection identity in seq order.
    const groupSet = new Set(group);
    const links: (typeof schema.incidentDetections.$inferInsert)[] = [];
    let linkSeq = 0;
    for (let i = 0; i < rows.length; i += 1) {
      const d = dets[i];
      if (d && groupSet.has(d)) {
        const row = rows[i];
        if (row) { linkSeq += 1; links.push({ incidentId, detectionId: row.id, seq: linkSeq }); }
      }
    }
    for (let i = 0; i < links.length; i += 500) {
      const chunk = links.slice(i, i + 500);
      if (chunk.length > 0) await db.insert(schema.incidentDetections).values(chunk);
    }
    const edgeRows = graphEdges(group).map((e) => ({
      incidentId, fromNode: e.from, toNode: e.to, kind: e.kind, techniqueId: e.techniqueId, time: e.time,
    }));
    if (edgeRows.length > 0) await db.insert(schema.edges).values(edgeRows);
  }
  await db.update(schema.datasets).set({ detectionCount: dets.length, staleRules: 0 })
    .where(eq(schema.datasets.id, datasetId));
  return incidentCount;
}

async function reprocessDataset(ctx: Ctx, datasetId: string, rules: Rule[]): Promise<string> {
  const db = ctx.db<typeof schema>();
  const rows = await db.select().from(schema.datasets).where(eq(schema.datasets.id, datasetId)).limit(1);
  const ds = rows[0];
  if (!ds) return "missing";
  let lines: string[] | null = null;
  if (ds.kind === "synthetic") lines = buildSyntheticLines();
  else if (ds.kind === "stream") {
    lines = [];
    const batches = Math.ceil(STREAM_TOTAL / STREAM_BATCH);
    for (let b = 0; b < batches; b += 1) lines.push(...buildStreamBatch(b));
  } else if (ds.rawText !== null) {
    lines = ds.rawText.split("\n");
  }
  if (lines === null) {
    await db.update(schema.datasets).set({ staleRules: 1 }).where(eq(schema.datasets.id, datasetId));
    return "stale";
  }
  await clearDatasetResults(ctx, datasetId);
  const agg: AggState = {};
  const result = await ingestLines(ctx, datasetId, lines, rules, agg, 0);
  await db.update(schema.datasets).set({
    totalLines: lines.length, parsedLines: result.parsed, unparsedLines: result.unparsed,
    aggState: JSON.stringify(agg), carryover: "", status: "ready",
  }).where(eq(schema.datasets.id, datasetId));
  await rebuildDataset(ctx, datasetId);
  return "ok";
}

// ---------------------------------------------------------------------------
// Shared response shapes
// ---------------------------------------------------------------------------

const datasetSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.string(),
  fileName: z.string().nullable(),
  status: z.string(),
  totalLines: z.number(),
  parsedLines: z.number(),
  unparsedLines: z.number(),
  detectionCount: z.number(),
  staleRules: z.boolean(),
  createdAt: z.string(),
});

const incidentSummarySchema = z.object({
  id: z.number(),
  datasetId: z.string(),
  title: z.string(),
  missionLabel: z.string(),
  startTime: z.string(),
  endTime: z.string(),
  hosts: z.array(z.string()),
  users: z.array(z.string()),
  riskScore: z.number(),
  mergedAlerts: z.number(),
  detectionCount: z.number(),
});

const stepSchema = z.object({
  id: z.number(),
  seq: z.number(),
  time: z.string(),
  host: z.string(),
  user: z.string(),
  ip: z.string(),
  source: z.string(),
  action: z.string(),
  detail: z.string(),
  techniqueId: z.string(),
  techniqueName: z.string(),
  tactic: z.string(),
  stage: z.string(),
  severity: z.string(),
  confidence: z.number(),
  ruleId: z.string(),
  mergedAlerts: z.number(),
  reason: z.string(),
});

const edgeSchema = z.object({
  from: z.string(), to: z.string(), kind: z.string(), techniqueId: z.string(), time: z.string(),
});

const nextReachSchema = z.object({
  host: z.string(), confidence: z.number(), reason: z.string(), block: z.string(),
});

function parseStringList(text: string): string[] {
  try {
    const parsed: unknown = JSON.parse(text);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export const Actions = {
  listDatasets: defineAction({
    description: "Lists every processed log dataset, newest first.",
    request: z.object({}),
    response: z.object({ datasets: z.array(datasetSchema) }),
    async handler(ctx) {
      await ensureRulesAndTopology(ctx);
      const db = ctx.db<typeof schema>();
      const rows = await db.select().from(schema.datasets).orderBy(desc(schema.datasets.createdAt));
      return {
        datasets: rows.map((r) => ({
          id: r.id, name: r.name, kind: r.kind, fileName: r.fileName, status: r.status,
          totalLines: r.totalLines, parsedLines: r.parsedLines, unparsedLines: r.unparsedLines,
          detectionCount: r.detectionCount, staleRules: r.staleRules === 1,
          createdAt: r.createdAt.toISOString(),
        })),
      };
    },
  }),

  listIncidents: defineAction({
    description: "Lists incidents for one dataset, worst risk score first.",
    request: z.object({ datasetId: z.string() }),
    response: z.object({ incidents: z.array(incidentSummarySchema) }),
    async handler(ctx, args) {
      const db = ctx.db<typeof schema>();
      const rows = await db.select().from(schema.incidents)
        .where(eq(schema.incidents.datasetId, args.datasetId))
        .orderBy(desc(schema.incidents.riskScore), desc(schema.incidents.detectionCount), asc(schema.incidents.id));
      return {
        incidents: rows.map((r) => ({
          id: r.id, datasetId: r.datasetId, title: r.title, missionLabel: r.missionLabel,
          startTime: r.startTime, endTime: r.endTime,
          hosts: parseStringList(r.hosts), users: parseStringList(r.users),
          riskScore: r.riskScore, mergedAlerts: r.mergedAlerts, detectionCount: r.detectionCount,
        })),
      };
    },
  }),

  getIncident: defineAction({
    description: "Returns one incident with its timeline steps, graph edges, next-reach targets, and English + Hindi reports.",
    request: z.object({ incidentId: z.number() }),
    response: z.object({
      incident: incidentSummarySchema,
      steps: z.array(stepSchema),
      edges: z.array(edgeSchema),
      nextReach: z.array(nextReachSchema),
      englishReport: z.string(),
      hindiReport: z.string(),
      hindiSource: z.string(),
      hindiWarning: z.string(),
    }),
    async handler(ctx, args) {
      const db = ctx.db<typeof schema>();
      const rows = await db.select().from(schema.incidents).where(eq(schema.incidents.id, args.incidentId)).limit(1);
      const inc = rows[0];
      if (!inc) throw new Error("Incident not found");
      const linkRows = await db.select().from(schema.incidentDetections)
        .where(eq(schema.incidentDetections.incidentId, args.incidentId))
        .orderBy(asc(schema.incidentDetections.seq));
      const detIds = linkRows.map((r) => r.detectionId);
      const detRows = detIds.length > 0
        ? await db.select().from(schema.detections).where(inArray(schema.detections.id, detIds))
        : [];
      const detById = new Map(detRows.map((r) => [r.id, r]));
      const steps = linkRows.map((link) => {
        const r = detById.get(link.detectionId);
        return {
          id: link.detectionId, seq: link.seq,
          time: r?.time ?? "", host: r?.host ?? "", user: r?.user ?? "", ip: r?.ip ?? "",
          source: r?.source ?? "", action: r?.action ?? "", detail: r?.detail ?? "",
          techniqueId: r?.techniqueId ?? "", techniqueName: r?.techniqueName ?? "",
          tactic: r?.tactic ?? "", stage: r?.stage ?? "", severity: r?.severity ?? "Medium",
          confidence: r?.confidence ?? 0, ruleId: r?.ruleId ?? "",
          mergedAlerts: r?.mergedAlerts ?? 1, reason: r?.reason ?? "",
        };
      });
      const edgeRows = await db.select().from(schema.edges).where(eq(schema.edges.incidentId, args.incidentId));
      const hosts = parseStringList(inc.hosts);
      const users = parseStringList(inc.users);
      const topology = await loadTopology(ctx);
      const next = nextReach(hosts, users, topology);
      const incidentView = {
        id: inc.id, datasetId: inc.datasetId, title: inc.title, missionLabel: inc.missionLabel,
        startTime: inc.startTime, endTime: inc.endTime, hosts, users,
        riskScore: inc.riskScore, mergedAlerts: inc.mergedAlerts, detectionCount: inc.detectionCount,
      };
      const stepDets: Detection[] = steps.map((s) => ({
        time: s.time, ts: parseTimestamp(s.time), host: s.host, user: s.user, ip: s.ip,
        source: s.source, action: s.action, detail: s.detail, severity: s.severity,
        techniqueId: s.techniqueId, techniqueName: s.techniqueName, tactic: s.tactic,
        stage: s.stage, confidence: s.confidence, ruleId: s.ruleId,
        mergedAlerts: s.mergedAlerts, reason: s.reason,
      }));
      return {
        incident: incidentView,
        steps,
        edges: edgeRows.map((e) => ({ from: e.fromNode, to: e.toNode, kind: e.kind, techniqueId: e.techniqueId, time: e.time })),
        nextReach: next,
        englishReport: englishReport(incidentView, stepDets, next),
        hindiReport: hindiTemplate(incidentView, next),
        hindiSource: "mock_template",
        hindiWarning: "No Sarvam API key is set, so this is a Hindi template built from the incident fields, NOT a real Sarvam translation.",
      };
    },
  }),

  seedSynthetic: defineAction({
    description: "Loads the built-in synthetic log set through the detection pipeline, once, when no synthetic dataset exists yet.",
    request: z.object({}),
    response: z.object({ seeded: z.boolean(), datasetId: z.string(), incidents: z.number(), detections: z.number(), totalLines: z.number() }),
    async handler(ctx) {
      await ensureRulesAndTopology(ctx);
      const db = ctx.db<typeof schema>();
      const existing = await db.select().from(schema.datasets).where(eq(schema.datasets.id, "synthetic")).limit(1);
      if (existing.length > 0) {
        const incs = await db.select({ id: schema.incidents.id }).from(schema.incidents).where(eq(schema.incidents.datasetId, "synthetic"));
        return { seeded: false, datasetId: "synthetic", incidents: incs.length, detections: existing[0]?.detectionCount ?? 0, totalLines: existing[0]?.totalLines ?? 0 };
      }
      const { rules } = await loadRules(ctx);
      const lines = buildSyntheticLines();
      await db.insert(schema.datasets).values({
        id: "synthetic", name: "Synthetic set - planted attacks", kind: "synthetic",
        status: "ready", totalLines: 0, parsedLines: 0, unparsedLines: 0,
        detectionCount: 0, carryover: "", aggState: "{}", rawText: lines.join("\n"),
      });
      const agg: AggState = {};
      const result = await ingestLines(ctx, "synthetic", lines, rules, agg, 0);
      await db.update(schema.datasets).set({
        totalLines: lines.length, parsedLines: result.parsed, unparsedLines: result.unparsed,
        aggState: JSON.stringify(agg),
      }).where(eq(schema.datasets.id, "synthetic"));
      const incidents = await rebuildDataset(ctx, "synthetic");
      ctx.invalidateQueries();
      return { seeded: true, datasetId: "synthetic", incidents, detections: result.detections, totalLines: lines.length };
    },
  }),

  startUpload: defineAction({
    description: "Starts a chunked .log/.txt upload session and returns its dataset id.",
    request: z.object({ fileName: z.string().min(1).max(200) }),
    response: z.object({ datasetId: z.string() }),
    async handler(ctx, args) {
      await ensureRulesAndTopology(ctx);
      const db = ctx.db<typeof schema>();
      const datasetId = `up-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
      await db.insert(schema.datasets).values({
        id: datasetId, name: `Upload - ${args.fileName}`, kind: "upload",
        fileName: args.fileName, status: "ingesting",
        totalLines: 0, parsedLines: 0, unparsedLines: 0, detectionCount: 0,
        carryover: "", aggState: "{}", rawText: "",
      });
      ctx.invalidateQueries();
      return { datasetId };
    },
  }),

  ingestChunk: defineAction({
    description: "Processes one 64KB text chunk of an upload in stream order, counting benign lines and storing only detections.",
    request: z.object({
      datasetId: z.string(),
      text: z.string().max(100000),
      isLast: z.boolean(),
    }),
    response: z.object({
      ok: z.boolean(), error: z.string(),
      totalLines: z.number(), parsedLines: z.number(), unparsedLines: z.number(),
      detections: z.number(), incidents: z.number(), finished: z.boolean(),
    }),
    async handler(ctx, args) {
      const db = ctx.db<typeof schema>();
      const rows = await db.select().from(schema.datasets).where(eq(schema.datasets.id, args.datasetId)).limit(1);
      const ds = rows[0];
      if (!ds) return { ok: false, error: "Upload session not found.", totalLines: 0, parsedLines: 0, unparsedLines: 0, detections: 0, incidents: 0, finished: false };
      if (ds.status === "capped") {
        return { ok: false, error: "This upload passed the 2,000,000-line cap and was stopped.", totalLines: ds.totalLines, parsedLines: ds.parsedLines, unparsedLines: ds.unparsedLines, detections: ds.detectionCount, incidents: 0, finished: false };
      }
      const { rules } = await loadRules(ctx);
      const agg = parseAggState(ds.aggState);
      const combined = ds.carryover + args.text;
      const parts = combined.split("\n");
      const carryover = args.isLast ? "" : (parts.pop() ?? "");
      if (args.isLast && parts.length > 0 && (parts[parts.length - 1] ?? "").trim() === "") parts.pop();
      const lines = parts;
      if (ds.totalLines + lines.length > 2000000) {
        await db.update(schema.datasets).set({ status: "capped" }).where(eq(schema.datasets.id, args.datasetId));
        return { ok: false, error: "This upload passed the 2,000,000-line cap and was stopped.", totalLines: ds.totalLines, parsedLines: ds.parsedLines, unparsedLines: ds.unparsedLines, detections: ds.detectionCount, incidents: 0, finished: false };
      }
      const currentDetRows = await db.select({ seq: schema.detections.seq }).from(schema.detections)
        .where(eq(schema.detections.datasetId, args.datasetId))
        .orderBy(desc(schema.detections.seq)).limit(1);
      const startSeq = currentDetRows[0]?.seq ?? 0;
      const result = await ingestLines(ctx, args.datasetId, lines, rules, agg, startSeq);
      const rawText = ds.rawText === null ? null
        : ((ds.rawText ?? "") + args.text).length > 2000000 ? null : (ds.rawText ?? "") + args.text;
      const totalLines = ds.totalLines + lines.length;
      const parsedLines = ds.parsedLines + result.parsed;
      const unparsedLines = ds.unparsedLines + result.unparsed;
      await db.update(schema.datasets).set({
        totalLines, parsedLines, unparsedLines,
        detectionCount: ds.detectionCount + result.detections,
        carryover, aggState: JSON.stringify(agg), rawText,
        status: args.isLast ? "ready" : "ingesting",
      }).where(eq(schema.datasets.id, args.datasetId));
      let incidents = 0;
      if (args.isLast) incidents = await rebuildDataset(ctx, args.datasetId);
      ctx.invalidateQueries();
      return {
        ok: true, error: "", totalLines, parsedLines, unparsedLines,
        detections: ds.detectionCount + result.detections, incidents, finished: args.isLast,
      };
    },
  }),

  appendLiveLines: defineAction({
    description: "Appends pasted or fed log lines to the live dataset and re-links its incidents within seconds.",
    request: z.object({ text: z.string().min(1).max(100000), demoFeed: z.boolean().default(false) }),
    response: z.object({
      totalLines: z.number(), detections: z.number(), incidents: z.number(),
    }),
    async handler(ctx, args) {
      await ensureRulesAndTopology(ctx);
      const db = ctx.db<typeof schema>();
      let rows = await db.select().from(schema.datasets).where(eq(schema.datasets.id, "live")).limit(1);
      if (rows.length === 0) {
        await db.insert(schema.datasets).values({
          id: "live", name: "Live feed", kind: "live", status: "ready",
          totalLines: 0, parsedLines: 0, unparsedLines: 0, detectionCount: 0,
          carryover: "", aggState: "{}", rawText: "",
        });
        rows = await db.select().from(schema.datasets).where(eq(schema.datasets.id, "live")).limit(1);
      }
      const ds = rows[0];
      if (!ds) throw new Error("Live dataset could not be created");
      const { rules } = await loadRules(ctx);
      const agg = parseAggState(ds.aggState);
      const lines = args.text.split("\n");
      if (lines.length > 0 && (lines[lines.length - 1] ?? "").trim() === "") lines.pop();
      const currentDetRows = await db.select({ seq: schema.detections.seq }).from(schema.detections)
        .where(eq(schema.detections.datasetId, "live"))
        .orderBy(desc(schema.detections.seq)).limit(1);
      const result = await ingestLines(ctx, "live", lines, rules, agg, currentDetRows[0]?.seq ?? 0);
      await db.update(schema.datasets).set({
        totalLines: ds.totalLines + lines.length,
        parsedLines: ds.parsedLines + result.parsed,
        unparsedLines: ds.unparsedLines + result.unparsed,
        detectionCount: ds.detectionCount + result.detections,
        aggState: JSON.stringify(agg),
        rawText: (ds.rawText ?? "") + (ds.rawText ? "\n" : "") + args.text,
      }).where(eq(schema.datasets.id, "live"));
      const incidents = await rebuildDataset(ctx, "live");
      ctx.invalidateQueries();
      void args.demoFeed;
      return { totalLines: ds.totalLines + lines.length, detections: ds.detectionCount + result.detections, incidents };
    },
  }),

  startStreamDemo: defineAction({
    description: "Resets the large-volume stream demo dataset (5,009 lines) so it can be streamed in 500-line batches.",
    request: z.object({}),
    response: z.object({ datasetId: z.string(), totalLines: z.number(), batches: z.number() }),
    async handler(ctx) {
      await ensureRulesAndTopology(ctx);
      const db = ctx.db<typeof schema>();
      const existing = await db.select().from(schema.datasets).where(eq(schema.datasets.id, "stream-demo")).limit(1);
      if (existing.length > 0) await clearDatasetResults(ctx, "stream-demo");
      await db.delete(schema.datasets).where(eq(schema.datasets.id, "stream-demo"));
      await db.insert(schema.datasets).values({
        id: "stream-demo", name: "Stream demo - 5,009 lines, concealed attack", kind: "stream",
        status: "streaming", totalLines: 0, parsedLines: 0, unparsedLines: 0,
        detectionCount: 0, carryover: "", aggState: "{}", rawText: null,
      });
      ctx.invalidateQueries();
      return { datasetId: "stream-demo", totalLines: STREAM_TOTAL, batches: Math.ceil(STREAM_TOTAL / STREAM_BATCH) };
    },
  }),

  streamDemoBatch: defineAction({
    description: "Processes one 500-line batch of the stream demo and reports running counts.",
    request: z.object({ datasetId: z.string(), batch: z.number().int().min(0).max(20) }),
    response: z.object({
      batch: z.number(), totalLines: z.number(), parsedLines: z.number(), unparsedLines: z.number(),
      detections: z.number(), incidents: z.number(), finished: z.boolean(),
    }),
    async handler(ctx, args) {
      const db = ctx.db<typeof schema>();
      const rows = await db.select().from(schema.datasets).where(eq(schema.datasets.id, args.datasetId)).limit(1);
      const ds = rows[0];
      if (!ds) throw new Error("Stream demo dataset not found - start it first");
      const { rules } = await loadRules(ctx);
      const agg = parseAggState(ds.aggState);
      const lines = buildStreamBatch(args.batch);
      const currentDetRows = await db.select({ seq: schema.detections.seq }).from(schema.detections)
        .where(eq(schema.detections.datasetId, args.datasetId))
        .orderBy(desc(schema.detections.seq)).limit(1);
      const result = await ingestLines(ctx, args.datasetId, lines, rules, agg, currentDetRows[0]?.seq ?? 0);
      const finished = (args.batch + 1) * STREAM_BATCH >= STREAM_TOTAL;
      await db.update(schema.datasets).set({
        totalLines: ds.totalLines + lines.length,
        parsedLines: ds.parsedLines + result.parsed,
        unparsedLines: ds.unparsedLines + result.unparsed,
        detectionCount: ds.detectionCount + result.detections,
        aggState: JSON.stringify(agg),
        status: finished ? "ready" : "streaming",
      }).where(eq(schema.datasets.id, args.datasetId));
      let incidents = 0;
      if (finished) incidents = await rebuildDataset(ctx, args.datasetId);
      ctx.invalidateQueries();
      return {
        batch: args.batch,
        totalLines: ds.totalLines + lines.length,
        parsedLines: ds.parsedLines + result.parsed,
        unparsedLines: ds.unparsedLines + result.unparsed,
        detections: ds.detectionCount + result.detections,
        incidents, finished,
      };
    },
  }),

  getRules: defineAction({
    description: "Returns the current Sigma-style rules config text and its parsed rule list.",
    request: z.object({}),
    response: z.object({
      yaml: z.string(),
      rules: z.array(z.object({
        id: z.string(), name: z.string(), techniqueId: z.string(), techniqueName: z.string(),
        tactic: z.string(), stage: z.string(), confidence: z.number(), priority: z.number(),
        description: z.string(), type: z.string(),
      })),
      error: z.string(),
    }),
    async handler(ctx) {
      await ensureRulesAndTopology(ctx);
      const db = ctx.db<typeof schema>();
      const rows = await db.select().from(schema.rulesConfig).where(eq(schema.rulesConfig.id, 1)).limit(1);
      const yaml = rows[0]?.yamlText ?? DEFAULT_RULES_YAML;
      try {
        const rules = parseRulesYaml(yaml);
        return {
          yaml,
          rules: rules.map((r) => ({
            id: r.id, name: r.name, techniqueId: r.techniqueId, techniqueName: r.techniqueName,
            tactic: r.tactic, stage: r.stage, confidence: r.confidence, priority: r.priority,
            description: r.description, type: r.type,
          })),
          error: "",
        };
      } catch (e) {
        return { yaml, rules: [], error: e instanceof Error ? e.message : String(e) };
      }
    },
  }),

  saveRules: defineAction({
    description: "Validates edited Sigma-style YAML rules, saves them, and re-runs detection over every dataset whose raw lines are available.",
    request: z.object({ yaml: z.string().min(1).max(100000) }),
    response: z.object({ ok: z.boolean(), error: z.string(), reprocessed: z.array(z.string()) }),
    async handler(ctx, args) {
      let rules: Rule[];
      try {
        rules = parseRulesYaml(args.yaml);
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e), reprocessed: [] };
      }
      const db = ctx.db<typeof schema>();
      await db.update(schema.rulesConfig).set({ yamlText: args.yaml, updatedAt: new Date() })
        .where(eq(schema.rulesConfig.id, 1));
      const all = await db.select({ id: schema.datasets.id }).from(schema.datasets);
      const reprocessed: string[] = [];
      for (const row of all) {
        const status = await reprocessDataset(ctx, row.id, rules);
        if (status === "ok") reprocessed.push(row.id);
      }
      ctx.invalidateQueries();
      return { ok: true, error: "", reprocessed };
    },
  }),

  resetRules: defineAction({
    description: "Restores the default Sigma-style rules and re-runs detection.",
    request: z.object({}),
    response: z.object({ yaml: z.string(), reprocessed: z.array(z.string()) }),
    async handler(ctx) {
      const db = ctx.db<typeof schema>();
      await db.update(schema.rulesConfig).set({ yamlText: DEFAULT_RULES_YAML, updatedAt: new Date() })
        .where(eq(schema.rulesConfig.id, 1));
      const rules = parseRulesYaml(DEFAULT_RULES_YAML);
      const all = await db.select({ id: schema.datasets.id }).from(schema.datasets);
      const reprocessed: string[] = [];
      for (const row of all) {
        const status = await reprocessDataset(ctx, row.id, rules);
        if (status === "ok") reprocessed.push(row.id);
      }
      ctx.invalidateQueries();
      return { yaml: DEFAULT_RULES_YAML, reprocessed };
    },
  }),

  deleteDataset: defineAction({
    description: "Deletes one dataset and all of its detections and incidents.",
    request: z.object({ datasetId: z.string() }),
    response: z.object({ deleted: z.boolean() }),
    async handler(ctx, args) {
      if (args.datasetId === "synthetic") {
        await clearDatasetResults(ctx, args.datasetId);
      }
      const db = ctx.db<typeof schema>();
      await clearDatasetResults(ctx, args.datasetId);
      await db.delete(schema.datasets).where(eq(schema.datasets.id, args.datasetId));
      ctx.invalidateQueries();
      return { deleted: true };
    },
  }),

  getEngineFacts: defineAction({
    description: "Returns the engine design facts, tiers, targets, and measured synthetic-run numbers shown in the Engine chapter.",
    request: z.object({}),
    response: z.object({
      tiers: z.array(z.object({ tier: z.string(), size: z.string(), tests: z.string(), multiplier: z.string() })),
      targets: z.array(z.object({ measure: z.string(), how: z.string(), good: z.string(), great: z.string() })),
      measured: z.array(z.object({ label: z.string(), value: z.string() })),
      loadout: z.array(z.object({ slot: z.string(), name: z.string(), job: z.string() })),
    }),
    async handler() {
      return {
        tiers: [
          { tier: "Core", size: "15 GB", tests: "Bigger than a typical laptop's memory, so the log must be streamed in chunks", multiplier: "1.0x" },
          { tier: "Advanced", size: "30 GB", tests: "Needs parallel processing and compact storage to finish in time", multiplier: "1.3x" },
          { tier: "Extreme", size: "50 GB", tests: "Full scale; a multi-core machine or cloud instance is expected", multiplier: "1.6x" },
        ],
        targets: [
          { measure: "Detection", how: "Share of planted attack steps found", good: "Over 70%", great: "Over 90%" },
          { measure: "Correct labels", how: "Share of found steps with the right ATT&CK technique", good: "Over 60%", great: "Over 85%" },
          { measure: "Attack path", how: "Planted attacks rebuilt with the right steps in the right order", good: "Half of them", great: "All of them" },
          { measure: "False alarms", how: "Share of incidents that are not real attacks", good: "Under 30%", great: "Under 10%" },
          { measure: "Processing time", how: "Time to process the full chosen tier", good: "Under 3 hours", great: "Under 1 hour" },
          { measure: "Memory", how: "Peak memory used while processing", good: "Under 16 GB", great: "Under 8 GB" },
          { measure: "Investigation speed", how: "Time to open one incident's attack path", good: "Under 2 seconds", great: "Under 500 ms" },
        ],
        measured: [
          { label: "Synthetic run, Python engine", value: "5,009 lines → 24 detections, 5 incidents" },
          { label: "Processing time", value: "0.47 s (10,701 events/sec)" },
          { label: "Peak memory", value: "94.8 MB" },
          { label: "Evaluation vs planted ground truth", value: "Detection 100% · Labels 100% · Path 100% · False alarms 0%" },
          { label: "Honest limit", value: "No 15/30/50 GB file was run; tier times are targets, not measurements" },
        ],
        loadout: [
          { slot: "SLOT 01", name: "Python streaming parser", job: "Reads logs line by line in batches. The whole file is never loaded into memory." },
          { slot: "SLOT 02", name: "DuckDB storage", job: "Detections, incidents, merged counts, and graph edges on disk, looked up by incident id." },
          { slot: "SLOT 03", name: "NetworkX graph", job: "Hosts and users as nodes, events as edges; time-ordered path rebuild and next-reach." },
          { slot: "SLOT 04", name: "Sigma-style YAML rules", job: "Detection rules live in a config file. Add a rule by editing the file, never the code." },
        ],
      };
    },
  }),
} satisfies ActionsModule;
