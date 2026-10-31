import { index, integer, real, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const datasets = sqliteTable("datasets", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  kind: text("kind").notNull(),
  fileName: text("file_name"),
  status: text("status").notNull().default("ready"),
  totalLines: integer("total_lines").notNull().default(0),
  parsedLines: integer("parsed_lines").notNull().default(0),
  unparsedLines: integer("unparsed_lines").notNull().default(0),
  detectionCount: integer("detection_count").notNull().default(0),
  carryover: text("carryover").notNull().default(""),
  aggState: text("agg_state").notNull().default("{}"),
  rawText: text("raw_text"),
  staleRules: integer("stale_rules").notNull().default(0),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
});

export const detections = sqliteTable(
  "detections",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    datasetId: text("dataset_id").notNull(),
    seq: integer("seq").notNull(),
    time: text("time").notNull().default(""),
    ts: real("ts"),
    host: text("host").notNull().default(""),
    user: text("user").notNull().default(""),
    ip: text("ip").notNull().default(""),
    source: text("source").notNull().default(""),
    action: text("action").notNull().default(""),
    detail: text("detail").notNull().default(""),
    techniqueId: text("technique_id").notNull().default(""),
    techniqueName: text("technique_name").notNull().default(""),
    tactic: text("tactic").notNull().default(""),
    stage: text("stage").notNull().default(""),
    severity: text("severity").notNull().default("Medium"),
    confidence: integer("confidence").notNull().default(0),
    ruleId: text("rule_id").notNull().default(""),
    mergedAlerts: integer("merged_alerts").notNull().default(1),
    reason: text("reason").notNull().default(""),
  },
  (t) => [index("detections_dataset_seq_idx").on(t.datasetId, t.seq)],
);

export const incidents = sqliteTable(
  "incidents",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    datasetId: text("dataset_id").notNull(),
    title: text("title").notNull(),
    missionLabel: text("mission_label").notNull().default(""),
    startTime: text("start_time").notNull().default(""),
    endTime: text("end_time").notNull().default(""),
    hosts: text("hosts").notNull().default("[]"),
    users: text("users").notNull().default("[]"),
    riskScore: real("risk_score").notNull().default(0),
    mergedAlerts: integer("merged_alerts").notNull().default(0),
    detectionCount: integer("detection_count").notNull().default(0),
  },
  (t) => [index("incidents_dataset_risk_idx").on(t.datasetId, t.riskScore, t.detectionCount, t.id)],
);

export const incidentDetections = sqliteTable("incident_detections", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  incidentId: integer("incident_id").notNull(),
  detectionId: integer("detection_id").notNull(),
  seq: integer("seq").notNull().default(0),
});

export const edges = sqliteTable("edges", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  incidentId: integer("incident_id").notNull(),
  fromNode: text("from_node").notNull(),
  toNode: text("to_node").notNull(),
  kind: text("kind").notNull().default("event"),
  techniqueId: text("technique_id").notNull().default(""),
  time: text("time").notNull().default(""),
});

export const rulesConfig = sqliteTable("rules_config", {
  id: integer("id").primaryKey(),
  yamlText: text("yaml_text").notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
});

export const topology = sqliteTable("topology", {
  id: integer("id").primaryKey(),
  jsonText: text("json_text").notNull(),
});
