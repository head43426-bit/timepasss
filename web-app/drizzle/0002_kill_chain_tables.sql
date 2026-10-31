DROP TABLE IF EXISTS entries;
--> statement-breakpoint
CREATE TABLE datasets (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  file_name TEXT,
  status TEXT NOT NULL DEFAULT 'ready',
  total_lines INTEGER NOT NULL DEFAULT 0,
  parsed_lines INTEGER NOT NULL DEFAULT 0,
  unparsed_lines INTEGER NOT NULL DEFAULT 0,
  detection_count INTEGER NOT NULL DEFAULT 0,
  carryover TEXT NOT NULL DEFAULT '',
  agg_state TEXT NOT NULL DEFAULT '{}',
  raw_text TEXT,
  stale_rules INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
--> statement-breakpoint
CREATE TABLE detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  time TEXT NOT NULL DEFAULT '',
  ts REAL,
  host TEXT NOT NULL DEFAULT '',
  user TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  technique_id TEXT NOT NULL DEFAULT '',
  technique_name TEXT NOT NULL DEFAULT '',
  tactic TEXT NOT NULL DEFAULT '',
  stage TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'Medium',
  confidence INTEGER NOT NULL DEFAULT 0,
  rule_id TEXT NOT NULL DEFAULT '',
  merged_alerts INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL DEFAULT ''
);
--> statement-breakpoint
CREATE INDEX detections_dataset_seq_idx ON detections (dataset_id, seq);
--> statement-breakpoint
CREATE TABLE incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id TEXT NOT NULL,
  title TEXT NOT NULL,
  mission_label TEXT NOT NULL DEFAULT '',
  start_time TEXT NOT NULL DEFAULT '',
  end_time TEXT NOT NULL DEFAULT '',
  hosts TEXT NOT NULL DEFAULT '[]',
  users TEXT NOT NULL DEFAULT '[]',
  risk_score REAL NOT NULL DEFAULT 0,
  merged_alerts INTEGER NOT NULL DEFAULT 0,
  detection_count INTEGER NOT NULL DEFAULT 0
);
--> statement-breakpoint
CREATE INDEX incidents_dataset_risk_idx ON incidents (dataset_id, risk_score DESC, detection_count DESC, id ASC);
--> statement-breakpoint
CREATE TABLE incident_detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  detection_id INTEGER NOT NULL,
  seq INTEGER NOT NULL DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  from_node TEXT NOT NULL,
  to_node TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'event',
  technique_id TEXT NOT NULL DEFAULT '',
  time TEXT NOT NULL DEFAULT ''
);
--> statement-breakpoint
CREATE TABLE rules_config (
  id INTEGER PRIMARY KEY NOT NULL,
  yaml_text TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
--> statement-breakpoint
CREATE TABLE topology (
  id INTEGER PRIMARY KEY NOT NULL,
  json_text TEXT NOT NULL
);
