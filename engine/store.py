"""DuckDB storage (compact, on-disk, indexed incident lookup).

Tables:
  detections(id, time, ts, host, user, ip, source, action, detail,
             technique_id, technique_name, tactic, kill_chain_stage,
             severity, confidence, rule_id, merged_alerts, reason)
  incidents(id, title, start_time, end_time, hosts, users, risk_score,
            merged_alerts, detection_count)
  incident_detections(incident_id, detection_id, seq)
  edges(incident_id, from_node, to_node, kind, technique_id, time)
  topology_admin(account, host)      -- from topology.json, if given
  topology_subnet(host, subnet)      -- from topology.json, if given

Investigation-speed design: an incident's path is fetched by
``incident_id`` only (primary-key / indexed joins), never by scanning
all detections. The API measures and reports that query time; see
``get_incident``.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY, time VARCHAR, ts DOUBLE, host VARCHAR,
  user VARCHAR, ip VARCHAR, source VARCHAR, action VARCHAR,
  detail VARCHAR, technique_id VARCHAR, technique_name VARCHAR,
  tactic VARCHAR, kill_chain_stage VARCHAR, severity VARCHAR,
  confidence INTEGER, rule_id VARCHAR, merged_alerts INTEGER,
  reason VARCHAR
);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY, title VARCHAR, start_time VARCHAR,
  end_time VARCHAR, hosts VARCHAR, users VARCHAR, risk_score DOUBLE,
  merged_alerts INTEGER, detection_count INTEGER
);
CREATE TABLE IF NOT EXISTS incident_detections (
  incident_id INTEGER, detection_id INTEGER, seq INTEGER,
  PRIMARY KEY (incident_id, detection_id)
);
CREATE TABLE IF NOT EXISTS edges (
  incident_id INTEGER, from_node VARCHAR, to_node VARCHAR,
  kind VARCHAR, technique_id VARCHAR, time VARCHAR
);
CREATE TABLE IF NOT EXISTS topology_admin (account VARCHAR, host VARCHAR);
CREATE TABLE IF NOT EXISTS topology_subnet (host VARCHAR, subnet VARCHAR);
"""


def connect(db_path: str, fresh: bool = False):
    if fresh and os.path.exists(db_path):
        os.remove(db_path)
    con = duckdb.connect(db_path)
    con.execute("BEGIN TRANSACTION")
    for stmt in SCHEMA.strip().split(";\n"):
        if stmt.strip():
            con.execute(stmt)
    con.execute("COMMIT")
    return con


def insert_detections(con, detections: List[Dict], start_id: int) -> int:
    rows = [(
        start_id + i, d.get("time", ""), d.get("ts"),
        d.get("host", ""), d.get("user", ""), d.get("ip", ""),
        d.get("source", ""), d.get("action", ""), d.get("detail", ""),
        d.get("technique_id", ""), d.get("technique_name", ""),
        d.get("tactic", ""), d.get("kill_chain_stage", ""),
        d.get("severity", "Medium"), int(d.get("confidence", 0)),
        d.get("rule_id", ""), int(d.get("merged_alerts", 1)),
        d.get("reason", ""),
    ) for i, d in enumerate(detections)]
    if rows:
        con.executemany(
            "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return start_id + len(rows)


def insert_incident(con, incident: Dict) -> None:
    con.execute(
        "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?)",
        [incident["id"], incident["title"], incident.get("start_time", ""),
         incident.get("end_time", ""), json.dumps(incident.get("hosts", [])),
         json.dumps(incident.get("users", [])),
         float(incident.get("risk_score", 0)),
         int(incident.get("merged_alerts", 0)),
         int(incident.get("detection_count", 0))])
    det_rows = [(incident["id"], det_id, seq) for seq, det_id in enumerate(incident.get("detection_ids", []))]
    if det_rows:
        con.executemany("INSERT INTO incident_detections VALUES (?,?,?)", det_rows)
    edge_rows = [(incident["id"], edge["from"], edge["to"], edge["kind"],
                  edge.get("technique_id", ""), edge.get("time", "")) for edge in incident.get("edges", [])]
    if edge_rows:
        con.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?)", edge_rows)


def load_topology(con, topology: Dict) -> None:
    for account, hosts in (topology.get("admin_rights") or {}).items():
        for host in hosts:
            con.execute("INSERT INTO topology_admin VALUES (?,?)", [account, host])
    for subnet, hosts in (topology.get("subnets") or {}).items():
        for host in hosts:
            con.execute("INSERT INTO topology_subnet VALUES (?,?)", [host, subnet])
    for host in topology.get("hosts", []):
        # Hosts listed without a subnet still exist; no subnet row = no
        # subnet-based next-reach guess for them (never guessed).
        pass


def list_incidents(con) -> List[Dict]:
    rows = con.execute(
        "SELECT id, title, start_time, end_time, hosts, users, risk_score,"
        " merged_alerts, detection_count FROM incidents"
        " ORDER BY risk_score DESC, detection_count DESC, id ASC").fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r[0], "title": r[1], "start_time": r[2], "end_time": r[3],
            "hosts": json.loads(r[4] or "[]"), "users": json.loads(r[5] or "[]"),
            "risk_score": r[6], "merged_alerts": r[7], "detection_count": r[8],
        })
    return out


def get_incident(con, incident_id: int) -> Optional[Dict]:
    """Incident path by id only (indexed lookup, no full scan)."""
    row = con.execute(
        "SELECT id, title, start_time, end_time, hosts, users, risk_score,"
        " merged_alerts, detection_count FROM incidents WHERE id = ?",
        [incident_id]).fetchone()
    if not row:
        return None
    timeline = con.execute(
        "SELECT d.id, d.time, d.host, d.user, d.ip, d.source, d.action,"
        " d.detail, d.technique_id, d.technique_name, d.tactic,"
        " d.kill_chain_stage, d.severity, d.confidence, d.rule_id,"
        " d.merged_alerts, d.reason FROM detections d"
        " JOIN incident_detections idt ON idt.detection_id = d.id"
        " WHERE idt.incident_id = ? ORDER BY idt.seq ASC",
        [incident_id]).fetchall()
    edges = con.execute(
        "SELECT from_node, to_node, kind, technique_id, time FROM edges"
        " WHERE incident_id = ?", [incident_id]).fetchall()
    nodes = {}
    for det in timeline:
        nodes.setdefault(det[2], {"id": det[2], "type": "host"})
        nodes.setdefault(det[3], {"id": det[3], "type": "user"})
    return {
        "id": row[0], "title": row[1], "start_time": row[2], "end_time": row[3],
        "hosts": json.loads(row[4] or "[]"), "users": json.loads(row[5] or "[]"),
        "risk_score": row[6], "merged_alerts": row[7], "detection_count": row[8],
        "timeline": [{
            "id": d[0], "time": d[1], "host": d[2], "user": d[3], "ip": d[4],
            "source": d[5], "action": d[6], "detail": d[7],
            "technique_id": d[8], "technique_name": d[9], "tactic": d[10],
            "kill_chain_stage": d[11], "severity": d[12], "confidence": d[13],
            "rule_id": d[14], "merged_alerts": d[15], "reason": d[16],
        } for d in timeline],
        "graph": {
            "nodes": sorted(nodes.values(), key=lambda n: (n["type"], n["id"])),
            "edges": [{
                "from": e[0], "to": e[1], "kind": e[2],
                "technique_id": e[3], "time": e[4],
            } for e in edges],
        },
    }


def get_topology(con) -> Dict:
    admin: Dict[str, List[str]] = {}
    for account, host in con.execute(
            "SELECT account, host FROM topology_admin").fetchall():
        admin.setdefault(account, []).append(host)
    subnet: Dict[str, str] = {}
    for host, sub in con.execute(
            "SELECT host, subnet FROM topology_subnet").fetchall():
        subnet[host] = sub
    return {"admin_rights": admin, "host_subnet": subnet}


def count_detections(con) -> int:
    return con.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
