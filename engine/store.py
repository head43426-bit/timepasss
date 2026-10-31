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
    # MEMORY FIX (2026-11-01): DuckDB has no memory cap by default and
    # will happily grow toward all RAM during big inserts/queries —
    # on an 8 GB machine that is what pushes the system to 90%.
    # Cap it at 1 GB (or 25% of total RAM on smaller machines, never
    # below 256 MB); DuckDB spills to disk past the cap instead of
    # eating the machine. Slightly slower on huge runs, far safer.
    try:
        import sys as _sys
        if _sys.platform == "win32":
            import ctypes
            class _MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            _ms = _MS(); _ms.dwLength = ctypes.sizeof(_MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(_ms))
            _total_gb = _ms.ullTotalPhys / (1024 ** 3)
        else:
            _total_gb = 0
            with open("/proc/meminfo") as _f:
                for _line in _f:
                    if _line.startswith("MemTotal:"):
                        _total_gb = int(_line.split()[1]) / (1024 ** 2)
                        break
        _cap_gb = max(0.25, min(1.0, _total_gb * 0.25)) if _total_gb else 1.0
        con.execute(f"SET memory_limit='{_cap_gb:.2f}GB'")
    except Exception:
        pass
    con.execute("BEGIN TRANSACTION")
    for stmt in SCHEMA.strip().split(";\n"):
        if stmt.strip():
            con.execute(stmt)
    con.execute("COMMIT")
    return con


def insert_detections(con, detections: List[Dict], start_id: int) -> int:
    """Bulk insert. The old executemany path took 30 seconds for 60,000
    rows on this VM — that, not parsing, was the real speed wall.
    DuckDB's C-speed CSV reader does the same 60,000 rows in 0.37s
    (80x faster, measured). CSV writing is done by Python's csv
    module, which quotes commas/quotes/newlines correctly, and any
    failure falls back to the old executemany path so a weird field
    can never lose a detection."""
    if not detections:
        return start_id
    try:
        import csv
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                         delete=False, newline="",
                                         encoding="utf-8") as tf:
            writer = csv.writer(tf)
            for i, d in enumerate(detections):
                writer.writerow([
                    start_id + i, d.get("time", ""), d.get("ts"),
                    d.get("host", ""), d.get("user", ""), d.get("ip", ""),
                    d.get("source", ""), d.get("action", ""), d.get("detail", ""),
                    d.get("technique_id", ""), d.get("technique_name", ""),
                    d.get("tactic", ""), d.get("kill_chain_stage", ""),
                    d.get("severity", "Medium"), int(d.get("confidence", 0)),
                    d.get("rule_id", ""), int(d.get("merged_alerts", 1)),
                    d.get("reason", ""),
                ])
            tmp_path = tf.name
        try:
            con.execute(
                "INSERT INTO detections SELECT * FROM read_csv(?, header=false,"
                " columns={'c0':'INTEGER','c1':'VARCHAR','c2':'DOUBLE',"
                "'c3':'VARCHAR','c4':'VARCHAR','c5':'VARCHAR','c6':'VARCHAR',"
                "'c7':'VARCHAR','c8':'VARCHAR','c9':'VARCHAR','c10':'VARCHAR',"
                "'c11':'VARCHAR','c12':'VARCHAR','c13':'VARCHAR',"
                "'c14':'INTEGER','c15':'VARCHAR','c16':'INTEGER',"
                "'c17':'VARCHAR'})", [tmp_path])
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except Exception:
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
        con.executemany(
            "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return start_id + len(detections)


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
        # Same CSV bulk-load trick as detections: executemany for a
        # 60,000-step incident took most of the old run time.
        try:
            import csv
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                             delete=False, newline="",
                                             encoding="utf-8") as tf:
                writer = csv.writer(tf)
                writer.writerows(det_rows)
                tmp_path = tf.name
            try:
                con.execute(
                    "INSERT INTO incident_detections SELECT * FROM read_csv(?,"
                    " header=false, columns={'c0':'INTEGER','c1':'INTEGER',"
                    "'c2':'INTEGER'})", [tmp_path])
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except Exception:
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
    # FAST PATH — this is the unresponsive-page fix. A 271,896-step
    # incident used to load every timeline row into Python dicts
    # before the page could draw anything, and the report then did it
    # again. For large incidents, DuckDB itself does the work: first
    # 200 + last 200 rows by seq, plus a GROUP BY summary (counts,
    # first/last non-empty time per technique). The page then renders
    # 400 rows, never 271k, and RAM stays flat on a 4 GB machine.
    # ?full=1 still returns everything, for a deliberate export.
    _cols = ("d.id, d.time, d.host, d.user, d.ip, d.source, d.action,"
             " d.detail, d.technique_id, d.technique_name, d.tactic,"
             " d.kill_chain_stage, d.severity, d.confidence, d.rule_id,"
             " d.merged_alerts, d.reason")
    _base = (" FROM detections d JOIN incident_detections idt"
             " ON idt.detection_id = d.id WHERE idt.incident_id = ?")
    _count = row[8] or 0
    _sampled = _count > 500
    if _sampled:
        _first = con.execute(
            f"SELECT {_cols}{_base} ORDER BY idt.seq ASC LIMIT 200",
            [incident_id]).fetchall()
        _last = con.execute(
            f"SELECT {_cols}{_base} ORDER BY idt.seq DESC LIMIT 200",
            [incident_id]).fetchall()
        timeline = _first + list(reversed(_last))
        _summary = con.execute(
            "SELECT d.technique_id, d.technique_name, d.kill_chain_stage,"
            " COUNT(*), MIN(idt.seq), MIN(NULLIF(d.time, '')),"
            " MAX(NULLIF(d.time, ''))" + _base +
            " GROUP BY d.technique_id, d.technique_name, d.kill_chain_stage"
            " ORDER BY MIN(idt.seq)",
            [incident_id]).fetchall()
    else:
        timeline = con.execute(
            f"SELECT {_cols}{_base} ORDER BY idt.seq ASC",
            [incident_id]).fetchall()
        _summary = []
    edges = con.execute(
        "SELECT from_node, to_node, kind, technique_id, time FROM edges"
        " WHERE incident_id = ?", [incident_id]).fetchall()
    # MAP FIX (2026-11-01): nodes come ONLY from edge endpoints.
    # The old code added every host/user from the incident row first,
    # so the firewall name FGT... always appeared as an isolated node
    # even when no edge touched it — that is the "single host, nothing
    # showing" map. Edge endpoints are the real machines (srcip,
    # dstip/domain, user, technique); anything else is not drawn.
    _users = set(json.loads(row[5] or "[]"))
    tech_ids = {det[8] for det in timeline if det[8]} | {s[0] for s in _summary if s[0]}
    nodes = {}
    for e in edges:
        for endpoint in (e[0], e[1]):
            if endpoint and endpoint not in nodes:
                nodes[endpoint] = {"id": endpoint,
                                   "type": "user" if endpoint in _users
                                   else "technique" if endpoint in tech_ids
                                   else "host"}
    # NODE COLOUR DATA (2026-11-01, graph redesign): the frontend
    # colours each node by its worst severity and labels it with its
    # earliest kill-chain stage, so the map can be read at a glance
    # instead of a wall of identical red boxes. Severity comes from
    # DuckDB aggregates over the whole incident (not the 400-row
    # timeline sample), grouped by technique, by user and by src IP;
    # a host node's severity is the worst severity of any edge
    # touching it, via that edge's technique. Stage comes from the
    # technique -> stage mapping in the summary/timeline.
    _sev_w = {"Critical": 40, "High": 25, "Medium": 10, "Low": 3}
    _tech_sev, _tech_stage, _user_sev, _ip_sev = {}, {}, {}, {}
    try:
        _base_q = (" FROM detections d JOIN incident_detections idt"
                   " ON idt.detection_id = d.id WHERE idt.incident_id = ?")
        for _tid, _sev in con.execute(
                "SELECT d.technique_id, d.severity" + _base_q + " AND d.technique_id <> ''",
                [incident_id]).fetchall():
            if _tid not in _tech_sev or _sev_w.get(_sev, 10) > _sev_w.get(_tech_sev[_tid], 10):
                _tech_sev[_tid] = _sev
        for _u, _sev in con.execute(
                "SELECT d.user, d.severity" + _base_q + " AND d.user <> ''",
                [incident_id]).fetchall():
            if _u not in _user_sev or _sev_w.get(_sev, 10) > _sev_w.get(_user_sev[_u], 10):
                _user_sev[_u] = _sev
        for _ip, _sev in con.execute(
                "SELECT d.ip, d.severity" + _base_q + " AND d.ip <> ''",
                [incident_id]).fetchall():
            if _ip not in _ip_sev or _sev_w.get(_sev, 10) > _sev_w.get(_ip_sev[_ip], 10):
                _ip_sev[_ip] = _sev
    except Exception:
        pass
    for _s in _summary:
        if _s[0] and _s[2]:
            _tech_stage[_s[0]] = _s[2]
    for _d in timeline:
        if _d[8] and _d[11]:
            _tech_stage.setdefault(_d[8], _d[11])
    _order = ["Reconnaissance", "Initial Access", "Execution", "Persistence",
              "Privilege Escalation", "Defense Evasion", "Credential Access",
              "Discovery", "Lateral Movement", "Collection",
              "Command and Control", "Exfiltration", "Impact"]
    for _nid, _node in nodes.items():
        if _node["type"] == "user":
            _node["severity"] = _user_sev.get(_nid, "Low")
            _node["stage"] = ""
        elif _node["type"] == "technique":
            _node["severity"] = _tech_sev.get(_nid, "Medium")
            _node["stage"] = _tech_stage.get(_nid, "")
        else:
            _touch = [e[3] for e in edges if e[0] == _nid or e[1] == _nid]
            _sev_list = [_tech_sev[t] for t in _touch if t in _tech_sev]
            _node["severity"] = (max(_sev_list, key=lambda s: _sev_w.get(s, 10))
                                 if _sev_list else _ip_sev.get(_nid, "Low"))
            _stages = [_tech_stage[t] for t in _touch if t in _tech_stage]
            _node["stage"] = (min(_stages, key=lambda s: _order.index(s) if s in _order else 99)
                              if _stages else "")
    return {
        "id": row[0], "title": row[1], "start_time": row[2], "end_time": row[3],
        "hosts": json.loads(row[4] or "[]"), "users": json.loads(row[5] or "[]"),
        "risk_score": row[6], "merged_alerts": row[7], "detection_count": row[8],
        "timeline_sampled": _sampled, "timeline_total": _count,
        "timeline_summary": [{
            "technique_id": s[0], "technique_name": s[1],
            "kill_chain_stage": s[2], "count": s[3],
            "first": s[5] or "", "last": s[6] or "",
        } for s in _summary],
        "timeline": [{
            "id": d[0], "time": d[1], "host": d[2], "user": d[3], "ip": d[4],
            "source": d[5], "action": d[6], "detail": d[7],
            "technique_id": d[8], "technique_name": d[9], "tactic": d[10],
            "kill_chain_stage": d[11], "severity": d[12], "confidence": d[13],
            "rule_id": d[14], "merged_alerts": d[15], "reason": d[16],
        } for d in timeline],
        "graph": {
            "nodes": sorted(nodes.values(), key=lambda n: (n["type"], n["id"])),
            # Skip edges from/to a blank node (Fortinet logs with no
            # user stored a "" -> host edge; that is not a real move).
            "edges": [{
                "from": e[0], "to": e[1], "kind": e[2],
                "technique_id": e[3], "time": e[4],
            } for e in edges if e[0] and e[1]],
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
