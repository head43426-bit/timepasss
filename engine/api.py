"""Simple HTTP API (FR-7) using only the Python standard library.

Endpoints:
  GET /health                          -> {"status": "ok", ...}
  GET /incidents                       -> risk-ranked incidents (B-1),
                                          each with merged_alerts (B-3)
  GET /incidents/{id}/path             -> timeline + graph nodes/edges
  GET /incidents/{id}/report           -> plain-English report (B-2)
  GET /incidents/{id}/report?hindi=1   -> + Hindi (Sarvam if keyed, else
                                          labelled mock template, B-2)
  GET /incidents/{id}/next             -> what the attacker could reach
                                          next (FR-6)

Optional live mode: --watch <logfile> starts a background tailer thread
(polling every 2s, B-5) in the same process; the API reads from the same
DuckDB connection under a lock, so new lines appear in /incidents
without restarting the server.

Usage: python3 -m engine.api --db out.duckdb --port 8000 [--watch logs]
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import graph as graph_mod
from .severity import normalize_severity, weight_of
from . import report as report_mod
from . import store
from .live import Tailer
from .rules import Detector, load_rules

LOCK = threading.Lock()


def _incident_with_extras(con, incident_id):
    inc = store.get_incident(con, incident_id)
    if not inc:
        return None
    topology = store.get_topology(con)
    nxt = graph_mod.next_reach(inc["hosts"], inc["users"], topology)
    # OBSERVED FALLBACK (2026-11-01 fix): a web upload never supplies
    # a topology, so the topology-only path always returned [] and
    # the page said 'no next system' for every incident. When no
    # topology is present, use what the logs actually show: the
    # frontier destinations (contacted, not yet a stepping stone).
    # When a topology IS supplied (CLI --topology), it still wins.
    _edges = (inc.get("graph") or {}).get("edges", [])
    _tech_sev = {}
    try:
        for _tid, _sev in con.execute(
                "SELECT d.technique_id, d.severity FROM detections d "
                "JOIN incident_detections idt ON idt.detection_id = d.id "
                "WHERE idt.incident_id = ? AND d.technique_id <> ''",
                [incident_id]).fetchall():
            _sev = normalize_severity(_sev) or "Low"
            _w = weight_of(_sev)
            _cur = _tech_sev.get(_tid)
            if _cur is None or _w > weight_of(_cur):
                _tech_sev[_tid] = _sev
    except Exception:
        _tech_sev = {}
    if nxt:
        inc["next_reach"] = nxt
        inc["next_basis"] = "supplied topology"
        inc["next_frontier_total"] = len(nxt)
    else:
        _obs = graph_mod.observed_next_reach(_edges, _tech_sev)
        inc["next_reach"] = _obs[:10]
        inc["next_basis"] = "observed graph"
        inc["next_frontier_total"] = len(_obs)
    # Stage look-ahead works even without topology (firex case).
    _stages = []
    for _s in inc.get("timeline_summary", []):
        if _s.get("kill_chain_stage"):
            _stages.append(_s["kill_chain_stage"])
    if not _stages:
        _stages = [d.get("kill_chain_stage", "") for d in inc.get("timeline", [])]
    inc["next_stages"] = graph_mod.next_stages(_stages)
    # BLAST RADIUS (2026-11-01 fix): topology score is 0 whenever no
    # topology was supplied, which is every web upload. Use the
    # observed-graph score then, and say which basis it is, so the
    # page never again shows a meaningless 0/100 for a 184-node
    # incident. Detections for the score come from the timeline
    # (sampled for huge incidents - the score is an estimate then,
    # and the breakdown says so in the frontend).
    if topology.get("host_subnet"):
        inc["blast_radius"] = graph_mod.blast_radius_score(inc["hosts"], topology)
        inc["blast_basis"] = "supplied topology"
        inc["blast_breakdown"] = None
    else:
        _br = graph_mod.observed_blast_radius(inc.get("timeline", []), _edges)
        inc["blast_radius"] = _br["score"]
        inc["blast_basis"] = "observed graph"
        inc["blast_breakdown"] = _br
    from engine import protect as protect_mod
    inc["protections"] = protect_mod.protections_for(inc)
    return inc


def _apply_detection(con, detector, event, next_id):
    """Incrementally link one live detection into the DB (B-5)."""
    for det in detector.process(event):
        con.execute("BEGIN TRANSACTION")
        try:
            det_id = next_id[0]
            next_id[0] += 1
            store.insert_detections(con, [det], det_id)
            # Find an existing incident sharing host/user/IP, else create.
            incidents = store.list_incidents(con)
            target = None
            for inc in incidents:
                full = store.get_incident(con, inc["id"])
                if (det["host"] in full["hosts"] or det["user"] in full["users"]
                        or (det.get("ip") and any(
                            d.get("ip") == det["ip"] for d in full["timeline"]))):
                    target = full
                    break
            if target is None:
                new_id = max([i["id"] for i in incidents], default=0) + 1
                store.insert_incident(con, {
                    "id": new_id, "title": f"Live incident on {det['host']}",
                    "start_time": det["time"], "end_time": det["time"],
                    "hosts": [det["host"]], "users": [det["user"]],
                    "risk_score": graph_mod.risk_score([det]),
                    "merged_alerts": det["merged_alerts"],
                    "detection_count": 1, "detection_ids": [det_id],
                    "edges": graph_mod.graph_edges([det]),
                })
            else:
                timeline = target["timeline"] + [det]
                hosts = sorted(set(target["hosts"]) | {det["host"]})
                users = sorted(set(target["users"]) | {det["user"]})
                con.execute(
                    "UPDATE incidents SET end_time=?, hosts=?, users=?,"
                    " risk_score=?, merged_alerts=?, detection_count=?"
                    " WHERE id=?",
                    [det["time"], json.dumps(hosts), json.dumps(users),
                     graph_mod.risk_score(timeline),
                     target["merged_alerts"] + det["merged_alerts"],
                     target["detection_count"] + 1, target["id"]])
                con.execute(
                    "INSERT INTO incident_detections VALUES (?,?,?)",
                    [target["id"], det_id, target["detection_count"]])
                for edge in graph_mod.graph_edges(timeline):
                    con.execute(
                        "DELETE FROM edges WHERE incident_id=?", [target["id"]])
                    break
                for edge in graph_mod.graph_edges(timeline):
                    con.execute(
                        "INSERT INTO edges VALUES (?,?,?,?,?,?)",
                        [target["id"], edge["from"], edge["to"], edge["kind"],
                         edge.get("technique_id", ""), edge.get("time", "")])
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise


def make_handler(con, rules_dir):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # keep stdout clean
            sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

        def _send(self, obj, status=200):
            body = json.dumps(obj, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            query = parse_qs(parsed.query)
            with LOCK:
                if parts == ["health"]:
                    count = store.count_detections(con)
                    return self._send({"status": "ok",
                                       "detections": count,
                                       "incidents": len(store.list_incidents(con))})
                if parts == ["incidents"]:
                    return self._send(store.list_incidents(con))
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "path":
                    try:
                        inc_id = int(parts[1])
                    except ValueError:
                        return self._send({"error": "bad incident id"}, 400)
                    start = time.perf_counter()
                    inc = store.get_incident(con, inc_id)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    if not inc:
                        return self._send({"error": "incident not found"}, 404)
                    inc["query_ms"] = round(elapsed_ms, 2)
                    return self._send(inc)
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "report":
                    try:
                        inc_id = int(parts[1])
                    except ValueError:
                        return self._send({"error": "bad incident id"}, 400)
                    inc = _incident_with_extras(con, inc_id)
                    if not inc:
                        return self._send({"error": "incident not found"}, 404)
                    out = {"incident_id": inc_id, "title": inc["title"],
                           "report": report_mod.english_report(inc, inc["next_reach"]),
                           "next_reach": inc["next_reach"],
                           "merged_alerts": inc["merged_alerts"]}
                    if query.get("hindi") == ["1"]:
                        out["hindi"] = report_mod.hindi_report(inc, inc["next_reach"])
                    return self._send(out)
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "next":
                    try:
                        inc_id = int(parts[1])
                    except ValueError:
                        return self._send({"error": "bad incident id"}, 400)
                    inc = _incident_with_extras(con, inc_id)
                    if not inc:
                        return self._send({"error": "incident not found"}, 404)
                    return self._send({"incident_id": inc_id,
                                       "next_reach": inc["next_reach"]})
                return self._send({"error": "not found"}, 404)

    return Handler


def serve(db_path, host="127.0.0.1", port=8000, watch=None, rules_dir="rules",
          interval=2.0):
    con = store.connect(db_path)
    if watch:
        detector = Detector(load_rules(rules_dir))
        tailer = Tailer(watch)
        next_id = [store.count_detections(con) + 1]

        def _watch_loop():
            while True:
                events = tailer.tail_once()
                if events:
                    with LOCK:
                        for event in events:
                            _apply_detection(con, detector, event, next_id)
                time.sleep(interval)

        thread = threading.Thread(target=_watch_loop, daemon=True)
        thread.start()
        print(f"Live watch: {watch} every {interval}s")
    server = ThreadingHTTPServer((host, port), make_handler(con, rules_dir))
    print(f"API listening on http://{host}:{port} (db: {db_path})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("API stopped.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Kill Chain engine API")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--watch")
    parser.add_argument("--rules", default="rules")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args(argv)
    serve(args.db, args.host, args.port, args.watch, args.rules, args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
