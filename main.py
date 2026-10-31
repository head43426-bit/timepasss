#!/usr/bin/env python3
"""Kill Chain Attack Path Reconstruction — proper project entry point.

Frontend + backend, no demo data. You bring your own .log file.

    pip install -r requirements.txt
    python main.py serve --db out.duckdb --port 8001
    # open http://localhost:8001 and upload your .log file there

    python main.py run --log mylogs.log --db out.duckdb
    python main.py run --log mylogs.log --db out.duckdb --ground-truth truth.json

Backend: engine/ (parser, rules, DuckDB store, NetworkX graph, report, live tailer).
Frontend: frontend/ (index.html, styles.css, app.js) — served by this file, no build step.
Uploads are processed by the real pipeline (engine.cli.run), not by browser JavaScript.
Use only synthetic or authorised logs. Never real production logs or credentials.
"""
import argparse
import json
import mimetypes
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from engine import graph as graph_mod  # noqa: E402
from engine import report as report_mod  # noqa: E402
from engine import store  # noqa: E402
from engine.api import LOCK, _apply_detection, _incident_with_extras  # noqa: E402
from engine.cli import run as cli_run  # noqa: E402
from engine.parallel import parallel_run  # noqa: E402
from engine.live import Tailer  # noqa: E402
from engine.rules import Detector, load_rules  # noqa: E402

FRONTEND = os.path.join(ROOT, "frontend")


class DBHolder:
    """Holds the live DuckDB connection. Upload replaces the whole DB,
    so the holder is swapped (not the file deleted under an open connection)."""

    def __init__(self, con):
        self.con = con


def make_handler(holder, rules_dir, db_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def _send_json(self, obj, status=200):
            body = json.dumps(obj, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, path):
            if not os.path.isfile(path):
                return self._send_json({"error": "not found"}, 404)
            with open(path, "rb") as f:
                body = f.read()
            mime, _ = mimetypes.guess_type(path)
            self.send_response(200)
            self.send_header("Content-Type", mime or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            query = parse_qs(parsed.query)
            # Showcase is the main page. The real-data upload dashboard
            # (frontend/) lives at /app — the showcase links there.
            if parsed.path == "/":
                return self._send_file(os.path.join(ROOT, "showcase.html"))
            if parsed.path in ("/app", "/app/"):
                return self._send_file(os.path.join(FRONTEND, "index.html"))
            if parsed.path in ("/app/styles.css", "/app/app.js"):
                return self._send_file(os.path.join(FRONTEND, parsed.path.split("/")[-1]))
            # Frontend (no build step, plain files) — kept for /index.html
            if parsed.path == "/index.html":
                return self._send_file(os.path.join(FRONTEND, "index.html"))
            if parsed.path in ("/styles.css", "/app.js"):
                return self._send_file(os.path.join(FRONTEND, parsed.path.lstrip("/")))
            # Amazing pages from before — these were in the repo but
            # NOT served, so localhost:8001 always showed only the
            # plain frontend dashboard. That is why the dashboard
            # looked the same even after restoring them.
            if parsed.path in ("/showcase.html", "/dashboard.html"):
                return self._send_file(os.path.join(ROOT, parsed.path.lstrip("/")))
            if parsed.path == "/demo" or parsed.path.startswith("/demo/"):
                # Original browser demo (root index.html + its JS/CSS).
                # Served under /demo/ so its relative styles.css/app.js
                # do not clash with the frontend's files at /styles.css.
                rel = "index.html" if parsed.path in ("/demo", "/demo/") else parsed.path[len("/demo/"):]
                if ".." in rel:
                    return self._send_json({"error": "not found"}, 404)
                return self._send_file(os.path.join(ROOT, rel))
            with LOCK:
                if parts == ["db", "stats"]:
                    tables = [t[0] for t in holder.con.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'").fetchall()]
                    counts = {t: holder.con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
                    file_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
                    breakdown = holder.con.execute("SELECT kill_chain_stage, technique_id, technique_name, count(*) as count FROM detections GROUP BY kill_chain_stage, technique_id, technique_name ORDER BY count DESC LIMIT 10").fetchall()
                    return self._send_json({
                        "db_path": os.path.abspath(db_path),
                        "file_size_bytes": file_size,
                        "file_size_mb": round(file_size / (1024 * 1024), 2),
                        "tables": counts,
                        "top_techniques": [{"stage": b[0], "technique_id": b[1], "technique_name": b[2], "count": b[3]} for b in breakdown]
                    })
                if parts == ["health"]:
                    return self._send_json({"status": "ok",
                                            "detections": store.count_detections(holder.con),
                                            "incidents": len(store.list_incidents(holder.con))})
                if parts == ["incidents"]:
                    return self._send_json(store.list_incidents(holder.con))
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "path":
                    try:
                        inc_id = int(parts[1])
                    except ValueError:
                        return self._send_json({"error": "bad incident id"}, 400)
                    inc = store.get_incident(holder.con, inc_id)
                    if not inc:
                        return self._send_json({"error": "incident not found"}, 404)
                    return self._send_json(inc)
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "report":
                    inc = _incident_with_extras(holder.con, int(parts[1])) if parts[1].isdigit() else None
                    if not inc:
                        return self._send_json({"error": "incident not found"}, 404)
                    out = {"incident_id": inc["id"], "title": inc["title"],
                           "report": report_mod.english_report(inc, inc["next_reach"]),
                           "next_reach": inc["next_reach"],
                           "merged_alerts": inc["merged_alerts"]}
                    if query.get("hindi") == ["1"]:
                        out["hindi"] = report_mod.hindi_report(inc, inc["next_reach"])
                    return self._send_json(out)
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "next":
                    inc = _incident_with_extras(holder.con, int(parts[1])) if parts[1].isdigit() else None
                    if not inc:
                        return self._send_json({"error": "incident not found"}, 404)
                    return self._send_json({"incident_id": inc["id"], "next_reach": inc["next_reach"]})
                return self._send_json({"error": "not found, try / , /health or /incidents"}, 404)

        def do_POST(self):
            if urlparse(self.path).path != "/upload":
                return self._send_json({"error": "not found"}, 404)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            filename = self.headers.get("X-Filename") or "uploaded.log"
            # Write the uploaded log to a temp file, then run the real pipeline on it.
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".log", delete=False) as tmp:
                tmp.write(raw)
                tmp_path = tmp.name
            try:
                with LOCK:
                    try:
                        holder.con.close()
                    except Exception:
                        pass
                    summary = cli_run(tmp_path, db_path, rules_dir)
                    holder.con = store.connect(db_path)
                summary["filename"] = filename
                return self._send_json(summary)
            except Exception as exc:  # keep the server alive, report the error
                return self._send_json({"error": str(exc)}, 500)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    return Handler


def serve(db_path, host, port, rules_dir, watch=None, interval=2.0):
    holder = DBHolder(store.connect(db_path))
    con = holder.con
    if watch:
        detector = Detector(load_rules(rules_dir))
        tailer = Tailer(watch)
        next_id = [store.count_detections(holder.con) + 1]

        def _watch_loop():
            while True:
                events = tailer.tail_once()
                if events:
                    with LOCK:
                        for event in events:
                            _apply_detection(holder.con, detector, event, next_id)
                time.sleep(interval)

        threading.Thread(target=_watch_loop, daemon=True).start()
        print("Live watch: %s every %ss" % (watch, interval))
    server = ThreadingHTTPServer((host, port), make_handler(holder, rules_dir, db_path))
    print("Dashboard: http://%s:%d  (upload your .log file there)" % (host, port))
    print("API: /health, /incidents, /incidents/{id}/path, /incidents/{id}/report, /incidents/{id}/next")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")


def main():
    ap = argparse.ArgumentParser(description="Kill Chain — proper project")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="dashboard + API")
    s.add_argument("--db", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8001)
    s.add_argument("--rules", default="rules")
    s.add_argument("--watch", default=None)
    r = sub.add_parser("run", help="process a log file on the command line")
    r.add_argument("--log", required=True)
    r.add_argument("--db", required=True)
    r.add_argument("--rules", default="rules")
    r.add_argument("--topology", default=None)
    r.add_argument("--ground-truth", default=None)
    r.add_argument("--workers", type=int, default=1,
                   help="1 = single-core (default). >1 = multi-core parallel, 0 = all cores")
    args = ap.parse_args()
    if args.cmd == "serve":
        serve(args.db, args.host, args.port, args.rules, args.watch)
    else:
        if args.workers != 1:
            summary = parallel_run(args.log, args.db, args.rules, workers=args.workers,
                                   topology_path=args.topology, ground_truth_path=args.ground_truth)
        else:
            summary = cli_run(args.log, args.db, args.rules, args.topology, ground_truth_path=args.ground_truth)
        print("Events: %(events)s  Detections: %(detections)s  Incidents: %(incidents)s  "
              "%(seconds)ss (%(events_per_second)s events/sec)  Peak RSS: %(peak_rss_mb)s MB" % {**summary, "peak_rss_mb": summary.get("peak_rss_mb", 0)})
        if "evaluation" in summary:
            print("Evaluation:", summary["evaluation"])


if __name__ == "__main__":
    main()
