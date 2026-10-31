#!/usr/bin/env python3
"""Kill Chain Attack Path Reconstruction - proper project entry point.

Frontend + backend, no demo data. You bring your own .log file.

    pip install -r requirements.txt
    python main.py serve --db out.duckdb --port 8001
    # open http://localhost:8001 and upload your .log file there

    python main.py run --log mylogs.log --db out.duckdb
    python main.py run --log mylogs.log --db out.duckdb --ground-truth truth.json

Backend: engine/ (parser, rules, DuckDB store, NetworkX graph, report, live tailer).
Frontend: frontend/ (index.html, styles.css, app.js) - served by this file, no build step.
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


def _load_dotenv():
    """Load repo-root .env into os.environ, without logging any value.

    Only keys not already set in the environment are added, and empty
    values are ignored. This is what makes SARVAM_API_KEY work from a
    private .env file: the server reads it at startup, so a page reload
    alone never loads a key -- restart the server after editing .env.
    """
    env_path = os.path.join(ROOT, ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass


_load_dotenv()

from engine import graph as graph_mod  # noqa: E402
from engine import mitre as mitre_mod  # noqa: E402
from engine import report as report_mod  # noqa: E402
from engine import store  # noqa: E402
from engine.api import LOCK, _apply_detection, _incident_with_extras  # noqa: E402
from engine.cli import run as cli_run  # noqa: E402
from engine.parallel import parallel_run  # noqa: E402
from engine.live import Tailer  # noqa: E402
from engine.rules import Detector, load_rules  # noqa: E402

FRONTEND = os.path.join(ROOT, "frontend")

# Upload progress, shared between the upload thread and GET /progress.
# No DB lock is needed to read it: it is only ever replaced, never mutated in place.
PROGRESS = {
    "stage": "idle", "stage_text": "No upload running.",
    "filename": "", "bytes_received": 0, "bytes_total": 0,
    "events": 0, "detections": 0, "estimated_total_events": 0,
    "events_per_second": 0, "elapsed_seconds": 0, "eta_seconds": None,
    "done": False, "error": "", "top_techniques": [],
}
PROGRESS_LOCK = threading.Lock()


def _fmt_eta(seconds):
    if seconds is None:
        return None
    seconds = int(seconds)
    if seconds < 60:
        return f"about {seconds}s left"
    if seconds < 3600:
        return f"about {seconds // 60}m {seconds % 60}s left"
    return f"about {seconds // 3600}h {(seconds % 3600) // 60}m left"


def _set_progress(**kw):
    with PROGRESS_LOCK:
        PROGRESS.update(kw)


def _progress_snapshot():
    with PROGRESS_LOCK:
        snap = dict(PROGRESS)
    snap["eta_text"] = _fmt_eta(snap["eta_seconds"])
    # CPU/RAM on every poll (never break a poll if stats fail).
    try:
        from engine import sysstats as _ss
        snap.update(_ss.snapshot())
        snap["elapsed_text"] = _ss.fmt_duration(snap.get("elapsed_seconds", 0))
    except Exception:
        pass
    return snap


class DBHolder:
    """Holds the live DuckDB connection. Upload replaces the whole DB,
    so the holder is swapped (not the file deleted under an open connection)."""

    def __init__(self, con):
        self.con = con


def make_handler(holder, rules_dir, db_path, live_watch=None):
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
            # ASK brand assets (transparent logo + favicons, assets/).
            # Binary PNG/ICO files cannot go through the snapshot push
            # (UTF-8 text only), so each one also has a .b64 text twin
            # in the repo. If the binary is missing (a fresh pull), the
            # server decodes the .b64 twin and serves the real bytes.
            def _send_asset(name):
                path = os.path.join(ROOT, "assets", name)
                if os.path.isfile(path):
                    return self._send_file(path)
                b64 = path + ".b64"
                if os.path.isfile(b64):
                    import base64
                    with open(b64, "r", encoding="ascii") as f:
                        body = base64.b64decode(f.read())
                    mime, _ = mimetypes.guess_type(path)
                    self.send_response(200)
                    self.send_header("Content-Type", mime or "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return None
                return self._send_json({"error": "not found"}, 404)
            if parsed.path == "/favicon.ico":
                return _send_asset("favicon.ico")
            if parsed.path.startswith("/assets/") or parsed.path.startswith("/app/assets/"):
                name = parsed.path.split("/")[-1]
                if ".." in name or "/" in name:
                    return self._send_json({"error": "not found"}, 404)
                return _send_asset(name)
            # Showcase is the main page. The real-data upload dashboard
            # (frontend/) lives at /app - the showcase links there.
            if parsed.path == "/":
                return self._send_file(os.path.join(ROOT, "showcase.html"))
            if parsed.path in ("/app", "/app/"):
                return self._send_file(os.path.join(FRONTEND, "index.html"))
            if parsed.path in ("/app/styles.css", "/app/app.js"):
                return self._send_file(os.path.join(FRONTEND, parsed.path.split("/")[-1]))
            # Frontend (no build step, plain files) - kept for /index.html
            if parsed.path == "/index.html":
                return self._send_file(os.path.join(FRONTEND, "index.html"))
            if parsed.path in ("/styles.css", "/app.js"):
                return self._send_file(os.path.join(FRONTEND, parsed.path.lstrip("/")))
            # Amazing pages from before - these were in the repo but
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
            if parts == ["progress"]:
                return self._send_json(_progress_snapshot())
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
                # Note: Amogh's timess also added a GET /clear route that
                # wiped the DB on a plain GET. Removed on merge: clearing
                # must only happen via POST /clear (the button), never by
                # visiting a URL, a prefetch, or a link.
                if parts == ["health"]:
                    return self._send_json({"status": "ok",
                                            "detections": store.count_detections(holder.con),
                                            "incidents": len(store.list_incidents(holder.con)),
                                            "live_watch": live_watch})
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
                    # A 118,043-step incident must not ship a 118,043-item
                    # timeline to the browser - that is what made the old
                    # detail page unusable. Above 500 steps, send a
                    # summary (counts by stage/technique) plus the first
                    # and last 200 steps as a sample. Full detail is
                    # still available with ?full=1.
                    tl = inc.get("timeline", [])
                    if len(tl) > 500 and query.get("full") != ["1"]:
                        counts = {}
                        for d in tl:
                            k = (d.get("kill_chain_stage", ""), d.get("technique_id", ""),
                                 d.get("technique_name", ""))
                            counts[k] = counts.get(k, 0) + 1
                        inc["timeline_total"] = len(tl)
                        inc["timeline_sampled"] = True
                        inc["timeline_summary"] = [
                            {"kill_chain_stage": k[0], "technique_id": k[1],
                             "technique_name": k[2], "count": c}
                            for k, c in counts.items()]
                        inc["timeline"] = tl[:200] + tl[-200:]
                    # Look-ahead rides along with the path, so the
                    # frontend does not need a second slow request.
                    _extra = _incident_with_extras(holder.con, inc_id)
                    if _extra:
                        inc["next_reach"] = _extra["next_reach"]
                        inc["next_stages"] = _extra["next_stages"]
                        inc["blast_radius"] = _extra["blast_radius"]
                    return self._send_json(inc)
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "report":
                    inc = _incident_with_extras(holder.con, int(parts[1])) if parts[1].isdigit() else None
                    if not inc:
                        return self._send_json({"error": "incident not found"}, 404)
                    out = {"incident_id": inc["id"], "title": inc["title"],
                           "report": report_mod.english_report(inc, inc["next_reach"]),
                           "next_reach": inc["next_reach"],
                           "next_stages": inc["next_stages"],
                           "blast_radius": inc["blast_radius"],
                           "protections": inc["protections"],
                           "merged_alerts": inc["merged_alerts"]}
                    if query.get("hindi") == ["1"]:
                        out["hindi"] = report_mod.hindi_report(inc, inc["next_reach"])
                    _lang = (query.get("lang") or [""])[0].lower()
                    if _lang in ("en", "hi", "ta", "te", "ml"):
                        _tr = report_mod.translate_report(inc, inc["next_reach"], _lang)
                        out["lang"] = _lang
                        out["translated"] = _tr
                    return self._send_json(out)
                if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "next":
                    inc = _incident_with_extras(holder.con, int(parts[1])) if parts[1].isdigit() else None
                    if not inc:
                        return self._send_json({"error": "incident not found"}, 404)
                    return self._send_json({"incident_id": inc["id"], "next_reach": inc["next_reach"],
                                            "next_stages": inc["next_stages"],
                                            "blast_radius": inc["blast_radius"],
                                            "next_basis": inc.get("next_basis", ""),
                                            "next_frontier_total": inc.get("next_frontier_total", 0),
                                            "blast_basis": inc.get("blast_basis", ""),
                                            "blast_breakdown": inc.get("blast_breakdown")})
                # Slim MITRE index (lookup only, lazy - see engine/mitre.py).
                if parts == ["mitre"]:
                    return self._send_json(mitre_mod.coverage(
                        os.path.join(ROOT, "rules")))
                if len(parts) == 2 and parts[0] == "mitre":
                    _t = mitre_mod.lookup(parts[1].upper())
                    if not _t:
                        return self._send_json({"error": "technique not in MITRE index"}, 404)
                    return self._send_json(_t)
                # Custom 404 page for browsers, JSON only for API calls.
                if parts and parts[0] not in ("health", "incidents", "progress", "db", "clear", "upload", "mitre"):
                    _p404 = os.path.join(FRONTEND, "404.html")
                    if os.path.isfile(_p404):
                        with open(_p404, "rb") as _f:
                            _body = _f.read()
                        self.send_response(404)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(_body)))
                        self.end_headers()
                        self.wfile.write(_body)
                        return None
                return self._send_json({"error": "not found, try / , /health or /incidents"}, 404)

        def do_POST(self):
            if urlparse(self.path).path == "/clear":
                with LOCK:
                    try:
                        holder.con.close()
                    except Exception:
                        pass
                    holder.con = store.connect(db_path, fresh=True)
                return self._send_json({"status": "ok", "detections": 0, "incidents": 0})
            if urlparse(self.path).path == "/sample":
                # LOAD SAMPLE (2026-11-01, changed behaviour): it no
                # longer loads the small sample_attack.log and no
                # longer wipes the DB. It generates about 500 MB of
                # synthetic log from generate_logs.py
                # (engine/sample_gen.py, streamed to a temp file next
                # to the DB, never held in RAM) and APPENDS it with
                # cli run_append (fresh=False): existing detections
                # and incidents keep their ids and graphs, and the new
                # detections link among themselves into new incidents.
                # Progress reuses /progress like /demo, so the bar
                # tracks generation then processing. When this POST
                # returns, the page reloads the list; the dashboard's
                # 5-second /health refresh also picks the new counts
                # up afterwards (live mode). Expect a few minutes for
                # the full 500 MB run.
                from engine.sample_gen import TARGET_BYTES as _SAMPLE_BYTES, iter_sample_lines
                from engine.cli import run_append as _run_append
                started = time.time()
                filename = "sample-500mb.log (synthetic, from generate_logs.py)"
                try:
                    _before_incidents = len(store.list_incidents(holder.con))
                except Exception:
                    _before_incidents = 0
                # Scratch file goes in the repo dir (real disk), NOT
                # next to the DB: a DB in /tmp (a 512 MB tmpfs here)
                # cannot hold a 500 MB temp file, and that exact
                # failure was hit in testing. The file is deleted
                # after processing either way.
                _db_dir = ROOT
                tmp_path = None
                try:
                    _set_progress(stage="generating",
                                  stage_text="Generating sample - synthetic, about 500 MB, from generate_logs.py",
                                  filename=filename, bytes_received=0,
                                  bytes_total=_SAMPLE_BYTES, events=0,
                                  detections=0, estimated_total_events=0,
                                  events_per_second=0, elapsed_seconds=0,
                                  eta_seconds=None, done=False, error="")
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, dir=_db_dir, encoding="utf-8") as tmp:
                        tmp_path = tmp.name
                        buf = []
                        written = 0
                        for line in iter_sample_lines(_SAMPLE_BYTES):
                            buf.append(line)
                            written += len(line) + 1
                            if len(buf) >= 1000:
                                tmp.write("\n".join(buf) + "\n")
                                buf = []
                                _set_progress(bytes_received=written,
                                              elapsed_seconds=round(time.time() - started, 1))
                        if buf:
                            tmp.write("\n".join(buf) + "\n")
                    length = os.path.getsize(tmp_path)
                    est_total = 0
                    try:
                        with open(tmp_path, "rb") as f:
                            sample = [next(f) for _ in range(200)]
                        if sample:
                            avg = sum(len(l) for l in sample) / len(sample)
                            if avg > 0:
                                est_total = int(length / avg)
                    except Exception:
                        est_total = 0
                    _set_progress(estimated_total_events=est_total)

                    def _on_progress_sample(events, detections, stage, top=None):
                        elapsed = max(time.time() - started, 0.001)
                        eps = events / elapsed if stage == "reading" else 0
                        eta = None
                        if stage == "reading" and eps > 0 and est_total > events:
                            eta = (est_total - events) / eps
                        texts = {"reading": "Step 2 of 4 - Reading",
                                 "linking": "Step 3 of 4 - Linking",
                                 "storing": "Step 4 of 4 - Saving"}
                        _kw = dict(stage=stage, stage_text=texts.get(stage, stage),
                                   events=events, detections=detections,
                                   events_per_second=round(eps, 1),
                                   elapsed_seconds=round(elapsed, 1),
                                   eta_seconds=round(eta) if eta is not None else None)
                        if top is not None:
                            _kw["top_techniques"] = top
                        _set_progress(**_kw)

                    _queue_started = time.time()
                    while not LOCK.acquire(blocking=False):
                        _wait = int(time.time() - _queue_started)
                        _set_progress(stage="queued",
                                      stage_text=f"Queued - sample file is ready and waiting for the previous upload to finish. Waiting {_wait}s so far.",
                                      elapsed_seconds=round(time.time() - started, 1))
                        time.sleep(1)
                    try:
                        _set_progress(stage="reading", stage_text="Step 2 of 4 - Reading")
                        try:
                            holder.con.close()
                        except Exception:
                            pass
                        summary = _run_append(tmp_path, db_path, rules_dir,
                                              chunk_size=20000, on_progress=_on_progress_sample)
                        holder.con = store.connect(db_path)
                        # run_append's incident counter starts at the
                        # old max id, so report only the incidents this
                        # run actually added, matching events/detections.
                        try:
                            summary["incidents"] = max(0, len(store.list_incidents(holder.con)) - _before_incidents)
                        except Exception:
                            pass
                    finally:
                        LOCK.release()
                    summary["filename"] = filename
                    summary["appended"] = True
                    from engine import sysstats as _ss_sample
                    _total_s = round(time.time() - started, 1)
                    _set_progress(stage="done",
                                  stage_text=f"Done in {_ss_sample.fmt_duration(_total_s)} - appended sample incidents are ready below.",
                                  events=summary.get("events", 0),
                                  detections=summary.get("detections", 0),
                                  elapsed_seconds=_total_s, eta_seconds=0, done=True)
                    return self._send_json(summary)
                except Exception as exc:
                    _set_progress(stage="error", stage_text=f"Failed: {exc}", done=True, error=str(exc))
                    try:
                        holder.con = store.connect(db_path)
                    except Exception:
                        pass
                    try:
                        return self._send_json({"error": str(exc)}, 500)
                    except Exception:
                        return None
                finally:
                    if tmp_path:
                        try:
                            os.unlink(tmp_path)
                        except OSError:
                            pass
            if urlparse(self.path).path == "/tiny":
                # Tiny Demo endpoint, kept for API compatibility. Its
                # button was removed from the dashboard (2026-11-01).
                # It still REPLACES the DB, like /upload - it is not
                # an append, so do not use it expecting Load Sample
                # behaviour.
                try:
                    _db_dir = os.path.dirname(os.path.abspath(db_path)) or "."
                    _lines = [
                        "2026-11-01T08:00:00Z|workstation-01|alice|10.10.40.156|network|net_connect|Inbound HTTPS connection|Normal|None|Low",
                        "2026-11-01T08:05:00Z|workstation-01|alice|10.10.40.156|sysmon|powershell_exec|powershell -enc SQBFAFgAAB executed encoded command|Execution|T1059.001|High",
                        "2026-11-01T08:10:00Z|workstation-01|alice|10.10.20.11|edr|kerberoasting|Kerberoasting request for service ticket|Credential Access|T1558.003|High",
                        "2026-11-01T08:15:00Z|workstation-01|alice|10.10.0.20|edr|c2_connect|Periodic C2 beacon to external server|Command and Control|T1071.001|High",
                        "2026-11-01T08:20:00Z|workstation-01|alice|10.10.40.156|network|dns|DNS query resolved for example.com|Normal|None|Low",
                    ]
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, dir=_db_dir, encoding="utf-8") as _tf:
                        _tf.write("\n".join(_lines) + "\n")
                        _tmp = _tf.name
                    with LOCK:
                        try:
                            holder.con.close()
                        except Exception:
                            pass
                        _summary = cli_run(_tmp, db_path, rules_dir, chunk_size=20000)
                        holder.con = store.connect(db_path)
                    try:
                        os.unlink(_tmp)
                    except OSError:
                        pass
                    return self._send_json(_summary)
                except Exception as exc:
                    try:
                        holder.con = store.connect(db_path)
                    except Exception:
                        pass
                    return self._send_json({"error": str(exc)}, 500)
            if urlparse(self.path).path == "/demo":
                # DEMO BUTTON (2026-11-01): server generates ~100 MB of
                # synthetic log (engine/demo.py, same pattern as
                # sample_attack.log - no real logs, no download, no
                # browser round-trip of 100 MB) and then runs it
                # through the exact same processing as /upload
                # (parallel_run / cli_run, same rules, same DB).
                # Progress reuses /progress, so the page's elapsed /
                # CPU / RAM line works unchanged.
                from engine.demo import TARGET_BYTES, iter_demo_lines
                started = time.time()
                filename = "demo-100mb.log (synthetic)"
                _db_dir = os.path.dirname(os.path.abspath(db_path)) or "."
                tmp_path = None
                try:
                    _set_progress(stage="generating",
                                  stage_text="Generating demo - synthetic, about 100 MB",
                                  filename=filename, bytes_received=0,
                                  bytes_total=TARGET_BYTES, events=0,
                                  detections=0, estimated_total_events=0,
                                  events_per_second=0, elapsed_seconds=0,
                                  eta_seconds=None, done=False, error="")
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, dir=_db_dir, encoding="utf-8") as tmp:
                        tmp_path = tmp.name
                        buf = []
                        written = 0
                        for line in iter_demo_lines(TARGET_BYTES):
                            buf.append(line)
                            written += len(line) + 1
                            if len(buf) >= 1000:
                                tmp.write("\n".join(buf) + "\n")
                                buf = []
                                _set_progress(bytes_received=written,
                                              elapsed_seconds=round(time.time() - started, 1))
                        if buf:
                            tmp.write("\n".join(buf) + "\n")
                    length = os.path.getsize(tmp_path)
                    est_total = 0
                    try:
                        with open(tmp_path, "rb") as f:
                            sample = [next(f) for _ in range(200)]
                        if sample:
                            avg = sum(len(l) for l in sample) / len(sample)
                            if avg > 0:
                                est_total = int(length / avg)
                    except Exception:
                        est_total = 0
                    _set_progress(estimated_total_events=est_total)

                    def _on_progress_demo(events, detections, stage, top=None):
                        elapsed = max(time.time() - started, 0.001)
                        eps = events / elapsed if stage == "reading" else 0
                        eta = None
                        if stage == "reading" and eps > 0 and est_total > events:
                            eta = (est_total - events) / eps
                        texts = {"reading": "Step 2 of 4 - Reading",
                                 "linking": "Step 3 of 4 - Linking",
                                 "storing": "Step 4 of 4 - Saving"}
                        _kw = dict(stage=stage, stage_text=texts.get(stage, stage),
                                   events=events, detections=detections,
                                   events_per_second=round(eps, 1),
                                   elapsed_seconds=round(elapsed, 1),
                                   eta_seconds=round(eta) if eta is not None else None)
                        if top is not None:
                            _kw["top_techniques"] = top
                        _set_progress(**_kw)

                    _queue_started = time.time()
                    while not LOCK.acquire(blocking=False):
                        _wait = int(time.time() - _queue_started)
                        _set_progress(stage="queued",
                                      stage_text=f"Queued - demo file is ready and waiting for the previous upload to finish. Waiting {_wait}s so far.",
                                      elapsed_seconds=round(time.time() - started, 1))
                        time.sleep(1)
                    try:
                        _set_progress(stage="reading", stage_text="Step 2 of 4 - Reading")
                        try:
                            holder.con.close()
                        except Exception:
                            pass
                        from engine.parallel import cpu_friendly_workers as _workers_demo
                        _workers_n = _workers_demo(6)
                        if (est_total > 50000 or length > 20 * 1024 * 1024) and _workers_n > 1:
                            _set_progress(stage_text=f"Step 2 of 4 - Reading ({_workers_n} workers)")
                            summary = parallel_run(tmp_path, db_path, rules_dir,
                                                   workers=_workers_n, on_progress=_on_progress_demo)
                        else:
                            summary = cli_run(tmp_path, db_path, rules_dir,
                                              chunk_size=20000, on_progress=_on_progress_demo)
                        holder.con = store.connect(db_path)
                    finally:
                        LOCK.release()
                    summary["filename"] = filename
                    from engine import sysstats as _ss_demo
                    _total_s = round(time.time() - started, 1)
                    _set_progress(stage="done",
                                  stage_text=f"Done in {_ss_demo.fmt_duration(_total_s)} - demo incidents are ready below.",
                                  events=summary.get("events", 0),
                                  detections=summary.get("detections", 0),
                                  elapsed_seconds=_total_s, eta_seconds=0, done=True)
                    return self._send_json(summary)
                except Exception as exc:
                    _set_progress(stage="error", stage_text=f"Failed: {exc}", done=True, error=str(exc))
                    try:
                        holder.con = store.connect(db_path)
                    except Exception:
                        pass
                    try:
                        return self._send_json({"error": str(exc)}, 500)
                    except Exception:
                        return None
                finally:
                    if tmp_path:
                        try:
                            os.unlink(tmp_path)
                        except OSError:
                            pass
            if urlparse(self.path).path != "/upload":
                return self._send_json({"error": "not found"}, 404)
            length = int(self.headers.get("Content-Length") or 0)
            filename = self.headers.get("X-Filename") or "uploaded.log"
            started = time.time()
            _set_progress(stage="uploading",
                          stage_text="Step 1 of 4 - Receiving",
                          filename=filename, bytes_received=0, bytes_total=length,
                          events=0, detections=0, estimated_total_events=0,
                          events_per_second=0, elapsed_seconds=0, eta_seconds=None,
                          done=False, error="")
            # Stream the body to a temp file in chunks. The old code did
            # rfile.read(length), which loaded the whole file into RAM -
            # that alone would kill a 50 GB upload. Chunked reading keeps
            # memory flat whatever the file size.
            # Temp file lives NEXT TO THE DATABASE, not in system /tmp:
            # on many machines /tmp is a RAM disk (512 MB here), and a
            # 2 GB upload plus parallel temp files filled it completely
            # ("No space left on device" mid-upload, which looked like a
            # freeze). The DB directory is real disk, with room.
            _db_dir = os.path.dirname(os.path.abspath(db_path)) or "."
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".log", delete=False, dir=_db_dir) as tmp:
                tmp_path = tmp.name
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    tmp.write(chunk)
                    remaining -= len(chunk)
                    _set_progress(bytes_received=length - remaining,
                                  elapsed_seconds=round(time.time() - started, 1))
            try:
                # Estimate total lines cheaply: average line length from
                # the first 200 lines, scaled to the file size. No second
                # full pass over the file, and the estimate is labelled
                # as an estimate in the UI. Falls back to unknown.
                est_total = 0
                try:
                    size = os.path.getsize(tmp_path)
                    with open(tmp_path, "rb") as f:
                        sample = [next(f) for _ in range(200)]
                    if sample:
                        avg = sum(len(l) for l in sample) / len(sample)
                        if avg > 0:
                            est_total = int(size / avg)
                except Exception:
                    est_total = 0
                _set_progress(estimated_total_events=est_total)

                def _on_progress(events, detections, stage, top=None):
                    elapsed = max(time.time() - started, 0.001)
                    eps = events / elapsed if stage == "reading" else 0
                    eta = None
                    if stage == "reading" and eps > 0 and est_total > events:
                        eta = (est_total - events) / eps
                    # SHORT stage texts (2026-11-01): the old sentences
                    # were long and repeated on every poll - removed,
                    # not kept. The progress line now carries the numbers
                    # (elapsed, ETA, CPU, RAM) instead of prose.
                    texts = {
                        "reading": "Step 2 of 4 - Reading",
                        "linking": "Step 3 of 4 - Linking",
                        "storing": "Step 4 of 4 - Saving",
                    }
                    _kw = dict(stage=stage, stage_text=texts.get(stage, stage),
                               events=events, detections=detections,
                               events_per_second=round(eps, 1),
                               elapsed_seconds=round(elapsed, 1),
                               eta_seconds=round(eta) if eta is not None else None)
                    if top is not None:
                        _kw["top_techniques"] = top
                    _set_progress(**_kw)

                # STUCK-STEP-1 FIX: receiving is DONE at this point, so
                # never leave the stage as "uploading" again. And never
                # wait silently for the global lock: a previous upload
                # may still be processing for tens of minutes, and the
                # old code sat inside `with LOCK:` with the text still
                # saying Step 1, which looked exactly like a freeze.
                # Now: try the lock once a second, and while waiting
                # say so plainly ("Queued") with the wait time.
                _queue_started = time.time()
                while not LOCK.acquire(blocking=False):
                    _wait = int(time.time() - _queue_started)
                    _set_progress(stage="queued",
                                  stage_text=(
                                      f"Queued - your file is safely saved "
                                      f"(100% received) and is waiting for "
                                      f"the previous upload to finish before "
                                      f"it starts. Waiting {_wait}s so far - "
                                      f"this is not stuck, it is just queued."),
                                  elapsed_seconds=round(time.time() - started, 1))
                    time.sleep(1)
                try:
                    _set_progress(stage="reading",
                                  stage_text="Step 2 of 4 - Reading")
                    try:
                        holder.con.close()
                    except Exception:
                        pass
                    # Speed, capped at 70% CPU so Windows stays usable:
                    # large uploads (over ~50k lines or 20 MB) run on
                    # parallel workers; small uploads stay single-core
                    # (spawning workers would cost more than it saves).
                    # Parallel uses byte-range chunks + global aggregate
                    # replay, so no line is ever dropped or double-counted.
                    import os as _os
                    from engine.parallel import cpu_friendly_workers as _workers
                    # User demand, revised (2026-11-01): 6 workers, not
                    # 8 - the 8-worker run jammed for 5 minutes on an
                    # HDD + 90% RAM machine (8 concurrent disk streams
                    # thrash a spinning disk and page memory). 6 is the
                    # compromise the user asked to try. Explicit
                    # request, capped by cores and by RAM.
                    _workers_n = _workers(6)
                    if (est_total > 50000 or length > 20 * 1024 * 1024) and _workers_n > 1:
                        _set_progress(stage_text=(
                            f"Step 2 of 4 - Reading ({_workers_n} workers)"))
                        summary = parallel_run(tmp_path, db_path, rules_dir,
                                               workers=_workers_n,
                                               on_progress=_on_progress)
                    else:
                        summary = cli_run(tmp_path, db_path, rules_dir,
                                          chunk_size=20000, on_progress=_on_progress)
                    holder.con = store.connect(db_path)
                finally:
                    LOCK.release()
                summary["filename"] = filename
                # TOTAL TIME (2026-11-01): elapsed was tracked all along
                # but the frontend never showed it - the done line just
                # said 'incidents are ready'. Now the total time is in
                # the done text itself, so it cannot be missed.
                from engine import sysstats as _ss2
                _total_s = round(time.time() - started, 1)
                _set_progress(stage="done",
                              stage_text=f"Done in {_ss2.fmt_duration(_total_s)} - incidents are ready below.",
                              events=summary.get("events", 0),
                              detections=summary.get("detections", 0),
                              elapsed_seconds=_total_s,
                              eta_seconds=0, done=True)
                return self._send_json(summary)
            except Exception as exc:  # keep the server alive, report the error
                _set_progress(stage="error", stage_text=f"Failed: {exc}", done=True, error=str(exc))
                # Bug found via the WinError 10053 report: holder.con was
                # closed before processing and never reconnected on
                # failure, so the dashboard stayed broken until a full
                # server restart. Reconnect to the existing DB file
                # (not fresh - never wipe data because an upload failed).
                try:
                    holder.con = store.connect(db_path)
                except Exception:
                    pass
                try:
                    return self._send_json({"error": str(exc)}, 500)
                except Exception:
                    # Client already gone (that is what WinError 10053
                    # means) - nothing left to send to, just stay alive.
                    return None
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
    # Lowest-spec, least-knowledge friendly: if the port is already
    # taken (another program, or an old ASK still running), do not
    # crash with a traceback - just try the next ports and say which
    # one actually worked, in plain words.
    server = None
    for try_port in range(port, port + 11):
        try:
            server = ThreadingHTTPServer((host, try_port), make_handler(holder, rules_dir, db_path, live_watch=watch))
            port = try_port
            break
        except OSError:
            continue
    if server is None:
        print(f"Sorry - ports {port} to {port + 10} are all busy. Close another program and try again.")
        return
    if port != 8001:
        print(f"Port 8001 was busy, so ASK is using port {port} instead.")
    print("Dashboard: http://%s:%d  (upload your .log file there)" % (host, port))
    print("API: /health, /incidents, /incidents/{id}/path, /incidents/{id}/report, /incidents/{id}/next")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")


def main():
    ap = argparse.ArgumentParser(description="Kill Chain - proper project")
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
                   help="1 = single-core (default). >1 = multi-core parallel, capped at 70% of cores so the system stays usable. 0 = 70% of cores, negative = all cores")
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
