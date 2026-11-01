"""Pipeline CLI (one command, end to end):

  python3 -m engine.cli --log mylogs.log --db out.duckdb \\
      --rules rules --topology topology.json \\
      --ground-truth truth.json

Steps: stream-parse + detect in batches -> DuckDB -> link into
incidents -> risk-score -> store graph edges -> print processing time,
peak RSS (resource.getrusage, the process's own peak), counts, and
evaluation vs ground truth when --ground-truth is given.

Memory: only one batch of raw events, the detector's aggregate counters,
and the detection list (detections are far fewer than raw lines, and
are flushed to DuckDB per batch) are held at once. Raw benign events
are counted and dropped, never stored. For the full 15/30/50 GB tiers
the same code path runs; see README's scale section for what is
implemented vs what is a documented next step (multiprocessing workers).
"""

from __future__ import annotations

import argparse
import json
try:
    import resource
except ImportError:
    resource = None
import sys
import time
from typing import List

from . import graph as graph_mod
from . import store
from .evaluate import evaluate as evaluate_fn
from .parser import iter_events
from .rules import Detector, load_rules


def peak_rss_mb() -> float:
    # ru_maxrss is KiB on Linux, bytes on macOS.
    if resource is not None:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(value / 1024.0, 1) if sys.platform != "darwin" else round(value / 1e6, 1)
    
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        # Same 64-bit handle truncation bug as sysstats: without
        # HANDLE restype, GetCurrentProcess() is truncated to
        # c_int and GetProcessMemoryInfo fails, giving peak 0 MB
        # on Windows. Explicit restype/argtypes fix it.
        ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD]
        ctypes.windll.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return round(counters.PeakWorkingSetSize / (1024.0 * 1024.0), 1)
    except Exception:
        pass
    return 0.0




def run(log_path: str, db_path: str, rules_dir: str, topology_path: str = None,
        chunk_size: int = 5000, ground_truth_path: str = None,
        on_progress=None, fresh: bool = True, rule_files=None) -> dict:
    """on_progress(events, detections, stage) is called after each batch
    (stage "reading") and again for "linking" / "storing", so a caller
    (e.g. the dashboard) can show plain-words progress and an ETA.

    fresh=True (default, uploads) wipes the DB first. fresh=False
    (Load Sample append, 2026-11-01) keeps every existing row and
    continues both id counters past the current maxima, so new
    detections and incidents never collide with existing ones.
    The linker itself is fresh per run, so appended detections link
    among themselves into NEW incidents - existing incident rows,
    their detection lists and their graphs are never rewritten."""
    started = time.time()
    rules = load_rules(rules_dir, only_files=rule_files)
    detector = Detector(rules)
    con = store.connect(db_path, fresh=fresh)
    if topology_path:
        with open(topology_path, "r", encoding="utf-8") as handle:
            store.load_topology(con, json.load(handle))
    total_lines = 0
    detection_count = 0
    if fresh:
        next_id = 1
        incident_count = 0
    else:
        try:
            _row = con.execute("SELECT MAX(id) FROM detections").fetchone()
            next_id = (_row[0] or 0) + 1
            _row = con.execute("SELECT MAX(id) FROM incidents").fetchone()
            incident_count = _row[0] or 0
        except Exception:
            next_id = 1
            incident_count = 0
    linker = graph_mod.StreamingLinker()
    # Live tells: counts + the giveaway phrase per technique, for the
    # dynamic slab shown while the upload runs. Updated per batch, so
    # the slab changes as new attacks are found, not just at the end.
    from collections import Counter as _Counter
    from . import protect as _protect
    _tell_map = {}
    for _r in rules:
        _phrases = []
        for _k in ("any_contains", "action_contains", "detail_contains"):
            _v = _r.match.get(_k)
            if _v:
                _phrases = [str(_v)] if isinstance(_v, str) else [str(x) for x in _v]
                break
        _tell_map[_r.id] = _phrases[0] if _phrases else (_r.description or "")
    _top_counter: Dict = {}

    def _top_list():
        _items = sorted(_top_counter.items(), key=lambda kv: -kv[1]["count"])[:5]
        return [_protect.live_tell(v["technique_id"], v["technique_name"],
                                   v["stage"], v["count"], v["tell"])
                for _, v in _items]

    def _flush(dets):
        nonlocal incident_count
        if not dets:
            return
        # Linker hands back compact tuples (memory fix) - expand to
        # the minimal dicts risk/graph need before anything else.
        dets = graph_mod.expand_compact(dets)
        incident_count += 1
        hosts = sorted({d["host"] for d in dets if d["host"]})
        users = sorted({d["user"] for d in dets if d["user"]})
        first = dets[0]
        times = [d.get("time", "") for d in dets if d.get("time", "")]
        record = {
            "id": incident_count,
            "title": (f"{first.get('technique_name') or first.get('technique_id', '')} "
                       f"path on {first.get('ip') or first['host']}" if dets else f"Incident {incident_count}"),
            "start_time": times[0] if times else "", "end_time": times[-1] if times else "",
            "hosts": hosts, "users": users,
            "risk_score": graph_mod.risk_score(dets),
            "merged_alerts": sum(d.get("merged_alerts", 1) for d in dets),
            "detection_count": len(dets),
            "detection_ids": [d["_id"] for d in dets],
            "edges": graph_mod.graph_edges(dets),
        }
        con.execute("BEGIN TRANSACTION")
        store.insert_incident(con, record)
        con.execute("COMMIT")

    for batch in iter_events(log_path, chunk_size=chunk_size):
        total_lines += len(batch)
        batch_detections = []
        for event in batch:
            batch_detections.extend(detector.process(event))
        if batch_detections:
            # Stamp the DB id onto each detection BEFORE linking, so a
            # flushed incident can point at its rows without any
            # all-detections list or id() map.
            for i, d in enumerate(batch_detections):
                d["_id"] = next_id + i
            con.execute("BEGIN TRANSACTION")
            next_id = store.insert_detections(con, batch_detections, next_id)
            con.execute("COMMIT")
            detection_count += len(batch_detections)
            for det in batch_detections:
                _key = det.get("technique_id", "")
                if _key:
                    _entry = _top_counter.setdefault(_key, {
                        "technique_id": _key,
                        "technique_name": det.get("technique_name", ""),
                        "stage": det.get("kill_chain_stage", ""),
                        "tell": _tell_map.get(det.get("rule_id", ""), ""),
                        "count": 0})
                    _entry["count"] += det.get("merged_alerts", 1)
                for finished in linker.feed(det):
                    _flush(finished)
        if on_progress:
            on_progress(total_lines, detection_count, "reading", _top_list())
        if total_lines % 100000 < chunk_size:
            print(f"  ... {total_lines} events, {detection_count} detections, "
                  f"peak RSS {peak_rss_mb()} MB", flush=True)
    if on_progress:
        on_progress(total_lines, detection_count, "linking", _top_list())
    for finished in linker.finish():
        _flush(finished)
    if on_progress:
        on_progress(total_lines, detection_count, "storing", _top_list())
    con.close()
    elapsed = time.time() - started
    summary = {
        "events": total_lines, "detections": detection_count,
        "incidents": incident_count, "seconds": round(elapsed, 2),
        "peak_rss_mb": peak_rss_mb(),
        "events_per_second": round(total_lines / elapsed, 1) if elapsed else 0,
    }
    if ground_truth_path:
        summary["evaluation"] = evaluate_fn(db_path, ground_truth_path)
    return summary


def run_append(log_path: str, db_path: str, rules_dir: str,
               chunk_size: int = 5000, on_progress=None) -> dict:
    """Append a log to an existing DB: same pipeline as run(), but
    fresh=False, so nothing already stored is wiped or rewritten."""
    return run(log_path, db_path, rules_dir, chunk_size=chunk_size,
               on_progress=on_progress, fresh=False)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Kill Chain engine pipeline")
    parser.add_argument("--log", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--rules", default="rules")
    parser.add_argument("--topology")
    parser.add_argument("--chunk-size", type=int, default=5000)
    parser.add_argument("--ground-truth")
    args = parser.parse_args(argv)
    summary = run(args.log, args.db, args.rules, args.topology,
                  args.chunk_size, args.ground_truth)
    print(f"Events processed: {summary['events']}")
    print(f"Detections: {summary['detections']}")
    print(f"Incidents: {summary['incidents']}")
    print(f"Processing time: {summary['seconds']}s "
          f"({summary['events_per_second']} events/sec)")
    print(f"Peak RSS: {summary['peak_rss_mb']} MB")
    if "evaluation" in summary:
        ev = summary["evaluation"]
        print(f"Evaluation: detection {ev['detection']:.1f}%, "
              f"correct labels {ev['correct_labels']:.1f}%, "
              f"attack path {ev['attack_path']:.1f}%, "
              f"false alarms {ev['false_alarms']:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
