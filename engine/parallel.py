"""Multi-core parallel processing (Advanced tier: 30 GB, 1.3x).

Why processes, not threads: parsing and keyword detection are CPU-bound,
and Python threads share the GIL, so threads would not speed them up.
Processes each get their own core.

How it works, and how it stays correct:
  1. Split the log file into byte ranges, one per worker. Each range is
     adjusted to a line boundary, so every line is processed exactly once.
  2. Each worker runs the *simple* rules on its chunk only, and returns
     only detections (benign lines are counted and dropped, never returned).
     DuckDB is never touched by workers — only the main process writes.
  3. Aggregate rules (e.g. brute force: 50 failed logins, then a success)
     are NOT evaluated per worker, because a sequence split across two
     chunks would be missed. Workers return the trigger/success events,
     the main process replays them in global line order through one
     Detector, so aggregates are exactly the same as single-core.
  4. The main process merges all detections, sorts by time, links them
     into incidents, scores risk, and stores graph edges — exactly the
     same code path as the single-core CLI. Parallelism only speeds up
     parse + detect, the slow part.

Usage:
    python main.py run --log mylogs.log --db out.duckdb --workers 4
    python main.py run --log mylogs.log --db out.duckdb --workers 0   # all cores

On Windows/macOS this must run under ``if __name__ == "__main__"``
(which main.py already does) — otherwise workers would re-spawn the
parent process.
"""
from __future__ import annotations

import os
from .cli import peak_rss_mb
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from typing import List, Tuple

from . import graph as graph_mod
from . import store
from .evaluate import evaluate as evaluate_fn
from .parser import parse_line
from .rules import Detector, _match_conditions, load_rules

_SIMPLE_DETECTOR = None
_AGG_RULES = []


def _init_worker(rules_dir: str):
    global _SIMPLE_DETECTOR, _AGG_RULES
    rules = load_rules(rules_dir)
    _SIMPLE_DETECTOR = Detector([r for r in rules if r.rule_type == "simple"])
    _AGG_RULES = [r for r in rules if r.rule_type == "aggregate"]


def _byte_ranges(path: str, workers: int) -> List[Tuple[int, int]]:
    size = os.path.getsize(path)
    if size == 0 or workers <= 1:
        return [(0, size)]
    chunk = (size + workers - 1) // workers
    ranges = []
    with open(path, "rb") as f:
        start = 0
        for _ in range(workers):
            if start >= size:
                break
            end = min(size, start + chunk)
            if end < size:
                f.seek(end)
                f.readline()  # advance to the next line boundary
                end = f.tell()
            ranges.append((start, end))
            start = end
    return ranges


def _process_range(args) -> dict:
    path, start, end = args
    detections, agg_events, events = [], [], 0
    seq = start  # approximate global order key; exact order is by byte offset
    with open(path, "rb") as f:
        f.seek(start)
        # No line is discarded here: _byte_ranges already aligned every
        # range start to a line boundary. Discarding here dropped the
        # first line of every chunk after the first (a real bug, caught
        # in testing: 10 lines became 7 with 4 workers).
        while True:
            pos = f.tell()
            if pos >= end:
                break
            raw = f.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace")
            event = parse_line(line)
            if event is None:
                continue
            events += 1
            # Simple rules, in chunk order, stateful only within this chunk
            # (simple rules carry no cross-event state, so this is exact).
            detections.extend(_SIMPLE_DETECTOR.process(event))
            # Aggregate candidates: replayed globally in the main process.
            for rule in _AGG_RULES:
                if _match_conditions(event, rule.trigger) or _match_conditions(event, rule.success):
                    agg_events.append((pos, event))
                    break
            seq += 1
    # Tag simple detections with their byte position for final ordering.
    for d in detections:
        d["_pos"] = pos
    return {"detections": detections, "agg_events": agg_events, "events": events}


def parallel_run(log_path: str, db_path: str, rules_dir: str, workers: int = 0,
                 topology_path: str = None, ground_truth_path: str = None) -> dict:
    started = time.time()
    if workers <= 0:
        workers = os.cpu_count() or 1
    con = store.connect(db_path, fresh=True)
    if topology_path:
        import json
        with open(topology_path, "r", encoding="utf-8") as handle:
            store.load_topology(con, json.load(handle))
    ranges = _byte_ranges(log_path, workers)
    total_events = 0
    simple_detections, agg_events = [], []
    with ProcessPoolExecutor(max_workers=len(ranges),
                             initializer=_init_worker, initargs=(rules_dir,)) as pool:
        completed_workers = 0
        for result in pool.map(_process_range, [(log_path, s, e) for s, e in ranges]):
            completed_workers += 1
            total_events += result["events"]
            simple_detections.extend(result["detections"])
            agg_events.extend(result["agg_events"])
            print(f"  ... Worker chunk {completed_workers}/{len(ranges)} complete ({result['events']:,} events, {len(result['detections'])} detections)", flush=True)
    # Global aggregate pass, in original file order.
    agg_detections = []
    if agg_events:
        print(f"  ... Processing {len(agg_events):,} aggregate candidates...", flush=True)
        agg_events.sort(key=lambda x: x[0])
        agg_detector = Detector(load_rules(rules_dir))
        agg_detector.simple = []
        for _, event in agg_events:
            agg_detections.extend(agg_detector.process(event))
        print(f"  ... Finished aggregate pass ({len(agg_detections)} aggregate detections)", flush=True)
    all_detections = simple_detections + agg_detections
    all_detections.sort(key=lambda d: (d.get("ts") is None, d.get("ts") or 0))
    for d in all_detections:
        d.pop("_pos", None)
    if all_detections:
        print(f"  ... Inserting {len(all_detections):,} detections into DuckDB...", flush=True)
        con.execute("BEGIN TRANSACTION")
        store.insert_detections(con, all_detections, 1)
        con.execute("COMMIT")
    det_id_map = {id(d): idx for idx, d in enumerate(all_detections, 1)}
    print(f"  ... Linking {len(all_detections):,} detections into incident paths...", flush=True)
    incidents = graph_mod.link_detections(all_detections)
    print(f"  ... Built {len(incidents):,} incidents. Storing into DuckDB...", flush=True)
    stored = []
    for idx, dets in enumerate(incidents, start=1):
        hosts = sorted({d["host"] for d in dets})
        users = sorted({d["user"] for d in dets})
        first, last = dets[0], dets[-1]
        stored.append({
            "id": idx,
            "title": (f"{first.get('technique_name') or first.get('technique_id', '')} path on {first['host']}"
                       if dets else f"Incident {idx}"),
            "start_time": first.get("time", ""), "end_time": last.get("time", ""),
            "hosts": hosts, "users": users,
            "risk_score": graph_mod.risk_score(dets),
            "merged_alerts": sum(d.get("merged_alerts", 1) for d in dets),
            "detection_count": len(dets),
            "detection_ids": [det_id_map[id(d)] for d in dets],
            "edges": graph_mod.graph_edges(dets),
        })
    con.execute("BEGIN TRANSACTION")
    for record in stored:
        store.insert_incident(con, record)
    con.execute("COMMIT")
    con.close()
    elapsed = time.time() - started
    summary = {
        "events": total_events, "detections": len(all_detections),
        "incidents": len(stored), "seconds": round(elapsed, 2),
        "events_per_second": round(total_events / elapsed, 1) if elapsed else 0,
        "workers": len(ranges), "chunks": len(ranges),
        "peak_rss_mb": peak_rss_mb(),
    }
    if ground_truth_path:
        summary["evaluation"] = evaluate_fn(db_path, ground_truth_path)
    return summary
