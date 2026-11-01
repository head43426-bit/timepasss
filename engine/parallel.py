"""Multi-core parallel processing (Advanced tier: 30 GB, 1.3x).

Why processes, not threads: parsing and keyword detection are CPU-bound,
and Python threads share the GIL, so threads would not speed them up.
Processes each get their own core.

How it works, and how it stays correct:
  1. Split the log file into byte ranges, one per worker. Each range is
     adjusted to a line boundary, so every line is processed exactly once.
  2. Each worker runs the *simple* rules on its chunk only, and returns
     only detections (benign lines are counted and dropped, never returned).
     DuckDB is never touched by workers - only the main process writes.
  3. Aggregate rules (e.g. brute force: 50 failed logins, then a success)
     are NOT evaluated per worker, because a sequence split across two
     chunks would be missed. Workers return the trigger/success events,
     the main process replays them in global line order through one
     Detector, so aggregates are exactly the same as single-core.
  4. The main process merges all detections, sorts by time, links them
     into incidents, scores risk, and stores graph edges - exactly the
     same code path as the single-core CLI. Parallelism only speeds up
     parse + detect, the slow part.

Usage:
    python main.py run --log mylogs.log --db out.duckdb --workers 4
    python main.py run --log mylogs.log --db out.duckdb --workers 0   # all cores

On Windows/macOS this must run under ``if __name__ == "__main__"``
(which main.py already does) - otherwise workers would re-spawn the
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


def _init_worker(rules_dir: str, rule_files=None):
    # FIX (2026-11-01, found by full check): parallel_run passes
    # initargs=(rules_dir, rule_files), but this took only 1 arg,
    # so every parallel worker crashed with "takes 1 positional
    # argument but 2 were given" — breaking all >50k-line uploads
    # and POST /demo (small uploads use cli_run, so they hid it).
    # Workers must also respect the fixed rule pack, not load all.
    global _SIMPLE_DETECTOR, _AGG_RULES
    rules = load_rules(rules_dir, only_files=rule_files)
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
    """Worker: parse + detect its byte range, writing detections and
    aggregate candidates to DISK (temp JSONL files), never returning
    them to the parent. Returning them was the parallel RAM wall: the
    parent collected every detection from every worker before linking.
    Now the parent streams the temp files in chunk order, inserts in
    batches, and links with the streaming linker - memory stays flat
    whatever the file size. Chunk order is time order for a
    chronological log, which real logs are. Temp files live in the
    DB directory (passed in args), NOT system /tmp - /tmp is a RAM
    disk on many machines and a large run filled it completely."""
    import json as _json
    import tempfile
    path, start, end, tmpdir = args
    events = 0
    det_file = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl",
                                           delete=False, encoding="utf-8", dir=tmpdir)
    agg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl",
                                           delete=False, encoding="utf-8", dir=tmpdir)
    det_count = agg_count = 0
    with open(path, "rb") as f:
        f.seek(start)
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
            for det in _SIMPLE_DETECTOR.process(event):
                det_file.write(_json.dumps(det) + "\n")
                det_count += 1
            for rule in _AGG_RULES:
                if _match_conditions(event, rule.trigger) or _match_conditions(event, rule.success):
                    agg_file.write(_json.dumps({"pos": pos, "event": event}) + "\n")
                    agg_count += 1
                    break
    det_file.close()
    agg_file.close()
    return {"det_path": det_file.name, "agg_path": agg_file.name,
            "events": events, "detections": det_count, "agg_events": agg_count}


def _total_ram_gb() -> float:
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
            return _ms.ullTotalPhys / (1024 ** 3)
        with open("/proc/meminfo") as _f:
            for _line in _f:
                if _line.startswith("MemTotal:"):
                    return int(_line.split()[1]) / (1024 ** 2)
    except Exception:
        pass
    return 0


def cpu_friendly_workers(requested: int = 0) -> int:
    """How many workers to actually use. 70% of cores, never all of
    them, so the machine stays usable while ASK runs - the user asked
    for speed without the system freezing. On an 8-core machine that
    is 5 workers; on a 4-core machine, 2; on a 1-core machine, 1.
    Pass an explicit workers count to override, but it is still capped
    at 70% unless the caller really insists (workers < 0 means uncapped).
    MEMORY FIX (2026-11-01): also capped by RAM - on a 4 GB machine
    at most 2 workers. WORKERS FIX (2026-11-01, user demand): the
    upload path now explicitly asks for 8 workers, and an explicit
    request is honoured up to the machine's core count (not the 70%
    cap - that cap only applies to the default, requested == 0).
    On an 8 GB machine the RAM cap for an explicit request is 8
    workers; the user accepts that 8 workers use more RAM/CPU and
    the system may lag while they run, in exchange for speed."""
    total = os.cpu_count() or 1
    cap = max(1, int(total * 0.7))
    _ram = _total_ram_gb()
    if requested > 0:
        _ram_cap = 2 if (_ram and _ram <= 4) else 8
        return min(requested, total, _ram_cap)
    if _ram and _ram <= 4:
        cap = min(cap, 2)
    if requested < 0:
        return total
    if requested == 0:
        return cap
    return min(requested, cap)


def parallel_run(log_path: str, db_path: str, rules_dir: str, workers: int = 0,
                 topology_path: str = None, ground_truth_path: str = None,
                 on_progress=None, rule_files=None) -> dict:
    started = time.time()
    workers = cpu_friendly_workers(workers)
    con = store.connect(db_path, fresh=True)
    if topology_path:
        import json
        with open(topology_path, "r", encoding="utf-8") as handle:
            store.load_topology(con, json.load(handle))
    # PROGRESS/JAM FIX (2026-11-01): previously one chunk per worker,
    # so a 3.9M-line file showed "0 lines, 0 detections" for the
    # entire first ~974k-line chunk. Now the file is split into 16x
    # as many chunks as workers (96 chunks for 6 workers, ~40k lines
    # each for firex), while the pool still has only `workers`
    # processes - pool.map preserves input order, so chunk order,
    # aggregate replay and counts are unchanged, but progress now
    # updates after every small chunk, and a slow chunk blocks
    # progress for far less long. max_workers must stay `workers`,
    # NOT len(ranges), or dozens of processes would spawn at once.
    ranges = _byte_ranges(log_path, workers * 16)
    total_events = 0
    chunk_results = []
    with ProcessPoolExecutor(max_workers=workers,
                             initializer=_init_worker, initargs=(rules_dir, rule_files)) as pool:
        completed_workers = 0
        _tmpdir = os.path.dirname(os.path.abspath(db_path)) or "."
        for result in pool.map(_process_range, [(log_path, s, e, _tmpdir) for s, e in ranges]):
            completed_workers += 1
            total_events += result["events"]
            chunk_results.append(result)
            if on_progress:
                on_progress(total_events, sum(r["detections"] for r in chunk_results), "reading")
            print(f"  ... Worker chunk {completed_workers}/{len(ranges)} complete ({result['events']:,} events, {result['detections']} detections)", flush=True)
    # Global aggregate pass, in original file order (chunk order, then
    # byte position inside the chunk). Aggregate detections are few by
    # definition (only emitted after threshold + success), so holding
    # them sorted is cheap; simple detections are never held.
    import json as _json
    agg_detections = []
    total_agg = sum(r["agg_events"] for r in chunk_results)
    if total_agg:
        print(f"  ... Processing {total_agg:,} aggregate candidates...", flush=True)
        agg_detector = Detector(load_rules(rules_dir, only_files=rule_files))
        agg_detector.simple = []
        for result in chunk_results:
            with open(result["agg_path"], encoding="utf-8") as fh:
                for line in fh:
                    row = _json.loads(line)
                    agg_detections.extend(agg_detector.process(row["event"]))
        agg_detections.sort(key=lambda d: (d.get("ts") is None, d.get("ts") or 0))
        print(f"  ... Finished aggregate pass ({len(agg_detections)} aggregate detections)", flush=True)
    # Stream simple detections in chunk order, merging aggregate
    # detections by time as they are reached, inserting in batches
    # and linking with the streaming linker. Nothing here holds the
    # whole detection list.
    from engine import protect as _protect
    _rules = load_rules(rules_dir, only_files=rule_files)
    _tell_map = {}
    for _r in _rules:
        _phrases = []
        for _k in ("any_contains", "action_contains", "detail_contains"):
            _v = _r.match.get(_k)
            if _v:
                _phrases = [str(_v)] if isinstance(_v, str) else [str(x) for x in _v]
                break
        _tell_map[_r.id] = _phrases[0] if _phrases else (_r.description or "")
    _top_counter = {}

    def _top_list():
        _items = sorted(_top_counter.items(), key=lambda kv: -kv[1]["count"])[:5]
        return [_protect.live_tell(v["technique_id"], v["technique_name"],
                                   v["stage"], v["count"], v["tell"])
                for _, v in _items]

    def _count_top(dets):
        for _d in dets:
            _key = _d.get("technique_id", "")
            if _key:
                _e = _top_counter.setdefault(_key, {
                    "technique_id": _key,
                    "technique_name": _d.get("technique_name", ""),
                    "stage": _d.get("kill_chain_stage", ""),
                    "tell": _tell_map.get(_d.get("rule_id", ""), ""),
                    "count": 0})
                _e["count"] += _d.get("merged_alerts", 1)

    linker = graph_mod.StreamingLinker()
    next_id = 1
    detection_count = 0
    incident_count = 0
    agg_idx = 0

    def _flush(dets):
        nonlocal incident_count
        if not dets:
            return
        # Linker hands back compact tuples (memory fix) - expand to
        # the minimal dicts risk/graph need before anything else.
        dets = graph_mod.expand_compact(dets)
        incident_count += 1
        first = dets[0]
        times = [d.get("time", "") for d in dets if d.get("time", "")]
        con.execute("BEGIN TRANSACTION")
        store.insert_incident(con, {
            "id": incident_count,
            "title": (f"{first.get('technique_name') or first.get('technique_id', '')} path on {first.get('ip') or first['host']}"
                       if dets else f"Incident {incident_count}"),
            "start_time": times[0] if times else "", "end_time": times[-1] if times else "",
            "hosts": sorted({d["host"] for d in dets if d["host"]}),
            "users": sorted({d["user"] for d in dets if d["user"]}),
            "risk_score": graph_mod.risk_score(dets),
            "merged_alerts": sum(d.get("merged_alerts", 1) for d in dets),
            "detection_count": len(dets),
            "detection_ids": [d["_id"] for d in dets],
            "edges": graph_mod.graph_edges(dets),
        })
        con.execute("COMMIT")

    def _feed(det):
        for finished in linker.feed(det):
            _flush(finished)

    def _insert_and_feed(batch):
        """Insert one batch (ids assigned contiguously at insert time),
        then feed its detections in order, merging aggregate detections
        whose time has arrived - each aggregate is inserted as its own
        row first, so incident_detections never points at a missing id."""
        nonlocal next_id, detection_count, agg_idx
        if not batch:
            return
        for i, d in enumerate(batch):
            d["_id"] = next_id + i
        con.execute("BEGIN TRANSACTION")
        store.insert_detections(con, batch, batch[0]["_id"])
        con.execute("COMMIT")
        next_id += len(batch)
        detection_count += len(batch)
        _count_top(batch)
        if on_progress:
            on_progress(total_events, detection_count, "reading", _top_list())
        for det in batch:
            while agg_idx < len(agg_detections) and (agg_detections[agg_idx].get("ts") or 0) <= (det.get("ts") or 0):
                agg = agg_detections[agg_idx]
                agg["_id"] = next_id
                con.execute("BEGIN TRANSACTION")
                store.insert_detections(con, [agg], next_id)
                con.execute("COMMIT")
                next_id += 1
                detection_count += 1
                _feed(agg)
                agg_idx += 1
            _feed(det)

    for result in chunk_results:
        batch = []
        with open(result["det_path"], encoding="utf-8") as fh:
            for line in fh:
                batch.append(_json.loads(line))
                if len(batch) >= 5000:
                    _insert_and_feed(batch)
                    batch = []
        _insert_and_feed(batch)
    # Any aggregate detections after the last simple detection.
    while agg_idx < len(agg_detections):
        agg = agg_detections[agg_idx]
        agg["_id"] = next_id
        con.execute("BEGIN TRANSACTION")
        store.insert_detections(con, [agg], next_id)
        con.execute("COMMIT")
        next_id += 1
        detection_count += 1
        _feed(agg)
        agg_idx += 1
    for finished in linker.finish():
        _flush(finished)
    for result in chunk_results:
        for key in ("det_path", "agg_path"):
            try:
                os.unlink(result[key])
            except OSError:
                pass
    con.close()
    elapsed = time.time() - started
    summary = {
        "events": total_events, "detections": detection_count,
        "incidents": incident_count, "seconds": round(elapsed, 2),
        "events_per_second": round(total_events / elapsed, 1) if elapsed else 0,
        "workers": workers, "chunks": len(ranges),
        "peak_rss_mb": peak_rss_mb(),
    }
    if ground_truth_path:
        summary["evaluation"] = evaluate_fn(db_path, ground_truth_path)
    return summary
