"""Streaming log parser (FR-1).

Reads a log file line by line, in configurable batches. The whole file is
NEVER loaded into memory: ``iter_events`` yields one batch at a time and
the caller inserts / processes that batch before the next one is read.

Supported line formats (one event per line):
  * JSON-lines: {"time": "...", "host": "...", "user": "...", ...}
    Flexible key names are accepted (time/timestamp, host, user, ip,
    source/src, action, detail/message, stage, technique/mitre,
    severity/sev).
  * Pipe-separated, 9 fields (the browser demo's format):
        time|host|user|source|action|detail|stage|technique|severity
  * Pipe-separated, 10 fields (with IP):
        time|host|user|ip|source|action|detail|stage|technique|severity
  * CSV with the same 9/10 columns (header row is skipped).

An event is a plain dict. ``ts`` is epoch seconds (float) when the
timestamp parses, else None; linking uses ``ts`` when present and falls
back to arrival order otherwise.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

_TIME_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M")


def parse_timestamp(value) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _normalise(raw: Dict) -> Dict:
    def pick(*keys, default=""):
        for key in keys:
            if key in raw and raw[key] not in (None, ""):
                return raw[key]
        return default

    time_value = pick("time", "timestamp", "t", "datetime")
    return {
        "time": str(time_value),
        "ts": parse_timestamp(time_value),
        "host": str(pick("host", "hostname", "device")),
        "user": str(pick("user", "username", "account")),
        "ip": str(pick("ip", "src_ip", "source_ip")),
        "source": str(pick("source", "src", "system")),
        "action": str(pick("action", "event", "event_type")),
        "detail": str(pick("detail", "message", "description", "msg")),
        "stage_hint": str(pick("stage", "kill_chain_stage")),
        "technique_hint": str(pick("technique", "mitre", "technique_id")),
        "severity": str(pick("severity", "sev", "level", default="Medium")),
    }


_KV_RE = re.compile(r'([a-zA-Z0-9_\.\-]+)=(?:"([^"]*)"|(\S+))')


def _parse_kv(line: str) -> Optional[Dict]:
    pairs = _KV_RE.findall(line)
    if not pairs or len(pairs) < 3:
        return None
    raw = {}
    for k, v_quoted, v_unquoted in pairs:
        raw[k] = v_quoted if v_quoted != "" else v_unquoted
    if "date" in raw and "time" in raw:
        raw["time"] = f"{raw['date']}T{raw['time']}"
    if "devname" in raw and "host" not in raw:
        raw["host"] = raw["devname"]
    if "srcip" in raw and "ip" not in raw:
        raw["ip"] = raw["srcip"]
    if "logdesc" in raw and "action" not in raw:
        raw["action"] = raw["logdesc"]
    elif "action" in raw and "logdesc" in raw:
        raw["action"] = f"{raw['logdesc']} {raw['action']}"
    if "msg" in raw:
        raw["detail"] = raw["msg"]
    elif "attack" in raw:
        raw["detail"] = f"Attack {raw.get('attack')} on {raw.get('dstip', '')}"
        # Keep logdesc in the action: overwriting it here used to lose
        # the only keyword a rule could match on.
        raw["action"] = f"{raw.get('logdesc', '')} attack {raw.get('attack')}".strip()
    elif "virus" in raw:
        raw["detail"] = f"Virus {raw.get('virus')} url: {raw.get('url', '')}"
        raw["action"] = "malicious file virus"
    elif "catdesc" in raw:
        raw["detail"] = f"{raw.get('catdesc')} {raw.get('url', '')}"
        raw["action"] = raw.get("catdesc")
    return _normalise(raw)


def parse_line(line: str) -> Optional[Dict]:
    """Parse one log line. Returns None for blank / unparseable lines."""
    line = line.strip()
    if not line:
        return None
    if "=" in line and (" " in line or "\t" in line):
        kv = _parse_kv(line)
        if kv is not None:
            return kv
    if line.startswith("{"):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        return _normalise(data)
    if "|" in line:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 10:
            keys = ["time", "host", "user", "ip", "source", "action",
                    "detail", "stage", "technique", "severity"]
        elif len(parts) == 9:
            keys = ["time", "host", "user", "source", "action",
                    "detail", "stage", "technique", "severity"]
        else:
            return None
        return _normalise(dict(zip(keys, parts)))
    # CSV fallback (single row).
    try:
        row = next(csv.reader(io.StringIO(line)))
    except Exception:
        return None
    if not row or row[0].lower() in ("time", "timestamp"):
        return None
    if len(row) == 10:
        keys = ["time", "host", "user", "ip", "source", "action",
                "detail", "stage", "technique", "severity"]
    elif len(row) == 9:
        keys = ["time", "host", "user", "source", "action",
                "detail", "stage", "technique", "severity"]
    else:
        # Plain unstructured line: keep it as an event so keyword rules
        # can still flag it (e.g. "phishing email delivered"). Host/user
        # stay blank; benign plain lines are counted and dropped later.
        return _normalise({"action": line, "detail": line})
    return _normalise(dict(zip(keys, row)))


def iter_events(path: str, chunk_size: int = 5000) -> Iterator[List[Dict]]:
    """Yield batches of events from ``path`` without loading the file.

    Also yields nothing for a missing/empty file (caller reports counts).
    """
    batch: List[Dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_line(line)
            if event is None:
                continue
            batch.append(event)
            if len(batch) >= chunk_size:
                yield batch
                batch = []
    if batch:
        yield batch


def count_lines(path: str) -> int:
    """Streaming line count (used only for progress reporting)."""
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for _ in handle:
            total += 1
    return total
