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

from .severity import normalize_severity

_TIME_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M",
                 "%b %d %H:%M:%S", "%b %d %Y %H:%M:%S")


def epoch_from_eventtime(value) -> Optional[float]:
    """Fortinet eventtime is epoch in nanoseconds (19 digits), sometimes
    microseconds or milliseconds. Normalise to seconds by magnitude, so
    a real UTM line gives an exact timestamp instead of a date+time
    string that is off by the timezone offset."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n > 1e17:  # nanoseconds
        return n / 1e9
    if n > 1e14:  # microseconds
        return n / 1e6
    if n > 1e11:  # milliseconds
        return n / 1e3
    if n > 1e9:  # seconds already
        return n
    return None


def _normalise_epoch(value: float) -> Optional[float]:
    """Epoch in s/ms/us/ns, by magnitude - same rule as
    epoch_from_eventtime, applied to ANY timestamp field, not
    just Fortinet eventtime."""
    if value > 1e17:
        return value / 1e9
    if value > 1e14:
        return value / 1e6
    if value > 1e11:
        return value / 1e3
    if value > 1e9:
        return value
    if value > 0:
        return value
    return None


def parse_timestamp(value) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return _normalise_epoch(float(value))
    text = str(value).strip()
    try:
        return _normalise_epoch(float(text))
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
            dt = datetime.strptime(text, fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.now(timezone.utc).year)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _deep_pick(raw: Dict, *keys):
    """Pick a field by any of its names, case-insensitively, and
    searching nested dicts/lists too. Top-level exact match wins,
    then case-insensitive top-level, then recursive search."""
    wanted = {k.lower() for k in keys}
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            v = raw[key]
            if isinstance(v, (str, int, float)):
                return v
            if isinstance(v, dict) and v.get("name") not in (None, ""):
                return v["name"]
    for k, v in raw.items():
        if k.lower() in wanted and v not in (None, ""):
            if isinstance(v, (str, int, float)):
                return v
            if isinstance(v, dict) and v.get("name") not in (None, ""):
                return v["name"]
    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in wanted and v not in (None, "") and isinstance(v, (str, int, float)):
                    return v
            for v in obj.values():
                r = _walk(v)
                if r is not None:
                    return r
        elif isinstance(obj, list):
            for v in obj:
                r = _walk(v)
                if r is not None:
                    return r
        return None
    r = _walk(raw)
    return r if r is not None else ""


def _normalise(raw: Dict) -> Dict:
    def pick(*keys, default=""):
        v = _deep_pick(raw, *keys)
        return v if v != "" else default

    time_value = pick("time", "timestamp", "t", "datetime", "@timestamp",
                      "event_time", "log_time", "date_time", "timestamp_ms",
                      "eventtime")
    # eventtime wins for ts when present: it is the device's own epoch,
    # exact to the nanosecond, and immune to the tz parsing below.
    ts = epoch_from_eventtime(raw.get("eventtime")) if "eventtime" in raw else None
    if ts is None:
        ts = parse_timestamp(time_value)
    _action = pick("action", "event", "event_type", "event_name", "eventName",
                   "activity", "operation", "verb")
    _detail = pick("detail", "message", "description", "msg", "eventMessage",
                   "event_message", "log_message", "text", "summary", "reason")
    if not _action and _detail:
        _action = _detail
    return {
        "time": str(time_value),
        "ts": ts,
        "hostname": str(pick("hostname", "host_name", "machine_name", default="")),
        "host": str(pick("host", "hostname", "device", "computer", "machine",
                         "endpoint", "device_name", "host_name")),
        "user": str(pick("user", "username", "account", "user_name", "principal",
                         "actor", "subject", "targetusername", "target_user_name",
                         "user_id")),
        "ip": str(pick("ip", "src_ip", "source_ip", "src_addr", "source_address",
                       "client_ip", "remote_ip", "ip_address", "ipaddress",
                       "srcip")),
        # Destination IP is the real host-to-host target in firewall
        # logs (srcip -> dstip). It used to be dropped, which is why
        # every Fortinet detection collapsed onto the firewall host.
        "dst_ip": str(pick("dst_ip", "dstip", "destination_ip", "dst_addr",
                           "destination_address", "dest_ip", "dest_addr",
                           "target_ip", "dstip")),
        "source": str(pick("source", "src", "system", "sender", "process",
                           "subsystem", "category", "service", "component",
                           "facility", "log_source", "vendor")),
        "action": str(_action),
        "detail": str(_detail),
        "stage_hint": str(pick("stage", "kill_chain_stage", "phase", "killchain")),
        "technique_hint": str(pick("technique", "mitre", "technique_id",
                                   "mitre_id", "attack_id", "tactic")),
        # Severity is normalised here (any casing / synonym -> Title
        # Case) and left "" when the line carries none, instead of
        # defaulting to Medium. The detector fills it in (intrinsic
        # technique priority, else Low) - see engine/severity.py.
        "severity": normalize_severity(pick("severity", "sev", "level", "priority",
                                            "criticality")),
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
        # tz="+0530" -> "+05:30", so fromisoformat gives the true UTC
        # epoch. Without this, every Fortinet time was 5.5 hours off
        # for IST logs (08:48 IST was stored as 08:48 UTC).
        if "tz" in raw:
            _tz = raw["tz"].strip()
            if len(_tz) == 5 and _tz[0] in "+-":
                raw["time"] = raw["time"] + f"{_tz[:3]}:{_tz[3:]}"
    if "devname" in raw and "host" not in raw:
        raw["host"] = raw["devname"]
    if "srcip" in raw and "ip" not in raw:
        raw["ip"] = raw["srcip"]
    # Fortinet level -> severity, so a critical UTM line does not
    # score as a generic Medium in the risk formula.
    _level_map = {"emergency": "Critical", "alert": "Critical",
                  "critical": "Critical", "error": "High",
                  "warning": "Medium", "notice": "Low",
                  "information": "Low", "debug": "Low"}
    if "level" in raw and "severity" not in raw:
        raw["severity"] = _level_map.get(raw["level"].lower(), "Medium")
    # Real UTM context: subtype/service are the source, not an empty
    # string, so rules and the graph can tell DNS from web from IPS.
    if "subtype" in raw and "source" not in raw:
        raw["source"] = raw["subtype"]
    elif "type" in raw and "source" not in raw:
        raw["source"] = raw["type"]
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
    else:
        # Generic UTM line (the DNS sample): action="pass" alone tells
        # the detector nothing, and detail was empty, so hostname,
        # country, port and protocol were all lost. Build a detail
        # that keeps them, without inventing an attack: a benign DNS
        # pass to nytimes.com still produces NO detection, but a
        # suspicious hostname now has something to match on.
        _parts = []
        for _k in ("subtype", "service", "hostname", "url", "dstip",
                   "dstport", "dstcountry", "proto", "sessionid"):
            if raw.get(_k):
                _parts.append(f"{_k}={raw[_k]}")
        if _parts:
            raw["detail"] = " ".join(_parts)
            if "action" in raw:
                raw["action"] = f"{raw.get('subtype', '')} {raw.get('service', '')} {raw['action']}".strip()
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
    _syslog = re.match(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
        r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
        r"\s+(\S+)\s+([^\s:]+)(?:\[\d+\])?:\s*(.*)$", line)
    if _syslog:
        _ts_str, _host, _proc, _msg = _syslog.groups()
        return _normalise({"time": _ts_str, "host": _host, "source": _proc,
                           "action": _msg, "detail": _msg})
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
