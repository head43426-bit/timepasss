"""Format sniffing: read the first few lines and decide what the
file is, before processing it.

This is NOT magic learning. It does not invent a field mapping
for a format it has never seen — an Apple JSON shape with
`eventMessage` / `sender` keys will still not map to detail/source
until those aliases are added to parser._normalise. What sniffing
does, honestly, is:

  * decide the dominant line format from the first 200 lines
    (JSON-lines, 10-field pipe, 9-field pipe, CSV, Fortinet KV,
    generic KV, plain text, or unknown),
  * report the JSON top-level keys it actually saw, so a new
    format is visible instead of silently dropping fields,
  * warn when the dominant format is unknown or when JSON keys
    are present that the parser does not map — so the user knows
    *before* a 100 MB run that coverage will be weak, instead of
    finding out from an empty incident list afterwards.

The per-line parser (engine/parser.py parse_line) already tries
KV -> JSON -> pipe -> CSV -> plain for every line, so a mixed
file still works. Sniffing is the file-level decision on top of
that: what this file mostly is, and what it contains.
"""
from __future__ import annotations

import json
from collections import Counter

# Keys parser._normalise actually maps (lowercased — sniffing
# compares case-insensitively, because Apple uses eventMessage
# and Windows uses TargetUserName). Anything else in a JSON
# object is ignored by the parser today — sniffing reports it.
# Keep this in sync with parser._normalise pick lists; if they
# drift, the worst case is a spurious warning, never a blocked
# run — sniffing never changes parsing.
KNOWN_JSON_KEYS = {
    "time", "timestamp", "t", "datetime", "@timestamp", "event_time",
    "log_time", "date_time", "timestamp_ms", "eventtime",
    "hostname", "host_name", "machine_name", "host", "device", "computer",
    "machine", "endpoint", "device_name",
    "user", "username", "account", "user_name", "principal", "actor",
    "subject", "targetusername", "target_user_name", "user_id",
    "ip", "src_ip", "source_ip", "src_addr", "source_address",
    "client_ip", "remote_ip", "ip_address", "srcip",
    "dst_ip", "dstip", "destination_ip", "dst_addr",
    "destination_address", "dest_ip", "dest_addr", "target_ip",
    "source", "src", "system", "sender", "process", "subsystem",
    "category", "service", "component", "facility", "log_source",
    "vendor", "subtype", "type",
    "action", "event", "event_type", "event_name", "eventname",
    "activity", "operation", "verb", "logdesc",
    "detail", "message", "description", "msg", "eventmessage",
    "event_message", "log_message", "text", "summary", "reason",
    "stage", "kill_chain_stage", "phase", "killchain",
    "technique", "mitre", "technique_id", "mitre_id", "attack_id",
    "tactic",
    "severity", "sev", "level", "priority", "criticality",
    "date", "tz", "devname", "attack", "virus", "catdesc",
    "url", "dstport", "dstcountry", "proto", "sessionid",
    # Metadata keys that are not normalised fields but are not
    # warning-worthy either (e.g. Windows event code).
    "code", "event_code", "id", "version", "ipaddress",
    # Container identifiers, e.g. ECS host.name — not a field
    # itself, but not warning-worthy.
    "name",
}


import re as _re

_SYSLOG_RE = _re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+\S+\s+[^\s:]+(?:\[\d+\])?:\s*.+$")


def _line_format(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    if _SYSLOG_RE.match(s):
        return "syslog"
    if s.startswith("{"):
        try:
            data = json.loads(s)
        except Exception:
            return "unknown"
        return "json" if isinstance(data, dict) else "unknown"
    if "=" in s and (" " in s or "\t" in s):
        # Fortinet KV lines have date=/time=/devname=/srcip= etc.
        if "srcip=" in s or "devname=" in s or "logdesc=" in s:
            return "fortinet_kv"
        return "kv"
    if "|" in s:
        n = len(s.split("|"))
        if n == 10:
            return "pipe_10"
        if n == 9:
            return "pipe_9"
        return "unknown"
    if "," in s:
        n = len(s.split(","))
        if n in (9, 10):
            return "csv"
        return "unknown"
    return "plain"


def sniff_lines(lines, max_lines: int = 200) -> dict:
    """Sniff up to max_lines non-blank lines. Returns a dict with:
    format, confidence (0-1, share of the dominant format),
    counts, json_keys (sorted top-level keys seen in JSON lines),
    unmapped_json_keys (JSON keys the parser does not map today),
    warning ('' if none, else a plain-language warning)."""
    counts = Counter()
    json_keys = Counter()
    total = 0
    _os_text = []
    for raw in lines:
        if total >= max_lines:
            break
        s = raw.strip() if isinstance(raw, str) else ""
        if not s:
            continue
        _os_text.append(s)
        total += 1
        fmt = _line_format(s)
        counts[fmt] += 1
        if fmt == "json":
            try:
                data = json.loads(s)
            except Exception:
                data = {}
            # Collect leaf keys recursively (nested Windows/ECS
            # JSON nests fields) — container keys (dict/list values)
            # are not counted as unmapped, only leaf keys are.
            def _collect(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, (dict, list)):
                            _collect(v)
                        else:
                            json_keys[k] += 1
                elif isinstance(obj, list):
                    for v in obj:
                        _collect(v)
            if isinstance(data, dict):
                _collect(data)
    if total == 0:
        return {"format": "empty", "confidence": 0.0, "counts": {},
                "json_keys": [], "unmapped_json_keys": [], "warning": "File is empty.",
                "os_hint": ""}
    # Ignore 'unknown' lines when picking the dominant known format,
    # but keep them in the counts so confidence is honest.
    known = [(k, v) for k, v in counts.most_common() if k != "unknown"]
    if not known:
        fmt = "unknown"
        confidence = counts.get("unknown", 0) / total
    else:
        fmt, n = known[0]
        confidence = n / total
    unmapped = sorted(k for k in json_keys if k.lower() not in KNOWN_JSON_KEYS)
    warning = ""
    if fmt == "unknown":
        warning = ("Format not recognised from the first lines — lines "
                   "will be treated as plain text and only keyword rules "
                   "can fire. Share a few sample lines to add this format.")
    elif unmapped:
        warning = ("JSON keys seen that the parser does not map yet: "
                   + ", ".join(unmapped)
                   + ". Those fields will be ignored until their aliases "
                   "are added to the parser.")
    elif confidence < 0.8:
        warning = ("Mixed formats in the first lines — the parser handles "
                   "mixed lines one by one, so this is not an error, but "
                   "coverage may vary by line.")
    return {"format": fmt, "confidence": round(confidence, 2),
            "counts": dict(counts),
            "json_keys": sorted(json_keys),
            "unmapped_json_keys": unmapped,
            "warning": warning,
            "os_hint": detect_os(_os_text)}


APPLE_SIGNALS = ("osascript", "launchagent", "launchdaemon", "gatekeeper",
                 "keychain", "com.apple", "eventmessage")


def detect_os(lines) -> str:
    """Very small OS hint from the first lines: 'macos' only if
    Apple signals appear, else ''. This is a hint for pack
    selection, not a guarantee — mixed files return '' and fall
    back to loading all packs."""
    text = "\n".join(str(l) for l in lines).lower()
    if any(s in text for s in APPLE_SIGNALS):
        return "macos"
    return ""


def sniff_file(path: str, max_lines: int = 200) -> dict:
    """Sniff the first max_lines lines of a file on disk."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for line in f:
                lines.append(line)
                if len(lines) >= max_lines:
                    break
    except OSError as exc:
        return {"format": "error", "confidence": 0.0, "counts": {},
                "json_keys": [], "unmapped_json_keys": [],
                "warning": f"Could not read file for sniffing: {exc}",
                "os_hint": ""}
    return sniff_lines(lines, max_lines=max_lines)
