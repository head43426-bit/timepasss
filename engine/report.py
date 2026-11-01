"""Incident reports (B-2): plain-English narrative, always local, plus
Hindi via the Sarvam API as a pluggable, key-gated adapter.

English: generated locally from the incident's timeline + next-reach
list. No network call, ever.

Hindi: only attempted when SARVAM_API_KEY is set in the environment.
On success the response is labelled source="sarvam". On any failure
(no key, network error, unexpected response) the function returns a
short Hindi TEMPLATE built from the same structured fields, labelled
source="mock_template" with an explicit warning that no real Sarvam
translation happened. A mock is never presented as a real translation.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Dict, List

SARVAM_URL = "https://api.sarvam.ai/translate"


_KILL_CHAIN_ORDER = ["Reconnaissance", "Initial Access", "Execution",
                     "Persistence", "Privilege Escalation", "Defense Evasion",
                     "Credential Access", "Discovery", "Lateral Movement",
                     "Collection", "Command and Control", "Exfiltration",
                     "Impact"]


def _risk_tier(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s >= 90:
        return "Critical"
    if s >= 70:
        return "High"
    if s >= 40:
        return "Medium"
    return "Low"


def _parse_time(text):
    if not text:
        return None
    try:
        from datetime import datetime
        t = str(text).strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        return datetime.fromisoformat(t)
    except Exception:
        return None


def _fmt_duration(start, end):
    s, e = _parse_time(start), _parse_time(end)
    if not s or not e or e < s:
        return None
    secs = int((e - s).total_seconds())
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs2 = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if mins:
        parts.append(f"{mins} minute{'s' if mins != 1 else ''}")
    if not parts:
        parts.append(f"{secs2} second{'s' if secs2 != 1 else ''}")
    return ", ".join(parts)


def _short_list(items, limit=5):
    items = [str(x) for x in items if x]
    if not items:
        return None
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def _tech_rows(incident):
    """Techniques in first-seen order, with stage, count, first, last.

    For large incidents the counts and first/last times come from
    DuckDB's GROUP BY in timeline_summary (the full count, not the
    400-row dashboard sample). For small incidents they are derived
    from the full timeline, in the same order.
    """
    rows = []
    if incident.get("timeline_summary"):
        for s in incident["timeline_summary"]:
            rows.append({
                "technique_id": s.get("technique_id", ""),
                "technique_name": s.get("technique_name", ""),
                "kill_chain_stage": s.get("kill_chain_stage", ""),
                "count": s.get("count", 0),
                "first": s.get("first", "") or "",
                "last": s.get("last", "") or "",
            })
        return rows
    seen, order = {}, []
    for d in incident.get("timeline", []):
        key = (d.get("technique_id", ""), d.get("technique_name", ""))
        if key not in seen:
            seen[key] = {"technique_id": key[0], "technique_name": key[1],
                         "kill_chain_stage": "", "count": 0, "first": "", "last": ""}
            order.append(key)
        r = seen[key]
        r["count"] += 1
        t = d.get("time", "") or ""
        if t:
            if not r["first"]:
                r["first"] = t
            r["last"] = t
        if not r["kill_chain_stage"] and d.get("kill_chain_stage"):
            r["kill_chain_stage"] = d["kill_chain_stage"]
    return [seen[k] for k in order]


def _path_endpoints(incident):
    """Distinct sources and destinations from kind='path' edges only.

    User->source and source->technique edges are not movement, so
    they are excluded. If there are no path edges, both lists are
    empty and the caller must not invent movement from the hosts list.
    """
    edges = (incident.get("graph") or {}).get("edges", []) or []
    srcs, dsts = [], []
    for e in edges:
        if e.get("kind") != "path":
            continue
        for lst, val in ((srcs, e.get("from", "")), (dsts, e.get("to", ""))):
            if val and val not in lst:
                lst.append(val)
    return srcs, dsts


def english_report(incident: Dict, next_list: List[Dict]) -> str:
    """Full informative brief (2026-11-01, user demand: make the
    report more informative - this replaces the 6-line short brief).

    Sections, all from fields already on the incident (no new DB
    queries, no invented hosts, techniques or times):
      1. Header: title, risk + tier, time + duration.
      2. What happened: stages reached, in order.
      3. Techniques: every distinct technique, with stage, count
         and first/last time (full GROUP BY counts for large
         incidents, not the dashboard sample).
      4. Hosts and movement: sources and destinations from path
         edges only, plus users - with a plain explanation when no
         user was recorded, instead of implying no account was used.
      5. Scale: detections, raw alerts, rate per hour when the
         times parse.
      6. Blast radius: score, basis and breakdown when present.
      7. What the attacker could reach next: frontier hosts (with
         the reason each one is watched) and next kill-chain stages.
         Frontier hosts are destinations already contacted, not
         guessed hosts, and the total is stated, not just the 10
         shown.
      8. What to do now: the FULL protection list, not just the
         first action - the centre column shows the same list, but
         a printed report must stand on its own.
      9. Limits: what this report does not prove.
    The old "Attack on <hosts>" line is gone: the hosts list can
    hold the logging device (e.g. a firewall name), which is not
    the victim. The title and the path-edge endpoints are used
    instead, and when there is no movement the hosts are labelled
    neutrally as "hosts recorded", never as "attacked".
    The <pre> in the dashboard keeps the line breaks, and Sarvam
    Translate (the only thing Sarvam does - it does not write the
    brief) translates this text as-is.
    """
    incident = incident or {}
    timeline = incident.get("timeline", []) or []
    hosts = [h for h in incident.get("hosts", []) if h]
    users = [u for u in incident.get("users", []) if u]
    _times = [d.get("time", "") for d in timeline if d.get("time", "")]
    _start = incident.get("start_time") or (_times[0] if _times else "an unknown time")
    _end = incident.get("end_time") or (_times[-1] if _times else "an unknown time")
    _duration = _fmt_duration(incident.get("start_time"), incident.get("end_time"))
    _risk = incident.get("risk_score", 0)
    _tier = _risk_tier(_risk)
    _title = incident.get("title", "") or f"Incident #{incident.get('id', '')}"
    lines = []
    lines.append(f"ASK Incident #{incident.get('id', '')} - {_title}")
    lines.append(f"Risk: {_risk}/100" + (f" ({_tier})" if _tier else "") + ".")
    lines.append(f"Time: {_start} to {_end}" + (f" ({_duration})" if _duration else "") + ".")

    # 2. What happened: stages reached, in first-seen order.
    rows = _tech_rows(incident)
    stages = []
    for r in rows:
        st = r.get("kill_chain_stage", "")
        if st and st not in stages:
            stages.append(st)
    lines.append("")
    lines.append("1. What happened")
    if rows and stages:
        lines.append(f"This incident links {incident.get('detection_count', 0):,} detections into one attack chain, "
                     f"from {rows[0].get('technique_name') or rows[0].get('technique_id', '')} "
                     f"to {rows[-1].get('technique_name') or rows[-1].get('technique_id', '')}, "
                     f"across {len(stages)} kill-chain stage{'s' if len(stages) != 1 else ''}: {', '.join(stages)}.")
    elif rows:
        lines.append(f"This incident links {incident.get('detection_count', 0):,} detections into one attack chain.")
    else:
        lines.append("No techniques were recorded for this incident.")

    # 3. Techniques, in order.
    lines.append("")
    lines.append("2. Techniques, in order")
    if rows:
        for r in rows:
            name = r.get("technique_name") or r.get("technique_id", "")
            tid = r.get("technique_id", "")
            part = f"- {name} ({tid})" if tid and name != tid else f"- {name}"
            if r.get("kill_chain_stage"):
                part += f" - {r['kill_chain_stage']}"
            part += f" - {r.get('count', 0):,} detection{'s' if r.get('count', 0) != 1 else ''}"
            if r.get("first") and r.get("last") and r["first"] != r["last"]:
                part += f" - {r['first']} to {r['last']}"
            elif r.get("first"):
                part += f" - at {r['first']}"
            lines.append(part)
    else:
        lines.append("- No techniques recorded.")

    # 4. Hosts and movement.
    srcs, dsts = _path_endpoints(incident)
    lines.append("")
    lines.append("3. Hosts and movement")
    if srcs:
        lines.append(f"Sources seen: {_short_list(srcs, limit=10)} ({len(srcs)} distinct).")
    if dsts:
        lines.append(f"Destinations contacted: {_short_list(dsts, limit=10)} ({len(dsts)} distinct).")
    if not srcs and not dsts:
        if hosts:
            lines.append(f"No host-to-host movement was recorded in the graph for this incident. Hosts recorded in the incident record: {_short_list(hosts, limit=10)}.")
        else:
            lines.append("No host-to-host movement was recorded in the graph for this incident.")
    if users:
        lines.append(f"Users involved: {_short_list(users, limit=10)}.")
    else:
        lines.append("Users involved: no user account was recorded in the logs for this incident, so user attribution is not available from this data. That does not mean no account was used - it means these log lines carry no user field.")

    # 5. Scale.
    lines.append("")
    lines.append("4. Scale")
    lines.append(f"{incident.get('detection_count', 0):,} detections from {incident.get('merged_alerts', 0):,} raw alerts.")
    if _duration and _parse_time(incident.get("start_time")) and _parse_time(incident.get("end_time")):
        _hrs = ((_parse_time(incident["end_time"]) - _parse_time(incident["start_time"])).total_seconds() / 3600.0)
        if _hrs > 0:
            lines.append(f"About {round(incident.get('detection_count', 0) / _hrs):,} detections per hour over that period.")
    if incident.get("timeline_sampled"):
        lines.append(f"Note: the dashboard shows a 400-row sample (first and last 200 of {incident.get('timeline_total', 0):,} steps) for this large incident, but the technique counts above come from a full database count, not the sample.")

    # 6. Blast radius.
    lines.append("")
    lines.append("5. Blast radius")
    if incident.get("blast_radius") is not None:
        _br = incident.get("blast_breakdown") or {}
        _basis = incident.get("blast_basis", "") or ""
        part = f"{incident['blast_radius']}/100"
        if _basis:
            part += f" ({_basis})"
        if _br:
            part += (f" - Reach {_br.get('reach')}/25 from {_br.get('dst_count')} destinations, "
                     f"Spread {_br.get('spread')}/25 from {_br.get('src_count')} sources, "
                     f"Depth {_br.get('depth')}/25 from {_br.get('stage_count')} stages, "
                     f"Severity {_br.get('severity')}/25, worst severity {_br.get('worst_severity')}")
        lines.append(part + ".")
        lines.append("This is a score from what the logs show, not a count of compromised hosts.")
    else:
        lines.append("Blast radius was not calculated for this incident.")

    # 7. What the attacker could reach next.
    lines.append("")
    lines.append("6. What the attacker could reach next")
    _nxt = next_list or []
    _total = incident.get("next_frontier_total", len(_nxt))
    if _nxt:
        lines.append(f"Frontier hosts to watch: {_total} in total" + (f" (first {len(_nxt)} shown below)" if _total > len(_nxt) else "") + ". These are destinations the attacker has already contacted but has not yet used as a stepping stone - they are not guessed hosts.")
        for n in _nxt:
            part = f"- {n.get('host', '')} - watch score {n.get('confidence', 0)}/100"
            if n.get("reason"):
                part += f" - {n['reason']}"
            if n.get("block"):
                part += f". {n['block']}"
            lines.append(part)
        if incident.get("next_basis"):
            lines.append(f"Basis: {incident['next_basis']}.")
    else:
        lines.append("No frontier host to watch: no new target is guessed.")
    _stages_next = incident.get("next_stages", []) or []
    if _stages_next:
        lines.append("Next kill-chain stages to watch for:")
        for s in _stages_next:
            part = f"- {s.get('stage', '')}"
            if s.get("reason"):
                part += f" - {s['reason']}"
            if s.get("block"):
                part += f". {s['block']}"
            lines.append(part)

    # 8. What to do now: full list.
    lines.append("")
    lines.append("7. What to do now")
    _prot = incident.get("protections", []) or []
    if _prot:
        for i, p in enumerate(_prot, 1):
            _name = p.get("technique_name", "") or p.get("technique_id", "")
            _tid = p.get("technique_id", "")
            _label = f"{_tid} {_name}".strip() if _tid else _name
            lines.append(f"{i}. {_label}: {p.get('action', '')}")
        lines.append("ASK does not block, isolate or change anything itself - these are actions for you, your firewall or your endpoint tool to take.")
    else:
        lines.append("This report describes the attack only; it does not block or stop it.")

    # 9. Limits.
    lines.append("")
    lines.append("8. Limits of this report")
    lines.append("- Detections are rule matches on log lines. A contacted destination is a host or domain the attacker reached out to, not proof that host was taken over.")
    lines.append("- Risk tier is set by the worst severity, the stages and techniques reached, and scale - not by detection count alone, so a large low-severity flood does not automatically score 100.")
    lines.append("- If a technique, host or time is not in the logs, this report does not invent it; anything not shown here was not recorded.")
    return "\n".join(lines)


def _hindi_template(incident: Dict, next_list: List[Dict]) -> str:
    hosts = incident.get("title", "") or ", ".join(incident.get("hosts", [])) or "अज्ञात सिस्टम"
    nxt = ("; ".join(n["host"] for n in next_list)
           if next_list else "कोई अगला लक्ष्य नहीं मिला")
    return (
        f"यह घटना {incident.get('start_time', '')} को {hosts} पर शुरू हुई। "
        f"इसमें {incident.get('detection_count', 0)} पहचान और "
        f"{incident.get('merged_alerts', 0)} कच्चे अलर्ट शामिल हैं। "
        f"हमलावर आगे इन सिस्टम तक पहुँच सकता है: {nxt}। "
        f"यह एक टेम्पलेट रिपोर्ट है, असली अनुवाद नहीं।")


LANG_CODES = {"en": "en-IN", "hi": "hi-IN", "ta": "ta-IN", "te": "te-IN", "ml": "ml-IN"}
LANG_NAMES = {"en": "English", "hi": "Hindi", "ta": "Tamil", "te": "Telugu", "ml": "Malayalam"}


def translate_report(incident: Dict, next_list: List[Dict], lang: str) -> Dict:
    """Return {text, source, warning} for the requested language.

    English is generated locally, never translated. Other languages go
    through Sarvam Translate only when SARVAM_API_KEY is set. Without
    a key, or if Sarvam fails, the English report is returned with an
    explicit warning that it was NOT translated -- a fake Tamil /
    Telugu / Malayalam template is never invented, because this
    codebase only ever had a real Hindi template.
    """
    lang = (lang or "en").lower()
    if lang not in LANG_CODES:
        lang = "en"
    english = english_report(incident, next_list)
    if lang == "en":
        return {"text": english, "source": "local", "warning": ""}
    key = os.environ.get("SARVAM_API_KEY", "").strip()
    if not key:
        return {"text": english, "source": "not_translated",
                "warning": (f"No SARVAM_API_KEY is set, so this is the English "
                            f"report, NOT a {LANG_NAMES[lang]} translation. "
                            f"Add the key to a private .env file (see README) "
                            f"and restart the server for a real translation.")}
    try:
        payload = json.dumps({
            "input": english,
            "source_language_code": "en-IN",
            "target_language_code": LANG_CODES[lang],
            "mode": "formal",
        }).encode("utf-8")
        request = urllib.request.Request(
            SARVAM_URL, data=payload,
            headers={"Content-Type": "application/json",
                     "api-subscription-key": key}, method="POST")
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        translated = data.get("translated_text") or ""
        if translated:
            return {"text": translated, "source": "sarvam", "warning": ""}
        raise ValueError("Sarvam response had no translated_text")
    except Exception as exc:  # network/auth/format failure -> labelled fallback
        return {"text": english, "source": "not_translated",
                "warning": (f"Sarvam translation failed ({exc}); showing the "
                            f"English report instead, NOT a {LANG_NAMES[lang]} "
                            f"translation.")}


def hindi_report(incident: Dict, next_list: List[Dict]) -> Dict:
    """Backward-compatible wrapper: {hindi, source, warning} for Hindi.

    Kept because GET /incidents/{id}/report?hindi=1 already returns
    that shape. New code should use translate_report(..., "hi").
    """
    out = translate_report(incident, next_list, "hi")
    if out["source"] == "sarvam":
        return {"hindi": out["text"], "source": "sarvam", "warning": ""}
    # Old callers expect a Hindi template when Sarvam is unavailable.
    return {"hindi": _hindi_template(incident, next_list),
            "source": "mock_template",
            "warning": out["warning"] or ("No SARVAM_API_KEY is set, so this is a Hindi "
                            "template built from the incident fields, NOT a "
                            "real Sarvam translation.")}
