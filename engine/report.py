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


def english_report(incident: Dict, next_list: List[Dict]) -> str:
    timeline = incident.get("timeline", [])
    hosts = [h for h in incident.get("hosts", []) if h]
    users = [u for u in incident.get("users", []) if u]
    host_text = ", ".join(hosts) if hosts else "unknown hosts"
    user_text = (f"with user accounts {', '.join(users)}" if users
                 else "with no user account recorded in the logs")
    # Fall back to the timeline's first/last non-empty time when the
    # stored start/end is blank (old DBs, or a last detection with no
    # time) — never print "ended on ." again.
    _times = [d.get("time", "") for d in timeline if d.get("time", "")]
    _start = incident.get("start_time") or (_times[0] if _times else "an unknown time")
    _end = incident.get("end_time") or (_times[-1] if _times else "an unknown time")
    lines = [
        f"This incident began on {_start} "
        f"and ended on {_end}. "
        f"It involved {host_text}, {user_text}.",
    ]
    if incident.get("timeline_sampled") and incident.get("timeline_summary"):
        # Large incident: counts come from DuckDB's GROUP BY, not from
        # the 400-row sample — the sample's counts would be wrong.
        summary = "; ".join(
            f"{s['technique_name']} ({s['kill_chain_stage']}, {s['technique_id']})"
            f" — {s['count']:,} times, first {s['first']}, last {s['last']}"
            for s in incident["timeline_summary"])
        lines.append(
            f"What the attacker did, in order (distinct techniques, "
            f"first-seen order): {summary}.")
        lines.append(
            f"The remaining steps repeat these same techniques — "
            f"{incident.get('detection_count', 0):,} steps in total are not listed one by one, "
            f"because that list is unreadable and adds no new information.")
    elif timeline:
        # Group repeated steps: a 118,043-step flood of the same two
        # techniques must never be printed step by step. Summarise by
        # technique, in first-seen order, with counts and time ranges.
        # Small incidents (50 steps or fewer) still list every step.
        if len(timeline) <= 50:
            steps = "; ".join(
                f"{d.get('time', '')}: {d.get('technique_name', d.get('technique_id', ''))} "
                f"({d.get('kill_chain_stage', '')}) on {d.get('host', '')}"
                for d in timeline)
            lines.append(f"What the attacker did, in order: {steps}.")
        else:
            groups = {}
            order = []
            for d in timeline:
                key = (d.get("kill_chain_stage", ""), d.get("technique_id", ""),
                       d.get("technique_name", ""))
                if key not in groups:
                    groups[key] = {"count": 0, "first": d.get("time", ""),
                                   "last": d.get("time", "")}
                    order.append(key)
                groups[key]["count"] += 1
                if d.get("time", ""):
                    if not groups[key]["first"]:
                        groups[key]["first"] = d.get("time", "")
                    groups[key]["last"] = d.get("time", "")
            summary = "; ".join(
                f"{name} ({stage}, {tid}) — {groups[k]['count']:,} times, "
                f"first {groups[k]['first']}, last {groups[k]['last']}"
                for (stage, tid, name) in order
                for k in [(stage, tid, name)])
            lines.append(
                f"What the attacker did, in order (distinct techniques, "
                f"first-seen order): {summary}.")
            lines.append(
                f"The remaining steps repeat these same techniques — "
                f"{len(timeline):,} steps in total are not listed one by one, "
                f"because that list is unreadable and adds no new information.")
    else:
        lines.append("No detections were recorded for this incident.")
    lines.append(
        f"The incident merged {incident.get('merged_alerts', 0):,} raw alerts "
        f"into {incident.get('detection_count', 0):,} detections, "
        f"with a risk score of {incident.get('risk_score', 0)} out of 100.")
    if next_list:
        nxt = "; ".join(f"{n['host']} ({n['reason']})" for n in next_list)
        lines.append(f"What the attacker could reach next: {nxt}.")
    else:
        lines.append(
            "No next system could be identified from the supplied topology, "
            "so no next target is guessed.")
    # Stage look-ahead: always available, even with no topology.
    _next_stages = incident.get("next_stages", [])
    if _next_stages:
        _st = "; ".join(s["stage"] for s in _next_stages)
        lines.append(
            f"Looking ahead in the kill chain, the next stages to watch "
            f"for are: {_st}. These are stages, not guessed hosts.")
    if incident.get("blast_radius") is not None:
        lines.append(
            f"Blast radius from the supplied topology: "
            f"{incident['blast_radius']} out of 100.")
    _prot = incident.get("protections", [])
    if _prot:
        _p = "; ".join(f"{p['technique_id']}: {p['action']}" for p in _prot)
        lines.append(
            f"Protect — what to do now, per technique found (ASK itself "
            f"cannot block an attack; it has no agent on your hosts, so "
            f"these are the actions for you to take): {_p}.")
    lines.append(
        "This report describes the attack only; it does not block or stop it.")
    return " ".join(lines)


def _hindi_template(incident: Dict, next_list: List[Dict]) -> str:
    hosts = ", ".join(incident.get("hosts", [])) or "अज्ञात सिस्टम"
    nxt = ("; ".join(n["host"] for n in next_list)
           if next_list else "कोई अगला लक्ष्य नहीं मिला")
    return (
        f"यह घटना {incident.get('start_time', '')} को {hosts} पर शुरू हुई। "
        f"इसमें {incident.get('detection_count', 0)} पहचान और "
        f"{incident.get('merged_alerts', 0)} कच्चे अलर्ट शामिल हैं। "
        f"हमलावर आगे इन सिस्टम तक पहुँच सकता है: {nxt}। "
        f"यह एक टेम्पलेट रिपोर्ट है, असली अनुवाद नहीं।")


def hindi_report(incident: Dict, next_list: List[Dict]) -> Dict:
    """Return {hindi, source, warning}. Source is 'sarvam' only when the
    Sarvam API actually returned a translation."""
    english = english_report(incident, next_list)
    key = os.environ.get("SARVAM_API_KEY", "").strip()
    if not key:
        return {"hindi": _hindi_template(incident, next_list),
                "source": "mock_template",
                "warning": ("No SARVAM_API_KEY is set, so this is a Hindi "
                            "template built from the incident fields, NOT a "
                            "real Sarvam translation.")}
    try:
        payload = json.dumps({
            "input": english,
            "source_language_code": "en-IN",
            "target_language_code": "hi-IN",
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
            return {"hindi": translated, "source": "sarvam", "warning": ""}
        raise ValueError("Sarvam response had no translated_text")
    except Exception as exc:  # network/auth/format failure -> labelled fallback
        return {"hindi": _hindi_template(incident, next_list),
                "source": "mock_template",
                "warning": (f"Sarvam translation failed ({exc}); returning a "
                            f"Hindi template instead, NOT a real translation.")}
