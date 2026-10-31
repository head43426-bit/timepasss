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
    """Short brief, exactly 6 lines (2026-11-01, user demand: short
    and simple, 5-6 lines only). The old brief repeated the whole
    technique list with first/last times, the next-host list with
    reasons, the blast-radius breakdown AND the full protection list,
    so the Sarvam card ran to a full page - and the protection list
    is already shown in full in the centre column's 'Protect' section,
    so repeating it here added nothing. Each line below is one fact;
    the <pre> in the dashboard keeps the line breaks, and Sarvam
    Translate (the only thing Sarvam does in this project - it does
    not write the brief) translates this short text as-is.
    """
    timeline = incident.get("timeline", [])
    hosts = [h for h in incident.get("hosts", []) if h]
    users = [u for u in incident.get("users", []) if u]

    def _short_list(items, limit=5):
        if not items:
            return None
        if len(items) <= limit:
            return ", ".join(items)
        return ", ".join(items[:limit]) + f" and {len(items) - limit} more"

    host_text = _short_list(hosts) or "unknown hosts"
    user_text = _short_list(users) or "no user account recorded in the logs"
    # Fall back to the timeline's first/last non-empty time when the
    # stored start/end is blank (old DBs, or a last detection with no
    # time) - never print "ended on ." again.
    _times = [d.get("time", "") for d in timeline if d.get("time", "")]
    _start = incident.get("start_time") or (_times[0] if _times else "an unknown time")
    _end = incident.get("end_time") or (_times[-1] if _times else "an unknown time")
    # Techniques, in first-seen order, with counts. Large incidents:
    # counts come from DuckDB's GROUP BY in timeline_summary, not
    # from the 400-row sample - the sample's counts would be wrong.
    _techs = []
    if incident.get("timeline_summary"):
        for s in incident["timeline_summary"]:
            _techs.append(f"{s['technique_name']} ({s['technique_id']}) x{s['count']:,}")
    elif timeline:
        _seen = {}
        for d in timeline:
            key = (d.get("technique_id", ""), d.get("technique_name", ""))
            _seen[key] = _seen.get(key, 0) + 1
        for (tid, name), count in _seen.items():
            _techs.append(f"{name or tid} ({tid}) x{count:,}")
    tech_text = _short_list(_techs, limit=8) or "no techniques recorded"
    if next_list:
        _nxt_hosts = [n["host"] for n in next_list]
        _total = incident.get("next_frontier_total", len(next_list))
        _extra = f" (and {_total - len(next_list)} more like this)" if _total > len(next_list) else ""
        next_text = f"Watch next: {_short_list(_nxt_hosts, limit=5)}{_extra}."
    else:
        next_text = "No frontier host to watch: no new target is guessed."
    _prot = incident.get("protections", [])
    if _prot:
        first_action = _prot[0].get("action", "") or _prot[0].get("technique_name", "")
        do_text = (f"Do this first: {first_action} "
                   f"Full list: see Protect - what to do now, in the centre column.")
    else:
        do_text = "This report describes the attack only; it does not block or stop it."
    lines = [
        f"Attack on {host_text}, {_start} to {_end}. Risk {incident.get('risk_score', 0)}/100.",
        f"Users involved: {user_text}.",
        f"Techniques, in order: {tech_text}.",
        f"Scale: {incident.get('detection_count', 0):,} detections from {incident.get('merged_alerts', 0):,} raw alerts.",
        next_text,
        do_text,
    ]
    return "\n".join(lines)


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
