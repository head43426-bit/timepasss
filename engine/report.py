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
    hosts = ", ".join(incident.get("hosts", [])) or "unknown hosts"
    users = ", ".join(incident.get("users", [])) or "unknown accounts"
    lines = [
        f"This incident began on {incident.get('start_time', 'an unknown time')} "
        f"and involved {hosts} and accounts {users}.",
    ]
    if timeline:
        steps = "; ".join(
            f"{d.get('time', '')}: {d.get('technique_name', d.get('technique_id', ''))} "
            f"({d.get('kill_chain_stage', '')}) on {d.get('host', '')}"
            for d in timeline)
        lines.append(f"What the attacker did, in order: {steps}.")
    else:
        lines.append("No detections were recorded for this incident.")
    lines.append(
        f"The incident merged {incident.get('merged_alerts', 0)} raw alerts "
        f"into {incident.get('detection_count', 0)} detections, "
        f"with a risk score of {incident.get('risk_score', 0)} out of 100.")
    if next_list:
        nxt = "; ".join(f"{n['host']} ({n['reason']})" for n in next_list)
        lines.append(f"What the attacker could reach next: {nxt}.")
    else:
        lines.append(
            "No next system could be identified from the supplied topology, "
            "so no next target is guessed.")
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
