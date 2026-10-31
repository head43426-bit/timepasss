"""Severity normalisation, intrinsic technique priority, and Low tier.

Three bugs lived here, in different files, with the same effect:

1. Missing severity defaulted to Medium everywhere (parser, detector,
   store). A firewall log with no severity field therefore scored as
   Medium (base 40), so nothing ever qualified for Low (0-39).
2. Lowercase severity ("critical", "high") missed every dictionary
   lookup (keys are Title Case) and fell back to the Medium weight
   (10) - a Critical line was demoted to Medium.
3. A firewall syslog tag decided severity, even for techniques that
   are Critical by nature. A Mimikatz LSASS dump on a "notice" line
   scored Low, because the tag said so.

Fixes, in one place so they cannot drift apart again:

* normalize_severity(): any casing / synonym -> Title Case, or ""
  when unknown. Synonyms include the Fortinet level names
  (emergency/alert -> Critical, error -> High, warning -> Medium,
  notice/information/debug -> Low) and the user's .title() idea:
  a value whose title-cased form is a known severity is accepted.
* detection_severity(): the severity of one detection. It is the
  HIGHER of (a) the log line's own (normalised) severity and (b) the
  technique's intrinsic severity - except when the action was
  blocked/denied/dropped, in which case the attack did not succeed
  and the log line's severity stands (so a blocked notice event
  stays Low). When neither is known, the answer is Low, not Medium:
  a matched single probe / scan with no severity information is a
  Low, and the risk formula's Low tier (base 10, ceiling 39) then
  actually gets used.
* Weight lookups must use normalize_severity() first and fall back
  to the Low weight (3), never the Medium weight (10).
"""

from __future__ import annotations

import re

SEVERITY_WEIGHTS = {"Critical": 40, "High": 25, "Medium": 10, "Low": 3}

_SYNONYMS = {
    "critical": "Critical", "crit": "Critical", "emergency": "Critical",
    "alert": "Critical", "fatal": "Critical",
    "high": "High", "error": "High", "err": "High",
    "medium": "Medium", "moderate": "Medium", "warning": "Medium",
    "warn": "Medium",
    "low": "Low", "notice": "Low", "information": "Low",
    "informational": "Low", "info": "Low", "debug": "Low",
}

# Intrinsic priority by MITRE technique prefix. Only techniques that
# are serious by nature are listed - recon / scanning techniques are
# deliberately NOT here, so a single probe stays Low. A technique in
# this map upgrades a detection, it never downgrades one: the final
# severity is max(event severity, intrinsic severity), unless the
# action was blocked (see detection_severity).
_INTRINSIC_CRITICAL = ("T1003", "T1048", "T1485", "T1486", "T1490")
_INTRINSIC_HIGH = ("T1558", "T1071", "T1021", "T1059", "T1204",
                   "T1505", "T1136", "T1053", "T1070", "T1566")

_BLOCKED_RE = re.compile(r"\b(blocked|block|deny|denied|denying|drop|dropped|reject|rejected)\b")


def normalize_severity(value) -> str:
    """Return 'Critical'|'High'|'Medium'|'Low', or '' when unknown."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered in _SYNONYMS:
        return _SYNONYMS[lowered]
    titled = text.title()
    if titled in SEVERITY_WEIGHTS:
        return titled
    return ""


def weight_of(severity) -> int:
    """Weight for a severity string of any casing; unknown -> Low (3)."""
    return SEVERITY_WEIGHTS.get(normalize_severity(severity), 3)


def intrinsic_severity(technique_id: str) -> str:
    """Critical/High for techniques serious by nature, else ''."""
    tid = (technique_id or "").strip().upper()
    if not tid:
        return ""
    if tid.startswith(_INTRINSIC_CRITICAL):
        return "Critical"
    if tid.startswith(_INTRINSIC_HIGH):
        return "High"
    return ""


def detection_severity(event_severity, technique_id: str,
                       action: str = "", detail: str = "") -> str:
    """Final severity for one detection (see module docstring)."""
    event = normalize_severity(event_severity)
    combined = f"{action or ''} {detail or ''}".lower()
    if _BLOCKED_RE.search(combined):
        # Blocked / denied / dropped: the attack did not succeed, so
        # the log line's severity stands and intrinsic priority does
        # not upgrade it. Missing severity on a blocked event is Low.
        return event or "Low"
    intrinsic = intrinsic_severity(technique_id)
    if not event and not intrinsic:
        return "Low"
    if not event:
        return intrinsic
    if not intrinsic:
        return event
    return event if weight_of(event) >= weight_of(intrinsic) else intrinsic
