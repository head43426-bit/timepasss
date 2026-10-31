"""Sigma-style detection rules (FR-2, FR-3, B-4).

Rules are DATA, not code: they live in ``rules/*.yml`` and are loaded by
``load_rules``. Adding a rule means editing/adding a YAML file, never
editing this module. A rule has:

    id, name, technique_id, technique_name, tactic, kill_chain_stage,
    confidence (0-100), priority (higher wins when several rules match
    one event), description, and either:
      * match: {any_contains: [...], action_contains: [...],
                detail_contains: [...], action_equals: ...,
                severity_in: [...], source_contains: [...]}
        All specified keys must pass; inside a list, ANY item matches.
      * type: aggregate, threshold, window_minutes, group_by: [user, host],
        trigger: {action_contains: [...]}, success: {action_contains: [...]}
        Emits ONE detection when ``threshold`` trigger events for the
        same group are followed by a success event inside the window.
        Individual trigger events are NOT detections on their own.

A detection is a dict: time, ts, host, user, ip, source, action, detail,
technique_id, technique_name, tactic, kill_chain_stage, severity,
confidence, rule_id, merged_alerts (1 for simple rules, trigger count + 1
for aggregate rules), and a plain-words ``reason`` naming what matched.
"""

from __future__ import annotations

from collections import deque

import glob
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml


@dataclass
class Rule:
    id: str
    name: str
    technique_id: str
    technique_name: str
    tactic: str
    kill_chain_stage: str
    confidence: int = 80
    priority: int = 50
    description: str = ""
    match: Dict = field(default_factory=dict)
    rule_type: str = "simple"
    threshold: int = 0
    window_minutes: int = 120
    group_by: List[str] = field(default_factory=lambda: ["user", "host"])
    trigger: Dict = field(default_factory=dict)
    success: Dict = field(default_factory=dict)


def _rule_from_dict(data: Dict) -> Rule:
    match = data.get("match") or {}
    return Rule(
        id=str(data["id"]),
        name=str(data.get("name", data["id"])),
        technique_id=str(data.get("technique_id", "")),
        technique_name=str(data.get("technique_name", "")),
        tactic=str(data.get("tactic", "")),
        kill_chain_stage=str(data.get("kill_chain_stage", "")),
        confidence=int(data.get("confidence", 80)),
        priority=int(data.get("priority", 50)),
        description=str(data.get("description", "")),
        match=match,
        rule_type=str(data.get("type", "simple")),
        threshold=int(data.get("threshold", 0)),
        window_minutes=int(data.get("window_minutes", 120)),
        group_by=list(data.get("group_by", ["user", "host"])),
        trigger=data.get("trigger") or {},
        success=data.get("success") or {},
    )


def load_rules(rules_dir: str) -> List[Rule]:
    """Load every ``*.yml`` in ``rules_dir``, sorted by priority desc."""
    rules: List[Rule] = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path, "r", encoding="utf-8") as handle:
            doc = yaml.safe_load(handle) or {}
        for item in doc.get("rules", []):
            rules.append(_rule_from_dict(item))
    rules.sort(key=lambda r: (-r.priority, r.id))
    return rules


def _contains(haystack: str, needles) -> bool:
    text = (haystack or "").lower()
    if isinstance(needles, str):
        needles = [needles]
    return any(str(n).lower() in text for n in needles)


def _match_conditions(event: Dict, cond: Dict) -> bool:
    if not cond:
        return True
    action = event.get("action", "")
    detail = event.get("detail", "")
    combined = f"{action} {detail}"
    if "any_contains" in cond and not _contains(combined, cond["any_contains"]):
        return False
    if "action_contains" in cond and not _contains(action, cond["action_contains"]):
        return False
    if "detail_contains" in cond and not _contains(detail, cond["detail_contains"]):
        return False
    if "action_equals" in cond and action.strip().lower() != str(cond["action_equals"]).lower():
        return False
    if "severity_in" in cond and event.get("severity", "") not in cond["severity_in"]:
        return False
    if "source_contains" in cond and not _contains(event.get("source", ""), cond["source_contains"]):
        return False
    return True


class Detector:
    """Streaming detector. Holds only aggregate counters, never raw logs."""

    def __init__(self, rules: List[Rule]):
        self.simple = [r for r in rules if r.rule_type == "simple"]
        self.aggregate = [r for r in rules if r.rule_type == "aggregate"]
        # group key -> {"fails": [ts, ...]} per aggregate rule id
        self._agg_state: Dict[str, Dict[tuple, List[float]]] = {
            r.id: {} for r in self.aggregate
        }

    def _detection(self, event: Dict, rule: Rule, merged: int, reason: str) -> Dict:
        return {
            "time": event.get("time", ""),
            "ts": event.get("ts"),
            "host": event.get("host", ""),
            "user": event.get("user", ""),
            "ip": event.get("ip", ""),
            "source": event.get("source", ""),
            "action": event.get("action", ""),
            "detail": event.get("detail", ""),
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic": rule.tactic,
            "kill_chain_stage": rule.kill_chain_stage,
            "severity": event.get("severity", "Medium"),
            "confidence": rule.confidence,
            "rule_id": rule.id,
            "merged_alerts": merged,
            "reason": reason,
        }

    def process(self, event: Dict) -> List[Dict]:
        """Return 0 or 1 detections for one event (streaming, stateful)."""
        # Aggregate rules first: trigger events are counted, not emitted.
        for rule in self.aggregate:
            group = tuple(event.get(k, "") for k in rule.group_by)
            state = self._agg_state[rule.id].setdefault(group, deque())
            ts = event.get("ts")
            if _match_conditions(event, rule.trigger):
                if ts is not None:
                    window = rule.window_minutes * 60
                    while state and ts - state[0] > window:
                        state.popleft()
                    state.append(ts)
                else:
                    state.append(0.0)
                return []
            if _match_conditions(event, rule.success) and len(state) >= rule.threshold:
                count = len(state)
                state.clear()
                return [self._detection(
                    event, rule, merged=count + 1,
                    reason=(f"{count} failed logins for the same "
                            f"{'/'.join(rule.group_by)} followed by a success"),
                )]
        # Simple rules: highest priority match wins (one detection/event).
        for rule in self.simple:
            if _match_conditions(event, rule.match):
                matched = []
                for key in ("any_contains", "action_contains", "detail_contains"):
                    for needle in rule.match.get(key, []) if isinstance(
                            rule.match.get(key, []), list) else [rule.match.get(key)]:
                        if _contains(f"{event.get('action', '')} {event.get('detail', '')}",
                                      needle):
                            matched.append(str(needle))
                reason = rule.description or (
                    f"Matched rule '{rule.name}'"
                    + (f" on '{matched[0]}'" if matched else ""))
                return [self._detection(event, rule, merged=1, reason=reason)]
        return []
