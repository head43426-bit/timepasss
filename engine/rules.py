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

from .severity import detection_severity, normalize_severity


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


def load_rules(rules_dir: str, only_files=None) -> List[Rule]:
    """Load rules from ``rules_dir``, sorted by priority desc.
    only_files=None (default): every ``*.yml`` in the dir, as before.
    only_files=[...]: only those filenames - a fixed pack. Missing
    files are skipped, never an error, so a pack never crashes a run."""
    rules: List[Rule] = []
    if only_files is not None:
        _paths = [os.path.join(rules_dir, f) for f in only_files
                  if os.path.isfile(os.path.join(rules_dir, f))]
    else:
        _paths = sorted(glob.glob(os.path.join(rules_dir, "*.yml")))
    for path in _paths:
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
    if "severity_in" in cond:
        _sev = normalize_severity(event.get("severity", ""))
        _allowed = {normalize_severity(v) for v in cond["severity_in"]}
        if _sev not in _allowed:
            return False
    if "source_contains" in cond and not _contains(event.get("source", ""), cond["source_contains"]):
        return False
    return True


def _lower_list(value) -> tuple:
    if not value:
        return ()
    if isinstance(value, str):
        return (value.lower(),)
    return tuple(str(v).lower() for v in value)


def _fast_cond(cond: Dict) -> Dict:
    """Pre-lowercase every phrase once at load time. The old path
    lowercased the whole log line AND every phrase on every rule, for
    every event - 25 rules x ~60 phrases x millions of lines. That
    repeated lowercasing was a hidden speed tax on every upload."""
    return {
        "any": _lower_list(cond.get("any_contains")),
        "action": _lower_list(cond.get("action_contains")),
        "detail": _lower_list(cond.get("detail_contains")),
        "source": _lower_list(cond.get("source_contains")),
        "equals": (str(cond["action_equals"]).lower()
                   if cond.get("action_equals") else None),
        "severity": cond.get("severity_in"),
    }


def _fast_match(fast: Dict, combined: str, action: str,
                detail: str, source: str, severity: str) -> bool:
    if fast["any"] and not any(p in combined for p in fast["any"]):
        return False
    if fast["action"] and not any(p in action for p in fast["action"]):
        return False
    if fast["detail"] and not any(p in detail for p in fast["detail"]):
        return False
    if fast["source"] and not any(p in source for p in fast["source"]):
        return False
    if fast["equals"] is not None and action.strip() != fast["equals"]:
        return False
    if fast["severity"] is not None:
        _sev = normalize_severity(severity)
        _allowed = {normalize_severity(v) for v in fast["severity"]}
        if _sev not in _allowed:
            return False
    return True


class Detector:
    """Streaming detector. Holds only aggregate counters, never raw logs."""

    def __init__(self, rules: List[Rule]):
        self.simple = [r for r in rules if r.rule_type == "simple"]
        self.aggregate = [r for r in rules if r.rule_type == "aggregate"]
        self._simple_fast = [(r, _fast_cond(r.match)) for r in self.simple]
        self._agg_fast = [(r, _fast_cond(r.trigger), _fast_cond(r.success))
                          for r in self.aggregate]
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
            "dst_ip": event.get("dst_ip", ""),
            # Destination domain (DNS lines): nytimes.com, not its IP.
            # The graph uses this as the destination node when present.
            "hostname": event.get("hostname", ""),
            "source": event.get("source", ""),
            "action": event.get("action", ""),
            "detail": event.get("detail", ""),
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic": rule.tactic,
            "kill_chain_stage": rule.kill_chain_stage,
            "severity": detection_severity(event.get("severity", ""),
                                           rule.technique_id,
                                           event.get("action", ""),
                                           event.get("detail", "")),
            "confidence": rule.confidence,
            "rule_id": rule.id,
            "merged_alerts": merged,
            "reason": reason,
        }

    def process(self, event: Dict) -> List[Dict]:
        """Return 0 or 1 detections for one event (streaming, stateful).
        Fast path: the line is lowercased ONCE here, then every rule
        checks its pre-lowercased phrases against it. No rule ever
        re-lowercases the line or its phrases."""
        action = (event.get("action", "") or "").lower()
        detail = (event.get("detail", "") or "").lower()
        combined = f"{action} {detail}"
        source = (event.get("source", "") or "").lower()
        severity = normalize_severity(event.get("severity", ""))
        # Aggregate rules first: trigger events are counted, not emitted.
        for rule, trig, succ in self._agg_fast:
            group = tuple(event.get(k, "") for k in rule.group_by)
            state = self._agg_state[rule.id].setdefault(group, deque())
            ts = event.get("ts")
            if _fast_match(trig, combined, action, detail, source, severity):
                if ts is not None:
                    window = rule.window_minutes * 60
                    while state and ts - state[0] > window:
                        state.popleft()
                    state.append(ts)
                else:
                    state.append(0.0)
                return []
            if _fast_match(succ, combined, action, detail, source, severity) and len(state) >= rule.threshold:
                count = len(state)
                state.clear()
                return [self._detection(
                    event, rule, merged=count + 1,
                    reason=(f"{count} failed logins for the same "
                            f"{'/'.join(rule.group_by)} followed by a success"),
                )]
        # Heuristic (not a keyword rule): DNS tunneling. A real DNS
        # line never looks like this - nytimes.com is 2 labels, 11
        # chars. A tunnel hides data in a very long hostname with many
        # labels. Thresholds are deliberately high so normal DNS never
        # fires: 5+ labels OR 60+ characters, on a DNS-subtype line.
        _host = (event.get("hostname", "") or "").strip().lower()
        _src = (event.get("source", "") or "").lower()
        if _host and "dns" in _src and (_host.count(".") >= 4 or len(_host) >= 60):
            _dns_rule = Rule(id="dns_tunnel_heuristic", name="DNS tunneling (heuristic)",
                              technique_id="T1071.004", technique_name="DNS",
                              tactic="Command and Control", kill_chain_stage="Command and Control",
                              confidence=70, priority=80,
                              description=f"Unusually long/multi-label DNS hostname ({_host}) - possible DNS tunneling",
                              match={})
            return [self._detection(event, _dns_rule, merged=1,
                                    reason=f"DNS hostname {_host} has {_host.count('.') + 1} labels and {len(_host)} characters - far above normal DNS, consistent with data hidden in DNS queries")]
        # Heuristic (not a keyword rule): EXTERNAL SMB to an INTERNAL
        # host, accepted. Internal SMB is normal file sharing and must
        # NOT fire - that would flood false alarms. But SMB arriving
        # from a public IP to a private IP should never happen in
        # normal use: it is an outsider reaching straight into an
        # internal/DMZ host over the file-sharing protocol, i.e.
        # lateral movement (T1021.002). The old keyword rule only
        # fired on the literal phrase "smb lateral", which a Fortinet
        # traffic line never contains, so a real case in the user's
        # own logs (external -> DMZ over SMB, accepted) was missed.
        # This checks the IPs, not the words: src public + dst private
        # + service SMB (in action/detail) + action accept/pass.
        def _is_private(_ip: str) -> bool:
            try:
                _parts = [int(x) for x in _ip.strip().split(".")]
                if len(_parts) != 4 or any(p < 0 or p > 255 for p in _parts):
                    return False
                a, b = _parts[0], _parts[1]
                return (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31)
                        or (a == 192 and b == 168) or (a == 169 and b == 254))
            except Exception:
                return False
        _src_ip = (event.get("ip", "") or "").strip()
        _dst_ip = (event.get("dst_ip", "") or "").strip()
        if (_src_ip and _dst_ip and "smb" in combined
                and not _is_private(_src_ip) and _is_private(_dst_ip)
                and ("accept" in action or "pass" in action)):
            _smb_rule = Rule(id="external_smb_to_internal",
                             name="External SMB to internal host",
                             technique_id="T1021.002",
                             technique_name="Remote Services: SMB/Windows Admin Shares",
                             tactic="Lateral Movement",
                             kill_chain_stage="Lateral Movement",
                             confidence=70, priority=85,
                             description="SMB connection from a public IP to a private internal host, accepted",
                             match={})
            _det = self._detection(event, _smb_rule, merged=1,
                                   reason=(f"SMB from public IP {_src_ip} to private host {_dst_ip}, accepted by the firewall - "
                                           f"SMB should never arrive from the internet to an internal host. Check whether that host was exposed, "
                                           f"whether the session was legitimate, and block external SMB at the firewall if it was not."))
            _det["severity"] = "High"
            return [_det]
        # Simple rules: highest priority match wins (one detection/event).
        for rule, fast in self._simple_fast:
            if _fast_match(fast, combined, action, detail, source, severity):
                matched = [p for p in fast["any"] if p in combined]
                reason = rule.description or (
                    f"Matched rule '{rule.name}'"
                    + (f" on '{matched[0]}'" if matched else ""))
                return [self._detection(event, rule, merged=1, reason=reason)]
        return []
