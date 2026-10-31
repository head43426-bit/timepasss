"""Slim MITRE ATT&CK index — lookup only, never detection.

The full MITRE STIX bundle is 47 MB (26,689 objects) and would bloat
the repo, slow the push, and cost RAM on every server start on an
8 GB machine — so it is deliberately NOT bundled. Instead
``data/mitre_techniques.json`` (562 KB, 706 entries) holds only the
attack-pattern objects from that bundle: id, name, tactics,
description (truncated to 600 chars), MITRE URL, and whether it is a
sub-technique. Revoked/deprecated techniques are excluded.

This module is lazy: the file is read once, only when a lookup or
coverage request actually arrives. Detection, linking, upload and
memory use never touch it. Coverage is computed from the rules in
``rules/`` (the techniques ASK actually detects), so the coverage
page can honestly say '23 of 706' instead of pretending full MITRE
coverage.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_PATH = os.path.join(ROOT, "data", "mitre_techniques.json")


@lru_cache(maxsize=1)
def _index() -> Dict:
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {"source": "", "technique_count": 0, "techniques": []}


def lookup(technique_id: str) -> Optional[Dict]:
    """One technique by ID (e.g. 'T1566.001'), or None if unknown."""
    for tech in _index().get("techniques", []):
        if tech.get("id") == technique_id:
            return tech
    return None


def ask_technique_ids(rules_dir: str = None) -> List[str]:
    """Technique IDs ASK's own rules detect, from rules/*.yml."""
    try:
        from .rules import load_rules
        _dir = rules_dir or os.path.join(ROOT, "rules")
        return sorted({r.technique_id for r in load_rules(_dir) if r.technique_id})
    except Exception:
        return []


def coverage(rules_dir: str = None) -> Dict:
    """Honest coverage: ASK's detected techniques vs the MITRE index."""
    _idx = _index()
    _all = {t.get("id") for t in _idx.get("techniques", []) if t.get("id")}
    _ask = set(ask_technique_ids(rules_dir))
    _covered = sorted(_ask & _all)
    return {
        "source": _idx.get("source", ""),
        "mitre_technique_count": len(_all),
        "ask_technique_count": len(_covered),
        "ask_techniques": _covered,
        "ask_techniques_not_in_index": sorted(_ask - _all),
    }
