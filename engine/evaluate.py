"""Accuracy evaluation against planted ground truth.

Ground-truth format (written by ground-truth file):
  {"attacks": [{"id": "...", "title": "...",
                "steps": [{"technique_id": "...", "technique_name": "...",
                           "kill_chain_stage": "...", "host": "...",
                           "user": "..."}, ...]}, ...]}

Metrics (PRD targets table, Good / Great):
  detection %     planted steps whose technique appears in the best-
                  matching incident for that attack / all planted steps
  correct labels %  among planted steps matched to a detection on the
                  same host in the best incident, share whose technique
                  also matches
  attack path %   planted attacks whose steps appear in ONE incident in
                  the correct order (technique subsequence) / all attacks
  false alarms %  incidents that are not the best match for any attack
                  / all incidents

Usage: python3 -m engine.evaluate --db out.duckdb --ground-truth gt.json
Prints each metric next to its Good/Great bar and a PASS/GOOD/GREAT tag.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List

from . import store

TARGETS = {
    "detection": (70.0, 90.0),
    "correct_labels": (60.0, 85.0),
    "attack_path": (50.0, 100.0),
    "false_alarms": (30.0, 10.0),  # lower is better
}


def _subsequence(needles: List[str], haystack: List[str]) -> bool:
    it = iter(haystack)
    return all(any(x == n for x in it) for n in needles)


def evaluate(db_path: str, ground_truth_path: str) -> Dict:
    with open(ground_truth_path, "r", encoding="utf-8") as handle:
        truth = json.load(handle)
    attacks = truth.get("attacks", [])
    con = store.connect(db_path)
    incidents = [store.get_incident(con, inc["id"]) for inc in store.list_incidents(con)]
    con.close()

    total_steps = 0
    detected_steps = 0
    labelled_checked = 0
    labelled_correct = 0
    rebuilt = 0
    best_for_attack = {}
    for attack in attacks:
        steps = attack.get("steps", [])
        total_steps += len(steps)
        # Best incident = most planted techniques present (multiset-aware
        # enough for the demo: count technique occurrences).
        best, best_overlap = None, -1
        for inc in incidents:
            # Score technique matches higher when the host also matches,
            # so two attacks sharing a technique (e.g. two brute-force
            # cases) do not steal each other's best incident.
            score = 0
            for s in steps:
                for d in inc["timeline"]:
                    if d["technique_id"] == s["technique_id"]:
                        score += 2 if d["host"] == s["host"] else 1
                        break
            if score > best_overlap:
                best, best_overlap = inc, score
        if best is None:
            continue
        best_for_attack[attack["id"]] = best["id"]
        best_techs = [d["technique_id"] for d in best["timeline"]]
        detected_steps += sum(1 for s in steps if s["technique_id"] in best_techs)
        for step in steps:
            same_host = [d for d in best["timeline"] if d["host"] == step["host"]]
            if same_host:
                labelled_checked += 1
                if any(d["technique_id"] == step["technique_id"] for d in same_host):
                    labelled_correct += 1
        if _subsequence([s["technique_id"] for s in steps], best_techs):
            rebuilt += 1
    used = set(best_for_attack.values())
    false_count = sum(1 for inc in incidents if inc["id"] not in used)
    result = {
        "attacks": len(attacks),
        "planted_steps": total_steps,
        "incidents": len(incidents),
        "detection": (100.0 * detected_steps / total_steps) if total_steps else 0.0,
        "correct_labels": (100.0 * labelled_correct / labelled_checked) if labelled_checked else 0.0,
        "attack_path": (100.0 * rebuilt / len(attacks)) if attacks else 0.0,
        "false_alarms": (100.0 * false_count / len(incidents)) if incidents else 0.0,
        "false_incidents": false_count,
        "rebuilt_attacks": rebuilt,
    }
    return result


def _tag(metric: str, value: float) -> str:
    good, great = TARGETS[metric]
    if metric == "false_alarms":
        if value <= great:
            return "GREAT"
        if value <= good:
            return "GOOD"
        return "BELOW BAR"
    if value >= great:
        return "GREAT"
    if value >= good:
        return "GOOD"
    return "BELOW BAR"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate vs ground truth")
    parser.add_argument("--db", required=True)
    parser.add_argument("--ground-truth", required=True)
    args = parser.parse_args(argv)
    result = evaluate(args.db, args.ground_truth)
    print(f"Attacks: {result['attacks']}, planted steps: {result['planted_steps']}, "
          f"incidents found: {result['incidents']}")
    for metric in ("detection", "correct_labels", "attack_path", "false_alarms"):
        good, great = TARGETS[metric]
        print(f"{metric}: {result[metric]:.1f}%  (Good {'>' if metric != 'false_alarms' else '<'}"
              f"{good}%, Great {'>' if metric != 'false_alarms' else '<'}{great}%)"
              f"  -> {_tag(metric, result[metric])}")
    print(f"Rebuilt attacks: {result['rebuilt_attacks']}/{result['attacks']}, "
          f"false incidents: {result['false_incidents']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
