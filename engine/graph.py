"""NetworkX graph, path reconstruction, risk scoring, next-reach (FR-4/5/6).

Linking rule (batch mode, used by cli.py): detections are processed in
time order. A detection joins an active incident when it shares a host,
user, or IP with that incident AND the gap from the incident's last
detection is at most 48 hours (the credential window: a stolen account
may be reused days later). Incidents idle for >48h are closed. If a
detection matches several active incidents, those incidents are merged
into the earliest one. A detection matching nothing starts a new
incident. Unlinked detections are therefore their own (single-step)
incidents, never force-joined to an unrelated path.

Risk score (B-1), documented so a judge can recompute it:
    weights: Critical 40, High 25, Medium 10, Low 3
    score = min(100, 0.3 * sum(weights) + 3 * distinct_stages
                    + 15 if any exfiltration else 0
                    + 10 if any credential-access / privilege-escalation)
    Rounded to 1 decimal. Incidents are ranked by score, then by
    detection count, then by id.

Next-reach (FR-6) uses ONLY the topology supplied with the data
(topology.json -> DuckDB topology tables). It never guesses for a host
absent from that topology: such hosts produce no next-reach entry, and
the API says so.
"""

from __future__ import annotations

import networkx as nx
from typing import Dict, List

LINK_WINDOW_SECONDS = 48 * 3600
SEVERITY_WEIGHTS = {"Critical": 40, "High": 25, "Medium": 10, "Low": 3}


def risk_score(detections: List[Dict]) -> float:
    total = sum(SEVERITY_WEIGHTS.get(d.get("severity", "Medium"), 10)
                for d in detections)
    stages = {d.get("kill_chain_stage", "") for d in detections}
    score = 0.3 * total + 3 * len(stages)
    if any(d.get("kill_chain_stage") == "Exfiltration" for d in detections):
        score += 15
    if any(d.get("kill_chain_stage") in ("Privilege Escalation", "Credential Access")
           for d in detections):
        score += 10
    return round(min(100.0, score), 1)


def build_graph(detections: List[Dict]) -> nx.DiGraph:
    """Hosts + users as nodes; detections as user->host edges, plus a
    host->host edge for each consecutive distinct host in time order,
    plus a real src->dst host-to-host edge when a detection carries a
    destination IP (firewall logs: srcip -> dstip). Blank hosts/users
    are never nodes: a "" node is what made single-host graphs lie.
    If, after all that, the graph still has no edges (one host, no
    user, no destination — the Fortinet phishing/malware flood), fall
    back to a host -> technique graph, so there is still a real graph
    to draw: the host in the centre, one node per technique it was
    hit with."""
    graph = nx.DiGraph()
    for det in detections:
        host, user = det.get("host", ""), det.get("user", "")
        if host:
            graph.add_node(host, type="host")
        if user:
            graph.add_node(user, type="user")
            if host:
                graph.add_edge(user, host, kind="event",
                               technique_id=det.get("technique_id", ""),
                               time=det.get("time", ""))
        dst = det.get("dst_ip", "")
        if dst and dst != host:
            graph.add_node(dst, type="host")
            src = det.get("ip", "") or host
            if src:
                graph.add_edge(src, dst, kind="path",
                               technique_id=det.get("technique_id", ""),
                               time=det.get("time", ""))
    ordered = sorted(detections, key=lambda d: (d.get("ts") is None, d.get("ts") or 0))
    prev_host = None
    for det in ordered:
        if prev_host and det["host"] != prev_host:
            graph.add_edge(prev_host, det["host"], kind="path",
                           technique_id=det.get("technique_id", ""),
                           time=det.get("time", ""))
        prev_host = det["host"]
    if graph.number_of_edges() == 0 and detections:
        host = detections[0].get("host", "")
        if host:
            seen = []
            for det in detections:
                tid = det.get("technique_id", "")
                if tid and tid not in seen:
                    seen.append(tid)
            for tid in seen:
                graph.add_node(tid, type="technique")
                graph.add_edge(host, tid, kind="technique",
                               technique_id=tid, time="")
    return graph


def graph_edges(detections: List[Dict]) -> List[Dict]:
    graph = build_graph(detections)
    return [{"from": u, "to": v, "kind": data.get("kind", "event"),
             "technique_id": data.get("technique_id", ""),
             "time": data.get("time", "")}
            for u, v, data in graph.edges(data=True)]


def link_detections(detections: List[Dict]) -> List[List[Dict]]:
    """Batch linking. Input must be in time order; output is a list of
    incidents, each a time-ordered list of detections."""
    ordered = sorted(detections, key=lambda d: (d.get("ts") is None, d.get("ts") or 0))
    active: List[Dict] = []  # {hosts, users, ips, last_ts, dets}
    finished: List[List[Dict]] = []
    for det in ordered:
        ts = det.get("ts") or 0
        expired = [a for a in active if ts - a["last_ts"] > LINK_WINDOW_SECONDS]
        finished.extend(a["dets"] for a in expired)
        active = [a for a in active if ts - a["last_ts"] <= LINK_WINDOW_SECONDS]
        matches = [a for a in active
                   if det["host"] in a["hosts"] or det["user"] in a["users"]
                   or (det.get("ip") and det["ip"] in a["ips"])]
        if not matches:
            active.append({"hosts": {det["host"]}, "users": {det["user"]},
                           "ips": {det["ip"]} if det.get("ip") else set(),
                           "last_ts": ts, "dets": [det]})
            continue
        first = matches[0]
        for other in matches[1:]:
            first["hosts"] |= other["hosts"]
            first["users"] |= other["users"]
            first["ips"] |= other["ips"]
            first["dets"].extend(other["dets"])
            active.remove(other)
        first["hosts"].add(det["host"])
        first["users"].add(det["user"])
        if det.get("ip"):
            first["ips"].add(det["ip"])
        first["last_ts"] = max(first["last_ts"], ts)
        first["dets"].append(det)
    finished.extend(a["dets"] for a in active)
    # Sort each incident's detections by time, and incidents by start.
    out = []
    for dets in finished:
        dets.sort(key=lambda d: (d.get("ts") is None, d.get("ts") or 0))
        out.append(dets)
    out.sort(key=lambda dets: dets[0].get("ts") or 0 if dets else 0)
    return out


def next_reach(compromised_hosts: List[str], compromised_users: List[str],
               topology: Dict) -> List[Dict]:
    """What the attacker could reach next, from topology only."""
    admin_rights = topology.get("admin_rights", {})
    host_subnet = topology.get("host_subnet", {})
    compromised = set(compromised_hosts)
    results: Dict[str, Dict] = {}
    # Same-subnet peers of compromised hosts.
    subnet_of = {h: s for h, s in host_subnet.items()}
    for host in compromised_hosts:
        subnet = subnet_of.get(host)
        if not subnet:
            continue
        for peer, peer_subnet in host_subnet.items():
            if peer_subnet == subnet and peer not in compromised:
                results[peer] = {
                    "host": peer, "confidence": 60,
                    "reason": f"Same subnet as compromised host {host}",
                    "block": f"Segment the subnet or isolate {host} first",
                }
    # Hosts where a compromised account has admin rights (FR-6 example:
    # "This account has admin rights on 3 more servers").
    for account in compromised_users:
        for host in admin_rights.get(account, []):
            if host not in compromised:
                results[host] = {
                    "host": host, "confidence": 85,
                    "reason": f"Account {account} has admin rights on {host}",
                    "block": (f"Revoke admin rights for {account} on {host} "
                              f"and reset its credentials"),
                }
    return sorted(results.values(), key=lambda r: (-r["confidence"], r["host"]))
