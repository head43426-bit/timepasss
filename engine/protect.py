"""Protection playbook (not active blocking): for every technique in an
incident, the concrete action that stops it or fixes it. ASK cannot
block an attack itself — it has no agent on your hosts and no firewall
control, and claiming otherwise would be a lie. What it can do is tell
you, per technique found, exactly what to isolate, revoke, patch or
restore, in priority order. That is the protection this tool offers,
and it is generated from the incident's own techniques, never generic
advice pasted on every incident."""

from __future__ import annotations

from typing import Dict, List

MITIGATIONS = {
    "T1566.001": "Block the sender domain, quarantine the attachment, and reset the password of anyone who opened it. Turn on attachment sandboxing for mail.",
    "T1204.002": "Quarantine the file on every host it touched, kill its process, and re-image any host where it ran. Block its hash at the endpoint tool.",
    "T1059.001": "Block encoded PowerShell (Constrained Language Mode / WDAC), kill the PowerShell process, and check what command it actually ran before closing the incident.",
    "T1053.005": "Delete the scheduled task, find what created it, and remove that creator too — otherwise it comes back on reboot.",
    "T1505.003": "Remove the web shell file, patch the web application flaw that let it in, and rotate every credential stored on that web server.",
    "T1136": "Delete the new admin account, audit who created it, and reset all admin passwords.",
    "T1068": "Patch the exploited software, remove the attacker's elevated session, and audit what the elevated account touched.",
    "T1070": "Restore logs from a central log server (never only from the host), and alert on any future log-clearing event as a high-severity incident.",
    "T1003.001": "Force a password reset for every account on the host, enable Credential Guard / LSA protection, and treat all dumped credentials as compromised.",
    "T1558.003": "Reset the targeted service account, set it to a long random password, and require Kerberos armoring where possible.",
    "T1110": "Lock the targeted account, enforce multi-factor authentication, and rate-limit logins from the attacking IP.",
    "T1021.002": "Isolate the source host, disable SMB admin shares where not needed, and block lateral SMB between workstations.",
    "T1046": "Close unnecessary open services, firewall them to trusted hosts only, and alert on new service scans.",
    "T1087": "Restrict account enumeration (limit who can list users), and treat a sudden enumeration burst as a pre-attack signal.",
    "T1595": "Block the scanning IP at the firewall, close the ports it found open, and check whether it moved from scanning to exploiting.",
    "T1560": "Find the staged archive, delete it before it leaves, and check for the exfiltration channel it was staged for.",
    "T1071.001": "Block the beacon destination at the firewall/proxy, isolate the beaconing host, and hunt for other hosts beaconing to the same destination.",
    "T1071.004": "Block the DNS tunnel domain, force DNS through a filtered resolver, and alert on long or high-volume DNS queries.",
    "T1036": "Quarantine the masquerading file, check its real hash (not its name), and block that hash everywhere.",
    "T1055": "Kill the injected process and its host process, re-image the host if the injection persisted, and hunt for the injector.",
    "T1048": "Block the outside destination, isolate the uploading host, and check what data left — then treat that data as exposed.",
    "T1486": "Isolate the host immediately, do NOT pay, restore files from offline backups, and hunt for the ransomware's entry point on every other host.",
    "T1485": "Isolate the host, restore from offline backups, and check whether destruction spread to shared drives before restoring.",
}

GENERIC = "Isolate the affected host from the network, preserve its logs centrally, and work through the techniques above one by one — highest risk first."

# Why each stage matters, in one plain sentence — used by the live
# "what we're finding" slab while an upload is still running, so a
# non-expert can read a technique and immediately understand it.
WHY_BY_STAGE = {
    "Reconnaissance": "The attacker is still outside, looking for a way in — this is the earliest warning you will ever get.",
    "Initial Access": "The attacker got in. Everything after this is damage control, not prevention.",
    "Execution": "Attacker code actually ran on your host — this is no longer a probe, it is a foothold.",
    "Persistence": "The attacker is trying to survive a reboot, so cleaning the one file you found will not be enough.",
    "Privilege Escalation": "The attacker is climbing from a normal user to an admin — the blast radius just grew.",
    "Defense Evasion": "The attacker is actively hiding — logs, files or processes you cannot see are the point.",
    "Credential Access": "Passwords or tickets are being stolen — every account on that host must be treated as compromised.",
    "Discovery": "The attacker is mapping your network from inside — the next move is usually lateral movement.",
    "Lateral Movement": "The attacker is moving to other hosts — one compromised machine is becoming many.",
    "Collection": "Data is being gathered for stealing — this is the last step before it leaves.",
    "Command and Control": "The compromised host is talking to the attacker's server — it can receive new orders at any time.",
    "Exfiltration": "Data is leaving your network — the breach is already real, and scope matters more than speed now.",
    "Impact": "The attacker is destroying or encrypting — restore from backups, do not negotiate from the infected host.",
}


def live_tell(technique_id: str, technique_name: str, stage: str,
              count: int, tell: str) -> Dict:
    """One live slab entry: what was found, what gave it away (the
    tell), why it matters, and how it helps you. All plain words —
    this is the panel a non-expert reads while the upload runs."""
    return {
        "technique_id": technique_id, "technique_name": technique_name,
        "kill_chain_stage": stage, "count": count,
        "tell": tell or "a log line matching this attack's signature",
        "why": WHY_BY_STAGE.get(stage, "This is a step in the attack chain — earlier stages are warnings, later stages are damage."),
        "help": MITIGATIONS.get(technique_id, GENERIC),
    }


def protections_for(incident: Dict) -> List[Dict]:
    """One protection action per distinct technique in the incident,
    worst-first by kill-chain depth (later stages first, since they
    mean the attacker got further). Techniques with no specific entry
    still get the generic action, so no technique is ever left without
    a protection step."""
    seen = {}
    for s in incident.get("timeline_summary", []):
        seen[s["technique_id"]] = s.get("technique_name", "")
    if not seen:
        for d in incident.get("timeline", []):
            if d.get("technique_id"):
                seen[d["technique_id"]] = d.get("technique_name", "")
    order = ["Impact", "Exfiltration", "Command and Control", "Collection",
             "Lateral Movement", "Discovery", "Credential Access",
             "Defense Evasion", "Privilege Escalation", "Persistence",
             "Execution", "Initial Access", "Reconnaissance"]
    stage_of = {}
    for s in incident.get("timeline_summary", []):
        stage_of[s["technique_id"]] = s.get("kill_chain_stage", "")
    out = []
    for tid in sorted(seen, key=lambda t: order.index(stage_of.get(t, "")) if stage_of.get(t, "") in order else 99):
        out.append({"technique_id": tid, "technique_name": seen[tid],
                    "action": MITIGATIONS.get(tid, GENERIC)})
    return out
