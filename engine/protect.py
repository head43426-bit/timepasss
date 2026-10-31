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
