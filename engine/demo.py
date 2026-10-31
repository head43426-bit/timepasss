"""Synthetic demo log generator (~100 MB, on demand).

Built from the synthetic example already in the repo —
sample_attack.log / generate_logs.py: the same 11-step attack
chain (port scan -> phishing -> macro -> privilege escalation ->
credential dump -> scheduled task -> SMB lateral -> C2 -> staging
-> exfiltration -> log clearing) plus benign enterprise noise, in
the same 10-field pipe format.

NOT built from any real log: no real Fortinet/firex lines, no
real IPs or users are used here. Every host, user and IP is
synthetic (workstation-*/192.168.*), and every chain varies its
IP so chains stay separate incidents instead of collapsing into
one giant incident.

Streaming: lines are yielded one at a time, never held as a
100 MB list in RAM. The caller writes them to disk (next to the
DB, not /tmp) and stops at target_bytes. Deterministic seed, so
the same button always produces the same demo.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

TARGET_BYTES = 100 * 1024 * 1024  # ~100 MB

BENIGN_USERS = ["alice", "bob", "carol", "david", "emma", "frank", "grace"]
BENIGN_HOSTS = ["workstation-01", "workstation-02", "workstation-03",
                "laptop-sales", "hr-pc", "dev-box"]
BENIGN_ACTIONS = [
    ("auth", "User logged in via Kerberos ticket"),
    ("dns", "DNS query resolved for internal portal"),
    ("file_access", "Read access to departmental shared drive"),
    ("process_start", "Chrome browser process spawned"),
    ("dhcp", "DHCP lease renewed successfully"),
    ("system", "Windows Update check completed"),
    ("net_connect", "Outbound HTTPS connection to cdn.microsoft.com"),
    ("service", "Print spooler service status healthy"),
]

# Same steps as generate_logs.py ATTACK_STEPS, with host/user/ip
# filled in per chain. Detail phrases are what the rules match on.
ATTACK_TEMPLATE = [
    ("firewall", "scan_detected", "Active port scan detected from internal subnet", "Reconnaissance", "T1595", "Medium"),
    ("email_gateway", "email_delivered", "Phishing email opened with invoice.xlsm malicious attachment", "Initial Access", "T1566.001", "High"),
    ("sysmon", "macro_exec", "Malicious macro executed via excel.exe child process powershell", "Execution", "T1204.002", "High"),
    ("sysmon", "priv_esc", "Privilege escalation vulnerability exploited", "Privilege Escalation", "T1068", "Critical"),
    ("sysmon", "mimikatz", "Credential dump detected: lsass memory access by mimikatz", "Credential Access", "T1003.001", "Critical"),
    ("task_scheduler", "task_created", "Scheduled task created for persistence running hidden payload", "Persistence", "T1053.005", "High"),
    ("windows_security", "smb_session", "SMB lateral movement to fileserver", "Lateral Movement", "T1021.002", "Critical"),
    ("edr", "c2_connect", "Periodic C2 beacon detected connecting to external server", "Command and Control", "T1071.001", "High"),
    ("file_monitor", "archive_created", "Confidential database export files staged for exfiltration in 7z archive", "Collection", "T1560", "High"),
    ("network_ids", "data_transfer", "Large data upload to an outside IP detected", "Exfiltration", "T1048", "Critical"),
    ("event_log", "log_clear", "Security event logs cleared with wevtutil to evade detection", "Defense Evasion", "T1070", "High"),
]

BASE_TIME = datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc)


def _fmt(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def iter_demo_lines(target_bytes=TARGET_BYTES, seed=42):
    """Yield pipe-format lines until at least target_bytes are yielded.

    Returns nothing; the caller counts bytes of the yielded lines
    (including the newline it adds) and stops when it has enough.
    Each chain = 70 benign lines + 11 attack steps, with its own
    synthetic IP, so each chain is its own incident.
    """
    rng = random.Random(seed)
    chain = 0
    total = 0
    while total < target_bytes:
        host = BENIGN_HOSTS[chain % len(BENIGN_HOSTS)]
        user = BENIGN_USERS[chain % len(BENIGN_USERS)]
        # Distinct synthetic IP per chain: 192.168.<0-249>.<10-249>
        ip = "192.168.%d.%d" % (chain % 250, 10 + (chain // 250) % 240)
        t = BASE_TIME + timedelta(minutes=10 * chain)
        for _ in range(70):
            t += timedelta(seconds=rng.randint(5, 120))
            action, detail = rng.choice(BENIGN_ACTIONS)
            line = "%s|%s|%s|%s|%s|%s|%s|Normal|None|Low" % (
                _fmt(t), rng.choice(BENIGN_HOSTS), rng.choice(BENIGN_USERS),
                "192.168.1.%d" % rng.randint(10, 150),
                rng.choice(["sysmon", "auth", "os", "network"]),
                action, detail)
            total += len(line) + 1
            yield line
            if total >= target_bytes:
                return
        attack_t = BASE_TIME + timedelta(minutes=10 * chain, seconds=900)
        for (source, action, detail, stage, technique, severity) in ATTACK_TEMPLATE:
            attack_t += timedelta(minutes=15)
            line = "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                _fmt(attack_t), host, user, ip, source, action, detail,
                stage, technique, severity)
            total += len(line) + 1
            yield line
            if total >= target_bytes:
                return
        chain += 1
