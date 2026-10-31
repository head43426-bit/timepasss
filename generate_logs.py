#!/usr/bin/env python3
"""Synthetic security log generator for Kill Chain Reconstruction.

Generates realistic background enterprise traffic interleaved with
multi-stage cyber attack kill chains.
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone


BENIGN_USERS = ["alice", "bob", "carol", "david", "emma", "frank", "grace"]
BENIGN_HOSTS = ["workstation-01", "workstation-02", "workstation-03", "laptop-sales", "hr-pc", "dev-box"]
SERVERS = ["dc-01.corp.local", "fileserver-01", "app-srv-01", "db-prod-01"]
INTERNAL_SUBNET = "192.168.1."
EXTERNAL_IPS = ["203.0.113.42", "198.51.100.88", "185.220.101.5", "91.108.4.12"]

BENIGN_ACTIONS = [
    ("auth", "User logged in via Kerberos ticket", "Low"),
    ("dns", "DNS query resolved for internal portal", "Low"),
    ("file_access", "Read access to departmental shared drive", "Low"),
    ("process_start", "Chrome browser process spawned", "Low"),
    ("dhcp", "DHCP lease renewed successfully", "Low"),
    ("system", "Windows Update check completed", "Low"),
    ("net_connect", "Outbound HTTPS connection to cdn.microsoft.com", "Low"),
    ("service", "Print spooler service status healthy", "Low"),
]

# Kill chain progression steps designed to match rules in rules/core.yml
ATTACK_STEPS = [
    {
        "host": "workstation-01",
        "user": "alice",
        "ip": "192.168.1.105",
        "source": "firewall",
        "action": "scan_detected",
        "detail": "Active port scan detected from internal subnet",
        "stage": "Reconnaissance",
        "technique": "T1595",
        "severity": "Medium",
    },
    {
        "host": "workstation-01",
        "user": "alice",
        "ip": "192.168.1.105",
        "source": "email_gateway",
        "action": "email_delivered",
        "detail": "Phishing email opened with invoice.xlsm malicious attachment",
        "stage": "Initial Access",
        "technique": "T1566.001",
        "severity": "High",
    },
    {
        "host": "workstation-01",
        "user": "alice",
        "ip": "192.168.1.105",
        "source": "sysmon",
        "action": "macro_exec",
        "detail": "Malicious macro executed via excel.exe child process powershell",
        "stage": "Execution",
        "technique": "T1204.002",
        "severity": "High",
    },
    {
        "host": "workstation-01",
        "user": "alice",
        "ip": "192.168.1.105",
        "source": "sysmon",
        "action": "priv_esc",
        "detail": "Privilege escalation vulnerability exploited on workstation-01",
        "stage": "Privilege Escalation",
        "technique": "T1068",
        "severity": "Critical",
    },
    {
        "host": "workstation-01",
        "user": "SYSTEM",
        "ip": "192.168.1.105",
        "source": "sysmon",
        "action": "mimikatz",
        "detail": "Credential dump detected: lsass memory access by mimikatz",
        "stage": "Credential Access",
        "technique": "T1003.001",
        "severity": "Critical",
    },
    {
        "host": "workstation-01",
        "user": "admin_backup",
        "ip": "192.168.1.105",
        "source": "task_scheduler",
        "action": "task_created",
        "detail": "Scheduled task created for persistence running hidden payload",
        "stage": "Persistence",
        "technique": "T1053.005",
        "severity": "High",
    },
    {
        "host": "fileserver-01",
        "user": "admin_backup",
        "ip": "192.168.1.105",
        "source": "windows_security",
        "action": "smb_session",
        "detail": "SMB lateral movement from workstation-01 to fileserver-01",
        "stage": "Lateral Movement",
        "technique": "T1021.002",
        "severity": "Critical",
    },
    {
        "host": "fileserver-01",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "edr",
        "action": "c2_connect",
        "detail": "Periodic C2 beacon detected connecting to external server 185.220.101.5",
        "stage": "Command and Control",
        "technique": "T1071.001",
        "severity": "High",
    },
    {
        "host": "fileserver-01",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "file_monitor",
        "action": "archive_created",
        "detail": "Confidential database export files staged for exfiltration in 7z archive",
        "stage": "Collection",
        "technique": "T1560",
        "severity": "High",
    },
    {
        "host": "fileserver-01",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "network_ids",
        "action": "data_transfer",
        "detail": "Large data upload to an outside IP 185.220.101.5 detected",
        "stage": "Exfiltration",
        "technique": "T1048",
        "severity": "Critical",
    },
    {
        "host": "fileserver-01",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "event_log",
        "action": "log_clear",
        "detail": "Security event logs cleared with wevtutil to evade detection",
        "stage": "Defense Evasion",
        "technique": "T1070",
        "severity": "High",
    },
]


def generate_logs(num_benign: int = 50, format_type: str = "pipe", include_attack: bool = True) -> list:
    base_time = datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    current_time = base_time

    # Generate benign events
    for _ in range(num_benign):
        current_time += timedelta(seconds=random.randint(5, 120))
        action, detail, sev = random.choice(BENIGN_ACTIONS)
        events.append({
            "time": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": random.choice(BENIGN_HOSTS),
            "user": random.choice(BENIGN_USERS),
            "ip": f"{INTERNAL_SUBNET}{random.randint(10, 150)}",
            "source": random.choice(["sysmon", "auth", "os", "network"]),
            "action": action,
            "detail": detail,
            "stage": "Normal",
            "technique": "None",
            "severity": sev,
        })

    # Interleave attack steps into the timeline
    if include_attack:
        attack_time = base_time + timedelta(minutes=15)
        for step in ATTACK_STEPS:
            attack_time += timedelta(minutes=random.randint(10, 45))
            event = dict(step)
            event["time"] = attack_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            events.append(event)

    # Sort all events by time
    events.sort(key=lambda e: e["time"])

    # Format output
    lines = []
    for ev in events:
        if format_type == "json":
            lines.append(json.dumps(ev))
        else:
            # 10-field pipe format: time|host|user|ip|source|action|detail|stage|technique|severity
            line = f"{ev['time']}|{ev['host']}|{ev['user']}|{ev['ip']}|{ev['source']}|{ev['action']}|{ev['detail']}|{ev['stage']}|{ev['technique']}|{ev['severity']}"
            lines.append(line)

    return lines


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic security logs")
    parser.add_argument("--output", "-o", default="sample_attack.log", help="Output file path")
    parser.add_argument("--benign", "-b", type=int, default=100, help="Number of benign events")
    parser.add_argument("--format", "-f", choices=["pipe", "json"], default="pipe", help="Log format")
    parser.add_argument("--no-attack", action="store_true", help="Omit attack events (pure noise)")
    args = parser.parse_args()

    lines = generate_logs(num_benign=args.benign, format_type=args.format, include_attack=not args.no_attack)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {len(lines)} log lines into {args.output} (format: {args.format})")


if __name__ == "__main__":
    main()
