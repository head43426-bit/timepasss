"""Load Sample generator (2026-11-01): ~500 MB of synthetic log,
generated from generate_logs.py, streamed, never held as a list.

Why a new module instead of calling generate_logs.generate_logs()
directly: that function builds the whole log as a list in memory,
which is unusable at 500 MB. This module reuses its data verbatim -
BENIGN_ACTIONS, BENIGN_HOSTS, BENIGN_USERS and ATTACK_STEPS (the
same 11 steps that match rules/core.yml) - and yields pipe-format
lines one at a time, in the same chain shape as engine/demo.py:
70 benign lines, then the 11 attack steps, per chain.

Chain identity: one host and one user cycled from generate_logs'
lists, plus one distinct synthetic IP per chain
(192.168.<chain % 250>.<10 + (chain // 250) % 240>), and a chain
clock 10 minutes apart. The backend links detections by host, user,
IP and time (see engine/graph.py StreamingLinker), so appended
chains link into incidents exactly like an upload does - they do
NOT rewrite existing incidents. Existing incidents keep their ids,
rows and graphs; the new data adds new detections and new
incidents on top, and the dashboard's 5-second /health refresh
picks the new counts up once the run finishes.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone

# generate_logs.py lives at the repo root, not in engine/. main.py
# puts the repo root on sys.path, so this import works from the
# server; the __main__ test below adds the root itself.
sys.path.insert(0, __file__.rsplit("/", 2)[0])
from generate_logs import (  # noqa: E402
    ATTACK_STEPS,
    BENIGN_ACTIONS,
    BENIGN_HOSTS,
    BENIGN_USERS,
)

TARGET_BYTES = 500 * 1024 * 1024  # ~500 MB

BASE_TIME = datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc)


def _fmt(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def iter_sample_lines(target_bytes=TARGET_BYTES, seed=42):
    """Yield pipe-format lines until at least target_bytes are yielded.

    The caller counts bytes of the yielded lines (including the
    newline it adds) and stops when it has enough, exactly like
    engine/demo.py's caller does. Deterministic seed, so the same
    button always produces the same data.
    """
    rng = random.Random(seed)
    chain = 0
    total = 0
    while total < target_bytes:
        host = BENIGN_HOSTS[chain % len(BENIGN_HOSTS)]
        user = BENIGN_USERS[chain % len(BENIGN_USERS)]
        ip = "192.168.%d.%d" % (chain % 250, 10 + (chain // 250) % 240)
        t = BASE_TIME + timedelta(minutes=10 * chain)
        for _ in range(70):
            t += timedelta(seconds=rng.randint(5, 120))
            action, detail, sev = rng.choice(BENIGN_ACTIONS)
            line = "%s|%s|%s|%s|%s|%s|%s|Normal|None|%s" % (
                _fmt(t), rng.choice(BENIGN_HOSTS), rng.choice(BENIGN_USERS),
                "192.168.1.%d" % rng.randint(10, 150),
                rng.choice(["sysmon", "auth", "os", "network"]),
                action, detail, sev)
            total += len(line) + 1
            yield line
            if total >= target_bytes:
                return
        attack_t = BASE_TIME + timedelta(minutes=10 * chain, seconds=900)
        for step in ATTACK_STEPS:
            attack_t += timedelta(minutes=rng.randint(10, 45))
            line = "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                _fmt(attack_t), host, user, ip, step["source"],
                step["action"], step["detail"], step["stage"],
                step["technique"], step["severity"])
            total += len(line) + 1
            yield line
            if total >= target_bytes:
                return
        chain += 1
