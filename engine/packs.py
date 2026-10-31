"""Fixed rule packs (2026-11-01, corrected 2026-11-01 ~04:36 IST).

User priority, stated explicitly: the Fortinet UTM KV format
(date=... time=... eventtime=... tz="+0530" devname="FGT..."
type="utm" subtype="..." ...) must NEVER struggle. Other
formats may struggle — that is fine, and they get no fixed
guarantee.

So there is exactly one fixed pack: FORTINET_PACK. It is a
locked list of rule filenames in rules/. It does not grow
automatically when a new rule file is added later — a new file
only joins it when it is added to the list below, on purpose.

  * "fortinet" — ONLY for format fortinet_kv. Generic +
    Windows/Fortinet rules. macos.yml is deliberately NOT in
    it, so an Apple rule can never clash with a Fortinet log.
  * "macos" — Apple formats only (Apple signals in first 200
    lines). Kept from the earlier pack work, but it is NOT
    the priority pack.
  * "all" — fallback, today's behaviour: every *.yml in
    rules/. Used for every other format (pipe, JSON, CSV,
    syslog, plain, unknown, mixed). Those formats may
    struggle, per the user — no fixed guarantee is made
    for them, and nothing is ever missed by forcing a
    wrong pack.

load_rules(rules_dir, only_files=...) enforces a pack: if a
file in the list is missing, it is skipped, not an error, so a
pack never crashes a run because a file was renamed.
"""
from __future__ import annotations

FORTINET_PACK = [
    "core.yml",
    "coverage.yml",
    "brute_force.yml",
    "powershell_encoded.yml",
    "custom_example.yml",
]

# Backwards-compatible alias: the earlier name for this list.
FIXED_PACK = FORTINET_PACK

MACOS_PACK = FORTINET_PACK + ["macos.yml"]


def packs_for_format(sniffed_format: str, os_hint: str = "") -> list:
    """Return the fixed pack for a sniffed format.
    fortinet_kv -> FORTINET_PACK (the fixed, priority pack).
    Apple signals -> MACOS_PACK.
    Anything else -> [] meaning 'load all' (no fixed guarantee,
    may struggle, per the user)."""
    if (os_hint or "").lower() == "macos":
        return list(MACOS_PACK)
    if sniffed_format == "fortinet_kv":
        return list(FORTINET_PACK)
    return []
