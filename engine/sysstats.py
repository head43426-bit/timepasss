"""System stats for the /app progress line - stdlib only, no psutil.

Why no psutil: the server must run on a user's Windows machine with
only the documented dependencies (DuckDB, NetworkX, PyYAML). Adding a
new native dependency just for a progress number would complicate
installs and break the one-command run.sh/run.bat start.

What is measured, honestly:
  * System CPU % - sampled twice (Windows GetSystemTimes, Linux
    /proc/stat). The first call returns None (no previous sample yet);
    every later call is the % busy since the previous call. This is
    the WHOLE machine's CPU, not just ASK's - on a parallel run the
    workers are separate processes, so ASK-only CPU would undercount
    on Windows and mislead.
  * System RAM - total and available (Windows GlobalMemoryStatusEx,
    Linux /proc/meminfo). This is the number the user already watches
    in Task Manager (7.0/7.8 GB, 90%).
  * ASK process RSS - the main server process only (Windows
    WorkingSetSize, Linux /proc/self/status VmRSS). Workers are
    separate processes, so on a parallel run this is a lower bound
    for total ASK memory, and the UI says so nowhere - it is labelled
    'ASK (main)' for exactly that reason. Peak RSS (cli.py) is the
    end-of-run number; this is the live number.
All functions fail soft (return None/0) so a stats failure can never
break an upload or a /progress poll.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Optional, Tuple

_last_cpu = None  # (wall_time, busy, total)


def fmt_duration(seconds) -> str:
    """12s, 3m 12s, 1h 2m - the total/elapsed time the UI shows."""
    try:
        s = int(seconds)
    except Exception:
        return "0s"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def total_ram_mb() -> float:
    try:
        if sys.platform == "win32":
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            _ms = _MS()
            _ms.dwLength = ctypes.sizeof(_MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(_ms))
            return round(_ms.ullTotalPhys / (1024.0 * 1024.0), 1)
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return 0.0


def avail_ram_mb() -> float:
    try:
        if sys.platform == "win32":
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            _ms = _MS()
            _ms.dwLength = ctypes.sizeof(_MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(_ms))
            return round(_ms.ullAvailPhys / (1024.0 * 1024.0), 1)
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return 0.0


def process_rss_mb() -> float:
    """Current RSS of the main server process only (see module doc)."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class _PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD),
                            ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t),
                            ("PeakPagefileUsage", ctypes.c_size_t)]
            # ASK 0 MB FIX (2026-11-01, user screenshot: ASK (main):
            # 0 MB while PC RAM/CPU worked): without restype/argtypes,
            # ctypes treats GetCurrentProcess() as returning c_int,
            # truncating the 64-bit pseudo-handle (-1) to 32 bits, so
            # GetProcessMemoryInfo got an invalid handle, failed, and
            # this returned 0.0 - a lie the UI then displayed as
            # "0 MB". With HANDLE restype + explicit argtypes the
            # handle survives intact. If it still fails, fall through
            # to the fallbacks below instead of returning 0 here.
            _c = _PMC()
            _c.cb = ctypes.sizeof(_PMC)
            _k32 = ctypes.windll.kernel32
            _k32.GetCurrentProcess.restype = wintypes.HANDLE
            _psapi = ctypes.windll.psapi
            _psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD]
            _psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            _h = _k32.GetCurrentProcess()
            if _psapi.GetProcessMemoryInfo(_h, ctypes.byref(_c), _c.cb):
                return round(_c.WorkingSetSize / (1024.0 * 1024.0), 1)
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    try:
        import resource
        _v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(_v / 1024.0, 1) if sys.platform != "darwin" else round(_v / 1e6, 1)
    except Exception:
        return 0.0


def _cpu_times() -> Optional[Tuple[float, float]]:
    """(busy, total) CPU time ticks, platform-specific."""
    try:
        if sys.platform == "win32":
            import ctypes

            class _FT(ctypes.Structure):
                _fields_ = [("dwLowDateTime", ctypes.c_ulong),
                            ("dwHighDateTime", ctypes.c_ulong)]
            _idle, _kernel, _user = _FT(), _FT(), _FT()
            if not ctypes.windll.kernel32.GetSystemTimes(
                    ctypes.byref(_idle), ctypes.byref(_kernel), ctypes.byref(_user)):
                return None

            def _val(f):
                return (f.dwHighDateTime << 32) | f.dwLowDateTime
            _total = _val(_kernel) + _val(_user)
            _busy = _total - _val(_idle)
            return (float(_busy), float(_total))
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            _parts = handle.readline().split()[1:]
            _nums = [float(x) for x in _parts]
            _total = sum(_nums)
            _idle = _nums[3] + (_nums[4] if len(_nums) > 4 else 0)
            return (_total - _idle, _total)
    except Exception:
        return None


def system_cpu_percent() -> Optional[float]:
    """Whole-machine CPU % since the previous call, or None first time."""
    global _last_cpu
    _now = _cpu_times()
    if _now is None:
        return None
    _wall = time.time()
    if _last_cpu is None:
        _last_cpu = (_wall, _now[0], _now[1])
        return None
    _prev_wall, _prev_busy, _prev_total = _last_cpu
    _last_cpu = (_wall, _now[0], _now[1])
    _dt = _now[1] - _prev_total
    if _dt <= 0:
        return None
    return round(100.0 * (_now[0] - _prev_busy) / _dt, 1)


def snapshot() -> dict:
    """One dict for /progress: cpu %, RAM used/total/%, ASK main RSS."""
    _total = total_ram_mb()
    _avail = avail_ram_mb()
    _used = max(0.0, _total - _avail) if _total else 0.0
    _rss = process_rss_mb()
    # A failed RSS read is unknown, not 0 MB - the UI shows
    # "processing" for None, and a lying 0 for 0.0.
    return {
        "cpu_percent": system_cpu_percent(),
        "ram_used_mb": round(_used, 1),
        "ram_total_mb": _total,
        "ram_percent": round(100.0 * _used / _total, 1) if _total else None,
        "ask_rss_mb": _rss if _rss else None,
    }
