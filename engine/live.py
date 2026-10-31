"""Live mode (B-5): poll a log file for appended lines and ingest them.

Polling interval is stated everywhere it is used (default 2 seconds).
The tailer tracks a byte offset and a partial-line buffer, so a line is
only processed once it is complete. ``tail_once`` is the unit used by
both the standalone live CLI and the API's background watcher thread.
"""

from __future__ import annotations

import os
import time
from typing import Callable, List

from .parser import parse_line


class Tailer:
    def __init__(self, path: str):
        self.path = path
        self.offset = 0
        self._partial = ""
        if os.path.exists(path):
            self.offset = os.path.getsize(path)

    def tail_once(self) -> List[dict]:
        """Return newly completed events since the last call."""
        if not os.path.exists(self.path):
            return []
        size = os.path.getsize(self.path)
        if size < self.offset:  # file truncated / rotated: restart at 0
            self.offset = 0
            self._partial = ""
        if size == self.offset:
            return []
        with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self.offset)
            chunk = handle.read()
            self.offset = handle.tell()
        text = self._partial + chunk
        if text.endswith("\n"):
            lines, self._partial = text.splitlines(), ""
        else:
            *lines, self._partial = text.splitlines()
        events = []
        for line in lines:
            event = parse_line(line)
            if event is not None:
                events.append(event)
        return events


def run_live(path: str, on_events: Callable[[List[dict]], None],
             interval: float = 2.0) -> None:
    """Poll ``path`` every ``interval`` seconds, calling ``on_events``
    with each batch of new events. Runs until interrupted."""
    tailer = Tailer(path)
    print(f"Live mode: watching {path} every {interval}s (Ctrl+C to stop)")
    try:
        while True:
            events = tailer.tail_once()
            if events:
                on_events(events)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Live mode stopped.")
