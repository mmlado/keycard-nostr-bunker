"""Files kept next to the signer key that are not about client admission."""

import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable

DIR_MODE = 0o700
FILE_MODE = 0o600


def write_private(path: Path, text: str) -> None:
    """Write a file readable only by the owner, atomically."""
    path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.replace(tmp, path)


class SeenEvents:
    """Ids of requests already served, with their created_at, kept across restarts."""

    def __init__(self, path: Path | None = None, max_age: int = 300, limit: int = 4096,
                 now: Callable[[], float] = time.time):
        self._path = path
        self._max_age = max_age
        self._limit = limit
        self._now = now
        self._ids: OrderedDict[str, int] = OrderedDict()
        if path is not None and path.exists():
            cutoff = self._now() - max_age
            for line in path.read_text().splitlines():
                event_id, _, created = line.strip().partition(' ')
                if event_id and created.isdigit() and int(created) >= cutoff:
                    self._ids[event_id] = int(created)
            # Rewrite so the file does not grow forever across restarts.
            write_private(path, ''.join(f'{k} {v}\n' for k, v in self._ids.items()))

    def __contains__(self, event_id: str) -> bool:
        return event_id in self._ids

    def __len__(self) -> int:
        return len(self._ids)

    def record(self, event_id: str, created_at: int) -> None:
        if event_id in self._ids:
            return
        self._ids[event_id] = created_at
        while len(self._ids) > self._limit:
            self._ids.popitem(last=False)
        if self._path is not None:
            self._path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
            with os.fdopen(fd, 'a') as f:
                f.write(f'{event_id} {created_at}\n')
