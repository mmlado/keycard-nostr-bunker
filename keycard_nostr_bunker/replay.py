"""The replay window: which request events are fresh, and not served before."""

import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable

from .state import DIR_MODE, FILE_MODE, write_private

# A request is served only while its created_at is this close to now, either way.
WINDOW = 60
# Ids outlive the window, so a small step back of the clock cannot make one
# forgettable while its request is still fresh.
RETENTION = 2 * WINDOW
KNOWN_LIMIT = 4096
STRANGER_LIMIT = 1024
# Lines the seen file may carry beyond twice its live ids before it is rewritten.
COMPACT_SLACK = 256


class ReplayWindow:
    """Decides whether a verified request event may be served.

    Ids of known clients, admitted or waiting for approval, are kept in a file
    so a restart does not serve them twice. Strangers' ids stay in a small
    in-memory set, so a flood cannot crowd known clients' ids out. After a
    restart that forgot them, a replayed stranger request is either a connect,
    which is harmless, or a request the client itself sent shortly before it was
    admitted. Safe to call from several threads.
    """

    def __init__(self, path: Path | None = None, now: Callable[[], float] = time.time,
                 limit: int = KNOWN_LIMIT):
        self._now = now
        self._known = _SeenIds(path, RETENTION, limit, now)
        self._strangers = _SeenIds(None, RETENTION, STRANGER_LIMIT, now)
        self._lock = threading.Lock()

    def since(self) -> int:
        """The oldest created_at worth asking a relay for."""
        return int(self._now()) - WINDOW

    def admit(self, event_id: str, created_at: int, known: bool) -> bool:
        """Record an event that may be served. False if it was served before;
        ValueError if it is not fresh. Call it only after the signature checked out,
        or a forged event could block the real one."""
        if abs(self._now() - created_at) > WINDOW:
            raise ValueError(f'created_at {created_at} is outside the {WINDOW}s window')
        with self._lock:
            if event_id in self._known or event_id in self._strangers:
                return False
            (self._known if known else self._strangers).record(event_id, created_at)
        return True


class _SeenIds:
    """Ids with their created_at, newest last, at most limit of them.

    With a path they survive a restart: the file is appended to, and rewritten
    once it carries twice the live ids, dropping those older than max_age.
    """

    def __init__(self, path: Path | None, max_age: int, limit: int, now: Callable[[], float]):
        self._path = path
        self._max_age = max_age
        self._limit = limit
        self._now = now
        self._ids: OrderedDict[str, int] = OrderedDict()
        self._lines = 0
        if path is not None and path.exists():
            for line in path.read_text().splitlines():
                event_id, _, created = line.strip().partition(' ')
                if event_id and created.isdigit():
                    self._ids[event_id] = int(created)
                    self._ids.move_to_end(event_id)
            self._trim()
            self._compact()

    def __contains__(self, event_id: str) -> bool:
        return event_id in self._ids

    def __len__(self) -> int:
        return len(self._ids)

    def record(self, event_id: str, created_at: int) -> None:
        if event_id in self._ids:
            return
        self._ids[event_id] = created_at
        self._trim()
        self._expire()
        if self._path is None:
            return
        if self._lines >= 2 * len(self._ids) + COMPACT_SLACK:
            self._compact()
            return
        self._path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
        with os.fdopen(fd, 'a') as f:
            f.write(f'{event_id} {created_at}\n')
        self._lines += 1

    def _trim(self) -> None:
        while len(self._ids) > self._limit:
            self._ids.popitem(last=False)

    def _expire(self) -> None:
        cutoff = self._now() - self._max_age
        while self._ids and next(iter(self._ids.values())) < cutoff:
            self._ids.popitem(last=False)

    def _compact(self) -> None:
        assert self._path is not None
        cutoff = self._now() - self._max_age
        self._ids = OrderedDict((k, v) for k, v in self._ids.items() if v >= cutoff)
        write_private(self._path, ''.join(f'{k} {v}\n' for k, v in self._ids.items()))
        self._lines = len(self._ids)
