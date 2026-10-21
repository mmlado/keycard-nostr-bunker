"""State kept next to the signer key: clients, pending clients, served requests, the secret."""

import os
import secrets
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


class ClientList:
    """Pubkeys, one per line, with optional metadata after a space.

    Re-read when another process changes the file; a missing file is an
    empty list. With a limit, the oldest entry goes when a new one arrives.
    """

    def __init__(self, path: Path | None = None, limit: int | None = None):
        self._path = path
        self._limit = limit
        self._entries: OrderedDict[str, str] = OrderedDict()
        self._mtime: int | None = None
        self._refresh()

    def __contains__(self, pubkey: str) -> bool:
        self._refresh()
        return pubkey in self._entries

    def __len__(self) -> int:
        self._refresh()
        return len(self._entries)

    def __iter__(self):
        self._refresh()
        return iter(list(self._entries))

    def items(self) -> list[tuple[str, str]]:
        self._refresh()
        return list(self._entries.items())

    def add(self, pubkey: str, meta: str = '') -> None:
        self._refresh()
        if pubkey in self._entries:
            return
        self._entries[pubkey] = meta
        while self._limit and len(self._entries) > self._limit:
            self._entries.popitem(last=False)
        self._save()

    def remove(self, pubkey: str) -> bool:
        self._refresh()
        if pubkey not in self._entries:
            return False
        del self._entries[pubkey]
        self._save()
        return True

    def _refresh(self) -> None:
        if self._path is None:
            return
        try:
            mtime = self._path.stat().st_mtime_ns
        except FileNotFoundError:
            self._entries = OrderedDict()
            self._mtime = None
            return
        if mtime == self._mtime:
            return
        self._entries = OrderedDict()
        for line in self._path.read_text().splitlines():
            key, _, meta = line.strip().partition(' ')
            if key:
                self._entries[key] = meta
        self._mtime = mtime

    def _save(self) -> None:
        if self._path is None:
            return
        write_private(self._path, ''.join(
            f'{key} {meta}\n' if meta else f'{key}\n' for key, meta in self._entries.items()))
        self._mtime = self._path.stat().st_mtime_ns


def approve(pubkey: str, clients: ClientList, pending: ClientList) -> bool:
    """Admit a client; returns whether it was waiting for approval."""
    was_pending = pending.remove(pubkey)
    clients.add(pubkey, f'{int(time.time())} approved')
    return was_pending


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


class Secret:
    """The admission secret: fixed by the config, or kept in a file that may be rotated."""

    def __init__(self, value: str = '', path: Path | None = None):
        if not value and path is None:
            raise ValueError('a connection secret is required')
        self._fixed = bool(value)
        self._path = None if value else path
        self._value = value
        self._mtime: int | None = None
        if not self._fixed:
            self._refresh()

    @property
    def current(self) -> str:
        if not self._fixed:
            self._refresh()
        return self._value

    @property
    def rotatable(self) -> bool:
        return not self._fixed

    def rotate(self) -> str:
        if self._path is None:
            raise ValueError('the secret is fixed in the config')
        self._value = new_secret(self._path)
        self._mtime = self._path.stat().st_mtime_ns
        return self._value

    def _refresh(self) -> None:
        assert self._path is not None
        try:
            mtime = self._path.stat().st_mtime_ns
        except FileNotFoundError:
            self.rotate()
            return
        if mtime != self._mtime:
            self._value = self._path.read_text().strip()
            self._mtime = mtime


def load_or_generate_secret(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    return new_secret(path)


def new_secret(path: Path) -> str:
    secret = secrets.token_urlsafe(16)
    write_private(path, secret + '\n')
    return secret
