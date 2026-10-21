"""What the bunker keeps on disk: the state directory, its files, and how they are written."""

import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable

DIR_MODE = 0o700
FILE_MODE = 0o600
# Lines the seen file may carry beyond twice its live ids before it is rewritten.
COMPACT_SLACK = 256


class StateDir:
    """The directory of the signer key, where the bunker keeps everything it remembers.

    The one place that names the files. They are private: written atomically,
    mode 0600, in a 0700 directory the bunker creates itself.
    """

    def __init__(self, path: str | Path, signer_key_name: str = 'signer.key'):
        self.path = Path(path)
        self.signer_key = self.path / signer_key_name

    @classmethod
    def for_signer_key(cls, signer_key: str | Path) -> 'StateDir':
        key = Path(signer_key)
        return cls(key.parent, key.name)

    @property
    def secret(self) -> Path:
        return self.path / 'secret'

    @property
    def clients(self) -> Path:
        return self.path / 'clients'

    @property
    def pending(self) -> Path:
        return self.path / 'pending'

    @property
    def admission_lock(self) -> Path:
        return self.path / 'admission.lock'

    @property
    def seen(self) -> Path:
        return self.path / 'seen'

    @property
    def user_pubkey(self) -> Path:
        return self.path / 'user.pubkey'

    @property
    def pin_rejected(self) -> Path:
        return self.path / 'pin.rejected'

    def files(self) -> list[Path]:
        return [self.signer_key, self.secret, self.clients, self.pending, self.admission_lock,
                self.seen, self.user_pubkey, self.pin_rejected]

    def open_to_others(self) -> bool:
        return self.path.is_dir() and bool(os.stat(self.path).st_mode & 0o077)


def write_private(path: Path, text: str) -> None:
    """Write a file readable only by the owner, atomically."""
    path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.replace(tmp, path)


class SeenEvents:
    """Ids of requests already served, with their created_at, kept across restarts.

    Holds at most limit ids, newest last. The file is appended to and rewritten
    once it carries twice the live ids, dropping those older than max_age.
    """

    def __init__(self, path: Path | None = None, max_age: int = 300, limit: int = 4096,
                 now: Callable[[], float] = time.time):
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
