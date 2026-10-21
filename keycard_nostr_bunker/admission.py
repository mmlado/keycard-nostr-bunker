"""Client admission: who may use the bunker, and with which permissions.

A client gets in by presenting the connect secret, by being approved at the
prompt or from the pending list, or by being listed in the config. An
admitted client keeps the permissions it requested at connect.
"""

import hmac
import logging
import os
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Iterator

try:
    import fcntl
except ImportError:
    # Windows has no flock; there the bunker and the CLI do not lock each other out.
    fcntl = None  # type: ignore[assignment]

from .perms import Permissions
from .state import DIR_MODE, FILE_MODE, write_private

log = logging.getLogger(__name__)

PENDING_LIMIT = 64
CONFIG = 'config'
PERMS_TOKEN = 'perms='

# Given a client pubkey and the permissions it requested: True admits it,
# False refuses it, None leaves it pending.
Approver = Callable[[str, Permissions], bool | None]


class AdmissionError(Exception):
    """A connect or a request was refused; the message is safe to show the client."""


def defer(client: str, perms: Permissions) -> None:
    """The approver without a terminal: every client waits for `clients approve`."""
    return None


@dataclass(frozen=True)
class ClientRecord:
    """A client, when it was admitted or asked, through which relay, and what it requested."""

    pubkey: str
    since: int | None
    via: str
    perms: Permissions

    @classmethod
    def parse(cls, line: str) -> 'ClientRecord | None':
        tokens = line.split()
        if not tokens:
            return None
        since: int | None = None
        via = ''
        perms = Permissions(None)
        for token in tokens[1:]:
            if token.startswith(PERMS_TOKEN):
                perms = Permissions(frozenset(
                    item for item in token[len(PERMS_TOKEN):].split(',') if item))
            elif since is None and token.isdigit():
                since = int(token)
            elif not via:
                via = token
        return cls(tokens[0], since, via, perms)

    def line(self) -> str:
        parts = [self.pubkey]
        if self.since is not None:
            parts.append(str(self.since))
        if self.via:
            parts.append(self.via)
        if self.perms.items is not None:
            parts.append(PERMS_TOKEN + ','.join(sorted(self.perms.items)))
        return ' '.join(parts)


@dataclass(frozen=True)
class Revocation:
    removed: bool
    dropped_pending: bool
    in_config: bool
    rotated: bool
    secret_fixed: bool


def _stamp(path: Path) -> tuple[int, int, int] | None:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return st.st_ino, st.st_mtime_ns, st.st_size


class _RecordFile:
    """Client records, one per line, oldest first.

    Re-read when another process has replaced the file. Every write goes
    through os.replace, so the inode changes even within one mtime tick.
    """

    def __init__(self, path: Path | None, limit: int | None = None):
        self._path = path
        self._limit = limit
        self._records: dict[str, ClientRecord] = {}
        self._stamp: tuple[int, int, int] | None = None

    def get(self, pubkey: str) -> ClientRecord | None:
        return self._current().get(pubkey)

    def all(self) -> list[ClientRecord]:
        return list(self._current().values())

    def put(self, record: ClientRecord) -> None:
        """Callers hold the admission locks."""
        records = self._fresh()
        records.pop(record.pubkey, None)
        records[record.pubkey] = record
        while self._limit is not None and len(records) > self._limit:
            del records[next(iter(records))]
        self._store(records)

    def remove(self, pubkey: str) -> bool:
        """Callers hold the admission locks."""
        records = self._fresh()
        if records.pop(pubkey, None) is None:
            return False
        self._store(records)
        return True

    def _current(self) -> dict[str, ClientRecord]:
        if self._path is None:
            return self._records
        stamp = _stamp(self._path)
        if stamp != self._stamp:
            # Build the new dict before publishing it, so a reader on another
            # thread never sees it half filled.
            records = self._read() if stamp is not None else {}
            self._records = records
            self._stamp = stamp
        return self._records

    def _fresh(self) -> dict[str, ClientRecord]:
        if self._path is None:
            return dict(self._records)
        return self._read()

    def _read(self) -> dict[str, ClientRecord]:
        assert self._path is not None
        try:
            text = self._path.read_text()
        except FileNotFoundError:
            return {}
        records = {}
        for line in text.splitlines():
            record = ClientRecord.parse(line)
            if record is not None:
                records[record.pubkey] = record
        return records

    def _store(self, records: dict[str, ClientRecord]) -> None:
        if self._path is not None:
            write_private(self._path, ''.join(r.line() + '\n' for r in records.values()))
            stamp = _stamp(self._path)
        else:
            stamp = None
        # Records first: a reader that sees the new stamp must also see the new records.
        self._records = records
        self._stamp = stamp


class _Secret:
    """The connect secret: fixed by the config, or kept in a file that rotation replaces."""

    def __init__(self, fixed: str, path: Path | None):
        if not fixed and path is None:
            raise ValueError('a connection secret is required')
        self._path = None if fixed else path
        self._value = fixed
        self._stamp: tuple[int, int, int] | None = None

    @property
    def rotatable(self) -> bool:
        return self._path is not None

    def current(self) -> str:
        if self._path is not None:
            stamp = _stamp(self._path)
            if stamp is None:
                return self.rotate()
            if stamp != self._stamp:
                self._value = self._path.read_text().strip()
                self._stamp = stamp
        return self._value

    def matches(self, offered: str) -> bool:
        return hmac.compare_digest(offered.encode(), self.current().encode())

    def rotate(self) -> str:
        if self._path is None:
            raise ValueError('the secret is fixed in the config')
        value = secrets.token_urlsafe(16)
        write_private(self._path, value + '\n')
        self._value, self._stamp = value, _stamp(self._path)
        return value


class _Locks:
    """Serializes admission changes between threads, and through a lock file with the CLI."""

    def __init__(self, path: Path | None):
        self._path = path
        self._thread_lock = threading.RLock()
        self._depth = 0
        self._fd: int | None = None

    @contextmanager
    def held(self) -> Iterator[None]:
        with self._thread_lock:
            if self._depth == 0 and self._path is not None and fcntl is not None:
                if self._fd is None:
                    self._path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
                    self._fd = os.open(self._path, os.O_RDWR | os.O_CREAT, FILE_MODE)
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if self._depth == 0 and self._fd is not None and fcntl is not None:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)


class Admission:
    """Decides who may use the bunker, and remembers it.

    State lives in state_dir: the secret, the clients and pending files, and a
    lock file shared with the CLI. Without a state_dir it stays in memory and
    the secret must be fixed. Clients in authorized get in without the secret
    and are unrestricted; the list is read once, so changing it takes a restart.
    Safe to call from several threads.
    """

    def __init__(self, state_dir: Path | None, secret: str = '', rotate: bool = False,
                 approver: Approver | None = None, authorized: Iterable[str] = (),
                 on_rotate: Callable[[], None] | None = None,
                 now: Callable[[], float] = time.time):
        if rotate and secret:
            raise ValueError('a secret fixed in the config cannot rotate')

        def path(name: str) -> Path | None:
            return state_dir / name if state_dir is not None else None

        self._secret = _Secret(secret, path('secret'))
        self._clients = _RecordFile(path('clients'))
        self._pending = _RecordFile(path('pending'), PENDING_LIMIT)
        self._locks = _Locks(path('admission.lock'))
        self._rotate = rotate
        self._approver = approver
        self._authorized = frozenset(authorized)
        self._on_rotate = on_rotate
        self._now = now

    @property
    def secret(self) -> str:
        return self._secret.current()

    def admitted(self, client: str) -> bool:
        return client in self._authorized or self._clients.get(client) is not None

    def known(self, client: str) -> bool:
        """Admitted, or waiting for approval."""
        return self.admitted(client) or self._pending.get(client) is not None

    def require(self, client: str, method: str, kind: int | None = None) -> None:
        """Refuse a request the client may not make; pass the event kind for sign_event."""
        perms = self._permissions(client)
        if perms is None:
            raise AdmissionError('unauthorized')
        if not perms.allows(method, kind):
            what = f'sign_event for kind {kind}' if method == 'sign_event' else method
            log.info('%s from %s refused: not among its requested permissions', what, client)
            raise AdmissionError(f'{what} is not among the permissions this client requested')

    def connect(self, client: str, secret: str, requested: object, via: str) -> str:
        """Handle a NIP-46 connect: return 'ack' or raise AdmissionError.

        A client that already presented the secret and waits for approval is
        not asked for it again, because rotation may have replaced it since.
        """
        rotated = parked = False
        with self._locks.held():
            if self.admitted(client):
                return 'ack'
            record = self._pending.get(client)
            if record is None:
                # Compare and rotate under one lock, so one URL admits one client.
                if not self._secret.matches(secret):
                    log.warning('connect from %s with a wrong secret', client)
                    raise AdmissionError('invalid secret')
                if self._rotate:
                    self._secret.rotate()
                    rotated = True
                record = ClientRecord(client, int(self._now()), via,
                                      Permissions.requested(requested))
                if self._approver is not None:
                    self._pending.put(record)
                    parked = True
        if rotated and self._on_rotate is not None:
            self._on_rotate()
        decision = True if self._approver is None else self._approver(client, record.perms)
        if decision is None:
            if parked:
                log.warning('client %s waits for approval: keycard-nostr-bunker clients approve %s',
                            client, client)
            raise AdmissionError('pending approval')
        with self._locks.held():
            self._pending.remove(client)
            if not decision:
                log.warning('client %s refused', client)
                raise AdmissionError('connection refused')
            self._clients.put(replace(record, since=int(self._now())))
        log.info('client %s admitted, permissions: %s', client, record.perms.describe())
        return 'ack'

    def clients(self) -> list[ClientRecord]:
        """Admitted clients: the ones from the config first, then the ones admitted since."""
        config = [ClientRecord(key, None, CONFIG, Permissions(None))
                  for key in sorted(self._authorized)]
        return config + self._clients.all()

    def pending(self) -> list[ClientRecord]:
        return self._pending.all()

    def approve(self, pubkey: str) -> ClientRecord:
        """Admit a pending client, with the permissions it requested."""
        with self._locks.held():
            if pubkey in self._authorized:
                raise AdmissionError(f'{pubkey} is already admitted by '
                                     'connection.authorized_clients')
            if self._clients.get(pubkey) is not None:
                raise AdmissionError(f'{pubkey} is already admitted')
            record = self._pending.get(pubkey)
            if record is None:
                raise AdmissionError(f'{pubkey} is not waiting for approval; it has to connect '
                                     'with the secret first, or go in '
                                     'connection.authorized_clients')
            admitted = replace(record, since=int(self._now()))
            self._pending.remove(pubkey)
            self._clients.put(admitted)
        log.info('client %s approved, permissions: %s', pubkey, admitted.perms.describe())
        return admitted

    def revoke(self, pubkey: str) -> Revocation:
        """Remove a client and any pending request, and rotate the secret it knew."""
        with self._locks.held():
            removed = self._clients.remove(pubkey)
            dropped = self._pending.remove(pubkey)
            knew_secret = removed or dropped
            rotated = knew_secret and self._secret.rotatable
            if rotated:
                self._secret.rotate()
        return Revocation(removed, dropped, pubkey in self._authorized, rotated,
                          knew_secret and not self._secret.rotatable)

    def _permissions(self, client: str) -> Permissions | None:
        if client in self._authorized:
            return Permissions(None)
        record = self._clients.get(client)
        return None if record is None else record.perms
