import os
import stat

import pytest

from keycard_bunker.clients import (ClientList, Secret, SeenEvents, approve,
                                    load_or_generate_secret, new_secret, write_private)


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_in_memory():
    clients = ClientList()
    assert 'ab' not in clients and len(clients) == 0
    clients.add('ab')
    clients.add('ab')
    assert 'ab' in clients and len(clients) == 1
    assert clients.remove('ab') is True
    assert clients.remove('ab') is False
    assert 'ab' not in clients


def test_persisted_with_metadata(tmp_path):
    path = tmp_path / 'state' / 'clients'
    clients = ClientList(path)
    clients.add('cd', '1700000000 wss://relay')
    clients.add('ab')
    assert path.read_text() == 'cd 1700000000 wss://relay\nab\n'
    assert list(clients) == ['cd', 'ab']
    assert clients.items() == [('cd', '1700000000 wss://relay'), ('ab', '')]
    assert mode(path) == 0o600 and mode(path.parent) == 0o700
    assert not (tmp_path / 'state' / 'clients.tmp').exists()
    clients.remove('cd')
    assert ClientList(path).items() == [('ab', '')]


def test_limit_drops_the_oldest(tmp_path):
    pending = ClientList(tmp_path / 'pending', limit=2)
    for key in ('a', 'b', 'c'):
        pending.add(key)
    assert list(pending) == ['b', 'c']


def test_rereads_when_another_process_edits(tmp_path):
    path = tmp_path / 'clients'
    clients = ClientList(path)
    clients.add('ab')
    path.write_text('ab\nef meta\n')
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
    assert 'ef' in clients and clients.items()[1] == ('ef', 'meta')


def test_deleted_file_means_nobody(tmp_path):
    path = tmp_path / 'clients'
    clients = ClientList(path)
    clients.add('ab')
    path.unlink()
    assert 'ab' not in clients and len(clients) == 0
    clients.add('cd')
    assert path.read_text() == 'cd\n'


def test_approve_moves_from_pending(tmp_path):
    clients = ClientList(tmp_path / 'clients')
    pending = ClientList(tmp_path / 'pending')
    pending.add('ab', '1 wss://r')
    assert approve('ab', clients, pending) is True
    assert 'ab' in clients and 'ab' not in pending
    assert clients.items()[0][1].endswith(' approved')
    assert approve('cd', clients, pending) is False
    assert 'cd' in clients


def test_seen_events_record_and_reload(tmp_path):
    path = tmp_path / 'seen'
    clock = [1_000_000]
    seen = SeenEvents(path, max_age=100, now=lambda: clock[0])
    seen.record('old', 999_890)
    seen.record('new', 999_990)
    assert 'old' in seen and 'new' in seen
    assert mode(path) == 0o600
    clock[0] = 1_000_050
    reloaded = SeenEvents(path, max_age=100, now=lambda: clock[0])
    assert 'new' in reloaded and 'old' not in reloaded
    assert path.read_text() == 'new 999990\n'


def test_seen_events_limit():
    seen = SeenEvents(limit=2)
    for i in range(3):
        seen.record(str(i), i)
    assert '0' not in seen and '2' in seen and len(seen) == 2


def test_secret_fixed():
    secret = Secret('abc')
    assert secret.current == 'abc' and not secret.rotatable
    with pytest.raises(ValueError):
        secret.rotate()


def test_secret_file_rotation_and_reload(tmp_path):
    path = tmp_path / 'state' / 'secret'
    secret = Secret(path=path)
    first = secret.current
    assert len(first) >= 16 and mode(path) == 0o600
    assert Secret(path=path).current == first
    other = Secret(path=path)
    rotated = other.rotate()
    assert rotated != first and secret.current == rotated
    path.unlink()
    assert secret.current not in (first, rotated) and path.exists()


def test_secret_requires_a_value_or_path():
    with pytest.raises(ValueError):
        Secret()


def test_secret_generated_once(tmp_path):
    path = tmp_path / 'state' / 'secret'
    secret = load_or_generate_secret(path)
    assert load_or_generate_secret(path) == secret
    assert new_secret(path) != secret


def test_write_private_is_atomic_and_private(tmp_path):
    path = tmp_path / 'dir' / 'file'
    write_private(path, 'x\n')
    assert path.read_text() == 'x\n' and mode(path) == 0o600 and mode(path.parent) == 0o700
    assert list(path.parent.iterdir()) == [path]
