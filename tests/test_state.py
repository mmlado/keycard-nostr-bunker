import stat

from keycard_nostr_bunker.state import SeenEvents, write_private


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_write_private_is_atomic_and_private(tmp_path):
    path = tmp_path / 'dir' / 'file'
    write_private(path, 'x\n')
    assert path.read_text() == 'x\n' and mode(path) == 0o600 and mode(path.parent) == 0o700
    assert list(path.parent.iterdir()) == [path]


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
