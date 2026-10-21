import stat
import time

from keycard_nostr_bunker.state import SeenEvents, StateDir, write_private


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
    seen.record('old', 999_910)
    seen.record('new', 999_990)
    assert 'old' in seen and 'new' in seen
    assert mode(path) == 0o600
    clock[0] = 1_000_050
    reloaded = SeenEvents(path, max_age=100, now=lambda: clock[0])
    assert 'new' in reloaded and 'old' not in reloaded
    assert path.read_text() == 'new 999990\n'


def test_seen_events_limit():
    seen = SeenEvents(limit=2, now=lambda: 1_000_000)
    for i in range(3):
        seen.record(str(i), 1_000_000 + i)
    assert '0' not in seen and '2' in seen and len(seen) == 2


def test_seen_file_is_compacted_and_stays_bounded(tmp_path):
    from keycard_nostr_bunker.state import COMPACT_SLACK
    path = tmp_path / 'seen'
    clock = [1_000_000]
    seen = SeenEvents(path, max_age=100, limit=10, now=lambda: clock[0])
    for i in range(2000):
        clock[0] += 1
        seen.record(f'id{i}', clock[0])
        assert len(path.read_text().splitlines()) <= 2 * 10 + COMPACT_SLACK
    assert 'id1999' in seen and 'id0' not in seen and len(seen) == 10


def test_seen_file_tracks_the_live_window(tmp_path):
    from keycard_nostr_bunker.state import COMPACT_SLACK
    path = tmp_path / 'seen'
    clock = [1_000_000]
    seen = SeenEvents(path, max_age=100, now=lambda: clock[0])
    for i in range(3000):
        clock[0] += 1
        seen.record(f'id{i}', clock[0])
        assert len(path.read_text().splitlines()) <= 2 * 101 + COMPACT_SLACK
    assert len(seen) <= 101


def test_expired_ids_leave_memory_at_once_and_the_file_on_reload(tmp_path):
    path = tmp_path / 'seen'
    clock = [1_000_000]
    seen = SeenEvents(path, max_age=100, now=lambda: clock[0])
    seen.record('old', clock[0])
    clock[0] += 1000
    seen.record('new', clock[0])
    assert 'old' not in seen and 'new' in seen
    reloaded = SeenEvents(path, max_age=100, now=lambda: clock[0])
    assert 'old' not in reloaded and 'old' not in path.read_text() and 'new' in reloaded


def test_load_keeps_only_the_newest_ids(tmp_path):
    path = tmp_path / 'seen'
    path.write_text(''.join(f'id{i} 1000000\n' for i in range(50)))
    seen = SeenEvents(path, max_age=100, limit=5, now=lambda: 1_000_000)
    assert len(seen) == 5 and 'id49' in seen and 'id0' not in seen
    assert len(path.read_text().splitlines()) == 5


def test_layout_names_every_file_once(tmp_path):
    state = StateDir.for_signer_key(tmp_path / 'keys' / 'bunker.key')
    assert state.path == tmp_path / 'keys' and state.signer_key.name == 'bunker.key'
    names = [path.name for path in state.files()]
    assert len(names) == len(set(names))
    assert all(path.parent == state.path for path in state.files())


def test_every_file_the_bunker_writes_is_in_the_layout(tmp_path):
    from keycard_nostr_bunker.admission import Admission, AdmissionError, defer
    from keycard_nostr_bunker.signer import SoftwareSigner
    state = StateDir(tmp_path / 'state')
    SoftwareSigner.load_or_generate(state.signer_key)
    admission = Admission(state, approver=defer)
    try:
        admission.connect('a' * 64, admission.secret, 'sign_event:1', 'wss://relay.example')
    except AdmissionError:
        pass
    admission.approve('a' * 64)
    SeenEvents(state.seen).record('id', int(time.time()))
    written = set(state.path.iterdir())
    assert written and written <= set(state.files())


def test_open_to_others(tmp_path):
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    assert StateDir(shared).open_to_others()
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    assert not StateDir(private).open_to_others()
    assert not StateDir(tmp_path / 'missing').open_to_others()
