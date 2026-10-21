import stat
import time

from keycard_nostr_bunker.replay import ReplayWindow
from keycard_nostr_bunker.state import StateDir, write_private


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_write_private_is_atomic_and_private(tmp_path):
    path = tmp_path / 'dir' / 'file'
    write_private(path, 'x\n')
    assert path.read_text() == 'x\n' and mode(path) == 0o600 and mode(path.parent) == 0o700
    assert list(path.parent.iterdir()) == [path]


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
    ReplayWindow(state.seen).admit('id', int(time.time()), known=True)
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
