import stat

from keycard_nostr_bunker import schnorr
from keycard_nostr_bunker.cli import warn_if_open
from keycard_nostr_bunker.signer import SoftwareSigner


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_bunker_key_is_private_in_a_private_directory(tmp_path):
    path = tmp_path / 'state' / 'signer.key'
    signer = SoftwareSigner.load_or_generate(path)
    assert mode(path) == 0o600 and mode(path.parent) == 0o700
    assert SoftwareSigner.load_or_generate(path).pubkey == signer.pubkey
    assert signer.pubkey == schnorr.pubkey(bytes.fromhex(path.read_text().strip()))


def test_an_open_state_directory_is_reported_and_left_alone(tmp_path, caplog):
    open_dir = tmp_path / 'shared'
    open_dir.mkdir(mode=0o755)
    open_dir.chmod(0o755)
    warn_if_open(open_dir)
    assert 'chmod 700' in caplog.text and mode(open_dir) == 0o755
    caplog.clear()
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    warn_if_open(private)
    assert caplog.text == ''
