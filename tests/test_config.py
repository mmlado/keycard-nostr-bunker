from pathlib import Path

import pytest

from keycard_bunker.config import DEFAULT_KEY_PATH, load_config, validate_key_path


def write(tmp_path, text, mode=0o600):
    path = tmp_path / 'config.toml'
    path.write_text(text)
    path.chmod(mode)
    return path


def test_defaults_when_missing(tmp_path):
    cfg = load_config(tmp_path / 'none.toml')
    assert cfg.relay.urls == ['wss://relay.damus.io']
    assert cfg.keycard.key_path == DEFAULT_KEY_PATH
    assert cfg.keycard.trust_test_ca is False
    assert cfg.signing.policy == 'allowed_kinds' and cfg.signing.allowed_kinds == [1]
    assert cfg.signer.key_file == str(Path('~/.config/keycard-bunker/signer.key').expanduser())


def test_parse(tmp_path):
    path = write(tmp_path, '''
[relay]
urls = ["wss://a", "wss://b"]
[keycard]
pin = "123456"
reader = "ACS"
key_path = "m/44'/1237'/0'/0/0"
trust_test_ca = true
ca_public_keys = ["0317830be73e60535a18b9ebac1795d5247ad66073c943ece13fd05cd2ae7a3388"]
[signer]
key_file = "/tmp/x.key"
[signing]
policy = "all"
allowed_kinds = [0, 1, 3]
[connection]
secret = "abc"
approve_clients = true
''')
    cfg = load_config(path)
    assert cfg.relay.urls == ['wss://a', 'wss://b']
    assert cfg.keycard.pin == '123456' and cfg.keycard.reader == 'ACS'
    assert cfg.keycard.key_path == "m/44'/1237'/0'/0/0"
    assert cfg.keycard.trust_test_ca is True
    assert len(cfg.keycard.ca_public_keys) == 1
    assert cfg.signer.key_file == '/tmp/x.key'
    assert cfg.signing.policy == 'all' and cfg.signing.allowed_kinds == [0, 1, 3]
    assert cfg.connection.secret == 'abc'
    assert cfg.connection.approve_clients is True and cfg.connection.rotate_secret is False


def test_invalid_policy(tmp_path):
    with pytest.raises(ValueError, match='signing.policy'):
        load_config(write(tmp_path, '[signing]\npolicy = "interactive"\n'))


def test_rotate_needs_generated_secret(tmp_path):
    with pytest.raises(ValueError, match='rotate_secret'):
        load_config(write(tmp_path, '[connection]\nsecret = "fixed"\nrotate_secret = true\n'))
    cfg = load_config(write(tmp_path, '[connection]\nrotate_secret = true\n'))
    assert cfg.connection.rotate_secret


@pytest.mark.parametrize('text,message', [
    ('[approval]\nmode = "always"\n', r'unknown section \[approval\]'),
    ('[connection]\naprove_clients = true\n', 'unknown key connection.aprove_clients'),
    ('[keycard]\ntrust_test_ca = "false"\n', 'keycard.trust_test_ca must be true or false'),
    ('[keycard]\npin = 123456\n', 'keycard.pin must be a string, write it in quotes'),
    ('[signing]\nallowed_kinds = ["1"]\n', 'signing.allowed_kinds must be a list of integers'),
    ('[relay]\nurls = "wss://a"\n', 'relay.urls must be a list of strings'),
    ('[relay]\nurls = ["https://a"]\n', 'not a ws:// or wss:// URL'),
    ('[keycard]\nca_public_keys = ["abcd"]\n', 'ca_public_keys'),
    ('[keycard]\nkey_path = "m/44\'/60\'/0\'/0/0"\n', 'key_path must be under'),
    ('[keycard]\nkey_path = "m/44\'/1237\'/0\'"\n', 'key_path must be under'),
    ('relay = 1\n', r'\[relay\] must be a table'),
])
def test_rejected_config(tmp_path, text, message):
    with pytest.raises(ValueError, match=message):
        load_config(write(tmp_path, text))


@pytest.mark.parametrize('path', ["m/44'/1237'/0'/0/0", "m/43'/60'/1581'/0'/0",
                                  "m/43'/60'/1581'/1'/5/7"])
def test_valid_key_paths(path):
    validate_key_path(path)


def test_relative_key_file_is_next_to_the_config(tmp_path):
    cfg = load_config(write(tmp_path, '[signer]\nkey_file = "state/signer.key"\n'))
    assert cfg.signer.key_file == str(tmp_path / 'state' / 'signer.key')


def test_secrets_need_a_private_config(tmp_path):
    with pytest.raises(ValueError, match='chmod 600'):
        load_config(write(tmp_path, '[keycard]\npin = "123456"\n', mode=0o644))
    with pytest.raises(ValueError, match='chmod 600'):
        load_config(write(tmp_path, '[connection]\nsecret = "s"\n', mode=0o640))
    assert load_config(write(tmp_path, '[keycard]\npin = "123456"\n')).keycard.pin == '123456'
    assert load_config(write(tmp_path, '[relay]\nurls = ["wss://a"]\n', mode=0o644))
