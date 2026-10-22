import stat
import tomllib
from dataclasses import fields

import pytest

from keycard_nostr_bunker.config import USUAL_KINDS, Config, load_config
from keycard_nostr_bunker.configure import (SetupCancelled, render, setup, template,
                                            write_template)

DEV_CA = '0317830be73e60535a18b9ebac1795d5247ad66073c943ece13fd05cd2ae7a3388'


def answers(*replies):
    """An input() stand-in that gives the replies in order and records the questions."""
    asked = []
    queue = list(replies)

    def ask(question):
        asked.append(question)
        if not queue:
            raise EOFError
        return queue.pop(0)

    ask.asked = asked
    return ask


def run_setup(path, *replies, pins=()):
    told = []
    setup(path, answers(*replies), answers(*pins), told.append)
    return told


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_template_holds_every_setting_with_the_defaults(tmp_path):
    data = tomllib.loads(template())
    for section in fields(Config):
        keys = {f.name for f in fields(section.default_factory())}
        assert set(data[section.name]) == keys, section.name
    path = tmp_path / 'config.toml'
    write_template(path)
    cfg, default = load_config(path), Config()
    cfg.signer.key_file = default.signer.key_file = ''
    assert cfg == default and mode(path) == 0o600


def test_render_replaces_only_the_named_line():
    text = render({'connection': {'approve_clients': True}, 'relay': {'urls': ['wss://x']}})
    data = tomllib.loads(text)
    assert data['connection']['approve_clients'] is True and data['relay']['urls'] == ['wss://x']
    assert text.count('\n') == template().count('\n')
    with pytest.raises(KeyError):
        render({'relay': {'nope': 1}})


def test_first_setup_with_every_default(tmp_path):
    path = tmp_path / 'sub' / 'config.toml'
    told = run_setup(path, '', '', '', '', '')
    cfg = load_config(path)
    assert cfg.relay.urls == ['wss://nos.lol', 'wss://relay.primal.net']
    assert cfg.signing.policy == 'allowed_kinds'
    assert cfg.signing.allowed_kinds == list(USUAL_KINDS)
    assert cfg.keycard.trust_test_ca and cfg.keycard.ca_public_keys == []
    assert not cfg.connection.approve_clients and cfg.connection.rotate_secret
    assert '# Derivation path of the Nostr key' in path.read_text()
    assert mode(path) == 0o600 and mode(path.parent) == 0o700
    assert not (tmp_path / 'sub' / 'pin').exists()
    assert told[-1] == f'Wrote {path}'


def test_every_answer_given(tmp_path):
    path = tmp_path / 'config.toml'
    run_setup(path, 'wss://A.example/ ws://b.example:8080, wss://a.example', '2', '3', DEV_CA,
              'y', 'y', pins=('123456', '123456'))
    cfg = load_config(path)
    assert cfg.relay.urls == ['wss://a.example', 'ws://b.example:8080']
    assert cfg.signing.policy == 'all'
    assert not cfg.keycard.trust_test_ca and cfg.keycard.ca_public_keys == [DEV_CA]
    assert cfg.connection.approve_clients
    pin = tmp_path / 'pin'
    assert pin.read_text() == '123456\n' and mode(pin) == 0o600
    assert '123456' not in path.read_text()


def test_bad_answers_are_asked_again(tmp_path):
    path = tmp_path / 'config.toml'
    told = run_setup(path, 'https://x', 'wss://ok.example', '9', '1', '3', 'abcd', DEV_CA,
                     'maybe', 'n', 'y', pins=('12345', '123456', '654321', '123456', '123456'))
    cfg = load_config(path)
    assert cfg.relay.urls == ['wss://ok.example'] and cfg.keycard.ca_public_keys == [DEV_CA]
    assert "'https://x' is not a ws:// or wss:// URL" in told
    assert 'Answer one of 1, 2' in told
    assert 'The PIN is 6 digits' in told and 'The two PINs differ' in told
    assert (tmp_path / 'pin').read_text() == '123456\n'


def test_rerun_keeps_what_it_does_not_ask_and_backs_up(tmp_path):
    path = tmp_path / 'config.toml'
    old = ('[relay]\nurls = ["wss://mine.example"]\n'
           '[keycard]\nkey_path = "m/44\'/1237\'/0\'/0/0"\nca_public_keys = ["' + DEV_CA + '"]\n'
           '[signer]\nkey_file = "~/somewhere/signer.key"\n'
           '[signing]\nallowed_kinds = [1, 7]\n'
           '[connection]\nsecret = "fixed"\napprove_clients = true\n'
           'authorized_clients = ["' + 'ab' * 32 + '"]\n')
    path.write_text(old)
    path.chmod(0o600)
    ask = answers('', '', '', '', '', '')
    setup(path, ask, answers(), lambda text: None)
    assert '[wss://mine.example]' in ask.asked[0]
    assert ask.asked[1] == 'Choice [3]: ' and ask.asked[2] == 'Choice [3]: '
    assert ask.asked[3].endswith(f'[{DEV_CA}]: ') and ask.asked[4].endswith('[Y/n]: ')
    cfg = load_config(path)
    assert cfg.relay.urls == ['wss://mine.example']
    assert cfg.signing.allowed_kinds == [1, 7] and cfg.keycard.ca_public_keys == [DEV_CA]
    assert cfg.keycard.key_path == "m/44'/1237'/0'/0/0"
    assert cfg.connection.secret == 'fixed' and not cfg.connection.rotate_secret
    assert cfg.connection.approve_clients
    assert cfg.connection.authorized_clients == ['ab' * 32]
    assert 'key_file = "~/somewhere/signer.key"' in path.read_text()
    [backup] = tmp_path.glob('config.toml.*.bak')
    assert backup.read_text() == old and mode(backup) == 0o600


def test_a_stored_pin_is_kept_unless_replaced(tmp_path):
    path = tmp_path / 'config.toml'
    (tmp_path / 'pin').write_text('111111\n')
    run_setup(path, '', '', '', '', '')
    assert (tmp_path / 'pin').read_text() == '111111\n'
    run_setup(path, '', '', '', '', 'n', pins=('222222', '222222'))
    assert (tmp_path / 'pin').read_text() == '222222\n'


def test_leaving_writes_nothing(tmp_path):
    path = tmp_path / 'config.toml'
    with pytest.raises(SetupCancelled):
        run_setup(path, 'wss://a.example', '1')
    assert list(tmp_path.iterdir()) == []
