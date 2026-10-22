import logging
import sys

import pytest

from keycard_nostr_bunker import cli
from keycard_nostr_bunker.admission import Admission, AdmissionError, defer
from keycard_nostr_bunker.cli import build_parser, main
from keycard_nostr_bunker.configure import SetupCancelled
from keycard_nostr_bunker.state import StateDir
from keycard_nostr_bunker.signer import SoftwareSigner

PUBKEY = 'ab' * 32


def ask(tmp_path, pubkey=PUBKEY, perms='', secret=None):
    """Park a client the way the bunker does when approval is on."""
    bunker = Admission(StateDir(tmp_path), secret=secret or '', approver=defer)
    with pytest.raises(AdmissionError, match='pending approval'):
        bunker.connect(pubkey, secret or bunker.secret, perms, 'wss://relay.example')


def parse(argv):
    return build_parser().parse_args(argv)


def config(tmp_path, extra=''):
    path = tmp_path / 'config.toml'
    path.write_text(f'[signer]\nkey_file = "{tmp_path}/signer.key"\n{extra}')
    path.chmod(0o600)
    return ['-c', str(path)]


def test_default_is_run():
    args = parse([])
    assert args.command is None and not hasattr(args, 'config')


def test_global_options_before_or_after_subcommand():
    assert parse(['-c', 'x.toml', 'run', '--no-card']).config == 'x.toml'
    assert parse(['run', '-c', 'x.toml']).config == 'x.toml'
    assert parse(['-v', 'clients', 'list']).verbose is True
    assert parse(['clients', 'list', '-v']).verbose is True
    assert parse(['-c', 'x.toml', 'service', 'install']).config == 'x.toml'
    assert parse(['url', '-c', 'x.toml']).command == 'url'


def test_subcommands():
    args = parse(['clients', 'approve', PUBKEY])
    assert (args.command, args.action, args.pubkey) == ('clients', 'approve', PUBKEY)
    assert parse(['service', 'uninstall']).action == 'uninstall'
    assert parse(['readers']).command == 'readers'


@pytest.mark.parametrize('argv', [['clients'], ['service'], ['clients', 'approve'],
                                  ['clients', 'approve', 'abc'], ['bogus']])
def test_rejected(argv):
    with pytest.raises(SystemExit):
        parse(argv)


def test_clients_round_trip(tmp_path, capsys):
    c = config(tmp_path)
    assert main(['clients', 'list', *c]) == 0
    assert main(['clients', 'pending', *c]) == 0
    ask(tmp_path, perms='sign_event:1')
    assert main(['clients', 'pending', *c]) == 0
    assert main(['clients', 'approve', PUBKEY, *c]) == 0
    assert main(['clients', 'list', *c]) == 0
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[:2] == ['No admitted clients', 'No clients waiting for approval']
    assert out[2].startswith(f'{PUBKEY}  20') and out[2].endswith(
        'via wss://relay.example  requested: sign_event:1')
    assert out[3] == f'Approved {PUBKEY}, requested: sign_event:1'
    assert out[4].startswith(f'{PUBKEY}  20') and out[4].endswith('requested: sign_event:1')
    assert out[5] == f'Revoked {PUBKEY}'
    assert out[6] == 'Secret rotated; the running bunker uses the new one at once.'
    assert out[7] == f'{PUBKEY} was not an admitted client'


def test_approve_refuses_a_client_that_never_asked(tmp_path, capsys):
    c = config(tmp_path)
    assert main(['clients', 'approve', PUBKEY, *c]) == 1
    assert 'is not waiting for approval' in capsys.readouterr().out
    assert main(['clients', 'list', *c]) == 0
    assert capsys.readouterr().out.strip() == 'No admitted clients'


def test_revoke_rotates_the_generated_secret(tmp_path, capsys):
    c = config(tmp_path, '[relay]\nurls = ["wss://r"]\n')
    SoftwareSigner.generate().save(tmp_path / 'signer.key')
    assert main(['url', *c]) == 0
    first = capsys.readouterr().out.strip()
    assert first.startswith('bunker://') and '&secret=' in first
    ask(tmp_path)
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == f'Dropped the pending request from {PUBKEY}'
    assert out[-1].startswith('bunker://') and out[-1] != first
    assert (tmp_path / 'secret').read_text().strip() in out[-1]


def test_revoke_warns_when_the_secret_is_fixed(tmp_path, caplog):
    c = config(tmp_path, '[connection]\nsecret = "fixed"\n')
    ask(tmp_path, secret='fixed')
    assert main(['clients', 'approve', PUBKEY, *c]) == 0
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    assert 'fixed in the config' in caplog.text


def test_url_needs_a_signer_key(tmp_path, caplog):
    assert main(['url', *config(tmp_path)]) == 1
    assert 'run the bunker once' in caplog.text


def test_explicit_missing_config_is_an_error(tmp_path, caplog):
    assert main(['clients', 'list', '-c', str(tmp_path / 'nope.toml')]) == 1
    assert 'does not exist' in caplog.text


def test_bad_config_reported(tmp_path, caplog):
    path = tmp_path / 'config.toml'
    path.write_text('[signing]\npolicy = "nope"\n')
    assert main(['clients', 'list', '-c', str(path)]) == 1
    assert 'signing.policy' in caplog.text


def test_clients_from_the_config(tmp_path, capsys):
    other = 'cd' * 32
    c = config(tmp_path, f'[connection]\nauthorized_clients = ["{other}"]\n')
    ask(tmp_path)
    main(['clients', 'approve', PUBKEY, *c])
    capsys.readouterr()
    assert main(['clients', 'list', *c]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert rows[0] == f'{other}  from the config' and rows[1].startswith(PUBKEY)
    assert main(['clients', 'approve', other, *c]) == 1
    assert 'already admitted by connection.authorized_clients' in capsys.readouterr().out
    assert main(['clients', 'revoke', other, *c]) == 1
    assert 'remove it there and restart the bunker' in capsys.readouterr().out


def record(msg, *args, exc_info=None):
    return logging.LogRecord('keycard_nostr_bunker', logging.INFO, __file__, 1, msg, args, exc_info)


def test_log_lines_escape_control_characters():
    formatter = cli.EscapingFormatter(cli.LOG_FORMAT)
    line = formatter.format(record('NIP-46 %s -> ok', 'ping\x1b[2J\n12:00:00 [INFO] fake'))
    assert '\x1b' not in line and '\n' not in line
    assert line.endswith('NIP-46 ping\\x1b[2J\\n12:00:00 [INFO] fake -> ok')


def test_tracebacks_keep_their_lines_but_not_escapes():
    try:
        raise ValueError('bad\x1b]52;c;x\x07')
    except ValueError:
        failed = record('failed', exc_info=sys.exc_info())
    text = cli.EscapingFormatter(cli.LOG_FORMAT).format(failed)
    assert text.count('\n') >= 3 and '\x1b' not in text and '\x07' not in text
    assert "ValueError: bad\\x1b]52;c;x\\x07" in text


@pytest.fixture
def no_config(tmp_path, monkeypatch):
    """The default config location, empty: a first run."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    started = []
    monkeypatch.setattr(cli, 'run_bunker', lambda cfg, path, no_card: started.append(cfg) or 0)
    return tmp_path / 'xdg' / 'keycard-nostr-bunker' / 'config.toml', started


def test_first_run_without_a_terminal_writes_the_template(no_config, caplog):
    path, started = no_config
    assert main([]) == 0
    assert 'wrote the default one' in caplog.text and path.exists()
    assert started[0].relay.urls == ['wss://nos.lol', 'wss://relay.primal.net']


def test_first_run_in_a_terminal_asks(no_config, monkeypatch):
    path, started = no_config
    monkeypatch.setattr(cli, 'interactive', lambda: True)
    monkeypatch.setattr(cli, 'setup', lambda p: p.parent.mkdir(parents=True) or
                        p.write_text('[connection]\napprove_clients = true\n'))
    assert main(['run']) == 0
    assert started[0].connection.approve_clients


def test_cancelled_first_run_does_not_start(no_config, monkeypatch):
    path, started = no_config
    monkeypatch.setattr(cli, 'interactive', lambda: True)

    def cancel(p):
        raise SetupCancelled()

    monkeypatch.setattr(cli, 'setup', cancel)
    assert main(['run']) == 1 and started == [] and not path.exists()


def test_other_commands_need_a_config(no_config, caplog):
    path, started = no_config
    assert main(['url']) == 1
    assert 'run `keycard-nostr-bunker init`' in caplog.text and not path.exists()


def test_init_needs_a_terminal(no_config, caplog):
    assert main(['init']) == 1
    assert 'needs a terminal' in caplog.text
