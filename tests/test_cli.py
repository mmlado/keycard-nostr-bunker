import pytest

from keycard_nostr_bunker.cli import build_parser, main
from keycard_nostr_bunker.signer import SoftwareSigner

PUBKEY = 'ab' * 32


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
    assert main(['clients', 'approve', PUBKEY, *c]) == 0
    assert main(['clients', 'list', *c]) == 0
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[:3] == ['No admitted clients', 'No clients waiting for approval',
                       f'Approved {PUBKEY}, which was not waiting for approval']
    assert out[3].startswith(f'{PUBKEY}  20') and out[3].endswith('approved')
    assert out[4] == f'Revoked {PUBKEY}'
    assert out[5] == 'Secret rotated; the running bunker uses the new one at once.'
    assert out[6] == f'{PUBKEY} was not an admitted client'


def test_revoke_rotates_the_generated_secret(tmp_path, capsys):
    c = config(tmp_path, '[relay]\nurls = ["wss://r"]\n')
    SoftwareSigner.generate().save(tmp_path / 'signer.key')
    assert main(['url', *c]) == 0
    first = capsys.readouterr().out.strip()
    assert first.startswith('bunker://') and '&secret=' in first
    main(['clients', 'approve', PUBKEY, *c])
    assert main(['clients', 'revoke', PUBKEY, *c]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[-1].startswith('bunker://') and out[-1] != first
    assert (tmp_path / 'secret').read_text().strip() in out[-1]


def test_revoke_warns_when_the_secret_is_fixed(tmp_path, caplog):
    c = config(tmp_path, '[connection]\nsecret = "fixed"\n')
    main(['clients', 'approve', PUBKEY, *c])
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
    main(['clients', 'approve', PUBKEY, *c])
    capsys.readouterr()
    assert main(['clients', 'list', *c]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert rows[0] == f'{other}  from the config' and rows[1].startswith(PUBKEY)
    assert main(['clients', 'revoke', other, *c]) == 1
    assert 'remove it from the config' in capsys.readouterr().out
