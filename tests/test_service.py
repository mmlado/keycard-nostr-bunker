from pathlib import Path

import pytest

from keycard_bunker import service


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(service, 'executable', lambda: Path('/opt/venv/bin/keycard-bunker'))
    config = tmp_path / 'keycard-bunker' / 'config.toml'
    config.parent.mkdir()
    config.write_text('[relay]\nurls = ["wss://r"]\n')
    calls = []

    def run(cmd, check=False):
        calls.append(cmd)

    return tmp_path, config, calls, run


def test_unit_text_without_credential():
    text = service.unit_text(Path('/x/keycard-bunker'), Path('/c/config.toml'), None)
    assert 'ExecStart="/x/keycard-bunker" run --config "/c/config.toml"\n' in text
    assert 'LoadCredential' not in text
    assert 'Restart=always' in text and 'WantedBy=default.target' in text


def test_unit_text_quotes_awkward_paths():
    text = service.unit_text(Path('/my apps/bin/keycard-bunker'), Path('/c d/100%/config.toml'),
                             Path('/c d/100%/pin'))
    assert 'ExecStart="/my apps/bin/keycard-bunker" run --config "/c d/100%%/config.toml"\n' in text
    assert 'LoadCredential=pin:/c d/100%%/pin\n' in text


def test_install_writes_unit_and_enables(env):
    tmp_path, config, calls, run = env
    path = service.install(config, run)
    assert path == tmp_path / 'xdg' / 'systemd' / 'user' / 'keycard-bunker.service'
    text = path.read_text()
    assert f'ExecStart="/opt/venv/bin/keycard-bunker" run --config "{config}"\n' in text
    assert 'LoadCredential' not in text
    assert calls == [['systemctl', '--user', 'daemon-reload'],
                     ['systemctl', '--user', 'enable', '--now', 'keycard-bunker.service']]


def test_install_passes_pin_file_as_credential(env):
    tmp_path, config, calls, run = env
    (config.parent / 'pin').write_text('123456\n')
    text = service.install(config, run).read_text()
    assert f'LoadCredential=pin:{config.parent / "pin"}\n' in text


def test_install_needs_config(env):
    tmp_path, config, calls, run = env
    with pytest.raises(FileNotFoundError):
        service.install(tmp_path / 'missing.toml', run)
    assert calls == []


def test_uninstall(env):
    tmp_path, config, calls, run = env
    assert service.uninstall(run) is False
    path = service.install(config, run)
    calls.clear()
    assert service.uninstall(run) is True
    assert not path.exists()
    assert calls == [['systemctl', '--user', 'disable', '--now', 'keycard-bunker.service'],
                     ['systemctl', '--user', 'daemon-reload']]
