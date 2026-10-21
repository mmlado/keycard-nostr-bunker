"""Install the bunker as a systemd user service."""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

UNIT_NAME = 'keycard-nostr-bunker.service'
PIN_FILE = 'pin'

Runner = Callable[..., Any]


def unit_dir() -> Path:
    base = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    return base / 'systemd' / 'user'


def unit_path() -> Path:
    return unit_dir() / UNIT_NAME


def executable() -> Path:
    """The keycard-nostr-bunker command this process was started as."""
    candidate = Path(sys.argv[0])
    if candidate.name == 'keycard-nostr-bunker' and candidate.exists():
        return candidate.resolve()
    sibling = Path(sys.executable).with_name('keycard-nostr-bunker')
    if sibling.exists():
        return sibling.resolve()
    found = shutil.which('keycard-nostr-bunker')
    if found:
        return Path(found).resolve()
    raise FileNotFoundError('keycard-nostr-bunker command not found on PATH')


def pin_file(config: Path) -> Path:
    return config.with_name(PIN_FILE)


def _quote(path: Path) -> str:
    """A systemd command-line argument: quoted, with specifiers escaped."""
    text = str(path).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    return f'"{text}"'


def unit_text(exe: Path, config: Path, credential: Path | None) -> str:
    load = ''
    if credential:
        load = f'LoadCredential={PIN_FILE}:{str(credential).replace("%", "%%")}\n'
    return (
        '[Unit]\n'
        'Description=keycard-nostr-bunker NIP-46 remote signer\n'
        'After=network-online.target\n'
        'Wants=network-online.target\n'
        '\n'
        '[Service]\n'
        f'ExecStart={_quote(exe)} run --config {_quote(config)}\n'
        f'{load}'
        'Restart=always\n'
        'RestartSec=5\n'
        '\n'
        '[Install]\n'
        'WantedBy=default.target\n'
    )


def install(config: Path, run: Runner = subprocess.run) -> Path:
    """Write the unit for this config, then enable and start it."""
    config = config.resolve()
    if not config.exists():
        raise FileNotFoundError(f'{config} does not exist')
    credential = pin_file(config)
    path = unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(unit_text(executable(), config,
                              credential if credential.exists() else None))
    _systemctl(run, 'daemon-reload')
    _systemctl(run, 'enable', '--now', UNIT_NAME)
    return path


def uninstall(run: Runner = subprocess.run) -> bool:
    """Stop and disable the service and remove the unit; False if not installed."""
    path = unit_path()
    if not path.exists():
        return False
    run(['systemctl', '--user', 'disable', '--now', UNIT_NAME])
    path.unlink()
    _systemctl(run, 'daemon-reload')
    return True


def _systemctl(run: Runner, *args: str) -> None:
    run(['systemctl', '--user', *args], check=True)
