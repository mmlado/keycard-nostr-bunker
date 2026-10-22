"""The config file: the template shipped with the package, and the setup that fills it in.

pip cannot run code at install time, so the file is written on first run: filled
in by a few questions in a terminal, or the template as it is otherwise.
"""

import getpass
import json
import os
import re
import time
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from .config import USUAL_KINDS, Config, KeycardConfig, SigningConfig, load_config
from .config import normalize_relay_url
from .service import pin_file
from .state import write_private

TEMPLATE = 'config.example.toml'
PIN = re.compile(r'\d{6}')
CA_KEY = re.compile(r'0[23][0-9a-f]{64}')

Ask = Callable[[str], str]
Say = Callable[[str], None]


class SetupCancelled(Exception):
    """The user left the setup; nothing was written."""


def template() -> str:
    return resources.files(__package__).joinpath(TEMPLATE).read_text()


def write_template(path: Path) -> None:
    write_private(path, template())


def render(values: dict[str, dict[str, Any]], text: str | None = None) -> str:
    """The template with the `key = value` line of each given section and key replaced."""
    text = template() if text is None else text
    for section, keys in values.items():
        for key, value in keys.items():
            text = _set(text, section, key, value)
    return text


def setup(path: Path, ask: Ask = input, secret: Ask = getpass.getpass,
          say: Say = print) -> None:
    """Ask the few settings that differ between users and write the config to path.

    An existing config supplies the defaults and keeps every other setting; it is
    backed up first. Raises SetupCancelled on end of input or Ctrl-C.
    """
    try:
        _setup(path, ask, secret, say)
    except (EOFError, KeyboardInterrupt):
        raise SetupCancelled() from None


def _setup(path: Path, ask: Ask, secret: Ask, say: Say) -> None:
    existing = tomllib.loads(path.read_text()) if path.exists() else {}
    current = load_config(path) if path.exists() else Config()
    values = {section: dict(keys) for section, keys in existing.items()}
    connection = values.setdefault('connection', {})
    # The template rotates the secret, which a secret fixed in the old config cannot do.
    if connection.get('secret') and 'rotate_secret' not in connection:
        connection['rotate_secret'] = False

    say(f'Setting up {path}. Press Enter to keep the value in brackets.\n')
    values.setdefault('relay', {})['urls'] = _relays(ask, say, current.relay.urls)
    values.setdefault('signing', {}).update(_signing(ask, say, current.signing, bool(existing)))
    values.setdefault('keycard', {}).update(_certificate(ask, say, current.keycard,
                                                         bool(existing)))
    connection['approve_clients'] = _yes(
        ask, 'Ask before admitting a new client?', current.connection.approve_clients)
    pin = _pin(ask, secret, say, pin_file(path))

    text = render(values)
    candidate = path.with_name(path.name + '.new')
    write_private(candidate, text)
    try:
        load_config(candidate)
    except ValueError:
        candidate.unlink()
        raise
    if path.exists():
        backup = path.with_name(f'{path.name}.{time.strftime("%Y%m%d-%H%M%S")}.bak')
        write_private(backup, path.read_text())
        say(f'Old config kept as {backup}')
    os.replace(candidate, path)
    say(f'Wrote {path}')
    if pin:
        write_private(pin_file(path), pin + '\n')
        say(f'Wrote the PIN to {pin_file(path)}, for `keycard-nostr-bunker service install`')


def _relays(ask: Ask, say: Say, default: list[str]) -> list[str]:
    while True:
        answer = ask(f'Relays, separated by spaces [{" ".join(default)}]: ').strip()
        if not answer:
            return default
        try:
            return list(dict.fromkeys(normalize_relay_url(url)
                                      for url in answer.replace(',', ' ').split()))
        except ValueError as e:
            say(str(e).removeprefix('relay.urls: '))


def _signing(ask: Ask, say: Say, current: SigningConfig, existing: bool) -> dict[str, Any]:
    usual = list(USUAL_KINDS)
    say('What should the card sign?\n'
        '  1) the usual kinds: profile, notes, follows, DMs, reposts, reactions, deletions,\n'
        '     relay lists and relay login\n'
        '  2) every kind a client asks for')
    choices = {'1': {'policy': 'allowed_kinds', 'allowed_kinds': usual},
               '2': {'policy': 'all', 'allowed_kinds': current.allowed_kinds}}
    default = '2' if current.policy == 'all' else '1'
    if existing and current.allowed_kinds != usual:
        say(f'  3) keep the current list: {current.allowed_kinds}')
        choices['3'] = {'policy': 'allowed_kinds', 'allowed_kinds': current.allowed_kinds}
        if current.policy != 'all':
            default = '3'
    return choices[_choice(ask, say, choices, default)]


def _certificate(ask: Ask, say: Say, current: KeycardConfig,
                 existing: bool) -> dict[str, Any]:
    say('Which certificate does your card carry?\n'
        '  1) the official Keycard CA (store-bought cards)\n'
        '  2) the Test CA (development cards)\n'
        '  3) your own CA')
    if current.trust_test_ca or not existing:
        # Only development cards carry applet 4.x so far.
        default = '2'
    elif current.ca_public_keys:
        default = '3'
    else:
        default = '1'
    choice = _choice(ask, say, {'1', '2', '3'}, default)
    if choice == '1':
        return {'trust_test_ca': False, 'ca_public_keys': []}
    if choice == '2':
        return {'trust_test_ca': True, 'ca_public_keys': current.ca_public_keys}
    known = current.ca_public_keys[0] if current.ca_public_keys else ''
    while True:
        key = ask(f'Your CA public key, compressed, in hex [{known}]: ').strip().lower() or known
        if CA_KEY.fullmatch(key):
            return {'trust_test_ca': False, 'ca_public_keys': [key]}
        say('That is not a 33-byte compressed public key in hex (66 characters, 02 or 03 first)')


def _pin(ask: Ask, secret: Ask, say: Say, path: Path) -> str:
    if path.exists():
        if _yes(ask, f'Keep the PIN stored in {path}?', True):
            return ''
    elif not _yes(ask, 'Store the card PIN, so the bunker can run as a service?', False):
        return ''
    while True:
        pin = secret('Card PIN: ')
        if not PIN.fullmatch(pin):
            say('The PIN is 6 digits')
        elif secret('Card PIN again: ') != pin:
            say('The two PINs differ')
        else:
            return pin


def _choice(ask: Ask, say: Say, choices: Any, default: str) -> str:
    while True:
        answer = ask(f'Choice [{default}]: ').strip() or default
        if answer in choices:
            return answer
        say(f'Answer one of {", ".join(sorted(choices))}')


def _yes(ask: Ask, question: str, default: bool) -> bool:
    while True:
        answer = ask(f'{question} [{"Y/n" if default else "y/N"}]: ').strip().lower()
        if not answer:
            return default
        if answer in ('y', 'yes', 'n', 'no'):
            return answer.startswith('y')


def _set(text: str, section: str, key: str, value: Any) -> str:
    header = re.search(rf'^\[{re.escape(section)}\][ \t]*$', text, re.M)
    if header is None:
        raise KeyError(f'[{section}] is not in the template')
    end = re.search(r'^\[', text[header.end():], re.M)
    stop = header.end() + end.start() if end else len(text)
    body, count = re.subn(rf'^{re.escape(key)}[ \t]*=.*$',
                          lambda _: f'{key} = {_toml(value)}', text[header.end():stop],
                          count=1, flags=re.M)
    if not count:
        raise KeyError(f'{section}.{key} is not in the template')
    return text[:header.end()] + body + text[stop:]


def _toml(value: Any) -> str:
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return '[' + ', '.join(_toml(item) for item in value) + ']'
    raise TypeError(f'cannot write {value!r} to the config')
