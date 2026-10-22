import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from keycard.constants import DerivationSource
from keycard.parsing.keypath import KeyPath

DEFAULT_KEY_PATH = "m/43'/60'/1581'/0'/0"
SIGNING_POLICIES = ('allowed_kinds', 'all')
USUAL_KINDS = (0, 1, 3, 4, 5, 6, 7, 13, 10002, 10050, 22242)
DEFAULT_PORTS = {'ws': 80, 'wss': 443}
# The applet computes ECDH only under NIP-06 (m/44'/1237') and EIP-1581 (m/43'/60'/1581').
ECDH_PREFIXES = (bytes.fromhex('8000002c800004d5'), bytes.fromhex('8000002b8000003c8000062d'))
MIN_KEY_PATH_DEPTH = 5


@dataclass
class RelayConfig:
    urls: list[str] = field(default_factory=lambda: ['wss://nos.lol', 'wss://relay.primal.net'])


@dataclass
class KeycardConfig:
    pin: str = ''
    reader: str = ''
    key_path: str = DEFAULT_KEY_PATH
    trust_test_ca: bool = False
    ca_public_keys: list[str] = field(default_factory=list)


@dataclass
class SignerConfig:
    key_file: str = '~/.config/keycard-nostr-bunker/signer.key'


@dataclass
class SigningConfig:
    policy: str = 'allowed_kinds'
    allowed_kinds: list[int] = field(default_factory=lambda: list(USUAL_KINDS))


@dataclass
class ConnectionConfig:
    secret: str = ''
    rotate_secret: bool = True
    approve_clients: bool = False
    authorized_clients: list[str] = field(default_factory=list)


@dataclass
class Config:
    relay: RelayConfig = field(default_factory=RelayConfig)
    keycard: KeycardConfig = field(default_factory=KeycardConfig)
    signer: SignerConfig = field(default_factory=SignerConfig)
    signing: SigningConfig = field(default_factory=SigningConfig)
    connection: ConnectionConfig = field(default_factory=ConnectionConfig)


_EXPECTED: dict[Any, str] = {
    str: 'a string',
    bool: 'true or false',
    int: 'an integer',
    list[str]: 'a list of strings',
    list[int]: 'a list of integers',
}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _well_typed(kind: Any, value: Any) -> bool:
    if kind is str:
        return isinstance(value, str)
    if kind is bool:
        return isinstance(value, bool)
    if kind is int:
        return _is_int(value)
    if kind == list[str]:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    if kind == list[int]:
        return isinstance(value, list) and all(_is_int(v) for v in value)
    return False


def _apply(section_name: str, section: Any, values: Any) -> None:
    if not isinstance(values, dict):
        raise ValueError(f'[{section_name}] must be a table')
    known = {f.name: f for f in fields(section)}
    for key, value in values.items():
        if key not in known:
            raise ValueError(f'unknown key {section_name}.{key}')
        kind = known[key].type
        if not _well_typed(kind, value):
            hint = ', write it in quotes' if kind is str and _is_int(value) else ''
            raise ValueError(f'{section_name}.{key} must be {_EXPECTED[kind]}{hint}')
        setattr(section, key, value)


def validate_key_path(path: str) -> None:
    try:
        key_path = KeyPath(path)
    except (ValueError, TypeError) as e:
        raise ValueError(f'keycard.key_path: {e}') from e
    data = key_path.data
    under_prefix = any(data.startswith(prefix) for prefix in ECDH_PREFIXES)
    if key_path.source != DerivationSource.MASTER or not under_prefix \
            or len(data) < MIN_KEY_PATH_DEPTH * 4:
        raise ValueError("keycard.key_path must be under m/44'/1237' or m/43'/60'/1581' "
                         "with at least 5 levels; the card refuses ECDH elsewhere")


def normalize_relay_url(url: str) -> str:
    """One spelling per relay, so a relay listed twice is one connection."""
    bad = ValueError(f'relay.urls: {url!r} is not a ws:// or wss:// URL')
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise bad from None
    scheme, host = parts.scheme.lower(), parts.hostname
    if scheme not in DEFAULT_PORTS or not host:
        raise bad
    if ':' in host:
        host = f'[{host}]'
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f'{host}:{port}'
    return urlunsplit((scheme, netloc, parts.path.rstrip('/'), parts.query, ''))


def _validate(cfg: Config, path: Path) -> None:
    cfg.relay.urls = list(dict.fromkeys(normalize_relay_url(url) for url in cfg.relay.urls))
    for key in cfg.keycard.ca_public_keys:
        if len(key) != 66 or key[:2] not in ('02', '03') or not _is_hex(key):
            raise ValueError('keycard.ca_public_keys: each key is a 33-byte compressed '
                             'point in hex')
    validate_key_path(cfg.keycard.key_path)
    if cfg.signing.policy not in SIGNING_POLICIES:
        raise ValueError(f'signing.policy must be one of {SIGNING_POLICIES}')
    for key in cfg.connection.authorized_clients:
        if len(key) != 64 or not _is_hex(key):
            raise ValueError(f'connection.authorized_clients: {key!r} is not '
                             'a 64-character hex pubkey')
    cfg.connection.authorized_clients = [key.lower() for key in cfg.connection.authorized_clients]
    if cfg.connection.rotate_secret and cfg.connection.secret:
        raise ValueError('connection.rotate_secret needs an empty connection.secret')
    if (cfg.keycard.pin or cfg.connection.secret) and path.exists() \
            and os.stat(path).st_mode & 0o077:
        raise ValueError(f'{path} holds a PIN or secret but other users can read it; '
                         f'run: chmod 600 {path}')


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def load_config(path: str | Path) -> Config:
    cfg = Config()
    path = Path(path)
    data: dict[str, Any] = {}
    if path.exists():
        data = tomllib.loads(path.read_text())
        sections = {f.name for f in fields(cfg)}
        for name, values in data.items():
            if name not in sections:
                raise ValueError(f'unknown section [{name}]')
            _apply(name, getattr(cfg, name), values)
    # Rotation is the default, but a secret fixed in the config cannot rotate.
    if cfg.connection.secret and 'rotate_secret' not in data.get('connection', {}):
        cfg.connection.rotate_secret = False
    key_file = Path(cfg.signer.key_file).expanduser()
    if not key_file.is_absolute():
        key_file = path.resolve().parent / key_file
    cfg.signer.key_file = str(key_file)
    _validate(cfg, path)
    return cfg
