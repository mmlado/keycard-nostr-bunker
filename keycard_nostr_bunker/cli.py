import argparse
import asyncio
import getpass
import logging
import os
import select
import signal
import subprocess
import sys
import termios
import time
from pathlib import Path

from . import __version__, nip46, service
from .card import CardError, KeycardSigner, list_readers
from .clients import ClientList, Secret, SeenEvents, approve
from .config import Config, load_config
from .nip46 import Bunker
from .relay import RelayConn
from .signer import Signer, SoftwareSigner

log = logging.getLogger('keycard_nostr_bunker')

PIN_ENV = 'KEYCARD_NOSTR_BUNKER_PIN'
PIN_CREDENTIAL = 'pin'
APPROVAL_TIMEOUT = 60
LOCAL_CONFIG = Path('config.toml')


def default_config() -> Path:
    """config.toml in the working directory if present, else the XDG one."""
    if LOCAL_CONFIG.exists():
        return LOCAL_CONFIG
    base = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    return base / 'keycard-nostr-bunker' / 'config.toml'


def bunker_url(pubkey_hex: str, relays: list[str], secret: str) -> str:
    params = [f'relay={url}' for url in relays]
    if secret:
        params.append(f'secret={secret}')
    return f'bunker://{pubkey_hex}?' + '&'.join(params)


def state_file(cfg: Config, name: str) -> Path:
    return Path(cfg.signer.key_file).with_name(name)


def load_secret(cfg: Config) -> Secret:
    return Secret(cfg.connection.secret, state_file(cfg, 'secret'))


def current_url(cfg: Config, transport: SoftwareSigner, secret: Secret) -> str:
    return bunker_url(transport.pubkey.hex(), cfg.relay.urls, secret.current)


def show_url(url: str, reason: str) -> None:
    """Print the URL on a terminal only; it carries the secret and logs persist."""
    if sys.stdout.isatty():
        print(f'\n{url}\n', flush=True)
    else:
        log.info('%s; run "keycard-nostr-bunker url" to show the bunker URL', reason)


def terminal_approver(client: str) -> bool:
    code = client[:4]
    fd = sys.stdin.fileno()
    try:
        termios.tcflush(fd, termios.TCIFLUSH)
    except (termios.error, OSError):
        pass
    print(f'\nClient {client} asks to connect.\nType {code} to approve, anything else to refuse: ',
          end='', flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], APPROVAL_TIMEOUT)
    if not ready:
        print('\nNo answer, refused', flush=True)
        return False
    answer = os.read(fd, 1024).decode(errors='replace').partition('\n')[0].strip()
    return answer == code


def pubkey_arg(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise argparse.ArgumentTypeError('a pubkey is 64 hex characters')
    return value


def resolve_pin(cfg: Config) -> str:
    if cfg.keycard.pin:
        return cfg.keycard.pin
    if os.environ.get(PIN_ENV):
        return os.environ[PIN_ENV]
    credentials = os.environ.get('CREDENTIALS_DIRECTORY')
    if credentials and (Path(credentials) / PIN_CREDENTIAL).exists():
        return (Path(credentials) / PIN_CREDENTIAL).read_text().strip()
    if sys.stdin.isatty():
        return getpass.getpass('Keycard PIN: ')
    raise CardError(f'no PIN: set keycard.pin, {PIN_ENV}, or a systemd credential '
                    f'named {PIN_CREDENTIAL}')


def install_service(cfg: Config, config_path: Path) -> int:
    pin_file = service.pin_file(config_path.resolve())
    if not cfg.keycard.pin and not pin_file.exists():
        log.error('A service has no terminal to ask for the PIN. Either write the PIN to %s '
                  '(mode 0600), or set keycard.pin in %s and chmod 600 that file',
                  pin_file, config_path)
        return 1
    if pin_file.exists() and os.stat(pin_file).st_mode & 0o077:
        log.error('%s is readable by other users; run: chmod 600 %s', pin_file, pin_file)
        return 1
    try:
        path = service.install(config_path)
    except (OSError, subprocess.CalledProcessError) as e:
        log.error('Service install failed: %s', e)
        return 1
    print(f'Installed and started {path}')
    print(f'Logs:  journalctl --user -u {service.UNIT_NAME} -f')
    print('URL:   keycard-nostr-bunker url')
    print('To keep it running while logged out: loginctl enable-linger')
    return 0


def uninstall_service() -> int:
    try:
        removed = service.uninstall()
    except (OSError, subprocess.CalledProcessError) as e:
        log.error('Service uninstall failed: %s', e)
        return 1
    print('Service removed' if removed else 'Service was not installed')
    return 0


def _when(meta: str) -> str:
    stamp, _, rest = meta.partition(' ')
    if stamp.isdigit():
        when = time.strftime('%Y-%m-%d %H:%M', time.localtime(int(stamp)))
        return f'{when}  {rest}' if rest else when
    return meta


def manage_clients(cfg: Config, action: str, pubkey: str | None) -> int:
    clients = ClientList(state_file(cfg, 'clients'))
    pending = ClientList(state_file(cfg, 'pending'), limit=nip46.PENDING_LIMIT)
    match action:
        case 'list':
            rows = [f'{key}  from the config' for key in cfg.connection.authorized_clients]
            rows += [f'{key}  {_when(meta)}'.rstrip() for key, meta in clients.items()
                     if key not in cfg.connection.authorized_clients]
            print('\n'.join(rows) if rows else 'No admitted clients')
        case 'pending':
            rows = [f'{key}  {_when(meta)}'.rstrip() for key, meta in pending.items()]
            print('\n'.join(rows) if rows else 'No clients waiting for approval')
        case 'approve':
            assert pubkey
            was_pending = approve(pubkey, clients, pending)
            print(f'Approved {pubkey}' if was_pending
                  else f'Approved {pubkey}, which was not waiting for approval')
        case 'revoke':
            assert pubkey
            if pubkey in cfg.connection.authorized_clients:
                print(f'{pubkey} is in connection.authorized_clients; remove it from the config')
                return 1
            if not clients.remove(pubkey):
                print(f'{pubkey} was not an admitted client')
                return 0
            print(f'Revoked {pubkey}')
            return rotate_after_revoke(cfg)
    return 0


def rotate_after_revoke(cfg: Config) -> int:
    """A revoked client still knows the secret, so it must change too."""
    secret = load_secret(cfg)
    if not secret.rotatable:
        log.warning('connection.secret is fixed in the config; change it there, '
                    'or the revoked client can connect again')
        return 0
    secret.rotate()
    print('Secret rotated; the running bunker uses the new one at once.')
    if Path(cfg.signer.key_file).exists():
        return show_url_command(cfg)
    return 0


def show_url_command(cfg: Config) -> int:
    key_file = Path(cfg.signer.key_file)
    if not key_file.exists():
        log.error('%s does not exist yet; run the bunker once first', key_file)
        return 1
    print(current_url(cfg, SoftwareSigner.load(key_file), load_secret(cfg)))
    return 0


def open_card(cfg: Config) -> KeycardSigner:
    signer = KeycardSigner(cfg.keycard, resolve_pin(cfg), state_file(cfg, 'user.pubkey'))
    signer.start()
    if signer.refused:
        log.error('Keycard: refused: %s', signer.refused)
    elif not signer.present:
        log.warning('Keycard: not present, waiting for it')
    return signer


async def run(cfg: Config, transport: SoftwareSigner, user: Signer) -> None:
    secret = load_secret(cfg)
    clients = ClientList(state_file(cfg, 'clients'))
    pending = ClientList(state_file(cfg, 'pending'), limit=nip46.PENDING_LIMIT)
    seen = SeenEvents(state_file(cfg, 'seen'), max_age=nip46.MAX_AGE * 5)
    log.info('Admitted clients: %d', len(clients))
    admission = cfg.connection
    interactive = admission.approve_clients and sys.stdin.isatty()
    if admission.approve_clients:
        how = 'a prompt here' if interactive else 'keycard-nostr-bunker clients approve <pubkey>'
        log.info('New clients need approval: %s', how)

    def on_secret_accepted(client: str) -> None:
        if admission.rotate_secret:
            secret.rotate()
            show_url(current_url(cfg, transport, secret), 'Secret rotated')

    bunker = Bunker(transport, user, cfg.signing, secret, clients,
                    approve=admission.approve_clients,
                    approver=terminal_approver if interactive else None,
                    pending=pending, seen=seen, on_secret_accepted=on_secret_accepted,
                    preauthorized=admission.authorized_clients)
    conns: list[RelayConn] = []
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    async def on_message(message: list, relay: RelayConn) -> None:
        match message:
            case ['EVENT', _, dict() as event]:
                try:
                    reply = await asyncio.to_thread(bunker.handle, event, relay.url)
                except Exception:
                    log.exception('NIP-46 request handling failed')
                    return
                if reply:
                    await asyncio.gather(*(conn.send(['EVENT', reply]) for conn in conns),
                                         return_exceptions=True)
            case ['OK', event_id, accepted, *rest]:
                log.debug('Event %s %s %s', str(event_id)[:8],
                          'accepted' if accepted else 'rejected', rest[0] if rest else '')
            case ['NOTICE', text]:
                log.info('Relay notice from %s: %s', relay.url, text)
            case ['CLOSED', _, text]:
                log.warning('Subscription closed by %s: %s', relay.url, text)
            case ['EOSE', _]:
                log.debug('EOSE from %s', relay.url)
            case _:
                log.debug('Ignored relay message: %s', message[0])

    for url in cfg.relay.urls:
        conn = RelayConn(url, transport.pubkey.hex(), on_message)
        conn.start()
        conns.append(conn)

    show_url(current_url(cfg, transport, secret), 'Bunker ready')
    try:
        await stop.wait()
    finally:
        log.info('Shutting down')
        for conn in conns:
            await conn.stop()


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('-c', '--config', metavar='FILE', default=argparse.SUPPRESS,
                        help='TOML config file (default: config.toml here, '
                             'else ~/.config/keycard-nostr-bunker/config.toml)')
    common.add_argument('-v', '--verbose', action='store_true', default=argparse.SUPPRESS,
                        help='debug logging')

    parser = argparse.ArgumentParser(prog='keycard-nostr-bunker', parents=[common],
                                     description='NIP-46 remote signer backed by a Keycard')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    commands = parser.add_subparsers(dest='command', metavar='command')

    run = commands.add_parser('run', parents=[common], help='start the bunker (the default)')
    run.add_argument('--no-card', action='store_true',
                     help='sign with the bunker key instead of a Keycard (testing)')

    commands.add_parser('url', parents=[common],
                        help='print the bunker:// URL, secret included, without starting')
    commands.add_parser('readers', parents=[common], help='list PC/SC readers')

    svc = commands.add_parser('service', parents=[common], help='systemd user service')
    actions = svc.add_subparsers(dest='action', metavar='action', required=True)
    actions.add_parser('install', parents=[common],
                       help='install, enable and start the service for this config')
    actions.add_parser('uninstall', parents=[common], help='stop and remove the service')

    clients = commands.add_parser('clients', parents=[common], help='admitted clients')
    actions = clients.add_subparsers(dest='action', metavar='action', required=True)
    actions.add_parser('list', parents=[common], help='list admitted clients')
    actions.add_parser('pending', parents=[common], help='list clients waiting for approval')
    for name, text in (('approve', 'admit a client waiting for approval'),
                       ('revoke', 'remove an admitted client and rotate the secret')):
        sub = actions.add_parser(name, parents=[common], help=text)
        sub.add_argument('pubkey', type=pubkey_arg, help='64 hex characters, as shown in the log')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or 'run'
    action = getattr(args, 'action', None)
    explicit = hasattr(args, 'config')
    config_path = Path(args.config) if explicit else default_config()

    logging.basicConfig(level=logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    logging.getLogger('websockets').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.INFO)

    if command == 'readers':
        try:
            readers = list_readers()
        except CardError as e:
            log.error('%s', e)
            return 1
        print('\n'.join(readers) if readers else 'No PC/SC readers found')
        return 0
    if command == 'service' and action == 'uninstall':
        return uninstall_service()

    if explicit and not config_path.exists():
        log.error('%s does not exist', config_path)
        return 1
    try:
        cfg = load_config(config_path)
    except ValueError as e:
        log.error('%s: %s', config_path, e)
        return 1
    if command == 'service':
        return install_service(cfg, config_path)
    if command == 'clients':
        return manage_clients(cfg, args.action, getattr(args, 'pubkey', None))
    if command == 'url':
        return show_url_command(cfg)
    return run_bunker(cfg, config_path, getattr(args, 'no_card', False))


def run_bunker(cfg: Config, config_path: Path, no_card: bool) -> int:
    log.info('Config: %s%s', config_path.resolve(),
             '' if config_path.exists() else ' (missing, using defaults)')
    log.info('State: %s', Path(cfg.signer.key_file).parent)
    if not cfg.relay.urls:
        log.error('No relay URLs configured')
        return 1

    transport = SoftwareSigner.load_or_generate(cfg.signer.key_file)
    log.info('Bunker pubkey: %s', transport.pubkey.hex())

    card: KeycardSigner | None = None
    if no_card:
        user: Signer = transport
        log.warning('No card: signing with the bunker key')
    else:
        try:
            card = user = open_card(cfg)
        except CardError as e:
            log.error('Keycard: %s', e)
            return 1
    try:
        log.info('User pubkey: %s', user.pubkey.hex())
    except Exception:
        log.info('User pubkey: unknown until the Keycard is inserted')
    log.info('Signing policy: %s', cfg.signing.policy if cfg.signing.policy == 'all'
             else f'allowed_kinds {cfg.signing.allowed_kinds}')

    try:
        asyncio.run(run(cfg, transport, user))
    finally:
        if card is not None:
            card.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
