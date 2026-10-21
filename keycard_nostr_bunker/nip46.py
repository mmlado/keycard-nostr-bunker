"""NIP-46 request dispatcher."""

import hmac
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Iterable

from . import nip01, nip04, nip44, schnorr
from .clients import ClientList, Secret, SeenEvents
from .config import SigningConfig
from .signer import Signer, SignerUnavailable

log = logging.getLogger(__name__)

KIND = 24133
# A request older than this, or further ahead of our clock, is refused.
MAX_AGE = 60
PENDING_LIMIT = 64

_HEX = re.compile(r'[0-9a-f]+')


class RequestError(Exception):
    pass


class Bunker:
    """Verifies and decrypts kind:24133 requests, serves them, signs the replies.

    transport: the bunker key clients address; user: the identity that signs.
    A client is admitted by `connect` with the secret and remembered in clients;
    every other method is refused for anyone else. With approve set, the secret
    only gets the client asked about: the approver decides on the spot, or,
    without one, the client is parked in pending until approved elsewhere.
    on_secret_accepted runs as soon as a client presents the right secret,
    admitted or not, so the secret can be rotated.

    handle may run on several threads at once; the user signer serializes
    its own card access.
    """

    def __init__(self, transport: Signer, user: Signer, signing: SigningConfig,
                 secret: str | Secret, clients: ClientList | None = None,
                 approve: bool = False, approver: Callable[[str], bool] | None = None,
                 pending: ClientList | None = None, seen: SeenEvents | None = None,
                 on_secret_accepted: Callable[[str], None] | None = None,
                 preauthorized: Iterable[str] = (),
                 now: Callable[[], float] = time.time):
        self.transport = transport
        self.user = user
        self.signing = signing
        self.secret = Secret(secret) if isinstance(secret, str) else secret
        self.clients = clients if clients is not None else ClientList()
        self.approve = approve
        self.approver = approver
        self.pending = pending if pending is not None else ClientList(limit=PENDING_LIMIT)
        self.seen = seen if seen is not None else SeenEvents(max_age=MAX_AGE)
        self.on_secret_accepted = on_secret_accepted
        self.preauthorized = frozenset(preauthorized)
        self._now = now
        self._lock = threading.Lock()
        self._prompt = threading.Lock()
        self._transport_shared: dict[str, bytes] = {}

    def handle(self, event: dict[str, Any], source: str = '') -> dict[str, Any] | None:
        """Serve one request event; returns the reply event, or None.

        source names the relay it came from, for the pending list.
        """
        if event.get('kind') != KIND:
            return None
        try:
            client, event_id, created_at = self._verify(event)
        except (ValueError, TypeError, KeyError) as e:
            log.warning('NIP-46 rejected event: %s', e)
            return None
        with self._lock:
            if event_id in self.seen:
                return None
            self.seen.record(event_id, created_at)
        content = event['content']
        # Older clients still encrypt the transport with NIP-04.
        legacy = '?iv=' in content
        try:
            request = json.loads(self._decrypt(client, content, legacy))
        except (ValueError, KeyError) as e:
            log.warning('NIP-46 bad request from %s: %s', client, e)
            return None
        if not isinstance(request, dict):
            log.warning('NIP-46 bad request from %s: not an object', client)
            return None
        request_id = request.get('id')
        method = request.get('method')
        if request_id is None or not isinstance(method, str) or not method:
            return None
        params = request.get('params')
        params = params if isinstance(params, list) else []
        log.debug('NIP-46 %s from %s...', method, client[:8])

        error = None
        try:
            result = self._dispatch(method, params, client, source)
        except (RequestError, SignerUnavailable) as e:
            result, error = '', str(e)
        except Exception as e:
            log.exception('NIP-46 %s failed', method)
            result, error = '', f'{method} failed: {e}'

        try:
            reply = self._reply(client, request_id, result, error, legacy)
        except ValueError as e:
            log.warning('NIP-46 %s: cannot encrypt the reply: %s', method, e)
            error = f'{method} failed: reply exceeds the NIP-44 size limit'
            try:
                reply = self._reply(client, request_id, '', error, legacy)
            except ValueError:
                return None
        log.info('NIP-46 %s -> %s', method, error or 'ok')
        return reply

    def _verify(self, event: dict[str, Any]) -> tuple[str, str, int]:
        """Check the request event is well formed, recent, and signed by its pubkey."""
        client, event_id, sig = event['pubkey'], event['id'], event['sig']
        created_at, tags, content = event['created_at'], event.get('tags') or [], event['content']
        if not (_hex(client, 64) and _hex(event_id, 64) and _hex(sig, 128)):
            raise ValueError('pubkey, id or sig is not hex of the right length')
        if isinstance(created_at, bool) or not isinstance(created_at, int):
            raise ValueError('created_at is not an integer')
        if abs(self._now() - created_at) > MAX_AGE:
            raise ValueError(f'created_at {created_at} is outside the {MAX_AGE}s window')
        if not isinstance(content, str) or not isinstance(tags, list):
            raise ValueError('content or tags has the wrong type')
        if nip01.event_id(client, created_at, KIND, tags, content).hex() != event_id:
            raise ValueError('id does not match the event')
        if not schnorr.verify(bytes.fromhex(client), bytes.fromhex(event_id), bytes.fromhex(sig)):
            raise ValueError(f'bad signature from {client}')
        return client, event_id, created_at

    def _dispatch(self, method: str, params: list, client: str, source: str) -> str:
        if method == 'connect':
            return self._connect(params, client, source)
        if not self._admitted(client):
            log.info('NIP-46 %s from unauthorized %s', method, client)
            raise RequestError('unauthorized')
        match method:
            case 'get_public_key':
                return self.user.pubkey.hex()
            case 'ping':
                return 'pong'
            case 'sign_event':
                return self._sign_event(params)
            case 'nip44_encrypt':
                return nip44.encrypt(_param(params, 1), self._user_key(_param(params, 0)))
            case 'nip44_decrypt':
                return nip44.decrypt(_param(params, 1), self._user_key(_param(params, 0)))
            case 'nip04_encrypt':
                return nip04.encrypt(_param(params, 1), self._user_shared_x(_param(params, 0)))
            case 'nip04_decrypt':
                return nip04.decrypt(_param(params, 1), self._user_shared_x(_param(params, 0)))
            case _:
                raise RequestError(f'unsupported method: {method}')

    def _admitted(self, client: str) -> bool:
        return client in self.preauthorized or client in self.clients

    def _connect(self, params: list, client: str, source: str) -> str:
        if self._admitted(client):
            return 'ack'
        offered = str(params[1]) if len(params) > 1 and params[1] is not None else ''
        if not hmac.compare_digest(offered.encode(), self.secret.current.encode()):
            log.warning('NIP-46 connect from %s with a wrong secret', client)
            raise RequestError('invalid secret')
        if self.on_secret_accepted is not None:
            self.on_secret_accepted(client)
        if self.approve:
            if self.approver is None or not self._prompt.acquire(blocking=False):
                self._park(client, source)
                raise RequestError('pending approval')
            try:
                approved = self.approver(client)
            finally:
                self._prompt.release()
            if not approved:
                log.warning('NIP-46 client %s refused', client)
                raise RequestError('connection refused')
        with self._lock:
            self.clients.add(client, f'{int(self._now())} {source}'.strip())
            self.pending.remove(client)
        log.info('NIP-46 admitted client %s', client)
        return 'ack'

    def _park(self, client: str, source: str) -> None:
        with self._lock:
            if client in self.pending:
                return
            self.pending.add(client, f'{int(self._now())} {source}'.strip())
        log.warning('NIP-46 client %s waits for approval: keycard-nostr-bunker clients approve %s',
                    client, client)

    def _sign_event(self, params: list) -> str:
        raw = _param(params, 0)
        unsigned = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(unsigned, dict):
            raise RequestError('event is not an object')
        kind = int(unsigned['kind'])
        if not self._approved(kind):
            log.info('Rejected sign_event: kind %d is not in signing.allowed_kinds', kind)
            raise RequestError(f'kind {kind} is not in signing.allowed_kinds')
        signed = nip01.finalize_event(unsigned, self.user.pubkey.hex(), self.user.sign)
        return json.dumps(signed, separators=(',', ':'), ensure_ascii=False)

    def _approved(self, kind: int) -> bool:
        return self.signing.policy == 'all' or kind in self.signing.allowed_kinds

    def _user_shared_x(self, peer: Any) -> bytes:
        if not isinstance(peer, str) or not _hex(peer.lower(), 64):
            raise RequestError('invalid peer pubkey')
        return self.user.ecdh(bytes.fromhex(peer))

    def _user_key(self, peer: Any) -> bytes:
        return nip44.conversation_key(self._user_shared_x(peer))

    def _transport_shared_x(self, client: str) -> bytes:
        shared = self._transport_shared.get(client)
        if shared is None:
            shared = self.transport.ecdh(bytes.fromhex(client))
            # Only admitted clients are cached, so the cache stays bounded.
            if self._admitted(client):
                self._transport_shared[client] = shared
        return shared

    def _decrypt(self, client: str, content: str, legacy: bool) -> str:
        shared = self._transport_shared_x(client)
        if legacy:
            return nip04.decrypt(content, shared)
        return nip44.decrypt(content, nip44.conversation_key(shared))

    def _encrypt(self, client: str, plaintext: str, legacy: bool) -> str:
        shared = self._transport_shared_x(client)
        if legacy:
            return nip04.encrypt(plaintext, shared)
        return nip44.encrypt(plaintext, nip44.conversation_key(shared))

    def _reply(self, client: str, request_id: Any, result: str, error: str | None,
               legacy: bool) -> dict[str, Any]:
        response = json.dumps({'id': request_id, 'result': result, 'error': error})
        return nip01.finalize_event(
            {'kind': KIND, 'tags': [['p', client]],
             'content': self._encrypt(client, response, legacy)},
            self.transport.pubkey.hex(), self.transport.sign)


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and _HEX.fullmatch(value) is not None


def _param(params: list, index: int) -> Any:
    if len(params) <= index:
        raise RequestError(f'missing parameter {index}')
    return params[index]
