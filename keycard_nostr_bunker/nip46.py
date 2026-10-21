"""NIP-46 request dispatcher."""

import json
import logging
import re
from typing import Any

from . import envelope, nip01, nip04, nip44
from .admission import Admission, AdmissionError
from .config import SigningConfig
from .replay import ReplayWindow
from .signer import Signer, SignerUnavailable

log = logging.getLogger(__name__)

METHODS = frozenset({'get_public_key', 'ping', 'sign_event', 'nip44_encrypt', 'nip44_decrypt',
                     'nip04_encrypt', 'nip04_decrypt'})

_HEX = re.compile(r'[0-9a-f]+')


class RequestError(Exception):
    pass


class Bunker:
    """Verifies and decrypts kind:24133 requests, serves them, signs the replies.

    transport: the bunker key clients address; user: the identity that signs;
    admission: who may connect and what each client may ask for.

    handle may run on several threads at once; the user signer serializes
    its own card access and admission its own state.
    """

    def __init__(self, transport: Signer, user: Signer, signing: SigningConfig,
                 admission: Admission, replay: ReplayWindow | None = None):
        self.transport = transport
        self.user = user
        self.signing = signing
        self.admission = admission
        self.replay = replay if replay is not None else ReplayWindow()
        self._transport_shared: dict[str, bytes] = {}

    def handle(self, event: dict[str, Any], source: str = '') -> dict[str, Any] | None:
        """Serve one request event; returns the reply event, or None.

        source names the relay it came from, for the pending list.
        """
        if event.get('kind') != envelope.KIND:
            return None
        try:
            client = envelope.verify(event)
            if not self.replay.admit(event['id'], event['created_at'],
                                     self.admission.known(client)):
                return None
        except (ValueError, TypeError, KeyError) as e:
            log.warning('NIP-46 rejected event: %s', e)
            return None
        legacy = envelope.is_legacy(event)
        try:
            request = envelope.unseal(event, self._transport_shared_x(client))
        except (ValueError, KeyError) as e:
            log.warning('NIP-46 bad request from %s: %s', client, e)
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
        except (RequestError, AdmissionError, SignerUnavailable) as e:
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

    def _dispatch(self, method: str, params: list, client: str, source: str) -> str:
        if method == 'connect':
            secret = str(params[1]) if len(params) > 1 and params[1] is not None else ''
            requested = params[2] if len(params) > 2 else None
            return self.admission.connect(client, secret, requested, source)
        if not self.admission.admitted(client):
            log.info('NIP-46 %s from unauthorized %s', method, client)
            raise AdmissionError('unauthorized')
        if method == 'sign_event':
            return self._sign_event(params, client)
        if method in METHODS:
            self.admission.require(client, method)
        match method:
            case 'get_public_key':
                return self.user.pubkey.hex()
            case 'ping':
                return 'pong'
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

    def _sign_event(self, params: list, client: str) -> str:
        raw = _param(params, 0)
        unsigned = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(unsigned, dict):
            raise RequestError('event is not an object')
        kind = int(unsigned['kind'])
        if not self._approved(kind):
            log.info('Rejected sign_event: kind %d is not in signing.allowed_kinds', kind)
            raise RequestError(f'kind {kind} is not in signing.allowed_kinds')
        self.admission.require(client, 'sign_event', kind)
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
            if self.admission.admitted(client):
                self._transport_shared[client] = shared
        return shared

    def _reply(self, client: str, request_id: Any, result: str, error: str | None,
               legacy: bool) -> dict[str, Any]:
        return envelope.seal({'id': request_id, 'result': result, 'error': error},
                             self.transport, client, self._transport_shared_x(client), legacy)


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and _HEX.fullmatch(value) is not None


def _param(params: list, index: int) -> Any:
    if len(params) <= index:
        raise RequestError(f'missing parameter {index}')
    return params[index]
