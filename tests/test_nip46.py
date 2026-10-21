import json
import time

import pytest

from keycard_nostr_bunker import nip01, nip04, nip44, schnorr
from keycard_nostr_bunker.admission import Admission, defer
from keycard_nostr_bunker.config import SigningConfig
from keycard_nostr_bunker.nip46 import KIND, Bunker
from keycard_nostr_bunker.replay import WINDOW, ReplayWindow
from keycard_nostr_bunker.signer import SignerUnavailable, SoftwareSigner

TRANSPORT = SoftwareSigner((1).to_bytes(32, 'big'))
USER = SoftwareSigner((3).to_bytes(32, 'big'))
CLIENT = SoftwareSigner((2).to_bytes(32, 'big'))
THIRD_PARTY = SoftwareSigner((5).to_bytes(32, 'big'))
SECRET = 's3cret'
ALL = SigningConfig('all', [])

_counter = 0


def encrypt_for_bunker(plaintext, client=CLIENT, legacy=False):
    shared = client.ecdh(TRANSPORT.pubkey)
    if legacy:
        return nip04.encrypt(plaintext, shared)
    return nip44.encrypt(plaintext, nip44.conversation_key(shared))


def event_with(content, client=CLIENT, created_at=None):
    return nip01.finalize_event(
        {'kind': KIND, 'tags': [['p', TRANSPORT.pubkey.hex()]], 'content': content,
         'created_at': created_at or int(time.time())},
        client.pubkey.hex(), client.sign)


def request(method, params, legacy=False, client=CLIENT, created_at=None):
    global _counter
    _counter += 1
    body = json.dumps({'id': f'req-{_counter}', 'method': method, 'params': params},
                      ensure_ascii=False)
    return event_with(encrypt_for_bunker(body, client, legacy), client, created_at)


def decrypt_reply(reply, legacy=False, client=CLIENT):
    assert reply['kind'] == KIND
    assert reply['tags'] == [['p', client.pubkey.hex()]]
    assert reply['pubkey'] == TRANSPORT.pubkey.hex()
    assert schnorr.verify(TRANSPORT.pubkey, bytes.fromhex(reply['id']), bytes.fromhex(reply['sig']))
    shared = client.ecdh(TRANSPORT.pubkey)
    plain = (nip04.decrypt(reply['content'], shared) if legacy
             else nip44.decrypt(reply['content'], nip44.conversation_key(shared)))
    return json.loads(plain)


def bunker(policy='all', kinds=(), authorized=True, user=USER, replay=None, **admission):
    """A bunker whose client is admitted through the config unless authorized is False."""
    admission.setdefault('secret', SECRET)
    if authorized:
        admission.setdefault('authorized', [CLIENT.pubkey.hex()])
    return Bunker(TRANSPORT, user, SigningConfig(policy, list(kinds)), Admission(None, **admission),
                  replay)


def call(method, params, b=None, legacy=False):
    b = b or bunker()
    return decrypt_reply(b.handle(request(method, params, legacy), 'wss://test'), legacy)


def test_connect_with_the_secret_admits_the_client():
    b = bunker(authorized=False)
    assert call('ping', [], b)['error'] == 'unauthorized'
    r = call('connect', [TRANSPORT.pubkey.hex(), SECRET], b)
    assert r['result'] == 'ack' and r['error'] is None
    assert b.admission.admitted(CLIENT.pubkey.hex())
    assert call('ping', [], b)['result'] == 'pong'


def test_connect_with_a_wrong_or_missing_secret_is_refused():
    b = bunker(authorized=False)
    assert call('connect', [TRANSPORT.pubkey.hex(), 'wrong'], b)['error'] == 'invalid secret'
    assert call('connect', [TRANSPORT.pubkey.hex()], b)['error'] == 'invalid secret'
    assert call('connect', [TRANSPORT.pubkey.hex(), None], b)['error'] == 'invalid secret'


def test_admitted_client_reconnects_without_the_secret():
    assert call('connect', [TRANSPORT.pubkey.hex()])['result'] == 'ack'


def test_connect_waiting_for_approval():
    b = bunker(authorized=False, approver=defer)
    assert call('connect', [TRANSPORT.pubkey.hex(), SECRET], b)['error'] == 'pending approval'
    assert call('ping', [], b)['error'] == 'unauthorized'


def sign(b, kind):
    return call('sign_event', [{'kind': kind, 'content': '', 'created_at': 1700000000}], b)


def test_requested_permissions_reach_every_method():
    b = bunker(authorized=False)
    call('connect', [TRANSPORT.pubkey.hex(), SECRET, 'sign_event:1,nip44_encrypt'], b)
    assert sign(b, 1)['error'] is None
    assert sign(b, 3)['error'] == ('sign_event for kind 3 is not among the permissions '
                                   'this client requested')
    peer = THIRD_PARTY.pubkey.hex()
    assert call('nip44_encrypt', [peer, 'x'], b)['error'] is None
    assert call('nip44_decrypt', [peer, 'x'], b)['error'] == (
        'nip44_decrypt is not among the permissions this client requested')
    assert 'not among the permissions' in call('nip04_encrypt', [peer, 'x'], b)['error']
    assert call('get_public_key', [], b)['result'] == USER.pubkey.hex()


def test_signing_policy_applies_before_permissions():
    b = bunker('allowed_kinds', [1, 7], authorized=False)
    call('connect', [TRANSPORT.pubkey.hex(), SECRET, 'sign_event'], b)
    assert sign(b, 7)['error'] is None
    assert sign(b, 3)['error'] == 'kind 3 is not in signing.allowed_kinds'


def test_get_public_key():
    assert call('get_public_key', [])['result'] == USER.pubkey.hex()


def test_ping():
    assert call('ping', [])['result'] == 'pong'


@pytest.mark.parametrize('stringified', [False, True])
def test_sign_event(stringified):
    unsigned = {'kind': 1, 'content': 'hello', 'tags': [['t', 'x']], 'created_at': 1700000000}
    param = json.dumps(unsigned) if stringified else unsigned
    r = call('sign_event', [param])
    assert r['error'] is None
    signed = json.loads(r['result'])
    assert signed['pubkey'] == USER.pubkey.hex()
    assert signed['content'] == 'hello' and signed['tags'] == [['t', 'x']]
    assert schnorr.verify(USER.pubkey, bytes.fromhex(signed['id']), bytes.fromhex(signed['sig']))


def test_policy_allows_listed_kind():
    b = bunker('allowed_kinds', [0, 1])
    r = call('sign_event', [{'kind': 1, 'content': '', 'created_at': 1700000000}], b)
    assert r['error'] is None


def test_policy_rejects_other_kind():
    b = bunker('allowed_kinds', [0, 1])
    r = call('sign_event', [{'kind': 4, 'content': '', 'created_at': 1700000000}], b)
    assert r['result'] == '' and r['error'] == 'kind 4 is not in signing.allowed_kinds'


def test_nip44_encrypt_decrypt():
    peer = THIRD_PARTY.pubkey.hex()
    ciphertext = call('nip44_encrypt', [peer, 'secret note'])['result']
    key = nip44.conversation_key(THIRD_PARTY.ecdh(USER.pubkey))
    assert nip44.decrypt(ciphertext, key) == 'secret note'
    incoming = nip44.encrypt('reply', key)
    assert call('nip44_decrypt', [peer, incoming])['result'] == 'reply'


def test_nip04_encrypt_decrypt():
    peer = THIRD_PARTY.pubkey.hex()
    ciphertext = call('nip04_encrypt', [peer, 'old style'])['result']
    shared = THIRD_PARTY.ecdh(USER.pubkey)
    assert nip04.decrypt(ciphertext, shared) == 'old style'
    assert call('nip04_decrypt', [peer, nip04.encrypt('back', shared)])['result'] == 'back'


def test_invalid_peer_pubkey():
    assert call('nip44_encrypt', ['zz', 'x'])['error'] == 'invalid peer pubkey'
    assert call('nip04_encrypt', [5, 'x'])['error'] == 'invalid peer pubkey'


def test_missing_param():
    assert 'missing parameter' in call('nip44_encrypt', [THIRD_PARTY.pubkey.hex()])['error']


def test_params_not_a_list_is_treated_as_empty():
    body = json.dumps({'id': 'r', 'method': 'ping', 'params': 'x'})
    r = decrypt_reply(bunker().handle(event_with(encrypt_for_bunker(body))))
    assert r['result'] == 'pong'


def test_unknown_method():
    assert 'unsupported method' in call('delete_account', [])['error']


def test_legacy_nip04_transport():
    assert call('ping', [], legacy=True)['result'] == 'pong'


def test_duplicate_event_ignored():
    b = bunker()
    event = request('ping', [])
    assert b.handle(event) is not None
    assert b.handle(event) is None


def test_seen_events_survive_a_restart(tmp_path):
    path = tmp_path / 'seen'
    event = request('ping', [])
    first = bunker(replay=ReplayWindow(path))
    assert first.handle(event) is not None
    second = bunker(replay=ReplayWindow(path))
    assert second.handle(event) is None
    assert second.handle(request('ping', [])) is not None


def test_undecryptable_event_ignored():
    event = event_with(nip44.encrypt('{}', bytes(32)))
    assert bunker().handle(event) is None


def test_other_kind_ignored():
    event = request('ping', [])
    event['kind'] = 1
    assert bunker().handle(event) is None


@pytest.mark.parametrize('body', ['[]', '"x"', '1', 'null'])
def test_non_object_body_ignored(body):
    b = bunker()
    assert b.handle(event_with(encrypt_for_bunker(body))) is None
    assert call('ping', [], b)['result'] == 'pong'


def test_oversized_reply_becomes_an_error():
    # json.dumps escapes non-ASCII in the reply, so it outgrows the request.
    unsigned = {'kind': 1, 'content': 'é' * 12000, 'created_at': 1700000000}
    r = call('sign_event', [unsigned])
    assert r['result'] == '' and 'size limit' in r['error']


def test_tampered_or_unsigned_events_are_rejected():
    b = bunker()
    good = request('ping', [])
    for field, value in (('sig', '00' * 64), ('id', 'ff' * 32), ('pubkey', good['pubkey'].upper()),
                         ('created_at', True), ('tags', 'x')):
        bad = dict(good, **{field: value})
        assert b.handle(bad) is None, field
    forged = dict(good, content=encrypt_for_bunker(json.dumps({'id': 'x', 'method': 'ping'})))
    assert b.handle(forged) is None
    assert b.handle(good) is not None


def test_stale_or_future_events_are_rejected():
    b = bunker()
    now = int(time.time())
    assert b.handle(request('ping', [], created_at=now - WINDOW - 5)) is None
    assert b.handle(request('ping', [], created_at=now + WINDOW + 5)) is None
    assert b.handle(request('ping', [], created_at=now - WINDOW + 5)) is not None


def test_transport_cache_only_for_admitted_clients():
    b = bunker(authorized=False)
    call('ping', [], b)
    assert b._transport_shared == {}
    call('connect', [TRANSPORT.pubkey.hex(), SECRET], b)
    call('ping', [], b)
    assert list(b._transport_shared) == [CLIENT.pubkey.hex()]


class CountingSigner(SoftwareSigner):
    calls = 0

    def ecdh(self, peer):
        CountingSigner.calls += 1
        return super().ecdh(peer)


def test_user_ecdh_is_not_cached_by_the_bunker():
    user = CountingSigner((3).to_bytes(32, 'big'))
    b = bunker(user=user)
    for _ in range(2):
        call('nip44_encrypt', [THIRD_PARTY.pubkey.hex(), 'x'], b)
    assert CountingSigner.calls == 2


class AbsentSigner:
    pubkey = USER.pubkey

    def sign(self, digest):
        raise SignerUnavailable('Keycard not present')

    def ecdh(self, peer):
        raise SignerUnavailable('Keycard not present')


def test_signer_unavailable_is_reported_to_client():
    b = bunker(user=AbsentSigner())
    assert call('get_public_key', [], b)['result'] == USER.pubkey.hex()
    r = call('sign_event', [{'kind': 1, 'content': '', 'created_at': 1700000000}], b)
    assert r == {'id': r['id'], 'result': '', 'error': 'Keycard not present'}
    r = call('nip44_encrypt', [THIRD_PARTY.pubkey.hex(), 'x'], b)
    assert r['error'] == 'Keycard not present'


def test_strangers_do_not_reach_the_seen_file_or_crowd_out_known_clients(tmp_path):
    path = tmp_path / 'seen'
    b = bunker(replay=ReplayWindow(path, limit=5))
    known = request('ping', [])
    assert b.handle(known) is not None
    for _ in range(20):
        stranger = SoftwareSigner.generate()
        reply = b.handle(request('ping', [], client=stranger))
        assert decrypt_reply(reply, client=stranger)['error'] == 'unauthorized'
    assert b.handle(known) is None
    assert path.read_text() == f"{known['id']} {known['created_at']}\n"


def test_a_strangers_replayed_connect_is_dropped():
    b = bunker(authorized=False, approver=defer)
    stranger_connect = request('connect', [TRANSPORT.pubkey.hex(), SECRET])
    assert decrypt_reply(b.handle(stranger_connect))['error'] == 'pending approval'
    assert b.handle(stranger_connect) is None
