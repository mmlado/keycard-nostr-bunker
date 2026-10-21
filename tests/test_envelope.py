import pytest

from keycard_nostr_bunker import envelope, nip44
from keycard_nostr_bunker.envelope import KIND
from keycard_nostr_bunker.signer import SoftwareSigner

SENDER = SoftwareSigner((2).to_bytes(32, 'big'))
RECIPIENT = SoftwareSigner((1).to_bytes(32, 'big'))
SHARED = SENDER.ecdh(RECIPIENT.pubkey)
PING = {'id': '1', 'method': 'ping', 'params': []}


def sealed(body=PING, legacy=False, created_at=None):
    return envelope.seal(body, SENDER, RECIPIENT.pubkey.hex(), SHARED, legacy, created_at)


@pytest.mark.parametrize('legacy', [False, True])
def test_the_recipient_unseals_what_the_sender_sealed(legacy):
    body = {'id': '1', 'method': 'sign_event', 'params': ['é']}
    event = sealed(body, legacy)
    assert event['kind'] == KIND and event['tags'] == [['p', RECIPIENT.pubkey.hex()]]
    assert envelope.verify(event) == SENDER.pubkey.hex()
    assert envelope.is_legacy(event) is legacy
    assert envelope.unseal(event, RECIPIENT.ecdh(SENDER.pubkey)) == body


def test_created_at_is_the_one_given():
    assert sealed(created_at=1_700_000_000)['created_at'] == 1_700_000_000


@pytest.mark.parametrize('change', [
    {'sig': '00' * 64}, {'id': 'ff' * 32}, {'pubkey': SENDER.pubkey.hex().upper()}, {'kind': 1},
    {'created_at': True}, {'tags': 'x'}, {'content': sealed(dict(PING, id='2'))['content']},
], ids=['sig', 'id', 'pubkey', 'kind', 'created_at', 'tags', 'content'])
def test_an_altered_event_fails_verification(change):
    with pytest.raises(ValueError):
        envelope.verify(dict(sealed(), **change))


def test_an_event_missing_a_field_fails_verification():
    event = sealed()
    del event['sig']
    with pytest.raises(KeyError):
        envelope.verify(event)


@pytest.mark.parametrize('legacy', [False, True])
def test_the_wrong_key_does_not_unseal(legacy):
    with pytest.raises(ValueError):
        envelope.unseal(sealed(legacy=legacy), bytes(32))


@pytest.mark.parametrize('text', ['[]', '"x"', '1', 'null'])
def test_a_body_that_is_not_an_object_does_not_unseal(text):
    event = dict(sealed(), content=nip44.encrypt(text, nip44.conversation_key(SHARED)))
    with pytest.raises(ValueError, match='not an object'):
        envelope.unseal(event, SHARED)


def test_a_body_over_the_nip44_limit_is_refused():
    with pytest.raises(ValueError):
        sealed({'id': '1', 'result': 'x' * 65536})
