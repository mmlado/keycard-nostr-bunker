import pytest

from keycard_nostr_bunker import nip04

SHARED = bytes(range(32))


def test_roundtrip():
    text = 'hello, nip-04 ✓'
    payload = nip04.encrypt(text, SHARED)
    assert '?iv=' in payload
    assert nip04.decrypt(payload, SHARED) == text


def test_known_payload():
    # openssl enc -aes-256-cbc of "hello", key 00..1f, iv 00..0f
    payload = 'f9Etr7fpWZ0LhJrYwuPCHw==?iv=AAECAwQFBgcICQoLDA0ODw=='
    assert nip04.decrypt(payload, SHARED) == 'hello'


def test_missing_iv():
    with pytest.raises(ValueError):
        nip04.decrypt('abcd', SHARED)


def test_wrong_key():
    payload = nip04.encrypt('secret', SHARED)
    with pytest.raises(ValueError):
        nip04.decrypt(payload, bytes(32))
