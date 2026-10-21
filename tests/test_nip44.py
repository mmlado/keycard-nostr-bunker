"""NIP-44 v2 vectors from paulmillr/nip44."""

import pytest

from keycard_nostr_bunker import nip44, schnorr


@pytest.mark.parametrize('unpadded,expected', [
    (16, 32), (32, 32), (33, 64), (37, 64), (45, 64), (49, 64),
    (64, 64), (65, 96), (100, 128), (111, 128), (200, 224), (250, 256),
    (320, 320), (383, 384), (384, 384), (400, 448), (500, 512), (512, 512),
    (515, 640), (700, 768), (800, 896), (900, 1024), (1020, 1024), (65536, 65536),
])
def test_padded_len(unpadded, expected):
    assert nip44.padded_len(unpadded) == expected


@pytest.mark.parametrize('sec1,pub2,expected', [
    ('0000000000000000000000000000000000000000000000000000000000000001',
     '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
     '3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e'),
    ('0000000000000000000000000000000000000000000000000000000000000002',
     '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb',
     'be234f46f60a250bef52a5ee34c758800c4ca8e5030bf4cc1a31d37ba2104d43'),
    ('315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268',
     'c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133',
     '3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1'),
    ('a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e',
     '03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800',
     '4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b'),
    ('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139',
     '0000000000000000000000000000000000000000000000000000000000000002',
     '8b6392dbf2ec6a2b2d5b1477fc2be84d63ef254b667cadd31bd3f444c44ae6ba'),
])
def test_conversation_key(sec1, pub2, expected):
    shared = schnorr.ecdh_x(bytes.fromhex(sec1), bytes.fromhex(pub2))
    assert nip44.conversation_key(shared).hex() == expected


CONV_KEY = bytes.fromhex('c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d')
NONCE = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
PAYLOAD = ('AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4Dw'
           'rcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb')


def test_encrypt_vector():
    assert nip44.encrypt('a', CONV_KEY, NONCE) == PAYLOAD


def test_decrypt_vector():
    assert nip44.decrypt(PAYLOAD, CONV_KEY) == 'a'


def test_roundtrip_random_nonce():
    text = 'héllo wörld ' * 50
    assert nip44.decrypt(nip44.encrypt(text, CONV_KEY), CONV_KEY) == text


def test_invalid_mac():
    key = bytes.fromhex('cff7bd6a3e29a450fd27f6c125d5edeb0987c475fd1e8d97591e0d4d8a89763c')
    payload = ('Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholyySBfeh+EN8wNB9gaLlg4j6wdBYh+3oK+mnx'
               'Wu3NKRbSvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    with pytest.raises(ValueError, match='MAC'):
        nip44.decrypt(payload, key)


def test_empty_payload():
    with pytest.raises(ValueError):
        nip44.decrypt('', CONV_KEY)


def test_unknown_version():
    key = bytes.fromhex('ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642')
    payload = ('#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/'
               'GrE92xAc1K5odTpCzUB+mjXgbaqtntBUbTToSUoT0ovrlPwzGjyp')
    with pytest.raises(ValueError, match='version'):
        nip44.decrypt(payload, key)


@pytest.mark.parametrize('text', ['', 'x' * 65536])
def test_plaintext_length_limits(text):
    with pytest.raises(ValueError):
        nip44.encrypt(text, CONV_KEY)
