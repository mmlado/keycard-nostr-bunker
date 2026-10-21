"""NIP-44 v2 encryption.

Wire format: base64(version(1) || nonce(32) || ciphertext || mac(32)).
"""

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

SALT = b'nip44-v2'
VERSION = 2


def conversation_key(shared_x: bytes) -> bytes:
    """HKDF-extract of the ECDH x coordinate."""
    return hmac.new(SALT, shared_x, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b''
    block = b''
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _message_keys(conv_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    expanded = _hkdf_expand(conv_key, nonce, 76)
    return expanded[:32], expanded[32:44], expanded[44:76]


def padded_len(unpadded: int) -> int:
    if unpadded <= 32:
        return 32
    next_power = 1 << (unpadded - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((unpadded - 1) // chunk + 1)


def _pad(plaintext: bytes) -> bytes:
    length = len(plaintext)
    if not 1 <= length <= 65535:
        raise ValueError('plaintext length out of range')
    return length.to_bytes(2, 'big') + plaintext + bytes(padded_len(length) - length)


def _unpad(padded: bytes) -> bytes:
    if len(padded) < 2:
        raise ValueError('padded message too short')
    length = int.from_bytes(padded[:2], 'big')
    if length == 0 or len(padded) != 2 + padded_len(length):
        raise ValueError('invalid padding')
    return padded[2:2 + length]


def _chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    # cryptography takes a 16-byte nonce: 4-byte little-endian counter || nonce
    cipher = Cipher(algorithms.ChaCha20(key, bytes(4) + nonce), mode=None)
    return cipher.encryptor().update(data)


def encrypt(plaintext: str, conv_key: bytes, nonce: bytes | None = None) -> str:
    nonce = os.urandom(32) if nonce is None else nonce
    if len(nonce) != 32:
        raise ValueError('nonce must be 32 bytes')
    chacha_key, chacha_nonce, hmac_key = _message_keys(conv_key, nonce)
    ciphertext = _chacha20(chacha_key, chacha_nonce, _pad(plaintext.encode()))
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(bytes([VERSION]) + nonce + ciphertext + mac).decode()


def decrypt(payload: str, conv_key: bytes) -> str:
    if not 132 <= len(payload) <= 87472:
        raise ValueError('invalid payload length')
    if payload[0] == '#':
        raise ValueError('unsupported encryption version')
    raw = base64.b64decode(payload, validate=True)
    if not 99 <= len(raw) <= 65603:
        raise ValueError('invalid payload length')
    if raw[0] != VERSION:
        raise ValueError(f'unsupported version {raw[0]}')
    nonce, ciphertext, mac = raw[1:33], raw[33:-32], raw[-32:]
    chacha_key, chacha_nonce, hmac_key = _message_keys(conv_key, nonce)
    expected = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError('invalid MAC')
    return _unpad(_chacha20(chacha_key, chacha_nonce, ciphertext)).decode()
