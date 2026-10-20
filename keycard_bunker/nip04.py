"""NIP-04 encryption: AES-256-CBC keyed with the raw ECDH x coordinate."""

import base64
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(plaintext: str, shared_x: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(shared_x), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return f'{base64.b64encode(ciphertext).decode()}?iv={base64.b64encode(iv).decode()}'


def decrypt(payload: str, shared_x: bytes) -> str:
    ciphertext_b64, sep, iv_b64 = payload.partition('?iv=')
    if not sep:
        raise ValueError('missing iv')
    ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    iv = base64.b64decode(iv_b64, validate=True)
    if len(iv) != 16:
        raise ValueError('invalid iv')
    decryptor = Cipher(algorithms.AES(shared_x), modes.CBC(iv)).decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode()
