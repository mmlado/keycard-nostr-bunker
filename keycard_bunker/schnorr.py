"""BIP-340 Schnorr signatures and x-only ECDH on secp256k1, in pure Python."""

import hashlib
import os

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY, Point, PointJacobi

_G = SECP256k1.generator
_N = SECP256k1.order
_P = SECP256k1.curve.p()
_CURVE = SECP256k1.curve


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _int(data: bytes) -> int:
    return int.from_bytes(data, 'big')


def _bytes(value: int) -> bytes:
    return value.to_bytes(32, 'big')


def _scalar(seckey: bytes) -> int:
    if len(seckey) != 32:
        raise ValueError('secret key must be 32 bytes')
    d = _int(seckey)
    if not 1 <= d < _N:
        raise ValueError('secret key out of range')
    return d


def lift_x(x: bytes) -> PointJacobi:
    """The curve point with this x coordinate and even y."""
    if len(x) != 32:
        raise ValueError('x coordinate must be 32 bytes')
    xi = _int(x)
    if xi >= _P:
        raise ValueError('x coordinate out of range')
    y_sq = (pow(xi, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        raise ValueError('not a point on the curve')
    if y & 1:
        y = _P - y
    return PointJacobi.from_affine(Point(_CURVE, xi, y, _N))


def uncompressed(x: bytes) -> bytes:
    """The even-y point for an x-only key as 04 || x || y."""
    point = lift_x(x)
    return b'\x04' + _bytes(point.x()) + _bytes(point.y())


def pubkey(seckey: bytes) -> bytes:
    """The x-only public key."""
    return _bytes((_scalar(seckey) * _G).x())


def sign(seckey: bytes, msg: bytes, aux: bytes | None = None) -> bytes:
    """Sign a 32-byte message; aux is the 32-byte auxiliary randomness."""
    if len(msg) != 32:
        raise ValueError('message must be 32 bytes')
    aux = os.urandom(32) if aux is None else aux
    if len(aux) != 32:
        raise ValueError('aux must be 32 bytes')
    d0 = _scalar(seckey)
    point = d0 * _G
    d = d0 if point.y() % 2 == 0 else _N - d0
    px = _bytes(point.x())
    mask = _tagged_hash('BIP0340/aux', aux)
    t = bytes(a ^ b for a, b in zip(_bytes(d), mask))
    k0 = _int(_tagged_hash('BIP0340/nonce', t + px + msg)) % _N
    if k0 == 0:
        raise ValueError('nonce is zero')
    r = k0 * _G
    k = k0 if r.y() % 2 == 0 else _N - k0
    rx = _bytes(r.x())
    e = _int(_tagged_hash('BIP0340/challenge', rx + px + msg)) % _N
    sig = rx + _bytes((k + e * d) % _N)
    if not verify(px, msg, sig):
        raise RuntimeError('signature does not verify')
    return sig


def verify(pubkey_x: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pubkey_x) != 32 or len(msg) != 32 or len(sig) != 64:
        return False
    try:
        point = lift_x(pubkey_x)
    except ValueError:
        return False
    r = _int(sig[:32])
    s = _int(sig[32:])
    if r >= _P or s >= _N:
        return False
    e = _int(_tagged_hash('BIP0340/challenge', sig[:32] + pubkey_x + msg)) % _N
    rp = s * _G + (_N - e) * point
    return rp != INFINITY and rp.y() % 2 == 0 and rp.x() == r


def ecdh_x(seckey: bytes, peer_x: bytes) -> bytes:
    """The x coordinate of seckey * lift_x(peer_x): the NIP-44 shared secret."""
    return _bytes((_scalar(seckey) * lift_x(peer_x)).x())
