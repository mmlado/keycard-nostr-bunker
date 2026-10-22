"""BIP-340 Schnorr signatures and x-only ECDH on secp256k1.

Every multiplication by a secret scalar runs in OpenSSL, through cryptography,
which does it in constant time; python-ecdsa does not (GHSA-wj6h-64fc-37mp).
Verification only handles public values and stays in plain Python.
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import ec

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
_CURVE = ec.SECP256K1()

Jacobian = tuple[int, int, int]
_INFINITY: Jacobian = (1, 1, 0)


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


def _secret_times_g(k: int) -> tuple[int, int]:
    numbers = ec.derive_private_key(k, _CURVE).public_key().public_numbers()
    return numbers.x, numbers.y


def lift_x(x: bytes) -> tuple[int, int]:
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
    return xi, y if y % 2 == 0 else _P - y


def uncompressed(x: bytes) -> bytes:
    """The even-y point for an x-only key as 04 || x || y."""
    xi, y = lift_x(x)
    return b'\x04' + _bytes(xi) + _bytes(y)


def pubkey(seckey: bytes) -> bytes:
    """The x-only public key."""
    return _bytes(_secret_times_g(_scalar(seckey))[0])


def sign(seckey: bytes, msg: bytes, aux: bytes | None = None) -> bytes:
    """Sign a 32-byte message; aux is the 32-byte auxiliary randomness."""
    if len(msg) != 32:
        raise ValueError('message must be 32 bytes')
    aux = os.urandom(32) if aux is None else aux
    if len(aux) != 32:
        raise ValueError('aux must be 32 bytes')
    d0 = _scalar(seckey)
    px, py = _secret_times_g(d0)
    d = d0 if py % 2 == 0 else _N - d0
    mask = _tagged_hash('BIP0340/aux', aux)
    t = bytes(a ^ b for a, b in zip(_bytes(d), mask))
    k0 = _int(_tagged_hash('BIP0340/nonce', t + _bytes(px) + msg)) % _N
    if k0 == 0:
        raise ValueError('nonce is zero')
    rx, ry = _secret_times_g(k0)
    k = k0 if ry % 2 == 0 else _N - k0
    e = _int(_tagged_hash('BIP0340/challenge', _bytes(rx) + _bytes(px) + msg)) % _N
    sig = _bytes(rx) + _bytes((k + e * d) % _N)
    if not verify(_bytes(px), msg, sig):
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
    x, y, z = _double_mul(s, _G, _N - e, point)
    if z == 0:
        return False
    z_inv = pow(z, -1, _P)
    return y * z_inv ** 3 % _P % 2 == 0 and x * z_inv ** 2 % _P == r


def ecdh_x(seckey: bytes, peer_x: bytes) -> bytes:
    """The x coordinate of seckey * lift_x(peer_x): the NIP-44 shared secret."""
    peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, uncompressed(peer_x))
    return ec.derive_private_key(_scalar(seckey), _CURVE).exchange(ec.ECDH(), peer)


def _double_mul(a: int, pa: tuple[int, int], b: int, pb: tuple[int, int]) -> Jacobian:
    """a * pa + b * pb, for public scalars only: the time depends on a and b."""
    both = _to_affine(_add(_jacobian(pa), pb))
    result = _INFINITY
    for bit in range(max(a.bit_length(), b.bit_length()) - 1, -1, -1):
        result = _double(result)
        step = {(1, 0): pa, (0, 1): pb, (1, 1): both}.get(((a >> bit) & 1, (b >> bit) & 1))
        if step is not None:
            result = _add(result, step)
    return result


def _jacobian(point: tuple[int, int]) -> Jacobian:
    return point[0], point[1], 1


def _to_affine(point: Jacobian) -> tuple[int, int] | None:
    x, y, z = point
    if z == 0:
        return None
    z_inv = pow(z, -1, _P)
    return x * z_inv ** 2 % _P, y * z_inv ** 3 % _P


def _double(point: Jacobian) -> Jacobian:
    x, y, z = point
    if z == 0 or y == 0:
        return _INFINITY
    s = 4 * x * y * y % _P
    m = 3 * x * x % _P
    x3 = (m * m - 2 * s) % _P
    return x3, (m * (s - x3) - 8 * pow(y, 4, _P)) % _P, 2 * y * z % _P


def _add(a: Jacobian, b: tuple[int, int] | None) -> Jacobian:
    """a plus an affine point."""
    if b is None:
        return a
    x1, y1, z1 = a
    if z1 == 0:
        return _jacobian(b)
    z1z1 = z1 * z1 % _P
    u2 = b[0] * z1z1 % _P
    s2 = b[1] * z1 * z1z1 % _P
    if u2 == x1:
        return _double(a) if s2 == y1 else _INFINITY
    h = (u2 - x1) % _P
    r = (s2 - y1) % _P
    hh = h * h % _P
    hhh = h * hh % _P
    v = x1 * hh % _P
    x3 = (r * r - hhh - 2 * v) % _P
    return x3, (r * (v - x3) - y1 * hhh) % _P, z1 * h % _P
