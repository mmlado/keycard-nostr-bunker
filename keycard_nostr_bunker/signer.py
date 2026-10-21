"""A Nostr identity: x-only public key, BIP-340 signing and ECDH."""

import os
from pathlib import Path
from typing import Protocol

from . import schnorr


class SignerUnavailable(Exception):
    """The signer cannot serve right now; the message is safe to show the client."""


class Signer(Protocol):
    @property
    def pubkey(self) -> bytes: ...

    def sign(self, digest: bytes) -> bytes: ...

    def ecdh(self, peer_pubkey: bytes) -> bytes: ...


class SoftwareSigner:
    """A secp256k1 secret key held in memory."""

    def __init__(self, seckey: bytes):
        self.seckey = seckey
        self._pubkey = schnorr.pubkey(seckey)

    @property
    def pubkey(self) -> bytes:
        return self._pubkey

    def sign(self, digest: bytes) -> bytes:
        return schnorr.sign(self.seckey, digest)

    def ecdh(self, peer_pubkey: bytes) -> bytes:
        return schnorr.ecdh_x(self.seckey, peer_pubkey)

    @classmethod
    def generate(cls) -> 'SoftwareSigner':
        return cls(os.urandom(32))

    @classmethod
    def load(cls, path: str | Path) -> 'SoftwareSigner':
        return cls(bytes.fromhex(Path(path).read_text().strip()))

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(self.seckey.hex() + '\n')

    @classmethod
    def load_or_generate(cls, path: str | Path) -> 'SoftwareSigner':
        if Path(path).exists():
            return cls.load(path)
        signer = cls.generate()
        signer.save(path)
        return signer
