"""Keycard-backed signer.

Applet 4.x signs BIP-340 Schnorr and computes ECDH on the card. Older applets
can do neither and are ignored as if no card were inserted.

The signer runs without a card: it watches the PC/SC readers, opens a session
when the card is inserted and drops it when the card is removed. Until then
signing and ECDH raise CardNotPresent. When pcscd goes away the session is
dropped too, and the card is opened again once pcscd is back.
"""

import hashlib
import logging
import threading
from typing import Callable, TypeVar

from keycard import KeyCard, constants
from keycard.constants import DerivationOption, SigningAlgorithm
from keycard.exceptions import KeyCardError
from smartcard.Exceptions import SmartcardException
from smartcard.pcsc.PCSCExceptions import BaseSCardException
from smartcard.System import readers as pcsc_readers

from . import schnorr
from .pcsc import PcscLost, PcscPresence, Presence, hint
from .state import StateDir, write_private
from .config import KeycardConfig
from .signer import SignerUnavailable

log = logging.getLogger(__name__)

T = TypeVar('T')

MIN_APPLET_VERSION = (4, 0)
WAIT_MS = 1000
RETRY_MIN = 1.0
RETRY_MAX = 30.0


class CardError(Exception):
    pass


class CardNotPresent(CardError, SignerUnavailable):
    pass


def _new_card(ca_public_keys: list[bytes]) -> KeyCard:
    return KeyCard(ca_public_keys=ca_public_keys)


def list_readers() -> list[str]:
    try:
        return [str(reader) for reader in pcsc_readers()]
    except (SmartcardException, BaseSCardException) as e:
        raise CardError(f'PC/SC not available: {e}; {hint(e.hresult)}') from e


class _Session:
    def __init__(self, card: KeyCard, reader: str, version: tuple[int, int]):
        self.card = card
        self.reader = reader
        self.version = version
        # Per-peer ECDH results; dies with the session, so nothing survives the card.
        self.shared: dict[bytes, bytes] = {}


class KeycardSigner:
    def __init__(self, cfg: KeycardConfig, pin: str, state: StateDir,
                 card_factory: Callable[[list[bytes]], KeyCard] = _new_card,
                 readers_fn: Callable[[], list[str]] = list_readers,
                 presence_factory: Callable[[], Presence] | None = PcscPresence):
        self._cfg = cfg
        self._pin = pin
        self._pubkey_file = state.user_pubkey
        self._rejection_file = state.pin_rejected
        self._card_factory = card_factory
        self._readers_fn = readers_fn
        self._presence_factory = presence_factory
        self._watcher: threading.Thread | None = None
        self._stopping = threading.Event()
        self._lock = threading.RLock()
        self._session: _Session | None = None
        self._pin_rejected: set[bytes] = set()
        self._failed: set[str] = set()
        self.refused: str | None = None
        self._pubkey: bytes | None = None
        self._key_uid: bytes | None = None
        self._load_identity()

    @property
    def pubkey(self) -> bytes:
        if self._pubkey is None:
            raise CardNotPresent('Keycard not present')
        return self._pubkey

    @property
    def present(self) -> bool:
        return self._session is not None

    @property
    def version(self) -> tuple[int, int]:
        return self._session.version if self._session else (0, 0)

    def start(self) -> None:
        """Open a session with a card already inserted, then watch the readers."""
        readers = self._readers_fn()
        if not readers:
            log.warning('Keycard: no reader found, waiting for one')
        for reader in readers:
            self.attach(reader)
        if self._presence_factory is not None:
            self._stopping.clear()
            self._watcher = threading.Thread(target=self._watch, args=(self._presence_factory(),),
                                             name='keycard-watch', daemon=True)
            self._watcher.start()

    def stop(self) -> None:
        if self._watcher is not None:
            self._stopping.set()
            self._watcher.join(timeout=WAIT_MS / 1000 + 1)
            self._watcher = None
        with self._lock:
            self._drop()

    def attach(self, reader: str) -> None:
        """Open a session with the card in this reader; errors are logged."""
        with self._lock:
            if self._cfg.reader and self._cfg.reader not in reader:
                log.info('Keycard: ignoring reader %s', reader)
                return
            if self._session is not None:
                if self._session.reader != reader:
                    log.info('Keycard: already using %s, ignoring %s', self._session.reader, reader)
                return
            if reader in self._failed:
                log.debug('Keycard: %s was refused, waiting for a different card', reader)
                return
            try:
                self._open(reader)
            except SmartcardException as e:
                log.debug('Keycard: no card in %s: %s', reader, e)
            except Exception as e:
                self._failed.add(reader)
                self.refused = str(e)
                log.error('Keycard: %s: %s', reader, e)

    def detach(self, reader: str) -> None:
        with self._lock:
            self._failed.discard(reader)
            self.refused = None
            if self._session is not None and self._session.reader == reader:
                log.warning('Keycard: card removed from %s', reader)
                self._drop()

    def _watch(self, presence: Presence) -> None:
        present: set[str] = set()
        lost = False
        delay = RETRY_MIN
        try:
            while not self._stopping.is_set():
                try:
                    now = presence.wait(WAIT_MS)
                except PcscLost as e:
                    if not lost:
                        lost = True
                        present = set()
                        log.warning('Keycard: lost pcscd (%s); waiting for it to come back', e)
                        self._pcscd_lost()
                    self._stopping.wait(delay)
                    delay = min(delay * 2, RETRY_MAX)
                    continue
                if lost:
                    lost = False
                    delay = RETRY_MIN
                    log.info('Keycard: pcscd is back')
                for reader in present - now:
                    self.detach(reader)
                for reader in now - present:
                    self.attach(reader)
                present = now
        finally:
            presence.close()

    def _pcscd_lost(self) -> None:
        """Its card handles died with it; the cards are opened again when it is back."""
        with self._lock:
            self._drop()
            self._failed.clear()
            self.refused = None

    def sign(self, digest: bytes) -> bytes:
        with self._lock:
            return self._call(lambda card: card.sign_with_path(
                digest, self._cfg.key_path,
                algorithm=SigningAlgorithm.SCHNORR_BIP340).signature)

    def ecdh(self, peer_pubkey: bytes) -> bytes:
        peer = schnorr.uncompressed(peer_pubkey)
        with self._lock:
            cached = self._require().shared.get(peer_pubkey)
            if cached is not None:
                return cached
            shared = self._call(lambda card: card.ecdh(peer, self._cfg.key_path))
            self._require().shared[peer_pubkey] = shared
            return shared

    def _open(self, reader: str) -> None:
        readers = self._readers_fn()
        if reader not in readers:
            raise CardError(f'reader {reader} not found')
        card = self._card_factory(self._trusted_cas())
        card.transport.connect(readers.index(reader))
        try:
            self._open_session(card, reader)
        except BaseException:
            try:
                card.transport.disconnect()
            except Exception:
                pass
            raise

    def _open_session(self, card: KeyCard, reader: str) -> None:
        info = card.select()
        version = card.version
        log.info('Keycard: applet %d.%d in %s', version[0], version[1], reader)
        if version < MIN_APPLET_VERSION:
            raise CardError(f'applet {version[0]}.{version[1]} has no Schnorr or ECDH')
        if not info.is_initialized:
            raise CardError('card is not initialized')
        if not info.key_uid:
            raise CardError('card has no key loaded')
        key_uid = bytes(info.key_uid)
        if self._key_uid is not None and key_uid != self._key_uid:
            raise CardError('not the known user card (key UID differs); insert the right card, '
                            f'or delete {self._pubkey_file} after loading a new key')
        if key_uid in self._pin_rejected or self._rejected_earlier(key_uid):
            self._pin_rejected.add(key_uid)
            raise CardError('PIN was rejected for this card earlier; fix keycard.pin and restart')
        retries = info.pin_retries
        if retries is not None and retries <= 1:
            self._pin_rejected.add(key_uid)
            raise CardError(f'only {retries} PIN attempt left; not spending it. '
                            'Check the PIN with keycard-cli, or unblock it with the PUK')
        card.open_secure_channel()
        try:
            verified = card.verify_pin(self._pin)
        except RuntimeError:
            verified = False
        if not verified:
            self._pin_rejected.add(key_uid)
            self._remember_rejection(key_uid)
            raise CardError('wrong PIN; not retrying, to keep the card from blocking')
        self._forget_rejection()
        log.info('Keycard: PIN verified')
        pubkey = self._export_pubkey(card)
        if self._pubkey is not None and pubkey != self._pubkey:
            raise CardError(f'key at {self._cfg.key_path} is not the known user key; '
                            f'delete {self._pubkey_file} after a key_path change')
        if self._pubkey is None or self._key_uid is None:
            self._pubkey, self._key_uid = pubkey, key_uid
            self._save_identity()
        self._session = _Session(card, reader, version)
        self.refused = None
        self._failed.discard(reader)
        log.info('Keycard: ready')

    def _drop(self) -> None:
        if self._session is None:
            return
        try:
            self._session.card.transport.disconnect()
        except Exception:
            pass
        self._session = None

    def _require(self) -> _Session:
        if self._session is None:
            if self.refused:
                raise CardNotPresent(f'Keycard refused: {self.refused}')
            raise CardNotPresent('Keycard not present')
        return self._session

    def _call(self, op: Callable[[KeyCard], T]) -> T:
        session = self._require()
        try:
            return op(session.card)
        except (SmartcardException, KeyCardError) as e:
            log.warning('Keycard: %s; reopening the session', e)
        reader = session.reader
        self._drop()
        try:
            self._open(reader)
        except SmartcardException as e:
            log.warning('Keycard: reopening %s failed: %s', reader, e)
            raise CardNotPresent('Keycard not present') from e
        except CardError as e:
            self._failed.add(reader)
            self.refused = str(e)
            raise CardNotPresent(f'Keycard refused: {e}') from e
        return op(self._require().card)

    def _trusted_cas(self) -> list[bytes]:
        cas = [constants.OFFICIAL_CA_PUBLIC_KEY]
        if self._cfg.trust_test_ca:
            cas.append(constants.TEST_CA_PUBLIC_KEY)
        cas.extend(bytes.fromhex(key) for key in self._cfg.ca_public_keys)
        return cas

    def _export_pubkey(self, card: KeyCard) -> bytes:
        exported = card.export_key(
            DerivationOption.DERIVE, public_only=True, keypath=self._cfg.key_path)
        if not exported.public_key:
            raise CardError('card returned no public key')
        return exported.public_key[1:33]

    def _load_identity(self) -> None:
        if not self._pubkey_file.exists():
            return
        lines = self._pubkey_file.read_text().split()
        if lines:
            self._pubkey = bytes.fromhex(lines[0])
        if len(lines) > 1:
            self._key_uid = bytes.fromhex(lines[1])

    def _save_identity(self) -> None:
        assert self._pubkey is not None and self._key_uid is not None
        write_private(self._pubkey_file, f'{self._pubkey.hex()}\n{self._key_uid.hex()}\n')

    def _rejection_digest(self, key_uid: bytes) -> str:
        return hashlib.sha256(key_uid + self._pin.encode()).hexdigest()

    def _rejected_earlier(self, key_uid: bytes) -> bool:
        """Whether this PIN was already refused by this card in an earlier run."""
        if not self._rejection_file.exists():
            return False
        return self._rejection_file.read_text().strip() == self._rejection_digest(key_uid)

    def _remember_rejection(self, key_uid: bytes) -> None:
        write_private(self._rejection_file, self._rejection_digest(key_uid) + '\n')

    def _forget_rejection(self) -> None:
        try:
            self._rejection_file.unlink()
        except FileNotFoundError:
            pass
