"""KeycardSigner against a fake card."""

import logging
import queue
import threading
from types import SimpleNamespace

import pytest
from keycard.constants import DerivationOption, SigningAlgorithm
from keycard.exceptions import APDUError
from smartcard.Exceptions import CardConnectionException, NoCardException

from keycard_nostr_bunker import card as card_module
from keycard_nostr_bunker import schnorr
from keycard_nostr_bunker.card import CardError, CardNotPresent, KeycardSigner, list_readers
from keycard_nostr_bunker.config import KeycardConfig
from keycard_nostr_bunker.pcsc import PcscLost
from keycard_nostr_bunker.state import StateDir

SECKEY = (7).to_bytes(32, 'big')
KEY_UID = b'\x01' * 32
PATH = "m/43'/60'/1581'/0'/0"
READER = 'Fake Reader 00 00'


class FakeTransport:
    def __init__(self, card):
        self.card = card
        self.connected = None

    def connect(self, index=0):
        if self.card.empty:
            raise NoCardException('no card', hresult=0)
        self.connected = index

    def disconnect(self):
        self.connected = None


class FakeCard:
    def __init__(self, version, cas, pin='123456', key_loaded=True, seckey=SECKEY, empty=False,
                 key_uid=KEY_UID, pin_retries=3, blocked=False):
        self.cas = cas
        self.empty = empty
        self.transport = FakeTransport(self)
        self.version = version
        self.pin = pin
        self.key_loaded = key_loaded
        self.seckey = seckey
        self.key_uid = key_uid
        self.pin_retries = pin_retries
        self.blocked = blocked
        self.channel_open = False
        self.pin_verified = False
        self.fail_next = None
        self.calls = []

    def select(self):
        return SimpleNamespace(is_initialized=True, pin_retries=self.pin_retries,
                               key_uid=self.key_uid if self.key_loaded else b'')

    def open_secure_channel(self):
        self.channel_open = True

    def verify_pin(self, pin):
        self.calls.append(('verify_pin', pin))
        if self.blocked:
            raise RuntimeError('PIN is blocked')
        self.pin_verified = pin == self.pin
        return self.pin_verified

    def export_key(self, derivation_option, public_only, keypath=None, **_):
        assert self.channel_open and self.pin_verified
        assert derivation_option == DerivationOption.DERIVE and keypath == PATH
        self.calls.append(('export_key', public_only))
        return SimpleNamespace(public_key=schnorr.uncompressed(schnorr.pubkey(self.seckey)),
                               private_key=None)

    def _maybe_fail(self):
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error

    def sign_with_path(self, digest, path, algorithm, **_):
        self._maybe_fail()
        assert path == PATH and algorithm == SigningAlgorithm.SCHNORR_BIP340
        self.calls.append(('sign', digest))
        return SimpleNamespace(signature=schnorr.sign(self.seckey, digest))

    def ecdh(self, public_key, path):
        self._maybe_fail()
        assert path == PATH and len(public_key) == 65 and public_key[0] == 4
        self.calls.append(('ecdh', public_key))
        return schnorr.ecdh_x(self.seckey, public_key[1:33])


class FakePresence:
    """What pcscd reports, one fed event per wait; feed returns once the watcher handled it."""

    def __init__(self):
        self.events = queue.Queue()
        self.current = set()
        self.handled = None
        self.closed = False

    def wait(self, timeout_ms):
        if self.handled is not None:
            self.handled.set()
            self.handled = None
        try:
            event, self.handled = self.events.get(timeout=timeout_ms / 1000)
        except queue.Empty:
            return set(self.current)
        if isinstance(event, Exception):
            raise event
        self.current = set(event)
        return set(event)

    def close(self):
        self.closed = True

    def feed(self, event):
        handled = threading.Event()
        self.events.put((event, handled))
        assert handled.wait(5), 'the watcher did not handle the event'


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """A signer factory; `cards` records every card the factory handed out."""
    monkeypatch.setattr(card_module, 'WAIT_MS', 20)
    monkeypatch.setattr(card_module, 'RETRY_MIN', 0.01)
    monkeypatch.setattr(card_module, 'RETRY_MAX', 0.02)
    cards, presences, signers = [], [], []
    state = {'readers': [READER], 'card_kwargs': {}}

    def presence():
        presences.append(FakePresence())
        return presences[-1]

    def make(version=(4, 0), pin='123456', start=True, **cfg_kwargs):
        cfg = KeycardConfig(pin=pin, **cfg_kwargs)

        def factory(cas):
            cards.append(FakeCard(version, cas, **state['card_kwargs']))
            return cards[-1]

        signer = KeycardSigner(cfg, cfg.pin, StateDir(tmp_path), factory,
                               lambda: list(state['readers']), presence)
        signers.append(signer)
        if start:
            signer.start()
        return signer

    yield SimpleNamespace(make=make, cards=cards, presences=presences, state=state, path=tmp_path)
    for signer in signers:
        signer.stop()


def verify_calls(card):
    return [c for c in card.calls if c[0] == 'verify_pin']


def test_signs_and_ecdh_on_card(rig):
    signer = rig.make()
    assert signer.present and signer.version == (4, 0) and signer.refused is None
    assert signer.pubkey == schnorr.pubkey(SECKEY)
    identity = (rig.path / 'user.pubkey').read_text()
    assert identity == f'{schnorr.pubkey(SECKEY).hex()}\n{KEY_UID.hex()}\n'
    digest = bytes(range(32))
    assert schnorr.verify(signer.pubkey, digest, signer.sign(digest))
    peer = (11).to_bytes(32, 'big')
    assert signer.ecdh(schnorr.pubkey(peer)) == schnorr.ecdh_x(peer, signer.pubkey)
    assert [c[0] for c in rig.cards[0].calls] == ['verify_pin', 'export_key', 'sign', 'ecdh']
    assert rig.cards[0].transport.connected == 0


def test_ecdh_cached_per_session(rig):
    signer = rig.make()
    peer = schnorr.pubkey((11).to_bytes(32, 'big'))
    assert signer.ecdh(peer) == signer.ecdh(peer)
    assert len([c for c in rig.cards[0].calls if c[0] == 'ecdh']) == 1
    signer.detach(READER)
    with pytest.raises(CardNotPresent):
        signer.ecdh(peer)
    signer.attach(READER)
    signer.ecdh(peer)
    assert len([c for c in rig.cards[1].calls if c[0] == 'ecdh']) == 1


def test_watcher_follows_the_card(rig):
    signer = rig.make()
    pcscd = rig.presences[-1]
    pcscd.feed({READER})
    assert signer.present and len(rig.cards) == 1
    pcscd.feed(set())
    assert not signer.present
    pcscd.feed({READER})
    assert signer.present and len(rig.cards) == 2


def test_lost_pcscd_closes_the_session_until_it_is_back(rig, caplog):
    caplog.set_level(logging.INFO, logger='keycard_nostr_bunker.card')
    signer = rig.make()
    pcscd = rig.presences[-1]
    pcscd.feed({READER})
    pcscd.feed(PcscLost('RPC transport error.'))
    assert not signer.present and rig.cards[0].transport.connected is None
    with pytest.raises(CardNotPresent, match='not present'):
        signer.sign(bytes(32))
    pcscd.feed(PcscLost('Service not available.'))
    pcscd.feed({READER})
    assert signer.present and len(rig.cards) == 2 and len(verify_calls(rig.cards[1])) == 1
    assert caplog.text.count('lost pcscd (RPC transport error.)') == 1
    assert 'Service not available' not in caplog.text
    assert caplog.text.count('pcscd is back') == 1


def test_refused_card_is_tried_again_after_pcscd_is_back(rig):
    signer = rig.make((3, 1))
    pcscd = rig.presences[-1]
    pcscd.feed({READER})
    assert len(rig.cards) == 1
    pcscd.feed(PcscLost('RPC transport error.'))
    assert signer.refused is None
    pcscd.feed({READER})
    assert len(rig.cards) == 2 and 'Schnorr' in signer.refused


def test_stop_ends_the_watcher(rig):
    signer = rig.make()
    watcher = signer._watcher
    signer.stop()
    assert not watcher.is_alive() and rig.presences[-1].closed
    assert not signer.present


def test_no_reader_at_start(rig):
    rig.state['readers'] = []
    signer = rig.make()
    assert not signer.present
    with pytest.raises(CardNotPresent):
        signer.pubkey
    with pytest.raises(CardNotPresent, match='not present'):
        signer.sign(bytes(32))
    rig.state['readers'] = [READER]
    signer.attach(READER)
    assert signer.present and signer.pubkey == schnorr.pubkey(SECKEY)


def test_empty_reader_then_insert(rig):
    rig.state['card_kwargs'] = {'empty': True}
    signer = rig.make()
    assert not signer.present and signer.refused is None
    rig.state['card_kwargs'] = {}
    signer.attach(READER)
    assert signer.present


def test_cached_pubkey_without_card(rig):
    (rig.path / 'user.pubkey').write_text(schnorr.pubkey(SECKEY).hex() + '\n')
    rig.state['readers'] = []
    signer = rig.make()
    assert signer.pubkey == schnorr.pubkey(SECKEY)
    with pytest.raises(CardNotPresent):
        signer.ecdh(schnorr.pubkey((11).to_bytes(32, 'big')))


def test_old_identity_file_gets_the_key_uid(rig):
    (rig.path / 'user.pubkey').write_text(schnorr.pubkey(SECKEY).hex() + '\n')
    rig.make()
    assert (rig.path / 'user.pubkey').read_text().splitlines()[1] == KEY_UID.hex()


def test_wrong_card_refused_before_the_pin(rig):
    (rig.path / 'user.pubkey').write_text(f'{schnorr.pubkey(SECKEY).hex()}\n{"02" * 32}\n')
    signer = rig.make()
    assert not signer.present
    assert 'key UID' in signer.refused
    assert verify_calls(rig.cards[0]) == []
    assert rig.cards[0].transport.connected is None
    with pytest.raises(CardNotPresent, match='refused'):
        signer.sign(bytes(32))


def test_wrong_key_refused_after_the_pin(rig):
    (rig.path / 'user.pubkey').write_text(schnorr.pubkey((9).to_bytes(32, 'big')).hex() + '\n')
    signer = rig.make()
    assert not signer.present and 'not the known user key' in signer.refused
    assert rig.cards[0].transport.connected is None


def test_detach_drops_session_and_clears_refusal(rig):
    signer = rig.make()
    signer.detach('Other Reader')
    assert signer.present
    signer.detach(READER)
    assert not signer.present
    with pytest.raises(CardNotPresent):
        signer.sign(bytes(32))


def test_session_reopened_after_a_transmit_error(rig):
    signer = rig.make()
    rig.cards[0].fail_next = CardConnectionException('card was reset')
    digest = bytes(range(32))
    assert schnorr.verify(signer.pubkey, digest, signer.sign(digest))
    assert len(rig.cards) == 2 and signer.present
    assert rig.cards[0].transport.connected is None and rig.cards[1].transport.connected == 0
    rig.cards[1].fail_next = APDUError(0x6982)
    assert schnorr.verify(signer.pubkey, digest, signer.sign(digest))
    assert len(rig.cards) == 3


def test_reopen_fails_when_the_card_is_gone(rig):
    signer = rig.make()
    rig.cards[0].fail_next = CardConnectionException('removed')
    rig.state['card_kwargs'] = {'empty': True}
    with pytest.raises(CardNotPresent):
        signer.sign(bytes(32))
    assert not signer.present


def test_second_card_ignored_while_one_is_attached(rig):
    signer = rig.make()
    signer.attach('Second Reader')
    signer.attach(READER)
    assert len(rig.cards) == 1 and signer.present


def test_reader_filter(rig):
    rig.state['readers'] = [READER, 'Other Reader 01 00']
    signer = rig.make(reader='Other')
    assert signer.present and rig.cards[0].transport.connected == 1
    assert len(rig.cards) == 1


def test_wrong_pin_tried_once_and_remembered(rig):
    signer = rig.make(pin='000000')
    assert not signer.present and 'wrong PIN' in signer.refused
    signer.attach(READER)
    assert len(rig.cards) == 1 and verify_calls(rig.cards[0]) == [('verify_pin', '000000')]
    assert (rig.path / 'pin.rejected').exists()
    again = rig.make(pin='000000')
    assert not again.present and 'rejected for this card earlier' in again.refused
    assert verify_calls(rig.cards[1]) == []
    fixed = rig.make(pin='123456')
    assert fixed.present and not (rig.path / 'pin.rejected').exists()


def test_last_pin_attempt_is_not_spent(rig):
    rig.state['card_kwargs'] = {'pin_retries': 1}
    signer = rig.make()
    assert not signer.present and 'attempt left' in signer.refused
    assert verify_calls(rig.cards[0]) == []


def test_blocked_pin_counts_as_rejected(rig):
    rig.state['card_kwargs'] = {'blocked': True}
    signer = rig.make()
    assert not signer.present and 'wrong PIN' in signer.refused


def test_refused_reader_waits_for_a_different_card(rig):
    rig.state['card_kwargs'] = {'key_loaded': False}
    signer = rig.make()
    assert not signer.present and 'no key' in signer.refused
    assert rig.cards[0].transport.connected is None
    signer.attach(READER)
    assert len(rig.cards) == 1
    signer.detach(READER)
    assert signer.refused is None
    rig.state['card_kwargs'] = {}
    signer.attach(READER)
    assert signer.present


def test_old_applet_refused(rig):
    signer = rig.make((3, 1))
    assert not signer.present and 'Schnorr' in signer.refused
    assert verify_calls(rig.cards[0]) == []


def test_trusted_cas(rig):
    from keycard import constants
    dev = '0317830be73e60535a18b9ebac1795d5247ad66073c943ece13fd05cd2ae7a3388'
    rig.make(trust_test_ca=True, ca_public_keys=[dev])
    assert rig.cards[0].cas == [constants.OFFICIAL_CA_PUBLIC_KEY, constants.TEST_CA_PUBLIC_KEY,
                                bytes.fromhex(dev)]


def test_list_readers_without_pcscd(monkeypatch):
    from smartcard.pcsc.PCSCExceptions import EstablishContextException

    def broken():
        raise EstablishContextException(0x8010001D)

    monkeypatch.setattr(card_module, 'pcsc_readers', broken)
    with pytest.raises(CardError, match='pcscd'):
        list_readers()
