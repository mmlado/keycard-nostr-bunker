"""PcscPresence against fake PC/SC calls."""

import pytest
from smartcard.scard import (
    SCARD_E_NO_READERS_AVAILABLE,
    SCARD_E_NO_SERVICE,
    SCARD_E_TIMEOUT,
    SCARD_F_COMM_ERROR,
    SCARD_S_SUCCESS,
    SCARD_STATE_CHANGED,
    SCARD_STATE_EMPTY,
    SCARD_STATE_PRESENT,
    SCARD_STATE_UNAWARE,
    SCARD_W_SECURITY_VIOLATION,
)

from keycard_nostr_bunker import pcsc
from keycard_nostr_bunker.pcsc import PcscLost, PcscPresence

READER = 'Fake Reader 00 00'


class FakeScard:
    """pcscd: `status` is the scripted SCardGetStatusChange results, oldest first."""

    def __init__(self, monkeypatch):
        self.establish = SCARD_S_SUCCESS
        self.contexts = 0
        self.released = []
        self.readers = [READER]
        self.status = []
        self.asked = []
        self.slept = []
        monkeypatch.setattr(pcsc, 'SCardEstablishContext', self._establish)
        monkeypatch.setattr(pcsc, 'SCardReleaseContext', self.released.append)
        monkeypatch.setattr(pcsc, 'SCardListReaders', self._list)
        monkeypatch.setattr(pcsc, 'SCardGetStatusChange', self._status)
        monkeypatch.setattr(pcsc.time, 'sleep', self.slept.append)

    def _establish(self, scope):
        if self.establish != SCARD_S_SUCCESS:
            return self.establish, 0
        self.contexts += 1
        return SCARD_S_SUCCESS, self.contexts

    def _list(self, context, groups):
        if not self.readers:
            return SCARD_E_NO_READERS_AVAILABLE, []
        return SCARD_S_SUCCESS, list(self.readers)

    def _status(self, context, timeout, states):
        self.asked.append((context, states))
        hresult, event = self.status.pop(0)
        return hresult, [(reader, event, b'') for reader, _ in states]


@pytest.fixture
def scard(monkeypatch):
    return FakeScard(monkeypatch)


def test_reports_the_readers_with_a_card(scard):
    scard.status = [(SCARD_S_SUCCESS, SCARD_STATE_PRESENT | SCARD_STATE_CHANGED),
                    (SCARD_E_TIMEOUT, 0),
                    (SCARD_S_SUCCESS, SCARD_STATE_EMPTY | SCARD_STATE_CHANGED)]
    presence = PcscPresence()
    assert presence.wait(10) == {READER}
    assert presence.wait(10) == {READER}
    assert presence.wait(10) == set()
    assert [states for _, states in scard.asked] == [
        [(READER, SCARD_STATE_UNAWARE)], [(READER, SCARD_STATE_PRESENT)],
        [(READER, SCARD_STATE_PRESENT)]]


def test_lost_context_is_released_and_established_again(scard):
    scard.status = [(SCARD_S_SUCCESS, SCARD_STATE_PRESENT), (SCARD_F_COMM_ERROR, 0),
                    (SCARD_S_SUCCESS, SCARD_STATE_PRESENT)]
    presence = PcscPresence()
    presence.wait(10)
    with pytest.raises(PcscLost, match='RPC transport error'):
        presence.wait(10)
    assert scard.released == [1]
    assert presence.wait(10) == {READER}
    assert scard.asked[-1] == (2, [(READER, SCARD_STATE_UNAWARE)])


def test_without_pcscd(scard):
    scard.establish = SCARD_E_NO_SERVICE
    with pytest.raises(PcscLost, match='Service not available'):
        PcscPresence().wait(10)


def test_refused_by_polkit(scard):
    scard.establish = SCARD_W_SECURITY_VIOLATION
    with pytest.raises(PcscLost, match='Access denied.*polkit'):
        PcscPresence().wait(10)


def test_without_a_reader(scard):
    scard.readers = []
    assert PcscPresence().wait(250) == set()
    assert scard.slept == [0.25] and scard.asked == []


def test_close_releases_the_context(scard):
    scard.status = [(SCARD_E_TIMEOUT, 0)]
    presence = PcscPresence()
    presence.wait(10)
    presence.close()
    presence.close()
    assert scard.released == [1]
