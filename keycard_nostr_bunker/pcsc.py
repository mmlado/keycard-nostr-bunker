"""Which PC/SC readers hold a card, as pcscd reports them."""

import time
from typing import Protocol

from smartcard.scard import (
    SCARD_E_NO_READERS_AVAILABLE,
    SCARD_E_TIMEOUT,
    SCARD_E_UNKNOWN_READER,
    SCARD_S_SUCCESS,
    SCARD_SCOPE_USER,
    SCARD_STATE_CHANGED,
    SCARD_STATE_PRESENT,
    SCARD_STATE_UNAWARE,
    SCardEstablishContext,
    SCardGetErrorMessage,
    SCardGetStatusChange,
    SCardListReaders,
    SCardReleaseContext,
)


class PcscLost(Exception):
    """pcscd is not running, or restarted since the last call."""


class Presence(Protocol):
    def wait(self, timeout_ms: int) -> set[str]: ...

    def close(self) -> None: ...


class PcscPresence:
    """One PC/SC context, established again after pcscd goes away. Used by one thread."""

    def __init__(self) -> None:
        self._context: int | None = None
        self._states: dict[str, int] = {}

    def wait(self, timeout_ms: int) -> set[str]:
        """Block until a card or reader changes, or the timeout; return the readers with a card.

        Raises PcscLost; the next call then starts with a new context.
        """
        if self._context is None:
            hresult, context = SCardEstablishContext(SCARD_SCOPE_USER)
            if hresult != SCARD_S_SUCCESS:
                raise PcscLost(SCardGetErrorMessage(hresult))
            self._context, self._states = context, {}
        hresult, readers = SCardListReaders(self._context, [])
        if hresult == SCARD_E_NO_READERS_AVAILABLE:
            readers = []
        elif hresult != SCARD_S_SUCCESS:
            self._lost(hresult)
        if not readers:
            # Nothing for pcscd to wait on; its reader-arrival notice is not portable.
            time.sleep(timeout_ms / 1000)
            return set()
        hresult, states = SCardGetStatusChange(
            self._context, timeout_ms,
            [(reader, self._states.get(reader, SCARD_STATE_UNAWARE)) for reader in readers])
        if hresult == SCARD_S_SUCCESS:
            self._states = {reader: state & ~SCARD_STATE_CHANGED for reader, state, _ in states}
        elif hresult not in (SCARD_E_TIMEOUT, SCARD_E_UNKNOWN_READER):
            self._lost(hresult)
        return {reader for reader in readers
                if self._states.get(reader, 0) & SCARD_STATE_PRESENT}

    def close(self) -> None:
        if self._context is not None:
            SCardReleaseContext(self._context)
            self._context = None

    def _lost(self, hresult: int) -> None:
        self.close()
        raise PcscLost(SCardGetErrorMessage(hresult))
