import asyncio
import json
import logging
import time
from typing import Awaitable, Callable

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed
from websockets.protocol import State

from .nip46 import MAX_AGE

log = logging.getLogger(__name__)

RECONNECT_MIN = 3.0
RECONNECT_MAX = 30.0
RESUBSCRIBE_MIN = 5.0
RESUBSCRIBE_MAX = 300.0
SUBSCRIPTION_ID = 'nip46'

MessageHandler = Callable[[list, 'RelayConn'], Awaitable[None]]


class RelayConn:
    def __init__(self, url: str, pubkey_hex: str, handler: MessageHandler):
        self.url = url
        self._pubkey = pubkey_hex
        self._handler = handler
        self._ws: ClientConnection | None = None
        self._task: asyncio.Task | None = None
        self._resubscribe_task: asyncio.Task | None = None
        self._resubscribe_delay = RESUBSCRIBE_MIN

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f'relay:{self.url}')

    async def stop(self) -> None:
        for task in (self._resubscribe_task, self._task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    async def send(self, message: list) -> bool:
        ws = self._ws
        if ws is None or ws.state is not State.OPEN:
            log.warning('%s: not connected, dropping message', self.url)
            return False
        try:
            await ws.send(json.dumps(message))
        except ConnectionClosed as e:
            log.warning('%s: send failed: %s', self.url, e)
            return False
        return True

    async def _run(self) -> None:
        delay = RECONNECT_MIN
        while True:
            try:
                async with connect(self.url) as ws:
                    self._ws = ws
                    log.info('Connected to relay: %s', self.url)
                    delay = RECONNECT_MIN
                    await self._subscribe()
                    async for raw in ws:
                        await self._dispatch(raw)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning('%s: %s', self.url, e)
            finally:
                self._ws = None
            log.info('%s: reconnecting in %.0fs', self.url, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX)

    async def _subscribe(self) -> None:
        # Requests older than MAX_AGE are refused anyway, so do not ask for them.
        since = int(time.time()) - MAX_AGE
        await self.send(['REQ', SUBSCRIPTION_ID,
                         {'kinds': [24133], '#p': [self._pubkey], 'since': since}])

    async def _dispatch(self, raw: str | bytes) -> None:
        try:
            message = json.loads(raw)
        except ValueError as e:
            log.warning('%s: bad message: %s', self.url, e)
            return
        if not isinstance(message, list) or not message:
            return
        ours = len(message) > 1 and message[1] == SUBSCRIPTION_ID
        if message[0] == 'CLOSED' and ours:
            self._closed(str(message[2]) if len(message) > 2 else '')
            return
        if message[0] == 'EOSE' and ours:
            self._resubscribe_delay = RESUBSCRIBE_MIN
        try:
            await self._handler(message, self)
        except Exception:
            log.exception('%s: message handler failed', self.url)

    def _closed(self, reason: str) -> None:
        """The relay ended our subscription; ask again later on the same connection."""
        if reason.startswith('auth-required:'):
            delay = RESUBSCRIBE_MAX
            log.warning('%s closed the subscription: %s; NIP-42 AUTH is not supported, '
                        'trying again in %.0fs', self.url, reason, delay)
        else:
            delay = self._resubscribe_delay
            self._resubscribe_delay = min(delay * 2, RESUBSCRIBE_MAX)
            log.warning('%s closed the subscription: %s; subscribing again in %.0fs',
                        self.url, reason, delay)
        if self._resubscribe_task is None or self._resubscribe_task.done():
            self._resubscribe_task = asyncio.create_task(self._resubscribe(delay, self._ws))

    async def _resubscribe(self, delay: float, ws: ClientConnection | None) -> None:
        await asyncio.sleep(delay)
        # A new connection has already subscribed on its own.
        if ws is not None and self._ws is ws:
            await self._subscribe()
