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
SUBSCRIPTION_ID = 'nip46'

MessageHandler = Callable[[list, 'RelayConn'], Awaitable[None]]


class RelayConn:
    def __init__(self, url: str, pubkey_hex: str, handler: MessageHandler):
        self.url = url
        self._pubkey = pubkey_hex
        self._handler = handler
        self._ws: ClientConnection | None = None
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f'relay:{self.url}')

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
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
        try:
            await self._handler(message, self)
        except Exception:
            log.exception('%s: message handler failed', self.url)
