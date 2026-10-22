import asyncio
import json
import logging
import time
from typing import Any, Awaitable, Callable, Protocol

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed
from websockets.protocol import State

from .replay import WINDOW

log = logging.getLogger(__name__)

RECONNECT_MIN = 3.0
RECONNECT_MAX = 30.0
RESUBSCRIBE_MIN = 5.0
RESUBSCRIBE_MAX = 300.0
SUBSCRIPTION_ID = 'nip46'
MAX_IN_FLIGHT = 64
STOP_GRACE = 5.0


class Relay(Protocol):
    """One relay connection, as the run loop uses it."""

    url: str

    def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def send(self, message: list) -> bool: ...


MessageHandler = Callable[[list, Relay], Awaitable[None]]
RelayFactory = Callable[[str, str, MessageHandler], Relay]


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
        # Requests older than the replay window are refused anyway, so do not ask for them.
        since = int(time.time()) - WINDOW
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


Serve = Callable[[dict[str, Any], str], dict[str, Any] | None]


class _Turns:
    """One client's requests, served one at a time in the order they came."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.waiting = 0


class RelayPool:
    """Every relay the bunker uses: requests come in from any, replies go out to all.

    serve turns a request event and the URL it came from into a reply event, or
    None. It runs on a worker thread, one request per client at a time, so a slow
    request, such as an approval prompt or a card reopen, holds up only its client.
    """

    def __init__(self, urls: list[str], pubkey_hex: str, serve: Serve,
                 factory: RelayFactory = RelayConn):
        self._serve = serve
        self._relays = [factory(url, pubkey_hex, self._on_message) for url in urls]
        self._in_flight: set[asyncio.Task] = set()
        self._turns: dict[str, _Turns] = {}

    def start(self) -> None:
        for relay in self._relays:
            relay.start()

    async def stop(self) -> None:
        """Answer the requests already taken, unless one hangs, then close the relays."""
        if self._in_flight:
            await asyncio.wait(set(self._in_flight), timeout=STOP_GRACE)
        for task in self._in_flight:
            task.cancel()
        await asyncio.gather(*self._in_flight, return_exceptions=True)
        for relay in self._relays:
            await relay.stop()

    async def _on_message(self, message: list, relay: Relay) -> None:
        match message:
            case ['EVENT', _, dict() as event]:
                # A flood waits here, on the relay's read loop, instead of piling up tasks.
                while len(self._in_flight) >= MAX_IN_FLIGHT:
                    await asyncio.wait(self._in_flight, return_when=asyncio.FIRST_COMPLETED)
                task = asyncio.create_task(self._handle(event, relay))
                self._in_flight.add(task)
                task.add_done_callback(self._in_flight.discard)
            case ['OK', event_id, accepted, *rest]:
                reason = rest[0] if rest else ''
                if accepted:
                    log.debug('Event %s accepted %s', str(event_id)[:8], reason)
                else:
                    log.warning('%s rejected reply %s: %s', relay.url, str(event_id)[:8], reason)
            case ['NOTICE', text]:
                log.info('Relay notice from %s: %s', relay.url, text)
            case ['EOSE', _]:
                log.debug('EOSE from %s', relay.url)
            case _:
                log.debug('Ignored relay message: %s', message[0])

    async def _handle(self, event: dict[str, Any], relay: Relay) -> None:
        # Unverified here; a forged pubkey only queues behind that client's requests.
        client = str(event.get('pubkey'))
        turns = self._turns.setdefault(client, _Turns())
        turns.waiting += 1
        try:
            async with turns.lock:
                await self._serve_one(event, relay)
        finally:
            turns.waiting -= 1
            if not turns.waiting:
                del self._turns[client]

    async def _serve_one(self, event: dict[str, Any], relay: Relay) -> None:
        try:
            reply = await asyncio.to_thread(self._serve, event, relay.url)
        except Exception:
            log.exception('NIP-46 request handling failed')
            return
        if reply:
            # One relay failing must not keep the reply from the others.
            await asyncio.gather(*(r.send(['EVENT', reply]) for r in self._relays),
                                 return_exceptions=True)
