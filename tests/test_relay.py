import asyncio
import json

from websockets.exceptions import ConnectionClosed
from websockets.protocol import State

from keycard_bunker.relay import RelayConn


class FakeWs:
    def __init__(self, state=State.OPEN, fail=False):
        self.state = state
        self.fail = fail
        self.sent = []

    async def send(self, data):
        if self.fail:
            raise ConnectionClosed(None, None)
        self.sent.append(data)


async def noop(message, relay):
    pass


def test_send_only_when_open():
    conn = RelayConn('wss://r', 'ab', noop)
    assert asyncio.run(conn.send(['x'])) is False
    conn._ws = FakeWs(State.CLOSING)
    assert asyncio.run(conn.send(['x'])) is False
    conn._ws = FakeWs(fail=True)
    assert asyncio.run(conn.send(['x'])) is False
    conn._ws = FakeWs()
    assert asyncio.run(conn.send(['x'])) is True
    assert conn._ws.sent == ['["x"]']


def test_handler_errors_do_not_escape():
    seen = []

    async def handler(message, relay):
        seen.append(message)
        raise RuntimeError('boom')

    conn = RelayConn('wss://r', 'ab', handler)
    asyncio.run(conn._dispatch(json.dumps(['EVENT', 'sub', {}])))
    asyncio.run(conn._dispatch('not json'))
    asyncio.run(conn._dispatch('{}'))
    assert seen == [['EVENT', 'sub', {}]]
