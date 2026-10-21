import asyncio
import json

from websockets.exceptions import ConnectionClosed
from websockets.protocol import State

from keycard_nostr_bunker.relay import RelayConn


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


def subscriptions(ws):
    return [json.loads(m) for m in ws.sent if json.loads(m)[0] == 'REQ']


def test_closed_subscription_is_requested_again(monkeypatch):
    import keycard_nostr_bunker.relay as relay
    monkeypatch.setattr(relay, 'RESUBSCRIBE_MIN', 0.01)
    seen = []

    async def handler(message, conn):
        seen.append(message[0])

    async def main():
        conn = RelayConn('wss://r', 'ab', handler)
        conn._ws = FakeWs()
        conn._resubscribe_delay = relay.RESUBSCRIBE_MIN
        await conn._dispatch(json.dumps(['CLOSED', 'nip46', 'rate-limited: slow down']))
        await asyncio.sleep(0.05)
        [req] = subscriptions(conn._ws)
        assert req[1] == 'nip46' and req[2]['#p'] == ['ab']
        assert conn._resubscribe_delay == 0.02
        await conn._dispatch(json.dumps(['EOSE', 'nip46']))
        assert conn._resubscribe_delay == relay.RESUBSCRIBE_MIN
        await conn.stop()

    asyncio.run(main())
    assert seen == ['EOSE']


def test_auth_required_waits_the_longest(monkeypatch, caplog):
    import keycard_nostr_bunker.relay as relay

    async def main():
        conn = RelayConn('wss://r', 'ab', noop)
        conn._ws = FakeWs()
        await conn._dispatch(json.dumps(['CLOSED', 'nip46', 'auth-required: sign in']))
        await asyncio.sleep(0.02)
        assert subscriptions(conn._ws) == [] and not conn._resubscribe_task.done()
        await conn.stop()

    asyncio.run(main())
    assert 'NIP-42 AUTH is not supported' in caplog.text
    assert f'{relay.RESUBSCRIBE_MAX:.0f}s' in caplog.text


def test_resubscribe_skips_a_connection_that_was_replaced(monkeypatch):
    import keycard_nostr_bunker.relay as relay
    monkeypatch.setattr(relay, 'RESUBSCRIBE_MIN', 0.01)

    async def main():
        conn = RelayConn('wss://r', 'ab', noop)
        old = conn._ws = FakeWs()
        conn._resubscribe_delay = relay.RESUBSCRIBE_MIN
        await conn._dispatch(json.dumps(['CLOSED', 'nip46', 'error: restart']))
        conn._ws = FakeWs()
        await asyncio.sleep(0.05)
        assert subscriptions(old) == [] and subscriptions(conn._ws) == []

    asyncio.run(main())


def test_closed_for_another_subscription_is_passed_on():
    seen = []

    async def handler(message, conn):
        seen.append(message)

    conn = RelayConn('wss://r', 'ab', handler)
    asyncio.run(conn._dispatch(json.dumps(['CLOSED', 'other', 'x'])))
    assert seen == [['CLOSED', 'other', 'x']] and conn._resubscribe_task is None
