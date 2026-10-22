import asyncio
import json
import threading
import time

import pytest
from websockets.exceptions import ConnectionClosed
from websockets.protocol import State

from keycard_nostr_bunker import relay as relay_module
from keycard_nostr_bunker.relay import RelayConn, RelayPool


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


class FakeRelay:
    def __init__(self, url, pubkey, handler, fail=False):
        self.url, self.handler, self.fail = url, handler, fail
        self.sent = []
        self.started = self.stopped = False

    def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def send(self, message):
        if self.fail:
            raise ConnectionError('relay gone')
        self.sent.append(message)
        return True


def pool_with(serve, failing=()):
    relays = []

    def factory(url, pubkey, handler):
        relays.append(FakeRelay(url, pubkey, handler, fail=url in failing))
        return relays[-1]

    pool = RelayPool(['wss://a', 'wss://b', 'wss://c'], 'ab', serve, factory)
    return pool, relays


def deliver(pool, relay, message):
    async def main():
        await relay.handler(message, relay)
        await pool.stop()

    asyncio.run(main())


def event(client, event_id='e'):
    return ['EVENT', 'nip46', {'id': event_id, 'pubkey': client}]


def test_a_reply_goes_to_every_relay_even_if_one_fails():
    served = []

    def serve(event, source):
        served.append((event, source))
        return {'id': 'reply'}

    pool, (a, b, c) = pool_with(serve, failing={'wss://b'})
    deliver(pool, a, ['EVENT', 'nip46', {'id': 'request'}])
    assert served == [({'id': 'request'}, 'wss://a')]
    assert a.sent == c.sent == [['EVENT', {'id': 'reply'}]]


def test_no_reply_sends_nothing():
    pool, relays = pool_with(lambda event, source: None)
    deliver(pool, relays[0], ['EVENT', 'nip46', {'id': 'request'}])
    assert all(r.sent == [] for r in relays)


def test_a_failing_request_is_logged_and_contained(caplog):
    def serve(event, source):
        raise RuntimeError('broken')

    pool, relays = pool_with(serve)
    deliver(pool, relays[0], ['EVENT', 'nip46', {'id': 'request'}])
    assert all(r.sent == [] for r in relays)
    assert 'request handling failed' in caplog.text


@pytest.mark.parametrize('message', [['NOTICE', 'hello'], ['OK', 'ab', True, ''], ['EOSE', 'x'],
                                     ['EVENT', 'nip46', 'not an object'], ['WHAT']])
def test_other_messages_are_only_logged(message):
    pool, relays = pool_with(lambda event, source: pytest.fail('served'))
    deliver(pool, relays[0], message)
    assert all(r.sent == [] for r in relays)


def test_a_rejected_reply_is_a_warning(caplog):
    pool, relays = pool_with(lambda event, source: None)
    deliver(pool, relays[0], ['OK', 'abcdef0123', False, 'blocked: rate limited'])
    deliver(pool, relays[0], ['OK', '9876543210', True, ''])
    assert [(r.levelname, r.getMessage()) for r in caplog.records] == [
        ('WARNING', 'wss://a rejected reply abcdef01: blocked: rate limited')]


def test_a_slow_request_holds_up_only_its_client():
    release = threading.Event()
    served = []

    def serve(event, source):
        if event['pubkey'] == 'slow':
            release.wait(5)
        served.append(event['pubkey'])
        return {'id': 'reply-' + event['pubkey']}

    pool, (a, b, c) = pool_with(serve)

    async def main():
        await a.handler(event('slow'), a)
        await a.handler(event('quick'), a)
        for _ in range(200):
            if served:
                break
            await asyncio.sleep(0.01)
        assert served == ['quick']
        release.set()
        await pool.stop()

    asyncio.run(main())
    assert served == ['quick', 'slow']
    assert a.sent == [['EVENT', {'id': 'reply-quick'}], ['EVENT', {'id': 'reply-slow'}]]


def test_one_clients_requests_are_served_one_at_a_time_in_order():
    lock = threading.Lock()
    running, most, order = [0], [0], []

    def serve(event, source):
        with lock:
            running[0] += 1
            most[0] = max(most[0], running[0])
        time.sleep(0.02)
        with lock:
            order.append(event['id'])
            running[0] -= 1
        return None

    pool, (a, b, c) = pool_with(serve)

    async def main():
        for i in range(5):
            await a.handler(event('same', str(i)), a)
        await pool.stop()

    asyncio.run(main())
    assert order == ['0', '1', '2', '3', '4'] and most[0] == 1


def test_a_flood_waits_at_the_cap(monkeypatch):
    monkeypatch.setattr(relay_module, 'MAX_IN_FLIGHT', 2)
    release = threading.Event()
    pool, (a, b, c) = pool_with(lambda event, source: release.wait(5) and None)

    async def main():
        await a.handler(event('one'), a)
        await a.handler(event('two'), a)
        third = asyncio.create_task(a.handler(event('three'), a))
        await asyncio.sleep(0.05)
        assert not third.done()
        release.set()
        await asyncio.wait_for(third, 5)
        await pool.stop()

    asyncio.run(main())


def test_stop_gives_up_on_a_hung_request(monkeypatch):
    monkeypatch.setattr(relay_module, 'STOP_GRACE', 0.05)
    release = threading.Event()
    pool, relays = pool_with(lambda event, source: release.wait(5) and None)

    async def main():
        await relays[0].handler(event('stuck'), relays[0])
        await asyncio.wait_for(pool.stop(), 2)
        release.set()

    try:
        asyncio.run(main())
    finally:
        release.set()
    assert all(r.stopped for r in relays)


def test_start_and_stop_reach_every_relay():
    pool, relays = pool_with(lambda event, source: None)
    pool.start()
    asyncio.run(pool.stop())
    assert all(r.started and r.stopped for r in relays)
