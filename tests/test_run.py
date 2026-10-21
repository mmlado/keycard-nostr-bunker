"""The run loop with in-memory relays: reply fan-out, approver choice, secret rotation."""

import asyncio
import json
import logging
import time

import pytest

from keycard_nostr_bunker import cli, nip01, nip44
from keycard_nostr_bunker.cli import TerminalApprover, open_admission, run
from keycard_nostr_bunker.config import Config
from keycard_nostr_bunker.nip46 import KIND
from keycard_nostr_bunker.signer import SoftwareSigner

USER = SoftwareSigner((3).to_bytes(32, 'big'))
CLIENT = SoftwareSigner((2).to_bytes(32, 'big'))


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


class Stdin:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


def config(tmp_path, **connection):
    cfg = Config()
    cfg.relay.urls = ['wss://a.example', 'wss://b.example']
    cfg.signer.key_file = str(tmp_path / 'signer.key')
    cfg.signing.policy = 'all'
    for key, value in connection.items():
        setattr(cfg.connection, key, value)
    return cfg


def request(transport, method, params):
    shared = nip44.conversation_key(CLIENT.ecdh(transport.pubkey))
    body = json.dumps({'id': method, 'method': method, 'params': params})
    return nip01.finalize_event(
        {'kind': KIND, 'tags': [['p', transport.pubkey.hex()]],
         'content': nip44.encrypt(body, shared), 'created_at': int(time.time())},
        CLIENT.pubkey.hex(), CLIENT.sign)


def answer(transport, sent):
    [message] = sent
    assert message[0] == 'EVENT' and message[1]['pubkey'] == transport.pubkey.hex()
    shared = nip44.conversation_key(CLIENT.ecdh(transport.pubkey))
    return json.loads(nip44.decrypt(message[1]['content'], shared))


def serve(cfg, events, failing=()):
    """Run the bunker, hand each event to the first relay, and stop."""
    transport = SoftwareSigner.load_or_generate(cfg.signer.key_file)
    relays = []

    def factory(url, pubkey, handler):
        relays.append(FakeRelay(url, pubkey, handler, fail=url in failing))
        return relays[-1]

    async def main():
        stop = asyncio.Event()
        task = asyncio.create_task(run(cfg, transport, USER, relay_factory=factory, stop=stop))
        while len(relays) < len(cfg.relay.urls):
            await asyncio.sleep(0)
        for make in events:
            await relays[0].handler(['EVENT', 'nip46', make(transport)], relays[0])
        stop.set()
        await task

    asyncio.run(main())
    assert all(r.started and r.stopped for r in relays)
    return transport, relays


def test_reply_reaches_every_relay_when_one_fails(tmp_path):
    cfg = config(tmp_path, authorized_clients=[CLIENT.pubkey.hex()])
    transport, (a, b) = serve(cfg, [lambda t: request(t, 'ping', [])], failing={'wss://a.example'})
    assert answer(transport, b.sent)['result'] == 'pong'


def test_an_invalid_event_gets_no_reply(tmp_path):
    cfg = config(tmp_path, authorized_clients=[CLIENT.pubkey.hex()])
    _, (a, b) = serve(cfg, [lambda t: dict(request(t, 'ping', []), sig='00' * 64)])
    assert a.sent == [] and b.sent == []


def test_without_a_terminal_new_clients_wait(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.sys, 'stdin', Stdin(tty=False))
    cfg = config(tmp_path, approve_clients=True)
    secret = open_admission(cfg).secret
    transport, (a, b) = serve(cfg, [lambda t: request(t, 'connect', [t.pubkey.hex(), secret])])
    assert answer(transport, b.sent)['error'] == 'pending approval'
    assert [r.pubkey for r in open_admission(cfg).pending()] == [CLIENT.pubkey.hex()]


def test_in_a_terminal_the_prompt_decides(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.sys, 'stdin', Stdin(tty=True))
    asked = []
    monkeypatch.setattr(TerminalApprover, '_ask',
                        lambda self, client, perms: asked.append(perms.describe()) or True)
    cfg = config(tmp_path, approve_clients=True)
    secret = open_admission(cfg).secret
    transport, (a, b) = serve(
        cfg, [lambda t: request(t, 'connect', [t.pubkey.hex(), secret, 'sign_event:1'])])
    assert answer(transport, b.sent)['result'] == 'ack'
    assert asked == ['sign_event:1']


def test_rotate_secret_rotates_and_announces(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(cli.sys, 'stdin', Stdin(tty=False))
    caplog.set_level(logging.INFO, logger='keycard_nostr_bunker')
    cfg = config(tmp_path, rotate_secret=True)
    secret = open_admission(cfg).secret
    transport, (a, b) = serve(cfg, [lambda t: request(t, 'connect', [t.pubkey.hex(), secret])])
    assert answer(transport, b.sent)['result'] == 'ack'
    assert open_admission(cfg).secret != secret
    assert 'Secret rotated' in caplog.text


@pytest.mark.parametrize('message', [['NOTICE', 'hello'], ['OK', 'ab', True, ''], ['EOSE', 'x'],
                                     ['WHAT']])
def test_other_relay_messages_are_only_logged(tmp_path, message):
    cfg = config(tmp_path)
    transport = SoftwareSigner.load_or_generate(cfg.signer.key_file)
    relays = []

    async def main():
        stop = asyncio.Event()
        task = asyncio.create_task(run(
            cfg, transport, USER,
            relay_factory=lambda *args: relays.append(FakeRelay(*args)) or relays[-1], stop=stop))
        while len(relays) < 2:
            await asyncio.sleep(0)
        await relays[0].handler(message, relays[0])
        stop.set()
        await task

    asyncio.run(main())
    assert relays[0].sent == [] and relays[1].sent == []
