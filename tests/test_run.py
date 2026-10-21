"""The run loop with in-memory relays: approver choice and secret rotation."""

import asyncio
import logging
import threading

from keycard_nostr_bunker import cli, envelope
from keycard_nostr_bunker.cli import TerminalApprover, open_admission, run
from keycard_nostr_bunker.config import Config
from keycard_nostr_bunker.perms import Permissions
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
    return envelope.seal({'id': method, 'method': method, 'params': params}, CLIENT,
                         transport.pubkey.hex(), CLIENT.ecdh(transport.pubkey))


def answer(transport, sent):
    [message] = sent
    assert message[0] == 'EVENT' and envelope.verify(message[1]) == transport.pubkey.hex()
    return envelope.unseal(message[1], CLIENT.ecdh(transport.pubkey))


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


def test_announcements_wait_for_an_open_prompt(monkeypatch, capsys):
    approver = TerminalApprover()
    opened, answered = threading.Event(), threading.Event()

    def ask(self, client, perms):
        print('PROMPT', flush=True)
        opened.set()
        answered.wait(5)
        return True

    monkeypatch.setattr(TerminalApprover, '_ask', ask)
    worker = threading.Thread(target=approver, args=(CLIENT.pubkey.hex(), Permissions(None)))
    worker.start()
    assert opened.wait(5)
    approver.announce('URL')
    assert capsys.readouterr().out == 'PROMPT\n'
    answered.set()
    worker.join()
    assert capsys.readouterr().out == 'URL\n'
    approver.announce('NOW')
    assert capsys.readouterr().out == 'NOW\n'


def test_rotation_is_announced_through_the_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.sys, 'stdin', Stdin(tty=True))
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: True)
    monkeypatch.setattr(TerminalApprover, '_ask', lambda self, client, perms: True)
    said = []
    monkeypatch.setattr(TerminalApprover, 'announce', lambda self, text: said.append(text))
    cfg = config(tmp_path, approve_clients=True, rotate_secret=True)
    secret = open_admission(cfg).secret
    transport, (a, b) = serve(cfg, [lambda t: request(t, 'connect', [t.pubkey.hex(), secret])])
    assert answer(transport, b.sent)['result'] == 'ack'
    [text] = said
    assert open_admission(cfg).secret in text and text.strip().startswith('bunker://')
