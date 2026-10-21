"""
Minimal NIP-46 client for trying a bunker by hand. Each run is a new client
unless --key is given.

Usage:
    python tools/nip46_client.py "bunker://..." [--call ping] [--sign KIND] [--perms LIST]
                                 [--nip04] [--key HEX]
"""
import argparse
import asyncio
import json
import os
import sys
import time
from urllib.parse import parse_qs, urlparse

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import WebSocketException

from keycard_nostr_bunker import envelope
from keycard_nostr_bunker.signer import SoftwareSigner

# Long enough to cover the bunker's 60 s approval prompt.
REPLY_TIMEOUT = 90


def parse_url(url: str) -> tuple[str, list[str], str]:
    parsed = urlparse(url)
    if parsed.scheme != 'bunker':
        raise ValueError('not a bunker:// URL')
    query = parse_qs(parsed.query)
    return parsed.netloc, query.get('relay', []), query.get('secret', [''])[0]


async def open_first(relays: list[str]) -> ClientConnection:
    """Connect to the first relay in the URL that accepts, as a client app would."""
    if not relays:
        raise ValueError('the URL names no relay')
    for relay in relays:
        try:
            ws = await connect(relay, open_timeout=10)
        except (OSError, TimeoutError, WebSocketException) as e:
            print(f'{relay}: {e}', file=sys.stderr)
            continue
        print(f'relay {relay}')
        return ws
    raise ConnectionError('no relay in the URL accepted the connection')


async def run(url: str, calls: list[tuple[str, list]], legacy: bool, key: str | None,
              perms: str) -> int:
    bunker, relays, secret = parse_url(url)
    client = SoftwareSigner(bytes.fromhex(key)) if key else SoftwareSigner.generate()
    shared = client.ecdh(bytes.fromhex(bunker))
    print(f'client pubkey {client.pubkey.hex()}  (prompt code {client.pubkey.hex()[:4]})')

    failures = 0
    ws = await open_first(relays)
    async with ws:
        await ws.send(json.dumps(['REQ', 'client', {'kinds': [envelope.KIND],
                                                    '#p': [client.pubkey.hex()],
                                                    'since': int(time.time()) - 10}]))
        for method, params in [('connect', [bunker, secret, perms])] + calls:
            # A fresh id per request, so a reply left on the relay by an earlier run never matches.
            request_id = os.urandom(8).hex()
            request = {'id': request_id, 'method': method, 'params': params}
            event = envelope.seal(request, client, bunker, shared, legacy)
            await ws.send(json.dumps(['EVENT', event]))
            print(f'-> {method}')
            reply = await wait_reply(ws, bunker, request_id, shared)
            result = str(reply.get('result'))
            print(f'<- {method}: result={result[:80]!r} error={reply.get("error")!r}')
            if reply.get('error'):
                failures += 1
                if method == 'connect':
                    return 1
    return 1 if failures else 0


async def wait_reply(ws, bunker: str, request_id: str, shared: bytes) -> dict:
    deadline = time.monotonic() + REPLY_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f'no reply within {REPLY_TIMEOUT}s')
        message = json.loads(await asyncio.wait_for(ws.recv(), remaining))
        event = message[2] if message[0] == 'EVENT' else {}
        if event.get('pubkey') != bunker:
            continue
        try:
            envelope.verify(event)
            reply = envelope.unseal(event, shared)
        except (ValueError, TypeError, KeyError):
            continue
        if reply.get('id') == request_id:
            return reply


def main() -> int:
    parser = argparse.ArgumentParser(description='Try a NIP-46 bunker by hand')
    parser.add_argument('url', help='bunker:// URL, e.g. from "keycard-nostr-bunker url"')
    parser.add_argument('--call', action='append', default=[],
                        help='method to call after connect, repeatable: ping, get_public_key')
    parser.add_argument('--sign', action='append', default=[], type=int, metavar='KIND',
                        help='ask the bunker to sign a test event of this kind, repeatable')
    parser.add_argument('--perms', default='',
                        help='permissions to request at connect, e.g. sign_event:1,nip44_encrypt')
    parser.add_argument('--nip04', action='store_true', help='use NIP-04 for the transport')
    parser.add_argument('--key', help='client secret key in hex, to reconnect as the same client')
    args = parser.parse_args()
    try:
        calls = [(method, []) for method in args.call] + [
            ('sign_event', [{'kind': kind, 'content': 'keycard-nostr-bunker test', 'tags': [],
                             'created_at': int(time.time())}]) for kind in args.sign]
        return asyncio.run(run(args.url, calls, args.nip04, args.key, args.perms))
    except (TimeoutError, ValueError, OSError, WebSocketException) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
