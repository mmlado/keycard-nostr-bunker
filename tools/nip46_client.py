"""
Minimal NIP-46 client for trying a bunker by hand. Each run is a new client
unless --key is given.

Usage:
    python tools/nip46_client.py "bunker://..." [--call ping] [--nip04] [--key HEX]
"""
import argparse
import asyncio
import json
import sys
import time
from urllib.parse import parse_qs, urlparse

from websockets.asyncio.client import connect

from keycard_nostr_bunker import nip01, nip04, nip44
from keycard_nostr_bunker.signer import SoftwareSigner

KIND = 24133
# Long enough to cover the bunker's 60 s approval prompt.
REPLY_TIMEOUT = 90


def parse_url(url: str) -> tuple[str, list[str], str]:
    parsed = urlparse(url)
    if parsed.scheme != 'bunker':
        raise ValueError('not a bunker:// URL')
    query = parse_qs(parsed.query)
    return parsed.netloc, query.get('relay', []), query.get('secret', [''])[0]


async def run(url: str, calls: list[str], legacy: bool, key: str | None) -> int:
    bunker, relays, secret = parse_url(url)
    client = SoftwareSigner(bytes.fromhex(key)) if key else SoftwareSigner.generate()
    shared = client.ecdh(bytes.fromhex(bunker))
    print(f'client pubkey {client.pubkey.hex()}  (prompt code {client.pubkey.hex()[:4]})')

    def encrypt(text: str) -> str:
        if legacy:
            return nip04.encrypt(text, shared)
        return nip44.encrypt(text, nip44.conversation_key(shared))

    def decrypt(text: str) -> str:
        if legacy:
            return nip04.decrypt(text, shared)
        return nip44.decrypt(text, nip44.conversation_key(shared))

    async with connect(relays[0]) as ws:
        await ws.send(json.dumps(['REQ', 'client', {'kinds': [KIND], '#p': [client.pubkey.hex()],
                                                    'since': int(time.time()) - 10}]))
        for i, (method, params) in enumerate([('connect', [bunker, secret])]
                                             + [(c, []) for c in calls]):
            request = {'id': f'r{i}', 'method': method, 'params': params}
            event = nip01.finalize_event(
                {'kind': KIND, 'tags': [['p', bunker]], 'content': encrypt(json.dumps(request))},
                client.pubkey.hex(), client.sign)
            await ws.send(json.dumps(['EVENT', event]))
            print(f'-> {method}')
            reply = await wait_reply(ws, bunker, f'r{i}', decrypt)
            print(f'<- {method}: result={reply.get("result")!r} error={reply.get("error")!r}')
            if reply.get('error'):
                return 1
    return 0


async def wait_reply(ws, bunker: str, request_id: str, decrypt) -> dict:
    deadline = time.monotonic() + REPLY_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f'no reply within {REPLY_TIMEOUT}s')
        message = json.loads(await asyncio.wait_for(ws.recv(), remaining))
        if message[0] == 'EVENT' and message[2].get('pubkey') == bunker:
            reply = json.loads(decrypt(message[2]['content']))
            if reply.get('id') == request_id:
                return reply


def main() -> int:
    parser = argparse.ArgumentParser(description='Try a NIP-46 bunker by hand')
    parser.add_argument('url', help='bunker:// URL, e.g. from "keycard-nostr-bunker url"')
    parser.add_argument('--call', action='append', default=[],
                        help='method to call after connect, repeatable: ping, get_public_key')
    parser.add_argument('--nip04', action='store_true', help='use NIP-04 for the transport')
    parser.add_argument('--key', help='client secret key in hex, to reconnect as the same client')
    args = parser.parse_args()
    try:
        return asyncio.run(run(args.url, args.call, args.nip04, args.key))
    except (TimeoutError, ValueError, OSError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
