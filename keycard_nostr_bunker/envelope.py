"""NIP-46 messages: kind 24133 events that carry an encrypted JSON object.

NIP-44 encrypts them. Older clients still use NIP-04, recognised by the iv
marker in the content, and get their reply encrypted the same way.
"""

import json
import re
from typing import Any

from . import nip01, nip04, nip44, schnorr
from .signer import Signer

KIND = 24133

_HEX = re.compile(r'[0-9a-f]+')


def verify(event: dict[str, Any]) -> str:
    """Check a well-formed kind 24133 event signed by its pubkey; return that pubkey.

    Raises ValueError, TypeError or KeyError. Freshness is the replay window's job.
    """
    author, event_id, sig = event['pubkey'], event['id'], event['sig']
    created_at, tags, content = event['created_at'], event.get('tags') or [], event['content']
    if event.get('kind') != KIND:
        raise ValueError('not a NIP-46 event')
    if not (_hex(author, 64) and _hex(event_id, 64) and _hex(sig, 128)):
        raise ValueError('pubkey, id or sig is not hex of the right length')
    if isinstance(created_at, bool) or not isinstance(created_at, int):
        raise ValueError('created_at is not an integer')
    if not isinstance(content, str) or not isinstance(tags, list):
        raise ValueError('content or tags has the wrong type')
    if nip01.event_id(author, created_at, KIND, tags, content).hex() != event_id:
        raise ValueError('id does not match the event')
    if not schnorr.verify(bytes.fromhex(author), bytes.fromhex(event_id), bytes.fromhex(sig)):
        raise ValueError(f'bad signature from {author}')
    return author


def is_legacy(event: dict[str, Any]) -> bool:
    """Whether the content is NIP-04, which the reply must then use too."""
    return '?iv=' in event['content']


def unseal(event: dict[str, Any], shared_x: bytes) -> dict[str, Any]:
    """Decrypt the content to its JSON object; raises ValueError for anything else."""
    content = event['content']
    if is_legacy(event):
        text = nip04.decrypt(content, shared_x)
    else:
        text = nip44.decrypt(content, nip44.conversation_key(shared_x))
    body = json.loads(text)
    if not isinstance(body, dict):
        raise ValueError('not an object')
    return body


def seal(body: dict[str, Any], author: Signer, recipient: str, shared_x: bytes,
         legacy: bool = False, created_at: int | None = None) -> dict[str, Any]:
    """Encrypt body for recipient and sign it as author.

    Raises ValueError when NIP-44 is used and the JSON is over 65535 bytes.
    """
    text = json.dumps(body)
    if legacy:
        content = nip04.encrypt(text, shared_x)
    else:
        content = nip44.encrypt(text, nip44.conversation_key(shared_x))
    return nip01.finalize_event(
        {'kind': KIND, 'tags': [['p', recipient]], 'content': content, 'created_at': created_at},
        author.pubkey.hex(), author.sign)


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and _HEX.fullmatch(value) is not None
