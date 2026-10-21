"""NIP-01 event serialization, ID and signing."""

import hashlib
import json
import time
from typing import Any, Callable


def serialize(pubkey: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    return json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode()


def event_id(pubkey: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    return hashlib.sha256(serialize(pubkey, created_at, kind, tags, content)).digest()


def finalize_event(unsigned: dict[str, Any], pubkey: str,
                   sign: Callable[[bytes], bytes]) -> dict[str, Any]:
    """Fill in pubkey, id and sig; created_at defaults to now."""
    created_at = int(unsigned.get('created_at') or time.time())
    kind = int(unsigned['kind'])
    tags = unsigned.get('tags') or []
    content = unsigned.get('content') or ''
    eid = event_id(pubkey, created_at, kind, tags, content)
    return {
        'id': eid.hex(),
        'pubkey': pubkey,
        'created_at': created_at,
        'kind': kind,
        'tags': tags,
        'content': content,
        'sig': sign(eid).hex(),
    }
