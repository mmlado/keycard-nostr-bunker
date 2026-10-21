"""NIP-46 requested permissions: a comma-separated list of method or method:param."""

import re
from dataclasses import dataclass

ALWAYS_ALLOWED = frozenset({'ping', 'get_public_key'})
_ITEM = re.compile(r'[a-z0-9_]+(:[0-9]+)?')


@dataclass(frozen=True)
class Permissions:
    """What a client asked for at connect. None means it asked for nothing and is unrestricted."""

    items: frozenset[str] | None

    @classmethod
    def requested(cls, raw: object) -> 'Permissions':
        """From the connect parameter; an empty string requests nothing, as NIP-46 says."""
        if not isinstance(raw, str) or not raw.strip():
            return cls(None)
        # A non-empty request with no valid item still restricts the client.
        return cls(frozenset(item.strip() for item in raw.split(',')
                             if _ITEM.fullmatch(item.strip())))

    def allows(self, method: str, kind: int | None = None) -> bool:
        if self.items is None or method in ALWAYS_ALLOWED:
            return True
        if method == 'sign_event':
            return 'sign_event' in self.items or f'sign_event:{kind}' in self.items
        return method in self.items

    def describe(self) -> str:
        if self.items is None:
            return 'everything, no permissions requested'
        return ', '.join(sorted(self.items)) or 'nothing beyond ping and get_public_key'
