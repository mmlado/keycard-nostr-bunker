"""NIP-46 requested permissions: a comma-separated list of method or method:param.

Shown to the user, not enforced: clients list only what they want pre-approved
and expect the rest to work too.
"""

import re
from dataclasses import dataclass

_ITEM = re.compile(r'[a-z0-9_]+(:[0-9]+)?')


@dataclass(frozen=True)
class Permissions:
    """What a client asked for at connect; None when it sent no list."""

    items: frozenset[str] | None

    @classmethod
    def requested(cls, raw: object) -> 'Permissions':
        """From the connect parameter; an empty string requests nothing, as NIP-46 says."""
        if not isinstance(raw, str) or not raw.strip():
            return cls(None)
        return cls(frozenset(item.strip() for item in raw.split(',')
                             if _ITEM.fullmatch(item.strip())))

    def describe(self) -> str:
        return ', '.join(sorted(self.items or ())) or 'nothing listed'
