"""What the bunker keeps on disk: the state directory, its files, and how they are written."""

import os
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


class StateDir:
    """The directory of the signer key, where the bunker keeps everything it remembers.

    The one place that names the files. They are private: written atomically,
    mode 0600, in a 0700 directory the bunker creates itself.
    """

    def __init__(self, path: str | Path, signer_key_name: str = 'signer.key'):
        self.path = Path(path)
        self.signer_key = self.path / signer_key_name

    @classmethod
    def for_signer_key(cls, signer_key: str | Path) -> 'StateDir':
        key = Path(signer_key)
        return cls(key.parent, key.name)

    @property
    def secret(self) -> Path:
        return self.path / 'secret'

    @property
    def clients(self) -> Path:
        return self.path / 'clients'

    @property
    def pending(self) -> Path:
        return self.path / 'pending'

    @property
    def admission_lock(self) -> Path:
        return self.path / 'admission.lock'

    @property
    def seen(self) -> Path:
        return self.path / 'seen'

    @property
    def user_pubkey(self) -> Path:
        return self.path / 'user.pubkey'

    @property
    def pin_rejected(self) -> Path:
        return self.path / 'pin.rejected'

    def files(self) -> list[Path]:
        return [self.signer_key, self.secret, self.clients, self.pending, self.admission_lock,
                self.seen, self.user_pubkey, self.pin_rejected]

    def open_to_others(self) -> bool:
        return self.path.is_dir() and bool(os.stat(self.path).st_mode & 0o077)


def write_private(path: Path, text: str) -> None:
    """Write a file readable only by the owner, atomically."""
    path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.replace(tmp, path)
