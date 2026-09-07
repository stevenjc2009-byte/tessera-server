"""Content-addressed blob storage.

Uploads are named by the hash of their own bytes, never by anything the
uploader chose. That is what kills path traversal outright (spec section 4.3):
there is no filename to sanitise because there is no user-supplied filename at
any point in the pipeline.

`_validated` is the only place a string becomes a path, and it accepts exactly
64 lowercase hex characters and nothing else. Every public method routes
through it, including the ones that only read.

Nothing here inspects, parses, transcodes or validates the *content*. A blob
is bytes in and the identical bytes out. That is a security property, not
laziness — see spec section 5.6.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

DIGEST_HEX_LEN = 64
_HEX = frozenset("0123456789abcdef")

# 0640: readable by the service user and its group, writable by the owner,
# executable by nobody. The directory the daemon can write is explicitly not a
# directory anything can execute from (spec section 4.3).
BLOB_MODE = 0o640
DIR_MODE = 0o750


class BlobNotFound(KeyError):
    """No blob with that digest is stored."""


class InvalidDigest(ValueError):
    """A digest that is not exactly 64 lowercase hex characters."""


class BlobStore:
    """Files on disk, keyed by the hash of their contents."""

    def __init__(self, root: Path, hasher: Callable[[bytes], bytes]) -> None:
        self.root = Path(root)
        self._hasher = hasher
        self.root.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)

    # -- internals --------------------------------------------------------

    @staticmethod
    def _validated(digest_hex: str) -> str:
        if (
            not isinstance(digest_hex, str)
            or len(digest_hex) != DIGEST_HEX_LEN
            or any(c not in _HEX for c in digest_hex)
        ):
            raise InvalidDigest(
                f"blob id must be {DIGEST_HEX_LEN} lowercase hex characters, got {digest_hex!r}"
            )
        return digest_hex

    def path_for(self, digest_hex: str) -> Path:
        """Fan out over two levels so no directory holds 100k entries."""
        clean = self._validated(digest_hex)
        return self.root / clean[0:2] / clean[2:4] / clean

    # -- api --------------------------------------------------------------

    def put(self, data: bytes) -> str:
        """Store `data`, return its digest. Idempotent for identical bytes."""
        digest_hex = self._hasher(data).hex()
        target = self.path_for(digest_hex)
        if target.exists():
            return digest_hex

        target.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
        # Write-then-rename: a crash mid-write leaves a temp file, never a
        # truncated blob sitting under a hash that no longer describes it.
        handle, temp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temp_name, BLOB_MODE)
            os.replace(temp_name, target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        return digest_hex

    def exists(self, digest_hex: str) -> bool:
        return self.path_for(digest_hex).is_file()

    def get(self, digest_hex: str) -> bytes:
        path = self.path_for(digest_hex)
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise BlobNotFound(digest_hex) from exc

    def delete(self, digest_hex: str) -> bool:
        path = self.path_for(digest_hex)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True

    def total_bytes(self) -> int:
        """Bytes currently held. Walked rather than cached: the ceiling this
        feeds is a safety limit, and a cached counter that drifts is a limit
        that silently stops being one."""
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
