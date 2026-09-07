"""ctypes binding to libhydrogen, pinned at 617036a353cd4f6478ab6c3f98c36dd31e23ce8e.

This is the only native code the daemon calls, and the only place in the
server where an attacker-influenced buffer meets C. Every entry point below
therefore checks its argument sizes in Python *before* the call — libhydrogen
takes fixed-size arrays (uint8_t[64], uint8_t[32], char[8]) with no length
parameter, so a short buffer would be read past rather than rejected.

The 3DS client links the same pinned commit and signs with the same context,
so nothing here may be changed on one side alone.
"""

from __future__ import annotations

import ctypes
from pathlib import Path

SIGN_BYTES = 64
SIGN_PUBLICKEYBYTES = 32
SIGN_SECRETKEYBYTES = 64
CONTEXTBYTES = 8
HASH_BYTES = 32


class HydroError(RuntimeError):
    """libhydrogen could not be loaded, or was handed a wrongly sized buffer."""


class Hydro:
    """One loaded libhydrogen.so, with hydro_init() already called."""

    def __init__(self, library_path: Path) -> None:
        self._path = Path(library_path)
        try:
            lib = ctypes.CDLL(str(self._path))
        except OSError as exc:
            raise HydroError(f"could not load libhydrogen from {self._path}: {exc}") from exc

        lib.hydro_init.restype = ctypes.c_int
        lib.hydro_init.argtypes = []

        lib.hydro_sign_keygen.restype = None
        lib.hydro_sign_keygen.argtypes = [ctypes.c_void_p]

        lib.hydro_sign_create.restype = ctypes.c_int
        lib.hydro_sign_create.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        lib.hydro_sign_verify.restype = ctypes.c_int
        lib.hydro_sign_verify.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        lib.hydro_hash_hash.restype = ctypes.c_int
        lib.hydro_hash_hash.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        if lib.hydro_init() != 0:
            raise HydroError("hydro_init() failed — no usable entropy source")

        self._lib = lib

    # -- argument guards --------------------------------------------------

    @staticmethod
    def _context(context: str) -> bytes:
        raw = context.encode("ascii")
        if len(raw) != CONTEXTBYTES:
            raise HydroError(
                f"context must be exactly {CONTEXTBYTES} ASCII bytes, got {len(raw)}"
            )
        return raw

    @staticmethod
    def _fixed(name: str, value: bytes, size: int) -> bytes:
        if not isinstance(value, (bytes, bytearray)) or len(value) != size:
            raise HydroError(f"{name} must be exactly {size} bytes, got {len(value)}")
        return bytes(value)

    # -- api --------------------------------------------------------------

    def keygen(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key). Used by tooling and tests only."""
        buf = ctypes.create_string_buffer(SIGN_PUBLICKEYBYTES + SIGN_SECRETKEYBYTES)
        self._lib.hydro_sign_keygen(ctypes.cast(buf, ctypes.c_void_p))
        raw = buf.raw[: SIGN_PUBLICKEYBYTES + SIGN_SECRETKEYBYTES]
        return raw[:SIGN_PUBLICKEYBYTES], raw[SIGN_PUBLICKEYBYTES:]

    def sign_create(self, message: bytes, context: str, secret_key: bytes) -> bytes:
        ctx = self._context(context)
        sk = self._fixed("secret key", secret_key, SIGN_SECRETKEYBYTES)
        out = ctypes.create_string_buffer(SIGN_BYTES)
        rc = self._lib.hydro_sign_create(out, message, len(message), ctx, sk)
        if rc != 0:
            raise HydroError("hydro_sign_create failed")
        return out.raw[:SIGN_BYTES]

    def sign_verify(
        self, signature: bytes, message: bytes, context: str, public_key: bytes
    ) -> bool:
        ctx = self._context(context)
        sig = self._fixed("signature", signature, SIGN_BYTES)
        pk = self._fixed("public key", public_key, SIGN_PUBLICKEYBYTES)
        return self._lib.hydro_sign_verify(sig, message, len(message), ctx, pk) == 0

    def hash32(self, message: bytes, context: str) -> bytes:
        """Unkeyed 32-byte hydro_hash. Used for body digests and content ids.

        libhydrogen's own hash rather than BLAKE2b or SHA-256 on purpose: the
        3DS client already links this library and nothing else, so using it for
        the content id means the console can compute the same id the server
        will store without carrying a second hash implementation.
        """
        ctx = self._context(context)
        out = ctypes.create_string_buffer(HASH_BYTES)
        rc = self._lib.hydro_hash_hash(out, HASH_BYTES, message, len(message), ctx, None)
        if rc != 0:
            raise HydroError("hydro_hash_hash failed")
        return out.raw[:HASH_BYTES]
