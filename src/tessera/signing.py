"""Request signing: the whole of Tessera's authentication.

There is no TLS (the 3DS `ssl:C` tops out at TLS 1.1), and there are no
passwords. Identity, vote integrity and admin authority all rest on a
libhydrogen signature over a canonical byte string that pins the method, the
path *including its query string*, a timestamp, a per-request nonce and a hash
of the body. Change any of those five and the signature stops verifying.

The client builds the identical byte string. If this layout ever changes, the
version tag at the front must change with it, so an old client fails closed
with a bad signature instead of ambiguously.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from .config import TesseraConfig
from .hydro import SIGN_BYTES, SIGN_PUBLICKEYBYTES, Hydro, HydroError

SIGNED_PREFIX = b"tessera-v1"

HEADER_KEY = "X-Tessera-Key"
HEADER_SIG = "X-Tessera-Sig"
HEADER_TS = "X-Tessera-Ts"
HEADER_NONCE = "X-Tessera-Nonce"

NONCE_HEX_LEN = 32  # 16 random bytes
_HEX = frozenset("0123456789abcdef")


class SignatureError(Exception):
    """A signed request that must not be executed. Carries the HTTP status."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail or code


@dataclass(frozen=True)
class SignedIdentity:
    """Who sent a verified request. Not an authorisation — just a name."""

    key_hex: str
    is_admin: bool


class ReplayChecker(Protocol):
    def check_and_record(self, key_hex: str, nonce_hex: str, now: int, window: int) -> bool: ...


def canonical_message(
    method: str, path: str, timestamp: int, nonce_hex: str, body_hash_hex: str
) -> bytes:
    """The exact bytes both ends sign. Newline-separated, no trailing newline."""
    return b"\n".join(
        (
            SIGNED_PREFIX,
            method.encode("ascii"),
            path.encode("utf-8"),
            str(timestamp).encode("ascii"),
            nonce_hex.encode("ascii"),
            body_hash_hex.encode("ascii"),
        )
    )


def _lower_hex(value: str, expected_len: int) -> str:
    if len(value) != expected_len or any(c not in _HEX for c in value):
        raise SignatureError(
            400, "malformed_signature", f"expected {expected_len} lowercase hex characters"
        )
    return value


def parse_signature_headers(headers: Mapping[str, str]) -> tuple[str, bytes, int, str]:
    """Pull and validate the four signature headers. Nothing crypto here yet."""
    try:
        key_hex = headers[HEADER_KEY]
        sig_hex = headers[HEADER_SIG]
        ts_raw = headers[HEADER_TS]
        nonce_hex = headers[HEADER_NONCE]
    except KeyError as exc:
        raise SignatureError(400, "malformed_signature", f"missing header {exc.args[0]}") from exc

    if key_hex is None or sig_hex is None or ts_raw is None or nonce_hex is None:
        raise SignatureError(400, "malformed_signature", "empty signature header")

    key_hex = _lower_hex(key_hex.strip(), SIGN_PUBLICKEYBYTES * 2)
    sig_hex = _lower_hex(sig_hex.strip(), SIGN_BYTES * 2)
    nonce_hex = _lower_hex(nonce_hex.strip(), NONCE_HEX_LEN)

    try:
        timestamp = int(ts_raw.strip(), 10)
    except ValueError as exc:
        raise SignatureError(400, "malformed_signature", "timestamp is not an integer") from exc

    return key_hex, bytes.fromhex(sig_hex), timestamp, nonce_hex


def verify_signed_request(
    *,
    hydro: Hydro,
    cfg: TesseraConfig,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
    now: int,
    replay: ReplayChecker,
) -> SignedIdentity:
    """Verify a state-changing request, or raise SignatureError.

    Order matters: cheap structural checks first, then the timestamp window,
    then the signature, and only then the nonce is *recorded*. Recording the
    nonce before the signature verifies would let anyone lock a real client's
    nonce out by guessing it, which is a denial of service against a specific
    console rather than a defence.
    """
    key_hex, signature, timestamp, nonce_hex = parse_signature_headers(headers)

    if abs(now - timestamp) > cfg.replay_window_secs:
        raise SignatureError(
            401,
            "stale_timestamp",
            f"timestamp {timestamp} is outside +/-{cfg.replay_window_secs}s of {now}",
        )

    try:
        body_hash_hex = hydro.hash32(body, cfg.sign_context).hex()
        message = canonical_message(method, path, timestamp, nonce_hex, body_hash_hex)
        ok = hydro.sign_verify(signature, message, cfg.sign_context, bytes.fromhex(key_hex))
    except HydroError as exc:
        raise SignatureError(400, "malformed_signature", str(exc)) from exc

    if not ok:
        raise SignatureError(401, "bad_signature", "signature does not verify")

    if not replay.check_and_record(key_hex, nonce_hex, now, cfg.replay_window_secs):
        raise SignatureError(409, "replayed", "nonce already used inside the replay window")

    return SignedIdentity(key_hex=key_hex, is_admin=key_hex in cfg.admin_keys)
