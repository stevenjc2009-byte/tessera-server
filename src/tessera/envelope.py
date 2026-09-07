"""The upload wire format.

A fixed-layout binary envelope rather than multipart/form-data. Multipart
means a boundary scanner, quoted-string header parsing, filename handling and
a state machine — all of it parsing attacker-controlled text, all of it
surface this service has no use for. This format has four integers and three
byte ranges, and it is trivial for the 3DS client to emit with fwrite.

Layout, little-endian throughout:

    offset  size  field
    0       4     magic, b"TSU1"
    4       4     meta_len   (uint32)
    8       4     model_len  (uint32)
    12      4     thumb_len  (uint32)
    16      meta_len   UTF-8 JSON: {"title": str, "kind": "pixel"|"model"}
    ...     model_len  the project file, OPAQUE
    ...     thumb_len  the console-rendered thumbnail, OPAQUE

The model and thumb ranges are never looked at. Not decoded, not sniffed, not
validated beyond their length. That is spec section 5.6 and it is the single
most important line in this file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .config import TesseraConfig

UPLOAD_MAGIC = b"TSU1"
HEADER_BYTES = 16
MAX_META_BYTES = 4096
MAX_TITLE_CHARS = 64
VALID_KINDS = frozenset({"pixel", "model"})


class EnvelopeError(ValueError):
    """The upload envelope is malformed. Always answered with 400."""


@dataclass(frozen=True)
class UploadEnvelope:
    title: str
    kind: str
    model: bytes
    thumb: bytes


def _clean_title(raw: object) -> str:
    if not isinstance(raw, str):
        raise EnvelopeError("title must be a string")
    # Control characters would end up in JSON responses and in the moderation
    # CLI's terminal output. Rejected rather than stripped, because a title
    # that silently changes is a title the uploader cannot recognise.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise EnvelopeError("title contains control characters")
    title = raw.strip()
    if not title:
        raise EnvelopeError("title is empty")
    return title[:MAX_TITLE_CHARS]


def parse_upload(body: bytes, cfg: TesseraConfig) -> UploadEnvelope:
    """Parse and length-check an upload envelope, or raise EnvelopeError."""
    if len(body) < HEADER_BYTES:
        raise EnvelopeError("body is shorter than the envelope header")
    if body[0:4] != UPLOAD_MAGIC:
        raise EnvelopeError("bad magic")

    meta_len = int.from_bytes(body[4:8], "little")
    model_len = int.from_bytes(body[8:12], "little")
    thumb_len = int.from_bytes(body[12:16], "little")

    # Checked against the configured ceilings BEFORE any slicing, so an
    # absurd declared length is rejected rather than producing a short slice
    # that silently truncates the upload.
    if meta_len > MAX_META_BYTES:
        raise EnvelopeError(f"metadata is {meta_len} bytes, the limit is {MAX_META_BYTES}")
    if model_len > cfg.max_model_bytes:
        raise EnvelopeError(f"model is {model_len} bytes, the limit is {cfg.max_model_bytes}")
    if thumb_len > cfg.max_thumb_bytes:
        raise EnvelopeError(f"thumbnail is {thumb_len} bytes, the limit is {cfg.max_thumb_bytes}")

    expected = HEADER_BYTES + meta_len + model_len + thumb_len
    if len(body) != expected:
        raise EnvelopeError(f"declared lengths sum to {expected} but the body is {len(body)}")

    meta_start = HEADER_BYTES
    model_start = meta_start + meta_len
    thumb_start = model_start + model_len

    try:
        meta = json.loads(body[meta_start:model_start].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"metadata is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise EnvelopeError("metadata must be a JSON object")

    kind = meta.get("kind")
    if kind not in VALID_KINDS:
        raise EnvelopeError(f"kind must be one of {sorted(VALID_KINDS)}")

    if model_len == 0:
        raise EnvelopeError("model is empty")
    if thumb_len == 0:
        raise EnvelopeError("thumbnail is empty")

    return UploadEnvelope(
        title=_clean_title(meta.get("title")),
        kind=kind,
        model=body[model_start:thumb_start],
        thumb=body[thumb_start:],
    )


def build_upload(title: str, kind: str, model: bytes, thumb: bytes) -> bytes:
    """Construct an envelope. The reference the 3DS client is written against."""
    meta = json.dumps({"title": title, "kind": kind}, separators=(",", ":")).encode("utf-8")
    return (
        UPLOAD_MAGIC
        + len(meta).to_bytes(4, "little")
        + len(model).to_bytes(4, "little")
        + len(thumb).to_bytes(4, "little")
        + meta
        + model
        + thumb
    )
