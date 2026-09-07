"""Abuse control for a gallery with no passwords.

Anyone holding the CIA can upload, so none of this can come from
authentication (spec section 4.5). What is left is arithmetic: a per-key daily
count, a global hourly cap, a total-disk ceiling, and a per-request byte
ceiling. Bans are the fifth lever and they are cheap to evade by reinstalling —
the per-IP limiter in ratelimit.py is what actually costs a determined abuser
anything.

The daily count deliberately includes uploads that have since been deleted or
unlisted. Otherwise getting something removed would refund the quota, which
turns moderation into a reward.
"""

from __future__ import annotations

import sqlite3

from .config import TesseraConfig
from .store import BlobStore

DAY_SECONDS = 86_400
HOUR_SECONDS = 3_600


class QuotaError(Exception):
    """An upload that must be refused. Carries the HTTP status to answer with."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def is_banned(conn: sqlite3.Connection, key_hex: str) -> bool:
    return conn.execute("SELECT 1 FROM bans WHERE key = ?", (key_hex,)).fetchone() is not None


def uploads_today(conn: sqlite3.Connection, author_key: str, now: int) -> int:
    """Uploads by this key in the trailing 24 hours, deleted ones included."""
    row = conn.execute(
        "SELECT COUNT(*) FROM models WHERE author_key = ? AND created_at > ?",
        (author_key, now - DAY_SECONDS),
    ).fetchone()
    return int(row[0])


def uploads_last_hour(conn: sqlite3.Connection, now: int) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM models WHERE created_at > ?", (now - HOUR_SECONDS,)
    ).fetchone()
    return int(row[0])


def check_upload_allowed(
    *,
    conn: sqlite3.Connection,
    store: BlobStore,
    cfg: TesseraConfig,
    author_key: str,
    incoming_bytes: int,
    now: int,
) -> None:
    """Raise QuotaError if this upload must be refused; return otherwise.

    Ordered cheapest-first, with the disk walk last: a banned key or an
    over-quota key should never cause a full traversal of the blob store.
    """
    if is_banned(conn, author_key):
        raise QuotaError(403, "banned", "this key is banned from uploading")

    if incoming_bytes > cfg.max_request_bytes:
        raise QuotaError(
            413,
            "too_large",
            f"{incoming_bytes} bytes exceeds the {cfg.max_request_bytes} byte ceiling",
        )

    used = uploads_today(conn, author_key, now)
    if used >= cfg.uploads_per_key_per_day:
        raise QuotaError(
            429,
            "daily_quota",
            f"{used} uploads in the last 24h, the daily limit is "
            f"{cfg.uploads_per_key_per_day}",
        )

    hourly = uploads_last_hour(conn, now)
    if hourly >= cfg.global_uploads_per_hour:
        raise QuotaError(
            429,
            "global_rate",
            f"the gallery has taken {hourly} uploads this hour, the cap is "
            f"{cfg.global_uploads_per_hour}",
        )

    if store.total_bytes() + incoming_bytes > cfg.max_total_disk_bytes:
        raise QuotaError(
            507,
            "disk_full",
            "the gallery has reached its total disk ceiling",
        )
