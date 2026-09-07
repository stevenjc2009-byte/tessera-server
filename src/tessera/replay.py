"""Sliding replay window over (public key, nonce) pairs.

Blocksmith's gateway/replay.c uses an IPsec-style bitmask because its
transport is UDP with a monotonically increasing 64-bit message id it controls
end to end. HTTP has no such id — requests arrive over independent TCP
connections, from a console whose clock is only roughly right — so the window
here is defined by time instead: a (key, nonce) pair is remembered for as long
as the signing layer would still accept its timestamp, and forgotten after.

That is the same guarantee, reached differently: a captured request can only
be replayed inside the timestamp window, and inside that window its nonce is
already on record. Outside it, `verify_signed_request` rejects the timestamp
before this class is ever consulted.

The table is purged on every write, so it cannot grow without bound. Its
maximum size is (requests accepted in one window), which the per-IP and global
rate limits already cap.
"""

from __future__ import annotations

import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    key        TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (key, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON nonces(expires_at);
"""


class ReplayWindow:
    """Remembers used nonces for exactly as long as they could still be replayed."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def ensure_table(self) -> None:
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def purge(self, now: int) -> int:
        cursor = self.conn.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
        self.conn.commit()
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def check_and_record(self, key_hex: str, nonce_hex: str, now: int, window: int) -> bool:
        """True if this (key, nonce) is fresh; records it. False if it is a replay.

        Purge first, so a nonce whose window has closed is genuinely gone
        before the uniqueness check runs — otherwise an old row would keep
        rejecting a nonce the signing layer has already stopped protecting.
        """
        self.purge(now)
        try:
            self.conn.execute(
                "INSERT INTO nonces (key, nonce, expires_at) VALUES (?, ?, ?)",
                (key_hex, nonce_hex, now + window),
            )
        except sqlite3.IntegrityError:
            return False
        self.conn.commit()
        return True
