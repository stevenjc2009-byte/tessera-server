"""SQLite index for the gallery.

Only the index lives here. The uploaded bytes themselves never touch this
database — they go to the content-addressed blob store (store.py), and the
rows below hold their hashes. That keeps the database small enough to copy
somewhere and read, and it means a corrupted row can never corrupt a file.

Every constraint that encodes a spec rule is enforced by SQLite rather than by
application code, because application code is what gets bypassed by the next
handler someone adds:

  - one thumbs vote per key per model     -> PRIMARY KEY (model_id, voter_key)
  - one report per key per model          -> UNIQUE (model_id, reporter_key)
  - the fixed six report reasons          -> CHECK (reason IN (...))
  - hearts are per (owner, model)         -> PRIMARY KEY (owner_key, model_id)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    model_hash   TEXT    NOT NULL UNIQUE,
    thumb_hash   TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    author_key   TEXT    NOT NULL,
    kind         TEXT    NOT NULL CHECK (kind IN ('pixel', 'model')),
    model_bytes  INTEGER NOT NULL,
    thumb_bytes  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    score        INTEGER NOT NULL DEFAULT 0,
    up_votes     INTEGER NOT NULL DEFAULT 0,
    down_votes   INTEGER NOT NULL DEFAULT 0,
    report_count INTEGER NOT NULL DEFAULT 0,
    visibility   TEXT    NOT NULL DEFAULT 'public'
                 CHECK (visibility IN ('public', 'unlisted', 'deleted'))
);
CREATE INDEX IF NOT EXISTS idx_models_browse_new ON models(visibility, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_models_browse_top ON models(visibility, score DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_models_author     ON models(author_key, created_at);

CREATE TABLE IF NOT EXISTS votes (
    model_id   INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    voter_key  TEXT    NOT NULL,
    value      INTEGER NOT NULL CHECK (value IN (-1, 1)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (model_id, voter_key)
);

CREATE TABLE IF NOT EXISTS favourites (
    model_id   INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    owner_key  TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_key, model_id)
);
CREATE INDEX IF NOT EXISTS idx_favourites_model ON favourites(model_id);

CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id     INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    reporter_key TEXT    NOT NULL,
    reason       TEXT    NOT NULL
                 CHECK (reason IN ('gore', 'sexual', 'hate', 'stolen', 'spam', 'other')),
    detail       TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    resolved_at  INTEGER,
    UNIQUE (model_id, reporter_key)
);
CREATE INDEX IF NOT EXISTS idx_reports_open ON reports(resolved_at, created_at DESC);

CREATE TABLE IF NOT EXISTS bans (
    key        TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    key        TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (key, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON nonces(expires_at);

-- Every moderation action, append-only. Nothing reads this at runtime; it
-- exists so a decision can be explained months later, and so a compromised
-- admin key leaves a trail. Deliberately NO foreign key on model_id: the
-- record of deleting something must outlive the thing it deleted.
CREATE TABLE IF NOT EXISTS admin_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id   INTEGER NOT NULL,
    admin_key  TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the index. WAL so a browse never blocks behind an upload."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    # Off by default in SQLite, and every cascade and reference above depends
    # on it. It is a per-connection pragma, so it must be set here and not in
    # the schema.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Create or update the schema. Safe to call on every start."""
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO schema_meta (k, v) VALUES ('schema_version', ?)"
        " ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        (str(SCHEMA_VERSION),),
    )
