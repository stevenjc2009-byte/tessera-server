from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tessera.db import SCHEMA_VERSION, connect, migrate

MODEL_ROW = (
    "aa" * 32, "bb" * 32, "A hexagon", "cc" * 32, "model", 1234, 512, 1_757_260_800,
)
INSERT_MODEL = """
INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,
                    model_bytes, thumb_bytes, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    connection = connect(tmp_path / "t.db")
    migrate(connection)
    return connection


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    connection = connect(tmp_path / "t.db")
    migrate(connection)
    migrate(connection)
    version = connection.execute(
        "SELECT v FROM schema_meta WHERE k = 'schema_version'"
    ).fetchone()[0]
    assert int(version) == SCHEMA_VERSION


def test_expected_tables_exist(conn: sqlite3.Connection) -> None:
    names = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"models", "votes", "favourites", "reports", "bans", "nonces", "schema_meta"} <= names


def test_foreign_keys_are_enforced(conn: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
            (999, "dd" * 32, 1, 0),
        )


def test_a_model_hash_is_unique(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT_MODEL, MODEL_ROW)


def test_visibility_defaults_to_public_and_is_constrained(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    assert conn.execute("SELECT visibility FROM models").fetchone()[0] == "public"
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE models SET visibility = 'banished'")


def test_kind_is_constrained(conn: sqlite3.Connection) -> None:
    bad = ("11" * 32, "22" * 32, "t", "33" * 32, "sculpture", 1, 1, 0)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT_MODEL, bad)


def test_one_vote_per_key_per_model(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    conn.execute(
        "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
        (model_id, "dd" * 32, 1, 0),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
            (model_id, "dd" * 32, -1, 0),
        )


def test_a_vote_must_be_plus_or_minus_one(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
            (model_id, "dd" * 32, 5, 0),
        )


def test_one_report_per_key_per_model(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    args = (model_id, "ee" * 32, "spam", "", 0)
    conn.execute(
        "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        args,
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            args,
        )


def test_the_reason_list_is_exactly_the_spec_list(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    for index, reason in enumerate(("gore", "sexual", "hate", "stolen", "spam", "other")):
        conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, f"{index:064x}", reason, "", 0),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, "ff" * 32, "annoying", "", 0),
        )


def test_favourites_are_unlimited_but_not_duplicated(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    conn.execute(
        "INSERT INTO favourites (model_id, owner_key, created_at) VALUES (?, ?, ?)",
        (model_id, "ab" * 32, 0),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO favourites (model_id, owner_key, created_at) VALUES (?, ?, ?)",
            (model_id, "ab" * 32, 0),
        )


def test_deleting_a_model_cascades(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    conn.execute(
        "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
        (model_id, "dd" * 32, 1, 0),
    )
    conn.execute("DELETE FROM models WHERE id = ?", (model_id,))
    assert conn.execute("SELECT COUNT(*) FROM votes").fetchone()[0] == 0


def test_wal_mode_is_on(conn: sqlite3.Connection) -> None:
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_rows_come_back_as_mappings(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    row = conn.execute("SELECT title, kind FROM models").fetchone()
    assert row["title"] == "A hexagon"
    assert row["kind"] == "model"
