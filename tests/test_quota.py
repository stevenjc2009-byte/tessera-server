from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from tessera.config import TesseraConfig, load_config
from tessera.db import connect, migrate
from tessera.quota import QuotaError, check_upload_allowed, uploads_last_hour, uploads_today
from tessera.store import BlobStore

NOW = 1_757_260_800
DAY = 86_400
HOUR = 3_600
AUTHOR = "aa" * 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    connection = connect(tmp_path / "t.db")
    migrate(connection)
    return connection


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs", sha256)


def add_upload(conn: sqlite3.Connection, author: str, created_at: int, tag: str) -> None:
    conn.execute(
        "INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,"
        " model_bytes, thumb_bytes, created_at) VALUES (?, ?, ?, ?, 'pixel', 10, 10, ?)",
        (sha256(tag.encode()).hex(), sha256((tag + "t").encode()).hex(), tag, author, created_at),
    )


def test_a_first_upload_is_allowed(conn, store, config: TesseraConfig) -> None:
    check_upload_allowed(
        conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=1000, now=NOW
    )


def test_the_eighth_upload_is_allowed_and_the_ninth_is_not(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - i * 60, f"m{i}")
        assert uploads_today(conn, AUTHOR, NOW) == i + 1
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
        )
    assert excinfo.value.code == "daily_quota"
    assert excinfo.value.status == 429


def test_the_daily_quota_is_a_rolling_24_hours(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - DAY - 60 - i, f"old{i}")
    assert uploads_today(conn, AUTHOR, NOW) == 0
    check_upload_allowed(
        conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
    )


def test_another_key_has_its_own_quota(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - i, f"m{i}")
    check_upload_allowed(
        conn=conn, store=store, cfg=config, author_key="bb" * 32, incoming_bytes=10, now=NOW
    )


def test_the_global_hourly_cap_stops_everyone(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_GLOBAL_UPLOADS_PER_HOUR": "3",
    })
    for i in range(3):
        add_upload(conn, f"{i:064x}", NOW - 60, f"g{i}")
    assert uploads_last_hour(conn, NOW) == 3
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=cfg, author_key="cc" * 32, incoming_bytes=10, now=NOW
        )
    assert excinfo.value.code == "global_rate"


def test_the_global_cap_is_a_rolling_hour(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_GLOBAL_UPLOADS_PER_HOUR": "3",
    })
    for i in range(3):
        add_upload(conn, f"{i:064x}", NOW - HOUR - 10 - i, f"g{i}")
    check_upload_allowed(
        conn=conn, store=store, cfg=cfg, author_key="cc" * 32, incoming_bytes=10, now=NOW
    )


def test_a_full_disk_refuses_the_upload(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_MAX_TOTAL_DISK_BYTES": "1000",
    })
    store.put(b"x" * 900)
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=cfg, author_key=AUTHOR, incoming_bytes=200, now=NOW
        )
    assert excinfo.value.code == "disk_full"
    assert excinfo.value.status == 507


def test_an_oversized_upload_is_refused(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_MAX_REQUEST_BYTES": "500",
    })
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=cfg, author_key=AUTHOR, incoming_bytes=501, now=NOW
        )
    assert excinfo.value.code == "too_large"
    assert excinfo.value.status == 413


def test_a_banned_key_cannot_upload(conn, store, config) -> None:
    conn.execute(
        "INSERT INTO bans (key, reason, created_at) VALUES (?, 'spam', ?)", (AUTHOR, NOW)
    )
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
        )
    assert excinfo.value.code == "banned"
    assert excinfo.value.status == 403


def test_deleted_uploads_still_count_against_the_daily_quota(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - i, f"m{i}")
    conn.execute("UPDATE models SET visibility = 'deleted'")
    with pytest.raises(QuotaError, match="daily"):
        check_upload_allowed(
            conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
        )
