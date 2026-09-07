from __future__ import annotations

import sqlite3

import pytest

from tessera.replay import ReplayWindow

WINDOW = 300
NOW = 1_757_260_800
KEY_A = "aa" * 32
KEY_B = "bb" * 32
NONCE_1 = "11" * 16
NONCE_2 = "22" * 16


@pytest.fixture
def window() -> ReplayWindow:
    conn = sqlite3.connect(":memory:")
    win = ReplayWindow(conn)
    win.ensure_table()
    return win


def test_a_fresh_nonce_is_accepted(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True


def test_the_same_nonce_twice_is_rejected(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is False


def test_the_same_nonce_from_a_different_key_is_fine(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_B, NONCE_1, NOW, WINDOW) is True


def test_a_different_nonce_from_the_same_key_is_fine(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_2, NOW, WINDOW) is True


def test_the_window_slides_so_an_expired_nonce_becomes_reusable(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_1, NOW + WINDOW // 2, WINDOW) is False
    # Past the trailing edge: the record has expired, and the signing layer's
    # own timestamp check is what stops the old request being replayed now.
    assert window.check_and_record(KEY_A, NONCE_1, NOW + 2 * WINDOW + 1, WINDOW) is True


def test_purge_removes_only_expired_rows(window: ReplayWindow) -> None:
    window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW)
    # One second inside NONCE_1's expiry, not on it: check_and_record purges
    # with `expires_at <= now` before inserting, so recording NONCE_2 at
    # exactly NOW + WINDOW would sweep NONCE_1 here and leave the explicit
    # purge below nothing to count.
    window.check_and_record(KEY_A, NONCE_2, NOW + WINDOW - 1, WINDOW)
    removed = window.purge(NOW + WINDOW + 1)
    assert removed == 1
    assert window.check_and_record(KEY_A, NONCE_1, NOW + WINDOW + 1, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_2, NOW + WINDOW + 1, WINDOW) is False


def test_the_table_does_not_grow_without_bound(window: ReplayWindow) -> None:
    for i in range(500):
        window.check_and_record(KEY_A, f"{i:032x}", NOW + i, WINDOW)
    rows = window.conn.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
    # Everything older than the window at the last recorded time is gone.
    assert rows <= 2 * WINDOW + 2, f"nonce table holds {rows} rows — purge is not running"


def test_ensure_table_is_idempotent(window: ReplayWindow) -> None:
    window.ensure_table()
    window.ensure_table()
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
