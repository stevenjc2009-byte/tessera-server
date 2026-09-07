from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tessera.store import BlobNotFound, BlobStore, InvalidDigest


def sha256(data: bytes) -> bytes:
    """Stand-in hasher. The real one is hydro_hash; the store does not care."""
    return hashlib.sha256(data).digest()


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs", sha256)


def test_put_returns_the_content_hash(store: BlobStore) -> None:
    digest = store.put(b"hello tessera")
    assert digest == sha256(b"hello tessera").hex()
    assert len(digest) == 64


def test_round_trip_is_byte_identical(store: BlobStore) -> None:
    payload = bytes(range(256)) * 8
    assert store.get(store.put(payload)) == payload


def test_putting_the_same_bytes_twice_is_one_file(store: BlobStore) -> None:
    first = store.put(b"same")
    second = store.put(b"same")
    assert first == second
    assert len(list(store.root.rglob("*"))) == len(list(store.root.rglob("*")))
    files = [p for p in store.root.rglob("*") if p.is_file()]
    assert len(files) == 1


def test_a_missing_blob_raises(store: BlobStore) -> None:
    with pytest.raises(BlobNotFound):
        store.get("ab" * 32)


@pytest.mark.parametrize(
    "bad",
    [
        "../../etc/passwd",
        "..",
        "/etc/passwd",
        "ab" * 31,
        "ab" * 33,
        "AB" * 32,
        "zz" * 32,
        "",
        "ab/cd" + "e" * 59,
        "\x00" * 64,
    ],
)
def test_a_user_supplied_name_can_never_reach_the_filesystem(
    store: BlobStore, bad: str
) -> None:
    with pytest.raises(InvalidDigest):
        store.get(bad)
    with pytest.raises(InvalidDigest):
        store.delete(bad)
    with pytest.raises(InvalidDigest):
        store.exists(bad)


def test_files_are_fanned_out_by_the_first_four_hex_characters(store: BlobStore) -> None:
    digest = store.put(b"fanout")
    expected = store.root / digest[0:2] / digest[2:4] / digest
    assert expected.is_file()
    assert expected.read_bytes() == b"fanout"


def test_stored_files_are_not_executable(store: BlobStore) -> None:
    digest = store.put(b"x")
    mode = (store.root / digest[0:2] / digest[2:4] / digest).stat().st_mode
    assert mode & 0o111 == 0, "a blob must never be executable"


def test_total_bytes_sums_the_store(store: BlobStore) -> None:
    assert store.total_bytes() == 0
    store.put(b"a" * 100)
    store.put(b"b" * 250)
    assert store.total_bytes() == 350
    store.put(b"a" * 100)  # already present, adds nothing
    assert store.total_bytes() == 350


def test_delete_removes_the_blob_and_reports_whether_it_existed(store: BlobStore) -> None:
    digest = store.put(b"gone soon")
    assert store.delete(digest) is True
    assert store.exists(digest) is False
    assert store.delete(digest) is False


def test_an_empty_blob_is_storable(store: BlobStore) -> None:
    digest = store.put(b"")
    assert store.get(digest) == b""


def test_the_store_never_interprets_the_bytes(store: BlobStore) -> None:
    # A PNG signature followed by garbage that would upset a real decoder.
    hostile = b"\x89PNG\r\n\x1a\n" + b"\xff" * 64 + b"IEND"
    assert store.get(store.put(hostile)) == hostile
