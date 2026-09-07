from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conftest as _conftest  # noqa: E402

from tessera.envelope import build_upload  # noqa: E402
from tessera.hydro import Hydro  # noqa: E402

THUMB = b"thumbnail-bytes"


@pytest.fixture
def client(tmp_path: Path, state_dir: Path, hydro_library_path: Path):
    """Overrides conftest's `client` for this module only.

    Several tests here seed `browse_page_size + 5` (25) or more models in a
    row from a single apparent IP. The default `ip_burst` (20) is tuned for
    the abuse-resistance tests in test_http_core.py, not for a browse test
    that needs to seed a full page plus a remainder — with it left at the
    default, seeding trips the per-IP rate limiter before the upload loop
    even finishes, which is a test-harness collision with rate limiting, not
    anything this task is testing. Raised the same way
    test_signing_redarm.py's in_process_server fixture already does.
    """
    server = _conftest._start(tmp_path, state_dir, hydro_library_path, {"ip_burst": 500})
    yield _conftest.Client(server, Hydro(hydro_library_path), use_ppv2=False)
    server.stop()


def seed(client, count: int, kind: str = "model") -> list[int]:
    ids = []
    for i in range(count):
        pk, sk = client.keypair()
        # Model bytes are namespaced by kind, not just index: the store dedups
        # by content hash alone (Task 12), so two seed() calls with different
        # kind but the same index would otherwise collide as a 409 duplicate.
        body = build_upload(f"piece {i:02d}", kind, f"model-{kind}-{i}".encode(), THUMB + bytes([i]))
        status, _, raw = client.signed("POST", "/upload", body, pk, sk)
        assert status == 201, raw
        ids.append(json.loads(raw)["id"])
    return ids


def browse(client, query: str = "") -> dict:
    status, _, raw = client.get("/browse" + query)
    assert status == 200, raw
    return json.loads(raw)


def test_browse_is_public_and_needs_no_signature(client) -> None:
    seed(client, 1)
    assert browse(client)["total"] == 1


def test_default_paging_uses_the_configured_page_size(client) -> None:
    seed(client, client.config.browse_page_size + 5)
    page = browse(client)
    assert page["page"] == 1
    assert page["per_page"] == client.config.browse_page_size
    assert len(page["items"]) == client.config.browse_page_size
    assert page["total"] == client.config.browse_page_size + 5


def test_the_second_page_holds_the_remainder_with_no_overlap(client) -> None:
    seed(client, 25)
    first = browse(client, "?page=1&per_page=20")
    second = browse(client, "?page=2&per_page=20")
    assert len(first["items"]) == 20
    assert len(second["items"]) == 5
    assert not {item["id"] for item in first["items"]} & {item["id"] for item in second["items"]}


def test_a_page_past_the_end_is_empty_not_an_error(client) -> None:
    seed(client, 3)
    page = browse(client, "?page=99")
    assert page["items"] == []
    assert page["total"] == 3


def test_per_page_is_clamped_to_the_maximum(client) -> None:
    seed(client, 3)
    page = browse(client, f"?per_page={client.config.browse_max_page_size + 500}")
    assert page["per_page"] == client.config.browse_max_page_size


@pytest.mark.parametrize("query", ["?page=0", "?page=-1", "?page=abc", "?per_page=0",
                                   "?per_page=-5", "?per_page=xyz", "?sort=sideways"])
def test_nonsense_query_parameters_fall_back_to_defaults(client, query: str) -> None:
    seed(client, 2)
    page = browse(client, query)
    assert page["page"] >= 1
    assert 1 <= page["per_page"] <= client.config.browse_max_page_size


def test_sort_new_is_newest_first(client) -> None:
    seed(client, 4)
    items = browse(client, "?sort=new")["items"]
    created = [item["created_at"] for item in items]
    ids = [item["id"] for item in items]
    assert created == sorted(created, reverse=True)
    assert ids == sorted(ids, reverse=True)


def test_sort_top_is_highest_score_first(client) -> None:
    ids = seed(client, 3)
    import sqlite3
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET score = 5 WHERE id = ?", (ids[0],))
    conn.execute("UPDATE models SET score = -2 WHERE id = ?", (ids[1],))
    conn.commit()
    conn.close()
    items = browse(client, "?sort=top")["items"]
    assert [item["score"] for item in items] == [5, 0, -2]


def test_kind_filters_the_list(client) -> None:
    seed(client, 2, kind="model")
    seed(client, 3, kind="pixel")
    assert browse(client, "?kind=pixel")["total"] == 3
    assert browse(client, "?kind=model")["total"] == 2
    assert browse(client, "")["total"] == 5


def test_unlisted_and_deleted_models_never_appear(client) -> None:
    ids = seed(client, 3)
    import sqlite3
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'unlisted' WHERE id = ?", (ids[0],))
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (ids[1],))
    conn.commit()
    conn.close()
    page = browse(client)
    assert page["total"] == 1
    assert [item["id"] for item in page["items"]] == [ids[2]]


def test_the_listed_fields_are_exactly_the_documented_set(client) -> None:
    seed(client, 1)
    item = browse(client)["items"][0]
    assert set(item) == {
        "id", "title", "author_key", "kind", "thumb_hash",
        "score", "up_votes", "down_votes", "created_at",
    }
    assert "model_hash" not in item  # the download endpoint resolves it, not the list
