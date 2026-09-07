from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload

MODEL = b'{"faces":[[0,1,2]],"palette":"db16"}'
THUMB = bytes(range(256))


def upload_one(client) -> int:
    pk, sk = client.keypair()
    status, _, raw = client.signed(
        "POST", "/upload", build_upload("A cube", "model", MODEL, THUMB), pk, sk
    )
    assert status == 201, raw
    return json.loads(raw)["id"]


def test_the_project_file_round_trips_byte_for_byte(client) -> None:
    model_id = upload_one(client)
    status, headers, body = client.get(f"/model/{model_id}")
    assert status == 200
    assert body == MODEL
    assert headers["Content-Length"] == str(len(MODEL))


def test_the_thumbnail_round_trips_byte_for_byte(client) -> None:
    model_id = upload_one(client)
    status, _, body = client.get(f"/thumb/{model_id}")
    assert status == 200
    assert body == THUMB


def test_downloads_are_served_as_opaque_bytes(client) -> None:
    model_id = upload_one(client)
    for path in (f"/model/{model_id}", f"/thumb/{model_id}"):
        _, headers, _ = client.get(path)
        assert headers["Content-Type"] == "application/octet-stream", path
        assert headers["X-Content-Type-Options"] == "nosniff", path
        assert headers["Content-Disposition"].startswith("attachment"), path


def test_downloads_need_no_signature(client) -> None:
    model_id = upload_one(client)
    status, _, _ = client.get(f"/model/{model_id}")
    assert status == 200


@pytest.mark.parametrize("path", ["/model/99999", "/thumb/99999"])
def test_an_unknown_id_is_404(client, path: str) -> None:
    status, _, raw = client.get(path)
    assert status == 404
    assert json.loads(raw)["error"] == "not_found"


@pytest.mark.parametrize(
    "path",
    ["/model/abc", "/model/-1", "/model/1.5", "/model/", "/model/../../etc/passwd",
     "/thumb/%2e%2e%2f", "/model/1;DROP TABLE models"],
)
def test_a_non_numeric_id_never_reaches_the_store(client, path: str) -> None:
    status, _, _ = client.get(path)
    assert status in (404, 400), f"{path} returned {status}"


def test_a_deleted_model_is_404_even_though_the_blob_still_exists(client) -> None:
    model_id = upload_one(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    assert client.get(f"/model/{model_id}")[0] == 404
    assert client.get(f"/thumb/{model_id}")[0] == 404


def test_an_unlisted_model_is_still_downloadable_by_direct_id(client) -> None:
    # Unlisted means "not in the browse list pending review", not "destroyed".
    # Someone who already has the id keeps their copy working; deletion is the
    # action that takes it away.
    model_id = upload_one(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'unlisted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    assert client.get(f"/model/{model_id}")[0] == 200


def test_a_missing_blob_behind_a_present_row_is_404_not_500(client) -> None:
    model_id = upload_one(client)
    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT model_hash FROM models WHERE id = ?", (model_id,)).fetchone()
    conn.close()
    digest = row[0]
    (client.config.blob_dir / digest[0:2] / digest[2:4] / digest).unlink()
    status, _, raw = client.get(f"/model/{model_id}")
    assert status == 404
    assert json.loads(raw)["error"] == "not_found"
