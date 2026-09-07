from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("favouritable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def fav(client, pk, sk, model_id: int, on: bool):
    body = json.dumps({"model_id": model_id, "on": on}).encode()
    status, _, raw = client.signed("POST", "/favourite", body, pk, sk)
    return status, (json.loads(raw) if raw else {})


def test_favouriting_records_it(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = fav(client, pk, sk, model_id, True)
    assert status == 200
    assert payload == {"model_id": model_id, "favourited": True, "favourite_count": 1}


def test_favouriting_twice_is_idempotent(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    _, payload = fav(client, pk, sk, model_id, True)
    assert payload["favourite_count"] == 1


def test_unfavouriting_removes_it(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    _, payload = fav(client, pk, sk, model_id, False)
    assert payload == {"model_id": model_id, "favourited": False, "favourite_count": 0}


def test_unfavouriting_something_never_favourited_is_not_an_error(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = fav(client, pk, sk, model_id, False)
    assert status == 200
    assert payload["favourited"] is False


def test_favourites_are_per_key(client) -> None:
    model_id = seed_model(client)
    pk_a, sk_a = client.keypair()
    pk_b, sk_b = client.keypair()
    fav(client, pk_a, sk_a, model_id, True)
    _, payload = fav(client, pk_b, sk_b, model_id, True)
    assert payload["favourite_count"] == 2
    _, payload = fav(client, pk_a, sk_a, model_id, False)
    assert payload["favourite_count"] == 1


def test_a_favourite_does_not_move_the_score(client) -> None:
    """Hearts and votes are separate axes (spec section 4). A favourite is a
    private bookmark; a vote is a public ranking signal. Conflating them would
    make the browse ordering mean something nobody asked for."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    _, _, raw = client.get("/browse")
    assert json.loads(raw)["items"][0]["score"] == 0


def test_an_unsigned_favourite_is_refused(client) -> None:
    model_id = seed_model(client)
    body = json.dumps({"model_id": model_id, "on": True}).encode()
    status, _, _ = client.request("POST", "/favourite", body)
    assert status == 400


def test_favouriting_a_missing_model_is_404(client) -> None:
    pk, sk = client.keypair()
    assert fav(client, pk, sk, 99999, True)[0] == 404


def test_favouriting_a_deleted_model_is_404(client) -> None:
    model_id = seed_model(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    pk, sk = client.keypair()
    assert fav(client, pk, sk, model_id, True)[0] == 404


@pytest.mark.parametrize("body", [b"", b"{}", b'{"model_id":1}', b'{"on":true}',
                                  b'{"model_id":1,"on":"yes"}', b'{"model_id":0,"on":true}'])
def test_a_malformed_favourite_body_is_400(client, body: bytes) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("POST", "/favourite", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


def test_a_banned_key_cannot_favourite(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    assert fav(client, pk, sk, model_id, True)[0] == 403


def test_deleting_a_model_row_takes_its_favourites_with_it(client) -> None:
    """The FK is ON DELETE CASCADE. This also proves foreign_keys=ON is really
    on: the PRAGMA is per-connection, and one that silently failed would leave
    orphan rows here and nothing else in the suite would notice."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM models WHERE id = ?", (model_id,))
    conn.commit()
    remaining = conn.execute(
        "SELECT COUNT(*) FROM favourites WHERE model_id = ?", (model_id,)
    ).fetchone()[0]
    conn.close()
    assert remaining == 0
