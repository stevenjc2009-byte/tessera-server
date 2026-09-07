from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("votable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def vote(client, pk, sk, model_id: int, value: int):
    body = json.dumps({"model_id": model_id, "value": value}).encode()
    status, _, raw = client.signed("POST", "/vote", body, pk, sk)
    return status, (json.loads(raw) if raw else {})


def test_an_upvote_moves_the_score(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = vote(client, pk, sk, model_id, 1)
    assert status == 200
    assert payload == {
        "model_id": model_id, "score": 1, "up_votes": 1, "down_votes": 0, "your_vote": 1
    }


def test_a_downvote_moves_the_score_the_other_way(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    _, payload = vote(client, pk, sk, model_id, -1)
    assert payload["score"] == -1
    assert payload["down_votes"] == 1


def test_the_same_key_voting_twice_does_not_double_count(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, payload = vote(client, pk, sk, model_id, 1)
    assert payload["score"] == 1
    assert payload["up_votes"] == 1


def test_changing_a_vote_swings_the_score_by_two(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, payload = vote(client, pk, sk, model_id, -1)
    assert payload["score"] == -1
    assert payload["up_votes"] == 0
    assert payload["down_votes"] == 1


def test_a_zero_value_retracts_the_vote(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, payload = vote(client, pk, sk, model_id, 0)
    assert payload["score"] == 0
    assert payload["up_votes"] == 0
    assert payload["your_vote"] == 0


def test_two_keys_both_count(client) -> None:
    model_id = seed_model(client)
    for _ in range(3):
        pk, sk = client.keypair()
        vote(client, pk, sk, model_id, 1)
    pk, sk = client.keypair()
    _, payload = vote(client, pk, sk, model_id, -1)
    assert payload["score"] == 2
    assert payload["up_votes"] == 3
    assert payload["down_votes"] == 1


def test_the_browse_listing_shows_the_tally(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, _, raw = client.get("/browse")
    item = json.loads(raw)["items"][0]
    assert item["score"] == 1
    assert item["up_votes"] == 1


def test_an_unsigned_vote_is_refused(client) -> None:
    model_id = seed_model(client)
    body = json.dumps({"model_id": model_id, "value": 1}).encode()
    status, _, raw = client.request("POST", "/vote", body)
    assert status == 400
    assert json.loads(raw)["error"] == "malformed_signature"


def test_voting_on_a_missing_model_is_404(client) -> None:
    pk, sk = client.keypair()
    status, payload = vote(client, pk, sk, 99999, 1)
    assert status == 404
    assert payload["error"] == "not_found"


def test_voting_on_a_deleted_model_is_404(client) -> None:
    model_id = seed_model(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    pk, sk = client.keypair()
    assert vote(client, pk, sk, model_id, 1)[0] == 404


@pytest.mark.parametrize("value", [2, -2, 100, "1", None, 1.5, [1]])
def test_a_value_outside_the_allowed_set_is_400(client, value) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "value": value}).encode()
    status, _, raw = client.signed("POST", "/vote", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b"{}", b'{"value":1}',
                                  b'{"model_id":"x","value":1}'])
def test_a_malformed_vote_body_is_400(client, body: bytes) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("POST", "/vote", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


def test_a_banned_key_cannot_vote(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    status, payload = vote(client, pk, sk, model_id, 1)
    assert status == 403
    assert payload["error"] == "banned"


def test_the_stored_tallies_match_a_recount_from_the_votes_table(client) -> None:
    """The denormalised counters on `models` are what browse sorts on. If they
    ever drift from the votes table, `sort=top` is quietly lying."""
    model_id = seed_model(client)
    for index in range(5):
        pk, sk = client.keypair()
        vote(client, pk, sk, model_id, 1 if index % 2 == 0 else -1)
    conn = sqlite3.connect(client.config.db_path)
    stored = conn.execute(
        "SELECT score, up_votes, down_votes FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    recount = conn.execute(
        "SELECT COALESCE(SUM(value), 0),"
        " COALESCE(SUM(value = 1), 0), COALESCE(SUM(value = -1), 0)"
        " FROM votes WHERE model_id = ?", (model_id,)
    ).fetchone()
    conn.close()
    assert tuple(stored) == tuple(recount)
