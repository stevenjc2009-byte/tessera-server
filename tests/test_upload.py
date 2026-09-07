from __future__ import annotations

import json

import pytest

from tessera.envelope import build_upload

MODEL = b'{"faces":[],"palette":"pico8"}'
THUMB = b"\x89PNG\r\n\x1a\n" + b"\x00" * 96


def upload(client, pk, sk, *, title="A hexagon", kind="model", model=MODEL, thumb=THUMB, **kw):
    body = build_upload(title, kind, model, thumb)
    status, headers, raw = client.signed("POST", "/upload", body, pk, sk, **kw)
    return status, (json.loads(raw) if raw else {})


def test_a_valid_upload_is_accepted_and_indexed(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk)
    assert status == 201
    assert len(payload["model_hash"]) == 64
    assert len(payload["thumb_hash"]) == 64
    assert payload["id"] >= 1

    status, _, raw = client.get("/browse")
    items = json.loads(raw)["items"]
    assert len(items) == 1
    assert items[0]["title"] == "A hexagon"
    assert items[0]["author_key"] == pk.hex()


def test_the_stored_bytes_come_back_identical(client) -> None:
    pk, sk = client.keypair()
    _, payload = upload(client, pk, sk)
    status, headers, raw = client.get(f"/model/{payload['id']}")
    assert status == 200
    assert raw == MODEL


def test_an_unsigned_upload_is_refused(client) -> None:
    status, _, raw = client.request("POST", "/upload", build_upload("t", "model", MODEL, THUMB))
    assert status == 400
    assert json.loads(raw)["error"] == "malformed_signature"


def test_the_ninth_upload_in_a_day_is_refused(client) -> None:
    pk, sk = client.keypair()
    for i in range(client.config.uploads_per_key_per_day):
        status, _ = upload(client, pk, sk, title=f"piece {i}", model=MODEL + bytes([i]))
        assert status == 201, f"upload {i} was refused"
    status, payload = upload(client, pk, sk, title="one too many", model=MODEL + b"\xff")
    assert status == 429
    assert payload["error"] == "daily_quota"


def test_another_key_is_unaffected_by_the_first_keys_quota(client) -> None:
    pk_a, sk_a = client.keypair()
    for i in range(client.config.uploads_per_key_per_day):
        upload(client, pk_a, sk_a, model=MODEL + bytes([i]))
    pk_b, sk_b = client.keypair()
    status, _ = upload(client, pk_b, sk_b, model=MODEL + b"\xfe")
    assert status == 201


def test_a_banned_key_is_refused(client) -> None:
    pk, sk = client.keypair()
    upload(client, pk, sk)
    # Ban through the database directly; the admin path is Task 20.
    import sqlite3
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    status, payload = upload(client, pk, sk, model=MODEL + b"\x01")
    assert status == 403
    assert payload["error"] == "banned"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"", "bad_envelope"),
        (b"NOPE" + b"\x00" * 12, "bad_envelope"),
        (b"TSU1" + (999999).to_bytes(4, "little") * 3, "bad_envelope"),
        (b"TSU1" + b"\x00" * 8, "bad_envelope"),
    ],
)
def test_a_malformed_envelope_is_400(client, body: bytes, expected: str) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == expected


def test_an_oversized_model_is_refused(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, model=b"m" * (client.config.max_model_bytes + 1))
    assert status == 400
    assert payload["error"] == "bad_envelope"


def test_an_oversized_thumbnail_is_refused(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, thumb=b"t" * (client.config.max_thumb_bytes + 1))
    assert status == 400
    assert payload["error"] == "bad_envelope"


def test_a_body_past_the_http_ceiling_never_reaches_the_handler(client) -> None:
    pk, sk = client.keypair()
    body = build_upload("t", "model", b"m" * (client.config.max_request_bytes), THUMB)
    # Sent via request()+expect_early_close, not client.signed(): the server
    # answers 413 off the Content-Length header alone and never reads this
    # multi-megabyte body, so the client's send can be cut off mid-flight by
    # the server's early close. client.signed() has no way to request that
    # accommodation; test_http_core.py's analogous over-ceiling case needs the
    # same flag for the same reason.
    headers = client.sign_headers("POST", "/upload", body, pk, sk)
    status, _, raw = client.request(
        "POST", "/upload", body, headers=headers, expect_early_close=True
    )
    assert status == 413


def test_a_bad_kind_is_refused(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, kind="sculpture")
    assert status == 400
    assert payload["error"] == "bad_envelope"


def test_an_empty_title_is_refused_and_a_long_one_is_truncated_not_rejected(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, title="")
    assert status == 400
    status, payload = upload(client, pk, sk, title="x" * 500, model=MODEL + b"\x02")
    assert status == 201


def test_uploading_identical_bytes_twice_is_a_conflict_not_a_duplicate_row(client) -> None:
    pk, sk = client.keypair()
    first_status, first = upload(client, pk, sk)
    second_status, second = upload(client, pk, sk)
    assert first_status == 201
    assert second_status == 409
    assert second["error"] == "duplicate"
    status, _, raw = client.get("/browse")
    assert json.loads(raw)["total"] == 1


def test_a_title_with_control_characters_is_rejected(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, title="bad\x00title")
    assert status == 400
    assert payload["error"] == "bad_envelope"
