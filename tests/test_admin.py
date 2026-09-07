from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> tuple[int, bytes]:
    pk, sk = client.keypair()
    body = build_upload("moderatable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"], pk


def report_from_a_new_key(client, model_id: int, reason: str = "spam", detail: str = ""):
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "reason": reason, "detail": detail}).encode()
    return client.signed("POST", "/report", body, pk, sk)


def act(client, pk, sk, model_id: int, action: str, reason: str = "reviewed"):
    body = json.dumps({"model_id": model_id, "action": action, "reason": reason}).encode()
    status, _, raw = client.signed("POST", "/admin/action", body, pk, sk)
    return status, (json.loads(raw) if raw else {})


def visibility_of(client, model_id: int) -> str:
    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT visibility FROM models WHERE id = ?", (model_id,)).fetchone()
    conn.close()
    return row[0]


# -- the queue ------------------------------------------------------------

def test_the_queue_is_empty_when_nothing_is_reported(admin_client) -> None:
    client, pk, sk = admin_client
    status, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 200
    assert json.loads(raw)["items"] == []


def test_a_reported_model_appears_with_its_reasons_rolled_up(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, author = seed_model(client)
    report_from_a_new_key(client, model_id, "gore", "very bad")
    report_from_a_new_key(client, model_id, "spam")

    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    items = json.loads(raw)["items"]
    assert len(items) == 1, "two reports on one model must be ONE queue row"
    entry = items[0]
    assert entry["model_id"] == model_id
    assert entry["title"] == "moderatable"
    assert entry["author_key"] == author.hex()
    assert entry["report_count"] == 2
    assert sorted(entry["reasons"]) == ["gore", "spam"]
    assert "very bad" in entry["details"]


def test_the_queue_needs_the_admin_key(client) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 403
    assert json.loads(raw)["error"] == "not_admin"


def test_the_queue_is_not_readable_unsigned(client) -> None:
    assert client.get("/admin/reports")[0] == 400


def test_resolved_reports_are_hidden_by_default_and_visible_on_request(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    report_from_a_new_key(client, model_id)
    act(client, pk, sk, model_id, "approve")

    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert json.loads(raw)["items"] == []

    _, _, raw = client.signed("GET", "/admin/reports?resolved=1", b"", pk, sk)
    assert len(json.loads(raw)["items"]) == 1


def test_the_queue_pages(admin_client) -> None:
    client, pk, sk = admin_client
    for index in range(7):
        model_id, _ = seed_model(client, tag=bytes([index]))
        report_from_a_new_key(client, model_id)
    _, _, raw = client.signed("GET", "/admin/reports?per_page=3&page=2", b"", pk, sk)
    page = json.loads(raw)
    assert page["total"] == 7
    assert len(page["items"]) == 3


def test_the_queue_puts_the_most_reported_first(admin_client) -> None:
    client, pk, sk = admin_client
    quiet, _ = seed_model(client, b"q")
    loud, _ = seed_model(client, b"l")
    report_from_a_new_key(client, quiet)
    for _ in range(2):
        report_from_a_new_key(client, loud)
    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert [item["model_id"] for item in json.loads(raw)["items"]] == [loud, quiet]


# -- the actions ----------------------------------------------------------

def test_approve_makes_it_public_and_closes_the_reports(admin_client) -> None:
    client, pk, sk = admin_client
    threshold = client.config.report_autohide_threshold
    model_id, _ = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    assert visibility_of(client, model_id) == "unlisted"

    status, payload = act(client, pk, sk, model_id, "approve")
    assert status == 200
    assert payload["visibility"] == "public"
    assert payload["resolved"] == threshold
    assert visibility_of(client, model_id) == "public"


def test_unlist_hides_it_from_browse_without_deleting(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    status, payload = act(client, pk, sk, model_id, "unlist")
    assert status == 200
    assert payload["visibility"] == "unlisted"
    _, _, raw = client.get("/browse")
    assert json.loads(raw)["items"] == []
    assert client.get(f"/model/{model_id}")[0] == 200


def test_unlist_leaves_the_reports_open(admin_client) -> None:
    """A model parked pending a decision must stay in the queue, or the next
    moderator has no idea why it is unlisted."""
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    report_from_a_new_key(client, model_id)
    act(client, pk, sk, model_id, "unlist")
    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert [item["model_id"] for item in json.loads(raw)["items"]] == [model_id]


def test_delete_removes_it_from_browse_and_from_download(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    status, payload = act(client, pk, sk, model_id, "delete")
    assert status == 200
    assert payload["visibility"] == "deleted"
    assert client.get(f"/model/{model_id}")[0] == 404
    assert client.get(f"/thumb/{model_id}")[0] == 404
    _, _, raw = client.get("/browse")
    assert json.loads(raw)["items"] == []


def test_delete_is_terminal(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    act(client, pk, sk, model_id, "delete")
    act(client, pk, sk, model_id, "approve")
    assert visibility_of(client, model_id) == "deleted", "approve resurrected a deleted model"


def test_ban_deletes_everything_that_key_uploaded(admin_client) -> None:
    client, pk, sk = admin_client
    conn_keys = client.keypair()
    author_pk, author_sk = conn_keys
    ids = []
    for index in range(3):
        body = build_upload(f"bad {index}", "model", b"m" + bytes([index]), b"t")
        status, _, raw = client.signed("POST", "/upload", body, author_pk, author_sk)
        assert status == 201, raw
        ids.append(json.loads(raw)["id"])

    status, payload = act(client, pk, sk, ids[0], "ban", "repeat offender")
    assert status == 200
    assert payload["banned_key"] == author_pk.hex()
    assert payload["visibility"] == "deleted"
    for model_id in ids:
        assert visibility_of(client, model_id) == "deleted", (
            f"model {model_id} by a banned key survived the ban"
        )

    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT reason FROM bans WHERE key = ?", (author_pk.hex(),)).fetchone()
    conn.close()
    assert row is not None and row[0] == "repeat offender"


def test_a_banned_author_cannot_upload_again(admin_client) -> None:
    client, pk, sk = admin_client
    author_pk, author_sk = client.keypair()
    body = build_upload("bad", "model", b"m", b"t")
    status, _, raw = client.signed("POST", "/upload", body, author_pk, author_sk)
    model_id = json.loads(raw)["id"]
    act(client, pk, sk, model_id, "ban")
    body = build_upload("again", "model", b"m2", b"t2")
    status, _, raw = client.signed("POST", "/upload", body, author_pk, author_sk)
    assert status == 403
    assert json.loads(raw)["error"] == "banned"


def test_an_action_from_a_non_admin_key_is_403_and_changes_nothing(client) -> None:
    model_id, _ = seed_model(client)
    pk, sk = client.keypair()
    status, payload = act(client, pk, sk, model_id, "delete")
    assert status == 403
    assert payload["error"] == "not_admin"
    assert visibility_of(client, model_id) == "public", "a non-admin changed a model's state"


def test_an_unsigned_action_is_refused_and_changes_nothing(client) -> None:
    model_id, _ = seed_model(client)
    body = json.dumps({"model_id": model_id, "action": "delete"}).encode()
    assert client.request("POST", "/admin/action", body)[0] == 400
    assert visibility_of(client, model_id) == "public"


@pytest.mark.parametrize("action", ["", "APPROVE", "purge", "drop", None, 1, "delete; ban"])
def test_an_unknown_action_is_400_and_changes_nothing(admin_client, action) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    body = json.dumps({"model_id": model_id, "action": action}).encode()
    status, _, raw = client.signed("POST", "/admin/action", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"
    assert visibility_of(client, model_id) == "public"


def test_an_action_on_a_missing_model_is_404(admin_client) -> None:
    client, pk, sk = admin_client
    assert act(client, pk, sk, 99999, "delete")[0] == 404


def test_every_action_is_written_to_the_audit_log(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    act(client, pk, sk, model_id, "unlist", "looks dodgy")
    conn = sqlite3.connect(client.config.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM admin_log ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row["model_id"] == model_id
    assert row["action"] == "unlist"
    assert row["reason"] == "looks dodgy"
    assert row["admin_key"] == pk.hex()
    assert row["created_at"] > 0
