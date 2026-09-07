from __future__ import annotations

import json
import sqlite3

from tessera import moderation
from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("hideable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def report_from_a_new_key(client, model_id: int, reason: str = "spam"):
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "reason": reason}).encode()
    status, _, raw = client.signed("POST", "/report", body, pk, sk)
    return status, json.loads(raw)


def visibility_of(client, model_id: int) -> str:
    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT visibility FROM models WHERE id = ?", (model_id,)).fetchone()
    conn.close()
    return row[0]


def open_conn(client) -> sqlite3.Connection:
    conn = sqlite3.connect(client.config.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def test_below_the_threshold_nothing_is_hidden(client) -> None:
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for index in range(threshold - 1):
        status, payload = report_from_a_new_key(client, model_id)
        assert status == 202
        assert payload["hidden"] is False, f"hidden after only {index + 1} reports"
    assert visibility_of(client, model_id) == "public"


def test_the_nth_distinct_key_hides_it(client) -> None:
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold - 1):
        report_from_a_new_key(client, model_id)
    status, payload = report_from_a_new_key(client, model_id)
    assert status == 202
    assert payload["report_count"] == threshold
    assert payload["hidden"] is True
    assert visibility_of(client, model_id) == "unlisted"


def test_the_default_threshold_is_the_spec_value(client) -> None:
    assert client.config.report_autohide_threshold == 3


def test_a_configured_threshold_of_two_hides_on_the_second_report(threshold_two_client) -> None:
    """Proves the code reads the config rather than a hardcoded 3. A server
    started with report_autohide_threshold = 2 must hide one report earlier."""
    client = threshold_two_client
    model_id = seed_model(client)
    assert report_from_a_new_key(client, model_id)[1]["hidden"] is False
    assert report_from_a_new_key(client, model_id)[1]["hidden"] is True
    assert visibility_of(client, model_id) == "unlisted"


def test_one_key_reporting_repeatedly_never_reaches_the_threshold(client) -> None:
    """The whole point of counting DISTINCT reporter keys. One angry person
    must not be able to unlist anything on their own."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    for reason in ("spam", "gore", "hate", "stolen", "sexual", "other"):
        body = json.dumps({"model_id": model_id, "reason": reason}).encode()
        status, _, raw = client.signed("POST", "/report", body, pk, sk)
        assert status == 202
        assert json.loads(raw)["report_count"] == 1
    assert visibility_of(client, model_id) == "public"


def test_a_hidden_model_disappears_from_browse(client) -> None:
    threshold = client.config.report_autohide_threshold
    keep = seed_model(client, b"keep")
    hide = seed_model(client, b"hide")
    for _ in range(threshold):
        report_from_a_new_key(client, hide)
    _, _, raw = client.get("/browse")
    listed = [item["id"] for item in json.loads(raw)["items"]]
    assert hide not in listed
    assert keep in listed


def test_a_hidden_model_is_still_downloadable_by_direct_id(client) -> None:
    """Unlisted means "not in the browse list pending review", not "destroyed".
    Someone who already has the id keeps their copy working; deletion is the
    action that takes it away, and only a human can order that."""
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    assert client.get(f"/model/{model_id}")[0] == 200


def test_set_visibility_never_resurrects_a_deleted_model(client) -> None:
    model_id = seed_model(client)
    conn = open_conn(client)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    moderation.set_visibility(conn, model_id, "unlisted")
    conn.commit()
    still = conn.execute("SELECT visibility FROM models WHERE id = ?", (model_id,)).fetchone()[0]
    conn.close()
    assert still == "deleted"


def test_set_visibility_refuses_a_state_that_is_not_a_state(client) -> None:
    model_id = seed_model(client)
    conn = open_conn(client)
    try:
        for bad in ("", "hidden", "PUBLIC", "deleted; DROP TABLE models"):
            try:
                moderation.set_visibility(conn, model_id, bad)
            except ValueError:
                continue
            raise AssertionError(f"{bad!r} was accepted as a visibility")
    finally:
        conn.close()


def test_resolving_the_reports_makes_the_model_public_again(client) -> None:
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    assert visibility_of(client, model_id) == "unlisted"

    conn = open_conn(client)
    resolved = moderation.resolve_reports(conn, model_id, now=1_000_000)
    moderation.set_visibility(conn, model_id, "public")
    conn.commit()
    open_now = moderation.open_report_count(conn, model_id)
    conn.close()

    assert resolved == threshold
    assert open_now == 0
    assert visibility_of(client, model_id) == "public"


def test_a_resolved_report_does_not_re_hide_on_the_next_new_report(client) -> None:
    """After a moderator approves a model its old reports are resolved. A
    single fresh report must not instantly re-hide it by counting the resolved
    ones again."""
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    conn = open_conn(client)
    moderation.resolve_reports(conn, model_id, now=1_000_000)
    moderation.set_visibility(conn, model_id, "public")
    conn.commit()
    conn.close()

    _, payload = report_from_a_new_key(client, model_id)
    assert payload["report_count"] == 1
    assert payload["hidden"] is False
    assert visibility_of(client, model_id) == "public"
