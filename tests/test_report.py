from __future__ import annotations

import json
import sqlite3
import subprocess

import pytest

from tessera.config import REPORT_REASONS
from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("reportable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def report(client, pk, sk, model_id: int, reason: str = "spam", detail: str | None = None):
    payload = {"model_id": model_id, "reason": reason}
    if detail is not None:
        payload["detail"] = detail
    status, _, raw = client.signed("POST", "/report", json.dumps(payload).encode(), pk, sk)
    return status, (json.loads(raw) if raw else {})


def test_a_report_is_accepted(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = report(client, pk, sk, model_id)
    assert status == 202
    assert payload["report_count"] == 1
    assert payload["hidden"] is False


def test_the_reason_list_is_exactly_the_spec_list() -> None:
    # Deviation from the plan: the plan's literal assertion is
    # `REPORT_REASONS == frozenset({...})`, but config.py (out of scope for
    # this task) defines REPORT_REASONS as a tuple, and tuple == frozenset is
    # always False in Python regardless of contents. Comparing as
    # frozenset(REPORT_REASONS) preserves the test's intent (the reason set is
    # exactly the spec set) without touching config.py.
    assert frozenset(REPORT_REASONS) == frozenset({"gore", "sexual", "hate", "stolen", "spam", "other"})


@pytest.mark.parametrize("reason", sorted(REPORT_REASONS))
def test_every_spec_reason_is_accepted(client, reason: str) -> None:
    model_id = seed_model(client, tag=reason.encode())
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, reason=reason)[0] == 202


@pytest.mark.parametrize("reason", ["", "SPAM", "harassment", "gore ", "other; DROP TABLE",
                                     None, 1])
def test_a_reason_outside_the_list_is_400(client, reason) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "reason": reason}).encode()
    status, _, raw = client.signed("POST", "/report", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


def test_the_same_key_reporting_twice_does_not_count_twice(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    report(client, pk, sk, model_id, "spam")
    status, payload = report(client, pk, sk, model_id, "gore")
    assert status == 202
    assert payload["report_count"] == 1, "one key must never be able to stack reports"


def test_a_second_report_from_the_same_key_corrects_the_reason(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    report(client, pk, sk, model_id, "spam")
    report(client, pk, sk, model_id, "gore")
    conn = sqlite3.connect(client.config.db_path)
    rows = conn.execute("SELECT reason FROM reports WHERE model_id = ?", (model_id,)).fetchall()
    conn.close()
    assert rows == [("gore",)]


def test_the_detail_field_is_stored_and_truncated_not_rejected(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, detail="x" * 5000)[0] == 202
    conn = sqlite3.connect(client.config.db_path)
    stored = conn.execute(
        "SELECT detail FROM reports WHERE model_id = ?", (model_id,)
    ).fetchone()[0]
    conn.close()
    assert 0 < len(stored) <= 512


def test_a_detail_with_control_characters_is_rejected(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, detail="line\x00break")[0] == 400


def test_a_detail_with_an_escape_sequence_is_rejected(client) -> None:
    """The detail is printed straight into a moderator's terminal by
    tools/tessera-reports. An ESC byte there is executed by the terminal, not
    displayed — a report is attacker-controlled text aimed at that screen."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, detail="\x1b]0;pwned\x07")[0] == 400


def test_an_unsigned_report_is_refused(client) -> None:
    model_id = seed_model(client)
    body = json.dumps({"model_id": model_id, "reason": "spam"}).encode()
    assert client.request("POST", "/report", body)[0] == 400


def test_reporting_a_missing_model_is_404(client) -> None:
    pk, sk = client.keypair()
    assert report(client, pk, sk, 99999)[0] == 404


def test_a_banned_key_cannot_report(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    assert report(client, pk, sk, model_id)[0] == 403


def test_reporting_produces_no_outbound_connection(client, live_server) -> None:
    """Spec section 4: reports are pull-based with ZERO egress. No webhook, no
    email, no push. This asserts the daemon holds no socket to anywhere but its
    own loopback listener after a report — if someone later adds a webhook,
    this goes red."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id)[0] == 202

    pid = live_server.process.pid
    try:
        out = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("ss(8) is not available on this machine")

    daemon_lines = [line for line in out.splitlines() if f"pid={pid}," in line]
    foreign = [
        line for line in daemon_lines
        if "127.0.0.1" not in line and "[::1]" not in line
    ]
    assert not foreign, "the daemon opened a connection off loopback:\n" + "\n".join(foreign)


def test_the_report_row_records_who_and_why(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    report(client, pk, sk, model_id, "stolen", "this is my model")
    conn = sqlite3.connect(client.config.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM reports WHERE model_id = ?", (model_id,)).fetchone()
    conn.close()
    assert row["reporter_key"] == pk.hex()
    assert row["reason"] == "stolen"
    assert row["detail"] == "this is my model"
    assert row["resolved_at"] is None
    assert row["created_at"] > 0
