from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from tessera.envelope import build_upload


def run_tool(repo_root: Path, name: str, config_path: Path, *args: str):
    env = dict(os.environ, PYTHONPATH=str(repo_root / "src"))
    return subprocess.run(
        [sys.executable, str(repo_root / "tools" / name), "--config", str(config_path), *args],
        capture_output=True, text=True, timeout=60, env=env,
    )


def seed_reported_model(client) -> int:
    pk, sk = client.keypair()
    status, _, raw = client.signed(
        "POST", "/upload", build_upload("bad model", "model", b"m", b"t"), pk, sk
    )
    assert status == 201, raw
    model_id = json.loads(raw)["id"]
    for _ in range(2):
        rpk, rsk = client.keypair()
        body = json.dumps({"model_id": model_id, "reason": "gore", "detail": "nope"}).encode()
        assert client.signed("POST", "/report", body, rpk, rsk)[0] == 202
    return model_id


# -- tessera-reports ------------------------------------------------------

def test_list_prints_the_open_queue(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list")
    assert result.returncode == 0, result.stderr
    assert str(model_id) in result.stdout
    assert "bad model" in result.stdout
    assert "gore" in result.stdout


def test_list_json_is_machine_readable(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list", "--json")
    assert result.returncode == 0, result.stderr
    items = json.loads(result.stdout)
    assert items[0]["model_id"] == model_id
    assert items[0]["report_count"] == 2
    assert items[0]["reasons"] == ["gore"]


def test_list_on_an_empty_queue_exits_zero(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list")
    assert result.returncode == 0
    assert "no open reports" in result.stdout.lower()


def test_show_prints_the_full_detail_for_one_model(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path, "show", str(model_id))
    assert result.returncode == 0, result.stderr
    assert "nope" in result.stdout
    assert "gore" in result.stdout


def test_delete_takes_the_model_down_and_logs_it(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path,
                      "delete", str(model_id), "--reason", "obvious")
    assert result.returncode == 0, result.stderr
    conn = sqlite3.connect(client.config.db_path)
    assert conn.execute(
        "SELECT visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()[0] == "deleted"
    assert conn.execute(
        "SELECT action, reason FROM admin_log ORDER BY id DESC LIMIT 1"
    ).fetchone() == ("delete", "obvious")
    conn.close()


def test_a_cli_delete_is_visible_over_http_immediately(client, repo_root) -> None:
    """The daemon and the CLI are two writers on one database. If the daemon
    were holding stale state, a moderator's takedown would not take effect
    until a restart — which is exactly the failure that matters here."""
    model_id = seed_reported_model(client)
    assert client.get(f"/model/{model_id}")[0] == 200
    run_tool(repo_root, "tessera-reports", client.config_path, "delete", str(model_id))
    assert client.get(f"/model/{model_id}")[0] == 404


def test_approve_clears_the_queue(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    run_tool(repo_root, "tessera-reports", client.config_path, "approve", str(model_id))
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list", "--json")
    assert json.loads(result.stdout) == []


def test_ban_then_unban_round_trips(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    conn = sqlite3.connect(client.config.db_path)
    author = conn.execute("SELECT author_key FROM models WHERE id = ?", (model_id,)).fetchone()[0]
    conn.close()

    assert run_tool(repo_root, "tessera-reports", client.config_path,
                    "ban", str(model_id), "--reason", "spammer").returncode == 0
    conn = sqlite3.connect(client.config.db_path)
    assert conn.execute("SELECT COUNT(*) FROM bans WHERE key = ?", (author,)).fetchone()[0] == 1
    conn.close()

    assert run_tool(repo_root, "tessera-reports", client.config_path,
                    "unban", author).returncode == 0
    conn = sqlite3.connect(client.config.db_path)
    assert conn.execute("SELECT COUNT(*) FROM bans WHERE key = ?", (author,)).fetchone()[0] == 0
    conn.close()


def test_an_action_on_an_unknown_model_exits_nonzero(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-reports", client.config_path, "delete", "99999")
    assert result.returncode != 0
    assert "99999" in result.stderr


def test_unbanning_a_key_that_is_not_banned_exits_nonzero(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-reports", client.config_path, "unban", "ab" * 32)
    assert result.returncode != 0


def test_a_report_detail_cannot_inject_an_escape_sequence(client, repo_root) -> None:
    """The detail is attacker-controlled text printed to a moderator's
    terminal. The API refuses control characters on the way in (Task 18); this
    is the second, independent guard, and the one that still holds for rows
    written before that check existed. Written straight into the database so
    the API check cannot be what makes this pass."""
    model_id = seed_reported_model(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE reports SET detail = ? WHERE model_id = ?",
                 ("\x1b]0;pwned\x07boom", model_id))
    conn.commit()
    conn.close()
    result = run_tool(repo_root, "tessera-reports", client.config_path, "show", str(model_id))
    assert "\x1b" not in result.stdout, "an escape byte reached the moderator's terminal"
    assert "boom" in result.stdout, "the sanitiser ate the readable text too"


# -- tessera-keys ---------------------------------------------------------

def test_new_prints_a_keypair(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-keys", client.config_path, "new")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["public_key"]) == 64
    assert len(payload["secret_key"]) == 128


def test_two_new_keys_differ(client, repo_root) -> None:
    a = json.loads(run_tool(repo_root, "tessera-keys", client.config_path, "new").stdout)
    b = json.loads(run_tool(repo_root, "tessera-keys", client.config_path, "new").stdout)
    assert a["public_key"] != b["public_key"]


def test_a_generated_key_is_one_the_daemon_accepts(client, repo_root) -> None:
    """End to end: a key made by the tool signs a request the running daemon
    verifies. Two hydrogen implementations that disagreed would be invisible
    to every other test here."""
    payload = json.loads(run_tool(repo_root, "tessera-keys", client.config_path, "new").stdout)
    pk = bytes.fromhex(payload["public_key"])
    sk = bytes.fromhex(payload["secret_key"])
    body = build_upload("from the tool", "model", b"tool-model", b"tool-thumb")
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw


def test_admin_add_writes_the_key_into_the_config_file(client, repo_root) -> None:
    key = "cd" * 32
    result = run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    assert result.returncode == 0, result.stderr
    assert key in client.config_path.read_text()
    assert key in run_tool(repo_root, "tessera-keys", client.config_path, "show").stdout


def test_admin_add_refuses_a_key_that_is_not_64_lowercase_hex(client, repo_root) -> None:
    for bad in ("", "xyz", "ab" * 31, "ab" * 33, "AB" * 32, "ab" * 31 + "g!"):
        result = run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", bad)
        assert result.returncode != 0, f"{bad!r} was accepted as an admin key"


def test_admin_add_is_idempotent(client, repo_root) -> None:
    key = "ef" * 32
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    assert client.config_path.read_text().count(key) == 1


def test_admin_remove_takes_it_out_again(client, repo_root) -> None:
    key = "12" * 32
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    result = run_tool(repo_root, "tessera-keys", client.config_path, "admin-remove", key)
    assert result.returncode == 0, result.stderr
    assert key not in client.config_path.read_text()


def test_rewriting_the_config_keeps_every_other_setting(client, repo_root) -> None:
    before = client.config_path.read_text()
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", "34" * 32)
    after = client.config_path.read_text()
    for line in before.splitlines():
        if line.strip() and not line.startswith("admin_keys"):
            assert line in after, f"tessera-keys dropped a config line: {line!r}"
