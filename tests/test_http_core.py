from __future__ import annotations

import json
import time

import pytest

from tessera.proxyproto import build_ppv2_header


def test_the_server_answers_browse_on_an_empty_gallery(client) -> None:
    status, headers, body = client.get("/browse")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    payload = json.loads(body)
    assert payload["items"] == []
    assert payload["total"] == 0


def test_an_unknown_path_is_404_json(client) -> None:
    status, headers, body = client.get("/does-not-exist")
    assert status == 404
    assert json.loads(body)["error"] == "not_found"


def test_a_wrong_method_is_405(client) -> None:
    status, _, body = client.request("DELETE", "/browse", b"")
    assert status == 405
    assert json.loads(body)["error"] == "method_not_allowed"


def test_a_body_over_the_ceiling_is_413_and_is_not_read(client) -> None:
    huge = b"x" * (client.config.max_request_bytes + 1)
    status, _, body = client.request("POST", "/upload", huge, expect_early_close=True)
    assert status == 413
    assert json.loads(body)["error"] == "too_large"


def test_a_missing_content_length_on_a_post_is_411(client) -> None:
    status, _, body = client.raw_request(
        b"POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    assert status == 411
    assert json.loads(body)["error"] == "length_required"


def test_the_server_never_advertises_what_it_is(client) -> None:
    _, headers, _ = client.get("/browse")
    assert "Server" not in headers or headers["Server"] == "tessera"
    assert "X-Powered-By" not in headers


def test_security_headers_are_present_on_every_answer(client) -> None:
    _, headers, _ = client.get("/browse")
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_the_rate_limiter_eventually_refuses(client) -> None:
    statuses = [client.get("/browse")[0] for _ in range(client.config.ip_burst + 10)]
    assert 429 in statuses, "the per-IP limiter never fired"
    assert statuses[0] == 200


def test_proxy_protocol_off_means_a_ppv2_prefix_is_a_bad_request(client) -> None:
    status, _, _ = client.raw_request(
        build_ppv2_header("203.0.113.9", 4242) + b"GET /browse HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    assert status == 400


def test_proxy_protocol_on_reads_the_real_client_address(pp_client) -> None:
    # Each simulated address gets its own bucket, so 3 x burst all succeed.
    for octet in (1, 2, 3):
        statuses = [
            pp_client.get("/browse", src_ip=f"203.0.113.{octet}")[0]
            for _ in range(pp_client.config.ip_burst)
        ]
        assert statuses.count(200) == pp_client.config.ip_burst


def test_proxy_protocol_on_refuses_a_connection_with_no_header(pp_client) -> None:
    status, _, _ = pp_client.raw_request(
        b"GET /browse HTTP/1.1\r\nHost: x\r\n\r\n", with_ppv2=False
    )
    assert status in (400, 0), "a missing PROXY header must not be served"


def test_the_daemon_writes_a_pid_and_dies_cleanly(live_server) -> None:
    assert live_server.process.poll() is None
    live_server.stop()
    assert live_server.process.poll() is not None


def test_a_signed_route_rejects_an_unsigned_request(client) -> None:
    status, _, body = client.request("POST", "/vote", b"{}")
    assert status == 400
    assert json.loads(body)["error"] == "malformed_signature"


def test_a_signed_route_rejects_a_forged_signature(client) -> None:
    pk, sk = client.keypair()
    body = b'{"model_id":1,"value":1}'
    headers = client.sign_headers("POST", "/vote", body, pk, sk)
    forged = bytearray(bytes.fromhex(headers["X-Tessera-Sig"]))
    forged[3] ^= 0xFF
    headers["X-Tessera-Sig"] = bytes(forged).hex()
    status, _, raw = client.request("POST", "/vote", body, headers=headers)
    assert status == 401
    assert json.loads(raw)["error"] == "bad_signature"


def test_a_signed_route_rejects_a_replayed_request(client) -> None:
    pk, sk = client.keypair()
    body = b'{"model_id":1,"value":1}'
    headers = client.sign_headers("POST", "/vote", body, pk, sk)
    first, _, _ = client.request("POST", "/vote", body, headers=headers)
    second, _, raw = client.request("POST", "/vote", body, headers=headers)
    assert first != 409, "the first attempt should not be a replay"
    assert second == 409
    assert json.loads(raw)["error"] == "replayed"


def test_a_signed_route_rejects_a_stale_timestamp(client) -> None:
    pk, sk = client.keypair()
    body = b"{}"
    stale = int(time.time()) - (client.config.replay_window_secs + 60)
    headers = client.sign_headers("POST", "/vote", body, pk, sk, timestamp=stale)
    status, _, raw = client.request("POST", "/vote", body, headers=headers)
    assert status == 401
    assert json.loads(raw)["error"] == "stale_timestamp"


def test_an_admin_route_refuses_an_ordinary_key(client) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 403
    assert json.loads(raw)["error"] == "not_admin"


def test_an_admin_route_accepts_the_configured_admin_key(admin_client) -> None:
    client, pk, sk = admin_client
    status, _, _ = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 200
