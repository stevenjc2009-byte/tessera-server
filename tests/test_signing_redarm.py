"""Red-arm proof for the signature gate.

A test that a forged request is rejected proves nothing on its own: the
request could be failing for an unrelated reason (a bad route, a rate limit, a
typo in the header name). This runs the same forged request twice against an
in-process server — once with `verify_signed_request` intact, once with it
monkeypatched to succeed — and asserts the answer *changes*. If it does not,
the 401 elsewhere in the suite is not coming from the signature check.

In-process on purpose: monkeypatching cannot reach a subprocess, and shipping
an environment variable that disables signature checking would be a far worse
thing to have in the tree than this file.
"""

from __future__ import annotations

import http.client
import threading
from pathlib import Path

import pytest

from tessera import http_server, signing
from tessera.config import TesseraConfig, load_config
from tessera.hydro import Hydro
from tessera.http_server import build_app, make_server
from tessera.signing import SignedIdentity

BODY = b'{"model_id":1,"value":1}'


@pytest.fixture
def in_process_server(state_dir: Path, hydro_library_path: Path):
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_LISTEN_PORT": "0",
        "TESSERA_IP_BURST": "500",
    })
    app = build_app(cfg)
    server = make_server(app)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def post_forged(port: int) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", "/vote", BODY, {
        "X-Tessera-Key": "ab" * 32,
        "X-Tessera-Sig": "cd" * 64,
        "X-Tessera-Ts": "0",
        "X-Tessera-Nonce": "ef" * 16,
        "Content-Length": str(len(BODY)),
    })
    status = conn.getresponse().status
    conn.close()
    return status


def test_the_signature_gate_is_what_rejects_the_forgery(in_process_server, monkeypatch) -> None:
    port = in_process_server.server_address[1]

    # Armed: the real check runs.
    armed = post_forged(port)
    assert armed in (401, 400), "a forged request was not rejected"

    # Disarmed: verification always succeeds. If the answer does not change,
    # the rejection above was not coming from the signature check at all.
    monkeypatch.setattr(
        http_server, "verify_signed_request",
        lambda **kwargs: SignedIdentity(key_hex="ab" * 32, is_admin=False),
    )
    disarmed = post_forged(port)
    assert disarmed not in (401,), (
        "disarming verify_signed_request did not change the answer — "
        "the 401 is not produced by the signature check"
    )
