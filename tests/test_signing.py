from __future__ import annotations

from pathlib import Path

import pytest

from tessera.config import TesseraConfig, load_config
from tessera.hydro import Hydro
from tessera.replay import ReplayWindow
from tessera.signing import (
    SignatureError,
    canonical_message,
    verify_signed_request,
)

CTX = "tessera1"
NOW = 1_757_260_800


class MemoryReplay:
    """Stand-in for the SQLite-backed window, so this module tests alone."""

    def __init__(self) -> None:
        self.seen: set[tuple[str, str]] = set()

    def check_and_record(self, key_hex: str, nonce_hex: str, now: int, window: int) -> bool:
        pair = (key_hex, nonce_hex)
        if pair in self.seen:
            return False
        self.seen.add(pair)
        return True


@pytest.fixture
def hydro(hydro_library_path: Path) -> Hydro:
    return Hydro(hydro_library_path)


def sign_request(
    hydro: Hydro,
    sk: bytes,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: int = NOW,
    nonce_hex: str = "00" * 16,
) -> dict[str, str]:
    body_hash = hydro.hash32(body, CTX).hex()
    message = canonical_message(method, path, timestamp, nonce_hex, body_hash)
    return {
        "X-Tessera-Key": "",  # filled by the caller
        "X-Tessera-Sig": hydro.sign_create(message, CTX, sk).hex(),
        "X-Tessera-Ts": str(timestamp),
        "X-Tessera-Nonce": nonce_hex,
    }


def headers_for(hydro: Hydro, pk: bytes, sk: bytes, method: str, path: str, body: bytes, **kw):
    headers = sign_request(hydro, sk, method, path, body, **kw)
    headers["X-Tessera-Key"] = pk.hex()
    return headers


def test_canonical_message_is_the_documented_layout() -> None:
    got = canonical_message("POST", "/vote", 17, "ab" * 16, "cd" * 32)
    assert got == b"tessera-v1\nPOST\n/vote\n17\n" + b"ab" * 16 + b"\n" + b"cd" * 32


def test_a_correctly_signed_request_is_accepted(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    body = b'{"model_id":1,"value":1}'
    headers = headers_for(hydro, pk, sk, "POST", "/vote", body)
    identity = verify_signed_request(
        hydro=hydro, cfg=config, method="POST", path="/vote",
        headers=headers, body=body, now=NOW, replay=MemoryReplay(),
    )
    assert identity.key_hex == pk.hex()
    assert identity.is_admin is False


def test_a_forged_signature_is_rejected(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    body = b'{"model_id":1,"value":1}'
    headers = headers_for(hydro, pk, sk, "POST", "/vote", body)
    forged = bytearray(bytes.fromhex(headers["X-Tessera-Sig"]))
    forged[7] ^= 0xFF
    headers["X-Tessera-Sig"] = bytes(forged).hex()
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/vote",
            headers=headers, body=body, now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.status == 401
    assert excinfo.value.code == "bad_signature"


def test_a_tampered_body_is_rejected(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    headers = headers_for(hydro, pk, sk, "POST", "/vote", b'{"value":1}')
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/vote",
            headers=headers, body=b'{"value":-1}', now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.code == "bad_signature"


def test_a_signature_for_another_path_is_rejected(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    body = b"{}"
    headers = headers_for(hydro, pk, sk, "POST", "/vote", body)
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/admin/action",
            headers=headers, body=body, now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.code == "bad_signature"


def test_a_replayed_request_is_rejected(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    body = b"{}"
    headers = headers_for(hydro, pk, sk, "POST", "/vote", body)
    replay = MemoryReplay()
    kwargs = dict(hydro=hydro, cfg=config, method="POST", path="/vote",
                  headers=headers, body=body, now=NOW, replay=replay)
    verify_signed_request(**kwargs)          # first time: fine
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(**kwargs)      # byte-identical replay
    assert excinfo.value.status == 409
    assert excinfo.value.code == "replayed"


def test_a_stale_timestamp_is_rejected(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    body = b"{}"
    headers = headers_for(hydro, pk, sk, "POST", "/vote", body, timestamp=NOW - 3600)
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/vote",
            headers=headers, body=body, now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.code == "stale_timestamp"


def test_a_far_future_timestamp_is_rejected(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    body = b"{}"
    headers = headers_for(hydro, pk, sk, "POST", "/vote", body, timestamp=NOW + 3600)
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/vote",
            headers=headers, body=body, now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.code == "stale_timestamp"


@pytest.mark.parametrize(
    "drop", ["X-Tessera-Key", "X-Tessera-Sig", "X-Tessera-Ts", "X-Tessera-Nonce"]
)
def test_a_missing_header_is_rejected(hydro: Hydro, config: TesseraConfig, drop: str) -> None:
    pk, sk = hydro.keygen()
    headers = headers_for(hydro, pk, sk, "POST", "/vote", b"{}")
    del headers[drop]
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/vote",
            headers=headers, body=b"{}", now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.code == "malformed_signature"


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("X-Tessera-Key", "zz" * 32),
        ("X-Tessera-Key", "ab" * 31),
        ("X-Tessera-Sig", "ab" * 63),
        ("X-Tessera-Ts", "not-a-number"),
        ("X-Tessera-Nonce", "ab" * 4),
        ("X-Tessera-Nonce", "zz" * 16),
    ],
)
def test_malformed_header_values_are_rejected(
    hydro: Hydro, config: TesseraConfig, header: str, value: str
) -> None:
    pk, sk = hydro.keygen()
    headers = headers_for(hydro, pk, sk, "POST", "/vote", b"{}")
    headers[header] = value
    with pytest.raises(SignatureError) as excinfo:
        verify_signed_request(
            hydro=hydro, cfg=config, method="POST", path="/vote",
            headers=headers, body=b"{}", now=NOW, replay=MemoryReplay(),
        )
    assert excinfo.value.code == "malformed_signature"


def test_an_admin_key_is_flagged(hydro: Hydro, state_dir: Path, hydro_library_path: Path) -> None:
    pk, sk = hydro.keygen()
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_ADMIN_KEYS": pk.hex(),
    })
    headers = headers_for(hydro, pk, sk, "GET", "/admin/reports", b"")
    identity = verify_signed_request(
        hydro=hydro, cfg=cfg, method="GET", path="/admin/reports",
        headers=headers, body=b"", now=NOW, replay=MemoryReplay(),
    )
    assert identity.is_admin is True


def test_the_path_signed_includes_the_query_string(hydro: Hydro, config: TesseraConfig) -> None:
    pk, sk = hydro.keygen()
    headers = headers_for(hydro, pk, sk, "GET", "/admin/reports?state=open", b"")
    with pytest.raises(SignatureError):
        verify_signed_request(
            hydro=hydro, cfg=config, method="GET", path="/admin/reports?state=all",
            headers=headers, body=b"", now=NOW, replay=MemoryReplay(),
        )
