from pathlib import Path

import pytest

from tessera.hydro import (
    CONTEXTBYTES,
    HASH_BYTES,
    SIGN_BYTES,
    SIGN_PUBLICKEYBYTES,
    SIGN_SECRETKEYBYTES,
    Hydro,
    HydroError,
)

CTX = "tessera1"


@pytest.fixture
def hydro(hydro_library_path: Path) -> Hydro:
    return Hydro(hydro_library_path)


def test_constants_match_the_c_header() -> None:
    assert (SIGN_BYTES, SIGN_PUBLICKEYBYTES, SIGN_SECRETKEYBYTES) == (64, 32, 64)
    assert (CONTEXTBYTES, HASH_BYTES) == (8, 32)


def test_keygen_returns_correctly_sized_keys(hydro: Hydro) -> None:
    pk, sk = hydro.keygen()
    assert len(pk) == SIGN_PUBLICKEYBYTES
    assert len(sk) == SIGN_SECRETKEYBYTES
    other_pk, _ = hydro.keygen()
    assert pk != other_pk


def test_a_real_signature_verifies(hydro: Hydro) -> None:
    pk, sk = hydro.keygen()
    message = b"POST\n/upload\n1757260800\ndeadbeef"
    sig = hydro.sign_create(message, CTX, sk)
    assert len(sig) == SIGN_BYTES
    assert hydro.sign_verify(sig, message, CTX, pk) is True


def test_a_flipped_signature_byte_fails(hydro: Hydro) -> None:
    pk, sk = hydro.keygen()
    message = b"POST\n/upload\n1757260800\ndeadbeef"
    sig = bytearray(hydro.sign_create(message, CTX, sk))
    sig[0] ^= 0x01
    assert hydro.sign_verify(bytes(sig), message, CTX, pk) is False


def test_a_changed_message_fails(hydro: Hydro) -> None:
    pk, sk = hydro.keygen()
    sig = hydro.sign_create(b"POST\n/vote\n1\nabc", CTX, sk)
    assert hydro.sign_verify(sig, b"POST\n/vote\n1\nabd", CTX, pk) is False


def test_a_different_key_fails(hydro: Hydro) -> None:
    _, sk = hydro.keygen()
    other_pk, _ = hydro.keygen()
    sig = hydro.sign_create(b"hello", CTX, sk)
    assert hydro.sign_verify(sig, b"hello", CTX, other_pk) is False


def test_a_different_context_fails(hydro: Hydro) -> None:
    pk, sk = hydro.keygen()
    sig = hydro.sign_create(b"hello", CTX, sk)
    assert hydro.sign_verify(sig, b"hello", "tessera2", pk) is False


def test_hash_is_32_bytes_and_deterministic(hydro: Hydro) -> None:
    first = hydro.hash32(b"some project bytes", CTX)
    second = hydro.hash32(b"some project bytes", CTX)
    assert first == second
    assert len(first) == HASH_BYTES
    assert hydro.hash32(b"other bytes", CTX) != first


def test_wrong_sized_arguments_raise_rather_than_reading_past_the_buffer(hydro: Hydro) -> None:
    pk, sk = hydro.keygen()
    with pytest.raises(HydroError, match="signature"):
        hydro.sign_verify(b"\x00" * 63, b"m", CTX, pk)
    with pytest.raises(HydroError, match="public key"):
        hydro.sign_verify(b"\x00" * 64, b"m", CTX, b"\x00" * 31)
    with pytest.raises(HydroError, match="secret key"):
        hydro.sign_create(b"m", CTX, b"\x00" * 63)
    with pytest.raises(HydroError, match="context"):
        hydro.sign_create(b"m", "short", sk)


def test_a_missing_library_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(HydroError, match="could not load"):
        Hydro(tmp_path / "nope.so")
