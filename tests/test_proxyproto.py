from __future__ import annotations

import io

import pytest

from tessera.proxyproto import (
    PPV2_SIGNATURE,
    ProxyProtocolError,
    build_ppv2_header,
    read_ppv2_header,
)


def test_a_well_formed_header_yields_the_real_client_address() -> None:
    raw = build_ppv2_header("203.0.113.9", 51234) + b"GET /browse HTTP/1.1\r\n\r\n"
    stream = io.BytesIO(raw)
    assert read_ppv2_header(stream) == ("203.0.113.9", 51234)
    assert stream.read() == b"GET /browse HTTP/1.1\r\n\r\n"


def test_v1_the_text_form_is_refused() -> None:
    # playit silently drops v1, so a v1 header can never legitimately arrive.
    # Accepting it would only add parser surface.
    stream = io.BytesIO(b"PROXY TCP4 203.0.113.9 10.0.0.1 51234 8080\r\nGET / HTTP/1.1\r\n")
    with pytest.raises(ProxyProtocolError, match="signature"):
        read_ppv2_header(stream)


def test_a_bad_signature_is_refused() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[3] ^= 0xFF
    with pytest.raises(ProxyProtocolError, match="signature"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_a_truncated_header_is_refused() -> None:
    raw = build_ppv2_header("203.0.113.9", 1)[:20]
    with pytest.raises(ProxyProtocolError, match="truncated"):
        read_ppv2_header(io.BytesIO(raw))


def test_an_empty_stream_is_refused() -> None:
    with pytest.raises(ProxyProtocolError, match="truncated"):
        read_ppv2_header(io.BytesIO(b""))


def test_the_local_command_is_refused() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[12] = 0x20  # version 2, command LOCAL
    with pytest.raises(ProxyProtocolError, match="command"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_a_wrong_version_nibble_is_refused() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[12] = 0x11  # version 1, command PROXY
    with pytest.raises(ProxyProtocolError, match="version"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_a_non_ipv4_family_is_refused() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[13] = 0x21  # AF_INET6 / STREAM
    with pytest.raises(ProxyProtocolError, match="family"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_a_udp_transport_is_refused() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[13] = 0x12  # AF_INET / DGRAM — this is an HTTP server
    with pytest.raises(ProxyProtocolError, match="family"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_an_absurd_length_is_refused_without_allocating() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[14:16] = (65535).to_bytes(2, "big")
    with pytest.raises(ProxyProtocolError, match="length"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_a_short_length_is_refused() -> None:
    raw = bytearray(build_ppv2_header("203.0.113.9", 1))
    raw[14:16] = (4).to_bytes(2, "big")
    with pytest.raises(ProxyProtocolError, match="length"):
        read_ppv2_header(io.BytesIO(bytes(raw)))


def test_trailing_tlvs_are_skipped_not_parsed() -> None:
    # A v2 header may carry TLVs after the address block. We do not need any
    # of them, so they are consumed and discarded — never interpreted.
    base = bytearray(build_ppv2_header("198.51.100.4", 9999))
    tlv = b"\x03\x00\x04\xde\xad\xbe\xef"  # PP2_TYPE_CRC32C, 4 bytes
    base[14:16] = (12 + len(tlv)).to_bytes(2, "big")
    stream = io.BytesIO(bytes(base) + tlv + b"GET / HTTP/1.1\r\n")
    assert read_ppv2_header(stream) == ("198.51.100.4", 9999)
    assert stream.read() == b"GET / HTTP/1.1\r\n"


def test_the_signature_constant_is_the_documented_one() -> None:
    assert PPV2_SIGNATURE == b"\r\n\r\n\x00\r\nQUIT\n"
    assert len(PPV2_SIGNATURE) == 12
