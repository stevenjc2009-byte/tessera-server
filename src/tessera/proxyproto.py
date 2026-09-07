"""HAProxy PROXY protocol v2, the TCP/stream variant.

The playit relay forwards every console's traffic from its own local socket,
so without this the daemon would see one source address for everybody: the
per-IP rate limiter would collapse into a single shared bucket and stop being
a limiter at all.

Blocksmith parses the same header per datagram because its transport is UDP.
Here it appears exactly once, at the very front of the TCP connection, before
the first byte of the HTTP request line — so it is consumed in the connection
handler's setup, and everything above this layer sees an ordinary HTTP stream.

Trust boundary: this header is UNAUTHENTICATED. Anything that can connect can
claim any source address. It is only safe because the daemon binds loopback
and `--proxy-protocol` is refused for peers outside `--trusted-proxy`. The
parser itself assumes nothing and validates everything.

v1 (the text form) is deliberately unsupported: playit ignores v1, so a v1
header can never legitimately arrive and supporting it would only add surface.
"""

from __future__ import annotations

import ipaddress
from typing import BinaryIO

PPV2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PPV2_HDR_BYTES = 16   # 12 signature + 1 ver/cmd + 1 fam/proto + 2 length
PPV2_INET_BYTES = 12  # src addr 4, dst addr 4, src port 2, dst port 2

_VER_CMD_PROXY = 0x21   # version 2, command PROXY
_FAM_INET_STREAM = 0x11  # AF_INET, SOCK_STREAM
_MAX_ADDR_BLOCK = 536    # generous TLV allowance; anything larger is nonsense


class ProxyProtocolError(Exception):
    """The bytes at the front of the connection are not a usable v2 header."""


def _read_exactly(rfile: BinaryIO, count: int) -> bytes:
    chunk = rfile.read(count)
    if chunk is None or len(chunk) != count:
        got = 0 if chunk is None else len(chunk)
        raise ProxyProtocolError(f"truncated header: wanted {count} bytes, got {got}")
    return chunk


def read_ppv2_header(rfile: BinaryIO) -> tuple[str, int]:
    """Consume one v2 header and return the real (client_ip, client_port).

    On return the stream is positioned at the first byte after the header, so
    the caller can hand it straight to an HTTP parser. On any problem this
    raises and the caller MUST drop the connection — there is no partial
    success and no fallback to the socket's own peer address, because falling
    back is exactly how a spoofed header would get itself trusted.
    """
    header = _read_exactly(rfile, PPV2_HDR_BYTES)

    if header[:12] != PPV2_SIGNATURE:
        raise ProxyProtocolError("bad PROXY protocol v2 signature")

    ver_cmd = header[12]
    if ver_cmd >> 4 != 0x2:
        raise ProxyProtocolError(f"unsupported PROXY protocol version {ver_cmd >> 4}")
    if ver_cmd != _VER_CMD_PROXY:
        raise ProxyProtocolError(f"unsupported PROXY command {ver_cmd & 0x0F:#x}")

    if header[13] != _FAM_INET_STREAM:
        raise ProxyProtocolError(
            f"unsupported address family/protocol {header[13]:#x}; only AF_INET/STREAM"
        )

    length = int.from_bytes(header[14:16], "big")
    if length < PPV2_INET_BYTES or length > _MAX_ADDR_BLOCK:
        raise ProxyProtocolError(f"implausible address-block length {length}")

    block = _read_exactly(rfile, length)
    src_ip = str(ipaddress.IPv4Address(block[0:4]))
    src_port = int.from_bytes(block[8:10], "big")
    # block[4:8] is the destination address and block[10:12] the destination
    # port; both are the tunnel's own local socket and tell us nothing. Any
    # remaining bytes are TLVs — consumed above, never interpreted.
    return src_ip, src_port


def build_ppv2_header(
    src_ip: str, src_port: int, dst_ip: str = "127.0.0.1", dst_port: int = 8080
) -> bytes:
    """Construct a valid v2 header. For tests and for `tessera-probe` only."""
    body = (
        ipaddress.IPv4Address(src_ip).packed
        + ipaddress.IPv4Address(dst_ip).packed
        + src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
    )
    return (
        PPV2_SIGNATURE
        + bytes([_VER_CMD_PROXY, _FAM_INET_STREAM])
        + len(body).to_bytes(2, "big")
        + body
    )
