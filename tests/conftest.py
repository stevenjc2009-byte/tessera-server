"""Fixtures shared by every Tessera test module."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tessera.config import TesseraConfig, load_config

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILT_HYDRO_SO = REPO_ROOT / "build" / "libhydrogen.so"


@pytest.fixture(scope="session")
def hydro_library_path() -> Path:
    """Path to the libhydrogen.so the suite runs against.

    `make test` exports TESSERA_HYDRO_LIBRARY; running pytest by hand falls
    back to the in-tree build. Either way this fails loudly rather than
    silently skipping — a suite that quietly stops exercising the signature
    code is worse than one that will not start.
    """
    override = os.environ.get("TESSERA_HYDRO_LIBRARY")
    path = Path(override) if override else BUILT_HYDRO_SO
    if not path.is_file():
        raise RuntimeError(
            f"libhydrogen.so not found at {path}. Run `make build` first "
            "(needs gcc and Linux; on Windows use WSL)."
        )
    return path


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "state"
    (directory / "blobs").mkdir(parents=True)
    return directory


@pytest.fixture
def config(state_dir: Path, hydro_library_path: Path) -> TesseraConfig:
    return load_config(
        None,
        {
            "TESSERA_STATE_DIR": str(state_dir),
            "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
            "TESSERA_LISTEN_PORT": "0",
        },
    )


@pytest.fixture
def repo_root() -> Iterator[Path]:
    yield REPO_ROOT


import http.client
import json as _json
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

from tessera.hydro import Hydro
from tessera.proxyproto import build_ppv2_header
from tessera.signing import canonical_message


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class LiveServer:
    process: subprocess.Popen
    port: int
    config: TesseraConfig
    config_path: Path

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def _write_config(path: Path, values: dict[str, object]) -> None:
    lines = []
    for key, value in values.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, (int, float)):
            lines.append(f"{key} = {value}")
        elif isinstance(value, (list, tuple)):
            inner = ", ".join(f'"{item}"' for item in value)
            lines.append(f"{key} = [{inner}]")
        else:
            lines.append(f'{key} = "{value}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _start(tmp_path: Path, state_dir: Path, hydro_so: Path, overrides: dict) -> LiveServer:
    """Start the REAL daemon as a subprocess and wait for it to answer.

    Deliberately a subprocess, not an in-process handler: the point of these
    tests is that the shipped entrypoint, argument parsing, socket setup and
    connection handling all work, and an in-process object proves none of that.
    """
    port = _free_port()
    values: dict[str, object] = {
        "state_dir": state_dir.as_posix(),
        "hydro_library": hydro_so.as_posix(),
        "listen_host": "127.0.0.1",
        "listen_port": port,
    }
    values.update(overrides)
    config_path = tmp_path / "tessera.toml"
    _write_config(config_path, values)

    process = subprocess.Popen(
        [sys.executable, "-m", "tessera.main", "--config", str(config_path)],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited early:\n{process.stdout.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.05)
    else:
        process.kill()
        raise RuntimeError("daemon never accepted a connection")

    cfg = load_config(config_path, {})
    return LiveServer(process=process, port=port, config=cfg, config_path=config_path)


class Client:
    """Speaks HTTP at a LiveServer, and can sign requests like a console."""

    def __init__(self, server: LiveServer, hydro: Hydro, use_ppv2: bool) -> None:
        self.server = server
        self.hydro = hydro
        self.config = server.config
        self.config_path = server.config_path
        self.use_ppv2 = use_ppv2
        self._nonce = 0

    # -- low level --------------------------------------------------------

    def raw_request(self, payload: bytes, *, with_ppv2: bool | None = None,
                    src_ip: str = "203.0.113.9",
                    expect_early_close: bool = False) -> tuple[int, dict[str, str], bytes]:
        prefix = b""
        want = self.use_ppv2 if with_ppv2 is None else with_ppv2
        if want:
            prefix = build_ppv2_header(src_ip, 40000, "127.0.0.1", self.server.port)
        full = prefix + payload
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=10) as sock:
            if expect_early_close:
                # A server that refuses on the Content-Length alone (413, for
                # instance) answers and closes before the whole oversized body
                # has left the client's socket buffer — that is the entire
                # point of the "not read" half of this test. Sending in small
                # chunks and swallowing the pipe error once the peer hangs up
                # lets the response below still be read; a bare `sendall` of
                # the whole payload just raises BrokenPipeError/ConnectionReset
                # instead, which proves nothing about what the server did.
                try:
                    view = memoryview(full)
                    chunk_size = 65536
                    for offset in range(0, len(view), chunk_size):
                        sock.sendall(view[offset:offset + chunk_size])
                except (BrokenPipeError, ConnectionResetError):
                    pass
                else:
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            else:
                sock.sendall(full)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except (ConnectionResetError, OSError):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw:
            return 0, {}, b""
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
        return status, headers, body

    def request(self, method: str, target: str, body: bytes = b"", *,
                headers: dict[str, str] | None = None, src_ip: str = "203.0.113.9",
                expect_early_close: bool = False) -> tuple[int, dict[str, str], bytes]:
        lines = [f"{method} {target} HTTP/1.1", "Host: tessera.test", "Connection: close",
                 f"Content-Length: {len(body)}"]
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
        return self.raw_request(payload, src_ip=src_ip, expect_early_close=expect_early_close)

    def get(self, target: str, *, src_ip: str = "203.0.113.9",
            headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        return self.request("GET", target, b"", headers=headers, src_ip=src_ip)

    # -- signing ----------------------------------------------------------

    def keypair(self) -> tuple[bytes, bytes]:
        return self.hydro.keygen()

    def sign_headers(self, method: str, target: str, body: bytes, pk: bytes, sk: bytes,
                     *, timestamp: int | None = None,
                     nonce_hex: str | None = None) -> dict[str, str]:
        self._nonce += 1
        nonce = nonce_hex or f"{self._nonce:032x}"
        ts = int(time.time()) if timestamp is None else timestamp
        digest = self.hydro.hash32(body, self.config.sign_context).hex()
        message = canonical_message(method, target, ts, nonce, digest)
        return {
            "X-Tessera-Key": pk.hex(),
            "X-Tessera-Sig": self.hydro.sign_create(message, self.config.sign_context, sk).hex(),
            "X-Tessera-Ts": str(ts),
            "X-Tessera-Nonce": nonce,
        }

    def signed(self, method: str, target: str, body: bytes, pk: bytes, sk: bytes,
               *, src_ip: str = "203.0.113.9", **sign_kwargs):
        headers = self.sign_headers(method, target, body, pk, sk, **sign_kwargs)
        return self.request(method, target, body, headers=headers, src_ip=src_ip)

    def signed_json(self, method: str, target: str, payload: dict, pk: bytes, sk: bytes, **kw):
        body = _json.dumps(payload, separators=(",", ":")).encode("utf-8")
        status, headers, raw = self.signed(method, target, body, pk, sk, **kw)
        parsed = _json.loads(raw) if raw else {}
        return status, headers, parsed


@pytest.fixture
def live_server(tmp_path: Path, state_dir: Path, hydro_library_path: Path):
    server = _start(tmp_path, state_dir, hydro_library_path, {})
    yield server
    server.stop()


@pytest.fixture
def client(live_server: LiveServer, hydro_library_path: Path) -> Client:
    return Client(live_server, Hydro(hydro_library_path), use_ppv2=False)


@pytest.fixture
def pp_client(tmp_path: Path, state_dir: Path, hydro_library_path: Path):
    server = _start(tmp_path, state_dir, hydro_library_path,
                    {"proxy_protocol": True, "trusted_proxy_cidr": "127.0.0.0/8"})
    yield Client(server, Hydro(hydro_library_path), use_ppv2=True)
    server.stop()


@pytest.fixture
def threshold_two_client(tmp_path: Path, state_dir: Path, hydro_library_path: Path):
    """A second live server with report_autohide_threshold = 2.

    A separate server rather than an edit to the shared one: the threshold is
    read at start-up, so mutating the shared fixture's config would leak into
    whatever test runs next.
    """
    server = _start(tmp_path, state_dir, hydro_library_path, {"report_autohide_threshold": 2})
    yield Client(server, Hydro(hydro_library_path), use_ppv2=False)
    server.stop()


@pytest.fixture
def admin_client(tmp_path: Path, state_dir: Path, hydro_library_path: Path):
    """A live server that already trusts one admin key. Yields (client, pk, sk)."""
    hydro = Hydro(hydro_library_path)
    pk, sk = hydro.keygen()
    server = _start(tmp_path, state_dir, hydro_library_path, {"admin_keys": [pk.hex()]})
    yield Client(server, hydro, use_ppv2=False), pk, sk
    server.stop()
