"""The HTTP layer: connection handling, routing, and the limits that must be
applied before a single byte of body is read.

Deliberately built on `http.server.BaseHTTPRequestHandler` rather than
`SimpleHTTPRequestHandler`. The security caveat in the stdlib docs is about
the latter's static file serving — path traversal into the working directory.
Nothing here serves a file by name: every response body is either JSON this
module produced or bytes fetched from the content-addressed store by a
64-hex digest. There is no path from a request string to a filesystem path.

Ordering inside `_dispatch` is the security property worth reading twice:
  1. the request target is size-capped and parsed
  2. the route is resolved (404/405 before any work)
  3. the per-IP token bucket is charged
  4. Content-Length is validated against the ceiling, and only then is the
     body read
Reading the body first would let anyone make the daemon allocate megabytes for
a request that was going to be refused.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .config import TesseraConfig
from .db import connect, migrate
from .hydro import Hydro
from .proxyproto import ProxyProtocolError, read_ppv2_header
from .ratelimit import TokenBucketLimiter
from .replay import ReplayWindow
from .signing import SignatureError, SignedIdentity, verify_signed_request
from .store import BlobStore

MAX_REQUEST_LINE = 4096
MAX_HEADER_COUNT = 40


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = "application/json"
    headers: tuple[tuple[str, str], ...] = ()


def json_response(status: int, payload: dict[str, Any]) -> Response:
    return Response(status, json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def error(status: int, code: str, detail: str = "") -> Response:
    return json_response(status, {"error": code, "detail": detail or code})


@dataclass(frozen=True)
class RequestContext:
    method: str
    path: str
    raw_target: str
    query: dict[str, list[str]]
    body: bytes
    headers: Any
    client_ip: str
    identity: SignedIdentity | None = None


Handler = Callable[["TesseraApp", RequestContext, dict[str, str]], Response]

ROUTES: list[tuple[str, re.Pattern[str], Handler]] = []


def route(method: str, pattern: str) -> Callable[[Handler], Handler]:
    """Register a handler. `pattern` is a regex anchored at both ends."""

    def decorate(func: Handler) -> Handler:
        ROUTES.append((method, re.compile("^" + pattern + "$"), func))
        return func

    return decorate


def signed_route(method: str, pattern: str, *, admin: bool = False) -> Callable[[Handler], Handler]:
    """Register a route that only runs after the request signature verifies.

    Everything state-changing goes through here. The wrapper is where the
    identity is attached to the RequestContext, so a handler can never
    accidentally run without one: there is no code path into the handler that
    skips the verification, and `ctx.identity` is non-None by construction.

    `admin=True` additionally requires the key to be in cfg.admin_keys. The
    admin key is an ordinary console keypair that happens to be listed — there
    is no second mechanism (spec section 6).
    """

    def decorate(func: Handler) -> Handler:
        def wrapper(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
            try:
                identity = verify_signed_request(
                    hydro=app.hydro,
                    cfg=app.cfg,
                    method=ctx.method,
                    path=ctx.raw_target,
                    headers=ctx.headers,
                    body=ctx.body,
                    now=app.now(),
                    replay=app.replay,
                )
            except SignatureError as exc:
                return error(exc.status, exc.code, exc.detail)

            if admin and not identity.is_admin:
                return error(403, "not_admin", "this endpoint needs the admin key")

            return func(
                app,
                RequestContext(
                    method=ctx.method, path=ctx.path, raw_target=ctx.raw_target,
                    query=ctx.query, body=ctx.body, headers=ctx.headers,
                    client_ip=ctx.client_ip, identity=identity,
                ),
                params,
            )

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        ROUTES.append((method, re.compile("^" + pattern + "$"), wrapper))
        return func

    return decorate


@dataclass
class TesseraApp:
    """Holds `cfg`, `conn`, `store`, `hydro`, `replay`, `limiter`, `routes`.

    `conn` and `replay` are computed properties, not plain fields — see
    `_thread_state` below for why. Everything that reads `app.conn` or
    `app.replay` (this module's dispatcher, handlers_content.py, and every
    handler module later lanes add) sees exactly the documented shape; only
    the storage underneath is thread-local.
    """

    cfg: TesseraConfig
    store: BlobStore
    hydro: Hydro
    limiter: TokenBucketLimiter
    routes: list[tuple[str, re.Pattern[str], Handler]] = field(default_factory=lambda: ROUTES)
    _local: threading.local = field(default_factory=threading.local, init=False, repr=False)

    def now(self) -> int:
        return int(time.time())

    def _thread_state(self) -> threading.local:
        """One sqlite3.Connection, and the ReplayWindow wrapping it, per
        worker thread.

        ThreadingHTTPServer hands every accepted connection its own thread
        (daemon_threads=True), and every handler reaches the database through
        `app.conn` / `app.replay`. tessera.db.connect() opens with sqlite3's
        default check_same_thread=True — correct for Task 5's own
        single-threaded callers (tests, the CLI tools) — so a connection
        opened on one thread cannot be touched from another: sqlite3 raises
        "SQLite objects created in a thread can only be used in that same
        thread." Rather than relax that guard (which would mean trusting the
        underlying SQLite build's own thread-safety compile mode instead of
        Python's own check), each request thread gets its own connection.
        WAL — already turned on inside db.connect() — is exactly what makes
        many short-lived connections to the same file both safe and cheap:
        one writer at a time, readers never blocked behind it.
        """
        if getattr(self._local, "conn", None) is None:
            conn = connect(self.cfg.db_path)
            migrate(conn)
            replay = ReplayWindow(conn)
            replay.ensure_table()
            self._local.conn = conn
            self._local.replay = replay
        return self._local

    @property
    def conn(self) -> Any:
        return self._thread_state().conn

    @property
    def replay(self) -> ReplayWindow:
        return self._thread_state().replay


def build_app(cfg: TesseraConfig) -> TesseraApp:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    # Fail fast on a broken schema before the server ever starts listening,
    # on a throwaway connection closed immediately after.
    boot_conn = connect(cfg.db_path)
    migrate(boot_conn)
    boot_conn.close()
    hydro = Hydro(cfg.hydro_library)
    store = BlobStore(cfg.blob_dir, lambda data: hydro.hash32(data, cfg.sign_context))
    return TesseraApp(
        cfg=cfg,
        store=store,
        hydro=hydro,
        limiter=TokenBucketLimiter.from_config(cfg),
    )


class TesseraHandler(BaseHTTPRequestHandler):
    server_version = "tessera"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    app: TesseraApp  # set on the server instance, read through self.server

    # -- connection setup -------------------------------------------------

    def setup(self) -> None:
        super().setup()
        self._client_ip = self.client_address[0]
        app: TesseraApp = self.server.app  # type: ignore[attr-defined]
        if not app.cfg.proxy_protocol:
            return
        # The header is unauthenticated, so it is only honoured from a peer
        # inside the trusted CIDR. Outside it, the connection is closed rather
        # than served with the socket's own address, because serving it would
        # teach a client that omitting the header works.
        peer = ip_address(self.client_address[0])
        if peer not in ip_network(app.cfg.trusted_proxy_cidr):
            self._refuse(400, "bad_proxy_header", "proxy header required from an untrusted peer")
            return
        try:
            self._client_ip, _ = read_ppv2_header(self.rfile)
        except ProxyProtocolError as exc:
            self._refuse(400, "bad_proxy_header", f"bad PROXY protocol header: {exc}")

    def _refuse(self, status: int, code: str, detail: str) -> None:
        """Write a raw HTTP error response directly, bypassing `_send`.

        Used from two places that both run before the ordinary per-request
        machinery is reachable: `setup()`, when the PROXY protocol header
        itself is bad, and `parse_request()` below, when the request line
        never parsed at all — in neither case does `self.command` exist yet,
        which `_send` depends on.
        """
        try:
            reason = {
                400: "Bad Request", 411: "Length Required", 413: "Payload Too Large",
            }.get(status, "Error")
            body = json.dumps({"error": code, "detail": detail}).encode()
            self.wfile.write(
                f"HTTP/1.1 {status} {reason}\r\n".encode()
                + b"Content-Type: application/json\r\n"
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                + b"Connection: close\r\n\r\n" + body
            )
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True

    def parse_request(self) -> bool:
        """As BaseHTTPRequestHandler, but a blank first line gets a loud 400.

        The stdlib treats a wholly empty request line as a harmless
        keep-alive artefact and closes without responding at all — see
        `http.server.BaseHTTPRequestHandler.parse_request`, the `if not
        words:` branch, which returns False with no `send_error` call.
        That silence is indistinguishable from a PROXY protocol v2 header
        landing unparsed in the HTTP stream because `proxy_protocol` is off:
        the signature's first two bytes are `\\r\\n`, which reads back as
        exactly one blank line. Silently dropping that connection is the
        outcome the CRITICAL constraint on this task rules out (a v1/misrouted
        header must be refused loudly, never mishandled quietly) — a
        misconfigured tunnel or a probe both deserve a 400, not a hang-up.
        """
        if self.raw_requestline.strip() == b"":
            self._refuse(400, "bad_request", "empty or unparseable request line")
            return False
        return super().parse_request()

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        # One line per request, to stdout, so journalctl has it. No user
        # strings are interpolated beyond the request line the base class
        # already escapes.
        print(f"{self._client_ip} {fmt % args}", flush=True)

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)
        self.close_connection = True

    # -- dispatch ---------------------------------------------------------
    #
    # Ordering, and why it is not "route first, then everything else":
    #   1. the request target is size-capped and parsed
    #   2. for POST/PUT/PATCH, Content-Length is validated against the
    #      ceiling — a malformed or oversized declared length is refused
    #      here, for EVERY such request, whether or not its path is one this
    #      build of the daemon has a handler for. A byte ceiling is protocol
    #      hygiene, not a property of any one route, so it must not depend on
    #      whether a route table entry happens to exist yet.
    #   3. the route is resolved (404/405)
    #   4. the per-IP token bucket is charged
    #   5. only now is the body actually read off the socket
    # Step 2 only inspects the header — it never calls self.rfile.read().
    # Reading the body before routing/rate-limiting have both accepted the
    # request would let anyone make the daemon allocate for a request that
    # was going to be refused anyway; checking the ceiling before routing
    # does not, because no bytes are consumed until step 5.

    def _dispatch(self) -> None:
        app: TesseraApp = self.server.app  # type: ignore[attr-defined]

        if len(self.path) > MAX_REQUEST_LINE:
            self._send(error(414, "uri_too_long"))
            return

        split = urlsplit(self.path)
        path = split.path
        query = parse_qs(split.query, keep_blank_values=True)

        length = 0
        if self.command in {"POST", "PUT", "PATCH"}:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._send(error(411, "length_required"))
                return
            try:
                length = int(raw_length)
            except ValueError:
                self._send(error(400, "bad_content_length"))
                return
            if length < 0 or length > app.cfg.max_request_bytes:
                self._send(
                    error(413, "too_large", f"the body ceiling is {app.cfg.max_request_bytes}")
                )
                return

        matched: tuple[Handler, dict[str, str]] | None = None
        path_exists = False
        for method, pattern, handler in app.routes:
            match = pattern.match(path)
            if match is None:
                continue
            path_exists = True
            if method == self.command:
                matched = (handler, match.groupdict())
                break

        if matched is None:
            self._send(
                error(405, "method_not_allowed") if path_exists else error(404, "not_found")
            )
            return

        if not app.limiter.allow(self._client_ip, time.monotonic()):
            self._send(error(429, "rate_limited", "slow down"))
            return

        body = b""
        if self.command in {"POST", "PUT", "PATCH"}:
            body = self.rfile.read(length)
            if len(body) != length:
                self._send(error(400, "short_body"))
                return

        context = RequestContext(
            method=self.command,
            path=path,
            raw_target=self.path,
            query=query,
            body=body,
            headers=self.headers,
            client_ip=self._client_ip,
        )
        handler, params = matched
        try:
            self._send(handler(app, context, params))
        except Exception as exc:  # noqa: BLE001 - a handler bug must not leak a traceback
            print(f"handler error on {self.command} {path}: {exc!r}", flush=True)
            self._send(error(500, "internal_error"))

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()


class TesseraServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # Bounded so a flood cannot spawn threads without limit. TasksMax in the
    # unit file is the second half of this; this is the half that answers
    # rather than being killed.
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], app: TesseraApp) -> None:
        self.app = app
        super().__init__(address, TesseraHandler)

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


def make_server(app: TesseraApp) -> TesseraServer:
    # Importing the handler modules is what populates ROUTES. Done here, at
    # the one place a server is constructed, so no module has to be imported
    # for its side effects anywhere else.
    from . import handlers_admin, handlers_content, handlers_social  # noqa: F401

    return TesseraServer((app.cfg.listen_host, app.cfg.listen_port), app)
