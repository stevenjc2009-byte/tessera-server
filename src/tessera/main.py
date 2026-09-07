"""Entrypoint: `python3 -m tessera.main --config /etc/tessera/tessera.toml`."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path
from types import FrameType

from .config import load_config
from .http_server import build_app, make_server


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="tessera", description="Tessera gallery server")
    parser.add_argument("--config", type=Path, default=None,
                        help="path to tessera.toml (default: /etc/tessera/tessera.toml)")
    parser.add_argument("--print-config", action="store_true",
                        help="resolve the configuration, print it, and exit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config(args.config)

    if args.print_config:
        for name in sorted(vars(cfg)):
            print(f"{name} = {getattr(cfg, name)!r}")
        return 0

    app = build_app(cfg)
    server = make_server(app)

    def shutdown(signum: int, _frame: FrameType | None) -> None:
        # BaseServer.shutdown() blocks until serve_forever's loop acknowledges
        # it. A Python signal handler runs on the main thread — the same thread
        # that is inside serve_forever — so calling it here waits for a loop
        # that cannot make progress until the handler returns: a deadlock. The
        # daemon logged this line and then hung until SIGKILL, which under
        # `Restart=on-failure` costs TimeoutStopSec (90s, the default, since
        # the unit does not set it) on every single stop and restart.
        #
        # So the blocking call goes on a thread of its own and the handler
        # returns immediately; serve_forever then unwinds into the finally
        # below. The alternative — a flag the main loop checks — would mean
        # replacing serve_forever with a hand-written handle_request loop,
        # which is a larger change than the bug warrants.
        print(f"received signal {signum}, shutting down", flush=True)
        threading.Thread(target=server.shutdown, name="tessera-shutdown",
                         daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    host, port = server.server_address[0], server.server_address[1]
    print(f"tessera listening on {host}:{port} "
          f"(proxy_protocol={cfg.proxy_protocol}, state={cfg.state_dir})", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        app.conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
