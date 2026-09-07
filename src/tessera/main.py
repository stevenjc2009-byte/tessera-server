"""Entrypoint: `python3 -m tessera.main --config /etc/tessera/tessera.toml`."""

from __future__ import annotations

import argparse
import signal
import sys
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
        print(f"received signal {signum}, shutting down", flush=True)
        server.shutdown()

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
