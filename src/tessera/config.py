"""Runtime configuration for the Tessera gallery server.

Precedence, lowest to highest: dataclass defaults, the TOML file, the
environment. The environment wins last so a systemd drop-in can override one
value without rewriting the file the provisioning script manages.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path

# Fixed by the spec. Not configurable: the client's report screen is built
# against exactly this list, and a server that accepted a seventh reason would
# be accepting something no client can produce.
REPORT_REASONS: tuple[str, ...] = ("gore", "sexual", "hate", "stolen", "spam", "other")

DEFAULT_CONFIG_PATH = Path("/etc/tessera/tessera.toml")


@dataclass(frozen=True)
class TesseraConfig:
    """Everything the daemon needs to run, resolved once at startup."""

    # --- network ---------------------------------------------------------
    # Loopback only. The playit agent is the sole thing facing the internet
    # and it forwards here locally; there is no reason to bind an address the
    # LAN could reach.
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    proxy_protocol: bool = False
    trusted_proxy_cidr: str = "127.0.0.0/8"

    # --- storage ---------------------------------------------------------
    state_dir: Path = Path("/var/lib/tessera")

    # --- signing ---------------------------------------------------------
    # libhydrogen contexts are exactly 8 bytes.
    sign_context: str = "tessera1"
    replay_window_secs: int = 300
    hydro_library: Path = Path("/opt/tessera/lib/libhydrogen.so")

    # --- limits ----------------------------------------------------------
    max_model_bytes: int = 1_048_576          # 1 MiB — a Tessera project file
    max_thumb_bytes: int = 65_536             # 64 KiB — a console-rendered thumb
    max_request_bytes: int = 2_097_152        # 2 MiB — whole-body ceiling
    max_total_disk_bytes: int = 2_147_483_648  # 2 GiB — blob store ceiling
    uploads_per_key_per_day: int = 8
    global_uploads_per_hour: int = 240
    ip_burst: int = 20
    ip_refill_secs: float = 3.0
    ip_slots: int = 512
    global_burst: int = 120
    global_refill_secs: float = 0.5
    browse_page_size: int = 20
    browse_max_page_size: int = 60

    # --- moderation ------------------------------------------------------
    report_autohide_threshold: int = 3
    admin_keys: tuple[str, ...] = ()

    report_reasons: tuple[str, ...] = field(default=REPORT_REASONS)

    @property
    def blob_dir(self) -> Path:
        return self.state_dir / "blobs"

    @property
    def db_path(self) -> Path:
        return self.state_dir / "tessera.db"


_PATH_FIELDS = {"state_dir", "hydro_library"}
_TUPLE_FIELDS = {"admin_keys"}


def _coerce(name: str, raw: object) -> object:
    """Turn a TOML or environment value into the dataclass field's type."""
    declared = {f.name: f.type for f in fields(TesseraConfig)}[name]

    if name in _PATH_FIELDS:
        return Path(str(raw)).expanduser()

    if name in _TUPLE_FIELDS:
        if isinstance(raw, str):
            items = [part for part in raw.replace(",", " ").split() if part]
        else:
            items = [str(part) for part in raw]  # type: ignore[union-attr]
        for item in items:
            if len(item) != 64 or any(c not in "0123456789abcdef" for c in item):
                raise ValueError(
                    f"admin_keys entry {item!r} is not 64 lowercase hex characters"
                )
        return tuple(items)

    if declared == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    if declared == "int":
        return int(str(raw))

    if declared == "float":
        return float(str(raw))

    return str(raw)


def load_config(
    path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> TesseraConfig:
    """Build a TesseraConfig from defaults, then `path`, then `env`.

    `path` of None means "use DEFAULT_CONFIG_PATH if it exists, otherwise pure
    defaults" — so the test suite and a fresh checkout both work with no file.
    """
    env = os.environ if env is None else env
    values: dict[str, object] = {}

    if path is None and DEFAULT_CONFIG_PATH.is_file():
        path = DEFAULT_CONFIG_PATH

    known = {f.name for f in fields(TesseraConfig)} - {"report_reasons"}

    if path is not None:
        with Path(path).open("rb") as handle:
            table = tomllib.load(handle)
        for key, raw in table.items():
            if key not in known:
                raise ValueError(f"unknown key {key!r} in {path}")
            values[key] = _coerce(key, raw)

    for key in known:
        env_key = "TESSERA_" + key.upper()
        if env_key in env:
            values[key] = _coerce(key, env[env_key])

    return TesseraConfig(**values)  # type: ignore[arg-type]
