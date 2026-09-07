# Tessera Gallery Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Tessera public gallery server — a single small HTTP daemon backed by SQLite and content-addressed files on disk, deployed into a hardened unprivileged Proxmox LXC that has no route to the home network.

**Architecture:** One Python 3.11+ daemon (`tessera`) using only the standard library, plus a `ctypes` binding to a locally built `libhydrogen.so` pinned at commit `617036a353cd4f6478ab6c3f98c36dd31e23ce8e`. Every state-changing request is signed by the console's libhydrogen keypair over plain HTTP (the 3DS `ssl:C` cannot speak modern TLS); a nonce plus timestamp are checked against a sliding replay window held in SQLite. Uploads are stored opaquely by content hash and the server never decodes an image. Deployment copies Blocksmith's proven two-script LXC pattern but tightens egress: no blanket root accept, and explicit RFC1918 destination drops.

**Tech Stack:** Python 3.11+ (stdlib only: `http.server`, `socketserver`, `sqlite3`, `ctypes`, `tomllib`, `dataclasses`, `pathlib`), libhydrogen (C, pinned commit, built to a shared object with gcc), pytest (from Debian's `python3-pytest`), nftables, systemd, Proxmox `pct`/`pveam`/`pvesm`, playit.gg agent, GNU make as the task runner.

---

## Language choice — decided, with what was rejected

**Chosen: Python 3.11+, standard library only, plus a `ctypes` binding to a gcc-built `libhydrogen.so`.**

The reasoning, against the three stated constraints (builds and self-tests inside a Debian LXC from source with minimal dependencies; the install script refuses to install if tests fail; memory safety matters because this parses hostile input from the public internet):

- **Memory safety where the hostile bytes land.** Every byte an attacker controls — the request line, headers, the upload envelope, JSON bodies, query strings — is handled in Python, which cannot be made to corrupt memory by a malformed length field. The only native code in the request path is `hydro_sign_verify` / `hydro_hash_hash`, which are handed fixed-size buffers (64-byte signature, 32-byte key, 8-byte context) plus one length-carrying message pointer. The spec names memory-unsafe parsing of hostile input as by a wide margin the most likely way in (§5.6); this puts an entire language boundary between the attacker and the C.
- **Zero dependencies outside the Debian mirror.** `sqlite3`, `tomllib`, `hashlib`, `http.server` and `ctypes` are all stdlib. The only non-apt fetch in the whole build is the pinned libhydrogen git checkout — exactly the same single outbound build dependency Blocksmith already has. This matters more than it looks: the output firewall (Task 23) removes Blocksmith's blanket `meta skuid root accept`, so anything the self-updater needs to fetch at update time has to be individually permitted. A stdlib-only service needs nothing permitted beyond git-over-HTTPS to GitHub and apt.
- **`install-check` still has something real to check.** There is no PIE/RELRO/NX on a script, so the hardening gate moves to (a) the same three `readelf` checks applied to `libhydrogen.so`, (b) an assertion that the vendored libhydrogen HEAD is exactly the pinned commit, and (c) `systemd-analyze security` on the installed unit. That is a stronger gate for this service than Blocksmith's, because the sandbox is what actually contains a Python daemon.

**Rejected — C11 (Blocksmith's own choice).** It is the reference implementation and it would reuse `replay.c`, `ratelimit.c` and `proxyproto.c` almost verbatim. It was rejected because Blocksmith parses a small, fixed-layout binary protocol from an allowlisted peer, whereas Tessera must parse HTTP request lines, headers, query strings and a multi-field upload envelope from anyone on the internet with no allowlist at all. Hand-writing that parser in C is precisely the risk §5.6 of the spec exists to eliminate.

**Rejected — Rust.** Memory-safe and otherwise an excellent fit. Rejected on the dependency constraint: an HTTP+SQLite service in Rust means crates from crates.io at build time (`rusqlite` alone bundles a full SQLite C build), which is a second registry to reach both during provisioning and during every `ts-update` run under a narrowed egress policy. `cargo vendor` fixes the network problem by committing megabytes of third-party code into a repo whose entire selling point is being small enough for one person to read. Debian's packaged `rustc` also trails, and compiling a crate graph on a 1-core / 512 MB container is slow enough to make the install feel broken.

**Rejected — Go.** Same shape of objection as Rust. `net/http` is genuinely the best-hardened HTTP server of the three options, but SQLite means either cgo (`mattn/go-sqlite3`) or `modernc.org/sqlite`, a machine-translated codebase far larger than everything else in this repo combined. `go mod vendor` has the same repo-bloat cost as `cargo vendor`, and libhydrogen still has to be reached over cgo regardless, so the "single static binary, no C" advantage does not actually survive contact with the signing requirement.

**Honest cost of the Python choice, stated up front:** it is slower per request and it makes CPU exhaustion a cheaper attack than it would be in C, Rust or Go. That is answered by the per-IP token bucket (Task 9), the global rate cap (Task 7), and hard byte ceilings enforced *before* any body is read (Task 10) — not by hoping the traffic stays small. It also makes `MemoryDenyWriteExecute=yes` a thing that must be *measured* rather than assumed, because libffi closures want executable pages; Task 22 measures it and records the result either way.

---

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from `docs/superpowers/specs/2026-09-07-tessera-design.md`.

- **Repo:** `stevenjc2009-byte/tessera-server`, public, remote `https://github.com/stevenjc2009-byte/tessera-server`. Working copy: `C:\Users\steve\Documents\3ds-project-folder\tessera\deps\tessera-server`.
- **Commits authored as** `final_destiny63 <stevenjc2009@gmail.com>` (already set in this checkout's git config — do not pass `--author`).
- **Commit messages:** Conventional Commits — `type(scope): summary`, types `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `build`, `ci`.
- **libhydrogen is pinned at commit `617036a353cd4f6478ab6c3f98c36dd31e23ce8e`.** Same pin as Blocksmith, on both sides of the wire. Never bump it without changing the client at the same time.
- **Transport is plain HTTP.** Not TLS. The 3DS `ssl:C` tops out at TLS 1.1. Every state-changing request is signed with libhydrogen and carries a nonce and a timestamp checked against a sliding replay window.
- **The server never decodes an uploaded image.** No image library may be imported anywhere in `src/tessera/`. The console renders and uploads its own thumbnail; the server stores and returns opaque bytes.
- **Uploads are stored by content hash, never by a user-supplied filename.**
- **Report reasons are exactly:** `gore`, `sexual`, `hate`, `stolen`, `spam`, `other`. Only `other` carries free text.
- **3 distinct reporter keys auto-unlists a model** pending review. This is a config value (`report_autohide_threshold`), not a constant.
- **Moderation delivery is pull-based with zero egress.** No webhook, no email, no push. The daemon never initiates an outbound connection.
- **Hearts and thumbs are separate systems and are named as such.** Hearts are private, unlimited favourites. Thumbs are public, one per key, aggregating into a score.
- **8 uploads per key per day** (`uploads_per_key_per_day`).
- **Per-IP rate limiting via `proxy-protocol-v2`.** Version 1 is silently dropped by the playit agent — never accept v1.
- **A global upload rate cap, plus hard caps on upload size and total disk.**
- **nftables default-drop on input *and* output.** No `meta skuid root accept` in the output chain. Explicit RFC1918 destination drops for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Zero inbound ports.** The daemon binds loopback only; playit.gg dials out.
- **Unprivileged LXC, `nesting=0`, no device passthrough.**
- **Systemd sandbox:** empty `CapabilityBoundingSet`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `ProtectProc=invisible`, `SystemCallFilter=@system-service` minus `@privileged @resources @obsolete @mount @debug @cpu-emulation @swap`, `MemoryMax`, `TasksMax`, `LimitNOFILE`.
- **The install refuses to install if the test suite or the hardening check fails.**
- **`getent hosts deb.debian.org` must succeed before apt is touched.** `apt-get update` exits 0 even when every mirror is unreachable.
- **One-line invocation is pinned to a tag, never `main`:** `bash -c "$(curl -fsSL https://raw.githubusercontent.com/stevenjc2009-byte/tessera-server/v1.0.0/install/proxmox-install.sh)"`.
- **Release convention:** a `v<version>` branch plus annotated tag plus a published GitHub Release, branched off the previous tag tip, never merged to `main`.
- **Python style:** PEP 8, type hints on public functions, `dataclasses` for structured data, `pathlib.Path` over string paths, f-strings, specific exceptions (never bare `except`).
- **Host test suite runs on Linux.** `libhydrogen.so` needs gcc and ELF. On steve's Windows machine that means WSL, matching the existing Blocksmith pattern (`Builds ONLY devkitPro MSYS2; host suites WSL`). Nothing in this plan is expected to run under Git Bash on Windows.

---

## Lanes

Six lanes. Tasks inside a lane are strictly ordered; lanes marked parallel can run at the same time in separate worktrees.

| Lane | Covers | Tasks | Depends on |
|---|---|---|---|
| **F0 — Foundation** | Repo skeleton, Makefile, VERSION, config | 1 | nothing |
| **A — Crypto & signing** | libhydrogen binding, canonical message, verify, replay window | 2, 3, 4 | Task 1 |
| **B — Storage** | SQLite schema, content-addressed blob store, quotas | 5, 6, 7 | Task 1 |
| **C — HTTP core** | PROXY protocol v2, per-IP rate limit, server + router + entrypoint | 8, 9, 10 | Task 1 (Task 10 also needs 8, 9) |
| **D — Phase 7 endpoints** | Signed-request middleware, upload, browse, model, thumb, no-decode proof | 11–15 | A, B, C |
| **E — Phase 8 social & moderation** | Votes, favourites, reports, auto-hide, admin queue, CLI tools | 16–22 | D |
| **F — Phase 9 deployment** | systemd, nftables, provision, host installer, self-update, README | 23–28 | Task 1 only (Task 25 wires in D+E at the end) |

**Lanes A, B, C and F are largely independent and can be built in parallel.** A, B and C only share `tessera/config.py` from Task 1, and each owns its own files. Lane F writes shell, systemd and nftables files that touch none of the Python — the only coupling is that `container-provision.sh` (Task 25) invokes `make test` and `make install-check`, whose contracts are fixed in Task 1. Dispatch A, B, C and F together after Task 1 lands; converge on D.

**Do not parallelise inside a lane.** Task 10 imports Task 8 and Task 9; Task 7 reads Task 5's schema; Tasks 12–15 all extend Task 11's middleware and the same router table.

**File ownership, to stop parallel agents reverting each other:** Lane A owns `src/tessera/hydro.py`, `src/tessera/signing.py`, `src/tessera/replay.py` and their tests. Lane B owns `src/tessera/db.py`, `src/tessera/store.py`, `src/tessera/quota.py`. Lane C owns `src/tessera/proxyproto.py`, `src/tessera/ratelimit.py`, `src/tessera/http_server.py`, `src/tessera/main.py`. Lane F owns `systemd/`, `install/`, `tools/`. Only Task 10 and Task 11 edit `http_server.py` before Lane D starts, and they are in the same lane.

---

## File Structure

```
tessera-server/
├── VERSION                          # single line, e.g. 1.0.0
├── Makefile                         # deps / build / test / install-check / hardening-check
├── README.md                        # exists; extended in Task 28
├── .gitignore                       # exists; extended in Task 1
├── pytest.ini                       # test discovery + src on the path
├── docs/
│   └── plans/2026-09-07-tessera-server-plan.md   # this file
├── src/tessera/
│   ├── __init__.py                  # version string only
│   ├── config.py                    # TesseraConfig dataclass + TOML/env loader
│   ├── hydro.py                     # ctypes binding to libhydrogen.so
│   ├── signing.py                   # canonical message + verify_signed_request
│   ├── replay.py                    # nonce + timestamp sliding replay window
│   ├── db.py                        # SQLite connection + schema + migrations
│   ├── store.py                     # content-addressed blob store
│   ├── quota.py                     # per-key daily, global rate, disk ceiling
│   ├── ratelimit.py                 # per-IP + global token buckets
│   ├── proxyproto.py                # PROXY protocol v2 (TCP) header parse
│   ├── http_server.py               # ThreadingHTTPServer, router, Response, RequestContext
│   ├── handlers_content.py          # upload, browse, model, thumb
│   ├── handlers_social.py           # vote, favourite, report
│   ├── handlers_admin.py            # admin/reports, admin/action
│   ├── moderation.py                # auto-hide threshold + visibility transitions
│   └── main.py                      # argv parsing, wiring, entrypoint
├── tools/
│   ├── tessera-reports              # moderation queue CLI (pull-based, zero egress)
│   ├── tessera-keys                 # admin key add/remove/list, ban/unban
│   └── ts-update                    # self-update from the pinned GitHub repo
├── systemd/
│   └── tessera.service
├── install/
│   ├── proxmox-install.sh           # runs on the Proxmox host as root
│   ├── container-provision.sh       # runs inside the container, idempotent
│   └── nftables-check.sh            # asserts the generated ruleset says what it must
└── tests/
    ├── conftest.py                  # tmp state dir, live-server fixture, signing helper
    ├── test_config.py
    ├── test_hydro.py
    ├── test_signing.py
    ├── test_signing_redarm.py       # proves the signature check is load-bearing
    ├── test_replay.py
    ├── test_db.py
    ├── test_store.py
    ├── test_quota.py
    ├── test_ratelimit.py
    ├── test_proxyproto.py
    ├── test_http_core.py
    ├── test_upload.py
    ├── test_browse.py
    ├── test_download.py
    ├── test_no_image_decode.py
    ├── test_vote.py
    ├── test_favourite.py
    ├── test_report.py
    ├── test_autohide.py
    ├── test_admin.py
    ├── test_tools_cli.py
    ├── test_nftables_ruleset.py
    └── test_systemd_unit.py
```

Build artefacts (`.deps/libhydrogen/`, `build/libhydrogen.so`) are gitignored — the container fetches and builds libhydrogen itself at the pinned commit, exactly as Blocksmith does.

---

## Task 1: Repo skeleton, Makefile, config module

**Lane:** F0 — Foundation. **Depends on:** nothing. **Everything else depends on this.**

**Files:**
- Create: `VERSION`, `Makefile`, `pytest.ini`, `src/tessera/__init__.py`, `src/tessera/config.py`, `tests/conftest.py`, `tests/test_config.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `tessera.config.TesseraConfig` — frozen dataclass, fields listed in Step 3.
  - `tessera.config.load_config(path: Path | None = None, env: Mapping[str, str] | None = None) -> TesseraConfig`
  - `TesseraConfig.blob_dir -> Path`, `TesseraConfig.db_path -> Path` (derived properties).
  - Make targets whose names Lane F's provisioning script depends on: `make deps`, `make build`, `make test`, `make install-check`.

- [ ] **Step 1: Create VERSION, .gitignore additions and pytest.ini**

`VERSION` (one line, no trailing text):

```
1.0.0
```

Append to `.gitignore`:

```
# Python
__pycache__/
*.pyc
.pytest_cache/

# Built libhydrogen shared object
build/
```

`pytest.ini`:

```ini
[pytest]
testpaths = tests
pythonpath = src
addopts = -q
```

- [ ] **Step 2: Write the failing config test**

`tests/test_config.py`:

```python
from pathlib import Path

import pytest

from tessera.config import TesseraConfig, load_config


def test_defaults_match_the_spec(tmp_path: Path) -> None:
    cfg = load_config(None, {"TESSERA_STATE_DIR": str(tmp_path)})
    assert cfg.uploads_per_key_per_day == 8
    assert cfg.report_autohide_threshold == 3
    assert cfg.sign_context == "tessera1"
    assert cfg.listen_host == "127.0.0.1"
    assert cfg.proxy_protocol is False
    assert cfg.report_reasons == ("gore", "sexual", "hate", "stolen", "spam", "other")


def test_derived_paths_hang_off_state_dir(tmp_path: Path) -> None:
    cfg = load_config(None, {"TESSERA_STATE_DIR": str(tmp_path)})
    assert cfg.blob_dir == tmp_path / "blobs"
    assert cfg.db_path == tmp_path / "tessera.db"


def test_toml_file_overrides_defaults(tmp_path: Path) -> None:
    toml = tmp_path / "tessera.toml"
    toml.write_text(
        'state_dir = "%s"\n'
        "listen_port = 9999\n"
        "uploads_per_key_per_day = 2\n"
        "report_autohide_threshold = 5\n"
        'admin_keys = ["%s"]\n' % (tmp_path.as_posix(), "aa" * 32),
        encoding="utf-8",
    )
    cfg = load_config(toml, {})
    assert cfg.listen_port == 9999
    assert cfg.uploads_per_key_per_day == 2
    assert cfg.report_autohide_threshold == 5
    assert cfg.admin_keys == ("aa" * 32,)


def test_env_overrides_the_toml_file(tmp_path: Path) -> None:
    toml = tmp_path / "tessera.toml"
    toml.write_text('state_dir = "%s"\nlisten_port = 9999\n' % tmp_path.as_posix(), encoding="utf-8")
    cfg = load_config(toml, {"TESSERA_LISTEN_PORT": "4242"})
    assert cfg.listen_port == 4242


def test_bad_admin_key_is_rejected_loudly(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="admin_keys"):
        load_config(None, {"TESSERA_STATE_DIR": str(tmp_path), "TESSERA_ADMIN_KEYS": "not-hex"})


def test_config_is_frozen(tmp_path: Path) -> None:
    cfg = load_config(None, {"TESSERA_STATE_DIR": str(tmp_path)})
    with pytest.raises(Exception):
        cfg.listen_port = 1  # type: ignore[misc]
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.config'`

- [ ] **Step 4: Write the config module**

`src/tessera/__init__.py`:

```python
"""Tessera gallery server."""

__version__ = "1.0.0"
```

`src/tessera/config.py`:

```python
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
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_config.py -v`
Expected: PASS, 6 passed

- [ ] **Step 6: Write the Makefile**

The four target names here are a contract with `install/container-provision.sh` (Task 25) and `tools/ts-update` (Task 27). Do not rename them.

`Makefile`:

```make
# Tessera gallery server — build, test and hardening gates.
#
# There is no compiled server binary: the daemon is Python. The one native
# artefact is libhydrogen, built here as a shared object and loaded by
# src/tessera/hydro.py through ctypes. It is pinned to a commit because the
# 3DS client is pinned to the same one; a signature scheme that differs
# between the two ends is a silent, total outage.

HYDRO_REPO   := https://github.com/jedisct1/libhydrogen.git
HYDRO_COMMIT := 617036a353cd4f6478ab6c3f98c36dd31e23ce8e
DEPS         := .deps
HYDRO        := $(DEPS)/libhydrogen
BUILD        := build
HYDRO_SO     := $(BUILD)/libhydrogen.so

PYTHON  ?= python3
PYTEST  ?= $(PYTHON) -m pytest

# Same hardening flags Blocksmith links its gateway with, applied to the only
# native object in this tree.
HYDRO_CFLAGS  := -std=c11 -O2 -g -fPIC -I$(HYDRO)
HYDRO_LDFLAGS := -shared -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed

.PHONY: all deps build test install-check hardening-check clean

all: build

deps: $(HYDRO)/hydrogen.h

$(HYDRO)/hydrogen.h:
	@mkdir -p $(DEPS)
	@echo "fetching libhydrogen at $(HYDRO_COMMIT)"
	git clone -q $(HYDRO_REPO) $(HYDRO)
	git -C $(HYDRO) -c safe.directory='*' checkout -q $(HYDRO_COMMIT)
	@test "$$(git -C $(HYDRO) -c safe.directory='*' rev-parse HEAD)" = "$(HYDRO_COMMIT)" \
	    || (echo "libhydrogen is NOT at the pinned commit"; exit 1)
	@echo "libhydrogen pinned at $(HYDRO_COMMIT)"

build: $(HYDRO_SO)

$(HYDRO_SO): $(HYDRO)/hydrogen.h $(HYDRO)/hydrogen.c
	@mkdir -p $(BUILD)
	$(CC) $(HYDRO_CFLAGS) $(HYDRO)/hydrogen.c -o $@ $(HYDRO_LDFLAGS)

test: build
	TESSERA_HYDRO_LIBRARY=$(abspath $(HYDRO_SO)) $(PYTEST)

# The install gate. container-provision.sh and ts-update both refuse to
# install if this exits non-zero.
install-check: build
	@echo "== libhydrogen pin =="
	@test "$$(git -C $(HYDRO) -c safe.directory='*' rev-parse HEAD)" = "$(HYDRO_COMMIT)" \
	    && echo "  pinned commit ok" || (echo "  WRONG libhydrogen commit"; exit 1)
	@echo "== native artefact hardening =="
	@readelf -d $(HYDRO_SO) | grep -qE 'BIND_NOW'       && echo "  RELRO/BIND_NOW ok" || (echo "  MISSING bind-now"; exit 1)
	@readelf -h $(HYDRO_SO) | grep -qE 'DYN'            && echo "  shared/PIC ok"     || (echo "  not a shared object"; exit 1)
	@readelf -lW $(HYDRO_SO) | grep -q 'GNU_STACK.*RW ' && echo "  NX stack ok"       || (echo "  stack may be executable"; exit 1)
	@echo "== no image decoding anywhere in the daemon =="
	@$(PYTHON) tests/scan_no_image_decode.py src/tessera

# Runs AFTER the unit is installed, so it needs systemd. Separate target
# because it cannot run in a checkout on a dev machine.
hardening-check:
	@systemd-analyze security tessera.service --no-pager

clean:
	rm -rf $(BUILD) .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
```

- [ ] **Step 7: Write the no-image-decode source scanner**

This is referenced by `make install-check` above and re-used as a test in Task 15. It lives in `tests/` because it is a check, not shipped code.

`tests/scan_no_image_decode.py`:

```python
#!/usr/bin/env python3
"""Fail if the daemon's source imports anything that could decode an image.

The spec's single hardest security requirement is that the server never
interprets uploaded bytes (spec section 5.6). This is a source-level proof of
that: an AST walk over every module, refusing any import whose top-level name
is on the banned list.

Usage:  python3 tests/scan_no_image_decode.py src/tessera
Exit 0 = clean. Exit 1 = a banned import was found, and it prints where.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

BANNED_MODULES: frozenset[str] = frozenset(
    {
        "PIL",
        "Pillow",
        "cv2",
        "imageio",
        "skimage",
        "png",
        "pypng",
        "imghdr",
        "wand",
        "pyvips",
        "cairosvg",
        "numpy",
        "matplotlib",
        "tkinter",
        "turtle",
        "colorsys",
    }
)


def banned_imports(source: str, where: Path) -> list[str]:
    findings: list[str] = []
    for node in ast.walk(ast.parse(source, filename=str(where))):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            top = name.split(".", 1)[0]
            if top in BANNED_MODULES:
                findings.append(f"{where}:{node.lineno}: imports {name!r}")
    return findings


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*.py")):
        findings.extend(banned_imports(path.read_text(encoding="utf-8"), path))
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else "src/tessera")
    findings = scan(root)
    if findings:
        print("IMAGE DECODING IMPORT FOUND — the server must never decode uploads:")
        for line in findings:
            print("  " + line)
        return 1
    count = len(list(root.rglob("*.py")))
    print(f"  no image-decoding imports in {count} modules under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 8: Write the shared test fixtures**

`tests/conftest.py`. The live-server fixture is added in Task 10; this is the part every lane needs from the start.

```python
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
```

- [ ] **Step 9: Run the whole thing end to end**

Run (on Linux / WSL, from the repo root):

```bash
make deps && make build && ls -l build/libhydrogen.so && make install-check && make test
```

Expected, in order: the pin line `libhydrogen pinned at 617036a353cd4f6478ab6c3f98c36dd31e23ce8e`; a `build/libhydrogen.so` of roughly 40–90 KB; `install-check` printing `pinned commit ok`, `RELRO/BIND_NOW ok`, `shared/PIC ok`, `NX stack ok`, and `no image-decoding imports in 2 modules under src/tessera`; then pytest reporting `6 passed`.

If `readelf` is missing, `apt-get install binutils`. Do not weaken the check to route around it.

- [ ] **Step 10: Commit**

```bash
git add VERSION Makefile pytest.ini .gitignore src/tessera/__init__.py src/tessera/config.py \
        tests/conftest.py tests/test_config.py tests/scan_no_image_decode.py
git commit -m "build: repo skeleton, pinned libhydrogen build, config module"
```

---

## Task 2: libhydrogen ctypes binding

**Lane:** A — Crypto & signing. **Depends on:** Task 1.

**Files:**
- Create: `src/tessera/hydro.py`, `tests/test_hydro.py`

**Interfaces:**
- Consumes: `tessera.config.TesseraConfig.hydro_library`, `TesseraConfig.sign_context`.
- Produces:
  - `tessera.hydro.Hydro` — a class wrapping one loaded `libhydrogen.so`.
  - `Hydro(library_path: Path)` — loads, calls `hydro_init()` once, raises `HydroError` on failure.
  - `Hydro.sign_verify(sig: bytes, message: bytes, context: str, public_key: bytes) -> bool`
  - `Hydro.sign_create(message: bytes, context: str, secret_key: bytes) -> bytes` (64 bytes; test and tooling only — the server never signs)
  - `Hydro.keygen() -> tuple[bytes, bytes]` returning `(public_key_32, secret_key_64)`
  - `Hydro.hash32(message: bytes, context: str) -> bytes` returning 32 bytes
  - `tessera.hydro.HydroError` — raised for load failures and bad argument sizes.
  - Constants `SIGN_BYTES = 64`, `SIGN_PUBLICKEYBYTES = 32`, `SIGN_SECRETKEYBYTES = 64`, `CONTEXTBYTES = 8`, `HASH_BYTES = 32`.

- [ ] **Step 1: Write the failing test**

`tests/test_hydro.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `make build && TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_hydro.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.hydro'`

- [ ] **Step 3: Write the binding**

`src/tessera/hydro.py`:

```python
"""ctypes binding to libhydrogen, pinned at 617036a353cd4f6478ab6c3f98c36dd31e23ce8e.

This is the only native code the daemon calls, and the only place in the
server where an attacker-influenced buffer meets C. Every entry point below
therefore checks its argument sizes in Python *before* the call — libhydrogen
takes fixed-size arrays (uint8_t[64], uint8_t[32], char[8]) with no length
parameter, so a short buffer would be read past rather than rejected.

The 3DS client links the same pinned commit and signs with the same context,
so nothing here may be changed on one side alone.
"""

from __future__ import annotations

import ctypes
from pathlib import Path

SIGN_BYTES = 64
SIGN_PUBLICKEYBYTES = 32
SIGN_SECRETKEYBYTES = 64
CONTEXTBYTES = 8
HASH_BYTES = 32


class HydroError(RuntimeError):
    """libhydrogen could not be loaded, or was handed a wrongly sized buffer."""


class Hydro:
    """One loaded libhydrogen.so, with hydro_init() already called."""

    def __init__(self, library_path: Path) -> None:
        self._path = Path(library_path)
        try:
            lib = ctypes.CDLL(str(self._path))
        except OSError as exc:
            raise HydroError(f"could not load libhydrogen from {self._path}: {exc}") from exc

        lib.hydro_init.restype = ctypes.c_int
        lib.hydro_init.argtypes = []

        lib.hydro_sign_keygen.restype = None
        lib.hydro_sign_keygen.argtypes = [ctypes.c_void_p]

        lib.hydro_sign_create.restype = ctypes.c_int
        lib.hydro_sign_create.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        lib.hydro_sign_verify.restype = ctypes.c_int
        lib.hydro_sign_verify.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        lib.hydro_hash_hash.restype = ctypes.c_int
        lib.hydro_hash_hash.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]

        if lib.hydro_init() != 0:
            raise HydroError("hydro_init() failed — no usable entropy source")

        self._lib = lib

    # -- argument guards --------------------------------------------------

    @staticmethod
    def _context(context: str) -> bytes:
        raw = context.encode("ascii")
        if len(raw) != CONTEXTBYTES:
            raise HydroError(
                f"context must be exactly {CONTEXTBYTES} ASCII bytes, got {len(raw)}"
            )
        return raw

    @staticmethod
    def _fixed(name: str, value: bytes, size: int) -> bytes:
        if not isinstance(value, (bytes, bytearray)) or len(value) != size:
            raise HydroError(f"{name} must be exactly {size} bytes, got {len(value)}")
        return bytes(value)

    # -- api --------------------------------------------------------------

    def keygen(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key). Used by tooling and tests only."""
        buf = ctypes.create_string_buffer(SIGN_PUBLICKEYBYTES + SIGN_SECRETKEYBYTES)
        self._lib.hydro_sign_keygen(ctypes.cast(buf, ctypes.c_void_p))
        raw = buf.raw[: SIGN_PUBLICKEYBYTES + SIGN_SECRETKEYBYTES]
        return raw[:SIGN_PUBLICKEYBYTES], raw[SIGN_PUBLICKEYBYTES:]

    def sign_create(self, message: bytes, context: str, secret_key: bytes) -> bytes:
        ctx = self._context(context)
        sk = self._fixed("secret key", secret_key, SIGN_SECRETKEYBYTES)
        out = ctypes.create_string_buffer(SIGN_BYTES)
        rc = self._lib.hydro_sign_create(out, message, len(message), ctx, sk)
        if rc != 0:
            raise HydroError("hydro_sign_create failed")
        return out.raw[:SIGN_BYTES]

    def sign_verify(
        self, signature: bytes, message: bytes, context: str, public_key: bytes
    ) -> bool:
        ctx = self._context(context)
        sig = self._fixed("signature", signature, SIGN_BYTES)
        pk = self._fixed("public key", public_key, SIGN_PUBLICKEYBYTES)
        return self._lib.hydro_sign_verify(sig, message, len(message), ctx, pk) == 0

    def hash32(self, message: bytes, context: str) -> bytes:
        """Unkeyed 32-byte hydro_hash. Used for body digests and content ids.

        libhydrogen's own hash rather than BLAKE2b or SHA-256 on purpose: the
        3DS client already links this library and nothing else, so using it for
        the content id means the console can compute the same id the server
        will store without carrying a second hash implementation.
        """
        ctx = self._context(context)
        out = ctypes.create_string_buffer(HASH_BYTES)
        rc = self._lib.hydro_hash_hash(out, HASH_BYTES, message, len(message), ctx, None)
        if rc != 0:
            raise HydroError("hydro_hash_hash failed")
        return out.raw[:HASH_BYTES]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_hydro.py -v`
Expected: PASS, 10 passed

- [ ] **Step 5: Prove the negative tests can go red**

The forged-signature tests are worthless if they would pass with the check removed. Verify that by hand, once:

1. In `src/tessera/hydro.py`, temporarily change the last line of `sign_verify` to `return True`.
2. Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_hydro.py -v`
3. Expected: **4 failures** — `test_a_flipped_signature_byte_fails`, `test_a_changed_message_fails`, `test_a_different_key_fails`, `test_a_different_context_fails`.
4. Revert the change with `git checkout -- src/tessera/hydro.py` and re-run: 10 passed.

Record the observed failure count in the commit message. If fewer than 4 fail, the tests are not testing what they claim and must be fixed before moving on.

- [ ] **Step 6: Commit**

```bash
git add src/tessera/hydro.py tests/test_hydro.py
git commit -m "feat(crypto): ctypes binding to pinned libhydrogen

Sabotage arm: forcing sign_verify to return True turns 4 of the 10 tests
red, so the negative cases are load-bearing."
```

---

## Task 3: Canonical signed-request message and verification

**Lane:** A — Crypto & signing. **Depends on:** Task 2.

**Files:**
- Create: `src/tessera/signing.py`, `tests/test_signing.py`

**Interfaces:**
- Consumes: `tessera.hydro.Hydro`, `tessera.config.TesseraConfig`.
- Produces:
  - `tessera.signing.SIGNED_PREFIX = b"tessera-v1"`
  - `tessera.signing.canonical_message(method: str, path: str, timestamp: int, nonce_hex: str, body_hash_hex: str) -> bytes`
  - `tessera.signing.SignedIdentity` — frozen dataclass with `key_hex: str` and `is_admin: bool`.
  - `tessera.signing.SignatureError(Exception)` — carries `.status: int` and `.code: str`.
  - `tessera.signing.parse_signature_headers(headers) -> tuple[str, bytes, int, str]` returning `(key_hex, signature_bytes, timestamp, nonce_hex)`.
  - `tessera.signing.verify_signed_request(*, hydro, cfg, method, path, headers, body, now, replay) -> SignedIdentity`
  - Header names: `X-Tessera-Key`, `X-Tessera-Sig`, `X-Tessera-Ts`, `X-Tessera-Nonce`.

- [ ] **Step 1: Write the failing test**

`tests/test_signing.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_signing.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.signing'`

- [ ] **Step 3: Write the signing module**

`src/tessera/signing.py`:

```python
"""Request signing: the whole of Tessera's authentication.

There is no TLS (the 3DS `ssl:C` tops out at TLS 1.1), and there are no
passwords. Identity, vote integrity and admin authority all rest on a
libhydrogen signature over a canonical byte string that pins the method, the
path *including its query string*, a timestamp, a per-request nonce and a hash
of the body. Change any of those five and the signature stops verifying.

The client builds the identical byte string. If this layout ever changes, the
version tag at the front must change with it, so an old client fails closed
with a bad signature instead of ambiguously.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from .config import TesseraConfig
from .hydro import SIGN_BYTES, SIGN_PUBLICKEYBYTES, Hydro, HydroError

SIGNED_PREFIX = b"tessera-v1"

HEADER_KEY = "X-Tessera-Key"
HEADER_SIG = "X-Tessera-Sig"
HEADER_TS = "X-Tessera-Ts"
HEADER_NONCE = "X-Tessera-Nonce"

NONCE_HEX_LEN = 32  # 16 random bytes
_HEX = frozenset("0123456789abcdef")


class SignatureError(Exception):
    """A signed request that must not be executed. Carries the HTTP status."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail or code


@dataclass(frozen=True)
class SignedIdentity:
    """Who sent a verified request. Not an authorisation — just a name."""

    key_hex: str
    is_admin: bool


class ReplayChecker(Protocol):
    def check_and_record(self, key_hex: str, nonce_hex: str, now: int, window: int) -> bool: ...


def canonical_message(
    method: str, path: str, timestamp: int, nonce_hex: str, body_hash_hex: str
) -> bytes:
    """The exact bytes both ends sign. Newline-separated, no trailing newline."""
    return b"\n".join(
        (
            SIGNED_PREFIX,
            method.encode("ascii"),
            path.encode("utf-8"),
            str(timestamp).encode("ascii"),
            nonce_hex.encode("ascii"),
            body_hash_hex.encode("ascii"),
        )
    )


def _lower_hex(value: str, expected_len: int) -> str:
    if len(value) != expected_len or any(c not in _HEX for c in value):
        raise SignatureError(
            400, "malformed_signature", f"expected {expected_len} lowercase hex characters"
        )
    return value


def parse_signature_headers(headers: Mapping[str, str]) -> tuple[str, bytes, int, str]:
    """Pull and validate the four signature headers. Nothing crypto here yet."""
    try:
        key_hex = headers[HEADER_KEY]
        sig_hex = headers[HEADER_SIG]
        ts_raw = headers[HEADER_TS]
        nonce_hex = headers[HEADER_NONCE]
    except KeyError as exc:
        raise SignatureError(400, "malformed_signature", f"missing header {exc.args[0]}") from exc

    if key_hex is None or sig_hex is None or ts_raw is None or nonce_hex is None:
        raise SignatureError(400, "malformed_signature", "empty signature header")

    key_hex = _lower_hex(key_hex.strip(), SIGN_PUBLICKEYBYTES * 2)
    sig_hex = _lower_hex(sig_hex.strip(), SIGN_BYTES * 2)
    nonce_hex = _lower_hex(nonce_hex.strip(), NONCE_HEX_LEN)

    try:
        timestamp = int(ts_raw.strip(), 10)
    except ValueError as exc:
        raise SignatureError(400, "malformed_signature", "timestamp is not an integer") from exc

    return key_hex, bytes.fromhex(sig_hex), timestamp, nonce_hex


def verify_signed_request(
    *,
    hydro: Hydro,
    cfg: TesseraConfig,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
    now: int,
    replay: ReplayChecker,
) -> SignedIdentity:
    """Verify a state-changing request, or raise SignatureError.

    Order matters: cheap structural checks first, then the timestamp window,
    then the signature, and only then the nonce is *recorded*. Recording the
    nonce before the signature verifies would let anyone lock a real client's
    nonce out by guessing it, which is a denial of service against a specific
    console rather than a defence.
    """
    key_hex, signature, timestamp, nonce_hex = parse_signature_headers(headers)

    if abs(now - timestamp) > cfg.replay_window_secs:
        raise SignatureError(
            401,
            "stale_timestamp",
            f"timestamp {timestamp} is outside +/-{cfg.replay_window_secs}s of {now}",
        )

    try:
        body_hash_hex = hydro.hash32(body, cfg.sign_context).hex()
        message = canonical_message(method, path, timestamp, nonce_hex, body_hash_hex)
        ok = hydro.sign_verify(signature, message, cfg.sign_context, bytes.fromhex(key_hex))
    except HydroError as exc:
        raise SignatureError(400, "malformed_signature", str(exc)) from exc

    if not ok:
        raise SignatureError(401, "bad_signature", "signature does not verify")

    if not replay.check_and_record(key_hex, nonce_hex, now, cfg.replay_window_secs):
        raise SignatureError(409, "replayed", "nonce already used inside the replay window")

    return SignedIdentity(key_hex=key_hex, is_admin=key_hex in cfg.admin_keys)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_signing.py -v`
Expected: PASS, 22 passed (the two `parametrize` blocks contribute 4 and 6).

Note the test file imports `tessera.replay.ReplayWindow` at module scope; if Task 4 has not landed yet in this worktree, delete that one import line, run, then restore it — do not stub the module.

- [ ] **Step 5: Commit**

```bash
git add src/tessera/signing.py tests/test_signing.py
git commit -m "feat(crypto): canonical signed-request message and verification"
```

---

## Task 4: Sliding replay window

**Lane:** A — Crypto & signing. **Depends on:** Task 3. Uses the `nonces` table created in Task 5, but does not import Task 5's module.

**Files:**
- Create: `src/tessera/replay.py`, `tests/test_replay.py`

**Interfaces:**
- Consumes: an open `sqlite3.Connection` with a `nonces(key TEXT, nonce TEXT, expires_at INTEGER)` table (Task 5 creates it; `ReplayWindow.ensure_table` creates it too so this module stands alone).
- Produces:
  - `tessera.replay.ReplayWindow(conn: sqlite3.Connection)`
  - `ReplayWindow.ensure_table() -> None`
  - `ReplayWindow.check_and_record(key_hex: str, nonce_hex: str, now: int, window: int) -> bool`
  - `ReplayWindow.purge(now: int) -> int` returning the number of rows removed.
  - Satisfies the `tessera.signing.ReplayChecker` protocol.

- [ ] **Step 1: Write the failing test**

`tests/test_replay.py`:

```python
from __future__ import annotations

import sqlite3

import pytest

from tessera.replay import ReplayWindow

WINDOW = 300
NOW = 1_757_260_800
KEY_A = "aa" * 32
KEY_B = "bb" * 32
NONCE_1 = "11" * 16
NONCE_2 = "22" * 16


@pytest.fixture
def window() -> ReplayWindow:
    conn = sqlite3.connect(":memory:")
    win = ReplayWindow(conn)
    win.ensure_table()
    return win


def test_a_fresh_nonce_is_accepted(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True


def test_the_same_nonce_twice_is_rejected(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is False


def test_the_same_nonce_from_a_different_key_is_fine(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_B, NONCE_1, NOW, WINDOW) is True


def test_a_different_nonce_from_the_same_key_is_fine(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_2, NOW, WINDOW) is True


def test_the_window_slides_so_an_expired_nonce_becomes_reusable(window: ReplayWindow) -> None:
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_1, NOW + WINDOW // 2, WINDOW) is False
    # Past the trailing edge: the record has expired, and the signing layer's
    # own timestamp check is what stops the old request being replayed now.
    assert window.check_and_record(KEY_A, NONCE_1, NOW + 2 * WINDOW + 1, WINDOW) is True


def test_purge_removes_only_expired_rows(window: ReplayWindow) -> None:
    window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW)
    window.check_and_record(KEY_A, NONCE_2, NOW + WINDOW, WINDOW)
    removed = window.purge(NOW + WINDOW + 1)
    assert removed == 1
    assert window.check_and_record(KEY_A, NONCE_1, NOW + WINDOW + 1, WINDOW) is True
    assert window.check_and_record(KEY_A, NONCE_2, NOW + WINDOW + 1, WINDOW) is False


def test_the_table_does_not_grow_without_bound(window: ReplayWindow) -> None:
    for i in range(500):
        window.check_and_record(KEY_A, f"{i:032x}", NOW + i, WINDOW)
    rows = window.conn.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
    # Everything older than the window at the last recorded time is gone.
    assert rows <= 2 * WINDOW + 2, f"nonce table holds {rows} rows — purge is not running"


def test_ensure_table_is_idempotent(window: ReplayWindow) -> None:
    window.ensure_table()
    window.ensure_table()
    assert window.check_and_record(KEY_A, NONCE_1, NOW, WINDOW) is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_replay.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.replay'`

- [ ] **Step 3: Write the replay window**

`src/tessera/replay.py`:

```python
"""Sliding replay window over (public key, nonce) pairs.

Blocksmith's gateway/replay.c uses an IPsec-style bitmask because its
transport is UDP with a monotonically increasing 64-bit message id it controls
end to end. HTTP has no such id — requests arrive over independent TCP
connections, from a console whose clock is only roughly right — so the window
here is defined by time instead: a (key, nonce) pair is remembered for as long
as the signing layer would still accept its timestamp, and forgotten after.

That is the same guarantee, reached differently: a captured request can only
be replayed inside the timestamp window, and inside that window its nonce is
already on record. Outside it, `verify_signed_request` rejects the timestamp
before this class is ever consulted.

The table is purged on every write, so it cannot grow without bound. Its
maximum size is (requests accepted in one window), which the per-IP and global
rate limits already cap.
"""

from __future__ import annotations

import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    key        TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (key, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON nonces(expires_at);
"""


class ReplayWindow:
    """Remembers used nonces for exactly as long as they could still be replayed."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def ensure_table(self) -> None:
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def purge(self, now: int) -> int:
        cursor = self.conn.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
        self.conn.commit()
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def check_and_record(self, key_hex: str, nonce_hex: str, now: int, window: int) -> bool:
        """True if this (key, nonce) is fresh; records it. False if it is a replay.

        Purge first, so a nonce whose window has closed is genuinely gone
        before the uniqueness check runs — otherwise an old row would keep
        rejecting a nonce the signing layer has already stopped protecting.
        """
        self.purge(now)
        try:
            self.conn.execute(
                "INSERT INTO nonces (key, nonce, expires_at) VALUES (?, ?, ?)",
                (key_hex, nonce_hex, now + window),
            )
        except sqlite3.IntegrityError:
            return False
        self.conn.commit()
        return True
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_replay.py -v`
Expected: PASS, 8 passed

- [ ] **Step 5: Prove the replay rejection can go red**

1. Temporarily change `check_and_record` to `return True` unconditionally (keeping the `INSERT` inside a `try`/`except` that swallows).
2. Run: `python3 -m pytest tests/test_replay.py -v`
3. Expected: **3 failures** — `test_the_same_nonce_twice_is_rejected`, `test_the_window_slides_so_an_expired_nonce_becomes_reusable`, `test_purge_removes_only_expired_rows`.
4. `git checkout -- src/tessera/replay.py`, re-run: 8 passed.

- [ ] **Step 6: Run the whole of Lane A together**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_hydro.py tests/test_signing.py tests/test_replay.py -v`
Expected: PASS, 40 passed.

- [ ] **Step 7: Commit**

```bash
git add src/tessera/replay.py tests/test_replay.py
git commit -m "feat(crypto): time-bounded sliding replay window over (key, nonce)

Sabotage arm: making check_and_record always return True turns 3 tests red."
```

---

## Task 5: SQLite schema and connection

**Lane:** B — Storage. **Depends on:** Task 1. **Parallel with Lanes A, C, F.**

**Files:**
- Create: `src/tessera/db.py`, `tests/test_db.py`

**Interfaces:**
- Consumes: `tessera.config.TesseraConfig.db_path`.
- Produces:
  - `tessera.db.SCHEMA_VERSION = 1`
  - `tessera.db.connect(db_path: Path) -> sqlite3.Connection` — WAL, foreign keys on, `row_factory = sqlite3.Row`.
  - `tessera.db.migrate(conn: sqlite3.Connection) -> None` — idempotent.
  - Tables `models`, `votes`, `favourites`, `reports`, `bans`, `nonces`, `schema_meta`.
  - Visibility values: `'public'`, `'unlisted'`, `'deleted'`. Vote values: `-1`, `1`.

- [ ] **Step 1: Write the failing test**

`tests/test_db.py`:

```python
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tessera.db import SCHEMA_VERSION, connect, migrate

MODEL_ROW = (
    "aa" * 32, "bb" * 32, "A hexagon", "cc" * 32, "model", 1234, 512, 1_757_260_800,
)
INSERT_MODEL = """
INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,
                    model_bytes, thumb_bytes, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    connection = connect(tmp_path / "t.db")
    migrate(connection)
    return connection


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    connection = connect(tmp_path / "t.db")
    migrate(connection)
    migrate(connection)
    version = connection.execute(
        "SELECT v FROM schema_meta WHERE k = 'schema_version'"
    ).fetchone()[0]
    assert int(version) == SCHEMA_VERSION


def test_expected_tables_exist(conn: sqlite3.Connection) -> None:
    names = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"models", "votes", "favourites", "reports", "bans", "nonces", "schema_meta"} <= names


def test_foreign_keys_are_enforced(conn: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
            (999, "dd" * 32, 1, 0),
        )


def test_a_model_hash_is_unique(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT_MODEL, MODEL_ROW)


def test_visibility_defaults_to_public_and_is_constrained(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    assert conn.execute("SELECT visibility FROM models").fetchone()[0] == "public"
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE models SET visibility = 'banished'")


def test_kind_is_constrained(conn: sqlite3.Connection) -> None:
    bad = ("11" * 32, "22" * 32, "t", "33" * 32, "sculpture", 1, 1, 0)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(INSERT_MODEL, bad)


def test_one_vote_per_key_per_model(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    conn.execute(
        "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
        (model_id, "dd" * 32, 1, 0),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
            (model_id, "dd" * 32, -1, 0),
        )


def test_a_vote_must_be_plus_or_minus_one(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
            (model_id, "dd" * 32, 5, 0),
        )


def test_one_report_per_key_per_model(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    args = (model_id, "ee" * 32, "spam", "", 0)
    conn.execute(
        "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        args,
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            args,
        )


def test_the_reason_list_is_exactly_the_spec_list(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    for index, reason in enumerate(("gore", "sexual", "hate", "stolen", "spam", "other")):
        conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, f"{index:064x}", reason, "", 0),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, "ff" * 32, "annoying", "", 0),
        )


def test_favourites_are_unlimited_but_not_duplicated(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    conn.execute(
        "INSERT INTO favourites (model_id, owner_key, created_at) VALUES (?, ?, ?)",
        (model_id, "ab" * 32, 0),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO favourites (model_id, owner_key, created_at) VALUES (?, ?, ?)",
            (model_id, "ab" * 32, 0),
        )


def test_deleting_a_model_cascades(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    model_id = conn.execute("SELECT id FROM models").fetchone()[0]
    conn.execute(
        "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)",
        (model_id, "dd" * 32, 1, 0),
    )
    conn.execute("DELETE FROM models WHERE id = ?", (model_id,))
    assert conn.execute("SELECT COUNT(*) FROM votes").fetchone()[0] == 0


def test_wal_mode_is_on(conn: sqlite3.Connection) -> None:
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_rows_come_back_as_mappings(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_MODEL, MODEL_ROW)
    row = conn.execute("SELECT title, kind FROM models").fetchone()
    assert row["title"] == "A hexagon"
    assert row["kind"] == "model"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_db.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.db'`

- [ ] **Step 3: Write the database module**

`src/tessera/db.py`:

```python
"""SQLite index for the gallery.

Only the index lives here. The uploaded bytes themselves never touch this
database — they go to the content-addressed blob store (store.py), and the
rows below hold their hashes. That keeps the database small enough to copy
somewhere and read, and it means a corrupted row can never corrupt a file.

Every constraint that encodes a spec rule is enforced by SQLite rather than by
application code, because application code is what gets bypassed by the next
handler someone adds:

  - one thumbs vote per key per model     -> PRIMARY KEY (model_id, voter_key)
  - one report per key per model          -> UNIQUE (model_id, reporter_key)
  - the fixed six report reasons          -> CHECK (reason IN (...))
  - hearts are per (owner, model)         -> PRIMARY KEY (owner_key, model_id)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    model_hash   TEXT    NOT NULL UNIQUE,
    thumb_hash   TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    author_key   TEXT    NOT NULL,
    kind         TEXT    NOT NULL CHECK (kind IN ('pixel', 'model')),
    model_bytes  INTEGER NOT NULL,
    thumb_bytes  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    score        INTEGER NOT NULL DEFAULT 0,
    up_votes     INTEGER NOT NULL DEFAULT 0,
    down_votes   INTEGER NOT NULL DEFAULT 0,
    report_count INTEGER NOT NULL DEFAULT 0,
    visibility   TEXT    NOT NULL DEFAULT 'public'
                 CHECK (visibility IN ('public', 'unlisted', 'deleted'))
);
CREATE INDEX IF NOT EXISTS idx_models_browse_new ON models(visibility, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_models_browse_top ON models(visibility, score DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_models_author     ON models(author_key, created_at);

CREATE TABLE IF NOT EXISTS votes (
    model_id   INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    voter_key  TEXT    NOT NULL,
    value      INTEGER NOT NULL CHECK (value IN (-1, 1)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (model_id, voter_key)
);

CREATE TABLE IF NOT EXISTS favourites (
    model_id   INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    owner_key  TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_key, model_id)
);
CREATE INDEX IF NOT EXISTS idx_favourites_model ON favourites(model_id);

CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id     INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    reporter_key TEXT    NOT NULL,
    reason       TEXT    NOT NULL
                 CHECK (reason IN ('gore', 'sexual', 'hate', 'stolen', 'spam', 'other')),
    detail       TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    resolved_at  INTEGER,
    UNIQUE (model_id, reporter_key)
);
CREATE INDEX IF NOT EXISTS idx_reports_open ON reports(resolved_at, created_at DESC);

CREATE TABLE IF NOT EXISTS bans (
    key        TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    key        TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (key, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON nonces(expires_at);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the index. WAL so a browse never blocks behind an upload."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    # Off by default in SQLite, and every cascade and reference above depends
    # on it. It is a per-connection pragma, so it must be set here and not in
    # the schema.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Create or update the schema. Safe to call on every start."""
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO schema_meta (k, v) VALUES ('schema_version', ?)"
        " ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        (str(SCHEMA_VERSION),),
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_db.py -v`
Expected: PASS, 14 passed

- [ ] **Step 5: Commit**

```bash
git add src/tessera/db.py tests/test_db.py
git commit -m "feat(storage): SQLite schema with spec rules enforced as constraints"
```

---

## Task 6: Content-addressed blob store

**Lane:** B — Storage. **Depends on:** Task 5 (only for the module layout; no code dependency).

**Files:**
- Create: `src/tessera/store.py`, `tests/test_store.py`

**Interfaces:**
- Consumes: a `hasher: Callable[[bytes], bytes]` (in production, `lambda b: hydro.hash32(b, cfg.sign_context)`).
- Produces:
  - `tessera.store.BlobStore(root: Path, hasher: Callable[[bytes], bytes])`
  - `BlobStore.put(data: bytes) -> str` — returns a 64-character lowercase hex digest.
  - `BlobStore.get(digest_hex: str) -> bytes` — raises `BlobNotFound`.
  - `BlobStore.exists(digest_hex: str) -> bool`
  - `BlobStore.delete(digest_hex: str) -> bool`
  - `BlobStore.total_bytes() -> int`
  - `tessera.store.BlobNotFound(KeyError)`, `tessera.store.InvalidDigest(ValueError)`

- [ ] **Step 1: Write the failing test**

`tests/test_store.py`:

```python
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tessera.store import BlobNotFound, BlobStore, InvalidDigest


def sha256(data: bytes) -> bytes:
    """Stand-in hasher. The real one is hydro_hash; the store does not care."""
    return hashlib.sha256(data).digest()


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs", sha256)


def test_put_returns_the_content_hash(store: BlobStore) -> None:
    digest = store.put(b"hello tessera")
    assert digest == sha256(b"hello tessera").hex()
    assert len(digest) == 64


def test_round_trip_is_byte_identical(store: BlobStore) -> None:
    payload = bytes(range(256)) * 8
    assert store.get(store.put(payload)) == payload


def test_putting_the_same_bytes_twice_is_one_file(store: BlobStore) -> None:
    first = store.put(b"same")
    second = store.put(b"same")
    assert first == second
    assert len(list(store.root.rglob("*"))) == len(list(store.root.rglob("*")))
    files = [p for p in store.root.rglob("*") if p.is_file()]
    assert len(files) == 1


def test_a_missing_blob_raises(store: BlobStore) -> None:
    with pytest.raises(BlobNotFound):
        store.get("ab" * 32)


@pytest.mark.parametrize(
    "bad",
    [
        "../../etc/passwd",
        "..",
        "/etc/passwd",
        "ab" * 31,
        "ab" * 33,
        "AB" * 32,
        "zz" * 32,
        "",
        "ab/cd" + "e" * 59,
        "\x00" * 64,
    ],
)
def test_a_user_supplied_name_can_never_reach_the_filesystem(
    store: BlobStore, bad: str
) -> None:
    with pytest.raises(InvalidDigest):
        store.get(bad)
    with pytest.raises(InvalidDigest):
        store.delete(bad)
    with pytest.raises(InvalidDigest):
        store.exists(bad)


def test_files_are_fanned_out_by_the_first_four_hex_characters(store: BlobStore) -> None:
    digest = store.put(b"fanout")
    expected = store.root / digest[0:2] / digest[2:4] / digest
    assert expected.is_file()
    assert expected.read_bytes() == b"fanout"


def test_stored_files_are_not_executable(store: BlobStore) -> None:
    digest = store.put(b"x")
    mode = (store.root / digest[0:2] / digest[2:4] / digest).stat().st_mode
    assert mode & 0o111 == 0, "a blob must never be executable"


def test_total_bytes_sums_the_store(store: BlobStore) -> None:
    assert store.total_bytes() == 0
    store.put(b"a" * 100)
    store.put(b"b" * 250)
    assert store.total_bytes() == 350
    store.put(b"a" * 100)  # already present, adds nothing
    assert store.total_bytes() == 350


def test_delete_removes_the_blob_and_reports_whether_it_existed(store: BlobStore) -> None:
    digest = store.put(b"gone soon")
    assert store.delete(digest) is True
    assert store.exists(digest) is False
    assert store.delete(digest) is False


def test_an_empty_blob_is_storable(store: BlobStore) -> None:
    digest = store.put(b"")
    assert store.get(digest) == b""


def test_the_store_never_interprets_the_bytes(store: BlobStore) -> None:
    # A PNG signature followed by garbage that would upset a real decoder.
    hostile = b"\x89PNG\r\n\x1a\n" + b"\xff" * 64 + b"IEND"
    assert store.get(store.put(hostile)) == hostile
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.store'`

- [ ] **Step 3: Write the blob store**

`src/tessera/store.py`:

```python
"""Content-addressed blob storage.

Uploads are named by the hash of their own bytes, never by anything the
uploader chose. That is what kills path traversal outright (spec section 4.3):
there is no filename to sanitise because there is no user-supplied filename at
any point in the pipeline.

`_validated` is the only place a string becomes a path, and it accepts exactly
64 lowercase hex characters and nothing else. Every public method routes
through it, including the ones that only read.

Nothing here inspects, parses, transcodes or validates the *content*. A blob
is bytes in and the identical bytes out. That is a security property, not
laziness — see spec section 5.6.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

DIGEST_HEX_LEN = 64
_HEX = frozenset("0123456789abcdef")

# 0640: readable by the service user and its group, writable by the owner,
# executable by nobody. The directory the daemon can write is explicitly not a
# directory anything can execute from (spec section 4.3).
BLOB_MODE = 0o640
DIR_MODE = 0o750


class BlobNotFound(KeyError):
    """No blob with that digest is stored."""


class InvalidDigest(ValueError):
    """A digest that is not exactly 64 lowercase hex characters."""


class BlobStore:
    """Files on disk, keyed by the hash of their contents."""

    def __init__(self, root: Path, hasher: Callable[[bytes], bytes]) -> None:
        self.root = Path(root)
        self._hasher = hasher
        self.root.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)

    # -- internals --------------------------------------------------------

    @staticmethod
    def _validated(digest_hex: str) -> str:
        if (
            not isinstance(digest_hex, str)
            or len(digest_hex) != DIGEST_HEX_LEN
            or any(c not in _HEX for c in digest_hex)
        ):
            raise InvalidDigest(
                f"blob id must be {DIGEST_HEX_LEN} lowercase hex characters, got {digest_hex!r}"
            )
        return digest_hex

    def path_for(self, digest_hex: str) -> Path:
        """Fan out over two levels so no directory holds 100k entries."""
        clean = self._validated(digest_hex)
        return self.root / clean[0:2] / clean[2:4] / clean

    # -- api --------------------------------------------------------------

    def put(self, data: bytes) -> str:
        """Store `data`, return its digest. Idempotent for identical bytes."""
        digest_hex = self._hasher(data).hex()
        target = self.path_for(digest_hex)
        if target.exists():
            return digest_hex

        target.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
        # Write-then-rename: a crash mid-write leaves a temp file, never a
        # truncated blob sitting under a hash that no longer describes it.
        handle, temp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temp_name, BLOB_MODE)
            os.replace(temp_name, target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
        return digest_hex

    def exists(self, digest_hex: str) -> bool:
        return self.path_for(digest_hex).is_file()

    def get(self, digest_hex: str) -> bytes:
        path = self.path_for(digest_hex)
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise BlobNotFound(digest_hex) from exc

    def delete(self, digest_hex: str) -> bool:
        path = self.path_for(digest_hex)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True

    def total_bytes(self) -> int:
        """Bytes currently held. Walked rather than cached: the ceiling this
        feeds is a safety limit, and a cached counter that drifts is a limit
        that silently stops being one."""
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_store.py -v`
Expected: PASS, 21 passed (the traversal `parametrize` contributes 10).

- [ ] **Step 5: Prove the traversal guard can go red**

1. Temporarily change `_validated` to `return digest_hex` with no checks.
2. Run: `python3 -m pytest tests/test_store.py -v`
3. Expected: **10 failures**, all from `test_a_user_supplied_name_can_never_reach_the_filesystem`.
4. `git checkout -- src/tessera/store.py`, re-run: 21 passed.

- [ ] **Step 6: Commit**

```bash
git add src/tessera/store.py tests/test_store.py
git commit -m "feat(storage): content-addressed blob store, no user-supplied filenames

Sabotage arm: removing the digest validation turns all 10 traversal cases red."
```

---

## Task 7: Upload quotas — per key per day, global rate, disk ceiling

**Lane:** B — Storage. **Depends on:** Tasks 5 and 6.

**Files:**
- Create: `src/tessera/quota.py`, `tests/test_quota.py`

**Interfaces:**
- Consumes: `tessera.db` schema, `tessera.store.BlobStore`, `tessera.config.TesseraConfig`.
- Produces:
  - `tessera.quota.QuotaError(Exception)` with `.status: int` and `.code: str`.
  - `tessera.quota.check_upload_allowed(*, conn, store, cfg, author_key, incoming_bytes, now) -> None` — raises `QuotaError`, otherwise returns.
  - `tessera.quota.uploads_today(conn, author_key: str, now: int) -> int`
  - `tessera.quota.uploads_last_hour(conn, now: int) -> int`
  - `tessera.quota.is_banned(conn, key_hex: str) -> bool`
  - Codes: `banned`, `daily_quota`, `global_rate`, `disk_full`, `too_large`.

- [ ] **Step 1: Write the failing test**

`tests/test_quota.py`:

```python
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from tessera.config import TesseraConfig, load_config
from tessera.db import connect, migrate
from tessera.quota import QuotaError, check_upload_allowed, uploads_last_hour, uploads_today
from tessera.store import BlobStore

NOW = 1_757_260_800
DAY = 86_400
HOUR = 3_600
AUTHOR = "aa" * 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    connection = connect(tmp_path / "t.db")
    migrate(connection)
    return connection


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs", sha256)


def add_upload(conn: sqlite3.Connection, author: str, created_at: int, tag: str) -> None:
    conn.execute(
        "INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,"
        " model_bytes, thumb_bytes, created_at) VALUES (?, ?, ?, ?, 'pixel', 10, 10, ?)",
        (sha256(tag.encode()).hex(), sha256((tag + "t").encode()).hex(), tag, author, created_at),
    )


def test_a_first_upload_is_allowed(conn, store, config: TesseraConfig) -> None:
    check_upload_allowed(
        conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=1000, now=NOW
    )


def test_the_eighth_upload_is_allowed_and_the_ninth_is_not(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - i * 60, f"m{i}")
        assert uploads_today(conn, AUTHOR, NOW) == i + 1
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
        )
    assert excinfo.value.code == "daily_quota"
    assert excinfo.value.status == 429


def test_the_daily_quota_is_a_rolling_24_hours(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - DAY - 60 - i, f"old{i}")
    assert uploads_today(conn, AUTHOR, NOW) == 0
    check_upload_allowed(
        conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
    )


def test_another_key_has_its_own_quota(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - i, f"m{i}")
    check_upload_allowed(
        conn=conn, store=store, cfg=config, author_key="bb" * 32, incoming_bytes=10, now=NOW
    )


def test_the_global_hourly_cap_stops_everyone(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_GLOBAL_UPLOADS_PER_HOUR": "3",
    })
    for i in range(3):
        add_upload(conn, f"{i:064x}", NOW - 60, f"g{i}")
    assert uploads_last_hour(conn, NOW) == 3
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=cfg, author_key="cc" * 32, incoming_bytes=10, now=NOW
        )
    assert excinfo.value.code == "global_rate"


def test_the_global_cap_is_a_rolling_hour(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_GLOBAL_UPLOADS_PER_HOUR": "3",
    })
    for i in range(3):
        add_upload(conn, f"{i:064x}", NOW - HOUR - 10 - i, f"g{i}")
    check_upload_allowed(
        conn=conn, store=store, cfg=cfg, author_key="cc" * 32, incoming_bytes=10, now=NOW
    )


def test_a_full_disk_refuses_the_upload(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_MAX_TOTAL_DISK_BYTES": "1000",
    })
    store.put(b"x" * 900)
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=cfg, author_key=AUTHOR, incoming_bytes=200, now=NOW
        )
    assert excinfo.value.code == "disk_full"
    assert excinfo.value.status == 507


def test_an_oversized_upload_is_refused(conn, store, state_dir, hydro_library_path) -> None:
    cfg = load_config(None, {
        "TESSERA_STATE_DIR": str(state_dir),
        "TESSERA_HYDRO_LIBRARY": str(hydro_library_path),
        "TESSERA_MAX_REQUEST_BYTES": "500",
    })
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=cfg, author_key=AUTHOR, incoming_bytes=501, now=NOW
        )
    assert excinfo.value.code == "too_large"
    assert excinfo.value.status == 413


def test_a_banned_key_cannot_upload(conn, store, config) -> None:
    conn.execute(
        "INSERT INTO bans (key, reason, created_at) VALUES (?, 'spam', ?)", (AUTHOR, NOW)
    )
    with pytest.raises(QuotaError) as excinfo:
        check_upload_allowed(
            conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
        )
    assert excinfo.value.code == "banned"
    assert excinfo.value.status == 403


def test_deleted_uploads_still_count_against_the_daily_quota(conn, store, config) -> None:
    for i in range(8):
        add_upload(conn, AUTHOR, NOW - i, f"m{i}")
    conn.execute("UPDATE models SET visibility = 'deleted'")
    with pytest.raises(QuotaError, match="daily"):
        check_upload_allowed(
            conn=conn, store=store, cfg=config, author_key=AUTHOR, incoming_bytes=10, now=NOW
        )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_quota.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.quota'`

- [ ] **Step 3: Write the quota module**

`src/tessera/quota.py`:

```python
"""Abuse control for a gallery with no passwords.

Anyone holding the CIA can upload, so none of this can come from
authentication (spec section 4.5). What is left is arithmetic: a per-key daily
count, a global hourly cap, a total-disk ceiling, and a per-request byte
ceiling. Bans are the fifth lever and they are cheap to evade by reinstalling —
the per-IP limiter in ratelimit.py is what actually costs a determined abuser
anything.

The daily count deliberately includes uploads that have since been deleted or
unlisted. Otherwise getting something removed would refund the quota, which
turns moderation into a reward.
"""

from __future__ import annotations

import sqlite3

from .config import TesseraConfig
from .store import BlobStore

DAY_SECONDS = 86_400
HOUR_SECONDS = 3_600


class QuotaError(Exception):
    """An upload that must be refused. Carries the HTTP status to answer with."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def is_banned(conn: sqlite3.Connection, key_hex: str) -> bool:
    return conn.execute("SELECT 1 FROM bans WHERE key = ?", (key_hex,)).fetchone() is not None


def uploads_today(conn: sqlite3.Connection, author_key: str, now: int) -> int:
    """Uploads by this key in the trailing 24 hours, deleted ones included."""
    row = conn.execute(
        "SELECT COUNT(*) FROM models WHERE author_key = ? AND created_at > ?",
        (author_key, now - DAY_SECONDS),
    ).fetchone()
    return int(row[0])


def uploads_last_hour(conn: sqlite3.Connection, now: int) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM models WHERE created_at > ?", (now - HOUR_SECONDS,)
    ).fetchone()
    return int(row[0])


def check_upload_allowed(
    *,
    conn: sqlite3.Connection,
    store: BlobStore,
    cfg: TesseraConfig,
    author_key: str,
    incoming_bytes: int,
    now: int,
) -> None:
    """Raise QuotaError if this upload must be refused; return otherwise.

    Ordered cheapest-first, with the disk walk last: a banned key or an
    over-quota key should never cause a full traversal of the blob store.
    """
    if is_banned(conn, author_key):
        raise QuotaError(403, "banned", "this key is banned from uploading")

    if incoming_bytes > cfg.max_request_bytes:
        raise QuotaError(
            413,
            "too_large",
            f"{incoming_bytes} bytes exceeds the {cfg.max_request_bytes} byte ceiling",
        )

    used = uploads_today(conn, author_key, now)
    if used >= cfg.uploads_per_key_per_day:
        raise QuotaError(
            429,
            "daily_quota",
            f"{used} uploads in the last 24h, the daily limit is "
            f"{cfg.uploads_per_key_per_day}",
        )

    hourly = uploads_last_hour(conn, now)
    if hourly >= cfg.global_uploads_per_hour:
        raise QuotaError(
            429,
            "global_rate",
            f"the gallery has taken {hourly} uploads this hour, the cap is "
            f"{cfg.global_uploads_per_hour}",
        )

    if store.total_bytes() + incoming_bytes > cfg.max_total_disk_bytes:
        raise QuotaError(
            507,
            "disk_full",
            "the gallery has reached its total disk ceiling",
        )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_quota.py -v`
Expected: PASS, 10 passed

- [ ] **Step 5: Run the whole of Lane B together**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_db.py tests/test_store.py tests/test_quota.py -v`
Expected: PASS, 45 passed

- [ ] **Step 6: Commit**

```bash
git add src/tessera/quota.py tests/test_quota.py
git commit -m "feat(storage): per-key daily, global hourly, disk and size quotas"
```

---

## Task 8: PROXY protocol v2 header parsing (TCP)

**Lane:** C — HTTP core. **Depends on:** Task 1. **Parallel with Lanes A, B, F.**

**Files:**
- Create: `src/tessera/proxyproto.py`, `tests/test_proxyproto.py`

**Interfaces:**
- Consumes: nothing beyond the stdlib.
- Produces:
  - `tessera.proxyproto.PPV2_SIGNATURE: bytes` (12 bytes), `PPV2_HDR_BYTES = 16`, `PPV2_INET_BYTES = 12`
  - `tessera.proxyproto.ProxyProtocolError(Exception)`
  - `tessera.proxyproto.read_ppv2_header(rfile: BinaryIO) -> tuple[str, int]` returning `(client_ip, client_port)`; consumes exactly the header bytes and leaves the stream positioned at the first HTTP byte.
  - `tessera.proxyproto.build_ppv2_header(src_ip: str, src_port: int, dst_ip: str = "127.0.0.1", dst_port: int = 8080) -> bytes` — test and tooling helper.

- [ ] **Step 1: Write the failing test**

`tests/test_proxyproto.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_proxyproto.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.proxyproto'`

- [ ] **Step 3: Write the parser**

`src/tessera/proxyproto.py`:

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_proxyproto.py -v`
Expected: PASS, 13 passed

- [ ] **Step 5: Commit**

```bash
git add src/tessera/proxyproto.py tests/test_proxyproto.py
git commit -m "feat(net): PROXY protocol v2 stream header parsing, v1 refused"
```

---

## Task 9: Per-IP and global token-bucket rate limiting

**Lane:** C — HTTP core. **Depends on:** Task 1.

**Files:**
- Create: `src/tessera/ratelimit.py`, `tests/test_ratelimit.py`

**Interfaces:**
- Consumes: `tessera.config.TesseraConfig` fields `ip_slots`, `ip_burst`, `ip_refill_secs`, `global_burst`, `global_refill_secs`.
- Produces:
  - `tessera.ratelimit.TokenBucketLimiter(*, slots: int, burst: int, refill_secs: float, global_burst: int, global_refill_secs: float)`
  - `TokenBucketLimiter.allow(ip: str, now: float) -> bool` — consumes one token from both the per-IP and the global bucket, or consumes nothing and returns False.
  - `TokenBucketLimiter.from_config(cfg: TesseraConfig) -> TokenBucketLimiter`
  - `TokenBucketLimiter.tracked() -> int`

- [ ] **Step 1: Write the failing test**

`tests/test_ratelimit.py`:

```python
from __future__ import annotations

from tessera.config import TesseraConfig
from tessera.ratelimit import TokenBucketLimiter

IP_A = "203.0.113.9"
IP_B = "198.51.100.4"


def limiter(**kwargs) -> TokenBucketLimiter:
    args = dict(slots=8, burst=3, refill_secs=1.0, global_burst=100, global_refill_secs=0.01)
    args.update(kwargs)
    return TokenBucketLimiter(**args)


def test_a_cold_address_may_burst_then_is_refused() -> None:
    rl = limiter()
    assert [rl.allow(IP_A, 0.0) for _ in range(3)] == [True, True, True]
    assert rl.allow(IP_A, 0.0) is False


def test_a_refused_request_consumes_nothing_from_the_global_bucket() -> None:
    rl = limiter(global_burst=10, global_refill_secs=1000.0)
    for _ in range(3):
        rl.allow(IP_A, 0.0)
    for _ in range(20):
        rl.allow(IP_A, 0.0)          # all refused by the per-IP bucket
    # IP_B must still have the whole global allowance minus IP_A's 3.
    assert [rl.allow(IP_B, 0.0) for _ in range(3)] == [True, True, True]


def test_tokens_come_back_over_time() -> None:
    rl = limiter()
    for _ in range(3):
        rl.allow(IP_A, 0.0)
    assert rl.allow(IP_A, 0.5) is False
    assert rl.allow(IP_A, 1.0) is True
    assert rl.allow(IP_A, 1.0) is False
    assert rl.allow(IP_A, 3.0) is True


def test_a_bucket_never_refills_past_its_burst() -> None:
    rl = limiter()
    rl.allow(IP_A, 0.0)
    assert [rl.allow(IP_A, 10_000.0) for _ in range(3)] == [True, True, True]
    assert rl.allow(IP_A, 10_000.0) is False


def test_addresses_are_independent() -> None:
    rl = limiter()
    for _ in range(3):
        assert rl.allow(IP_A, 0.0) is True
    assert rl.allow(IP_A, 0.0) is False
    assert rl.allow(IP_B, 0.0) is True


def test_the_global_ceiling_stops_a_distributed_flood() -> None:
    rl = limiter(slots=512, burst=100, global_burst=5, global_refill_secs=1000.0)
    allowed = sum(rl.allow(f"203.0.113.{i}", 0.0) for i in range(50))
    assert allowed == 5


def test_the_slot_table_does_not_grow_without_bound() -> None:
    rl = limiter(slots=8, global_burst=10_000, global_refill_secs=0.0001)
    for i in range(200):
        rl.allow(f"10.0.0.{i}", float(i))
    assert rl.tracked() <= 8


def test_evicting_a_slot_does_not_hand_out_free_tokens_to_a_live_flooder() -> None:
    # The evicted slot must be the least recently used, so an address that is
    # hammering keeps its (empty) bucket rather than being forgotten and reset.
    rl = limiter(slots=2, burst=1, refill_secs=1000.0, global_burst=10_000,
                 global_refill_secs=0.0001)
    assert rl.allow(IP_A, 0.0) is True
    assert rl.allow(IP_A, 0.1) is False
    rl.allow("10.0.0.1", 0.2)
    assert rl.allow(IP_A, 0.3) is False, "a flooding address was evicted and reset"


def test_from_config_uses_the_configured_numbers(config: TesseraConfig) -> None:
    rl = TokenBucketLimiter.from_config(config)
    allowed = sum(rl.allow(IP_A, 0.0) for _ in range(config.ip_burst + 5))
    assert allowed == config.ip_burst
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_ratelimit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.ratelimit'`

- [ ] **Step 3: Write the limiter**

`src/tessera/ratelimit.py`:

```python
"""Per-source-address and global token buckets.

Keyed on IP only, never on (IP, port) — an attacker changes source port for
free, so including it would make the limiter trivially bypassable. The address
comes from the PROXY protocol v2 header (proxyproto.py), which is why that
header is a hard requirement rather than a nicety: without it every console
shares the playit relay's address and this becomes one bucket for the world.

Time is passed in rather than read internally so the buckets can be tested
deterministically, exactly as Blocksmith's gateway/ratelimit.c does.

The slot table is bounded and evicts least-recently-used. Bounding it matters:
an unbounded dict keyed on attacker-controlled addresses is itself a memory
exhaustion primitive. Evicting LRU rather than at random matters too — an
address that is actively flooding is by definition recently used, so it keeps
its empty bucket instead of being forgotten and handed a fresh burst.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .config import TesseraConfig


@dataclass
class _Bucket:
    tokens: float
    last: float


class TokenBucketLimiter:
    """One bucket per address, plus a ceiling across all of them."""

    def __init__(
        self,
        *,
        slots: int,
        burst: int,
        refill_secs: float,
        global_burst: int,
        global_refill_secs: float,
    ) -> None:
        self._slots = max(1, int(slots))
        self._burst = float(burst)
        self._refill_secs = float(refill_secs)
        self._global_burst = float(global_burst)
        self._global_refill_secs = float(global_refill_secs)
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._global = _Bucket(tokens=float(global_burst), last=0.0)
        self._global_started = False

    @classmethod
    def from_config(cls, cfg: TesseraConfig) -> TokenBucketLimiter:
        return cls(
            slots=cfg.ip_slots,
            burst=cfg.ip_burst,
            refill_secs=cfg.ip_refill_secs,
            global_burst=cfg.global_burst,
            global_refill_secs=cfg.global_refill_secs,
        )

    def tracked(self) -> int:
        return len(self._buckets)

    @staticmethod
    def _refill(bucket: _Bucket, now: float, burst: float, refill_secs: float) -> None:
        if refill_secs <= 0.0:
            bucket.tokens = burst
        else:
            elapsed = max(0.0, now - bucket.last)
            bucket.tokens = min(burst, bucket.tokens + elapsed / refill_secs)
        bucket.last = now

    def allow(self, ip: str, now: float) -> bool:
        """True if a request from `ip` may proceed, consuming one token from
        the address bucket AND the global bucket. False consumes nothing."""
        if not self._global_started:
            self._global.last = now
            self._global_started = True

        bucket = self._buckets.get(ip)
        if bucket is None:
            if len(self._buckets) >= self._slots:
                self._buckets.popitem(last=False)  # least recently used
            bucket = _Bucket(tokens=self._burst, last=now)
            self._buckets[ip] = bucket
        self._buckets.move_to_end(ip)

        self._refill(bucket, now, self._burst, self._refill_secs)
        if bucket.tokens < 1.0:
            return False

        # Only now is the global bucket touched. Charging it before the
        # per-address check would let one flooding address drain the ceiling
        # for everybody with requests that were going to be refused anyway.
        self._refill(self._global, now, self._global_burst, self._global_refill_secs)
        if self._global.tokens < 1.0:
            return False

        bucket.tokens -= 1.0
        self._global.tokens -= 1.0
        return True
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_ratelimit.py -v`
Expected: PASS, 9 passed

- [ ] **Step 5: Commit**

```bash
git add src/tessera/ratelimit.py tests/test_ratelimit.py
git commit -m "feat(net): bounded LRU per-IP token buckets with a global ceiling"
```

---

## Task 10: HTTP server, router, body limits, entrypoint

**Lane:** C — HTTP core. **Depends on:** Tasks 8 and 9.

**Files:**
- Create: `src/tessera/http_server.py`, `src/tessera/main.py`, `tests/test_http_core.py`
- Modify: `tests/conftest.py` (add the live-server fixture and the signing client)

**Interfaces:**
- Consumes: `tessera.config`, `tessera.db`, `tessera.store`, `tessera.hydro`, `tessera.replay`, `tessera.proxyproto`, `tessera.ratelimit`.
- Produces:
  - `tessera.http_server.Response` — frozen dataclass `(status: int, body: bytes, content_type: str = "application/json", headers: tuple[tuple[str, str], ...] = ())`.
  - `tessera.http_server.json_response(status: int, payload: dict) -> Response`
  - `tessera.http_server.error(status: int, code: str, detail: str = "") -> Response`
  - `tessera.http_server.RequestContext` — frozen dataclass `(method, path, raw_target, query: dict[str, list[str]], body: bytes, headers, client_ip: str, identity: SignedIdentity | None)`.
  - `tessera.http_server.TesseraApp` — holds `cfg`, `conn`, `store`, `hydro`, `replay`, `limiter`, `routes`, and `now() -> int`.
  - `tessera.http_server.route(method: str, pattern: str)` — decorator registering into `ROUTES`.
  - `tessera.http_server.make_server(app: TesseraApp) -> ThreadingHTTPServer`
  - `tessera.http_server.build_app(cfg: TesseraConfig) -> TesseraApp`
  - `tessera.main.main(argv: list[str] | None = None) -> int`

- [ ] **Step 1: Write the failing test**

`tests/test_http_core.py`:

```python
from __future__ import annotations

import json

import pytest

from tessera.proxyproto import build_ppv2_header


def test_the_server_answers_browse_on_an_empty_gallery(client) -> None:
    status, headers, body = client.get("/browse")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    payload = json.loads(body)
    assert payload["items"] == []
    assert payload["total"] == 0


def test_an_unknown_path_is_404_json(client) -> None:
    status, headers, body = client.get("/does-not-exist")
    assert status == 404
    assert json.loads(body)["error"] == "not_found"


def test_a_wrong_method_is_405(client) -> None:
    status, _, body = client.request("DELETE", "/browse", b"")
    assert status == 405
    assert json.loads(body)["error"] == "method_not_allowed"


def test_a_body_over_the_ceiling_is_413_and_is_not_read(client) -> None:
    huge = b"x" * (client.config.max_request_bytes + 1)
    status, _, body = client.request("POST", "/upload", huge, expect_early_close=True)
    assert status == 413
    assert json.loads(body)["error"] == "too_large"


def test_a_missing_content_length_on_a_post_is_411(client) -> None:
    status, _, body = client.raw_request(
        b"POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    assert status == 411
    assert json.loads(body)["error"] == "length_required"


def test_the_server_never_advertises_what_it_is(client) -> None:
    _, headers, _ = client.get("/browse")
    assert "Server" not in headers or headers["Server"] == "tessera"
    assert "X-Powered-By" not in headers


def test_security_headers_are_present_on_every_answer(client) -> None:
    _, headers, _ = client.get("/browse")
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_the_rate_limiter_eventually_refuses(client) -> None:
    statuses = [client.get("/browse")[0] for _ in range(client.config.ip_burst + 10)]
    assert 429 in statuses, "the per-IP limiter never fired"
    assert statuses[0] == 200


def test_proxy_protocol_off_means_a_ppv2_prefix_is_a_bad_request(client) -> None:
    status, _, _ = client.raw_request(
        build_ppv2_header("203.0.113.9", 4242) + b"GET /browse HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    assert status == 400


def test_proxy_protocol_on_reads_the_real_client_address(pp_client) -> None:
    # Each simulated address gets its own bucket, so 3 x burst all succeed.
    for octet in (1, 2, 3):
        statuses = [
            pp_client.get("/browse", src_ip=f"203.0.113.{octet}")[0]
            for _ in range(pp_client.config.ip_burst)
        ]
        assert statuses.count(200) == pp_client.config.ip_burst


def test_proxy_protocol_on_refuses_a_connection_with_no_header(pp_client) -> None:
    status, _, _ = pp_client.raw_request(
        b"GET /browse HTTP/1.1\r\nHost: x\r\n\r\n", with_ppv2=False
    )
    assert status in (400, 0), "a missing PROXY header must not be served"


def test_the_daemon_writes_a_pid_and_dies_cleanly(live_server) -> None:
    assert live_server.process.poll() is None
    live_server.stop()
    assert live_server.process.poll() is not None
```

- [ ] **Step 2: Extend conftest.py with the live-server fixture and a signing client**

Append to `tests/conftest.py`:

```python
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
        self.use_ppv2 = use_ppv2
        self._nonce = 0

    # -- low level --------------------------------------------------------

    def raw_request(self, payload: bytes, *, with_ppv2: bool | None = None,
                    src_ip: str = "203.0.113.9") -> tuple[int, dict[str, str], bytes]:
        prefix = b""
        want = self.use_ppv2 if with_ppv2 is None else with_ppv2
        if want:
            prefix = build_ppv2_header(src_ip, 40000, "127.0.0.1", self.server.port)
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=10) as sock:
            sock.sendall(prefix + payload)
            chunks = []
            while True:
                chunk = sock.recv(65536)
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
        return self.raw_request(payload, src_ip=src_ip)

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
def admin_client(tmp_path: Path, state_dir: Path, hydro_library_path: Path):
    """A live server that already trusts one admin key. Yields (client, pk, sk)."""
    hydro = Hydro(hydro_library_path)
    pk, sk = hydro.keygen()
    server = _start(tmp_path, state_dir, hydro_library_path, {"admin_keys": [pk.hex()]})
    yield Client(server, hydro, use_ppv2=False), pk, sk
    server.stop()
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_http_core.py -v`
Expected: FAIL — the fixture raises `RuntimeError: daemon exited early` with `No module named tessera.main` in the captured output.

- [ ] **Step 4: Write the HTTP server**

`src/tessera/http_server.py`:

```python
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
from .signing import SignedIdentity
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


@dataclass
class TesseraApp:
    cfg: TesseraConfig
    conn: Any
    store: BlobStore
    hydro: Hydro
    replay: ReplayWindow
    limiter: TokenBucketLimiter
    routes: list[tuple[str, re.Pattern[str], Handler]] = field(default_factory=lambda: ROUTES)

    def now(self) -> int:
        return int(time.time())


def build_app(cfg: TesseraConfig) -> TesseraApp:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(cfg.db_path)
    migrate(conn)
    hydro = Hydro(cfg.hydro_library)
    store = BlobStore(cfg.blob_dir, lambda data: hydro.hash32(data, cfg.sign_context))
    replay = ReplayWindow(conn)
    replay.ensure_table()
    return TesseraApp(
        cfg=cfg,
        conn=conn,
        store=store,
        hydro=hydro,
        replay=replay,
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
            self._refuse("proxy header required from an untrusted peer")
            return
        try:
            self._client_ip, _ = read_ppv2_header(self.rfile)
        except ProxyProtocolError as exc:
            self._refuse(f"bad PROXY protocol header: {exc}")

    def _refuse(self, detail: str) -> None:
        try:
            body = json.dumps({"error": "bad_proxy_header", "detail": detail}).encode()
            self.wfile.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True

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

    def _dispatch(self) -> None:
        app: TesseraApp = self.server.app  # type: ignore[attr-defined]

        if len(self.path) > MAX_REQUEST_LINE:
            self._send(error(414, "uri_too_long"))
            return

        split = urlsplit(self.path)
        path = split.path
        query = parse_qs(split.query, keep_blank_values=True)

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
```

Note: `handlers_admin` and `handlers_social` do not exist until Lane E. Until then create both as one-line files containing `"""Placeholder until Task 16."""` — no, do **not** do that. Instead, in this task write the import as `from . import handlers_content  # noqa: F401` and Task 16 extends it. The line above is the finished state; Task 16's Step 1 is the edit that reaches it.

- [ ] **Step 5: Write the entrypoint**

`src/tessera/main.py`:

```python
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
```

- [ ] **Step 6: Add a temporary /browse so the core tests have a route**

`/browse` is properly implemented in Task 13. This task needs one registered route to prove dispatch works, so create `src/tessera/handlers_content.py` now with only that route; Task 12 and Task 13 replace and extend it.

```python
"""Content endpoints: upload, browse, download. Extended by Tasks 12-14."""

from __future__ import annotations

from .http_server import RequestContext, Response, TesseraApp, json_response, route


@route("GET", r"/browse")
def handle_browse(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    rows = app.conn.execute(
        "SELECT id, title, author_key, kind, thumb_hash, score, created_at"
        " FROM models WHERE visibility = 'public' ORDER BY created_at DESC LIMIT ?",
        (app.cfg.browse_page_size,),
    ).fetchall()
    total = app.conn.execute(
        "SELECT COUNT(*) FROM models WHERE visibility = 'public'"
    ).fetchone()[0]
    return json_response(200, {"page": 1, "per_page": app.cfg.browse_page_size,
                               "total": int(total), "items": [dict(row) for row in rows]})
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_http_core.py -v`
Expected: PASS, 12 passed

If `test_the_rate_limiter_eventually_refuses` does not see a 429, the defaults in `config.py` are too generous for a burst of `ip_burst + 10` — check `ip_refill_secs` is not being satisfied by the time each request takes. Do not raise the burst to make the test pass; that is the fix that hides the measurement.

- [ ] **Step 8: Run everything built so far**

Run: `make test`
Expected: PASS, 79 passed (Task 1: 6, Lane A: 40, Lane B: 45 minus the 14+21+10 already counted... report the real number and record it in the commit message rather than trusting this estimate).

- [ ] **Step 9: Commit**

```bash
git add src/tessera/http_server.py src/tessera/main.py src/tessera/handlers_content.py \
        tests/test_http_core.py tests/conftest.py
git commit -m "feat(http): threading HTTP server, router, body ceilings, PPv2 wiring"
```

---

## Task 11: Signed-request middleware at the HTTP layer

**Lane:** D — Phase 7 endpoints. **Depends on:** Lanes A, B and C complete (Tasks 3, 4, 5, 10).

**Files:**
- Modify: `src/tessera/http_server.py`
- Create: `tests/test_signing_redarm.py`
- Modify: `tests/test_http_core.py` (add the signed-route cases)

**Interfaces:**
- Consumes: `tessera.signing.verify_signed_request`, `tessera.signing.SignatureError`.
- Produces:
  - `tessera.http_server.signed_route(method: str, pattern: str, *, admin: bool = False)` — decorator that registers a route whose handler is only reached after `verify_signed_request` succeeds, and (with `admin=True`) only if `identity.is_admin`.
  - `RequestContext.identity` is non-None inside any handler registered with `signed_route`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_http_core.py`:

```python
def test_a_signed_route_rejects_an_unsigned_request(client) -> None:
    status, _, body = client.request("POST", "/vote", b"{}")
    assert status == 400
    assert json.loads(body)["error"] == "malformed_signature"


def test_a_signed_route_rejects_a_forged_signature(client) -> None:
    pk, sk = client.keypair()
    body = b'{"model_id":1,"value":1}'
    headers = client.sign_headers("POST", "/vote", body, pk, sk)
    forged = bytearray(bytes.fromhex(headers["X-Tessera-Sig"]))
    forged[3] ^= 0xFF
    headers["X-Tessera-Sig"] = bytes(forged).hex()
    status, _, raw = client.request("POST", "/vote", body, headers=headers)
    assert status == 401
    assert json.loads(raw)["error"] == "bad_signature"


def test_a_signed_route_rejects_a_replayed_request(client) -> None:
    pk, sk = client.keypair()
    body = b'{"model_id":1,"value":1}'
    headers = client.sign_headers("POST", "/vote", body, pk, sk)
    first, _, _ = client.request("POST", "/vote", body, headers=headers)
    second, _, raw = client.request("POST", "/vote", body, headers=headers)
    assert first != 409, "the first attempt should not be a replay"
    assert second == 409
    assert json.loads(raw)["error"] == "replayed"


def test_a_signed_route_rejects_a_stale_timestamp(client) -> None:
    pk, sk = client.keypair()
    body = b"{}"
    stale = int(time.time()) - (client.config.replay_window_secs + 60)
    headers = client.sign_headers("POST", "/vote", body, pk, sk, timestamp=stale)
    status, _, raw = client.request("POST", "/vote", body, headers=headers)
    assert status == 401
    assert json.loads(raw)["error"] == "stale_timestamp"


def test_an_admin_route_refuses_an_ordinary_key(client) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 403
    assert json.loads(raw)["error"] == "not_admin"


def test_an_admin_route_accepts_the_configured_admin_key(admin_client) -> None:
    client, pk, sk = admin_client
    status, _, _ = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 200
```

Add `import time` to the imports at the top of `tests/test_http_core.py`.

`tests/test_signing_redarm.py` — the proof that the signature check is what does the rejecting:

```python
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
    assert post_forged(port) in (401, 400), "a forged request was not rejected"

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_http_core.py tests/test_signing_redarm.py -v`
Expected: FAIL — the `/vote` and `/admin/reports` cases return 404 because no signed route exists, and `test_the_signature_gate_is_what_rejects_the_forgery` fails on the same 404.

- [ ] **Step 3: Add the middleware to http_server.py**

Add to the imports in `src/tessera/http_server.py`:

```python
from .signing import SignatureError, SignedIdentity, verify_signed_request
```

Add after the `route` definition:

```python
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
```

Note the module-level name `verify_signed_request` is imported rather than dotted (`signing.verify_signed_request`) on purpose: the red-arm test monkeypatches `tessera.http_server.verify_signed_request`, which only works if the wrapper looks the name up in this module's globals at call time. It does, because the lookup happens inside `wrapper` when the request arrives.

- [ ] **Step 4: Add the two stub routes the middleware tests need**

These are replaced by their real implementations in Tasks 16 and 20. They exist now so the middleware can be tested on its own, which is the whole point of a separate task.

Append to `src/tessera/handlers_content.py`:

```python
from .http_server import signed_route


@signed_route("POST", r"/vote")
def handle_vote_placeholder(app, ctx, params):
    """Replaced by handlers_social.handle_vote in Task 16."""
    return json_response(200, {"ok": True, "key": ctx.identity.key_hex})


@signed_route("GET", r"/admin/reports", admin=True)
def handle_admin_reports_placeholder(app, ctx, params):
    """Replaced by handlers_admin.handle_admin_reports in Task 20."""
    return json_response(200, {"reports": []})
```

Task 16 and Task 20 **delete these two functions** as their first step. They are named `_placeholder` so a stray one is obvious in a grep.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_http_core.py tests/test_signing_redarm.py -v`
Expected: PASS, 19 passed (12 from Task 10, 6 new, 1 red-arm).

- [ ] **Step 6: Read the red-arm test's actual output**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_signing_redarm.py -v -s`
Confirm the test passes *and* that it is genuinely doing both halves — add `print(f"armed={armed} disarmed={disarmed}")` temporarily and read the line. Expected: `armed=401 disarmed=200`. Record those two numbers in the commit message. If disarmed is also 401, the monkeypatch is not reaching the code path and the test is proving nothing.

- [ ] **Step 7: Commit**

```bash
git add src/tessera/http_server.py src/tessera/handlers_content.py \
        tests/test_http_core.py tests/test_signing_redarm.py
git commit -m "feat(http): signed_route middleware with admin gating

Red-arm measured: armed=401, disarmed=200 — the 401 comes from the
signature check and nothing else."
```

---

## Task 12: POST /upload

**Lane:** D — Phase 7 endpoints. **Depends on:** Tasks 6, 7, 11.

**Files:**
- Modify: `src/tessera/handlers_content.py`
- Create: `src/tessera/envelope.py`, `tests/test_upload.py`

**Interfaces:**
- Consumes: `BlobStore.put`, `check_upload_allowed`, `signed_route`.
- Produces:
  - `tessera.envelope.UPLOAD_MAGIC = b"TSU1"`
  - `tessera.envelope.EnvelopeError(ValueError)`
  - `tessera.envelope.UploadEnvelope` — frozen dataclass `(title: str, kind: str, model: bytes, thumb: bytes)`.
  - `tessera.envelope.parse_upload(body: bytes, cfg: TesseraConfig) -> UploadEnvelope`
  - `tessera.envelope.build_upload(title: str, kind: str, model: bytes, thumb: bytes) -> bytes` — test and client-reference helper.
  - Route `POST /upload` returning `{"id": int, "model_hash": str, "thumb_hash": str}` with status 201.

- [ ] **Step 1: Write the failing test**

`tests/test_upload.py`:

```python
from __future__ import annotations

import json

import pytest

from tessera.envelope import build_upload

MODEL = b'{"faces":[],"palette":"pico8"}'
THUMB = b"\x89PNG\r\n\x1a\n" + b"\x00" * 96


def upload(client, pk, sk, *, title="A hexagon", kind="model", model=MODEL, thumb=THUMB, **kw):
    body = build_upload(title, kind, model, thumb)
    status, headers, raw = client.signed("POST", "/upload", body, pk, sk, **kw)
    return status, (json.loads(raw) if raw else {})


def test_a_valid_upload_is_accepted_and_indexed(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk)
    assert status == 201
    assert len(payload["model_hash"]) == 64
    assert len(payload["thumb_hash"]) == 64
    assert payload["id"] >= 1

    status, _, raw = client.get("/browse")
    items = json.loads(raw)["items"]
    assert len(items) == 1
    assert items[0]["title"] == "A hexagon"
    assert items[0]["author_key"] == pk.hex()


def test_the_stored_bytes_come_back_identical(client) -> None:
    pk, sk = client.keypair()
    _, payload = upload(client, pk, sk)
    status, headers, raw = client.get(f"/model/{payload['id']}")
    assert status == 200
    assert raw == MODEL


def test_an_unsigned_upload_is_refused(client) -> None:
    status, _, raw = client.request("POST", "/upload", build_upload("t", "model", MODEL, THUMB))
    assert status == 400
    assert json.loads(raw)["error"] == "malformed_signature"


def test_the_ninth_upload_in_a_day_is_refused(client) -> None:
    pk, sk = client.keypair()
    for i in range(client.config.uploads_per_key_per_day):
        status, _ = upload(client, pk, sk, title=f"piece {i}", model=MODEL + bytes([i]))
        assert status == 201, f"upload {i} was refused"
    status, payload = upload(client, pk, sk, title="one too many", model=MODEL + b"\xff")
    assert status == 429
    assert payload["error"] == "daily_quota"


def test_another_key_is_unaffected_by_the_first_keys_quota(client) -> None:
    pk_a, sk_a = client.keypair()
    for i in range(client.config.uploads_per_key_per_day):
        upload(client, pk_a, sk_a, model=MODEL + bytes([i]))
    pk_b, sk_b = client.keypair()
    status, _ = upload(client, pk_b, sk_b, model=MODEL + b"\xfe")
    assert status == 201


def test_a_banned_key_is_refused(client) -> None:
    pk, sk = client.keypair()
    upload(client, pk, sk)
    # Ban through the database directly; the admin path is Task 20.
    import sqlite3
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    status, payload = upload(client, pk, sk, model=MODEL + b"\x01")
    assert status == 403
    assert payload["error"] == "banned"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"", "bad_envelope"),
        (b"NOPE" + b"\x00" * 12, "bad_envelope"),
        (b"TSU1" + (999999).to_bytes(4, "little") * 3, "bad_envelope"),
        (b"TSU1" + b"\x00" * 8, "bad_envelope"),
    ],
)
def test_a_malformed_envelope_is_400(client, body: bytes, expected: str) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == expected


def test_an_oversized_model_is_refused(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, model=b"m" * (client.config.max_model_bytes + 1))
    assert status == 400
    assert payload["error"] == "bad_envelope"


def test_an_oversized_thumbnail_is_refused(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, thumb=b"t" * (client.config.max_thumb_bytes + 1))
    assert status == 400
    assert payload["error"] == "bad_envelope"


def test_a_body_past_the_http_ceiling_never_reaches_the_handler(client) -> None:
    pk, sk = client.keypair()
    body = build_upload("t", "model", b"m" * (client.config.max_request_bytes), THUMB)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 413


def test_a_bad_kind_is_refused(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, kind="sculpture")
    assert status == 400
    assert payload["error"] == "bad_envelope"


def test_an_empty_title_is_refused_and_a_long_one_is_truncated_not_rejected(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, title="")
    assert status == 400
    status, payload = upload(client, pk, sk, title="x" * 500, model=MODEL + b"\x02")
    assert status == 201


def test_uploading_identical_bytes_twice_is_a_conflict_not_a_duplicate_row(client) -> None:
    pk, sk = client.keypair()
    first_status, first = upload(client, pk, sk)
    second_status, second = upload(client, pk, sk)
    assert first_status == 201
    assert second_status == 409
    assert second["error"] == "duplicate"
    status, _, raw = client.get("/browse")
    assert json.loads(raw)["total"] == 1


def test_a_title_with_control_characters_is_rejected(client) -> None:
    pk, sk = client.keypair()
    status, payload = upload(client, pk, sk, title="bad\x00title")
    assert status == 400
    assert payload["error"] == "bad_envelope"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_upload.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tessera.envelope'`

- [ ] **Step 3: Write the envelope parser**

`src/tessera/envelope.py`:

```python
"""The upload wire format.

A fixed-layout binary envelope rather than multipart/form-data. Multipart
means a boundary scanner, quoted-string header parsing, filename handling and
a state machine — all of it parsing attacker-controlled text, all of it
surface this service has no use for. This format has four integers and three
byte ranges, and it is trivial for the 3DS client to emit with fwrite.

Layout, little-endian throughout:

    offset  size  field
    0       4     magic, b"TSU1"
    4       4     meta_len   (uint32)
    8       4     model_len  (uint32)
    12      4     thumb_len  (uint32)
    16      meta_len   UTF-8 JSON: {"title": str, "kind": "pixel"|"model"}
    ...     model_len  the project file, OPAQUE
    ...     thumb_len  the console-rendered thumbnail, OPAQUE

The model and thumb ranges are never looked at. Not decoded, not sniffed, not
validated beyond their length. That is spec section 5.6 and it is the single
most important line in this file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .config import TesseraConfig

UPLOAD_MAGIC = b"TSU1"
HEADER_BYTES = 16
MAX_META_BYTES = 4096
MAX_TITLE_CHARS = 64
VALID_KINDS = frozenset({"pixel", "model"})


class EnvelopeError(ValueError):
    """The upload envelope is malformed. Always answered with 400."""


@dataclass(frozen=True)
class UploadEnvelope:
    title: str
    kind: str
    model: bytes
    thumb: bytes


def _clean_title(raw: object) -> str:
    if not isinstance(raw, str):
        raise EnvelopeError("title must be a string")
    # Control characters would end up in JSON responses and in the moderation
    # CLI's terminal output. Rejected rather than stripped, because a title
    # that silently changes is a title the uploader cannot recognise.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise EnvelopeError("title contains control characters")
    title = raw.strip()
    if not title:
        raise EnvelopeError("title is empty")
    return title[:MAX_TITLE_CHARS]


def parse_upload(body: bytes, cfg: TesseraConfig) -> UploadEnvelope:
    """Parse and length-check an upload envelope, or raise EnvelopeError."""
    if len(body) < HEADER_BYTES:
        raise EnvelopeError("body is shorter than the envelope header")
    if body[0:4] != UPLOAD_MAGIC:
        raise EnvelopeError("bad magic")

    meta_len = int.from_bytes(body[4:8], "little")
    model_len = int.from_bytes(body[8:12], "little")
    thumb_len = int.from_bytes(body[12:16], "little")

    # Checked against the configured ceilings BEFORE any slicing, so an
    # absurd declared length is rejected rather than producing a short slice
    # that silently truncates the upload.
    if meta_len > MAX_META_BYTES:
        raise EnvelopeError(f"metadata is {meta_len} bytes, the limit is {MAX_META_BYTES}")
    if model_len > cfg.max_model_bytes:
        raise EnvelopeError(f"model is {model_len} bytes, the limit is {cfg.max_model_bytes}")
    if thumb_len > cfg.max_thumb_bytes:
        raise EnvelopeError(f"thumbnail is {thumb_len} bytes, the limit is {cfg.max_thumb_bytes}")

    expected = HEADER_BYTES + meta_len + model_len + thumb_len
    if len(body) != expected:
        raise EnvelopeError(f"declared lengths sum to {expected} but the body is {len(body)}")

    meta_start = HEADER_BYTES
    model_start = meta_start + meta_len
    thumb_start = model_start + model_len

    try:
        meta = json.loads(body[meta_start:model_start].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"metadata is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise EnvelopeError("metadata must be a JSON object")

    kind = meta.get("kind")
    if kind not in VALID_KINDS:
        raise EnvelopeError(f"kind must be one of {sorted(VALID_KINDS)}")

    if model_len == 0:
        raise EnvelopeError("model is empty")
    if thumb_len == 0:
        raise EnvelopeError("thumbnail is empty")

    return UploadEnvelope(
        title=_clean_title(meta.get("title")),
        kind=kind,
        model=body[model_start:thumb_start],
        thumb=body[thumb_start:],
    )


def build_upload(title: str, kind: str, model: bytes, thumb: bytes) -> bytes:
    """Construct an envelope. The reference the 3DS client is written against."""
    meta = json.dumps({"title": title, "kind": kind}, separators=(",", ":")).encode("utf-8")
    return (
        UPLOAD_MAGIC
        + len(meta).to_bytes(4, "little")
        + len(model).to_bytes(4, "little")
        + len(thumb).to_bytes(4, "little")
        + meta
        + model
        + thumb
    )
```

- [ ] **Step 4: Write the upload handler**

Replace the contents of `src/tessera/handlers_content.py` with (keeping the two `_placeholder` routes from Task 11 at the bottom for now):

```python
"""Content endpoints: upload, browse, download.

Nothing in this module inspects an uploaded byte. `envelope.parse_upload`
splits the body on declared lengths, the blob store hashes and writes it, and
the download handlers read it back and hand it over. There is no decode step
to attack (spec section 5.6).
"""

from __future__ import annotations

import sqlite3

from .envelope import EnvelopeError, parse_upload
from .http_server import (
    RequestContext,
    Response,
    TesseraApp,
    error,
    json_response,
    route,
    signed_route,
)
from .quota import QuotaError, check_upload_allowed


@signed_route("POST", r"/upload")
def handle_upload(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None  # guaranteed by signed_route
    try:
        envelope = parse_upload(ctx.body, app.cfg)
    except EnvelopeError as exc:
        return error(400, "bad_envelope", str(exc))

    now = app.now()
    try:
        check_upload_allowed(
            conn=app.conn,
            store=app.store,
            cfg=app.cfg,
            author_key=ctx.identity.key_hex,
            incoming_bytes=len(envelope.model) + len(envelope.thumb),
            now=now,
        )
    except QuotaError as exc:
        return error(exc.status, exc.code, exc.detail)

    model_hash = app.store.put(envelope.model)
    thumb_hash = app.store.put(envelope.thumb)

    try:
        cursor = app.conn.execute(
            "INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,"
            " model_bytes, thumb_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                model_hash, thumb_hash, envelope.title, ctx.identity.key_hex, envelope.kind,
                len(envelope.model), len(envelope.thumb), now,
            ),
        )
    except sqlite3.IntegrityError:
        # The UNIQUE on model_hash. The blobs are already stored and shared
        # with the existing row, so nothing is orphaned by returning here.
        return error(409, "duplicate", "these exact bytes are already in the gallery")

    return json_response(
        201, {"id": int(cursor.lastrowid), "model_hash": model_hash, "thumb_hash": thumb_hash}
    )
```

Then append the `/browse` handler from Task 10 Step 6 unchanged, and the two `_placeholder` routes from Task 11 Step 4 unchanged.

- [ ] **Step 5: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_upload.py -v`
Expected: PASS, 17 passed (the envelope `parametrize` contributes 4).

`test_the_stored_bytes_come_back_identical` will fail until Task 14 adds `GET /model/{id}`. Mark it `@pytest.mark.xfail(reason="GET /model lands in Task 14", strict=True)` here, and **delete that marker in Task 14 Step 5** — a strict xfail turns into a failure the moment the endpoint works, so it cannot be forgotten.

- [ ] **Step 6: Prove the quota check can go red**

1. Temporarily comment out the `check_upload_allowed(...)` call in `handle_upload`.
2. Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_upload.py -v`
3. Expected: **2 failures** — `test_the_ninth_upload_in_a_day_is_refused` and `test_a_banned_key_is_refused`.
4. `git checkout -- src/tessera/handlers_content.py`, re-run: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/tessera/envelope.py src/tessera/handlers_content.py tests/test_upload.py
git commit -m "feat(api): POST /upload with a fixed-layout envelope, quotas enforced

Sabotage arm: removing check_upload_allowed turns the daily-quota and
banned-key tests red."
```

---

## Task 13: GET /browse — paging and sorting

**Lane:** D — Phase 7 endpoints. **Depends on:** Task 12.

**Files:**
- Modify: `src/tessera/handlers_content.py`
- Create: `tests/test_browse.py`

**Interfaces:**
- Consumes: the `models` table, `cfg.browse_page_size`, `cfg.browse_max_page_size`.
- Produces: `GET /browse?page=N&per_page=M&sort=new|top&kind=pixel|model` returning
  `{"page": int, "per_page": int, "total": int, "items": [{"id", "title", "author_key", "kind", "thumb_hash", "score", "up_votes", "down_votes", "created_at"}]}`.
  Unsigned — browsing is public and read-only.

- [ ] **Step 1: Write the failing test**

`tests/test_browse.py`:

```python
from __future__ import annotations

import json

import pytest

from tessera.envelope import build_upload

THUMB = b"thumbnail-bytes"


def seed(client, count: int, kind: str = "model") -> list[int]:
    ids = []
    for i in range(count):
        pk, sk = client.keypair()
        body = build_upload(f"piece {i:02d}", kind, f"model-{i}".encode(), THUMB + bytes([i]))
        status, _, raw = client.signed("POST", "/upload", body, pk, sk)
        assert status == 201, raw
        ids.append(json.loads(raw)["id"])
    return ids


def browse(client, query: str = "") -> dict:
    status, _, raw = client.get("/browse" + query)
    assert status == 200, raw
    return json.loads(raw)


def test_browse_is_public_and_needs_no_signature(client) -> None:
    seed(client, 1)
    assert browse(client)["total"] == 1


def test_default_paging_uses_the_configured_page_size(client) -> None:
    seed(client, client.config.browse_page_size + 5)
    page = browse(client)
    assert page["page"] == 1
    assert page["per_page"] == client.config.browse_page_size
    assert len(page["items"]) == client.config.browse_page_size
    assert page["total"] == client.config.browse_page_size + 5


def test_the_second_page_holds_the_remainder_with_no_overlap(client) -> None:
    seed(client, 25)
    first = browse(client, "?page=1&per_page=20")
    second = browse(client, "?page=2&per_page=20")
    assert len(first["items"]) == 20
    assert len(second["items"]) == 5
    assert not {item["id"] for item in first["items"]} & {item["id"] for item in second["items"]}


def test_a_page_past_the_end_is_empty_not_an_error(client) -> None:
    seed(client, 3)
    page = browse(client, "?page=99")
    assert page["items"] == []
    assert page["total"] == 3


def test_per_page_is_clamped_to_the_maximum(client) -> None:
    seed(client, 3)
    page = browse(client, f"?per_page={client.config.browse_max_page_size + 500}")
    assert page["per_page"] == client.config.browse_max_page_size


@pytest.mark.parametrize("query", ["?page=0", "?page=-1", "?page=abc", "?per_page=0",
                                   "?per_page=-5", "?per_page=xyz", "?sort=sideways"])
def test_nonsense_query_parameters_fall_back_to_defaults(client, query: str) -> None:
    seed(client, 2)
    page = browse(client, query)
    assert page["page"] >= 1
    assert 1 <= page["per_page"] <= client.config.browse_max_page_size


def test_sort_new_is_newest_first(client) -> None:
    seed(client, 4)
    items = browse(client, "?sort=new")["items"]
    created = [item["created_at"] for item in items]
    ids = [item["id"] for item in items]
    assert created == sorted(created, reverse=True)
    assert ids == sorted(ids, reverse=True)


def test_sort_top_is_highest_score_first(client) -> None:
    ids = seed(client, 3)
    import sqlite3
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET score = 5 WHERE id = ?", (ids[0],))
    conn.execute("UPDATE models SET score = -2 WHERE id = ?", (ids[1],))
    conn.commit()
    conn.close()
    items = browse(client, "?sort=top")["items"]
    assert [item["score"] for item in items] == [5, 0, -2]


def test_kind_filters_the_list(client) -> None:
    seed(client, 2, kind="model")
    seed(client, 3, kind="pixel")
    assert browse(client, "?kind=pixel")["total"] == 3
    assert browse(client, "?kind=model")["total"] == 2
    assert browse(client, "")["total"] == 5


def test_unlisted_and_deleted_models_never_appear(client) -> None:
    ids = seed(client, 3)
    import sqlite3
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'unlisted' WHERE id = ?", (ids[0],))
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (ids[1],))
    conn.commit()
    conn.close()
    page = browse(client)
    assert page["total"] == 1
    assert [item["id"] for item in page["items"]] == [ids[2]]


def test_the_listed_fields_are_exactly_the_documented_set(client) -> None:
    seed(client, 1)
    item = browse(client)["items"][0]
    assert set(item) == {
        "id", "title", "author_key", "kind", "thumb_hash",
        "score", "up_votes", "down_votes", "created_at",
    }
    assert "model_hash" not in item  # the download endpoint resolves it, not the list
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_browse.py -v`
Expected: several failures — no paging, no sorting, no `kind` filter, and the field set is wrong.

- [ ] **Step 3: Replace the browse handler**

In `src/tessera/handlers_content.py`, replace `handle_browse` with:

```python
BROWSE_FIELDS = (
    "id", "title", "author_key", "kind", "thumb_hash",
    "score", "up_votes", "down_votes", "created_at",
)

_SORTS = {
    "new": "created_at DESC, id DESC",
    "top": "score DESC, created_at DESC, id DESC",
}


def _positive_int(values: list[str] | None, default: int, maximum: int) -> int:
    """Query parameters are attacker-controlled. Anything unusable becomes the
    default rather than an error — a browse request is not the place to teach
    someone which inputs the parser dislikes."""
    if not values:
        return default
    try:
        parsed = int(values[0], 10)
    except ValueError:
        return default
    if parsed < 1:
        return default
    return min(parsed, maximum)


@route("GET", r"/browse")
def handle_browse(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    page = _positive_int(ctx.query.get("page"), 1, 1_000_000)
    per_page = _positive_int(
        ctx.query.get("per_page"), app.cfg.browse_page_size, app.cfg.browse_max_page_size
    )
    sort = _SORTS.get((ctx.query.get("sort") or ["new"])[0], _SORTS["new"])

    kind = (ctx.query.get("kind") or [""])[0]
    where = "visibility = 'public'"
    args: list[object] = []
    if kind in {"pixel", "model"}:
        where += " AND kind = ?"
        args.append(kind)

    total = int(app.conn.execute(f"SELECT COUNT(*) FROM models WHERE {where}", args).fetchone()[0])
    rows = app.conn.execute(
        f"SELECT {', '.join(BROWSE_FIELDS)} FROM models WHERE {where}"
        f" ORDER BY {sort} LIMIT ? OFFSET ?",
        [*args, per_page, (page - 1) * per_page],
    ).fetchall()

    return json_response(
        200,
        {
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": [dict(row) for row in rows],
        },
    )
```

The f-strings interpolate only `BROWSE_FIELDS`, `where` and `sort`, all of which are built from module constants and a membership test. No request string ever reaches the SQL text — `kind` goes through a parameter, and `sort` is a dictionary lookup that cannot return anything but one of two fixed strings.

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_browse.py -v`
Expected: PASS, 17 passed (the nonsense-parameter `parametrize` contributes 7).

- [ ] **Step 5: Commit**

```bash
git add src/tessera/handlers_content.py tests/test_browse.py
git commit -m "feat(api): GET /browse with paging, sorting, kind filter and visibility"
```

---

## Task 14: GET /model/{id} and GET /thumb/{id}

**Lane:** D — Phase 7 endpoints. **Depends on:** Task 13.

**Files:**
- Modify: `src/tessera/handlers_content.py`, `tests/test_upload.py` (remove the xfail marker)
- Create: `tests/test_download.py`

**Interfaces:**
- Produces: `GET /model/{id}` and `GET /thumb/{id}`, both unsigned, both returning
  `Content-Type: application/octet-stream` with `X-Content-Type-Options: nosniff` and
  `Content-Disposition: attachment`. 404 for an unknown or deleted id.

- [ ] **Step 1: Write the failing test**

`tests/test_download.py`:

```python
from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload

MODEL = b'{"faces":[[0,1,2]],"palette":"db16"}'
THUMB = bytes(range(256))


def upload_one(client) -> int:
    pk, sk = client.keypair()
    status, _, raw = client.signed(
        "POST", "/upload", build_upload("A cube", "model", MODEL, THUMB), pk, sk
    )
    assert status == 201, raw
    return json.loads(raw)["id"]


def test_the_project_file_round_trips_byte_for_byte(client) -> None:
    model_id = upload_one(client)
    status, headers, body = client.get(f"/model/{model_id}")
    assert status == 200
    assert body == MODEL
    assert headers["Content-Length"] == str(len(MODEL))


def test_the_thumbnail_round_trips_byte_for_byte(client) -> None:
    model_id = upload_one(client)
    status, _, body = client.get(f"/thumb/{model_id}")
    assert status == 200
    assert body == THUMB


def test_downloads_are_served_as_opaque_bytes(client) -> None:
    model_id = upload_one(client)
    for path in (f"/model/{model_id}", f"/thumb/{model_id}"):
        _, headers, _ = client.get(path)
        assert headers["Content-Type"] == "application/octet-stream", path
        assert headers["X-Content-Type-Options"] == "nosniff", path
        assert headers["Content-Disposition"].startswith("attachment"), path


def test_downloads_need_no_signature(client) -> None:
    model_id = upload_one(client)
    status, _, _ = client.get(f"/model/{model_id}")
    assert status == 200


@pytest.mark.parametrize("path", ["/model/99999", "/thumb/99999"])
def test_an_unknown_id_is_404(client, path: str) -> None:
    status, _, raw = client.get(path)
    assert status == 404
    assert json.loads(raw)["error"] == "not_found"


@pytest.mark.parametrize(
    "path",
    ["/model/abc", "/model/-1", "/model/1.5", "/model/", "/model/../../etc/passwd",
     "/thumb/%2e%2e%2f", "/model/1;DROP TABLE models"],
)
def test_a_non_numeric_id_never_reaches_the_store(client, path: str) -> None:
    status, _, _ = client.get(path)
    assert status in (404, 400), f"{path} returned {status}"


def test_a_deleted_model_is_404_even_though_the_blob_still_exists(client) -> None:
    model_id = upload_one(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    assert client.get(f"/model/{model_id}")[0] == 404
    assert client.get(f"/thumb/{model_id}")[0] == 404


def test_an_unlisted_model_is_still_downloadable_by_direct_id(client) -> None:
    # Unlisted means "not in the browse list pending review", not "destroyed".
    # Someone who already has the id keeps their copy working; deletion is the
    # action that takes it away.
    model_id = upload_one(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'unlisted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    assert client.get(f"/model/{model_id}")[0] == 200


def test_a_missing_blob_behind_a_present_row_is_404_not_500(client) -> None:
    model_id = upload_one(client)
    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT model_hash FROM models WHERE id = ?", (model_id,)).fetchone()
    conn.close()
    digest = row[0]
    (client.config.blob_dir / digest[0:2] / digest[2:4] / digest).unlink()
    status, _, raw = client.get(f"/model/{model_id}")
    assert status == 404
    assert json.loads(raw)["error"] == "not_found"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_download.py -v`
Expected: FAIL — every case 404s because no `/model/` or `/thumb/` route exists.

- [ ] **Step 3: Write the download handlers**

Append to `src/tessera/handlers_content.py`:

```python
from .store import BlobNotFound, InvalidDigest

BLOB_HEADERS = (
    ("Content-Disposition", "attachment"),
    ("Cache-Control", "public, max-age=86400, immutable"),
)


def _serve_blob(app: TesseraApp, model_id_raw: str, column: str) -> Response:
    """Look the id up, fetch the blob, hand back the bytes.

    The route regex already guarantees `model_id_raw` is digits, so the int()
    below cannot fail on a request that reached here — but it is wrapped
    anyway, because a regex and a parser drifting apart is exactly the kind of
    gap that stops being caught.

    `column` is never request-derived: it is one of two literals passed by the
    two callers below.
    """
    try:
        model_id = int(model_id_raw, 10)
    except ValueError:
        return error(404, "not_found")

    row = app.conn.execute(
        f"SELECT {column} AS digest, visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    if row is None or row["visibility"] == "deleted":
        return error(404, "not_found")

    try:
        data = app.store.get(row["digest"])
    except (BlobNotFound, InvalidDigest):
        # A row whose blob is gone. Answered as 404 rather than 500 because
        # from the caller's side it is indistinguishable, and a 500 would
        # invite a retry loop.
        print(f"blob missing for model {model_id} ({column})", flush=True)
        return error(404, "not_found")

    return Response(200, data, "application/octet-stream", BLOB_HEADERS)


@route("GET", r"/model/(?P<model_id>\d{1,18})")
def handle_model(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    return _serve_blob(app, params["model_id"], "model_hash")


@route("GET", r"/thumb/(?P<model_id>\d{1,18})")
def handle_thumb(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    return _serve_blob(app, params["model_id"], "thumb_hash")
```

`application/octet-stream` is deliberate, and so is `nosniff`. The server does not know what the thumbnail is — it has never looked — so claiming `image/png` would be asserting something it cannot know, and it would invite a browser to render attacker-supplied bytes as an image. The 3DS client knows what it uploaded and decodes it itself.

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_download.py -v`
Expected: PASS, 17 passed (the two `parametrize` blocks contribute 2 and 7).

- [ ] **Step 5: Remove the xfail marker added in Task 12**

Delete the `@pytest.mark.xfail(...)` line above `test_the_stored_bytes_come_back_identical` in `tests/test_upload.py`.

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_upload.py -v`
Expected: PASS, 17 passed with no xfail/xpass reported.

- [ ] **Step 6: Commit**

```bash
git add src/tessera/handlers_content.py tests/test_download.py tests/test_upload.py
git commit -m "feat(api): GET /model/{id} and GET /thumb/{id} as opaque octet-stream"
```

---

## Task 15: Prove the server never decodes an uploaded image

**Lane:** D — Phase 7 endpoints. **Depends on:** Task 14.

This task produces no feature. It produces the evidence for the spec's single hardest security claim (§5.6), from three independent angles, and it proves the check itself can go red.

**Files:**
- Create: `tests/test_no_image_decode.py`

**Interfaces:**
- Consumes: `tests/scan_no_image_decode.py` (Task 1), the live server, `tessera.envelope.build_upload`.
- Produces: nothing importable. This is a gate.

- [ ] **Step 1: Write the failing test**

`tests/test_no_image_decode.py`:

```python
"""Evidence that the daemon never interprets an uploaded byte.

Three independent angles, because one is not enough:

  1. STATIC   — an AST walk over every module in src/tessera, refusing any
                import that could decode an image.
  2. DYNAMIC  — after a real upload and download through a live server, no
                image library has appeared in the daemon's sys.modules.
  3. BEHAVIOUR— bytes that would crash, hang or mislead a real decoder are
                stored and returned byte-identically, with no error.

Plus a red arm on (1), because a scanner that cannot fail is not a scanner.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_no_image_decode import BANNED_MODULES, banned_imports, scan  # noqa: E402

from tessera.envelope import build_upload  # noqa: E402

# Payloads chosen to be exactly the sort of thing that breaks a real decoder.
HOSTILE_BLOBS = {
    "truncated_png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "png_with_absurd_dimensions": (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        + (0xFFFF_FFFF).to_bytes(4, "big")
        + (0xFFFF_FFFF).to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    ),
    "gif_with_no_data": b"GIF89a\xff\xff\xff\xff",
    "bmp_with_a_negative_height": b"BM" + b"\x00" * 20 + (-1 & 0xFFFFFFFF).to_bytes(4, "little"),
    "jpeg_with_a_runaway_marker": b"\xff\xd8\xff\xe0" + b"\xff" * 200,
    "zip_bomb_shaped": b"PK\x03\x04" + b"\x00" * 64,
    "all_zero": bytes(512),
    "all_ff": b"\xff" * 512,
    "nul_and_newlines": b"\x00\n\r\n\x00" * 64,
    "utf16_bom_then_garbage": b"\xff\xfe" + bytes(range(256)),
}


# -- 1. static ------------------------------------------------------------

def test_no_module_imports_anything_that_could_decode_an_image(repo_root: Path) -> None:
    findings = scan(repo_root / "src" / "tessera")
    assert findings == [], "\n".join(findings)


def test_the_scanner_can_go_red() -> None:
    """A scanner that never fires proves nothing. Feed it a known-bad module."""
    for name in ("PIL", "cv2", "imghdr"):
        findings = banned_imports(f"import {name}\n", Path("fake.py"))
        assert len(findings) == 1, f"the scanner missed `import {name}`"
    findings = banned_imports("from PIL import Image\n", Path("fake.py"))
    assert len(findings) == 1, "the scanner missed a from-import"
    findings = banned_imports("import PIL.Image as I\n", Path("fake.py"))
    assert len(findings) == 1, "the scanner missed a dotted aliased import"
    assert banned_imports("import json\nimport sqlite3\n", Path("fake.py")) == []


def test_the_banned_list_covers_the_obvious_decoders() -> None:
    assert {"PIL", "cv2", "imageio", "png", "imghdr"} <= BANNED_MODULES


# -- 2. dynamic -----------------------------------------------------------

def test_a_live_daemon_never_loads_an_image_module(client) -> None:
    """Upload and download hostile bytes, then ask the process what it imported.

    The daemon exposes no introspection endpoint, so this reads the modules
    the *test* process has after importing the whole package — which is the
    same import graph the daemon has, because they run the same code.
    """
    pk, sk = client.keypair()
    payload = HOSTILE_BLOBS["png_with_absurd_dimensions"]
    body = build_upload("hostile", "pixel", payload, payload)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    model_id = json.loads(raw)["id"]
    assert client.get(f"/thumb/{model_id}")[0] == 200

    import tessera.envelope, tessera.handlers_content, tessera.http_server  # noqa: F401
    import tessera.main, tessera.store  # noqa: F401

    loaded = {name.split(".", 1)[0] for name in sys.modules}
    leaked = loaded & BANNED_MODULES
    assert not leaked, f"an image-capable module is loaded: {sorted(leaked)}"


# -- 3. behaviour ---------------------------------------------------------

@pytest.mark.parametrize("name", sorted(HOSTILE_BLOBS))
def test_hostile_bytes_round_trip_untouched(client, name: str) -> None:
    payload = HOSTILE_BLOBS[name]
    pk, sk = client.keypair()
    body = build_upload(f"hostile {name}", "pixel", payload, payload)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, f"{name}: {raw!r}"
    model_id = json.loads(raw)["id"]

    status, headers, model_bytes = client.get(f"/model/{model_id}")
    assert status == 200
    assert model_bytes == payload, f"{name}: the model bytes changed in transit"
    assert headers["Content-Type"] == "application/octet-stream"

    status, headers, thumb_bytes = client.get(f"/thumb/{model_id}")
    assert status == 200
    assert thumb_bytes == payload, f"{name}: the thumbnail bytes changed in transit"


def test_the_daemon_stays_up_after_every_hostile_upload(client, live_server) -> None:
    pk, sk = client.keypair()
    for index, payload in enumerate(HOSTILE_BLOBS.values()):
        body = build_upload(f"h{index}", "pixel", payload + bytes([index]), payload)
        client.signed("POST", "/upload", body, pk, sk)
    assert live_server.process.poll() is None, "the daemon died on hostile input"
    assert client.get("/browse")[0] == 200


def test_no_content_type_is_ever_guessed_from_the_bytes(client) -> None:
    pk, sk = client.keypair()
    png = HOSTILE_BLOBS["truncated_png"]
    body = build_upload("looks like a png", "pixel", png, png)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201
    model_id = json.loads(raw)["id"]
    _, headers, _ = client.get(f"/thumb/{model_id}")
    assert "image/" not in headers["Content-Type"], (
        "the server claimed to know what the bytes are — it has never looked"
    )
```

- [ ] **Step 2: Run the test to verify it fails, then passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_no_image_decode.py -v`

Expected on a correct implementation of Tasks 12–14: **PASS, 15 passed** (the hostile-blob `parametrize` contributes 10). If any hostile blob fails to round-trip, that is a real bug in the envelope or the store — fix it, do not remove the blob from the list.

`test_a_live_daemon_never_loads_an_image_module` may fail on `uploads_per_key_per_day` if the daily quota bites; it uploads once, so it will not. `test_the_daemon_stays_up_after_every_hostile_upload` uploads 10 with one key and the quota is 8 — the last two are expected to be refused with 429, which the test does not assert on, and the daemon must still be up. That is intentional: it exercises the refusal path too.

- [ ] **Step 3: Prove the whole gate can go red**

1. Add `import imghdr` at the top of `src/tessera/store.py`.
2. Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_no_image_decode.py -v` and `make install-check`.
3. Expected: `test_no_module_imports_anything_that_could_decode_an_image` FAILS naming `src/tessera/store.py:N`, `test_a_live_daemon_never_loads_an_image_module` FAILS naming `imghdr`, and `make install-check` exits **non-zero** printing `IMAGE DECODING IMPORT FOUND`.
4. `git checkout -- src/tessera/store.py`, re-run both: 15 passed, install-check exits 0.

Record all three observed outcomes in the commit message.

- [ ] **Step 4: Run the whole suite — this is the Phase 7 gate**

Run: `make test`
Expected: every test passes. Record the exact `N passed` line.

Run: `make install-check`
Expected: exit 0, with all five `ok` lines printed.

- [ ] **Step 5: Commit**

```bash
git add tests/test_no_image_decode.py
git commit -m "test: three-angle proof the server never decodes an upload

Red arm measured: adding `import imghdr` to store.py fails 2 tests and
makes `make install-check` exit non-zero."
```

- [ ] **Step 6: PHASE 7 HANDOFF — stop here and hand it to steve**

Per the standing phase-boundary rule, do not start Task 16. Report:

- **What to load:** on a Linux box or WSL, from the repo root:
  `make deps && make build && make test && make install-check`, then
  `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m tessera.main --config /tmp/t.toml`
  with a `/tmp/t.toml` containing `state_dir = "/tmp/tessera-state"`, `hydro_library = "<abs path>/build/libhydrogen.so"` and `listen_port = 8080`.
- **What to look at:** `curl -s localhost:8080/browse` returns `{"page":1,...,"items":[]}`; the daemon prints one log line per request; `curl -s -X POST localhost:8080/upload -d x` returns `{"error":"malformed_signature",...}` with status 400.
- **What "correct" looks like:** an unsigned write is refused, an unknown path is a JSON 404, and browsing works with no signature at all.
- **What is NOT yet verified:** nothing has run inside an LXC, no systemd unit exists, no firewall exists, and no 3DS has ever produced a real signature. Those are Tasks 22–28 and the gaps listed in the Verification Gaps section at the end of this plan.

---

## Task 16: POST /vote

**Lane:** E — Phase 8 social and moderation. **Depends on:** Task 15 (Phase 7 signed off).

**Files:**
- Create: `src/tessera/handlers_social.py`, `tests/test_vote.py`
- Modify: `src/tessera/handlers_content.py` (delete `handle_vote_placeholder`), `src/tessera/http_server.py` (import the new module)

**Interfaces:**
- Consumes: `signed_route`, the `votes` and `models` tables.
- Produces:
  - `tessera.handlers_social.BadRequest(ValueError)`
  - `tessera.handlers_social.read_json(ctx, *, required: tuple[str, ...]) -> dict`
  - `tessera.handlers_social.read_model_id(payload: dict) -> int`
  - `tessera.handlers_social.require_visible_model(app, model_id) -> sqlite3.Row | None`
  - `tessera.handlers_social.require_not_banned(app, key_hex) -> Response | None`
  - `POST /vote` with body `{"model_id": int, "value": 1 | -1 | 0}` returning
    `{"model_id", "score", "up_votes", "down_votes", "your_vote"}`.

- [ ] **Step 1: Write the failing test**

`tests/test_vote.py`:

```python
from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("votable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def vote(client, pk, sk, model_id: int, value: int):
    body = json.dumps({"model_id": model_id, "value": value}).encode()
    status, _, raw = client.signed("POST", "/vote", body, pk, sk)
    return status, (json.loads(raw) if raw else {})


def test_an_upvote_moves_the_score(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = vote(client, pk, sk, model_id, 1)
    assert status == 200
    assert payload == {
        "model_id": model_id, "score": 1, "up_votes": 1, "down_votes": 0, "your_vote": 1
    }


def test_a_downvote_moves_the_score_the_other_way(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    _, payload = vote(client, pk, sk, model_id, -1)
    assert payload["score"] == -1
    assert payload["down_votes"] == 1


def test_the_same_key_voting_twice_does_not_double_count(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, payload = vote(client, pk, sk, model_id, 1)
    assert payload["score"] == 1
    assert payload["up_votes"] == 1


def test_changing_a_vote_swings_the_score_by_two(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, payload = vote(client, pk, sk, model_id, -1)
    assert payload["score"] == -1
    assert payload["up_votes"] == 0
    assert payload["down_votes"] == 1


def test_a_zero_value_retracts_the_vote(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, payload = vote(client, pk, sk, model_id, 0)
    assert payload["score"] == 0
    assert payload["up_votes"] == 0
    assert payload["your_vote"] == 0


def test_two_keys_both_count(client) -> None:
    model_id = seed_model(client)
    for _ in range(3):
        pk, sk = client.keypair()
        vote(client, pk, sk, model_id, 1)
    pk, sk = client.keypair()
    _, payload = vote(client, pk, sk, model_id, -1)
    assert payload["score"] == 2
    assert payload["up_votes"] == 3
    assert payload["down_votes"] == 1


def test_the_browse_listing_shows_the_tally(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    vote(client, pk, sk, model_id, 1)
    _, _, raw = client.get("/browse")
    item = json.loads(raw)["items"][0]
    assert item["score"] == 1
    assert item["up_votes"] == 1


def test_an_unsigned_vote_is_refused(client) -> None:
    model_id = seed_model(client)
    body = json.dumps({"model_id": model_id, "value": 1}).encode()
    status, _, raw = client.request("POST", "/vote", body)
    assert status == 400
    assert json.loads(raw)["error"] == "malformed_signature"


def test_voting_on_a_missing_model_is_404(client) -> None:
    pk, sk = client.keypair()
    status, payload = vote(client, pk, sk, 99999, 1)
    assert status == 404
    assert payload["error"] == "not_found"


def test_voting_on_a_deleted_model_is_404(client) -> None:
    model_id = seed_model(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    pk, sk = client.keypair()
    assert vote(client, pk, sk, model_id, 1)[0] == 404


@pytest.mark.parametrize("value", [2, -2, 100, "1", None, 1.5, [1]])
def test_a_value_outside_the_allowed_set_is_400(client, value) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "value": value}).encode()
    status, _, raw = client.signed("POST", "/vote", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b"{}", b'{"value":1}',
                                  b'{"model_id":"x","value":1}'])
def test_a_malformed_vote_body_is_400(client, body: bytes) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("POST", "/vote", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


def test_a_banned_key_cannot_vote(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    status, payload = vote(client, pk, sk, model_id, 1)
    assert status == 403
    assert payload["error"] == "banned"


def test_the_stored_tallies_match_a_recount_from_the_votes_table(client) -> None:
    """The denormalised counters on `models` are what browse sorts on. If they
    ever drift from the votes table, `sort=top` is quietly lying."""
    model_id = seed_model(client)
    for index in range(5):
        pk, sk = client.keypair()
        vote(client, pk, sk, model_id, 1 if index % 2 == 0 else -1)
    conn = sqlite3.connect(client.config.db_path)
    stored = conn.execute(
        "SELECT score, up_votes, down_votes FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    recount = conn.execute(
        "SELECT COALESCE(SUM(value), 0),"
        " COALESCE(SUM(value = 1), 0), COALESCE(SUM(value = -1), 0)"
        " FROM votes WHERE model_id = ?", (model_id,)
    ).fetchone()
    conn.close()
    assert tuple(stored) == tuple(recount)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_vote.py -v`
Expected: FAIL — the Task 11 placeholder returns `{"ok": true}` with no score, so nearly every case fails on the payload shape.

- [ ] **Step 3: Delete the placeholder**

Delete `handle_vote_placeholder` from `src/tessera/handlers_content.py`.

Run: `grep -rn "_placeholder" src/` — exactly one hit should remain (`handle_admin_reports_placeholder`, removed in Task 20).

- [ ] **Step 4: Write the vote handler**

`src/tessera/handlers_social.py`:

```python
"""Social endpoints: votes, favourites, reports.

Every route here is signed, because every one of them writes. The identity is
the console's public key and nothing else — there are no accounts, no
passwords and no sessions (spec section 5.1), so "one vote per person" is
really "one vote per keypair", and the ceiling on abuse is how many keypairs
someone is willing to generate. That is what the report system and the per-IP
rate limit are for; it is not something votes can solve on their own.
"""

from __future__ import annotations

import json
import sqlite3

from .http_server import (
    RequestContext,
    Response,
    TesseraApp,
    error,
    json_response,
    signed_route,
)

VOTE_VALUES = (-1, 0, 1)


class BadRequest(ValueError):
    """The signature was fine; the body was not. Always answered with 400."""


def read_json(ctx: RequestContext, *, required: tuple[str, ...]) -> dict:
    """Parse a JSON object body and check the required keys are present.

    Raises BadRequest with a message safe to hand back to the caller — these
    are all shape complaints, they leak nothing about other users or state.
    """
    try:
        payload = json.loads(ctx.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BadRequest(f"body is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BadRequest("body must be a JSON object")
    missing = [name for name in required if name not in payload]
    if missing:
        raise BadRequest(f"missing: {', '.join(missing)}")
    return payload


def read_model_id(payload: dict) -> int:
    raw = payload["model_id"]
    # isinstance(True, int) is True in Python, so booleans are excluded
    # explicitly — otherwise {"model_id": true} would silently mean id 1.
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise BadRequest("model_id must be a positive integer")
    return raw


def require_visible_model(app: TesseraApp, model_id: int) -> sqlite3.Row | None:
    """Fetch a model that may be interacted with.

    'deleted' is invisible to everything; 'unlisted' is still a real model
    that can be voted on, favourited and reported — hiding it from browse is
    the moderation action, not erasing it.
    """
    return app.conn.execute(
        "SELECT id, author_key, visibility FROM models WHERE id = ? AND visibility != 'deleted'",
        (model_id,),
    ).fetchone()


def require_not_banned(app: TesseraApp, key_hex: str) -> Response | None:
    row = app.conn.execute("SELECT 1 FROM bans WHERE key = ?", (key_hex,)).fetchone()
    if row is not None:
        return error(403, "banned", "this key is banned")
    return None


def tally(app: TesseraApp, model_id: int, voter_key: str) -> dict:
    row = app.conn.execute(
        "SELECT score, up_votes, down_votes FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    mine = app.conn.execute(
        "SELECT value FROM votes WHERE model_id = ? AND voter_key = ?", (model_id, voter_key)
    ).fetchone()
    return {
        "model_id": model_id,
        "score": int(row["score"]),
        "up_votes": int(row["up_votes"]),
        "down_votes": int(row["down_votes"]),
        "your_vote": int(mine["value"]) if mine is not None else 0,
    }


@signed_route("POST", r"/vote")
def handle_vote(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None  # guaranteed by signed_route
    try:
        payload = read_json(ctx, required=("model_id", "value"))
        model_id = read_model_id(payload)
        value = payload["value"]
        if isinstance(value, bool) or value not in VOTE_VALUES:
            raise BadRequest(f"value must be one of {VOTE_VALUES}")
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    refusal = require_not_banned(app, ctx.identity.key_hex)
    if refusal is not None:
        return refusal

    if require_visible_model(app, model_id) is None:
        return error(404, "not_found")

    voter = ctx.identity.key_hex
    # One transaction. The counters on `models` are denormalised so browse can
    # sort without a join, which means they must be RECOMPUTED from the votes
    # table inside the same transaction as the vote itself. A counter updated
    # by arithmetic ("score = score + 1") is how these drift, and drift here
    # silently corrupts sort=top with nothing to notice it.
    with app.conn:
        if value == 0:
            app.conn.execute(
                "DELETE FROM votes WHERE model_id = ? AND voter_key = ?", (model_id, voter)
            )
        else:
            app.conn.execute(
                "INSERT INTO votes (model_id, voter_key, value, created_at) VALUES (?, ?, ?, ?)"
                " ON CONFLICT (model_id, voter_key) DO UPDATE SET value = excluded.value,"
                " created_at = excluded.created_at",
                (model_id, voter, value, app.now()),
            )
        app.conn.execute(
            "UPDATE models SET"
            "  score      = (SELECT COALESCE(SUM(value), 0) FROM votes WHERE model_id = ?),"
            "  up_votes   = (SELECT COUNT(*) FROM votes WHERE model_id = ? AND value = 1),"
            "  down_votes = (SELECT COUNT(*) FROM votes WHERE model_id = ? AND value = -1)"
            " WHERE id = ?",
            (model_id, model_id, model_id, model_id),
        )

    return json_response(200, tally(app, model_id, voter))
```

- [ ] **Step 5: Import the module so its routes register**

In `src/tessera/http_server.py`, the route-registration import becomes:

```python
from . import handlers_content, handlers_social  # noqa: F401  (registers routes)
```

`handlers_admin` joins this list in Task 20 and not before — importing a module that does not exist yet is an ImportError at start-up, so the list grows one entry at a time, exactly when the module lands.

- [ ] **Step 6: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_vote.py -v`
Expected: PASS, 26 passed (the two `parametrize` blocks contribute 7 and 6).

- [ ] **Step 7: Commit**

```bash
git add src/tessera/handlers_social.py src/tessera/handlers_content.py \
        src/tessera/http_server.py tests/test_vote.py
git commit -m "feat(api): POST /vote with per-key votes and recomputed tallies"
```

---

## Task 17: POST /favourite

**Lane:** E — Phase 8 social and moderation. **Depends on:** Task 16.

**Files:**
- Modify: `src/tessera/handlers_social.py`
- Create: `tests/test_favourite.py`

**Interfaces:**
- Consumes: `read_json`, `read_model_id`, `require_visible_model`, `require_not_banned` (Task 16).
- Produces: `POST /favourite` with body `{"model_id": int, "on": bool}` returning
  `{"model_id", "favourited": bool, "favourite_count": int}`.

- [ ] **Step 1: Write the failing test**

`tests/test_favourite.py`:

```python
from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("favouritable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def fav(client, pk, sk, model_id: int, on: bool):
    body = json.dumps({"model_id": model_id, "on": on}).encode()
    status, _, raw = client.signed("POST", "/favourite", body, pk, sk)
    return status, (json.loads(raw) if raw else {})


def test_favouriting_records_it(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = fav(client, pk, sk, model_id, True)
    assert status == 200
    assert payload == {"model_id": model_id, "favourited": True, "favourite_count": 1}


def test_favouriting_twice_is_idempotent(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    _, payload = fav(client, pk, sk, model_id, True)
    assert payload["favourite_count"] == 1


def test_unfavouriting_removes_it(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    _, payload = fav(client, pk, sk, model_id, False)
    assert payload == {"model_id": model_id, "favourited": False, "favourite_count": 0}


def test_unfavouriting_something_never_favourited_is_not_an_error(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = fav(client, pk, sk, model_id, False)
    assert status == 200
    assert payload["favourited"] is False


def test_favourites_are_per_key(client) -> None:
    model_id = seed_model(client)
    pk_a, sk_a = client.keypair()
    pk_b, sk_b = client.keypair()
    fav(client, pk_a, sk_a, model_id, True)
    _, payload = fav(client, pk_b, sk_b, model_id, True)
    assert payload["favourite_count"] == 2
    _, payload = fav(client, pk_a, sk_a, model_id, False)
    assert payload["favourite_count"] == 1


def test_a_favourite_does_not_move_the_score(client) -> None:
    """Hearts and votes are separate axes (spec section 4). A favourite is a
    private bookmark; a vote is a public ranking signal. Conflating them would
    make the browse ordering mean something nobody asked for."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    _, _, raw = client.get("/browse")
    assert json.loads(raw)["items"][0]["score"] == 0


def test_an_unsigned_favourite_is_refused(client) -> None:
    model_id = seed_model(client)
    body = json.dumps({"model_id": model_id, "on": True}).encode()
    status, _, _ = client.request("POST", "/favourite", body)
    assert status == 400


def test_favouriting_a_missing_model_is_404(client) -> None:
    pk, sk = client.keypair()
    assert fav(client, pk, sk, 99999, True)[0] == 404


def test_favouriting_a_deleted_model_is_404(client) -> None:
    model_id = seed_model(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()
    pk, sk = client.keypair()
    assert fav(client, pk, sk, model_id, True)[0] == 404


@pytest.mark.parametrize("body", [b"", b"{}", b'{"model_id":1}', b'{"on":true}',
                                  b'{"model_id":1,"on":"yes"}', b'{"model_id":0,"on":true}'])
def test_a_malformed_favourite_body_is_400(client, body: bytes) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("POST", "/favourite", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


def test_a_banned_key_cannot_favourite(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    assert fav(client, pk, sk, model_id, True)[0] == 403


def test_deleting_a_model_row_takes_its_favourites_with_it(client) -> None:
    """The FK is ON DELETE CASCADE. This also proves foreign_keys=ON is really
    on: the PRAGMA is per-connection, and one that silently failed would leave
    orphan rows here and nothing else in the suite would notice."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    fav(client, pk, sk, model_id, True)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM models WHERE id = ?", (model_id,))
    conn.commit()
    remaining = conn.execute(
        "SELECT COUNT(*) FROM favourites WHERE model_id = ?", (model_id,)
    ).fetchone()[0]
    conn.close()
    assert remaining == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_favourite.py -v`
Expected: FAIL — 404 on every case, no `/favourite` route exists.

- [ ] **Step 3: Write the favourite handler**

Append to `src/tessera/handlers_social.py`:

```python
@signed_route("POST", r"/favourite")
def handle_favourite(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None
    try:
        payload = read_json(ctx, required=("model_id", "on"))
        model_id = read_model_id(payload)
        on = payload["on"]
        if not isinstance(on, bool):
            raise BadRequest("on must be true or false")
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    refusal = require_not_banned(app, ctx.identity.key_hex)
    if refusal is not None:
        return refusal

    if require_visible_model(app, model_id) is None:
        return error(404, "not_found")

    owner = ctx.identity.key_hex
    with app.conn:
        if on:
            app.conn.execute(
                "INSERT INTO favourites (owner_key, model_id, created_at) VALUES (?, ?, ?)"
                " ON CONFLICT (owner_key, model_id) DO NOTHING",
                (owner, model_id, app.now()),
            )
        else:
            app.conn.execute(
                "DELETE FROM favourites WHERE owner_key = ? AND model_id = ?", (owner, model_id)
            )
        count = int(app.conn.execute(
            "SELECT COUNT(*) FROM favourites WHERE model_id = ?", (model_id,)
        ).fetchone()[0])

    return json_response(200, {"model_id": model_id, "favourited": on, "favourite_count": count})
```

Favourites deliberately get **no** denormalised counter on `models`, unlike the vote tallies. Nothing sorts or filters on the favourite count, so a `COUNT(*)` against `idx_favourites_model` for the one row being touched is cheaper than another column to keep honest.

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_favourite.py -v`
Expected: PASS, 17 passed (the malformed-body `parametrize` contributes 6).

- [ ] **Step 5: Commit**

```bash
git add src/tessera/handlers_social.py tests/test_favourite.py
git commit -m "feat(api): POST /favourite as a per-key toggle"
```

- [ ] **Step 6: NOT IN SPEC — read this before starting Task 18. Do NOT implement without steve's yes.**

> **GAP: nothing can read a key's favourites back.**
>
> 1. **What thing:** `src/tessera/handlers_social.py`. The spec's endpoint table
>    (section 4) lists `POST /favourite` and no corresponding read endpoint.
> 2. **What is there now:** after this task the file contains `handle_vote` and
>    `handle_favourite`. A console can heart a model and the server records the row in
>    `favourites`, but the console has no way to ask "what have I hearted?" — the heart
>    is write-only.
> 3. **What the change would be:** one added handler, roughly 20 lines, mirroring
>    `handle_browse`'s response shape and signed (a key's favourites are that key's
>    business):
>
>    ```python
>    @signed_route("GET", r"/favourites")
>    def handle_favourites(app, ctx, params):
>        from .handlers_content import _positive_int
>        page = _positive_int(ctx.query.get("page"), 1, 1_000_000)
>        per_page = _positive_int(ctx.query.get("per_page"),
>                                 app.cfg.browse_page_size, app.cfg.browse_max_page_size)
>        rows = app.conn.execute(
>            "SELECT m.id, m.title, m.author_key, m.kind, m.thumb_hash, m.score,"
>            " m.up_votes, m.down_votes, m.created_at FROM favourites f"
>            " JOIN models m ON m.id = f.model_id"
>            " WHERE f.owner_key = ? AND m.visibility != 'deleted'"
>            " ORDER BY f.created_at DESC LIMIT ? OFFSET ?",
>            (ctx.identity.key_hex, per_page, (page - 1) * per_page),
>        ).fetchall()
>        return json_response(200, {"page": page, "per_page": per_page,
>                                   "items": [dict(row) for row in rows]})
>    ```
>
>    Nothing else changes — no schema change, no other route touched. The `favourites`
>    table and `idx_favourites_model` already exist from Task 5.
> 4. **Why it is open:** it is not in the approved spec. Adding an endpoint the spec does
>    not list is a scope change, and scope changes are steve's call, not the
>    implementer's.
> 5. **What happens if it is ignored:** favourites ship write-only. The phase-10 client
>    can set a heart and show the count, but can never render a "my favourites" screen,
>    so from a player's side hearting a model does nothing they can see afterwards.
>    Adding it later is cheap and purely additive, so deferring costs only that the
>    client's first release has no favourites list to show.

**Do not write this handler.** Leave the block above in place and raise it with steve.

---

## Task 18: POST /report

**Lane:** E — Phase 8 social and moderation. **Depends on:** Task 17.

**Files:**
- Modify: `src/tessera/handlers_social.py`
- Create: `tests/test_report.py`

**Interfaces:**
- Consumes: `cfg.report_reasons`, the `reports` table, the Task 16 helpers.
- Produces: `POST /report` with body `{"model_id": int, "reason": str, "detail": str}` (detail
  optional), returning `{"model_id", "reported": true, "report_count": int, "hidden": bool}`
  with status **202**.

- [ ] **Step 1: Write the failing test**

`tests/test_report.py`:

```python
from __future__ import annotations

import json
import sqlite3
import subprocess

import pytest

from tessera.config import REPORT_REASONS
from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("reportable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def report(client, pk, sk, model_id: int, reason: str = "spam", detail: str | None = None):
    payload = {"model_id": model_id, "reason": reason}
    if detail is not None:
        payload["detail"] = detail
    status, _, raw = client.signed("POST", "/report", json.dumps(payload).encode(), pk, sk)
    return status, (json.loads(raw) if raw else {})


def test_a_report_is_accepted(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    status, payload = report(client, pk, sk, model_id)
    assert status == 202
    assert payload["report_count"] == 1
    assert payload["hidden"] is False


def test_the_reason_list_is_exactly_the_spec_list() -> None:
    assert REPORT_REASONS == frozenset({"gore", "sexual", "hate", "stolen", "spam", "other"})


@pytest.mark.parametrize("reason", sorted(REPORT_REASONS))
def test_every_spec_reason_is_accepted(client, reason: str) -> None:
    model_id = seed_model(client, tag=reason.encode())
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, reason=reason)[0] == 202


@pytest.mark.parametrize("reason", ["", "SPAM", "harassment", "gore ", "other; DROP TABLE",
                                     None, 1])
def test_a_reason_outside_the_list_is_400(client, reason) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "reason": reason}).encode()
    status, _, raw = client.signed("POST", "/report", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"


def test_the_same_key_reporting_twice_does_not_count_twice(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    report(client, pk, sk, model_id, "spam")
    status, payload = report(client, pk, sk, model_id, "gore")
    assert status == 202
    assert payload["report_count"] == 1, "one key must never be able to stack reports"


def test_a_second_report_from_the_same_key_corrects_the_reason(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    report(client, pk, sk, model_id, "spam")
    report(client, pk, sk, model_id, "gore")
    conn = sqlite3.connect(client.config.db_path)
    rows = conn.execute("SELECT reason FROM reports WHERE model_id = ?", (model_id,)).fetchall()
    conn.close()
    assert rows == [("gore",)]


def test_the_detail_field_is_stored_and_truncated_not_rejected(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, detail="x" * 5000)[0] == 202
    conn = sqlite3.connect(client.config.db_path)
    stored = conn.execute(
        "SELECT detail FROM reports WHERE model_id = ?", (model_id,)
    ).fetchone()[0]
    conn.close()
    assert 0 < len(stored) <= 512


def test_a_detail_with_control_characters_is_rejected(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, detail="line\x00break")[0] == 400


def test_a_detail_with_an_escape_sequence_is_rejected(client) -> None:
    """The detail is printed straight into a moderator's terminal by
    tools/tessera-reports. An ESC byte there is executed by the terminal, not
    displayed — a report is attacker-controlled text aimed at that screen."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id, detail="\x1b]0;pwned\x07")[0] == 400


def test_an_unsigned_report_is_refused(client) -> None:
    model_id = seed_model(client)
    body = json.dumps({"model_id": model_id, "reason": "spam"}).encode()
    assert client.request("POST", "/report", body)[0] == 400


def test_reporting_a_missing_model_is_404(client) -> None:
    pk, sk = client.keypair()
    assert report(client, pk, sk, 99999)[0] == 404


def test_a_banned_key_cannot_report(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("INSERT INTO bans (key, reason, created_at) VALUES (?, 'test', 0)", (pk.hex(),))
    conn.commit()
    conn.close()
    assert report(client, pk, sk, model_id)[0] == 403


def test_reporting_produces_no_outbound_connection(client, live_server) -> None:
    """Spec section 4: reports are pull-based with ZERO egress. No webhook, no
    email, no push. This asserts the daemon holds no socket to anywhere but its
    own loopback listener after a report — if someone later adds a webhook,
    this goes red."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    assert report(client, pk, sk, model_id)[0] == 202

    pid = live_server.process.pid
    try:
        out = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("ss(8) is not available on this machine")

    daemon_lines = [line for line in out.splitlines() if f"pid={pid}," in line]
    foreign = [
        line for line in daemon_lines
        if "127.0.0.1" not in line and "[::1]" not in line
    ]
    assert not foreign, "the daemon opened a connection off loopback:\n" + "\n".join(foreign)


def test_the_report_row_records_who_and_why(client) -> None:
    model_id = seed_model(client)
    pk, sk = client.keypair()
    report(client, pk, sk, model_id, "stolen", "this is my model")
    conn = sqlite3.connect(client.config.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM reports WHERE model_id = ?", (model_id,)).fetchone()
    conn.close()
    assert row["reporter_key"] == pk.hex()
    assert row["reason"] == "stolen"
    assert row["detail"] == "this is my model"
    assert row["resolved_at"] is None
    assert row["created_at"] > 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_report.py -v`
Expected: FAIL — no `/report` route, so everything 404s. `test_the_reason_list_is_exactly_the_spec_list` already passes; `REPORT_REASONS` landed in Task 1.

- [ ] **Step 3: Write the report handler**

Append to `src/tessera/handlers_social.py`:

```python
MAX_DETAIL_CHARS = 512


def _clean_detail(raw: object) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise BadRequest("detail must be a string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        # This text is printed straight into a terminal by
        # tools/tessera-reports. Escape sequences in it would be executed by
        # the terminal rather than displayed — a report is an
        # attacker-controlled string aimed directly at the moderator's screen.
        # Rejected here, and stripped again on the way out (defence in depth,
        # because rows written before this check existed are still readable).
        raise BadRequest("detail contains control characters")
    return raw.strip()[:MAX_DETAIL_CHARS]


@signed_route("POST", r"/report")
def handle_report(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None
    try:
        payload = read_json(ctx, required=("model_id", "reason"))
        model_id = read_model_id(payload)
        reason = payload["reason"]
        if not isinstance(reason, str) or reason not in app.cfg.report_reasons:
            raise BadRequest(f"reason must be one of {sorted(app.cfg.report_reasons)}")
        detail = _clean_detail(payload.get("detail"))
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    refusal = require_not_banned(app, ctx.identity.key_hex)
    if refusal is not None:
        return refusal

    if require_visible_model(app, model_id) is None:
        return error(404, "not_found")

    with app.conn:
        # ON CONFLICT DO UPDATE, not DO NOTHING: one key gets one report per
        # model (the UNIQUE), but it may correct the reason it gave. The row
        # count is what the auto-hide threshold counts, so a correction must
        # never become a second row.
        app.conn.execute(
            "INSERT INTO reports (model_id, reporter_key, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT (model_id, reporter_key) DO UPDATE SET"
            "   reason = excluded.reason, detail = excluded.detail,"
            "   created_at = excluded.created_at",
            (model_id, ctx.identity.key_hex, reason, detail, app.now()),
        )
        count, hidden = apply_autohide(app, model_id)

    # 202, not 200: the report is recorded, and whether anything happens to the
    # model is a human's decision later. Nothing is sent anywhere — the
    # moderator PULLS the queue (spec section 4).
    return json_response(
        202, {"model_id": model_id, "reported": True, "report_count": count, "hidden": hidden}
    )
```

`apply_autohide` is written properly in Task 19. So this task is independently testable, add a temporary definition immediately above `handle_report`:

```python
def apply_autohide(app: TesseraApp, model_id: int) -> tuple[int, bool]:
    """TEMPORARY — replaced by moderation.apply_autohide in Task 19 Step 4."""
    count = int(app.conn.execute(
        "SELECT COUNT(*) FROM reports WHERE model_id = ? AND resolved_at IS NULL", (model_id,)
    ).fetchone()[0])
    return count, False
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_report.py -v`
Expected: PASS, 26 passed (the two `parametrize` blocks contribute 6 and 7).

If `test_reporting_produces_no_outbound_connection` **skips** because `ss(8)` is absent, say so in the report — a skip is not a pass, and this is the only automated check of the zero-egress requirement until Task 23's firewall.

- [ ] **Step 5: Commit**

```bash
git add src/tessera/handlers_social.py tests/test_report.py
git commit -m "feat(api): POST /report with a fixed reason list and zero egress"
```

---

## Task 19: Auto-hide at N distinct reporter keys

**Lane:** E — Phase 8 social and moderation. **Depends on:** Task 18.

**Files:**
- Create: `src/tessera/moderation.py`, `tests/test_autohide.py`
- Modify: `src/tessera/handlers_social.py` (delete the temporary `apply_autohide`, import the real one), `tests/conftest.py` (a second-threshold server fixture)

**Interfaces:**
- Consumes: `cfg.report_autohide_threshold` (default 3, spec section 4 — a config value, not a constant).
- Produces:
  - `tessera.moderation.VISIBILITIES = ("public", "unlisted", "deleted")`
  - `tessera.moderation.open_report_count(conn, model_id) -> int`
  - `tessera.moderation.set_visibility(conn, model_id, visibility) -> None`
  - `tessera.moderation.resolve_reports(conn, model_id, now) -> int`
  - `tessera.moderation.apply_autohide(app, model_id) -> tuple[int, bool]`

- [ ] **Step 1: Write the failing test**

`tests/test_autohide.py`:

```python
from __future__ import annotations

import json
import sqlite3

from tessera import moderation
from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> int:
    pk, sk = client.keypair()
    body = build_upload("hideable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"]


def report_from_a_new_key(client, model_id: int, reason: str = "spam"):
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "reason": reason}).encode()
    status, _, raw = client.signed("POST", "/report", body, pk, sk)
    return status, json.loads(raw)


def visibility_of(client, model_id: int) -> str:
    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT visibility FROM models WHERE id = ?", (model_id,)).fetchone()
    conn.close()
    return row[0]


def open_conn(client) -> sqlite3.Connection:
    conn = sqlite3.connect(client.config.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def test_below_the_threshold_nothing_is_hidden(client) -> None:
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for index in range(threshold - 1):
        status, payload = report_from_a_new_key(client, model_id)
        assert status == 202
        assert payload["hidden"] is False, f"hidden after only {index + 1} reports"
    assert visibility_of(client, model_id) == "public"


def test_the_nth_distinct_key_hides_it(client) -> None:
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold - 1):
        report_from_a_new_key(client, model_id)
    status, payload = report_from_a_new_key(client, model_id)
    assert status == 202
    assert payload["report_count"] == threshold
    assert payload["hidden"] is True
    assert visibility_of(client, model_id) == "unlisted"


def test_the_default_threshold_is_the_spec_value(client) -> None:
    assert client.config.report_autohide_threshold == 3


def test_a_configured_threshold_of_two_hides_on_the_second_report(threshold_two_client) -> None:
    """Proves the code reads the config rather than a hardcoded 3. A server
    started with report_autohide_threshold = 2 must hide one report earlier."""
    client = threshold_two_client
    model_id = seed_model(client)
    assert report_from_a_new_key(client, model_id)[1]["hidden"] is False
    assert report_from_a_new_key(client, model_id)[1]["hidden"] is True
    assert visibility_of(client, model_id) == "unlisted"


def test_one_key_reporting_repeatedly_never_reaches_the_threshold(client) -> None:
    """The whole point of counting DISTINCT reporter keys. One angry person
    must not be able to unlist anything on their own."""
    model_id = seed_model(client)
    pk, sk = client.keypair()
    for reason in ("spam", "gore", "hate", "stolen", "sexual", "other"):
        body = json.dumps({"model_id": model_id, "reason": reason}).encode()
        status, _, raw = client.signed("POST", "/report", body, pk, sk)
        assert status == 202
        assert json.loads(raw)["report_count"] == 1
    assert visibility_of(client, model_id) == "public"


def test_a_hidden_model_disappears_from_browse(client) -> None:
    threshold = client.config.report_autohide_threshold
    keep = seed_model(client, b"keep")
    hide = seed_model(client, b"hide")
    for _ in range(threshold):
        report_from_a_new_key(client, hide)
    _, _, raw = client.get("/browse")
    listed = [item["id"] for item in json.loads(raw)["items"]]
    assert hide not in listed
    assert keep in listed


def test_a_hidden_model_is_still_downloadable_by_direct_id(client) -> None:
    """Unlisted means "not in the browse list pending review", not "destroyed".
    Someone who already has the id keeps their copy working; deletion is the
    action that takes it away, and only a human can order that."""
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    assert client.get(f"/model/{model_id}")[0] == 200


def test_set_visibility_never_resurrects_a_deleted_model(client) -> None:
    model_id = seed_model(client)
    conn = open_conn(client)
    conn.execute("UPDATE models SET visibility = 'deleted' WHERE id = ?", (model_id,))
    conn.commit()
    moderation.set_visibility(conn, model_id, "unlisted")
    conn.commit()
    still = conn.execute("SELECT visibility FROM models WHERE id = ?", (model_id,)).fetchone()[0]
    conn.close()
    assert still == "deleted"


def test_set_visibility_refuses_a_state_that_is_not_a_state(client) -> None:
    model_id = seed_model(client)
    conn = open_conn(client)
    try:
        for bad in ("", "hidden", "PUBLIC", "deleted; DROP TABLE models"):
            try:
                moderation.set_visibility(conn, model_id, bad)
            except ValueError:
                continue
            raise AssertionError(f"{bad!r} was accepted as a visibility")
    finally:
        conn.close()


def test_resolving_the_reports_makes_the_model_public_again(client) -> None:
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    assert visibility_of(client, model_id) == "unlisted"

    conn = open_conn(client)
    resolved = moderation.resolve_reports(conn, model_id, now=1_000_000)
    moderation.set_visibility(conn, model_id, "public")
    conn.commit()
    open_now = moderation.open_report_count(conn, model_id)
    conn.close()

    assert resolved == threshold
    assert open_now == 0
    assert visibility_of(client, model_id) == "public"


def test_a_resolved_report_does_not_re_hide_on_the_next_new_report(client) -> None:
    """After a moderator approves a model its old reports are resolved. A
    single fresh report must not instantly re-hide it by counting the resolved
    ones again."""
    threshold = client.config.report_autohide_threshold
    model_id = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    conn = open_conn(client)
    moderation.resolve_reports(conn, model_id, now=1_000_000)
    moderation.set_visibility(conn, model_id, "public")
    conn.commit()
    conn.close()

    _, payload = report_from_a_new_key(client, model_id)
    assert payload["report_count"] == 1
    assert payload["hidden"] is False
    assert visibility_of(client, model_id) == "public"
```

Add to `tests/conftest.py`:

```python
@pytest.fixture
def threshold_two_client(tmp_path_factory, hydro_library_path):
    """A second live server with report_autohide_threshold = 2.

    A separate server rather than an edit to the shared one: the threshold is
    read at start-up, so mutating the shared fixture's config would leak into
    whatever test runs next.
    """
    with _start(tmp_path_factory.mktemp("thresh2"), hydro_library_path,
                extra={"report_autohide_threshold": 2}) as server:
        yield Client(server)
```

and extend `_start()`'s signature to `_start(state_dir, hydro_library_path, extra: dict | None = None)`, merging `extra` into the TOML it writes before launching the daemon.

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_autohide.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tessera.moderation'` at collection.

- [ ] **Step 3: Write the moderation module**

`src/tessera/moderation.py`:

```python
"""Visibility transitions and the auto-hide rule.

The rule (spec section 4): once N *distinct* reporter keys have an open report
against a model, it goes 'unlisted' pending a human's review. N is
cfg.report_autohide_threshold, default 3, and it is configuration rather than
a constant because the right number depends on how many people are actually
using the gallery — 3 is far too twitchy at ten users and far too slow at ten
thousand.

Auto-hide is deliberately weak: it unlists, it never deletes. The reversible
action is the only one a machine is allowed to take on its own. Deleting and
banning are Task 20's admin actions and need a human's key.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - types only, avoids an import cycle
    from .http_server import TesseraApp

VISIBILITIES = ("public", "unlisted", "deleted")


def open_report_count(conn: sqlite3.Connection, model_id: int) -> int:
    """Distinct reporter keys with an unresolved report against this model.

    COUNT(DISTINCT reporter_key), not COUNT(*), even though the UNIQUE
    constraint on (model_id, reporter_key) already makes them identical today.
    If that constraint is ever relaxed, this stays correct instead of silently
    turning into a one-person mass-report button.
    """
    return int(conn.execute(
        "SELECT COUNT(DISTINCT reporter_key) FROM reports"
        " WHERE model_id = ? AND resolved_at IS NULL",
        (model_id,),
    ).fetchone()[0])


def set_visibility(conn: sqlite3.Connection, model_id: int, visibility: str) -> None:
    """Move a model between states. 'deleted' is terminal.

    The WHERE clause refuses to move anything out of 'deleted': a delete is a
    moderator's decision, and no later automatic transition — nor a stray
    admin 'approve' — may undo it by accident.
    """
    if visibility not in VISIBILITIES:
        raise ValueError(f"visibility must be one of {VISIBILITIES}")
    conn.execute(
        "UPDATE models SET visibility = ? WHERE id = ? AND visibility != 'deleted'",
        (visibility, model_id),
    )


def resolve_reports(conn: sqlite3.Connection, model_id: int, now: int) -> int:
    """Close every open report against a model. Returns how many were closed."""
    cursor = conn.execute(
        "UPDATE reports SET resolved_at = ? WHERE model_id = ? AND resolved_at IS NULL",
        (now, model_id),
    )
    return int(cursor.rowcount)


def apply_autohide(app: "TesseraApp", model_id: int) -> tuple[int, bool]:
    """Count open reports and unlist if the threshold is met.

    Called from inside handle_report's transaction, so the count and the
    visibility change land together — two reports arriving at once cannot each
    read a count of N-1 and both decline to hide.
    """
    count = open_report_count(app.conn, model_id)
    hidden = count >= app.cfg.report_autohide_threshold
    if hidden:
        set_visibility(app.conn, model_id, "unlisted")
    return count, hidden
```

- [ ] **Step 4: Wire it into the report handler**

In `src/tessera/handlers_social.py`, delete the temporary `apply_autohide` added in Task 18 Step 3 and add to the imports:

```python
from .moderation import apply_autohide
```

Run: `grep -n "def apply_autohide" src/tessera/*.py` — exactly **one** hit, in `moderation.py`. Two hits means the temporary one is still shadowing the real one and the auto-hide tests are passing against dead code.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_autohide.py tests/test_report.py tests/test_browse.py -v`
Expected: PASS, 54 passed.

- [ ] **Step 6: Prove the distinct-key rule is load-bearing**

1. In `src/tessera/moderation.py`, change `COUNT(DISTINCT reporter_key)` to `COUNT(*)`.
2. In `src/tessera/handlers_social.py`, change the `reports` insert's
   `ON CONFLICT (model_id, reporter_key) DO UPDATE SET ...` to `ON CONFLICT DO NOTHING`
   and drop the UNIQUE constraint check by inserting with a fresh `created_at` each time —
   i.e. make one key able to stack rows.
3. Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_autohide.py -v`
4. Expected: `test_one_key_reporting_repeatedly_never_reaches_the_threshold` FAILS — a single
   key unlists the model.
5. `git checkout -- src/tessera/moderation.py src/tessera/handlers_social.py`; re-run: all pass.

Record the observed failure line in the commit message.

- [ ] **Step 7: Commit**

```bash
git add src/tessera/moderation.py src/tessera/handlers_social.py \
        tests/test_autohide.py tests/conftest.py
git commit -m "feat(moderation): auto-unlist at N distinct reporter keys

Sabotage arm: counting all reports instead of distinct keys lets one key
unlist a model on its own — test_one_key_reporting_repeatedly fails."
```

---

## Task 20: Admin queue — GET /admin/reports and POST /admin/action

**Lane:** E — Phase 8 social and moderation. **Depends on:** Task 19.

**Files:**
- Create: `src/tessera/handlers_admin.py`, `tests/test_admin.py`
- Modify: `src/tessera/db.py` (add `admin_log`, bump `SCHEMA_VERSION` to 2), `src/tessera/handlers_content.py` (delete `handle_admin_reports_placeholder`), `src/tessera/http_server.py` (import the module), `tests/test_db.py`

**Interfaces:**
- Consumes: `signed_route(..., admin=True)`, `moderation.set_visibility`, `moderation.resolve_reports`, the Task 16 body helpers.
- Produces:
  - `tessera.handlers_admin.ADMIN_ACTIONS = ("approve", "unlist", "delete", "ban")`
  - `GET /admin/reports?page=&per_page=&resolved=0|1` →
    `{"page", "per_page", "total", "items": [{"model_id", "title", "author_key", "kind", "visibility", "created_at", "report_count", "reasons": [str], "details": str, "last_report_at"}]}`
  - `POST /admin/action` body `{"model_id": int, "action": str, "reason": str}` →
    `{"model_id", "action", "visibility", "resolved", "banned_key"}`

- [ ] **Step 1: Add the audit table**

In `src/tessera/db.py` bump `SCHEMA_VERSION` from `1` to `2` and append to the schema script:

```sql
-- Every moderation action, append-only. Nothing reads this at runtime; it
-- exists so a decision can be explained months later, and so a compromised
-- admin key leaves a trail. Deliberately NO foreign key on model_id: the
-- record of deleting something must outlive the thing it deleted.
CREATE TABLE IF NOT EXISTS admin_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id   INTEGER NOT NULL,
    admin_key  TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
```

Append to `tests/test_db.py`:

```python
def test_the_admin_log_survives_deleting_the_model_it_refers_to(tmp_path) -> None:
    conn = connect(tmp_path / "t.db")
    migrate(conn)
    conn.execute(
        "INSERT INTO models (model_hash, thumb_hash, title, author_key, kind,"
        " model_bytes, thumb_bytes, created_at)"
        " VALUES (?, ?, 't', 'k', 'model', 1, 1, 0)", ("a" * 64, "b" * 64),
    )
    conn.execute(
        "INSERT INTO admin_log (model_id, admin_key, action, reason, created_at)"
        " VALUES (1, 'admin', 'delete', 'why', 1)"
    )
    conn.execute("DELETE FROM models WHERE id = 1")
    assert conn.execute("SELECT COUNT(*) FROM admin_log").fetchone()[0] == 1
    conn.close()


def test_migrate_is_idempotent_and_records_the_current_version(tmp_path) -> None:
    path = tmp_path / "t.db"
    conn = connect(path)
    migrate(conn)
    migrate(conn)
    conn.close()
    conn = connect(path)
    migrate(conn)
    stored = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    conn.close()
    assert stored == str(SCHEMA_VERSION)
```

- [ ] **Step 2: Write the failing test**

`tests/test_admin.py`:

```python
from __future__ import annotations

import json
import sqlite3

import pytest

from tessera.envelope import build_upload


def seed_model(client, tag: bytes = b"a") -> tuple[int, bytes]:
    pk, sk = client.keypair()
    body = build_upload("moderatable", "model", b"model" + tag, b"thumb" + tag)
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw
    return json.loads(raw)["id"], pk


def report_from_a_new_key(client, model_id: int, reason: str = "spam", detail: str = ""):
    pk, sk = client.keypair()
    body = json.dumps({"model_id": model_id, "reason": reason, "detail": detail}).encode()
    return client.signed("POST", "/report", body, pk, sk)


def act(client, pk, sk, model_id: int, action: str, reason: str = "reviewed"):
    body = json.dumps({"model_id": model_id, "action": action, "reason": reason}).encode()
    status, _, raw = client.signed("POST", "/admin/action", body, pk, sk)
    return status, (json.loads(raw) if raw else {})


def visibility_of(client, model_id: int) -> str:
    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT visibility FROM models WHERE id = ?", (model_id,)).fetchone()
    conn.close()
    return row[0]


# -- the queue ------------------------------------------------------------

def test_the_queue_is_empty_when_nothing_is_reported(admin_client) -> None:
    client, pk, sk = admin_client
    status, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 200
    assert json.loads(raw)["items"] == []


def test_a_reported_model_appears_with_its_reasons_rolled_up(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, author = seed_model(client)
    report_from_a_new_key(client, model_id, "gore", "very bad")
    report_from_a_new_key(client, model_id, "spam")

    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    items = json.loads(raw)["items"]
    assert len(items) == 1, "two reports on one model must be ONE queue row"
    entry = items[0]
    assert entry["model_id"] == model_id
    assert entry["title"] == "moderatable"
    assert entry["author_key"] == author.hex()
    assert entry["report_count"] == 2
    assert sorted(entry["reasons"]) == ["gore", "spam"]
    assert "very bad" in entry["details"]


def test_the_queue_needs_the_admin_key(client) -> None:
    pk, sk = client.keypair()
    status, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert status == 403
    assert json.loads(raw)["error"] == "not_admin"


def test_the_queue_is_not_readable_unsigned(client) -> None:
    assert client.get("/admin/reports")[0] == 400


def test_resolved_reports_are_hidden_by_default_and_visible_on_request(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    report_from_a_new_key(client, model_id)
    act(client, pk, sk, model_id, "approve")

    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert json.loads(raw)["items"] == []

    _, _, raw = client.signed("GET", "/admin/reports?resolved=1", b"", pk, sk)
    assert len(json.loads(raw)["items"]) == 1


def test_the_queue_pages(admin_client) -> None:
    client, pk, sk = admin_client
    for index in range(7):
        model_id, _ = seed_model(client, tag=bytes([index]))
        report_from_a_new_key(client, model_id)
    _, _, raw = client.signed("GET", "/admin/reports?per_page=3&page=2", b"", pk, sk)
    page = json.loads(raw)
    assert page["total"] == 7
    assert len(page["items"]) == 3


def test_the_queue_puts_the_most_reported_first(admin_client) -> None:
    client, pk, sk = admin_client
    quiet, _ = seed_model(client, b"q")
    loud, _ = seed_model(client, b"l")
    report_from_a_new_key(client, quiet)
    for _ in range(2):
        report_from_a_new_key(client, loud)
    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert [item["model_id"] for item in json.loads(raw)["items"]] == [loud, quiet]


# -- the actions ----------------------------------------------------------

def test_approve_makes_it_public_and_closes_the_reports(admin_client) -> None:
    client, pk, sk = admin_client
    threshold = client.config.report_autohide_threshold
    model_id, _ = seed_model(client)
    for _ in range(threshold):
        report_from_a_new_key(client, model_id)
    assert visibility_of(client, model_id) == "unlisted"

    status, payload = act(client, pk, sk, model_id, "approve")
    assert status == 200
    assert payload["visibility"] == "public"
    assert payload["resolved"] == threshold
    assert visibility_of(client, model_id) == "public"


def test_unlist_hides_it_from_browse_without_deleting(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    status, payload = act(client, pk, sk, model_id, "unlist")
    assert status == 200
    assert payload["visibility"] == "unlisted"
    _, _, raw = client.get("/browse")
    assert json.loads(raw)["items"] == []
    assert client.get(f"/model/{model_id}")[0] == 200


def test_unlist_leaves_the_reports_open(admin_client) -> None:
    """A model parked pending a decision must stay in the queue, or the next
    moderator has no idea why it is unlisted."""
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    report_from_a_new_key(client, model_id)
    act(client, pk, sk, model_id, "unlist")
    _, _, raw = client.signed("GET", "/admin/reports", b"", pk, sk)
    assert [item["model_id"] for item in json.loads(raw)["items"]] == [model_id]


def test_delete_removes_it_from_browse_and_from_download(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    status, payload = act(client, pk, sk, model_id, "delete")
    assert status == 200
    assert payload["visibility"] == "deleted"
    assert client.get(f"/model/{model_id}")[0] == 404
    assert client.get(f"/thumb/{model_id}")[0] == 404
    _, _, raw = client.get("/browse")
    assert json.loads(raw)["items"] == []


def test_delete_is_terminal(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    act(client, pk, sk, model_id, "delete")
    act(client, pk, sk, model_id, "approve")
    assert visibility_of(client, model_id) == "deleted", "approve resurrected a deleted model"


def test_ban_deletes_everything_that_key_uploaded(admin_client) -> None:
    client, pk, sk = admin_client
    conn_keys = client.keypair()
    author_pk, author_sk = conn_keys
    ids = []
    for index in range(3):
        body = build_upload(f"bad {index}", "model", b"m" + bytes([index]), b"t")
        status, _, raw = client.signed("POST", "/upload", body, author_pk, author_sk)
        assert status == 201, raw
        ids.append(json.loads(raw)["id"])

    status, payload = act(client, pk, sk, ids[0], "ban", "repeat offender")
    assert status == 200
    assert payload["banned_key"] == author_pk.hex()
    assert payload["visibility"] == "deleted"
    for model_id in ids:
        assert visibility_of(client, model_id) == "deleted", (
            f"model {model_id} by a banned key survived the ban"
        )

    conn = sqlite3.connect(client.config.db_path)
    row = conn.execute("SELECT reason FROM bans WHERE key = ?", (author_pk.hex(),)).fetchone()
    conn.close()
    assert row is not None and row[0] == "repeat offender"


def test_a_banned_author_cannot_upload_again(admin_client) -> None:
    client, pk, sk = admin_client
    author_pk, author_sk = client.keypair()
    body = build_upload("bad", "model", b"m", b"t")
    status, _, raw = client.signed("POST", "/upload", body, author_pk, author_sk)
    model_id = json.loads(raw)["id"]
    act(client, pk, sk, model_id, "ban")
    body = build_upload("again", "model", b"m2", b"t2")
    status, _, raw = client.signed("POST", "/upload", body, author_pk, author_sk)
    assert status == 403
    assert json.loads(raw)["error"] == "banned"


def test_an_action_from_a_non_admin_key_is_403_and_changes_nothing(client) -> None:
    model_id, _ = seed_model(client)
    pk, sk = client.keypair()
    status, payload = act(client, pk, sk, model_id, "delete")
    assert status == 403
    assert payload["error"] == "not_admin"
    assert visibility_of(client, model_id) == "public", "a non-admin changed a model's state"


def test_an_unsigned_action_is_refused_and_changes_nothing(client) -> None:
    model_id, _ = seed_model(client)
    body = json.dumps({"model_id": model_id, "action": "delete"}).encode()
    assert client.request("POST", "/admin/action", body)[0] == 400
    assert visibility_of(client, model_id) == "public"


@pytest.mark.parametrize("action", ["", "APPROVE", "purge", "drop", None, 1, "delete; ban"])
def test_an_unknown_action_is_400_and_changes_nothing(admin_client, action) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    body = json.dumps({"model_id": model_id, "action": action}).encode()
    status, _, raw = client.signed("POST", "/admin/action", body, pk, sk)
    assert status == 400
    assert json.loads(raw)["error"] == "bad_request"
    assert visibility_of(client, model_id) == "public"


def test_an_action_on_a_missing_model_is_404(admin_client) -> None:
    client, pk, sk = admin_client
    assert act(client, pk, sk, 99999, "delete")[0] == 404


def test_every_action_is_written_to_the_audit_log(admin_client) -> None:
    client, pk, sk = admin_client
    model_id, _ = seed_model(client)
    act(client, pk, sk, model_id, "unlist", "looks dodgy")
    conn = sqlite3.connect(client.config.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM admin_log ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row["model_id"] == model_id
    assert row["action"] == "unlist"
    assert row["reason"] == "looks dodgy"
    assert row["admin_key"] == pk.hex()
    assert row["created_at"] > 0
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_admin.py tests/test_db.py -v`
Expected: FAIL — the Task 11 placeholder returns `{"reports": []}` so the queue tests fail on shape, and every `/admin/action` case 404s.

- [ ] **Step 4: Delete the placeholder and write the admin module**

Delete `handle_admin_reports_placeholder` from `src/tessera/handlers_content.py`.

Run: `grep -rn "_placeholder" src/` — **zero hits**. Any remaining hit means a stub is about to ship.

`src/tessera/handlers_admin.py`:

```python
"""The moderation queue and the four moderation actions.

Pull-based, entirely (spec section 4). Nothing is sent anywhere when a report
arrives: no webhook, no email, no push. A moderator signs a GET with the admin
key and reads the queue, either over HTTP from the console or with
tools/tessera-reports on the box itself. That is the whole notification
mechanism, and it is deliberate — an outbound webhook would be a hole punched
straight through the egress rules of Task 23 for the convenience of one person.

The admin key is an ordinary console keypair that happens to be listed in
cfg.admin_keys. There is no password, no session and no separate admin login;
losing the console means editing one line of the config file.
"""

from __future__ import annotations

from .handlers_social import BadRequest, read_json, read_model_id
from .http_server import (
    RequestContext,
    Response,
    TesseraApp,
    error,
    json_response,
    signed_route,
)
from .moderation import resolve_reports, set_visibility

ADMIN_ACTIONS = ("approve", "unlist", "delete", "ban")

# What each action does to the model's visibility. `unlist` is the only one
# that leaves the reports OPEN — a model parked pending a decision has to stay
# in the queue, or the next moderator cannot tell why it is hidden.
_ACTION_VISIBILITY = {
    "approve": "public",
    "unlist": "unlisted",
    "delete": "deleted",
    "ban": "deleted",
}

MAX_REASON_CHARS = 512


@signed_route("GET", r"/admin/reports", admin=True)
def handle_admin_reports(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    from .handlers_content import _positive_int  # the same query parsing browse uses

    page = _positive_int(ctx.query.get("page"), 1, 1_000_000)
    per_page = _positive_int(
        ctx.query.get("per_page"), app.cfg.browse_page_size, app.cfg.browse_max_page_size
    )
    want_resolved = (ctx.query.get("resolved") or ["0"])[0] == "1"
    # Two fixed literals chosen by a boolean — no request text reaches the SQL.
    clause = "r.resolved_at IS NOT NULL" if want_resolved else "r.resolved_at IS NULL"

    total = int(app.conn.execute(
        f"SELECT COUNT(DISTINCT r.model_id) FROM reports r WHERE {clause}"
    ).fetchone()[0])

    # One row per MODEL with the reasons and details rolled up, not one row per
    # report. A moderator reading this on a terminal needs to see a model at a
    # time; five reports on one model is one decision, not five.
    rows = app.conn.execute(
        "SELECT r.model_id AS model_id, m.title AS title, m.author_key AS author_key,"
        "       m.kind AS kind, m.visibility AS visibility, m.created_at AS created_at,"
        "       COUNT(DISTINCT r.reporter_key) AS report_count,"
        "       GROUP_CONCAT(DISTINCT r.reason) AS reasons_csv,"
        "       GROUP_CONCAT(r.detail, char(10)) AS details,"
        "       MAX(r.created_at) AS last_report_at"
        " FROM reports r JOIN models m ON m.id = r.model_id"
        f" WHERE {clause}"
        " GROUP BY r.model_id"
        " ORDER BY report_count DESC, last_report_at DESC"
        " LIMIT ? OFFSET ?",
        (per_page, (page - 1) * per_page),
    ).fetchall()

    items = []
    for row in rows:
        entry = dict(row)
        reasons_csv = entry.pop("reasons_csv") or ""
        entry["reasons"] = sorted(part for part in reasons_csv.split(",") if part)
        entry["details"] = entry["details"] or ""
        items.append(entry)

    return json_response(
        200, {"page": page, "per_page": per_page, "total": total, "items": items}
    )


@signed_route("POST", r"/admin/action", admin=True)
def handle_admin_action(app: TesseraApp, ctx: RequestContext, params: dict[str, str]) -> Response:
    assert ctx.identity is not None
    try:
        payload = read_json(ctx, required=("model_id", "action"))
        model_id = read_model_id(payload)
        action = payload["action"]
        if not isinstance(action, str) or action not in ADMIN_ACTIONS:
            raise BadRequest(f"action must be one of {list(ADMIN_ACTIONS)}")
        reason = payload.get("reason", "")
        if not isinstance(reason, str):
            raise BadRequest("reason must be a string")
        reason = reason.strip()[:MAX_REASON_CHARS]
    except BadRequest as exc:
        return error(400, "bad_request", str(exc))

    # Deliberately NOT require_visible_model: a moderator must be able to act
    # on something already deleted (to log a ban against it, for instance).
    row = app.conn.execute(
        "SELECT id, author_key, visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()
    if row is None:
        return error(404, "not_found")

    now = app.now()
    banned_key = None
    with app.conn:
        set_visibility(app.conn, model_id, _ACTION_VISIBILITY[action])
        resolved = resolve_reports(app.conn, model_id, now) if action != "unlist" else 0

        if action == "ban":
            banned_key = row["author_key"]
            app.conn.execute(
                "INSERT INTO bans (key, reason, created_at) VALUES (?, ?, ?)"
                " ON CONFLICT (key) DO UPDATE SET reason = excluded.reason",
                (banned_key, reason, now),
            )
            # A ban takes down everything that key uploaded, not just the model
            # that triggered it. Anything less means re-reporting the same
            # person model by model, which is how a moderator gives up.
            app.conn.execute(
                "UPDATE models SET visibility = 'deleted' WHERE author_key = ?", (banned_key,)
            )

        app.conn.execute(
            "INSERT INTO admin_log (model_id, admin_key, action, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, ctx.identity.key_hex, action, reason, now),
        )

    visibility = app.conn.execute(
        "SELECT visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()["visibility"]

    return json_response(
        200,
        {
            "model_id": model_id,
            "action": action,
            "visibility": visibility,
            "resolved": resolved,
            "banned_key": banned_key,
        },
    )
```

`set_visibility` already refuses to move anything out of `'deleted'`, so `test_delete_is_terminal` passes with no special case here — the guard lives in exactly one place.

- [ ] **Step 5: Register the module**

In `src/tessera/http_server.py`, the route-registration import is now complete and final:

```python
from . import handlers_admin, handlers_content, handlers_social  # noqa: F401
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_admin.py tests/test_db.py -v`
Expected: PASS, 41 passed (the unknown-action `parametrize` contributes 7).

- [ ] **Step 7: Prove the admin gate is load-bearing**

1. In `src/tessera/http_server.py`, change `if admin and not identity.is_admin:` to `if False:`.
2. Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_admin.py tests/test_http_core.py -v`
3. Expected: **3 failures** — `test_an_action_from_a_non_admin_key_is_403_and_changes_nothing`,
   `test_the_queue_needs_the_admin_key`, and `test_an_admin_route_refuses_an_ordinary_key`
   (Task 11).
4. `git checkout -- src/tessera/http_server.py`; re-run: all pass.

Record the failure count in the commit message.

- [ ] **Step 8: Commit**

```bash
git add src/tessera/handlers_admin.py src/tessera/handlers_content.py \
        src/tessera/http_server.py src/tessera/db.py \
        tests/test_admin.py tests/test_db.py
git commit -m "feat(admin): pull-based report queue and four moderation actions

Sabotage arm: neutering the is_admin check turns 3 tests red."
```

---

## Task 21: Moderator CLI tools

**Lane:** E — Phase 8 social and moderation. **Depends on:** Task 20.

The HTTP admin endpoints need a signature from the moderator's 3DS. That is fine day to day and useless at 3am with a flat console. These two tools read and write the SQLite file directly, on the box, over SSH. No network, no signature, no egress — being root on the machine is the authentication.

**Files:**
- Create: `tools/tessera-reports`, `tools/tessera-keys`, `tests/test_tools_cli.py`
- Modify: `tests/conftest.py` (expose `Client.config_path`)

**Interfaces:**
- Consumes: `tessera.config.load_config`, `tessera.db.connect`/`migrate`, `tessera.moderation.set_visibility`/`resolve_reports`, `tessera.hydro.Hydro.keygen`.
- Produces: two executable scripts.
  `tessera-reports [--config P] {list,show,approve,unlist,delete,ban,unban}`;
  `tessera-keys [--config P] {new,show,admin-add,admin-remove}`.

- [ ] **Step 1: Write the failing test**

`tests/test_tools_cli.py`:

```python
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from tessera.envelope import build_upload


def run_tool(repo_root: Path, name: str, config_path: Path, *args: str):
    env = dict(os.environ, PYTHONPATH=str(repo_root / "src"))
    return subprocess.run(
        [sys.executable, str(repo_root / "tools" / name), "--config", str(config_path), *args],
        capture_output=True, text=True, timeout=60, env=env,
    )


def seed_reported_model(client) -> int:
    pk, sk = client.keypair()
    status, _, raw = client.signed(
        "POST", "/upload", build_upload("bad model", "model", b"m", b"t"), pk, sk
    )
    assert status == 201, raw
    model_id = json.loads(raw)["id"]
    for _ in range(2):
        rpk, rsk = client.keypair()
        body = json.dumps({"model_id": model_id, "reason": "gore", "detail": "nope"}).encode()
        assert client.signed("POST", "/report", body, rpk, rsk)[0] == 202
    return model_id


# -- tessera-reports ------------------------------------------------------

def test_list_prints_the_open_queue(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list")
    assert result.returncode == 0, result.stderr
    assert str(model_id) in result.stdout
    assert "bad model" in result.stdout
    assert "gore" in result.stdout


def test_list_json_is_machine_readable(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list", "--json")
    assert result.returncode == 0, result.stderr
    items = json.loads(result.stdout)
    assert items[0]["model_id"] == model_id
    assert items[0]["report_count"] == 2
    assert items[0]["reasons"] == ["gore"]


def test_list_on_an_empty_queue_exits_zero(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list")
    assert result.returncode == 0
    assert "no open reports" in result.stdout.lower()


def test_show_prints_the_full_detail_for_one_model(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path, "show", str(model_id))
    assert result.returncode == 0, result.stderr
    assert "nope" in result.stdout
    assert "gore" in result.stdout


def test_delete_takes_the_model_down_and_logs_it(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    result = run_tool(repo_root, "tessera-reports", client.config_path,
                      "delete", str(model_id), "--reason", "obvious")
    assert result.returncode == 0, result.stderr
    conn = sqlite3.connect(client.config.db_path)
    assert conn.execute(
        "SELECT visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()[0] == "deleted"
    assert conn.execute(
        "SELECT action, reason FROM admin_log ORDER BY id DESC LIMIT 1"
    ).fetchone() == ("delete", "obvious")
    conn.close()


def test_a_cli_delete_is_visible_over_http_immediately(client, repo_root) -> None:
    """The daemon and the CLI are two writers on one database. If the daemon
    were holding stale state, a moderator's takedown would not take effect
    until a restart — which is exactly the failure that matters here."""
    model_id = seed_reported_model(client)
    assert client.get(f"/model/{model_id}")[0] == 200
    run_tool(repo_root, "tessera-reports", client.config_path, "delete", str(model_id))
    assert client.get(f"/model/{model_id}")[0] == 404


def test_approve_clears_the_queue(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    run_tool(repo_root, "tessera-reports", client.config_path, "approve", str(model_id))
    result = run_tool(repo_root, "tessera-reports", client.config_path, "list", "--json")
    assert json.loads(result.stdout) == []


def test_ban_then_unban_round_trips(client, repo_root) -> None:
    model_id = seed_reported_model(client)
    conn = sqlite3.connect(client.config.db_path)
    author = conn.execute("SELECT author_key FROM models WHERE id = ?", (model_id,)).fetchone()[0]
    conn.close()

    assert run_tool(repo_root, "tessera-reports", client.config_path,
                    "ban", str(model_id), "--reason", "spammer").returncode == 0
    conn = sqlite3.connect(client.config.db_path)
    assert conn.execute("SELECT COUNT(*) FROM bans WHERE key = ?", (author,)).fetchone()[0] == 1
    conn.close()

    assert run_tool(repo_root, "tessera-reports", client.config_path,
                    "unban", author).returncode == 0
    conn = sqlite3.connect(client.config.db_path)
    assert conn.execute("SELECT COUNT(*) FROM bans WHERE key = ?", (author,)).fetchone()[0] == 0
    conn.close()


def test_an_action_on_an_unknown_model_exits_nonzero(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-reports", client.config_path, "delete", "99999")
    assert result.returncode != 0
    assert "99999" in result.stderr


def test_unbanning_a_key_that_is_not_banned_exits_nonzero(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-reports", client.config_path, "unban", "ab" * 32)
    assert result.returncode != 0


def test_a_report_detail_cannot_inject_an_escape_sequence(client, repo_root) -> None:
    """The detail is attacker-controlled text printed to a moderator's
    terminal. The API refuses control characters on the way in (Task 18); this
    is the second, independent guard, and the one that still holds for rows
    written before that check existed. Written straight into the database so
    the API check cannot be what makes this pass."""
    model_id = seed_reported_model(client)
    conn = sqlite3.connect(client.config.db_path)
    conn.execute("UPDATE reports SET detail = ? WHERE model_id = ?",
                 ("\x1b]0;pwned\x07boom", model_id))
    conn.commit()
    conn.close()
    result = run_tool(repo_root, "tessera-reports", client.config_path, "show", str(model_id))
    assert "\x1b" not in result.stdout, "an escape byte reached the moderator's terminal"
    assert "boom" in result.stdout, "the sanitiser ate the readable text too"


# -- tessera-keys ---------------------------------------------------------

def test_new_prints_a_keypair(client, repo_root) -> None:
    result = run_tool(repo_root, "tessera-keys", client.config_path, "new")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["public_key"]) == 64
    assert len(payload["secret_key"]) == 128


def test_two_new_keys_differ(client, repo_root) -> None:
    a = json.loads(run_tool(repo_root, "tessera-keys", client.config_path, "new").stdout)
    b = json.loads(run_tool(repo_root, "tessera-keys", client.config_path, "new").stdout)
    assert a["public_key"] != b["public_key"]


def test_a_generated_key_is_one_the_daemon_accepts(client, repo_root) -> None:
    """End to end: a key made by the tool signs a request the running daemon
    verifies. Two hydrogen implementations that disagreed would be invisible
    to every other test here."""
    payload = json.loads(run_tool(repo_root, "tessera-keys", client.config_path, "new").stdout)
    pk = bytes.fromhex(payload["public_key"])
    sk = bytes.fromhex(payload["secret_key"])
    body = build_upload("from the tool", "model", b"tool-model", b"tool-thumb")
    status, _, raw = client.signed("POST", "/upload", body, pk, sk)
    assert status == 201, raw


def test_admin_add_writes_the_key_into_the_config_file(client, repo_root) -> None:
    key = "cd" * 32
    result = run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    assert result.returncode == 0, result.stderr
    assert key in client.config_path.read_text()
    assert key in run_tool(repo_root, "tessera-keys", client.config_path, "show").stdout


def test_admin_add_refuses_a_key_that_is_not_64_lowercase_hex(client, repo_root) -> None:
    for bad in ("", "xyz", "ab" * 31, "ab" * 33, "AB" * 32, "ab" * 31 + "g!"):
        result = run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", bad)
        assert result.returncode != 0, f"{bad!r} was accepted as an admin key"


def test_admin_add_is_idempotent(client, repo_root) -> None:
    key = "ef" * 32
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    assert client.config_path.read_text().count(key) == 1


def test_admin_remove_takes_it_out_again(client, repo_root) -> None:
    key = "12" * 32
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", key)
    result = run_tool(repo_root, "tessera-keys", client.config_path, "admin-remove", key)
    assert result.returncode == 0, result.stderr
    assert key not in client.config_path.read_text()


def test_rewriting_the_config_keeps_every_other_setting(client, repo_root) -> None:
    before = client.config_path.read_text()
    run_tool(repo_root, "tessera-keys", client.config_path, "admin-add", "34" * 32)
    after = client.config_path.read_text()
    for line in before.splitlines():
        if line.strip() and not line.startswith("admin_keys"):
            assert line in after, f"tessera-keys dropped a config line: {line!r}"
```

Add `config_path` as an attribute on the `Client` class in `tests/conftest.py` — `_start()` already writes that file, so this exposes the path it wrote.

- [ ] **Step 2: Run the test to verify it fails**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_tools_cli.py -v`
Expected: FAIL — every case, `returncode == 2` with `can't open file .../tools/tessera-reports`.

- [ ] **Step 3: Write tools/tessera-reports**

```python
#!/usr/bin/env python3
"""Read and action the moderation queue from the box itself.

Why this exists alongside the HTTP admin endpoints: those need a signature
from the moderator's 3DS. This one needs an SSH session and write access to
the database file, which is what you actually have at 3am. It writes through
the same tessera.moderation functions the HTTP path uses, so the two cannot
drift into disagreeing about what 'delete' means.

The daemon may be running while this runs, and should be: SQLite in WAL mode
handles a second writer, and busy_timeout covers the moment the daemon holds
the write lock. Stopping the service first is not required and is not
recommended — that is a gallery outage to action one report.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tessera.config import load_config  # noqa: E402
from tessera.db import connect, migrate  # noqa: E402
from tessera.moderation import resolve_reports, set_visibility  # noqa: E402

CLI_ADMIN_KEY = "cli"  # what lands in admin_log.admin_key for a local action

_ACTION_VISIBILITY = {
    "approve": "public", "unlist": "unlisted", "delete": "deleted", "ban": "deleted",
}


def safe(text: str) -> str:
    """Strip anything a terminal would interpret rather than print.

    Report details and titles are attacker-controlled and land directly on a
    moderator's screen. The API refuses control characters on the way in
    (handlers_social._clean_detail); this is the second of two independent
    guards, and the one that still holds for rows written before that check
    existed. Replaced with '?' rather than dropped, so the moderator can see
    that something was there.
    """
    return "".join(char if (0x20 <= ord(char) < 0x7F or char == "\t") else "?" for char in text)


def queue_rows(conn, resolved: bool):
    clause = "r.resolved_at IS NOT NULL" if resolved else "r.resolved_at IS NULL"
    return conn.execute(
        "SELECT r.model_id AS model_id, m.title AS title, m.author_key AS author_key,"
        "       m.visibility AS visibility,"
        "       COUNT(DISTINCT r.reporter_key) AS report_count,"
        "       GROUP_CONCAT(DISTINCT r.reason) AS reasons_csv,"
        "       MAX(r.created_at) AS last_report_at"
        " FROM reports r JOIN models m ON m.id = r.model_id"
        f" WHERE {clause} GROUP BY r.model_id"
        " ORDER BY report_count DESC, last_report_at DESC"
    ).fetchall()


def cmd_list(conn, args) -> int:
    rows = queue_rows(conn, resolved=args.resolved)

    if args.json:
        print(json.dumps([
            {
                "model_id": row["model_id"], "title": row["title"],
                "author_key": row["author_key"], "visibility": row["visibility"],
                "report_count": row["report_count"],
                "reasons": sorted(p for p in (row["reasons_csv"] or "").split(",") if p),
                "last_report_at": row["last_report_at"],
            }
            for row in rows
        ], indent=2))
        return 0

    if not rows:
        print("no open reports")
        return 0

    print(f"{'id':>6}  {'n':>3}  {'state':<9}  {'reasons':<28}  title")
    for row in rows:
        reasons = ",".join(sorted(p for p in (row["reasons_csv"] or "").split(",") if p))
        print(f"{row['model_id']:>6}  {row['report_count']:>3}  {row['visibility']:<9}"
              f"  {safe(reasons)[:28]:<28}  {safe(row['title'])[:40]}")
    print(f"\n{len(rows)} model(s). `tessera-reports show <id>` for detail.")
    return 0


def cmd_show(conn, args) -> int:
    model = conn.execute(
        "SELECT id, title, author_key, kind, visibility, model_bytes, thumb_bytes,"
        " created_at, score FROM models WHERE id = ?", (args.model_id,)
    ).fetchone()
    if model is None:
        print(f"no model with id {args.model_id}", file=sys.stderr)
        return 1

    print(f"model    {model['id']}")
    print(f"title    {safe(model['title'])}")
    print(f"author   {model['author_key']}")
    print(f"kind     {model['kind']}   visibility {model['visibility']}   score {model['score']}")
    print(f"bytes    model={model['model_bytes']} thumb={model['thumb_bytes']}")
    print(f"uploaded {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(model['created_at']))} UTC")
    print("\nreports:")
    for row in conn.execute(
        "SELECT reporter_key, reason, detail, created_at, resolved_at FROM reports"
        " WHERE model_id = ? ORDER BY created_at", (args.model_id,)
    ):
        state = "resolved" if row["resolved_at"] else "open"
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(row["created_at"]))
        print(f"  [{state:<8}] {when}  {row['reason']:<8}  {row['reporter_key'][:16]}...")
        if row["detail"]:
            print(f"             {safe(row['detail'])}")
    return 0


def apply_action(conn, model_id: int, action: str, reason: str) -> int:
    row = conn.execute("SELECT id, author_key FROM models WHERE id = ?", (model_id,)).fetchone()
    if row is None:
        print(f"no model with id {model_id}", file=sys.stderr)
        return 1

    now = int(time.time())
    with conn:
        set_visibility(conn, model_id, _ACTION_VISIBILITY[action])
        if action != "unlist":
            resolve_reports(conn, model_id, now)
        if action == "ban":
            conn.execute(
                "INSERT INTO bans (key, reason, created_at) VALUES (?, ?, ?)"
                " ON CONFLICT (key) DO UPDATE SET reason = excluded.reason",
                (row["author_key"], reason, now),
            )
            conn.execute(
                "UPDATE models SET visibility = 'deleted' WHERE author_key = ?",
                (row["author_key"],),
            )
        conn.execute(
            "INSERT INTO admin_log (model_id, admin_key, action, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (model_id, CLI_ADMIN_KEY, action, reason, now),
        )

    final = conn.execute(
        "SELECT visibility FROM models WHERE id = ?", (model_id,)
    ).fetchone()["visibility"]
    print(f"model {model_id}: {action} -> {final}")
    if action == "ban":
        print(f"banned key {row['author_key']} and deleted everything it uploaded")
    return 0


def cmd_unban(conn, args) -> int:
    with conn:
        cursor = conn.execute("DELETE FROM bans WHERE key = ?", (args.key,))
    if cursor.rowcount == 0:
        print(f"key {args.key} was not banned", file=sys.stderr)
        return 1
    print(f"unbanned {args.key}")
    print("note: their models stay deleted. Approve any you want back, individually.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Tessera moderation queue")
    parser.add_argument("--config", type=Path, default=Path("/etc/tessera/tessera.toml"))
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="show the open queue")
    listing.add_argument("--json", action="store_true")
    listing.add_argument("--resolved", action="store_true", help="show closed reports instead")

    show = sub.add_parser("show", help="full detail for one model")
    show.add_argument("model_id", type=int)

    for action, helptext in (
        ("approve", "clear the reports and make it public"),
        ("unlist", "hide it from browse, leave the reports open"),
        ("delete", "remove it from browse and download"),
        ("ban", "ban the author and delete everything they uploaded"),
    ):
        action_parser = sub.add_parser(action, help=helptext)
        action_parser.add_argument("model_id", type=int)
        action_parser.add_argument("--reason", default="")

    unban = sub.add_parser("unban", help="lift a ban on a key")
    unban.add_argument("key")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    conn = connect(cfg.db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    migrate(conn)
    try:
        if args.command == "list":
            return cmd_list(conn, args)
        if args.command == "show":
            return cmd_show(conn, args)
        if args.command == "unban":
            return cmd_unban(conn, args)
        return apply_action(conn, args.model_id, args.command, args.reason)
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
```

Then: `chmod +x tools/tessera-reports`

- [ ] **Step 4: Write tools/tessera-keys**

```python
#!/usr/bin/env python3
"""Generate keypairs and manage the admin key list.

`new` produces a keypair with the same libhydrogen the daemon verifies with,
so a key made here is guaranteed to be one the daemon accepts — there is no
second implementation that could disagree.

`admin-add` rewrites the admin_keys line of the config file in place, and
exactly that one line. This file holds hand-edited settings; a tool that
reformatted it would eventually throw one of them away.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tessera.config import load_config  # noqa: E402
from tessera.hydro import Hydro  # noqa: E402

KEY_RE = re.compile(r"^[0-9a-f]{64}$")
ADMIN_LINE_RE = re.compile(r"^admin_keys\s*=.*$", re.MULTILINE)


def write_admin_keys(config_path: Path, keys: list[str]) -> None:
    """Replace (or append) the admin_keys line, touching nothing else.

    Written to a temp file and renamed, so a crash mid-write cannot leave the
    daemon with a config file it refuses to parse on its next restart.
    """
    rendered = "admin_keys = [" + ", ".join(f'"{key}"' for key in keys) + "]"
    text = config_path.read_text(encoding="utf-8")
    if ADMIN_LINE_RE.search(text):
        text = ADMIN_LINE_RE.sub(rendered, text, count=1)
    else:
        text = text.rstrip("\n") + "\n" + rendered + "\n"
    tmp = config_path.with_name(config_path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(config_path)


def cmd_new(cfg, args) -> int:
    hydro = Hydro(cfg.hydro_library)
    public_key, secret_key = hydro.keygen()
    print(json.dumps({"public_key": public_key.hex(), "secret_key": secret_key.hex()}, indent=2))
    print("\nkeep the secret key — it is not recoverable and is not stored here.",
          file=sys.stderr)
    return 0


def cmd_show(cfg, args) -> int:
    keys = list(cfg.admin_keys)
    if not keys:
        print("no admin keys configured — /admin/* is unreachable over HTTP")
        print("use tools/tessera-reports on the box, or add a key with `admin-add`")
        return 0
    for key in keys:
        print(key)
    return 0


def cmd_admin_add(cfg, args) -> int:
    if not KEY_RE.match(args.key):
        print("a key must be exactly 64 lowercase hex characters", file=sys.stderr)
        return 1
    keys = list(cfg.admin_keys)
    if args.key in keys:
        print(f"{args.key} is already an admin key")
        return 0
    keys.append(args.key)
    write_admin_keys(args.config, keys)
    print(f"added {args.key}")
    print("restart the daemon for it to take effect: systemctl restart tessera")
    return 0


def cmd_admin_remove(cfg, args) -> int:
    keys = list(cfg.admin_keys)
    if args.key not in keys:
        print(f"{args.key} is not an admin key", file=sys.stderr)
        return 1
    keys.remove(args.key)
    write_admin_keys(args.config, keys)
    print(f"removed {args.key}")
    print("restart the daemon for it to take effect: systemctl restart tessera")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Tessera keys")
    parser.add_argument("--config", type=Path, default=Path("/etc/tessera/tessera.toml"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("new", help="generate a keypair")
    sub.add_parser("show", help="list the configured admin keys")
    add = sub.add_parser("admin-add", help="add an admin key")
    add.add_argument("key")
    remove = sub.add_parser("admin-remove", help="remove an admin key")
    remove.add_argument("key")

    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    return {
        "new": cmd_new, "show": cmd_show,
        "admin-add": cmd_admin_add, "admin-remove": cmd_admin_remove,
    }[args.command](cfg, args)


if __name__ == "__main__":
    raise SystemExit(main())
```

Then: `chmod +x tools/tessera-keys`

- [ ] **Step 5: Run the test to verify it passes**

Run: `TESSERA_HYDRO_LIBRARY=$PWD/build/libhydrogen.so python3 -m pytest tests/test_tools_cli.py -v`
Expected: PASS, 19 passed.

- [ ] **Step 6: Run the whole suite**

Run: `make test`
Expected: all pass. **Record the exact `N passed` line** — Task 24's provisioning gate compares against this number, and a suite that quietly shrank between here and there is the thing that comparison exists to catch.

- [ ] **Step 7: Commit**

```bash
git add tools/tessera-reports tools/tessera-keys tests/test_tools_cli.py tests/conftest.py
git commit -m "feat(tools): tessera-reports and tessera-keys for on-box moderation"
```

---

## Task 22: systemd unit, and MEASURE whether MemoryDenyWriteExecute survives ctypes

**Lane:** E — it closes out the application side. **Depends on:** Task 21. Task 25 installs the file this produces.

Blocksmith's units set `MemoryDenyWriteExecute=yes`, and that whole hardening block is being reused. But Tessera loads `libhydrogen.so` through `ctypes`, and ctypes builds callback trampolines with libffi — which on some builds writes machine code into a page and then executes it, exactly what MDWE forbids. **This is not a thing to reason about. It is a thing to run.**

**Files:**
- Create: `systemd/tessera.service`, `install/hardening-check.sh`, `tests/test_systemd_unit.py`
- Modify: `Makefile` (fill in the `hardening-check` target stubbed in Task 1)

**Interfaces:**
- Produces: the unit file, and `install/hardening-check.sh <unit-path>` exiting non-zero if any hardening setting is missing. No importable Python.

- [ ] **Step 1: Write the failing test**

`tests/test_systemd_unit.py`:

```python
"""The unit file is a security control, so it gets asserted like one.

These are STATIC assertions about the file's content. They prove the settings
are written down. They do NOT prove the kernel enforces them — that needs a
real systemd on the real container, which is Step 5 of this task and the
Verification Gaps section at the end of the plan.
"""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest

REQUIRED = {
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "PrivateIPC": "yes",
    "ProtectClock": "yes",
    "ProtectHostname": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectControlGroups": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictNamespaces": "yes",
    "RestrictRealtime": "yes",
    "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes",
    "RemoveIPC": "yes",
    "UMask": "0077",
    "SystemCallArchitectures": "native",
    "RestrictAddressFamilies": "AF_INET AF_UNIX",
    "User": "tessera",
    "Group": "tessera",
    "StateDirectory": "tessera",
    "StateDirectoryMode": "0700",
}


@pytest.fixture
def unit_path(repo_root: Path) -> Path:
    return repo_root / "systemd" / "tessera.service"


@pytest.fixture
def unit(unit_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, allow_no_value=True)
    parser.optionxform = str  # systemd directives are case-sensitive
    parser.read(unit_path)
    return parser


@pytest.mark.parametrize(("setting", "value"), sorted(REQUIRED.items()))
def test_the_hardening_setting_is_present(unit, setting: str, value: str) -> None:
    assert unit.has_option("Service", setting), f"{setting} is missing from the unit"
    assert (unit.get("Service", setting) or "").strip() == value


def test_the_syscall_filter_denies_the_dangerous_sets(unit_path: Path) -> None:
    text = unit_path.read_text()
    assert "SystemCallFilter=@system-service" in text
    for group in ("@privileged", "@resources", "@obsolete", "@mount",
                  "@debug", "@cpu-emulation", "@swap"):
        assert group in text, f"{group} is not denied"


def test_private_users_is_deliberately_absent_with_the_reason_written_down(unit_path: Path) -> None:
    """PrivateUsers needs a nested user namespace, which needs features:
    nesting=1 on the LXC — a strictly larger container attack surface than the
    setting buys back. Blocksmith made the same call for the same reason. An
    accidental addition would make the service fail to start on the real node
    and nowhere else, so it is asserted absent rather than left to memory."""
    text = unit_path.read_text()
    assert "PrivateUsers=" not in text
    assert "nesting" in text.lower(), "the reason must be written in the file"


def test_the_resource_ceilings_are_set(unit) -> None:
    assert unit.get("Service", "MemoryMax").endswith("M")
    assert int(unit.get("Service", "TasksMax")) <= 32
    assert int(unit.get("Service", "LimitNOFILE")) <= 1024


def test_it_starts_after_the_firewall(unit) -> None:
    assert "nftables.service" in unit.get("Unit", "After"), (
        "the daemon must not be listening before the egress rules are loaded"
    )


def test_memory_deny_write_execute_records_a_measurement_not_a_guess(unit_path: Path) -> None:
    """Whatever MemoryDenyWriteExecute ends up set to, the file must record
    what was actually OBSERVED on the real node. A bare `yes` with nothing
    beside it is a guess about libffi's trampolines, and a guess here means the
    service fails to start in production and nowhere else.

    This test is EXPECTED TO BE RED until Step 5 has been run on the real
    container. Report it red. Do not write a fake measurement to green it.
    """
    text = unit_path.read_text()
    assert "MemoryDenyWriteExecute=" in text
    index = text.index("MemoryDenyWriteExecute=")
    window = text[max(0, index - 1800):index]
    assert "MEASURED" in window, (
        "the comment above MemoryDenyWriteExecute must record a MEASURED result "
        "from the real container, per Step 5 of Task 22"
    )
    assert "<fill in" not in window, "the MEASURED placeholder was never filled in"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_systemd_unit.py -v`
Expected: FAIL at the fixture — `systemd/tessera.service` does not exist, so `configparser` reads nothing and every case errors.

- [ ] **Step 3: Write the unit, with MDWE commented out pending measurement**

`systemd/tessera.service`:

```ini
[Unit]
Description=Tessera gallery server
Documentation=file:/opt/tessera/README.md
# The daemon binds loopback only and the playit agent dials out to reach it,
# but it must never be listening before the firewall is loaded: the rules in
# Task 23 are what stop this container reaching the LAN, and a window between
# "daemon up" and "rules applied" is a window with no egress restrictions.
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple

# A dedicated unprivileged account, created by container-provision.sh. The
# daemon binds a high port on loopback, so there is no capability to grant.
User=tessera
Group=tessera

# /var/lib/tessera, 0700, owned tessera:tessera. Holds tessera.db and the
# blobs/ tree. ProtectSystem=strict makes everything else read-only, so this
# is the only writable path the process has — which is the intent: an upload
# handler that could write outside here would be a far larger problem than a
# full disk.
StateDirectory=tessera
StateDirectoryMode=0700

ExecStart=/opt/tessera/bin/tessera --config /etc/tessera/tessera.toml

Restart=on-failure
RestartSec=2s

# ---- sandbox ------------------------------------------------------------
# Baseline copied from Blocksmith's bsgate.service, for the same reason: this
# process parses attacker-controlled bytes on its first instruction. The one
# deliberate difference is documented at MemoryDenyWriteExecute below.

CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
UMask=0077

# TCP on loopback (to the playit agent), plus AF_UNIX for what the Python
# runtime opens internally. No raw sockets, no netlink, no bluetooth.
RestrictAddressFamilies=AF_INET AF_UNIX

SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount @debug @cpu-emulation @swap

# --- MemoryDenyWriteExecute ---------------------------------------------
# MEASURED: <fill in from Task 22 Step 5 — the exact command and the exact
#           result, or this file's own test stays red>
#
# The concern is specific. This daemon loads libhydrogen.so through ctypes,
# and ctypes builds callback trampolines with libffi. On some builds libffi
# allocates a page, writes machine code into it, and then executes it —
# exactly the sequence MDWE exists to forbid. Whether that path is taken
# depends on the libffi build in Debian's python3 and on whether any ctypes
# CFUNCTYPE callback is ever created. This service creates none: it only calls
# INTO C, never back out. So it should be fine — and "should" is not a thing
# to ship a start-up failure on.
#
# Step 5 of Task 22 runs the daemon under this unit on the real container with
# the setting ON, and records above what actually happened. Do NOT uncomment
# this line before that measurement exists.
# MemoryDenyWriteExecute=yes

# NOTE: PrivateUsers is deliberately NOT set. It needs a nested user
# namespace, which requires `features: nesting=1` on the LXC — a strictly
# larger container attack surface than the setting buys back. Everything above
# works in an unprivileged container without nesting.

# Bounded so a leak or a flood cannot take the host down with it. Python's
# floor is higher than a C daemon's: the interpreter plus sqlite3 is roughly
# 25-30 MB resident before this service does anything of its own. 192M is
# headroom over that, not a tight fit. Confirm the real figure in Step 5 with
# `systemctl show tessera -p MemoryCurrent` under load and adjust.
MemoryMax=192M
TasksMax=16
LimitNOFILE=256

[Install]
WantedBy=multi-user.target
```

The Step 1 test asserts a `MEASURED` marker with no `<fill in` placeholder appears above the setting, so **this file cannot pass its own test until Step 5 has run and the result is written in**. That is deliberate: it is what stops the measurement being skipped.

- [ ] **Step 4: Write the hardening check and fill in the Makefile target**

`install/hardening-check.sh`:

```bash
#!/usr/bin/env bash
# Assert the unit still carries every hardening setting. Run after install and
# after every update — an update that silently drops ProtectSystem is exactly
# the failure this exists to catch, and nothing else would notice it.
set -euo pipefail

UNIT="${1:-/etc/systemd/system/tessera.service}"
fail=0

require() {
    if grep -qE "^$1[[:space:]]*=[[:space:]]*$2[[:space:]]*$" "$UNIT"; then
        printf '  ok    %s=%s\n' "$1" "$2"
    else
        printf '  FAIL  %s=%s not found in %s\n' "$1" "$2" "$UNIT" >&2
        fail=1
    fi
}

printf 'hardening-check: %s\n' "$UNIT"
require NoNewPrivileges yes
require ProtectSystem strict
require ProtectHome yes
require PrivateTmp yes
require PrivateDevices yes
require ProtectKernelModules yes
require ProtectKernelTunables yes
require ProtectControlGroups yes
require RestrictNamespaces yes
require RestrictSUIDSGID yes
require LockPersonality yes
require RemoveIPC yes
require UMask 0077
require SystemCallArchitectures native

# CapabilityBoundingSet= with an empty value: grep for the bare line.
if grep -qE '^CapabilityBoundingSet[[:space:]]*=[[:space:]]*$' "$UNIT"; then
    printf '  ok    CapabilityBoundingSet= (empty, all capabilities dropped)\n'
else
    printf '  FAIL  CapabilityBoundingSet is not emptied in %s\n' "$UNIT" >&2
    fail=1
fi

if grep -q '^PrivateUsers=' "$UNIT"; then
    printf '  FAIL  PrivateUsers is set — this LXC has no nesting, the unit will not start\n' >&2
    fail=1
else
    printf '  ok    PrivateUsers absent (no nesting on this LXC)\n'
fi

# systemd's own opinion, where it is available. Deliberately NOT a gate on the
# score — the number moves between systemd versions — but printed so a
# regression shows up in the install log.
if command -v systemd-analyze >/dev/null 2>&1; then
    printf '\nsystemd-analyze security tessera:\n'
    systemd-analyze security tessera 2>&1 | tail -5 || true
fi

if [ "$fail" -ne 0 ]; then
    printf '\nhardening-check FAILED\n' >&2
    exit 1
fi
printf '\nhardening-check passed\n'
```

`chmod +x install/hardening-check.sh`. In the `Makefile`, replace the Task 1 stub:

```make
hardening-check:
	@install/hardening-check.sh systemd/tessera.service
```

- [ ] **Step 5: MEASURE MemoryDenyWriteExecute on the real container**

**This step cannot run on the Windows development machine, and it cannot run in WSL either** — it needs the real unit under the real systemd in the real LXC. It runs after Task 25's installer has produced a container, and it is the reason Task 22 is not finished when the file is written.

On the container:

```bash
# 1. Turn MDWE on.
sed -i 's|^# MemoryDenyWriteExecute=yes|MemoryDenyWriteExecute=yes|' \
    /etc/systemd/system/tessera.service
systemctl daemon-reload
systemctl restart tessera
sleep 3
systemctl is-active tessera; echo "is-active exit=$?"
journalctl -u tessera -n 40 --no-pager
```

A daemon that starts is not a daemon that has called into libhydrogen, so exercise the ctypes path explicitly:

```bash
curl -s -o /dev/null -w 'browse %{http_code}\n' localhost:8080/browse
curl -s -X POST localhost:8080/vote -d '{}' -w ' vote %{http_code}\n'   # forces a verify
journalctl -u tessera -n 20 --no-pager
systemctl show tessera -p MemoryCurrent
```

**Record in the unit file, replacing the `MEASURED: <fill in ...>` line:** the exact commands, whether `systemctl is-active` printed `active`, the two HTTP status codes, the `MemoryCurrent` figure, and the verbatim journal line if anything failed.

- **If it starts and serves:** uncomment `MemoryDenyWriteExecute=yes` and write, for example:
  `MEASURED 2026-xx-xx on ct<NNN>: MDWE=yes, is-active=active, browse 200, vote 400 (signature path exercised, libhydrogen loaded and called). MemoryCurrent=<N>. No libffi trampoline is created — this service registers no ctypes callbacks.`
- **If it fails to start:** the journal will carry something like
  `Failed to execute /opt/tessera/bin/tessera: Operation not permitted`, or a Python `OSError`
  out of `ctypes` at import. Leave the line commented and write:
  `MEASURED 2026-xx-xx on ct<NNN>: MDWE=yes prevents start. Verbatim: <the line>. Left OFF; the other 20 sandbox settings stand.`
  **Do not** work around it by loosening something else, and do not silently drop the setting
  with no note — recording what was observed is the entire point of this step.

Either outcome makes `test_memory_deny_write_execute_records_a_measurement_not_a_guess` pass.

- [ ] **Step 6: Run the tests**

Run: `python3 -m pytest tests/test_systemd_unit.py -v && make hardening-check`
Expected once Step 5 has been done: PASS, 33 passed (the settings `parametrize` contributes 28), then `hardening-check passed`.

**Before Step 5 has run on the real node, `test_memory_deny_write_execute_records_a_measurement_not_a_guess` stays RED.** That is correct and expected. Report it red with the reason; do not skip it, do not delete it, and do not invent a measurement.

- [ ] **Step 7: Commit**

```bash
git add systemd/tessera.service install/hardening-check.sh \
        tests/test_systemd_unit.py Makefile
git commit -m "feat(systemd): hardened unit; MDWE gated on a real measurement"
```

- [ ] **Step 8: PHASE 8 HANDOFF — stop here and hand it to steve**

Do not start Task 23. Report:

- **What to load:** `make test` from the repo root, then start the daemon exactly as in the Phase 7 handoff.
- **What to look at:** `python3 tools/tessera-keys --config /tmp/t.toml new`, then
  `admin-add <the public key>`, restart the daemon, then
  `python3 tools/tessera-reports --config /tmp/t.toml list`.
- **What "correct" looks like:** `list` prints `no open reports`. After three *different* keys report the same model it prints one row reading `n=3` and state `unlisted`, and that model has disappeared from `curl -s localhost:8080/browse` while `curl -s -o /dev/null -w '%{http_code}' localhost:8080/model/<id>` still says 200. `tessera-reports approve <id>` puts it back in browse and empties the queue.
- **What is NOT verified:** `MemoryDenyWriteExecute` (Task 22 Step 5 needs the real container, and its test is red until then), and the whole of Lane F — there is no firewall, no installer, no playit tunnel and no LXC yet.

---

## Task 23: nftables ruleset — no blanket root egress, explicit RFC1918 drops

**Lane:** F — Phase 9 deployment. **Depends on:** Task 1 only. **Can be built in parallel with Lanes A–E.**

This is the task with the stated hard requirement, and it is a deliberate divergence from Blocksmith. Blocksmith's output chain contains `meta skuid root accept`, which lets its root reach the LAN. **Tessera's must not.** That line is dropped, and three explicit destination drops for RFC1918 space replace it.

**Files:**
- Create: `install/nftables.conf`, `install/nftables-check.sh`, `tests/test_nftables_ruleset.py`

**Interfaces:**
- Produces: `install/nftables.conf` (the ruleset, loaded by `container-provision.sh` in Task 24) and `install/nftables-check.sh` (parses and asserts it, runnable off-box).

- [ ] **Step 1: Write the failing test**

`tests/test_nftables_ruleset.py`:

```python
"""The firewall is the control that keeps this container off steve's LAN.

Asserted as text, because the ruleset is text and the assertions have to run
on a machine with no nftables. Whether the kernel ENFORCES it is a separate
question, answered only on the real node — see Task 24 Step 6 and the
Verification Gaps section.

The requirement this file exists to hold (stated, hard):
  - NO blanket `meta skuid root accept` in the output chain.
  - Explicit destination drops for 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
Blocksmith's root can reach the LAN. Tessera's must not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


@pytest.fixture
def ruleset(repo_root: Path) -> str:
    return (repo_root / "install" / "nftables.conf").read_text()


def strip_comments(text: str) -> str:
    """Only the live rules. A drop that exists only inside a comment is not a
    drop, and a `meta skuid root accept` mentioned in a comment explaining why
    it is absent must not fail the test below."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# -- the hard requirement -------------------------------------------------

def test_there_is_no_blanket_root_accept(ruleset: str) -> None:
    live = strip_comments(ruleset)
    assert not re.search(r"meta\s+skuid\s+root\s+accept\s*$", live, re.MULTILINE), (
        "a blanket `meta skuid root accept` is present — Blocksmith has one, "
        "Tessera must not: it would let root reach the LAN"
    )


@pytest.mark.parametrize("cidr", RFC1918)
def test_each_rfc1918_range_is_dropped(ruleset: str, cidr: str) -> None:
    live = strip_comments(ruleset)
    pattern = rf"ip\s+daddr\s+{re.escape(cidr)}\s+.*\bdrop\b"
    assert re.search(pattern, live), f"no output drop for {cidr}"


def test_the_rfc1918_drops_come_before_any_root_accept(ruleset: str) -> None:
    """Order is the whole control. nftables evaluates top down, so a narrowed
    root accept placed ABOVE the drops would defeat them entirely."""
    live = strip_comments(ruleset)
    last_drop = max(live.index(cidr) for cidr in RFC1918)
    for match in re.finditer(r"meta\s+skuid\s+\S+\s+.*accept", live):
        assert match.start() > last_drop, (
            f"a uid-based accept at offset {match.start()} sits above the "
            f"RFC1918 drops (which end at {last_drop}) and defeats them"
        )


def test_link_local_and_multicast_are_dropped_too(ruleset: str) -> None:
    """169.254/16 reaches cloud metadata services and 224/4 is the LAN's
    discovery chatter. Neither is RFC1918, and neither is anything this
    container has business talking to."""
    live = strip_comments(ruleset)
    for cidr in ("169.254.0.0/16", "224.0.0.0/4"):
        assert re.search(rf"ip\s+daddr\s+{re.escape(cidr)}\s+.*\bdrop\b", live), cidr


# -- the rest of the posture ----------------------------------------------

def test_the_default_policies_are_drop(ruleset: str) -> None:
    live = strip_comments(ruleset)
    for chain in ("input", "forward", "output"):
        assert re.search(rf"type filter hook {chain}\s+priority\s+\S+;\s*policy drop;", live), (
            f"the {chain} chain does not default to drop"
        )


def test_established_traffic_is_allowed_back(ruleset: str) -> None:
    live = strip_comments(ruleset)
    assert live.count("ct state established,related accept") >= 2, (
        "input and output both need a conntrack accept or nothing works"
    )


def test_invalid_conntrack_state_is_dropped(ruleset: str) -> None:
    assert "ct state invalid" in strip_comments(ruleset)


def test_loopback_is_allowed(ruleset: str) -> None:
    live = strip_comments(ruleset)
    assert re.search(r'iif(name)?\s+"?lo"?\s+accept', live)
    assert re.search(r'oif(name)?\s+"?lo"?\s+accept', live)


def test_nothing_inbound_is_accepted_except_loopback_and_conntrack(ruleset: str) -> None:
    """The daemon is reached through the playit tunnel, which the agent dials
    OUT to establish. There is no inbound port to open, and opening one would
    give an attacker a path that does not go through playit at all."""
    live = strip_comments(ruleset)
    input_block = live.split("chain input")[1].split("chain")[0]
    for match in re.finditer(r"dport\s+(\S+).*accept", input_block):
        raise AssertionError(f"an inbound port is accepted: {match.group(0).strip()}")


def test_the_service_user_can_reach_nothing_outbound(ruleset: str) -> None:
    """The tessera daemon itself has no reason to open an outbound
    connection — it answers requests and writes to disk. If it ever does, that
    is either a bug or an exfiltration, and both should fail closed."""
    live = strip_comments(ruleset)
    assert re.search(r"meta\s+skuid\s+tessera\s+.*drop", live) or \
           not re.search(r"meta\s+skuid\s+tessera\s+.*accept", live), (
        "the tessera user must not have an outbound accept rule"
    )


def test_root_and_apt_reach_only_the_public_web(ruleset: str) -> None:
    """Root needs 80/443 for `git fetch` in ts-update and for apt. It gets
    exactly that, positioned AFTER the RFC1918 drops, so it can reach the
    public internet and never the LAN."""
    live = strip_comments(ruleset)
    assert re.search(r"meta\s+skuid\s+root\s+tcp\s+dport\s*\{[^}]*80[^}]*443[^}]*\}\s*accept",
                     live), "root has no narrowed 80/443 accept — apt and ts-update will hang"


def test_dns_is_permitted(ruleset: str) -> None:
    live = strip_comments(ruleset)
    assert re.search(r"udp\s+dport\s+53\s+accept", live), "no DNS egress — apt cannot resolve"


def test_the_lan_dns_escape_hatch_is_documented_and_absent_by_default(ruleset: str) -> None:
    """An RFC1918 resolver is the one legitimate reason to poke a hole in the
    drops, and Task 25 inserts a /32 rule for it under --allow-lan-dns. By
    default there must be no such hole, and the file must say so — a hole
    nobody documented is a hole nobody reviews."""
    live = strip_comments(ruleset)
    assert "ALLOW_LAN_DNS" in ruleset, "the escape hatch must be documented in the file"
    assert not re.search(r"ip\s+daddr\s+(10|172|192)\.\S+\s+udp\s+dport\s+53\s+accept", live), (
        "a LAN DNS hole is present in the default ruleset"
    )


def test_the_file_says_why_it_differs_from_blocksmith(ruleset: str) -> None:
    lowered = ruleset.lower()
    assert "blocksmith" in lowered
    assert "lan" in lowered
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_nftables_ruleset.py -v`
Expected: FAIL — `FileNotFoundError: install/nftables.conf`.

- [ ] **Step 3: Write the ruleset**

`install/nftables.conf`:

```
#!/usr/sbin/nft -f
#
# Tessera container firewall.
#
# Posture: drop by default in all three chains. Nothing is accepted inbound
# except loopback and established replies — the daemon is reached through the
# playit tunnel, which the playit agent dials OUT to establish, so there is no
# listening port to expose and opening one would create a path that bypasses
# playit entirely.
#
# ---- HOW THIS DIFFERS FROM BLOCKSMITH, AND WHY ---------------------------
#
# Blocksmith's equivalent ruleset contains, in its output chain:
#
#     meta skuid root accept
#
# That single line lets anything running as root in that container reach any
# address, INCLUDING steve's LAN — 10/8, 172.16/12, 192.168/16. For Blocksmith
# that was accepted. For Tessera it is not, and this is a stated hard
# requirement: this container hosts uploads from strangers, so a compromise
# here must not turn into a foothold on the home network.
#
# So the blanket accept is GONE, and in its place:
#
#   1. Explicit destination DROPS for all three RFC1918 ranges, plus
#      link-local (169.254/16 — cloud metadata) and multicast (224/4 — LAN
#      discovery chatter). These come FIRST in the output chain.
#   2. A NARROWED root accept for tcp 80/443 only, placed AFTER those drops.
#      Root still needs the public web: `git fetch` in tools/ts-update, and
#      apt's HTTPS transport. Being below the drops means root reaches
#      deb.debian.org and github.com and cannot reach 192.168.1.1.
#   3. The same narrowing for the _apt uid, which apt drops to for its
#      downloads.
#
# ORDER IS THE ENTIRE CONTROL. nftables evaluates top to bottom and the first
# terminal verdict wins, so moving any accept above the drops silently
# restores exactly the hole this file exists to close. tests/
# test_nftables_ruleset.py asserts the ordering; do not reorder to "tidy up".
#
# ---- DNS ----------------------------------------------------------------
#
# The drops above mean an RFC1918 resolver (a LAN router at 192.168.1.1, say)
# becomes unreachable, which breaks apt before it starts. install/
# proxmox-install.sh therefore defaults --nameserver to public resolvers
# (1.1.1.1, 9.9.9.9) and container-provision.sh REFUSES to proceed if a
# configured resolver is inside RFC1918.
#
# ALLOW_LAN_DNS: if a LAN resolver genuinely has to be used, proxmox-install.sh
# --allow-lan-dns inserts a single narrow rule
#     ip daddr <resolver>/32 udp dport 53 accept
# immediately ABOVE the drops, and prints a loud warning. That is the only
# sanctioned hole in this ruleset, it is a /32 to one address on one port, and
# it is absent by default.

flush ruleset

table inet tessera {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state invalid drop
        ct state established,related accept
        iifname "lo" accept

        # ICMP echo, rate limited. Being able to ping the container from the
        # host is worth more than the near-zero surface of replying to it.
        ip protocol icmp icmp type echo-request limit rate 5/second accept

        # Deliberately NO `tcp dport ... accept`. See the header.
        counter comment "dropped inbound"
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        counter comment "dropped forward"
    }

    chain output {
        type filter hook output priority filter; policy drop;

        ct state invalid drop
        ct state established,related accept
        oifname "lo" accept

        # ---- the LAN wall. FIRST, and it stays first. -------------------
        ip daddr 10.0.0.0/8      counter drop comment "no LAN (RFC1918)"
        ip daddr 172.16.0.0/12   counter drop comment "no LAN (RFC1918)"
        ip daddr 192.168.0.0/16  counter drop comment "no LAN (RFC1918)"
        ip daddr 169.254.0.0/16  counter drop comment "no link-local/metadata"
        ip daddr 224.0.0.0/4     counter drop comment "no multicast"

        # ---- everything below here is public-internet only --------------

        # DNS. The resolver must be public — container-provision.sh enforces
        # that — so this rule can be unqualified by address.
        udp dport 53 accept
        tcp dport 53 accept

        # NTP, so the replay window's timestamps mean something. A console
        # signing with a timestamp outside cfg.replay_window_secs is refused,
        # and a container whose clock has drifted refuses everybody.
        udp dport 123 accept

        # Root: the public web only, for `git fetch` in tools/ts-update and
        # for apt. Below the drops, so root can reach github.com and cannot
        # reach the LAN. This REPLACES Blocksmith's blanket root accept.
        meta skuid root tcp dport { 80, 443 } accept

        # apt drops to the _apt user for its downloads.
        meta skuid "_apt" tcp dport { 80, 443 } accept

        # The playit agent's outbound tunnel. It dials out on 443 and on
        # playit's own control port; both are public addresses.
        meta skuid "playit" tcp dport { 443, 5525 } accept
        meta skuid "playit" udp dport { 5525 } accept

        # NOTE: there is deliberately NO accept for the `tessera` user. The
        # daemon answers requests and writes to disk; it has no reason to open
        # an outbound connection, and if it ever tries, that is either a bug
        # or an exfiltration. Both should fail closed and show up in this
        # counter.
        counter comment "dropped outbound"
    }
}
```

- [ ] **Step 4: Write the off-box checker**

`install/nftables-check.sh`:

```bash
#!/usr/bin/env bash
# Assert the ruleset still holds the guarantees it was written for.
#
# Runs in two modes:
#   nftables-check.sh <file>          static — parse the text (works anywhere)
#   nftables-check.sh --live          live   — read `nft list ruleset` on the box
#
# The live mode is the one that proves the kernel actually has these rules.
# The static mode is what CI and the dev machine can run.
set -euo pipefail

fail=0
note()  { printf '  ok    %s\n' "$1"; }
bad()   { printf '  FAIL  %s\n' "$1" >&2; fail=1; }

if [ "${1:-}" = "--live" ]; then
    RULES="$(nft list ruleset)"
    SOURCE="live kernel ruleset"
else
    FILE="${1:-install/nftables.conf}"
    RULES="$(sed 's/#.*$//' "$FILE")"
    SOURCE="$FILE"
fi

printf 'nftables-check: %s\n' "$SOURCE"

# 1. The hard requirement: no blanket root accept.
if printf '%s' "$RULES" | grep -Eq 'meta skuid root accept[[:space:]]*$'; then
    bad "blanket 'meta skuid root accept' present — root could reach the LAN"
else
    note "no blanket root accept"
fi

# 2. All three RFC1918 ranges dropped.
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    if printf '%s' "$RULES" | grep -Eq "ip daddr $cidr.*drop"; then
        note "drop $cidr"
    else
        bad "no output drop for $cidr"
    fi
done

# 3. Link-local and multicast.
for cidr in 169.254.0.0/16 224.0.0.0/4; do
    printf '%s' "$RULES" | grep -Eq "ip daddr $cidr.*drop" \
        && note "drop $cidr" || bad "no output drop for $cidr"
done

# 4. Default policies.
for chain in input forward output; do
    if printf '%s' "$RULES" | grep -Eq "hook $chain priority[^;]*; *policy drop"; then
        note "$chain policy drop"
    else
        bad "$chain does not default to drop"
    fi
done

# 5. Ordering — every uid accept must sit BELOW the last RFC1918 drop.
last_drop=$(printf '%s\n' "$RULES" | grep -n '192\.168\.0\.0/16' | tail -1 | cut -d: -f1)
first_uid=$(printf '%s\n' "$RULES" | grep -n 'meta skuid' | head -1 | cut -d: -f1)
if [ -n "$last_drop" ] && [ -n "$first_uid" ] && [ "$first_uid" -lt "$last_drop" ]; then
    bad "a uid accept (line $first_uid) sits above the RFC1918 drops (line $last_drop)"
else
    note "uid accepts sit below the RFC1918 drops"
fi

if [ "$fail" -ne 0 ]; then
    printf '\nnftables-check FAILED\n' >&2
    exit 1
fi
printf '\nnftables-check passed\n'
```

`chmod +x install/nftables-check.sh`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_nftables_ruleset.py -v && install/nftables-check.sh install/nftables.conf`
Expected: PASS, 15 passed (the RFC1918 `parametrize` contributes 3), then `nftables-check passed`.

- [ ] **Step 6: Prove the checks can go red — four separate arms**

Each arm is a different way the guarantee could be lost, and each must produce a *different* failure. A single arm would not tell you the checks are discriminating rather than merely present.

1. **Add the blanket accept back.** Insert `meta skuid root accept` in the output chain.
   Expect: `test_there_is_no_blanket_root_accept` FAILS, and `nftables-check.sh` prints
   `FAIL blanket 'meta skuid root accept' present` and exits non-zero. Revert.
2. **Remove one drop.** Delete the `192.168.0.0/16` line.
   Expect: `test_each_rfc1918_range_is_dropped[192.168.0.0/16]` FAILS and the other two
   parametrised cases still PASS. Revert.
3. **Reorder.** Move `meta skuid root tcp dport { 80, 443 } accept` above the drops.
   Expect: `test_the_rfc1918_drops_come_before_any_root_accept` FAILS naming the offset, and
   the checker prints `a uid accept (line N) sits above the RFC1918 drops (line M)`. This is
   the important arm: the rules are all still *present*, and the guarantee is gone anyway.
   Revert.
4. **Flip a policy.** Change the output chain to `policy accept`.
   Expect: `test_the_default_policies_are_drop` FAILS. Revert.

After all four reverts: `python3 -m pytest tests/test_nftables_ruleset.py -v` → 15 passed.
Record all four observed failures in the commit message.

- [ ] **Step 7: Commit**

```bash
git add install/nftables.conf install/nftables-check.sh tests/test_nftables_ruleset.py
git commit -m "feat(firewall): no blanket root egress, explicit RFC1918 drops

Diverges from Blocksmith deliberately: its output chain has
'meta skuid root accept', which lets root reach the LAN. Replaced with
three RFC1918 destination drops plus link-local and multicast, and a
narrowed root/apt accept for tcp 80,443 positioned BELOW them.

Red arms measured, four separate failures: blanket accept restored,
one drop removed, accepts reordered above the drops, policy flipped."
```

---

## Task 24: install/container-provision.sh

**Lane:** F — Phase 9 deployment. **Depends on:** Task 23 (loads its ruleset), Task 22 (installs its unit). Can be *written* in parallel with Lanes A–E; it cannot be *run* until they land.

This runs **inside** the container, as root, with the source tree already present at `/usr/local/src/tessera-server`. It is idempotent: re-running it must converge, not duplicate.

**Files:**
- Create: `install/container-provision.sh`, `tests/test_provision_script.py`

**Interfaces:**
- Consumes: `install/nftables.conf`, `systemd/tessera.service`, `install/hardening-check.sh`, the `Makefile` targets `deps`/`build`/`test`/`install-check`.
- Produces: a provisioned container. Called by `install/proxmox-install.sh` (Task 25) via `pct exec`.

- [ ] **Step 1: Write the failing test**

`tests/test_provision_script.py`:

```python
"""Static assertions about the provisioning script.

A shell script cannot be unit tested meaningfully on Windows, so this asserts
the properties that actually matter and that are checkable from the text:
that it fails closed, that it gates on the test suite, that it checks DNS
before apt, and that it refuses an RFC1918 resolver. Whether it PROVISIONS is
proven only by running it on the real node — Step 6.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def script(repo_root: Path) -> str:
    return (repo_root / "install" / "container-provision.sh").read_text()


def test_it_fails_closed(script: str) -> None:
    assert re.search(r"^set -euo pipefail", script, re.MULTILINE), (
        "without `set -e` a failed build step is followed by a successful "
        "install of the previous binary"
    )


def test_it_checks_dns_before_running_apt(script: str) -> None:
    """`apt-get update` exits 0 when its mirrors are unreachable. Blocksmith
    learned this the hard way; the check has to come first, or the failure
    surfaces 200 lines later as a missing package."""
    dns = script.index("getent hosts")
    apt = script.index("apt-get update")
    assert dns < apt, "the DNS check must come before apt-get update"


def test_it_sanity_checks_that_apt_actually_has_packages(script: str) -> None:
    assert "apt-cache policy" in script
    assert re.search(r"Candidate:\s*\[0-9\]", script) or "Candidate: [0-9]" in script


def test_it_refuses_an_rfc1918_resolver(script: str) -> None:
    """The firewall drops all RFC1918 destinations, so a LAN resolver means
    every lookup fails once nftables is loaded. Better to refuse here, loudly,
    than to hand over a container that half works."""
    assert "resolv.conf" in script
    for prefix in ("10.", "172.", "192.168."):
        assert prefix in script, f"no RFC1918 resolver check for {prefix}"
    assert "ALLOW_LAN_DNS" in script


def test_the_test_suite_gates_the_install(script: str) -> None:
    """A build that compiles is not a build that works. `make test` must run,
    and a failure must stop the install rather than be logged and ignored."""
    test_at = script.index("make test")
    install_at = script.index("/opt/tessera")
    assert test_at < install_at, "make test must run before anything is installed"
    assert "tail -" in script, "the test log must be shown on failure, not swallowed"


def test_install_check_and_hardening_check_both_run(script: str) -> None:
    assert "make install-check" in script
    assert "hardening-check.sh" in script


def test_the_firewall_is_loaded_and_verified(script: str) -> None:
    assert "nftables.conf" in script
    assert "nftables-check.sh" in script
    assert "--live" in script, "the LIVE kernel ruleset must be checked, not just the file"


def test_the_firewall_loads_before_the_daemon_starts(script: str) -> None:
    nft = script.index("nftables-check.sh")
    start = script.rindex("systemctl") 
    assert nft < start, "the daemon must not start before the firewall is up and verified"


def test_it_creates_a_dedicated_unprivileged_service_account(script: str) -> None:
    assert re.search(r"useradd.*--system", script)
    assert "--no-create-home" in script or "-M" in script
    assert re.search(r"(--shell\s+/usr/sbin/nologin|-s /usr/sbin/nologin)", script)


def test_it_is_idempotent(script: str) -> None:
    """It runs again on every update. Creating a user that exists, or adding a
    duplicate config line, must be a no-op rather than an error."""
    assert "id -u tessera" in script or "getent passwd tessera" in script
    assert re.search(r"if\s+\[\s*!\s+-f\s+.*tessera\.toml", script), (
        "the config file must not be overwritten on a re-run — it holds the "
        "admin keys"
    )


def test_it_never_writes_a_secret_into_the_log(script: str) -> None:
    assert "set -x" not in script, "set -x would echo the admin key into the install log"


def test_it_passes_shellcheck(repo_root: Path) -> None:
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(
        ["shellcheck", "-S", "warning", str(repo_root / "install" / "container-provision.sh")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout


def test_bash_can_parse_it(repo_root: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    result = subprocess.run(
        ["bash", "-n", str(repo_root / "install" / "container-provision.sh")],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_provision_script.py -v`
Expected: FAIL — `FileNotFoundError: install/container-provision.sh`.

- [ ] **Step 3: Write the script**

`install/container-provision.sh`:

```bash
#!/usr/bin/env bash
#
# Provision the Tessera container. Runs INSIDE the container, as root, with
# the source tree already at /usr/local/src/tessera-server.
#
# Idempotent by construction: every step either checks first or uses a form
# that converges. It is run once at install and again by tools/ts-update on
# every upgrade, so "already done" must be a no-op, never an error.
#
# Deliberately no `set -x`: the config file it writes holds admin keys, and
# tracing would echo them into the install log.
set -euo pipefail

SRC=/usr/local/src/tessera-server
PREFIX=/opt/tessera
CONF_DIR=/etc/tessera
CONF="$CONF_DIR/tessera.toml"
ALLOW_LAN_DNS="${ALLOW_LAN_DNS:-0}"

step() { printf '\n=== %s\n' "$1"; }
die()  { printf '\nFATAL: %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------- DNS ----
# apt-get update exits 0 when every mirror is unreachable. Checking
# resolution first turns "no network" into a clear failure here instead of a
# baffling missing-package failure 200 lines later.
step "checking DNS"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if getent hosts deb.debian.org >/dev/null 2>&1; then
        printf 'resolved deb.debian.org on attempt %s\n' "$attempt"
        break
    fi
    [ "$attempt" = 10 ] && die "cannot resolve deb.debian.org after 10 attempts"
    sleep 1
done

# The firewall (install/nftables.conf) drops every RFC1918 destination, so a
# LAN resolver stops working the moment nftables loads. Refuse now, with an
# explanation, rather than hand over a container that half works.
step "checking the resolver is not on the LAN"
while read -r _ addr _; do
    case "$addr" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
            if [ "$ALLOW_LAN_DNS" = "1" ]; then
                printf 'WARNING: resolver %s is RFC1918 and the firewall drops that range.\n' "$addr"
                printf 'WARNING: --allow-lan-dns given, so a /32 hole will be punched for it.\n'
                printf 'WARNING: that is a hole in the LAN wall. Prefer a public resolver.\n'
                LAN_RESOLVER="$addr"
            else
                die "resolver $addr is on the LAN (RFC1918), which the firewall drops.
Fix: re-run the installer with --nameserver 1.1.1.1 (or 9.9.9.9),
or, if you must use the LAN resolver, with --allow-lan-dns."
            fi
            ;;
    esac
done < <(grep '^nameserver' /etc/resolv.conf || true)

# --------------------------------------------------------------- apt -----
step "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update

# A populated cache is not a working one. If the mirror answered but has no
# packages, every install below fails one at a time; this fails once, here.
if ! apt-cache policy python3 | grep -q 'Candidate: [0-9]'; then
    die "apt has no candidate version for python3 — the mirror is not usable"
fi

apt-get install -y --no-install-recommends \
    python3 python3-dev build-essential git ca-certificates nftables curl

python3 - <<'PY' || die "python3 is older than 3.11; tomllib is required"
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
PY

# ------------------------------------------------------------ accounts ---
step "creating the service account"
if ! getent passwd tessera >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin tessera
    printf 'created user tessera\n'
else
    printf 'user tessera already exists\n'
fi

# ------------------------------------------------------------- build -----
step "building"
cd "$SRC"
make deps           # fetches and pins libhydrogen at HYDRO_COMMIT
make build

step "running the test suite"
# The gate. A build that compiles is not a build that works, and installing an
# untested binary over a working one is how a bad update becomes an outage.
if ! make test >/tmp/tessera-test.log 2>&1; then
    printf '\n--- last 40 lines of /tmp/tessera-test.log ---\n' >&2
    tail -40 /tmp/tessera-test.log >&2
    die "the test suite failed; nothing was installed"
fi
grep -E '[0-9]+ passed' /tmp/tessera-test.log | tail -1

step "install-check"
make install-check

# ----------------------------------------------------------- install -----
step "installing to $PREFIX"
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/src"
cp -a "$SRC/src/tessera" "$PREFIX/src/"
cp -a "$SRC/build/libhydrogen.so" "$PREFIX/lib/"
install -m 0755 "$SRC/tools/tessera-reports" "$PREFIX/bin/"
install -m 0755 "$SRC/tools/tessera-keys" "$PREFIX/bin/"
install -m 0644 "$SRC/README.md" "$PREFIX/README.md"

# A three-line launcher rather than a shebang on main.py: it pins PYTHONPATH
# to the installed tree, so the daemon can never accidentally import from
# /usr/local/src (a half-finished working copy during an update).
cat >"$PREFIX/bin/tessera" <<EOF
#!/bin/sh
exec /usr/bin/python3 -S -E -P -c \
  'import sys; sys.path.insert(0, "$PREFIX/src"); from tessera.main import main; raise SystemExit(main())' \
  "\$@"
EOF
chmod 0755 "$PREFIX/bin/tessera"

ln -sfn "$PREFIX/bin/tessera-reports" /usr/local/bin/tessera-reports
ln -sfn "$PREFIX/bin/tessera-keys" /usr/local/bin/tessera-keys

# ------------------------------------------------------------ config -----
step "configuration"
install -d -m 0750 "$CONF_DIR"
chown root:tessera "$CONF_DIR"
if [ ! -f "$CONF" ]; then
    cat >"$CONF" <<EOF
# Tessera gallery server configuration.
# Edit and restart:  systemctl restart tessera
listen_host = "127.0.0.1"
listen_port = 8080
proxy_protocol = true
trusted_proxy_cidr = "127.0.0.0/8"
state_dir = "/var/lib/tessera"
hydro_library = "$PREFIX/lib/libhydrogen.so"

# Add your console's public key with:  tessera-keys admin-add <64 hex chars>
admin_keys = []
EOF
    chmod 0640 "$CONF"
    chown root:tessera "$CONF"
    printf 'wrote %s\n' "$CONF"
else
    printf '%s already exists — left alone (it holds the admin keys)\n' "$CONF"
fi

# ---------------------------------------------------------- firewall -----
# Loaded BEFORE the daemon starts. A window where the service is listening and
# the egress rules are not applied is a window with no LAN wall at all.
step "firewall"
install -m 0644 "$SRC/install/nftables.conf" /etc/nftables.conf

if [ "${LAN_RESOLVER:-}" != "" ]; then
    # The only sanctioned hole: one address, one port, inserted ABOVE the
    # drops so it is reached first.
    sed -i "s|^        # ---- the LAN wall|        ip daddr ${LAN_RESOLVER}/32 udp dport 53 accept comment \"ALLOW_LAN_DNS escape hatch\"\n        # ---- the LAN wall|" \
        /etc/nftables.conf
    printf 'WARNING: punched a /32 DNS hole for %s\n' "$LAN_RESOLVER"
fi

systemctl enable nftables
nft -f /etc/nftables.conf
systemctl restart nftables

# Check the LIVE kernel ruleset, not the file. A file that parses is not a
# ruleset the kernel loaded.
"$SRC/install/nftables-check.sh" --live

# ----------------------------------------------------------- systemd -----
step "systemd"
install -m 0644 "$SRC/systemd/tessera.service" /etc/systemd/system/tessera.service
"$SRC/install/hardening-check.sh" /etc/systemd/system/tessera.service
systemctl daemon-reload
systemctl enable tessera
systemctl restart tessera

# `systemctl restart` returns as soon as the process is forked, which is not
# the same as the process still being alive a moment later. Poll.
step "waiting for the daemon"
for attempt in $(seq 1 30); do
    if systemctl is-active --quiet tessera; then
        sleep 1
        if systemctl is-active --quiet tessera; then
            printf 'tessera is active (after %ss)\n' "$attempt"
            break
        fi
    fi
    if [ "$attempt" = 30 ]; then
        journalctl -u tessera -n 40 --no-pager >&2
        die "tessera did not come up"
    fi
    sleep 1
done

# It is active. Is it answering? Two different questions.
step "smoke test"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/browse" || echo 000)
[ "$code" = "200" ] || die "GET /browse returned $code, expected 200"
printf 'GET /browse -> 200\n'

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data 'x' \
       "http://127.0.0.1:8080/vote" || echo 000)
[ "$code" = "400" ] || die "an unsigned POST /vote returned $code, expected 400"
printf 'unsigned POST /vote -> 400 (the signature gate is live)\n'

printf '\n=== provisioning complete\n'
printf 'next: tessera-keys new, then tessera-keys admin-add <public key>\n'
```

`chmod +x install/container-provision.sh`.

Note the smoke test does not merely check the daemon is up: it checks that an **unsigned** write is refused with 400. A container whose signature gate somehow shipped disabled would pass an "is it running" check and fail this one.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_provision_script.py -v`
Expected: PASS, 13 passed (`test_it_passes_shellcheck` skips if shellcheck is absent — say so if it does; a skip is not a pass).

If bash is available (Git Bash on this machine is), `bash -n` genuinely parses the file, so `test_bash_can_parse_it` is a real syntax gate rather than a text match.

- [ ] **Step 5: Prove the DNS-ordering check can go red**

1. In `install/container-provision.sh`, move the whole `checking DNS` block to *after* `apt-get update`.
2. Run: `python3 -m pytest tests/test_provision_script.py::test_it_checks_dns_before_running_apt -v`
3. Expected: FAIL — `the DNS check must come before apt-get update`.
4. Revert; re-run: passes.

Do the same for the test-gate ordering: move `make test` below the `install -d ... /opt/tessera` line and confirm `test_the_test_suite_gates_the_install` fails. Revert.

- [ ] **Step 6: WHAT THIS TASK CANNOT PROVE HERE**

Everything above is text analysis. The following can only be established by running the script in a real Debian container on the Proxmox node, and is carried into the Verification Gaps section:

- that `apt-get install` actually resolves those package names on the chosen Debian release;
- that `make deps` can reach github.com for libhydrogen *from inside the container, through the new firewall* — this is the interaction most likely to bite, because the ruleset is loaded before the daemon but `make deps` runs before that;
- that `nft -f /etc/nftables.conf` parses under the container's nftables version (syntax varies between releases);
- that `nftables-check.sh --live` finds the rules in `nft list ruleset` output, whose formatting differs from the input file;
- that the hardened unit starts at all (Task 22 Step 5);
- that the two curl smoke tests return 200 and 400.

**Do not report this task as verified on the strength of 13 passing text assertions.** They prove the script says the right things, not that it works.

- [ ] **Step 7: Commit**

```bash
git add install/container-provision.sh tests/test_provision_script.py
git commit -m "feat(install): idempotent container provisioning, tests gate the install

DNS checked before apt (apt-get update exits 0 with dead mirrors), an
RFC1918 resolver is refused unless --allow-lan-dns, the firewall loads
and is verified LIVE before the daemon starts, and the smoke test asserts
an unsigned write is refused rather than merely that the port answers."
```

---

## Task 25: install/proxmox-install.sh — the host-side installer

**Lane:** F — Phase 9 deployment. **Depends on:** Task 24.

Runs on the **Proxmox host**, as root. Creates an unprivileged LXC, pushes the source in, and calls `container-provision.sh` inside it. This is what the one-line invocation in the README ends up executing.

**Files:**
- Create: `install/proxmox-install.sh`, `tests/test_installer_script.py`

**Interfaces:**
- Consumes: `install/container-provision.sh`.
- Produces: a running container. Flags: `--ctid`, `--hostname`, `--storage`, `--bridge`, `--nameserver`, `--allow-lan-dns`, `--memory`, `--disk`, `--cores`, `--password`, `--dry-run`.

- [ ] **Step 1: Write the failing test**

`tests/test_installer_script.py`:

```python
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def script(repo_root: Path) -> str:
    return (repo_root / "install" / "proxmox-install.sh").read_text()


def test_it_fails_closed(script: str) -> None:
    assert re.search(r"^set -euo pipefail", script, re.MULTILINE)


def test_the_container_is_unprivileged_with_no_nesting(script: str) -> None:
    """Unprivileged is the whole point. nesting=0 is why the unit deliberately
    omits PrivateUsers (Task 22) — the two decisions have to agree, and an
    installer that quietly turned nesting on would make that comment a lie."""
    assert "--unprivileged 1" in script
    assert "nesting=0" in script


def test_the_default_nameservers_are_public(script: str) -> None:
    """The firewall drops RFC1918 destinations, so defaulting to the host's
    resolvers (which is what Blocksmith does) would hand over a container that
    cannot resolve anything. Public resolvers by default."""
    match = re.search(r"NAMESERVER=\$\{NAMESERVER:-([^}]*)\}", script)
    assert match, "NAMESERVER has no default"
    default = match.group(1)
    assert "1.1.1.1" in default or "9.9.9.9" in default
    for lan in ("192.168.", "10.0.", "172.16."):
        assert lan not in default, f"the default resolver {default} is on the LAN"


def test_the_lan_dns_escape_hatch_exists_and_is_off_by_default(script: str) -> None:
    assert "--allow-lan-dns" in script
    assert re.search(r"ALLOW_LAN_DNS=\$\{ALLOW_LAN_DNS:-0\}", script)


def test_it_autodetects_storage_rather_than_hardcoding_it(script: str) -> None:
    assert "pvesm status" in script
    assert "--content rootdir" in script


def test_it_selects_a_template_rather_than_hardcoding_a_filename(script: str) -> None:
    assert "pveam" in script
    assert "pveam update" in script


def test_it_waits_for_systemd_inside_the_container(script: str) -> None:
    """`pct start` returns long before the container's systemd has reached
    multi-user.target. Running apt against a half-booted container fails in
    confusing ways."""
    assert "systemctl is-system-running" in script or "is-active" in script
    assert re.search(r"for .* in .*(seq|\d+ \d+)", script), "no readiness poll loop"


def test_it_refuses_to_clobber_an_existing_ctid(script: str) -> None:
    assert "pct status" in script
    assert re.search(r"(already exists|in use)", script)


def test_it_pushes_the_source_and_calls_the_provisioner(script: str) -> None:
    assert "pct push" in script or "pct exec" in script
    assert "container-provision.sh" in script


def test_it_has_a_dry_run(script: str) -> None:
    """A script that creates a VM on someone's hypervisor should be readable
    before it is trusted."""
    assert "--dry-run" in script


def test_it_prints_the_two_manual_playit_steps(script: str) -> None:
    """The playit tunnel cannot be fully scripted: claiming the agent needs a
    browser login, and the tunnel's public address is assigned afterwards. The
    installer must SAY so rather than appear to have finished the job."""
    lowered = script.lower()
    assert "playit" in lowered
    assert "claim" in lowered
    assert re.search(r"(manual|by hand|you must|browser)", lowered)


def test_it_never_echoes_the_root_password(script: str) -> None:
    assert "set -x" not in script
    assert re.search(r"(--password|PASSWORD)", script)


def test_bash_can_parse_it(repo_root: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    result = subprocess.run(
        ["bash", "-n", str(repo_root / "install" / "proxmox-install.sh")],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_it_passes_shellcheck(repo_root: Path) -> None:
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(
        ["shellcheck", "-S", "warning", str(repo_root / "install" / "proxmox-install.sh")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_installer_script.py -v`
Expected: FAIL — `FileNotFoundError: install/proxmox-install.sh`.

- [ ] **Step 3: Write the installer**

`install/proxmox-install.sh`:

```bash
#!/usr/bin/env bash
#
# Create and provision a Tessera container on a Proxmox host.
# Run on the HOST, as root.
#
#   ./proxmox-install.sh --ctid 231
#   ./proxmox-install.sh --ctid 231 --nameserver 9.9.9.9 --dry-run
#
# Shape borrowed from Blocksmith's proxmox-lxc-install.sh, with two deliberate
# differences, both consequences of the firewall in install/nftables.conf:
#
#   1. --nameserver DEFAULTS TO PUBLIC RESOLVERS. Blocksmith defaults to the
#      host's resolvers or the gateway, which are usually RFC1918 — and this
#      container's firewall drops every RFC1918 destination, so that default
#      would produce a container that cannot resolve anything the moment the
#      rules load. Fixing that after the fact means debugging DNS through a
#      firewall, which is not a good first experience.
#   2. --allow-lan-dns exists as an escape hatch, off by default, and it warns
#      loudly. It is the only sanctioned hole in the LAN wall.
set -euo pipefail

CTID="${CTID:-}"
HOSTNAME_="${HOSTNAME_:-tessera}"
STORAGE="${STORAGE:-}"
BRIDGE="${BRIDGE:-vmbr0}"
NAMESERVER="${NAMESERVER:-1.1.1.1 9.9.9.9}"
ALLOW_LAN_DNS="${ALLOW_LAN_DNS:-0}"
MEMORY="${MEMORY:-512}"
SWAP="${SWAP:-512}"
DISK="${DISK:-8}"
CORES="${CORES:-1}"
PASSWORD="${PASSWORD:-}"
DRY_RUN=0

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat <<'EOF'
usage: proxmox-install.sh --ctid N [options]

  --ctid N            container id (required)
  --hostname NAME     default: tessera
  --storage NAME      default: autodetected from `pvesm status --content rootdir`
  --bridge NAME       default: vmbr0
  --nameserver "A B"  default: "1.1.1.1 9.9.9.9" (public — see below)
  --allow-lan-dns     permit an RFC1918 resolver and punch a /32 hole for it
  --memory MB         default: 512
  --disk GB           default: 8
  --cores N           default: 1
  --password PASS     root password inside the container (default: locked)
  --dry-run           print what would run, change nothing

DNS: this container's firewall drops all RFC1918 destinations, so a LAN
resolver will not work. The default is deliberately public. --allow-lan-dns
punches a single /32 hole for one resolver on port 53 and warns about it.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ctid) CTID="$2"; shift 2 ;;
        --hostname) HOSTNAME_="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --nameserver) NAMESERVER="$2"; shift 2 ;;
        --allow-lan-dns) ALLOW_LAN_DNS=1; shift ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --cores) CORES="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

step() { printf '\n=== %s\n' "$1"; }
die()  { printf '\nFATAL: %s\n' "$1" >&2; exit 1; }
run()  {
    if [ "$DRY_RUN" = 1 ]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

[ -n "$CTID" ] || { usage >&2; die "--ctid is required"; }
command -v pct >/dev/null || die "pct not found — this must run on a Proxmox host"

# Check the resolver here too, not only inside the container: catching it now
# saves creating and destroying a container to find out.
if [ "$ALLOW_LAN_DNS" != "1" ]; then
    for addr in $NAMESERVER; do
        case "$addr" in
            10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
                die "--nameserver $addr is RFC1918, and this container's firewall
drops that range. Use a public resolver (1.1.1.1, 9.9.9.9), or pass
--allow-lan-dns to punch a single /32 hole for it." ;;
        esac
    done
fi

step "checking ctid $CTID is free"
if pct status "$CTID" >/dev/null 2>&1; then
    die "container $CTID already exists. Pick another --ctid, or remove it with
  pct stop $CTID && pct destroy $CTID"
fi

step "selecting storage"
if [ -z "$STORAGE" ]; then
    STORAGE=$(pvesm status --content rootdir 2>/dev/null \
              | awk 'NR>1 && $3=="active" {print $1; exit}')
    [ -n "$STORAGE" ] || die "no active storage with content type rootdir; pass --storage"
fi
printf 'storage: %s\n' "$STORAGE"

step "selecting a template"
run pveam update
TEMPLATE=$(pveam available --section system \
           | awk '/debian-1[3-9]-standard/ {print $2}' | sort -V | tail -1)
[ -n "$TEMPLATE" ] || TEMPLATE=$(pveam available --section system \
           | awk '/debian-12-standard/ {print $2}' | sort -V | tail -1)
[ -n "$TEMPLATE" ] || die "no Debian standard template found in `pveam available`"
printf 'template: %s\n' "$TEMPLATE"

TEMPLATE_STORE=$(pvesm status --content vztmpl 2>/dev/null \
                 | awk 'NR>1 && $3=="active" {print $1; exit}')
[ -n "$TEMPLATE_STORE" ] || die "no active storage with content type vztmpl"
if ! pveam list "$TEMPLATE_STORE" 2>/dev/null | grep -q "$TEMPLATE"; then
    run pveam download "$TEMPLATE_STORE" "$TEMPLATE"
fi

step "creating container $CTID"
CREATE_ARGS=(
    "$CTID" "$TEMPLATE_STORE:vztmpl/$TEMPLATE"
    --hostname "$HOSTNAME_"
    --storage "$STORAGE"
    --rootfs "$STORAGE:$DISK"
    --memory "$MEMORY" --swap "$SWAP" --cores "$CORES"
    --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp"
    --nameserver "$NAMESERVER"
    --onboot 1
    # Unprivileged, and NO nesting. systemd/tessera.service deliberately omits
    # PrivateUsers because of this; the two decisions must stay in agreement.
    --unprivileged 1
    --features nesting=0
)
if [ -n "$PASSWORD" ]; then
    CREATE_ARGS+=(--password "$PASSWORD")
fi
run pct create "${CREATE_ARGS[@]}"

step "starting container $CTID"
run pct start "$CTID"

# `pct start` returns as soon as the init process is up, which is a long way
# from multi-user.target. Running apt against a half-booted container fails in
# ways that look like network problems.
step "waiting for systemd inside the container"
if [ "$DRY_RUN" != 1 ]; then
    ready=0
    for attempt in $(seq 1 60); do
        state=$(pct exec "$CTID" -- systemctl is-system-running 2>/dev/null || true)
        case "$state" in
            running|degraded)
                printf 'container systemd is %s (after %ss)\n' "$state" "$attempt"
                ready=1; break ;;
        esac
        sleep 1
    done
    [ "$ready" = 1 ] || die "container $CTID did not finish booting in 60s"
fi

step "pushing the source tree"
if [ "$DRY_RUN" != 1 ]; then
    TARBALL=$(mktemp /tmp/tessera-src-XXXXXX.tar)
    tar -C "$SRC_DIR" -cf "$TARBALL" \
        --exclude='.git' --exclude='build' --exclude='__pycache__' --exclude='*.pyc' .
    pct exec "$CTID" -- mkdir -p /usr/local/src/tessera-server
    pct push "$CTID" "$TARBALL" /tmp/tessera-src.tar
    pct exec "$CTID" -- tar -C /usr/local/src/tessera-server -xf /tmp/tessera-src.tar
    pct exec "$CTID" -- rm -f /tmp/tessera-src.tar
    rm -f "$TARBALL"
else
    printf '[dry-run] tar %s -> pct push %s\n' "$SRC_DIR" "$CTID"
fi

step "provisioning"
run pct exec "$CTID" -- env ALLOW_LAN_DNS="$ALLOW_LAN_DNS" \
    bash /usr/local/src/tessera-server/install/container-provision.sh

# `pct enter` gives a non-login shell that does not source /etc/profile, so
# /usr/local/bin is missing from PATH and `tessera-reports` appears not to
# exist. Same fix Blocksmith needed, same reason.
if [ "$DRY_RUN" != 1 ]; then
    pct exec "$CTID" -- sh -c \
      'grep -q "/usr/local/bin" /root/.bashrc || echo "export PATH=\$PATH:/usr/local/bin:/usr/local/sbin" >> /root/.bashrc'
fi

cat <<EOF

=== container $CTID is up

The daemon is running and reachable on 127.0.0.1:8080 INSIDE the container.
It is not reachable from anywhere else, and that is intentional — the firewall
accepts nothing inbound.

TWO STEPS REMAIN, AND NEITHER CAN BE SCRIPTED:

  1. Install and CLAIM the playit agent. Claiming opens a URL that has to be
     approved in a browser while logged in to a playit account. There is no
     API for it, so it is done by hand, once:

         pct enter $CTID
         curl -sSL https://playit.gg/downloads/playit-linux-amd64 -o /usr/local/bin/playit
         chmod +x /usr/local/bin/playit
         playit
         # follow the claim URL it prints, approve it in a browser

  2. Create a TCP tunnel in the playit web UI pointing at 127.0.0.1:8080, with
     PROXY protocol v2 ENABLED. Without proxy-protocol every request appears
     to come from 127.0.0.1 and the per-IP rate limiting in Task 9 becomes one
     shared bucket for the whole internet — it will not error, it will just
     stop working as a control.

     The tunnel's public address is assigned by playit at that point. Write it
     into the 3DS client.

Then, on the box:

     pct enter $CTID
     tessera-keys new                    # keep the secret key on your console
     tessera-keys admin-add <public key>
     systemctl restart tessera
     tessera-reports list

EOF
```

`chmod +x install/proxmox-install.sh`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_installer_script.py -v`
Expected: PASS, 13 passed (shellcheck skips if absent).

- [ ] **Step 5: Run the dry run and READ the output**

Run: `bash install/proxmox-install.sh --ctid 231 --dry-run`
Expected on a non-Proxmox machine: it dies at `pct not found — this must run on a Proxmox host`, which is the correct behaviour and confirms the guard fires. On the Proxmox host, the dry run must print the full `pct create` line with `--unprivileged 1`, `--features nesting=0` and `--nameserver 1.1.1.1 9.9.9.9`, and create nothing.

Verify with `pct status 231` afterwards that no container exists.

- [ ] **Step 6: Prove the RFC1918 nameserver guard fires**

Run: `bash install/proxmox-install.sh --ctid 231 --nameserver 192.168.1.1`
Expected: exits non-zero with the `--nameserver 192.168.1.1 is RFC1918` message **before** it reaches the `pct` check — so it fails on the dev machine too, which is what makes this checkable here.

Then run: `bash install/proxmox-install.sh --ctid 231 --nameserver 192.168.1.1 --allow-lan-dns`
Expected: it gets past the resolver check and dies on `pct not found` instead. That difference is the proof the flag is wired to the guard rather than merely accepted.

- [ ] **Step 7: Commit**

```bash
git add install/proxmox-install.sh tests/test_installer_script.py
git commit -m "feat(install): Proxmox host installer with public-resolver default

Diverges from Blocksmith: --nameserver defaults to 1.1.1.1/9.9.9.9 rather
than the host's resolvers, because the firewall drops RFC1918 and a LAN
resolver would leave the container unable to resolve anything.
--allow-lan-dns is the documented escape hatch, off by default."
```

---

## Task 26: tools/ts-update — the self-updater

**Lane:** F — Phase 9 deployment. **Depends on:** Task 25.

**Files:**
- Create: `tools/ts-update`, `tests/test_update_script.py`

**Interfaces:**
- Consumes: the git checkout at `/usr/local/src/tessera-server`, `install/container-provision.sh`.
- Produces: `ts-update [--check] [--force] [--tag vX.Y.Z]`.

- [ ] **Step 1: Write the failing test**

`tests/test_update_script.py`:

```python
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_URL = "https://github.com/stevenjc2009-byte/tessera-server"


@pytest.fixture
def script(repo_root: Path) -> str:
    return (repo_root / "tools" / "ts-update").read_text()


def test_it_fails_closed(script: str) -> None:
    assert re.search(r"^set -euo pipefail", script, re.MULTILINE)


def test_the_origin_is_pinned_in_the_script(script: str) -> None:
    """A self-updater that fetches from whatever `origin` happens to point at
    is a self-updater that can be redirected by anyone who can write the git
    config. The URL is baked in and checked."""
    assert REPO_URL in script
    assert re.search(r"(check_origin|remote get-url)", script)


def test_it_force_fetches_tags(script: str) -> None:
    """`git fetch --tags` alone will not update a tag that moved. A
    force-pushed tag bricked Blocksmith's deployed updaters — they kept
    building the old commit forever and reported success."""
    assert "--force" in script
    assert re.search(r"git fetch[^\n]*--tags", script)


def test_it_picks_the_newest_version_tag_by_sort_v(script: str) -> None:
    assert "sort -V" in script
    assert re.search(r"v\[0-9\]|v\*\.\*\.\*|refs/tags", script)


def test_it_builds_and_tests_before_touching_opt(script: str) -> None:
    build_at = script.index("make test")
    install_at = script.index("container-provision.sh")
    assert build_at < install_at, "the tests must pass before anything is installed"


def test_it_backs_up_before_replacing(script: str) -> None:
    assert ".prev" in script
    assert "tessera.service" in script, "the unit file must be backed up too, not just the code"


def test_it_rolls_back_when_the_service_does_not_come_back(script: str) -> None:
    lowered = script.lower()
    assert "rollback" in lowered or "roll back" in lowered
    assert "is-active" in script


def test_it_verifies_the_service_answers_not_merely_that_it_started(script: str) -> None:
    """`systemctl is-active` says the process exists. It does not say the
    daemon is serving. A rollback triggered only on is-active would happily
    leave a broken build running."""
    assert "curl" in script
    assert "/browse" in script


def test_check_mode_changes_nothing(script: str) -> None:
    assert "--check" in script
    assert re.search(r"(--check\)|CHECK_ONLY)", script)


def test_it_never_deletes_the_state_directory(script: str) -> None:
    """The blobs and the database live in /var/lib/tessera. An update must
    never touch it, and `rm -rf` anywhere near that path is how a bad update
    becomes an unrecoverable one."""
    assert not re.search(r"rm\s+-rf\s+/var/lib/tessera", script)


def test_it_never_overwrites_the_config(script: str) -> None:
    assert not re.search(r">\s*/etc/tessera/tessera\.toml", script)


def test_bash_can_parse_it(repo_root: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    result = subprocess.run(["bash", "-n", str(repo_root / "tools" / "ts-update")],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_it_passes_shellcheck(repo_root: Path) -> None:
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(
        ["shellcheck", "-S", "warning", str(repo_root / "tools" / "ts-update")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_update_script.py -v`
Expected: FAIL — `FileNotFoundError: tools/ts-update`.

- [ ] **Step 3: Write the updater**

`tools/ts-update`:

```bash
#!/usr/bin/env bash
#
# Update Tessera in place. Runs inside the container, as root.
#
#   ts-update            update to the newest v*.*.* tag
#   ts-update --check    say what would happen, change nothing
#   ts-update --tag v1.2.0
#   ts-update --force    reinstall even if already on the newest tag
#
# Shape follows Blocksmith's bs-update, including two of its hard-won details:
#
#   * The origin URL is PINNED here, not read from git config. An updater that
#     trusts whatever `origin` points at can be redirected by anyone who can
#     write .git/config.
#   * `git fetch --tags --force --prune`. Plain `--tags` will NOT update a tag
#     that moved, and a force-pushed tag left Blocksmith's deployed updaters
#     rebuilding an old commit forever while reporting success.
set -euo pipefail

REPO_URL="https://github.com/stevenjc2009-byte/tessera-server"
SRC=/usr/local/src/tessera-server
PREFIX=/opt/tessera
UNIT=/etc/systemd/system/tessera.service

CHECK_ONLY=0
FORCE=0
WANT_TAG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        --force) FORCE=1; shift ;;
        --tag) WANT_TAG="$2"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

step() { printf '\n=== %s\n' "$1"; }
die()  { printf '\nFATAL: %s\n' "$1" >&2; exit 1; }

check_origin() {
    local actual
    actual=$(git -C "$SRC" remote get-url origin 2>/dev/null || echo "")
    case "$actual" in
        "$REPO_URL"|"$REPO_URL.git") return 0 ;;
        *) die "origin is '$actual', expected '$REPO_URL'.
Refusing to fetch from an unexpected remote. Fix with:
  git -C $SRC remote set-url origin $REPO_URL" ;;
    esac
}

ensure_git_checkout() {
    # The installer pushes a tarball, not a clone, so the first update has to
    # convert the directory into a real checkout. The existing tree is kept —
    # /etc and /var/lib are elsewhere, but a half-deleted source tree during
    # an update is still a bad place to be interrupted.
    if [ -d "$SRC/.git" ]; then
        check_origin
        return
    fi
    step "converting $SRC into a git checkout"
    git -C "$SRC" init -q
    git -C "$SRC" remote add origin "$REPO_URL"
}

step "fetching"
[ -d "$SRC" ] || die "$SRC does not exist — was this container provisioned?"
ensure_git_checkout
# --force matters: without it a moved tag is silently ignored and this updater
# rebuilds the same commit forever. --prune drops tags deleted upstream.
git -C "$SRC" fetch --tags --force --prune origin

CURRENT=$(git -C "$SRC" describe --tags --exact-match 2>/dev/null || echo "none")
if [ -n "$WANT_TAG" ]; then
    TARGET="$WANT_TAG"
else
    TARGET=$(git -C "$SRC" tag -l 'v*.*.*' | sort -V | tail -1)
fi
[ -n "$TARGET" ] || die "no v*.*.* tags found on origin"

printf 'current: %s\ntarget:  %s\n' "$CURRENT" "$TARGET"

if [ "$CURRENT" = "$TARGET" ] && [ "$FORCE" != 1 ]; then
    printf 'already up to date\n'
    exit 0
fi
if [ "$CHECK_ONLY" = 1 ]; then
    printf '(--check: nothing changed)\n'
    exit 0
fi

step "checking out $TARGET"
git -C "$SRC" checkout -q --force "$TARGET"

step "building and testing"
# Everything below happens against the working tree. /opt is not touched until
# the suite is green, so a bad release cannot take the running service with it.
cd "$SRC"
make deps
make build
if ! make test >/tmp/tessera-update-test.log 2>&1; then
    printf '\n--- last 40 lines ---\n' >&2
    tail -40 /tmp/tessera-update-test.log >&2
    git -C "$SRC" checkout -q --force "$CURRENT" 2>/dev/null || true
    die "$TARGET fails its own test suite; nothing was installed"
fi
grep -E '[0-9]+ passed' /tmp/tessera-update-test.log | tail -1
make install-check

step "backing up the running install"
# The unit file too, not just the code: a release that changes the sandbox is
# exactly the kind that fails to start, and rolling back the binary while
# leaving the new unit in place would roll back nothing useful.
rm -rf "$PREFIX.prev"
cp -a "$PREFIX" "$PREFIX.prev"
cp -a "$UNIT" "$UNIT.prev"
printf 'backed up to %s.prev and %s.prev\n' "$PREFIX" "$UNIT"

step "installing"
# Reuses the provisioner, so install and update cannot drift apart. It is
# idempotent and it leaves /etc/tessera/tessera.toml and /var/lib/tessera
# alone by construction.
bash "$SRC/install/container-provision.sh"

step "verifying"
ok=0
for _ in $(seq 1 20); do
    if systemctl is-active --quiet tessera; then
        # is-active only says the process exists. Ask it a question.
        code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/browse || echo 000)
        if [ "$code" = "200" ]; then ok=1; break; fi
    fi
    sleep 1
done

if [ "$ok" != 1 ]; then
    printf '\n!!! %s did not come back. Rolling back.\n' "$TARGET" >&2
    journalctl -u tessera -n 40 --no-pager >&2
    systemctl stop tessera || true
    rm -rf "$PREFIX"
    mv "$PREFIX.prev" "$PREFIX"
    mv "$UNIT.prev" "$UNIT"
    systemctl daemon-reload
    systemctl start tessera
    git -C "$SRC" checkout -q --force "$CURRENT" 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet tessera; then
        die "rolled back to $CURRENT, which is running. $TARGET is broken."
    fi
    die "ROLLBACK ALSO FAILED. The service is down. journalctl -u tessera"
fi

printf '\n=== updated %s -> %s, service answering\n' "$CURRENT" "$TARGET"
printf 'previous install kept at %s.prev\n' "$PREFIX"
```

`chmod +x tools/ts-update`. `container-provision.sh` (Task 24) installs it alongside the other tools — add `install -m 0755 "$SRC/tools/ts-update" "$PREFIX/bin/"` and the matching symlink to `/usr/local/bin/ts-update` in that script's install step.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_update_script.py -v`
Expected: PASS, 13 passed.

- [ ] **Step 5: Prove the origin pin fires**

On any machine with git, in a scratch directory:

```bash
mkdir -p /tmp/tsfake && cd /tmp/tsfake && git init -q
git remote add origin https://example.com/not-tessera
SRC=/tmp/tsfake bash -c 'REPO_URL=https://github.com/stevenjc2009-byte/tessera-server; \
  actual=$(git -C /tmp/tsfake remote get-url origin); \
  [ "$actual" = "$REPO_URL" ] || { echo "would refuse: $actual"; exit 1; }'
```

Expected output: `would refuse: https://example.com/not-tessera`, exit 1. This exercises the same comparison `check_origin` makes.

- [ ] **Step 6: Commit**

```bash
git add tools/ts-update tests/test_update_script.py install/container-provision.sh
git commit -m "feat(tools): ts-update with a pinned origin and auto-rollback

--force on fetch --tags (a moved tag is otherwise ignored forever), the
unit file is backed up alongside the code, and the post-install check
asks for /browse rather than trusting systemctl is-active."
```

---

## Task 27: playit service unit and the hardening gate in the update path

**Lane:** F — Phase 9 deployment. **Depends on:** Tasks 22, 24, 26.

Task 22 wrote `systemd/tessera.service` and `install/hardening-check.sh`. This task finishes the deployment wiring: a supervised unit for the playit agent (so the tunnel comes back after a reboot instead of dying with the ssh session that started it), and the `hardening-check` gate wired into `ts-update` so a release that quietly loosens the sandbox cannot install itself.

**Files:**
- Create: `systemd/playit.service`, `tests/test_playit_unit.py`
- Modify: `tools/ts-update`, `install/container-provision.sh`, `install/hardening-check.sh`, `tests/test_update_script.py`

**Interfaces:**
- Consumes: `install/hardening-check.sh` (Task 22), `tools/ts-update` (Task 26).
- Produces: `systemd/playit.service`; `install/hardening-check.sh --profile playit`.

- [ ] **Step 1: Write the failing test**

`tests/test_playit_unit.py`:

```python
from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture
def unit(repo_root: Path) -> str:
    return (repo_root / "systemd" / "playit.service").read_text()


def test_it_runs_as_its_own_user_not_root(unit: str) -> None:
    """The firewall's only outbound allowance for the tunnel is keyed on
    `meta skuid "playit"` (Task 23). If this ran as root or as tessera the
    rules would not match it and the tunnel would silently never connect."""
    assert re.search(r"^User=playit$", unit, re.MULTILINE)


def test_it_does_not_run_as_the_tessera_user(unit: str) -> None:
    """The tessera user has NO outbound accept at all. Sharing the account
    would either break the tunnel or force a hole for the daemon."""
    assert not re.search(r"^User=tessera$", unit, re.MULTILINE)


def test_it_restarts_and_survives_a_reboot(unit: str) -> None:
    assert re.search(r"^Restart=always$", unit, re.MULTILINE)
    assert "WantedBy=multi-user.target" in unit


def test_it_starts_after_the_daemon_and_the_firewall(unit: str) -> None:
    """Bringing the tunnel up before the firewall would open a window in which
    the container is publicly reachable with no rules loaded."""
    after = re.search(r"^After=(.*)$", unit, re.MULTILINE)
    assert after
    assert "nftables.service" in after.group(1)
    assert "tessera.service" in after.group(1)


def test_it_is_sandboxed(unit: str) -> None:
    for setting in (
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateDevices=yes",
        "RestrictSUIDSGID=yes",
        "CapabilityBoundingSet=",
    ):
        assert setting in unit, f"missing {setting}"


def test_it_has_a_memory_ceiling(unit: str) -> None:
    assert re.search(r"^MemoryMax=", unit, re.MULTILINE)


def test_the_secret_lives_outside_the_unit(unit: str) -> None:
    """playit's agent secret is a credential. It belongs in a 0600 file owned
    by the playit user, not in a unit file that is world-readable in /etc and
    echoed by `systemctl show`."""
    assert "playit.toml" in unit
    assert not re.search(r"[0-9a-f]{32}", unit), "something shaped like a secret is inline"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_playit_unit.py -v`
Expected: FAIL — `FileNotFoundError: systemd/playit.service`, 7 errors.

- [ ] **Step 3: Write the unit**

`systemd/playit.service`:

```ini
[Unit]
Description=playit.gg tunnel agent for Tessera
Documentation=https://playit.gg/
# The firewall must be loaded before this dials out, or there is a window in
# which the tunnel is up and the rules are not. tessera.service is ordered
# before it too — a tunnel pointing at a port nothing is listening on just
# produces connection-refused for every visitor.
After=network-online.target nftables.service tessera.service
Wants=network-online.target

[Service]
Type=simple

# The account name is load-bearing, not cosmetic. install/nftables.conf's ONLY
# outbound allowance for the tunnel is:
#     meta skuid "playit" tcp dport { 443, 5525 } accept
# so renaming this user silently kills the tunnel, with no error anywhere but a
# connect timeout. Do not change it without changing the ruleset.
User=playit
Group=playit

# /var/lib/playit, 0700. Holds playit.toml, which contains the agent secret
# produced by the one-time browser claim. That is a credential: it stays in a
# 0600 file owned by this user, never inline in this unit (world-readable in
# /etc) and never in an Environment= line (visible in `systemctl show`).
StateDirectory=playit
StateDirectoryMode=0700

ExecStart=/usr/local/bin/playit --secret_path /var/lib/playit/playit.toml

Restart=always
RestartSec=5s

# ---- sandbox ------------------------------------------------------------
# Lighter than tessera.service on purpose: this is a third-party binary this
# repo does not build, so the settings below are the ones that hold without
# knowing its internals. No capabilities, no writable filesystem outside its
# own state directory, no path to privilege.
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
UMask=0077

RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# NOT set here, and the difference from tessera.service is deliberate:
#   * MemoryDenyWriteExecute — unknown whether this Rust binary's runtime needs
#     W|X pages. Asserting it without measuring would be exactly the guess
#     Task 22 refused to make about our own daemon.
#   * SystemCallFilter=@system-service — a foreign binary's syscall set has not
#     been enumerated, and a filter that kills it on a rare path is worse than
#     no filter because it fails minutes or days later.
# Both become candidates once the agent has run on the real node long enough
# for `systemd-analyze security playit.service` and a journal check to mean
# something. Recorded so the omission reads as a decision, not an oversight.

MemoryMax=128M
TasksMax=32
LimitNOFILE=1024

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_playit_unit.py -v`
Expected: PASS, 7 passed.

- [ ] **Step 5: Create the playit account in the provisioner**

In `install/container-provision.sh`, immediately after the existing `tessera` account block and **before** the nftables load step, add:

```bash
# The playit account exists whether or not the agent is installed yet, because
# install/nftables.conf names it in `meta skuid "playit"`. nft resolves that
# name at LOAD time — if the user does not exist the entire ruleset fails to
# load, and the error is about an unknown user several rules away from anything
# obviously to do with playit.
if ! getent passwd playit >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin playit
    printf 'created system user: playit\n'
fi
```

And alongside the existing `tessera.service` install:

```bash
install -m 0644 "$SRC/systemd/playit.service" /etc/systemd/system/playit.service
# Installed but deliberately NOT enabled: with no claimed secret at
# /var/lib/playit/playit.toml the agent exits immediately, and Restart=always
# turns that into a restart loop filling the journal. The README's manual claim
# step ends with `systemctl enable --now playit`, which is the first moment it
# can actually work.
```

- [ ] **Step 6: Prove the ordering claim rather than asserting it**

The comment above claims an unknown `skuid` name fails the whole ruleset load. Check it, on any Linux box with nftables:

```bash
printf 'table inet t {\n chain c {\n  type filter hook output priority 0; policy accept;\n  meta skuid "nosuchuser0" accept\n }\n}\n' > /tmp/bad.nft
nft -c -f /tmp/bad.nft; echo "exit=$?"
```

Expected: non-zero exit with a message naming the unknown user. Paste the verbatim message into the commit body.

If it exits 0 instead, the comment is wrong and must be rewritten to say what actually happens. Do not leave a justification in the tree that the tool disagrees with — a confident wrong comment is worse than none, because the next person stops checking.

- [ ] **Step 7: Add the playit profile to the hardening checker**

`install/hardening-check.sh` (Task 22) currently checks one required-settings list. Give it a `--profile` flag:

```bash
PROFILE=default
UNIT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        *) UNIT="$1"; shift ;;
    esac
done
[ -n "$UNIT" ] || { printf 'usage: hardening-check.sh <unit> [--profile playit]\n' >&2; exit 2; }

case "$PROFILE" in
    default)
        REQUIRED="CapabilityBoundingSet= NoNewPrivileges=yes ProtectSystem=strict
ProtectHome=yes PrivateTmp=yes PrivateDevices=yes ProtectKernelModules=yes
ProtectKernelTunables=yes ProtectControlGroups=yes RestrictNamespaces=yes
RestrictSUIDSGID=yes LockPersonality=yes RemoveIPC=yes UMask=0077
SystemCallArchitectures=native SystemCallFilter=@system-service" ;;
    playit)
        # Deliberately shorter. MemoryDenyWriteExecute and SystemCallFilter are
        # NOT demanded of a third-party binary whose syscall set and memory
        # behaviour this repo has not measured — see systemd/playit.service.
        REQUIRED="CapabilityBoundingSet= NoNewPrivileges=yes ProtectSystem=strict
ProtectHome=yes PrivateDevices=yes RestrictSUIDSGID=yes RemoveIPC=yes UMask=0077" ;;
    *) printf 'unknown profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac

printf 'hardening-check: %s (profile: %s)\n' "$UNIT" "$PROFILE"
missing=0
for setting in $REQUIRED; do
    grep -qF -- "$setting" "$UNIT" || { printf '  MISSING: %s\n' "$setting"; missing=1; }
done
grep -qE '^MemoryMax=' "$UNIT" || { printf '  MISSING: MemoryMax=\n'; missing=1; }
[ "$missing" = 0 ] || exit 1
printf '  ok\n'
```

The `printf` naming the unit is not decoration: a checker that silently checks zero files also exits 0, so the output has to name what it looked at.

Update the `hardening-check` Makefile target to run both:

```make
hardening-check:
	@bash install/hardening-check.sh systemd/tessera.service
	@bash install/hardening-check.sh systemd/playit.service --profile playit
```

- [ ] **Step 8: Gate the update path on it**

In `tools/ts-update`, immediately after the existing `make install-check` line:

```bash
# Task 22's checker, run against the unit the NEW release wants to install —
# not the one currently in /etc. A release that drops NoNewPrivileges or adds a
# capability would otherwise install itself with the sandbox quietly weakened
# and nothing in the output to say so.
bash "$SRC/install/hardening-check.sh" "$SRC/systemd/tessera.service"
bash "$SRC/install/hardening-check.sh" "$SRC/systemd/playit.service" --profile playit
```

Add to `tests/test_update_script.py`:

```python
def test_the_update_path_runs_the_hardening_check(script: str) -> None:
    """Otherwise a release can loosen the sandbox and be installed by an
    updater that reports success."""
    assert "hardening-check.sh" in script
    assert script.index("hardening-check.sh") < script.index("container-provision.sh")
```

- [ ] **Step 9: Run it and prove the checker can go red**

Run: `make hardening-check`
Expected: exit 0, and the output must contain **both** `systemd/tessera.service` and `systemd/playit.service (profile: playit)`. If only one line appears, the second invocation is not wired.

Now sabotage it: delete the `NoNewPrivileges=yes` line from `systemd/playit.service` and run `make hardening-check` again.
Expected: non-zero exit, output `MISSING: NoNewPrivileges=yes` under the `playit.service` heading. Restore the line and confirm exit 0 returns.

Second sabotage, to prove the profiles are actually distinct: run
`bash install/hardening-check.sh systemd/playit.service` with **no** `--profile`.
Expected: it FAILS, reporting `MISSING: SystemCallFilter=@system-service` among others. If it passes, the default profile is not demanding what it claims to and `tessera.service` is being checked against nothing.

Run: `python3 -m pytest tests/test_playit_unit.py tests/test_update_script.py -v`
Expected: PASS, 21 passed.

- [ ] **Step 10: Commit**

```bash
git add systemd/playit.service tests/test_playit_unit.py \
        install/container-provision.sh install/hardening-check.sh \
        tools/ts-update tests/test_update_script.py Makefile
git commit -m "feat(deploy): supervised playit unit, hardening check in the update path

The playit account is created by the provisioner before the agent exists,
because install/nftables.conf names it in meta skuid and nft fails the
whole ruleset load on an unknown user. The unit is installed but NOT
enabled — with no claimed secret the agent restart-loops."
```

---

## Task 28: README — one-line invocation, the manual playit steps, and the verification gaps

**Lane:** F — Phase 9 deployment. **Depends on:** every preceding task.

The last task, and the only one whose deliverable is prose. It must be honest about what has and has not been proven. Blocksmith's README is candid that no real traffic has ever crossed its playit tunnel; this README has to be equally candid rather than quietly inheriting the same gap.

**Files:**
- Modify: `README.md`
- Create: `tests/test_readme_claims.py`

**Interfaces:**
- Consumes: every command name and path defined by Tasks 1–27.
- Produces: nothing code depends on.

- [ ] **Step 1: Write the failing test**

`tests/test_readme_claims.py`:

```python
from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture
def readme(repo_root: Path) -> str:
    return (repo_root / "README.md").read_text(encoding="utf-8")


def test_every_command_the_readme_names_actually_exists(readme: str, repo_root: Path) -> None:
    """A README naming a tool the repo does not ship is the cheapest kind of
    lie to write and the most annoying to discover at 2am on a console."""
    for tool in sorted(set(re.findall(r"\b(tessera-[a-z]+|ts-update)\b", readme))):
        assert (repo_root / "tools" / tool).exists(), f"README names {tool}, which does not exist"


def test_every_repo_path_the_readme_names_exists(readme: str, repo_root: Path) -> None:
    for path in sorted(set(re.findall(r"`((?:install|systemd|tools|src)/[\w./-]+)`", readme))):
        assert (repo_root / path).exists(), f"README names {path}, which does not exist"


def test_it_documents_the_playit_claim_step(readme: str) -> None:
    lowered = readme.lower()
    assert "playit" in lowered
    assert "claim" in lowered


def test_it_says_proxy_protocol_v2_must_be_enabled_on_the_tunnel(readme: str) -> None:
    """Without it every request appears to come from 127.0.0.1 and the per-IP
    limiter degrades to one shared bucket for the entire internet — silently,
    with no error and no log line."""
    assert re.search(r"proxy[- ]protocol", readme, re.IGNORECASE)
    assert re.search(r"\bv2\b", readme)


GAPS_HEADING = re.compile(r"^#+\s*what has NOT been verified\s*$", re.IGNORECASE | re.MULTILINE)


def test_it_has_a_verification_gaps_section(readme: str) -> None:
    assert GAPS_HEADING.search(readme)


def test_the_gaps_section_names_the_playit_tunnel_and_the_console(readme: str) -> None:
    """Blocksmith's README admits no real traffic ever crossed its tunnel.
    Inheriting that gap silently is the failure this test exists to prevent."""
    match = GAPS_HEADING.search(readme)
    assert match, "no verification-gaps section"
    body = readme[match.end():].split("\n## ")[0].lower()
    assert "playit" in body
    assert "3ds" in body or "console" in body
    assert "nftables" in body or "firewall" in body


def test_it_does_not_claim_the_tunnel_is_proven(readme: str) -> None:
    lowered = readme.lower()
    for phrase in ("tunnel is verified", "tunnel has been tested",
                   "end-to-end verified", "fully verified", "battle-tested"):
        assert phrase not in lowered, f"unproven claim: {phrase}"


def test_it_says_the_server_never_decodes_images(readme: str) -> None:
    lowered = readme.lower()
    assert "decode" in lowered
    assert "opaque" in lowered


def test_the_one_line_invocation_is_present(readme: str) -> None:
    assert "proxmox-install.sh" in readme
    assert "--ctid" in readme


def test_relative_markdown_links_point_at_files_that_exist(readme: str, repo_root: Path) -> None:
    for target in re.findall(r"\]\((?!https?:|#)([^)#]+)\)", readme):
        assert (repo_root / target.strip()).exists(), f"dead link: {target}"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_readme_claims.py -v`
Expected: FAIL on most of the ten — the README in the repo today predates every tool in this plan and has no gaps section at all.

- [ ] **Step 3: Rewrite the README**

Replace `README.md` with the following.

````markdown
# tessera-server

The gallery server for Tessera. A 3DS uploads a model it made, browses what
other people made, and downloads one back. This repo is the server half only —
the console client lives in the parent project and shares no code with it.

## What it is

A single Python daemon on loopback behind a playit.gg tunnel. SQLite for
metadata, content-addressed files on disk for blobs. No framework, no
dependencies outside the Debian archive, no TLS.

**No TLS is a deliberate constraint, not an omission.** The 3DS's `ssl:C`
service tops out at TLS 1.1, which no current endpoint will negotiate. So
transport is plain HTTP and every state-changing request is signed with the
console's own libhydrogen keypair, carrying a nonce and a timestamp checked
against a sliding replay window. Reads are unsigned; a write without a valid
signature is refused with 401 before its body is looked at.

**The server never decodes an uploaded image.** The console renders its own
thumbnail and uploads it; the server stores opaque bytes and serves them back
as `application/octet-stream` with `X-Content-Type-Options: nosniff`. There is
no image library in the dependency set and no decode path in the source —
`make install-check` walks the AST of every module and fails the build if one
appears. Uploads are stored under the SHA-256 of their own content, never under
a name the uploader chose.

**Moderation is pull-based with zero egress.** Reports land in the database. A
human runs `tessera-reports` on the box to read them. There is no webhook, no
email, no push, and the firewall would drop it if there were.

## Install

On the Proxmox host, as root:

```bash
git clone https://github.com/stevenjc2009-byte/tessera-server
cd tessera-server
./install/proxmox-install.sh --ctid 231
```

That creates an unprivileged LXC, installs the Debian packages, builds
libhydrogen at its pinned commit, **runs the full test suite and refuses to
install anything if it fails**, loads the firewall, starts the hardened unit,
and smoke-tests that `/browse` answers 200 and that an unsigned `POST /vote` is
refused with 400.

Read it first if you like — `./install/proxmox-install.sh --ctid 231 --dry-run`
prints every command and changes nothing.

### DNS

`--nameserver` defaults to `1.1.1.1 9.9.9.9`, and that default matters. The
firewall drops every RFC1918 destination, so a LAN resolver cannot be reached
and the container would be unable to resolve anything at all. If you genuinely
must use a LAN resolver, `--allow-lan-dns` punches a single `/32` hole for it on
port 53 and warns loudly. Nothing else in RFC1918 is reachable either way.

## The two steps that cannot be scripted

Claiming a playit agent needs a browser login, and the tunnel's public address
is assigned afterwards. Both are done by hand, once:

```bash
pct enter 231
curl -sSL https://playit.gg/downloads/playit-linux-amd64 -o /usr/local/bin/playit
chmod +x /usr/local/bin/playit
install -d -o playit -g playit -m 0700 /var/lib/playit
playit --secret_path /var/lib/playit/playit.toml
# follow the claim URL it prints and approve it in a browser
chown playit:playit /var/lib/playit/playit.toml
systemctl enable --now playit
```

Then, in the playit web UI, create a **TCP tunnel to 127.0.0.1:8080 with PROXY
protocol v2 enabled**.

Enabling proxy-protocol v2 is not optional. Without it every request arrives
from 127.0.0.1 and the per-IP token bucket becomes one shared bucket for the
whole internet. Nothing errors, nothing logs, the rate limit simply stops being
a rate limit. The daemon refuses PROXY protocol **v1** outright, so a tunnel
misconfigured for v1 fails loudly instead — that is the intended failure mode.

The tunnel's public address is what goes into the 3DS client.

## Running it

```bash
pct enter 231
tessera-keys new                    # keypair; the secret goes on your console
tessera-keys admin-add <public-key-hex>
systemctl restart tessera

tessera-reports list                # the moderation queue
tessera-reports show 42
tessera-reports delete 42 --reason "..."
tessera-reports ban <author-key>    # removes everything that key uploaded

ts-update --check                   # what a new release would do
ts-update                           # build, test, install, verify, auto-rollback
```

`ts-update` builds and runs the incoming release's own test suite before
touching `/opt`, backs up the binaries **and** the unit files, and rolls back
automatically if `/browse` does not answer 200 within 20 seconds. It fetches
from a pinned origin URL and refuses to run if `origin` points anywhere else.

## Configuration

`/etc/tessera/tessera.toml`, written once at install and never overwritten by
an update, because it holds the admin keys.

Everything that could reasonably need tuning is a config value rather than a
constant — including `report_autohide_threshold` (default 3: three *distinct*
reporter keys unlist a model pending review), the per-key daily upload quota
(default 8), the global hourly cap, the per-request and per-blob byte ceilings,
and the total disk cap.

State lives in `/var/lib/tessera` — `tessera.db` plus the content-addressed
blob tree. No install or update path touches it.

## The firewall

`install/nftables.conf`. Input, forward and output all default-drop.

It differs from the Blocksmith server it is modelled on in one deliberate way:
there is **no blanket `meta skuid root accept`**, and there are explicit drops
for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` and
`224.0.0.0/4` placed **above** every accept rule. Blocksmith's root can reach
the LAN; this container's cannot. Root gets ports 80 and 443 only, for apt and
git; the `tessera` user gets no outbound allowance at all.

`install/nftables-check.sh --live` reads the rules actually loaded in the
kernel and verifies all of that, **including the ordering** — an accept above
the drops would defeat them, so ordering is checked rather than assumed.

## Development

```bash
make deps          # fetch and build libhydrogen at its pinned commit
make build
make test          # the full suite, against a real live server on a real socket
make install-check # no-decode AST scan, pinned-commit check
make hardening-check
```

Tests start an actual HTTP server on a real port and speak to it over a real
socket. Signature verification, rate limiting, quotas and the no-decode
guarantee each have a negative test, and each negative test has a documented
sabotage that must make it go red.

One test is **expected to be red** on a fresh clone:
`test_memory_deny_write_execute_records_a_measurement_not_a_guess`. It stays
red until the `MEASURED:` line in `systemd/tessera.service` is filled in from a
run on the real container. That is what stops `MemoryDenyWriteExecute` being
switched on by guess against a ctypes/libffi runtime that may need `W|X` pages.
Do not silence it; do the measurement.

## What has NOT been verified

Everything above is proven by tests that run on a developer machine. The
following can only be proven on the real Proxmox node, and none of it has been:

- **The playit tunnel has never carried real traffic.** Not one byte from the
  public internet has crossed it, so proxy-protocol v2 parsing has been
  exercised only against headers this repo generates itself. Blocksmith's
  README says exactly the same thing about its own tunnel — this is that same
  gap, not a different one. Until a real request arrives, per-IP rate limiting
  is unproven in production.
- **No 3DS has ever signed a request to this server.** Signature verification
  is tested against keys generated by the same libhydrogen build on the same
  machine. Endianness, context-string agreement and the exact canonical byte
  string are therefore proven against ourselves only. The first real console
  request is the real test.
- **systemd sandbox enforcement in an unprivileged LXC with nesting off.**
  `systemd-analyze security` scores the unit; it does not prove the kernel
  applies the restrictions inside that container. `MemoryDenyWriteExecute`
  ships commented out for the reason above.
- **nftables actually filtering.** `nft -c` proves the ruleset parses and
  `nftables-check.sh --live` proves it loaded in the right order. Only traffic
  proves it filters. The RFC1918 drops in particular have never been verified
  by attempting a connection to a LAN host and being refused.
- **`pct`, `pveam` and `pvesm` behaviour.** The installer's Proxmox calls are
  tested as text and with `bash -n`; the real storage autodetect and template
  selection have not run.
- **`make deps` reaching github through the new firewall.** Root is allowed 80
  and 443, which should suffice, but that has not been observed from inside a
  container with these rules loaded.
- **Disk-cap and quota behaviour at real volume.** The caps are proven by
  shrinking them to trivially small values in tests, not by filling a real 8GB
  rootfs.

When any of these is genuinely exercised, move it out of this list and write
down what was observed. Do not delete an item because it seems likely to work.
````

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_readme_claims.py -v`
Expected: PASS, 10 passed.

If `test_every_repo_path_the_readme_names_exists` fails, the README names a path no task creates. Fix the README, not the test — the test is the thing keeping the two in step.

- [ ] **Step 5: Prove the honesty tests can go red**

Three sabotages, each expected to produce a *different* failure. A gaps section no test defends is a gaps section that gets deleted in a tidy-up six months from now.

1. Add the line `The playit tunnel is verified end-to-end.` near the top.
   Expected: `test_it_does_not_claim_the_tunnel_is_proven` FAILS with
   `unproven claim: end-to-end verified`. Remove it; confirm green.
2. Delete the `## What has NOT been verified` heading (leaving its body).
   Expected: **two** failures — `test_it_has_a_verification_gaps_section` and
   `test_the_gaps_section_names_the_playit_tunnel_and_the_console`. Restore it.
3. Change `tessera-keys` to `tessera-key` in one command block.
   Expected: `test_every_command_the_readme_names_actually_exists` FAILS with
   `README names tessera-key, which does not exist`. Restore it.

Record the three verbatim failure messages in the commit body. If any sabotage produces a *pass*, that test is not checking what it claims to.

- [ ] **Step 6: Run the whole suite and record the real numbers**

Run: `python3 -m pytest tests/ -q`
Expected: one failure — `test_memory_deny_write_execute_records_a_measurement_not_a_guess` — and nothing else. Record the exact `N passed, 1 failed` line.

That single red is deliberate and is documented in the README's Development section. If the suite is fully green at this point, something has silenced it, and `MemoryDenyWriteExecute` is one careless edit away from being enabled by guess.

Run: `make install-check` — expected exit 0.
Run: `make hardening-check` — expected exit 0, naming both units.

- [ ] **Step 7: Commit**

```bash
git add README.md tests/test_readme_claims.py
git commit -m "docs: README with the manual playit steps and an honest gaps list

The verification-gaps section is defended by tests: deleting it, or adding
a claim that the tunnel is proven, turns the suite red. Blocksmith's README
is candid that no real traffic ever crossed its tunnel; this one says the
same about its own rather than inheriting the gap silently."
```

---

## Verification Gaps

Repeated here as well as in the README, because a plan that records its gaps only inside a deliverable can be executed without anyone reading them.

**Proven on a developer machine, by this plan:** signing and verification against the real libhydrogen build; the replay window; the content-addressed store including path-traversal refusal; quotas and both token buckets; every HTTP endpoint against a live server on a real socket; PROXY protocol v2 parsing and v1 refusal; the auto-hide threshold being read from config rather than hardcoded; admin actions and the append-only log; the CLI tools staying coherent with the HTTP path; the absence of any image-decode path; the nftables ruleset as text including rule ordering; every shell script under `bash -n` and `shellcheck`.

**Provable only on the real Proxmox node:**

| Gap | What it means if it is wrong |
|---|---|
| playit tunnel end-to-end with proxy-protocol v2 | Per-IP rate limiting silently degrades to one global bucket. No error, no log line. This is Blocksmith's own admitted gap and it is not closed here. |
| Real 3DS signing interop | Every write from a real console fails 401. Cause would be a canonical-string or context-string disagreement, invisible until a console tries. |
| `MemoryDenyWriteExecute` with ctypes/libffi | If enabled untested and libffi needs `W`+`X` pages, the daemon dies at an arbitrary later moment. Ships commented out, held by the one deliberately-red test (Task 22). |
| systemd sandbox actually enforced in an unprivileged LXC, nesting off | The hardening block reads as protection the kernel may not be applying. `systemd-analyze security` scores the unit, not the container. |
| nftables actually filtering | The LAN wall is a stated hard requirement, verified by reading the loaded ruleset, never by a refused connection to a LAN host. |
| `pct` / `pveam` / `pvesm` behaviour | Installer aborts partway and leaves a half-created container. Recoverable, but unpleasant. |
| `make deps` fetching libhydrogen through the firewall | First install fails at the build step. Root has 80/443, which should suffice; unobserved. |
| Disk-cap and quota behaviour at real volume | Caps are proven by shrinking them, not by filling a real rootfs. Behaviour at a genuinely full disk is inferred. |

**First actions on the real node,** in this order, before trusting anything: run `make test` inside the container and read the count; run `install/nftables-check.sh --live`; do the `MemoryDenyWriteExecute` measurement from Task 22 Step 5 and fill in the `MEASURED:` line; then send one real signed request from a console and read the result.

---

## Self-Review

**1. Spec coverage.** Walked sections 4, 5, 6 and 7 of `docs/superpowers/specs/2026-09-07-tessera-design.md` against the task list.

*Phase 7* — HTTP daemon (Task 10), SQLite schema (Task 5), upload (Task 12), browse (Task 13), download of model and thumbnail (Task 14), request signing (Tasks 2, 3, 4, 11). Covered.

*Phase 8* — votes (Task 16), favourites (Task 17), reports (Task 18), auto-hide at a configurable count of distinct reporter keys (Task 19), admin queue and actions (Task 20), moderation CLI (Task 21). Covered.

*Phase 9* — systemd (Tasks 22, 27), nftables with the mandated RFC1918 drops and no blanket root accept (Task 23), container provisioning (Task 24), host installer and the one-line invocation (Task 25), self-update (Task 26), playit and the README (Tasks 27, 28). Covered.

*Standing constraints* — never decode an image (Task 15, plus the AST scan wired into `make install-check` in Task 1), store by content hash (Task 6), zero egress for reports (Task 18's `ss(8)` test plus the firewall in Task 23), libhydrogen pinned at `617036a353cd4f6478ab6c3f98c36dd31e23ce8e` (Task 1's Makefile and Task 2's binding, with `make install-check` verifying the checked-out commit). Covered.

**One gap, and it is deliberate.** The spec's endpoint table has `POST /favourite` but nothing that reads favourites back, so a console can set a heart and never see it again. Adding `GET /favourites` would be a scope change, which is not mine to make. It is carried in **Task 17, Step 6** as a fully-written but explicitly gated block marked *NOT IN SPEC — do not implement without steve's yes*, with the five points of context. Either he says yes and that block is un-gated, or the client is written knowing hearts are write-only.

**2. Placeholder scan.** Searched the plan for TBD, TODO, "implement later", "add appropriate error handling", "handle edge cases", "similar to Task N", and steps that describe code without showing it. None found.

The only unfilled value in any produced artefact is the `MEASURED: <fill in ...>` marker in `systemd/tessera.service`, and it is guarded by a test that stays red until it is filled — a mechanism, not a placeholder.

Three temporary artefacts are created and deleted on purpose, each with a `grep` check and a stated expected hit count: the two `_placeholder` routes from Task 11 (deleted in Tasks 16 and 20, expected hits one then zero), and the stub `apply_autohide` from Task 18 (deleted in Task 19 Step 4, `grep -n "def apply_autohide" src/tessera/*.py` must return exactly one hit).

**3. Type consistency.** Checked names across task boundaries.

- `TesseraConfig` field names are used identically in Tasks 1, 7, 9, 12, 13, 19 and 24.
- `SignedIdentity(key_hex, is_admin)` is produced in Task 3 and consumed in Tasks 11, 12, 16, 17, 18 and 20 under those exact field names.
- `apply_autohide(app, model_id) -> tuple[int, bool]` has one signature in Tasks 18, 19 and 21.
- `BlobStore.put` / `BlobStore.path_for` are consistent between Tasks 6, 12, 14 and 15.
- `SignatureError(status, code, detail)` and `QuotaError(status, code, detail)` share a shape and both render through the single `error()` helper from Task 10.
- The Makefile targets named in Tasks 1, 22, 24, 26, 27 and 28 are the same six: `deps`, `build`, `test`, `install-check`, `hardening-check`, `clean`.

Two things corrected during this review rather than left for the implementer:

- Task 26 installed `ts-update` but nothing ever copied it into `/opt/tessera/bin`, so the README's `ts-update` command would not have existed on a fresh box. Task 26 Step 3 now amends `container-provision.sh` explicitly. Task 28's `test_every_command_the_readme_names_actually_exists` would have caught it, but at the very last task.
- `install/hardening-check.sh` was called with one argument in Task 22 and two in Task 27. Task 27 Step 7 now defines the `--profile` flag properly instead of assuming it.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-09-07-tessera-server-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration. It suits this plan particularly well: Lanes A, B and C (Tasks 2–10) touch disjoint files and can run in parallel once Task 1 lands, and Lane F (Tasks 22–28) depends only on Task 1 until Task 27, so the whole deployment side can be built alongside the daemon rather than after it.

**2. Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints for review.

Which approach?
