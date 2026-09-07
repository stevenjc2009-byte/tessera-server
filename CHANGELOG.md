# Changelog

All notable changes to the Tessera gallery server.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version this file's topmost released heading names must match the contents
of `VERSION`. Nothing enforces that automatically yet.

## [1.0.0] - 2026-09-08

First release. A public gallery for Tessera creations that a 3DS can talk to
directly, reachable from the open internet through playit.gg, and built so that
a compromise of the service reaches a dead end.

### Added

- **Signed plain HTTP transport.** Every mutating request carries a
  libhydrogen signature over a canonical string, checked against the sender's
  public key, with a replay window. This is deliberately not TLS: the 3DS's
  `ssl:C` service tops out at TLS 1.1, so a TLS-terminating server would have
  had to accept a downgraded connection to be reachable at all. Signing the
  requests instead gives integrity and authenticity without asking the console
  to do something it cannot do well.
- **Content-addressed blob store.** Uploads are stored under the hash of their
  bytes, never under a filename the uploader chose, so a crafted name cannot
  escape the store directory or collide with another user's file.
- **The server never decodes an uploaded image.** The console uploads its own
  thumbnail alongside the artwork and the server stores both as opaque bytes.
  An image decoder is the largest attack surface a gallery can have, and this
  one does not have it.
- **Upload quota: 8 per identity per day**, plus per-IP rate limiting.
- **Browse, download, vote and favourite endpoints.** Votes are heart, thumbs
  up and thumbs down.
- **Reports with six fixed reasons** — gore, sexual, hate, stolen, spam,
  other — where `other` carries a free-text reason. The reporter's public key
  is stored with the report. Content auto-hides at
  `report_autohide_threshold` reports, 3 by default
  (`src/tessera/config.py:62`).
- **A pull-based admin queue with ZERO egress.** No webhook, no email, no push
  of any kind. Moderation is done by connecting to the service and reading the
  queue; nothing is ever sent outward, so there is no outbound channel for an
  attacker to inherit. `tools/tessera-reports` is the reader.
- **PROXY protocol v2 parsing**, so the real client address survives the
  playit.gg hop and the rate limiter sees the right IP.
- **A hardened Proxmox LXC deployment** (`install/container-provision.sh`).
  The nftables output chain drops RFC1918 destinations — 10/8, 172.16/12 and
  192.168/16 — above every accept rule, so a compromised service cannot reach
  anything on the home network. There is no blanket
  `meta skuid root accept` escape.
- **systemd hardening**, including `MemoryDenyWriteExecute=yes`. That one was
  measured rather than assumed: the unit's `MEASURED:` comment block records
  the exact `systemd-run --user` commands, all arms, and the red arm — a raw
  `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` refused with `EACCES` — that proves
  the filter actually loaded. Provenance is honest in the file: the
  measurement was taken on WSL2, not on the Proxmox node.
- `tools/tessera-keys` and `tools/ts-update` for key management and updates.
- `install/hardening-check.sh`, which verifies the deployed sandbox on the
  node. **It has not been run on the real node yet.**

### Fixed

- **SIGTERM deadlocked the daemon.** The signal handler called
  `server.shutdown()` directly; `serve_forever()` cannot process that request
  until the handler returns, and the handler could not return until
  `shutdown()` completed. The daemon parked and only died to SIGKILL —
  measured at "still alive 20.070s after SIGTERM ... after SIGKILL: exit code
  137". The handler now hands `shutdown()` to its own thread and returns; the
  same harness then measured a clean exit in 0.220s, which is exactly the
  `poll_interval=0.2` a correct shutdown should cost.

  This also cost the test suite most of its runtime, because
  `tests/conftest.py`'s `LiveServer.stop()` paid the full 5s SIGKILL fallback
  on every live-server test. Over `test_browse.py` and `test_vote.py`, 42
  tests: **222.16s before, 19.77s after**, same 42 passing.

### Known gaps

- The MDWE measurement and the SIGTERM fix were both proven on WSL2, not
  inside the Proxmox LXC under the full sandbox. `install/hardening-check.sh`
  on the node is what closes that gap.
- `systemd/tessera.service` sets no `TimeoutStopSec`, so the effective
  shutdown timeout is systemd's default unless the node's `system.conf`
  overrides `DefaultTimeoutStopSec`. The node was not checked.
- Upload is open to anyone holding the client `.cia`; there is no connection
  password. Identity is a generated key, not an account.
