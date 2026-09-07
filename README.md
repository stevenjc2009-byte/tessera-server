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
