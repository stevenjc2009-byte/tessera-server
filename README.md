# tessera-server

The public gallery server for [Tessera](https://github.com/stevenjc2009-byte/tessera),
a Nintendo 3DS homebrew pixel art and 3D modelling app.

Consoles upload their creations here; anyone else with the app can browse,
download and rate them.

## Status

**Design approved, no code yet.** The full design lives in the client repo at
`docs/superpowers/specs/2026-09-07-tessera-design.md`.

## Shape

One small HTTP daemon in an unprivileged Proxmox LXC. Files on disk, SQLite
index. Reached through a playit.gg outbound tunnel — no port forward, no home
IP exposed, no inbound ports at all.

## Transport: signed plain HTTP

The 3DS cannot speak modern HTTPS — its `ssl:C` service tops out at TLS 1.1 and
modern servers refuse it.

So: **plain HTTP, with every state-changing request signed by the console's
keypair using libhydrogen.** The gallery content is public, and uploads are open
to anyone with the app, so encryption buys almost nothing. What actually matters
is forgery of identity and votes, and signatures are the right tool for that.

Requests carry a nonce and timestamp checked against a sliding replay window.

## Security model

The requirement: if someone gets in, they reach a dead end and cannot touch the
home network.

- Unprivileged LXC, `nesting=0`, no device passthrough.
- Zero inbound ports; playit.gg dials out.
- nftables default-drop on input **and** output.
- Explicit RFC1918 destination drops, and no blanket root egress accept.
- Heavy systemd sandbox — empty capability set, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, syscall filtering, memory and task caps.
- **The server never decodes uploaded images.** Running a memory-unsafe parser
  on hostile input is the likeliest way in, so the console uploads its own
  thumbnail and the server only ever stores bytes.
- Uploads stored by content hash, never by a user-supplied filename.

## Open uploads

There is no password. The per-console keypair is an *identity*, not a gate — it
attributes uploads, enforces one vote per person, and gives a ban handle.

Limits: 8 uploads per key per day, per-IP rate limiting via `proxy-protocol-v2`,
a global rate cap, and hard caps on upload size and total disk.

## Moderation

Fixed reason list — gore, sexual, hate, stolen, spam, other. Choosing "other"
opens a text box. The reporter's key is stored so one person cannot report the
same piece repeatedly.

Three distinct reporter keys auto-unlists a model pending review. Reports are
**pull-based with zero egress** — they sit in SQLite and are fetched, never
pushed. Webhook and email delivery were rejected because they require a hole in
the outbound firewall, and a hole outward is what an attacker exfiltrates
through.

## Install

Planned: a one-line invocation pasted into the Proxmox host shell, pinned to a
tag.

```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/stevenjc2009-byte/tessera-server/v1.0.0/install/proxmox-install.sh)"
```

Two steps cannot be scripted and will be documented:

1. `playit setup` needs interactive browser approval — writing a secret to
   `playit.toml` does not work, the daemon ignores it.
2. The tunnel must be created in the playit.gg dashboard as
   **`proxy-protocol-v2`**. Version 1 silently drops traffic with no error.

## Licence

MIT.
