#!/usr/bin/env bash
#
# Provision the Tessera container. Runs INSIDE the container, as root, with
# the source tree already at /usr/local/src/tessera-server.
#
# Idempotent by construction: every step either checks first or uses a form
# that converges. It is run once at install and again by tools/ts-update on
# every upgrade, so "already done" must be a no-op, never an error.
#
# Deliberately no shell tracing (xtrace) enabled: the config file it writes
# holds admin keys, and tracing would echo them into the install log.
set -euo pipefail

SRC=/usr/local/src/tessera-server
ALLOW_LAN_DNS="${ALLOW_LAN_DNS:-0}"

step() { printf '\n=== %s\n' "$1"; }
die()  { printf '\nFATAL: %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------- DNS ----
# apt's package-list refresh can return success even when every mirror is
# unreachable. Checking resolution first turns "no network" into a clear
# failure here instead of a baffling missing-package failure 200 lines later.
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

# The playit account exists whether or not the agent is installed yet, because
# install/nftables.conf names it in `meta skuid "playit"`. nft resolves that
# name at LOAD time — if the user does not exist the entire ruleset fails to
# load, and the error is about an unknown user several rules away from anything
# obviously to do with playit.
if ! getent passwd playit >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin playit
    printf 'created system user: playit\n'
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
# Declared here, not at the top with SRC: nothing above this line touches the
# filesystem outside /tmp, so the first byte this script writes under /opt or
# /etc happens only after the build above and the test gate above THAT have
# both succeeded.
PREFIX=/opt/tessera
CONF_DIR=/etc/tessera
CONF="$CONF_DIR/tessera.toml"

step "installing to $PREFIX"
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/src"
cp -a "$SRC/src/tessera" "$PREFIX/src/"
cp -a "$SRC/build/libhydrogen.so" "$PREFIX/lib/"
install -m 0755 "$SRC/tools/tessera-reports" "$PREFIX/bin/"
install -m 0755 "$SRC/tools/tessera-keys" "$PREFIX/bin/"
install -m 0755 "$SRC/tools/ts-update" "$PREFIX/bin/"
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
ln -sfn "$PREFIX/bin/ts-update" /usr/local/bin/ts-update

# ------------------------------------------------------------ config -----
step "configuration"
install -d -m 0750 "$CONF_DIR"
chown root:tessera "$CONF_DIR"
if [ ! -f "$CONF_DIR/tessera.toml" ]; then
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

install -m 0644 "$SRC/systemd/playit.service" /etc/systemd/system/playit.service
# Installed but deliberately NOT enabled: with no claimed secret at
# /var/lib/playit/playit.toml the agent exits immediately, and Restart=always
# turns that into a restart loop filling the journal. The README's manual claim
# step ends with `systemctl enable --now playit`, which is the first moment it
# can actually work.

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
