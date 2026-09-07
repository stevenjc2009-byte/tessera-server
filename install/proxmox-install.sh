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
NAMESERVER=${NAMESERVER:-1.1.1.1 9.9.9.9}
ALLOW_LAN_DNS=${ALLOW_LAN_DNS:-0}
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

# Check the resolver before the pct check, not after: catching a bad
# --nameserver here saves creating and destroying a container to find out,
# and it means this guard is exercisable on a machine with no `pct` at all.
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

command -v pct >/dev/null || die "pct not found — this must run on a Proxmox host"

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
[ -n "$TEMPLATE" ] || die "no Debian standard template found in pveam available"
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
