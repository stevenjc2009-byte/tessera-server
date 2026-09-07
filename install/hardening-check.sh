#!/usr/bin/env bash
# Assert the unit still carries every hardening setting. Run after install and
# after every update — an update that silently drops ProtectSystem is exactly
# the failure this exists to catch, and nothing else would notice it.
#
# --profile playit checks systemd/playit.service against a deliberately
# shorter list: it is a third-party binary this repo does not build, so
# MemoryDenyWriteExecute and SystemCallFilter are not demanded of it without
# having measured its actual behaviour (see systemd/playit.service).
set -euo pipefail

PROFILE=default
UNIT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        *) UNIT="$1"; shift ;;
    esac
done
UNIT="${UNIT:-/etc/systemd/system/tessera.service}"

case "$PROFILE" in
    default)
        REQUIRED="NoNewPrivileges=yes ProtectSystem=strict
ProtectHome=yes PrivateTmp=yes PrivateDevices=yes ProtectKernelModules=yes
ProtectKernelTunables=yes ProtectControlGroups=yes RestrictNamespaces=yes
RestrictSUIDSGID=yes LockPersonality=yes RemoveIPC=yes UMask=0077
SystemCallArchitectures=native SystemCallFilter=@system-service" ;;
    playit)
        REQUIRED="NoNewPrivileges=yes ProtectSystem=strict
ProtectHome=yes PrivateDevices=yes RestrictSUIDSGID=yes RemoveIPC=yes UMask=0077" ;;
    *) printf 'unknown profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac

printf 'hardening-check: %s (profile: %s)\n' "$UNIT" "$PROFILE"
fail=0

for setting in $REQUIRED; do
    key="${setting%%=*}"
    val="${setting#*=}"
    if grep -qE "^${key}[[:space:]]*=[[:space:]]*${val}[[:space:]]*$" "$UNIT"; then
        printf '  ok    %s\n' "$setting"
    else
        printf '  MISSING: %s\n' "$setting"
        fail=1
    fi
done

# CapabilityBoundingSet= with an empty value, required in every profile. A
# plain substring match would also pass a NON-empty set (the string
# "CapabilityBoundingSet=CAP_SYS_ADMIN" contains "CapabilityBoundingSet=" too),
# so this is anchored to the bare, empty line specifically.
if grep -qE '^CapabilityBoundingSet[[:space:]]*=[[:space:]]*$' "$UNIT"; then
    printf '  ok    CapabilityBoundingSet= (empty, all capabilities dropped)\n'
else
    printf '  MISSING: CapabilityBoundingSet= (empty)\n'
    fail=1
fi

if ! grep -qE '^MemoryMax=' "$UNIT"; then
    printf '  MISSING: MemoryMax=\n'
    fail=1
fi

# nesting=0 on this LXC means no unit here can use PrivateUsers, regardless of
# profile — the setting requires a user namespace the container does not have.
if grep -q '^PrivateUsers=' "$UNIT"; then
    printf '  FAIL  PrivateUsers is set — this LXC has no nesting, the unit will not start\n'
    fail=1
else
    printf '  ok    PrivateUsers absent (no nesting on this LXC)\n'
fi

# systemd's own opinion, where it is available. Deliberately NOT a gate on the
# score — the number moves between systemd versions — but printed so a
# regression shows up in the install log.
if command -v systemd-analyze >/dev/null 2>&1; then
    unit_name="$(basename "$UNIT")"
    printf '\nsystemd-analyze security %s:\n' "$unit_name"
    systemd-analyze security "$unit_name" 2>&1 | tail -5 || true
fi

if [ "$fail" -ne 0 ]; then
    printf '\nhardening-check FAILED\n' >&2
    exit 1
fi
printf '\nhardening-check passed\n'
