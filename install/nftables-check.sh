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
