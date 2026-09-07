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
