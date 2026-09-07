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
