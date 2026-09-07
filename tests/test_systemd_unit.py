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
