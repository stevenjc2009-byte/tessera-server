from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def script(repo_root: Path) -> str:
    return (repo_root / "install" / "proxmox-install.sh").read_text()


def test_it_fails_closed(script: str) -> None:
    assert re.search(r"^set -euo pipefail", script, re.MULTILINE)


def test_the_container_is_unprivileged_with_no_nesting(script: str) -> None:
    """Unprivileged is the whole point. nesting=0 is why the unit deliberately
    omits PrivateUsers (Task 22) — the two decisions have to agree, and an
    installer that quietly turned nesting on would make that comment a lie."""
    assert "--unprivileged 1" in script
    assert "nesting=0" in script


def test_the_default_nameservers_are_public(script: str) -> None:
    """The firewall drops RFC1918 destinations, so defaulting to the host's
    resolvers (which is what Blocksmith does) would hand over a container that
    cannot resolve anything. Public resolvers by default."""
    match = re.search(r"NAMESERVER=\$\{NAMESERVER:-([^}]*)\}", script)
    assert match, "NAMESERVER has no default"
    default = match.group(1)
    assert "1.1.1.1" in default or "9.9.9.9" in default
    for lan in ("192.168.", "10.0.", "172.16."):
        assert lan not in default, f"the default resolver {default} is on the LAN"


def test_the_lan_dns_escape_hatch_exists_and_is_off_by_default(script: str) -> None:
    assert "--allow-lan-dns" in script
    assert re.search(r"ALLOW_LAN_DNS=\$\{ALLOW_LAN_DNS:-0\}", script)


def test_it_autodetects_storage_rather_than_hardcoding_it(script: str) -> None:
    assert "pvesm status" in script
    assert "--content rootdir" in script


def test_it_selects_a_template_rather_than_hardcoding_a_filename(script: str) -> None:
    assert "pveam" in script
    assert "pveam update" in script


def test_it_waits_for_systemd_inside_the_container(script: str) -> None:
    """`pct start` returns long before the container's systemd has reached
    multi-user.target. Running apt against a half-booted container fails in
    confusing ways."""
    assert "systemctl is-system-running" in script or "is-active" in script
    assert re.search(r"for .* in .*(seq|\d+ \d+)", script), "no readiness poll loop"


def test_it_refuses_to_clobber_an_existing_ctid(script: str) -> None:
    assert "pct status" in script
    assert re.search(r"(already exists|in use)", script)


def test_it_pushes_the_source_and_calls_the_provisioner(script: str) -> None:
    assert "pct push" in script or "pct exec" in script
    assert "container-provision.sh" in script


def test_it_has_a_dry_run(script: str) -> None:
    """A script that creates a VM on someone's hypervisor should be readable
    before it is trusted."""
    assert "--dry-run" in script


def test_it_prints_the_two_manual_playit_steps(script: str) -> None:
    """The playit tunnel cannot be fully scripted: claiming the agent needs a
    browser login, and the tunnel's public address is assigned afterwards. The
    installer must SAY so rather than appear to have finished the job."""
    lowered = script.lower()
    assert "playit" in lowered
    assert "claim" in lowered
    assert re.search(r"(manual|by hand|you must|browser)", lowered)


def test_it_never_echoes_the_root_password(script: str) -> None:
    assert "set -x" not in script
    assert re.search(r"(--password|PASSWORD)", script)


def test_bash_can_parse_it(repo_root: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    result = subprocess.run(
        ["bash", "-n", str(repo_root / "install" / "proxmox-install.sh")],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_it_passes_shellcheck(repo_root: Path) -> None:
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(
        ["shellcheck", "-S", "warning", str(repo_root / "install" / "proxmox-install.sh")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout
