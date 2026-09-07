"""Static assertions about the provisioning script.

A shell script cannot be unit tested meaningfully on Windows, so this asserts
the properties that actually matter and that are checkable from the text:
that it fails closed, that it gates on the test suite, that it checks DNS
before apt, and that it refuses an RFC1918 resolver. Whether it PROVISIONS is
proven only by running it on the real node — Step 6.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def script(repo_root: Path) -> str:
    return (repo_root / "install" / "container-provision.sh").read_text()


def test_it_fails_closed(script: str) -> None:
    assert re.search(r"^set -euo pipefail", script, re.MULTILINE), (
        "without `set -e` a failed build step is followed by a successful "
        "install of the previous binary"
    )


def test_it_checks_dns_before_running_apt(script: str) -> None:
    """`apt-get update` exits 0 when its mirrors are unreachable. Blocksmith
    learned this the hard way; the check has to come first, or the failure
    surfaces 200 lines later as a missing package."""
    dns = script.index("getent hosts")
    apt = script.index("apt-get update")
    assert dns < apt, "the DNS check must come before apt-get update"


def test_it_sanity_checks_that_apt_actually_has_packages(script: str) -> None:
    assert "apt-cache policy" in script
    assert re.search(r"Candidate:\s*\[0-9\]", script) or "Candidate: [0-9]" in script


def test_it_refuses_an_rfc1918_resolver(script: str) -> None:
    """The firewall drops all RFC1918 destinations, so a LAN resolver means
    every lookup fails once nftables is loaded. Better to refuse here, loudly,
    than to hand over a container that half works."""
    assert "resolv.conf" in script
    for prefix in ("10.", "172.", "192.168."):
        assert prefix in script, f"no RFC1918 resolver check for {prefix}"
    assert "ALLOW_LAN_DNS" in script


def test_the_test_suite_gates_the_install(script: str) -> None:
    """A build that compiles is not a build that works. `make test` must run,
    and a failure must stop the install rather than be logged and ignored."""
    test_at = script.index("make test")
    install_at = script.index("/opt/tessera")
    assert test_at < install_at, "make test must run before anything is installed"
    assert "tail -" in script, "the test log must be shown on failure, not swallowed"


def test_install_check_and_hardening_check_both_run(script: str) -> None:
    assert "make install-check" in script
    assert "hardening-check.sh" in script


def test_the_firewall_is_loaded_and_verified(script: str) -> None:
    assert "nftables.conf" in script
    assert "nftables-check.sh" in script
    assert "--live" in script, "the LIVE kernel ruleset must be checked, not just the file"


def test_the_firewall_loads_before_the_daemon_starts(script: str) -> None:
    nft = script.index("nftables-check.sh")
    start = script.rindex("systemctl")
    assert nft < start, "the daemon must not start before the firewall is up and verified"


def test_it_creates_a_dedicated_unprivileged_service_account(script: str) -> None:
    assert re.search(r"useradd.*--system", script)
    assert "--no-create-home" in script or "-M" in script
    assert re.search(r"(--shell\s+/usr/sbin/nologin|-s /usr/sbin/nologin)", script)


def test_it_is_idempotent(script: str) -> None:
    """It runs again on every update. Creating a user that exists, or adding a
    duplicate config line, must be a no-op rather than an error."""
    assert "id -u tessera" in script or "getent passwd tessera" in script
    assert re.search(r"if\s+\[\s*!\s+-f\s+.*tessera\.toml", script), (
        "the config file must not be overwritten on a re-run — it holds the "
        "admin keys"
    )


def test_it_never_writes_a_secret_into_the_log(script: str) -> None:
    assert "set -x" not in script, "set -x would echo the admin key into the install log"


def test_it_passes_shellcheck(repo_root: Path) -> None:
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(
        ["shellcheck", "-S", "warning", str(repo_root / "install" / "container-provision.sh")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout


def test_bash_can_parse_it(repo_root: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    result = subprocess.run(
        ["bash", "-n", str(repo_root / "install" / "container-provision.sh")],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
