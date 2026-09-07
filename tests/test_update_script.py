from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_URL = "https://github.com/stevenjc2009-byte/tessera-server"


@pytest.fixture
def script(repo_root: Path) -> str:
    return (repo_root / "tools" / "ts-update").read_text()


def test_it_fails_closed(script: str) -> None:
    assert re.search(r"^set -euo pipefail", script, re.MULTILINE)


def test_the_origin_is_pinned_in_the_script(script: str) -> None:
    """A self-updater that fetches from whatever `origin` happens to point at
    is a self-updater that can be redirected by anyone who can write the git
    config. The URL is baked in and checked."""
    assert REPO_URL in script
    assert re.search(r"(check_origin|remote get-url)", script)


def test_it_force_fetches_tags(script: str) -> None:
    """`git fetch --tags` alone will not update a tag that moved. A
    force-pushed tag bricked Blocksmith's deployed updaters — they kept
    building the old commit forever and reported success."""
    assert "--force" in script
    assert re.search(r"git fetch[^\n]*--tags", script)


def test_it_picks_the_newest_version_tag_by_sort_v(script: str) -> None:
    assert "sort -V" in script
    assert re.search(r"v\[0-9\]|v\*\.\*\.\*|refs/tags", script)


def test_it_builds_and_tests_before_touching_opt(script: str) -> None:
    build_at = script.index("make test")
    install_at = script.index("container-provision.sh")
    assert build_at < install_at, "the tests must pass before anything is installed"


def test_it_backs_up_before_replacing(script: str) -> None:
    assert ".prev" in script
    assert "tessera.service" in script, "the unit file must be backed up too, not just the code"


def test_it_rolls_back_when_the_service_does_not_come_back(script: str) -> None:
    lowered = script.lower()
    assert "rollback" in lowered or "roll back" in lowered
    assert "is-active" in script


def test_it_verifies_the_service_answers_not_merely_that_it_started(script: str) -> None:
    """`systemctl is-active` says the process exists. It does not say the
    daemon is serving. A rollback triggered only on is-active would happily
    leave a broken build running."""
    assert "curl" in script
    assert "/browse" in script


def test_check_mode_changes_nothing(script: str) -> None:
    assert "--check" in script
    assert re.search(r"(--check\)|CHECK_ONLY)", script)


def test_it_never_deletes_the_state_directory(script: str) -> None:
    """The blobs and the database live in /var/lib/tessera. An update must
    never touch it, and `rm -rf` anywhere near that path is how a bad update
    becomes an unrecoverable one."""
    assert not re.search(r"rm\s+-rf\s+/var/lib/tessera", script)


def test_it_never_overwrites_the_config(script: str) -> None:
    assert not re.search(r">\s*/etc/tessera/tessera\.toml", script)


def test_the_update_path_runs_the_hardening_check(script: str) -> None:
    """Otherwise a release can loosen the sandbox and be installed by an
    updater that reports success."""
    assert "hardening-check.sh" in script
    assert script.index("hardening-check.sh") < script.index("container-provision.sh")


def test_bash_can_parse_it(repo_root: Path) -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    result = subprocess.run(["bash", "-n", str(repo_root / "tools" / "ts-update")],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_it_passes_shellcheck(repo_root: Path) -> None:
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    result = subprocess.run(
        ["shellcheck", "-S", "warning", str(repo_root / "tools" / "ts-update")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout
