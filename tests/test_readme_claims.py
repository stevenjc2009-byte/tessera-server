from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture
def readme(repo_root: Path) -> str:
    return (repo_root / "README.md").read_text(encoding="utf-8")


# The project's own name matches the tool-name pattern below: it is the README's
# title heading and the clone URL. It is not a CLI tool, and tools/tessera-server
# must never exist. Excluded by name rather than by loosening the pattern, so the
# test still fails on any OTHER tessera-* command the README invents.
PROJECT_NAME = "tessera-server"


def test_every_command_the_readme_names_actually_exists(readme: str, repo_root: Path) -> None:
    """A README naming a tool the repo does not ship is the cheapest kind of
    lie to write and the most annoying to discover at 2am on a console."""
    named = set(re.findall(r"\b(tessera-[a-z]+|ts-update)\b", readme)) - {PROJECT_NAME}
    assert named, "the tool-name pattern matched nothing, so this test proves nothing"
    for tool in sorted(named):
        assert (repo_root / "tools" / tool).exists(), f"README names {tool}, which does not exist"


def test_every_repo_path_the_readme_names_exists(readme: str, repo_root: Path) -> None:
    for path in sorted(set(re.findall(r"`((?:install|systemd|tools|src)/[\w./-]+)`", readme))):
        assert (repo_root / path).exists(), f"README names {path}, which does not exist"


def test_it_documents_the_playit_claim_step(readme: str) -> None:
    lowered = readme.lower()
    assert "playit" in lowered
    assert "claim" in lowered


def test_it_says_proxy_protocol_v2_must_be_enabled_on_the_tunnel(readme: str) -> None:
    """Without it every request appears to come from 127.0.0.1 and the per-IP
    limiter degrades to one shared bucket for the entire internet — silently,
    with no error and no log line."""
    assert re.search(r"proxy[- ]protocol", readme, re.IGNORECASE)
    assert re.search(r"\bv2\b", readme)


GAPS_HEADING = re.compile(r"^#+\s*what has NOT been verified\s*$", re.IGNORECASE | re.MULTILINE)


def test_it_has_a_verification_gaps_section(readme: str) -> None:
    assert GAPS_HEADING.search(readme)


def test_the_gaps_section_names_the_playit_tunnel_and_the_console(readme: str) -> None:
    """Blocksmith's README admits no real traffic ever crossed its tunnel.
    Inheriting that gap silently is the failure this test exists to prevent."""
    match = GAPS_HEADING.search(readme)
    assert match, "no verification-gaps section"
    body = readme[match.end():].split("\n## ")[0].lower()
    assert "playit" in body
    assert "3ds" in body or "console" in body
    assert "nftables" in body or "firewall" in body


def test_it_does_not_claim_the_tunnel_is_proven(readme: str) -> None:
    lowered = readme.lower()
    for phrase in ("tunnel is verified", "tunnel has been tested",
                   "end-to-end verified", "fully verified", "battle-tested"):
        assert phrase not in lowered, f"unproven claim: {phrase}"


def test_it_says_the_server_never_decodes_images(readme: str) -> None:
    lowered = readme.lower()
    assert "decode" in lowered
    assert "opaque" in lowered


def test_the_one_line_invocation_is_present(readme: str) -> None:
    assert "proxmox-install.sh" in readme
    assert "--ctid" in readme


def test_relative_markdown_links_point_at_files_that_exist(readme: str, repo_root: Path) -> None:
    for target in re.findall(r"\]\((?!https?:|#)([^)#]+)\)", readme):
        assert (repo_root / target.strip()).exists(), f"dead link: {target}"
