from pathlib import Path

import pytest

from tessera.config import TesseraConfig, load_config


def test_defaults_match_the_spec(tmp_path: Path) -> None:
    cfg = load_config(None, {"TESSERA_STATE_DIR": str(tmp_path)})
    assert cfg.uploads_per_key_per_day == 8
    assert cfg.report_autohide_threshold == 3
    assert cfg.sign_context == "tessera1"
    assert cfg.listen_host == "127.0.0.1"
    assert cfg.proxy_protocol is False
    assert cfg.report_reasons == ("gore", "sexual", "hate", "stolen", "spam", "other")


def test_derived_paths_hang_off_state_dir(tmp_path: Path) -> None:
    cfg = load_config(None, {"TESSERA_STATE_DIR": str(tmp_path)})
    assert cfg.blob_dir == tmp_path / "blobs"
    assert cfg.db_path == tmp_path / "tessera.db"


def test_toml_file_overrides_defaults(tmp_path: Path) -> None:
    toml = tmp_path / "tessera.toml"
    toml.write_text(
        'state_dir = "%s"\n'
        "listen_port = 9999\n"
        "uploads_per_key_per_day = 2\n"
        "report_autohide_threshold = 5\n"
        'admin_keys = ["%s"]\n' % (tmp_path.as_posix(), "aa" * 32),
        encoding="utf-8",
    )
    cfg = load_config(toml, {})
    assert cfg.listen_port == 9999
    assert cfg.uploads_per_key_per_day == 2
    assert cfg.report_autohide_threshold == 5
    assert cfg.admin_keys == ("aa" * 32,)


def test_env_overrides_the_toml_file(tmp_path: Path) -> None:
    toml = tmp_path / "tessera.toml"
    toml.write_text('state_dir = "%s"\nlisten_port = 9999\n' % tmp_path.as_posix(), encoding="utf-8")
    cfg = load_config(toml, {"TESSERA_LISTEN_PORT": "4242"})
    assert cfg.listen_port == 4242


def test_bad_admin_key_is_rejected_loudly(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="admin_keys"):
        load_config(None, {"TESSERA_STATE_DIR": str(tmp_path), "TESSERA_ADMIN_KEYS": "not-hex"})


def test_config_is_frozen(tmp_path: Path) -> None:
    cfg = load_config(None, {"TESSERA_STATE_DIR": str(tmp_path)})
    with pytest.raises(Exception):
        cfg.listen_port = 1  # type: ignore[misc]
