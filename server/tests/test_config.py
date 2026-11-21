from __future__ import annotations

import json
from pathlib import Path

import pytest

from yournas.core.config import ConfigError, is_loopback_host, load_settings


def test_defaults_with_only_storage_root() -> None:
    s = load_settings({"YOURNAS_STORAGE_ROOT": "C:\\data"})
    assert s.storage_root == Path("C:\\data")
    assert s.host == "127.0.0.1"
    assert s.port == 8000
    assert s.allow_non_loopback is False
    assert s.log_level == "INFO"
    assert s.log_dir is None
    assert s.enable_docs is False


def test_missing_storage_root_is_an_error() -> None:
    with pytest.raises(ConfigError, match="storage_root"):
        load_settings({})


def test_env_overrides_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"storage_root": "C:\\a", "port": 9000, "log_level": "DEBUG"}))
    s = load_settings({"YOURNAS_CONFIG": str(cfg), "YOURNAS_PORT": "9100"})
    assert s.port == 9100
    assert s.log_level == "DEBUG"
    assert s.storage_root == Path("C:\\a")


def test_config_file_in_cwd_is_not_picked_up_implicitly() -> None:
    Path("config.local.json").write_text(json.dumps({"storage_root": "C:\\fromfile"}))
    with pytest.raises(ConfigError, match="storage_root"):
        load_settings({})


def test_empty_environment_value_counts_as_unset() -> None:
    s = load_settings(
        {"YOURNAS_STORAGE_ROOT": "C:\\a", "YOURNAS_LOG_DIR": "", "YOURNAS_PORT": ""}
    )
    assert s.log_dir is None
    assert s.port == 8000


def test_log_dir_inside_storage_root_rejected(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    for inside in (root / "logs", root, root / "users" / "bob"):
        with pytest.raises(ConfigError, match="log_dir"):
            load_settings(
                {"YOURNAS_STORAGE_ROOT": str(root), "YOURNAS_LOG_DIR": str(inside)}
            )


def test_log_dir_beside_storage_root_accepted(tmp_path: Path) -> None:
    root = tmp_path / "data"
    s = load_settings(
        {"YOURNAS_STORAGE_ROOT": str(root), "YOURNAS_LOG_DIR": str(tmp_path / "data-logs")}
    )
    assert s.log_dir == tmp_path / "data-logs"


def test_explicit_missing_config_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings({"YOURNAS_CONFIG": str(tmp_path / "nope.json")})


def test_invalid_json_does_not_echo_contents(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text('{"storage_root": "C:\\\\a", "secret_thing": hunter2')
    with pytest.raises(ConfigError) as exc:
        load_settings({"YOURNAS_CONFIG": str(cfg)})
    assert "not valid JSON" in str(exc.value)
    assert "hunter2" not in str(exc.value)


def test_json_must_be_an_object(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text("[1, 2]")
    with pytest.raises(ConfigError, match="JSON object"):
        load_settings({"YOURNAS_CONFIG": str(cfg)})


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"storage_root": "C:\\a", "storge_typo": 1}))
    with pytest.raises(ConfigError, match="storge_typo"):
        load_settings({"YOURNAS_CONFIG": str(cfg)})


@pytest.mark.parametrize("port", ["0", "70000", "-1", "abc"])
def test_bad_port_is_rejected_without_echoing_value(port: str) -> None:
    with pytest.raises(ConfigError) as exc:
        load_settings({"YOURNAS_STORAGE_ROOT": "C:\\a", "YOURNAS_PORT": port})
    assert "port" in str(exc.value)
    assert f"'{port}'" not in str(exc.value)


def test_bad_log_level_is_rejected() -> None:
    with pytest.raises(ConfigError, match="log_level"):
        load_settings({"YOURNAS_STORAGE_ROOT": "C:\\a", "YOURNAS_LOG_LEVEL": "LOUD"})


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.5.5.5"])
def test_loopback_hosts_accepted(host: str) -> None:
    assert load_settings({"YOURNAS_STORAGE_ROOT": "C:\\a", "YOURNAS_HOST": host}).host == host
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.0.5", "100.64.0.1", "example.com", "::"])
def test_non_loopback_rejected_without_override(host: str) -> None:
    assert not is_loopback_host(host)
    with pytest.raises(ConfigError, match="loopback"):
        load_settings({"YOURNAS_STORAGE_ROOT": "C:\\a", "YOURNAS_HOST": host})


def test_non_loopback_allowed_with_explicit_override() -> None:
    s = load_settings(
        {
            "YOURNAS_STORAGE_ROOT": "C:\\a",
            "YOURNAS_HOST": "100.64.0.1",
            "YOURNAS_ALLOW_NON_LOOPBACK": "true",
        }
    )
    assert s.host == "100.64.0.1"
    assert s.allow_non_loopback is True


@pytest.mark.parametrize(
    ("raw", "expected"), [("true", True), ("1", True), ("false", False), ("0", False)]
)
def test_bool_env_parsing(raw: str, expected: bool) -> None:
    s = load_settings({"YOURNAS_STORAGE_ROOT": "C:\\a", "YOURNAS_ENABLE_DOCS": raw})
    assert s.enable_docs is expected
