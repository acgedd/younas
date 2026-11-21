from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from yournas.core.config import ConfigError, Settings, load_settings


def test_defaults_are_conservative(tmp_path: Path) -> None:
    s = Settings(storage_root=tmp_path)
    assert s.session_idle_hours == 24 * 7
    assert s.session_lifetime_days == 30
    assert s.trust_forwarded_for is False
    assert s.data_dir is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_idle_hours", 0),
        ("session_idle_hours", 24 * 365 + 1),
        ("session_lifetime_days", 0),
        ("session_lifetime_days", 366),
    ],
)
def test_session_limits_are_bounded(tmp_path: Path, field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"storage_root": tmp_path, field: value})


def test_settings_load_from_the_environment(tmp_path: Path) -> None:
    s = load_settings(
        {
            "YOURNAS_STORAGE_ROOT": str(tmp_path),
            "YOURNAS_SESSION_IDLE_HOURS": "2",
            "YOURNAS_SESSION_LIFETIME_DAYS": "3",
            "YOURNAS_TRUST_FORWARDED_FOR": "true",
            "YOURNAS_DATA_DIR": str(tmp_path / "db"),
        }
    )
    assert (s.session_idle_hours, s.session_lifetime_days) == (2, 3)
    assert s.trust_forwarded_for is True and s.data_dir == tmp_path / "db"


def test_bad_session_setting_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings({"YOURNAS_STORAGE_ROOT": str(tmp_path), "YOURNAS_SESSION_IDLE_HOURS": "0"})
