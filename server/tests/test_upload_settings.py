from __future__ import annotations

import pytest

from yournas.core.config import GIB, MIB, ConfigError, load_settings

BASE = {"YOURNAS_STORAGE_ROOT": r"C:\data"}


def test_upload_defaults() -> None:
    s = load_settings(BASE)
    assert s.max_upload_bytes == 20 * GIB
    assert s.free_space_floor_bytes == 5 * GIB
    assert s.upload_chunk_max_bytes == 8 * MIB
    assert s.upload_stale_hours == 72
    assert s.max_uploads_per_user == 8
    assert s.max_concurrent_chunks_per_user == 4
    assert s.max_inflight_upload_bytes_per_user == 50 * GIB


def test_upload_settings_from_environment() -> None:
    s = load_settings(
        {
            **BASE,
            "YOURNAS_MAX_UPLOAD_BYTES": "1000",
            "YOURNAS_FREE_SPACE_FLOOR_BYTES": "0",
            "YOURNAS_UPLOAD_CHUNK_MAX_BYTES": "4096",
            "YOURNAS_UPLOAD_STALE_HOURS": "5",
            "YOURNAS_MAX_UPLOADS_PER_USER": "2",
            "YOURNAS_MAX_CONCURRENT_CHUNKS_PER_USER": "7",
            "YOURNAS_MAX_INFLIGHT_UPLOAD_BYTES_PER_USER": "123456",
        }
    )
    assert s.max_concurrent_chunks_per_user == 7
    assert s.max_inflight_upload_bytes_per_user == 123456
    assert (s.max_upload_bytes, s.free_space_floor_bytes, s.upload_chunk_max_bytes) == (
        1000,
        0,
        4096,
    )
    assert (s.upload_stale_hours, s.max_uploads_per_user) == (5, 2)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MAX_UPLOAD_BYTES", "0"),
        ("MAX_UPLOAD_BYTES", "-5"),
        ("MAX_UPLOAD_BYTES", "lots"),
        ("FREE_SPACE_FLOOR_BYTES", "-1"),
        ("UPLOAD_CHUNK_MAX_BYTES", "0"),
        ("UPLOAD_CHUNK_MAX_BYTES", str(64 * MIB + 1)),
        ("UPLOAD_STALE_HOURS", "0"),
        ("UPLOAD_STALE_HOURS", str(24 * 365 + 1)),
        ("MAX_UPLOADS_PER_USER", "0"),
        ("MAX_UPLOADS_PER_USER", "101"),
        ("MAX_CONCURRENT_CHUNKS_PER_USER", "0"),
        ("MAX_INFLIGHT_UPLOAD_BYTES_PER_USER", "0"),
        ("MAX_INFLIGHT_UPLOAD_BYTES_PER_USER", "-1"),
        ("MAX_INFLIGHT_UPLOAD_BYTES_PER_USER", "plenty"),
    ],
)
def test_insane_upload_settings_are_refused(name: str, value: str) -> None:
    with pytest.raises(ConfigError, match=name.lower()):
        load_settings({**BASE, f"YOURNAS_{name}": value})
