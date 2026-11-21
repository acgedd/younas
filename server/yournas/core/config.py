"""Settings loaded from a JSON file and YOURNAS_* environment variables."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from yournas.core.hosts import normalize_host_name

ENV_PREFIX = "YOURNAS_"
CONFIG_ENV = "YOURNAS_CONFIG"

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


class ConfigError(Exception):
    """Configuration is missing or invalid. The message never contains setting values."""


_UTC_OFFSET = re.compile(r"([+-])([0-9]{2}):([0-9]{2})")


def utc_offset_seconds(text: str) -> int:
    """Seconds east of UTC of an offset written "+HH:MM" or "-HH:MM", from -12:00 to +14:00."""
    m = _UTC_OFFSET.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        raise ValueError('must be "+HH:MM" or "-HH:MM"')
    sign, hours, minutes = m.group(1), int(m.group(2)), int(m.group(3))
    total = hours * 60 + minutes
    if minutes > 59 or (sign == "+" and total > 14 * 60) or (sign == "-" and total > 12 * 60):
        raise ValueError("must be between -12:00 and +14:00")
    return (total if sign == "+" else -total) * 60


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    storage_root: Path
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    allow_non_loopback: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_dir: Path | None = None
    enable_docs: bool = False
    # Directory for the SQLite database. Default: <storage_root>/.yournas-data (not reachable
    # through any space).
    data_dir: Path | None = None
    # Sliding idle timeout and absolute lifetime of a login session.
    session_idle_hours: int = Field(default=24 * 7, ge=1, le=24 * 365)
    session_lifetime_days: int = Field(default=30, ge=1, le=365)
    # Take the client address from the last X-Forwarded-For entry when the TCP peer is
    # loopback. Enable only behind a trusted loopback proxy (Tailscale Serve), after verifying
    # that it sets the header. Off: loopback peers are "unknown" and get no per-IP throttle.
    trust_forwarded_for: bool = False
    # Host names (no port) the app answers to, besides the loopback names (localhost, 127.0.0.1,
    # [::1]), which are always accepted. Any other Host header is refused with 400, which defeats
    # DNS rebinding. Empty = loopback only. Put the exact Tailscale MagicDNS name here once it is
    # known; no wildcards. Only the Host header is used, never X-Forwarded-Host.
    allowed_hosts: tuple[str, ...] = ()
    # Send Strict-Transport-Security on every response. Leave off until the site is reached over
    # HTTPS (Tailscale Serve) and that works: a browser that saw the header refuses plain HTTP to
    # that name for a year. Browsers ignore the header on plain-HTTP responses.
    enable_hsts: bool = False
    # Largest file one upload may declare.
    max_upload_bytes: int = Field(default=20 * GIB, ge=1)
    # At least this much must stay free on the staging volume: checked when an upload starts (the
    # unwritten rest of every live upload is reserved) and again before every chunk.
    free_space_floor_bytes: int = Field(default=5 * GIB, ge=0)
    # Largest body of one PATCH /uploads/{id} request. It is buffered in memory while it arrives.
    upload_chunk_max_bytes: int = Field(default=8 * MIB, ge=1, le=64 * MIB)
    # An upload that received nothing for this long is discarded together with its staging file.
    upload_stale_hours: int = Field(default=72, ge=1, le=24 * 365)
    # Unfinished uploads one user may have at the same time.
    max_uploads_per_user: int = Field(default=8, ge=1, le=100)
    # PATCH /uploads/{id} requests one user may have in flight at once (each can hold a chunk in
    # memory); more are answered 429 before their body is read.
    max_concurrent_chunks_per_user: int = Field(default=4, ge=1)
    # Total declared bytes of one user's unfinished uploads. Declaring more is refused (507) when
    # an upload starts (507 upload_quota_exceeded).
    max_inflight_upload_bytes_per_user: int = Field(default=50 * GIB, ge=1)
    # Photos by month: a photo without a usable date taken goes in the month of its file time
    # (the upload time) seen in this UTC offset. "+HH:MM" or "-HH:MM", from -12:00 to +14:00.
    photo_fallback_utc_offset: str = "+08:00"

    @field_validator("photo_fallback_utc_offset", mode="after")
    @classmethod
    def _check_utc_offset(cls, value: str) -> str:
        utc_offset_seconds(value)  # raises ValueError, without repeating the value
        return value

    @property
    def photo_fallback_offset_seconds(self) -> int:
        return utc_offset_seconds(self.photo_fallback_utc_offset)

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _split_allowed_hosts(cls, value: Any) -> Any:
        # An environment variable is one string: "a.example, b.example" or "a.example b.example".
        if isinstance(value, str):
            return [part for part in re.split(r"[,\s]+", value) if part]
        return value

    @field_validator("allowed_hosts", mode="after")
    @classmethod
    def _normalize_allowed_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        names: list[str] = []
        for entry in value:
            name = normalize_host_name(entry)
            if name is None:
                # The message never repeats the entry.
                raise ValueError(
                    "allowed_hosts entries must be plain host names or IP addresses: "
                    "no wildcard, port, scheme, path or trailing dot"
                )
            if name not in names:
                names.append(name)
        return tuple(names)

    @model_validator(mode="after")
    def _require_loopback_unless_overridden(self) -> Settings:
        if not self.allow_non_loopback and not is_loopback_host(self.host):
            raise ValueError(
                "host must be a loopback address (127.0.0.1, ::1, localhost); "
                "set allow_non_loopback to override"
            )
        return self

    @model_validator(mode="after")
    def _log_dir_outside_storage(self) -> Settings:
        # Logs hold server paths and request metadata; they must never be reachable as user files.
        if self.log_dir is not None:
            log = os.path.normcase(os.path.realpath(self.log_dir))
            root = os.path.normcase(os.path.realpath(self.storage_root))
            try:
                inside = os.path.commonpath([log, root]) == root
            except ValueError:  # different drives
                inside = False
            if inside:
                raise ValueError("log_dir must not be inside storage_root")
        return self

    @model_validator(mode="after")
    def _data_dir_not_exposed(self) -> Settings:
        # The database holds password hashes. It must have a fixed location and must never sit
        # inside a directory that a space exposes as user files.
        if self.data_dir is None:
            return self
        if not self.data_dir.is_absolute():
            raise ValueError("data_dir must be an absolute path")
        data = os.path.normcase(os.path.realpath(self.data_dir))
        root = os.path.normcase(os.path.realpath(self.storage_root))
        for exposed in ("users", "shared"):
            base = os.path.join(root, exposed)
            try:
                inside = os.path.commonpath([data, base]) == base
            except ValueError:  # different drives
                inside = False
            if inside:
                raise ValueError(f"data_dir must not be inside storage_root/{exposed}")
        return self


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror}") from None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"config file {path} is not valid JSON (line {exc.lineno}, column {exc.colno})"
        ) from None
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must contain a JSON object")
    return data


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Build Settings. Environment variables override the config file."""
    env = os.environ if environ is None else environ
    # A config file is used only when named explicitly. There is no implicit lookup in the
    # working directory: under a service that directory is arbitrary.
    data: dict[str, Any] = {}
    explicit = env.get(CONFIG_ENV)
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        data.update(_read_config_file(path))

    for name in Settings.model_fields:
        key = ENV_PREFIX + name.upper()
        if env.get(key, "") != "":  # an empty variable counts as unset
            data[name] = env[key]

    try:
        return Settings(**data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'settings'}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"invalid configuration: {problems}") from None
