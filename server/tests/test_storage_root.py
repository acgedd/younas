from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from yournas.storage import root as root_mod
from yournas.storage.root import (
    StorageRootError,
    VolumeInfo,
    open_storage,
    prepare_storage_root,
    query_volume,
    validate_storage_root,
)


def fake_volume(fs: str = "NTFS", drive_type: int = 3) -> Callable[[Path], VolumeInfo]:
    return lambda _path: VolumeInfo(fs, drive_type)


@pytest.fixture
def junction() -> Iterator[Callable[[Path, Path], Path]]:
    made: list[Path] = []

    def _make(link: Path, target: Path) -> Path:
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True
        )
        if result.returncode != 0:
            pytest.skip(f"cannot create junction: {result.stderr.strip()}")
        made.append(link)
        return link

    yield _make
    for link in made:
        if link.exists():
            os.rmdir(link)


def names(p: Path) -> set[str]:
    return {c.name for c in p.iterdir()}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_real_volume_of_temp_dir_is_ntfs_fixed(storage_root: Path) -> None:
    info = query_volume(storage_root)
    assert info.fs_name.upper() == "NTFS"
    assert info.drive_type == 3


def test_valid_root_is_prepared(storage_root: Path) -> None:
    s = open_storage(storage_root)
    assert s.root == storage_root
    assert s.users.is_dir() and s.shared.is_dir() and s.tmp.is_dir()
    assert names(storage_root) == {"users", "shared", ".yournas-tmp"}
    assert not any(n.startswith(".yournas-write-test") for n in names(storage_root))


def test_prepare_is_idempotent_and_keeps_data(storage_root: Path) -> None:
    open_storage(storage_root)
    (storage_root / "users" / "keep.txt").write_text("data")
    open_storage(storage_root)
    assert (storage_root / "users" / "keep.txt").read_text() == "data"


def age(path: Path, seconds: float) -> None:
    """Make `path` look `seconds` old."""
    t = time.time() - seconds
    os.utime(path, (t, t))


def test_old_staging_entries_are_swept_and_young_ones_survive(storage_root: Path) -> None:
    s = open_storage(storage_root)
    (s.tmp / "old.part").write_text("x")
    (s.tmp / "young.part").write_text("x")
    (s.tmp / "dir").mkdir()
    (s.tmp / "dir" / "inner").write_text("x")
    age(s.tmp / "old.part", 73 * 3600)
    age(s.tmp / "dir", 73 * 3600)  # the folder itself is old, but its content is fresh
    s2 = open_storage(storage_root)
    assert {p.name for p in s2.tmp.iterdir()} == {"young.part", "dir"}  # a fresh child keeps "dir"
    assert s2.swept_tmp_entries == 1
    age(s.tmp / "dir" / "inner", 73 * 3600)
    age(s.tmp / "dir", 73 * 3600)  # now everything in the folder is old
    s3 = open_storage(storage_root)
    assert {p.name for p in s3.tmp.iterdir()} == {"young.part"}
    assert s3.swept_tmp_entries == 1


def test_staging_age_limit_is_a_parameter(storage_root: Path) -> None:
    s = open_storage(storage_root)
    (s.tmp / "a.part").write_text("x")
    age(s.tmp / "a.part", 2 * 3600)
    assert open_storage(storage_root).swept_tmp_entries == 0  # default limit is 72 hours
    again = open_storage(storage_root, tmp_max_age_seconds=3600)
    assert again.swept_tmp_entries == 1
    assert list(again.tmp.iterdir()) == []


def test_sweep_removes_junction_without_touching_target(
    storage_root: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    s = open_storage(storage_root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("keep")
    junction(s.tmp / "link", outside)  # brand new: links are removed whatever their age
    open_storage(storage_root)
    assert (outside / "precious.txt").read_text() == "keep"
    assert list(s.tmp.iterdir()) == []


@pytest.mark.parametrize(
    "bad", ["relative\\dir", "data", "\\\\server\\share\\x", "//server/share/x", "\\\\?\\C:\\x"]
)
def test_relative_unc_and_device_paths_rejected(bad: str) -> None:
    with pytest.raises(StorageRootError):
        validate_storage_root(bad, volume_query=fake_volume())


def test_drive_letter_without_slash_rejected() -> None:
    with pytest.raises(StorageRootError, match="absolute"):
        validate_storage_root("C:data", volume_query=fake_volume())


def test_drive_root_rejected() -> None:
    with pytest.raises(StorageRootError, match="drive root"):
        validate_storage_root(Path(Path.cwd().anchor), volume_query=fake_volume())


def test_missing_root_rejected_and_nothing_created(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(StorageRootError, match="does not exist"):
        open_storage(missing)
    assert not missing.exists()


def test_file_instead_of_directory_rejected(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(StorageRootError, match="not a directory"):
        validate_storage_root(f, volume_query=fake_volume())


@pytest.mark.parametrize("fs", ["FAT32", "exFAT", "ReFS", ""])
def test_non_ntfs_rejected_and_nothing_created(storage_root: Path, fs: str) -> None:
    with pytest.raises(StorageRootError, match="NTFS"):
        open_storage(storage_root, volume_query=fake_volume(fs))
    assert names(storage_root) == set()


@pytest.mark.parametrize("drive_type", [0, 1, 2, 4, 5, 6])
def test_non_fixed_drive_rejected(storage_root: Path, drive_type: int) -> None:
    with pytest.raises(StorageRootError, match="local fixed disk"):
        validate_storage_root(storage_root, volume_query=fake_volume(drive_type=drive_type))


@pytest.mark.parametrize("var", ["SystemRoot", "windir", "ProgramFiles", "ProgramData"])
def test_system_directories_rejected(storage_root: Path, var: str) -> None:
    inside = storage_root / "inside"
    inside.mkdir()
    with pytest.raises(StorageRootError, match="system directory"):
        validate_storage_root(
            inside, volume_query=fake_volume(), environ={var: str(storage_root)}
        )


def test_system_directory_itself_rejected(storage_root: Path) -> None:
    with pytest.raises(StorageRootError, match="system directory"):
        validate_storage_root(
            storage_root, volume_query=fake_volume(), environ={"SystemRoot": str(storage_root)}
        )


def test_sibling_with_same_prefix_is_not_a_system_directory(tmp_path: Path) -> None:
    sys_dir = tmp_path / "Windows"
    sys_dir.mkdir()
    sibling = tmp_path / "Windows2"
    sibling.mkdir()
    validate_storage_root(
        sibling, volume_query=fake_volume(), environ={"SystemRoot": str(sys_dir)}
    )


def test_junction_as_root_rejected(
    storage_root: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    link = junction(tmp_path / "linked", storage_root)
    with pytest.raises(StorageRootError, match="reparse"):
        open_storage(link)
    assert names(storage_root) == set()


def test_root_below_a_junction_rejected(
    storage_root: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    (storage_root / "sub").mkdir()
    link = junction(tmp_path / "linked", storage_root)
    with pytest.raises(StorageRootError, match="reparse"):
        open_storage(link / "sub")


@pytest.mark.parametrize("name", ["users", "shared", ".yournas-tmp"])
def test_existing_file_in_place_of_subdir_rejected(storage_root: Path, name: str) -> None:
    (storage_root / name).write_text("x")
    with pytest.raises(StorageRootError, match="real directory"):
        open_storage(storage_root)


@pytest.mark.parametrize("name", ["users", "shared", ".yournas-tmp"])
def test_junction_in_place_of_subdir_rejected(
    storage_root: Path, tmp_path: Path, junction: Callable[[Path, Path], Path], name: str
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    junction(storage_root / name, outside)
    with pytest.raises(StorageRootError, match="real directory"):
        prepare_storage_root(storage_root)
    assert list(outside.iterdir()) == []


def test_unwritable_root_rejected(storage_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = os.open

    def deny(path: str | os.PathLike[str], *args: object, **kwargs: object) -> int:
        if ".yournas-write-test" in str(path):
            raise PermissionError(13, "Access is denied")
        return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", deny)
    with pytest.raises(StorageRootError, match="not writable"):
        validate_storage_root(storage_root, volume_query=fake_volume())
    monkeypatch.undo()
    assert names(storage_root) == set()


@pytest.mark.parametrize(
    "bad",
    [
        "/\\?\\C:\\x",  # mixed slashes, extended-length prefix
        "/\\.\\C:\\x",  # mixed slashes, device prefix
        "\\\\.\\C:\\x",
        "/\\host\\share",
        "//?/C:/x",
    ],
)
def test_mixed_slash_unc_and_device_prefixes_rejected(bad: str) -> None:
    with pytest.raises(StorageRootError, match="UNC"):
        validate_storage_root(bad, volume_query=fake_volume())


@pytest.mark.parametrize("suffix", ["::$INDEX_ALLOCATION", ":stream", ":$DATA"])
def test_alternate_data_stream_syntax_rejected(storage_root: Path, suffix: str) -> None:
    with pytest.raises(StorageRootError, match="':'"):
        validate_storage_root(str(storage_root) + suffix, volume_query=fake_volume())


@pytest.mark.parametrize("name", ["dot.", "space ", "...", "a. "])
def test_trailing_dot_or_space_rejected(storage_root: Path, name: str) -> None:
    with pytest.raises(StorageRootError, match="dot or a space"):
        validate_storage_root(str(storage_root) + "\\" + name, volume_query=fake_volume())


def test_nul_byte_rejected_without_traceback(storage_root: Path) -> None:
    with pytest.raises(StorageRootError, match="invalid character"):
        validate_storage_root(str(storage_root) + "\x00x", volume_query=fake_volume())


def test_returned_root_is_canonical(storage_root: Path) -> None:
    import ntpath

    short = ntpath.abspath(str(storage_root))
    assert validate_storage_root(short, volume_query=fake_volume()) == Path(
        os.path.realpath(storage_root)
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_real_windows_directory_rejected_with_default_environment() -> None:
    windir = os.environ["SYSTEMROOT"]
    for candidate in (windir, windir + "\\System32"):
        with pytest.raises(StorageRootError, match="system directory"):
            validate_storage_root(candidate, volume_query=fake_volume())


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_system_directory_rejected_even_with_empty_environment() -> None:
    with pytest.raises(StorageRootError, match="system directory"):
        validate_storage_root(os.environ["SYSTEMROOT"], volume_query=fake_volume(), environ={})


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_system_directory_aliases_rejected() -> None:
    windir = Path(os.environ["SYSTEMROOT"])
    candidates = [str(windir.parent / (windir.name + ".")) + "\\System32"]
    short_pf = Path(windir.anchor) / "PROGRA~1"
    if short_pf.exists():
        candidates.append(str(short_pf))
    for candidate in candidates:
        # The trailing-dot form is refused by name rules; the short form by canonicalization.
        with pytest.raises(StorageRootError):
            validate_storage_root(candidate, volume_query=fake_volume())


def test_unknown_windows_directory_fails_closed(
    storage_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(root_mod, "_windows_directory", lambda: None)
    with pytest.raises(StorageRootError, match="Windows directory"):
        validate_storage_root(storage_root, volume_query=fake_volume(), environ={})


def test_locked_or_readonly_staging_entries_do_not_block_startup(storage_root: Path) -> None:
    s = open_storage(storage_root)
    readonly = s.tmp / "readonly.part"
    readonly.write_text("x")
    readonly.chmod(stat.S_IREAD)
    locked = s.tmp / "locked.part"
    locked.write_text("x")
    age(readonly, 100 * 3600)
    age(locked, 100 * 3600)
    with locked.open("rb"):  # an open handle blocks deletion on Windows
        again = open_storage(storage_root)
    assert not readonly.exists()
    assert again.swept_tmp_entries >= 1
    assert again.skipped_tmp_entries == 1
    assert locked.exists()
