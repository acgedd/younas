"""dir_is_empty / remove_empty_dir: the only way a share folder is ever removed."""

from __future__ import annotations

import ctypes
import os
import subprocess
import unicodedata
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from yournas.storage import files
from yournas.storage.errors import InvalidPath, NotEmpty, NotFound, UnsafePath

SHARE = "s_0123456789abcdef"
FILE_ATTRIBUTE_HIDDEN = 0x2


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    base = tmp_path / "shared"
    base.mkdir()
    return base


@pytest.fixture
def share_dir(shared: Path) -> Path:
    d = shared / SHARE
    d.mkdir()
    return d


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
        if link.exists() or link.is_junction():
            os.rmdir(link)


def _create_raw(directory: Path, name: str) -> bool:
    try:
        with open("\\\\?\\" + str(directory) + "\\" + name, "wb") as fh:
            fh.write(b"x")
    except OSError:
        return False
    return True


# --------------------------------------------------------------------------- dir_is_empty


def test_missing_folder_counts_as_empty(shared: Path) -> None:
    assert files.dir_is_empty(shared, SHARE) is True


def test_empty_folder_is_empty(share_dir: Path, shared: Path) -> None:
    assert files.dir_is_empty(shared, SHARE) is True


def test_one_file_makes_it_not_empty(share_dir: Path, shared: Path) -> None:
    (share_dir / "a.txt").write_bytes(b"x")
    assert files.dir_is_empty(shared, SHARE) is False


def test_an_empty_subfolder_makes_it_not_empty(share_dir: Path, shared: Path) -> None:
    (share_dir / "sub").mkdir()
    assert files.dir_is_empty(shared, SHARE) is False


def test_hidden_files_count(share_dir: Path, shared: Path) -> None:
    f = share_dir / "secret.txt"
    f.write_bytes(b"x")
    ctypes.windll.kernel32.SetFileAttributesW(str(f), FILE_ATTRIBUTE_HIDDEN)
    assert files.dir_is_empty(shared, SHARE) is False


def test_names_no_listing_would_show_count(share_dir: Path, shared: Path) -> None:
    # A listing hides these (not NFC / unaddressable on Windows) and a delete must not be blind.
    nfd = unicodedata.normalize("NFD", "café.txt")
    (share_dir / nfd).write_bytes(b"x")
    assert files.list_dir(share_dir, (), limit=10, after=None).entries == ()  # really invisible
    assert files.dir_is_empty(shared, SHARE) is False


@pytest.mark.parametrize("name", ["trailing.", "con.txt", "aux", "name with trailing space "])
def test_unaddressable_win32_names_count(share_dir: Path, shared: Path, name: str) -> None:
    if not _create_raw(share_dir, name):
        pytest.skip("cannot create that name here")
    assert files.list_dir(share_dir, (), limit=10, after=None).entries == ()
    assert files.dir_is_empty(shared, SHARE) is False


def test_a_junction_inside_counts(
    share_dir: Path, shared: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    junction(share_dir / "link", outside)
    assert files.dir_is_empty(shared, SHARE) is False
    assert outside.exists()


def test_a_junction_in_the_folders_place_is_not_empty(
    shared: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()  # empty, but we must not look through the link
    junction(shared / SHARE, outside)
    assert files.dir_is_empty(shared, SHARE) is False


def test_a_file_in_the_folders_place_is_not_empty(shared: Path) -> None:
    (shared / SHARE).write_bytes(b"x")
    assert files.dir_is_empty(shared, SHARE) is False


@pytest.mark.parametrize("name", ["", "..", "a/b", "a\\b", "x" * 65, "c:", "a.b", "."])
def test_bad_names_are_refused(shared: Path, name: str) -> None:
    with pytest.raises(InvalidPath):
        files.dir_is_empty(shared, name)
    with pytest.raises(InvalidPath):
        files.remove_empty_dir(shared, name)


def test_a_missing_or_linked_base_is_an_error_not_empty(
    tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    with pytest.raises(NotFound):
        files.dir_is_empty(tmp_path / "nope", SHARE)
    real = tmp_path / "real"
    real.mkdir()
    junction(tmp_path / "linked", real)
    with pytest.raises(UnsafePath):
        files.dir_is_empty(tmp_path / "linked", SHARE)
    with pytest.raises(UnsafePath):
        files.remove_empty_dir(tmp_path / "linked", SHARE)


# --------------------------------------------------------------------------- remove_empty_dir


def test_removes_an_empty_folder(share_dir: Path, shared: Path) -> None:
    assert files.remove_empty_dir(shared, SHARE) is True
    assert not share_dir.exists()
    assert shared.exists()


def test_removing_a_missing_folder_is_fine(shared: Path) -> None:
    assert files.remove_empty_dir(shared, SHARE) is True


def test_refuses_a_non_empty_folder_and_keeps_everything(share_dir: Path, shared: Path) -> None:
    (share_dir / "keep.txt").write_bytes(b"x")
    (share_dir / "sub").mkdir()
    (share_dir / "sub" / "deep.txt").write_bytes(b"y")
    with pytest.raises(NotEmpty):
        files.remove_empty_dir(shared, SHARE)
    assert (share_dir / "keep.txt").read_bytes() == b"x"
    assert (share_dir / "sub" / "deep.txt").read_bytes() == b"y"


def test_refuses_a_folder_holding_only_an_invisible_name(share_dir: Path, shared: Path) -> None:
    (share_dir / unicodedata.normalize("NFD", "café.txt")).write_bytes(b"x")
    with pytest.raises(NotEmpty):
        files.remove_empty_dir(shared, SHARE)
    assert any(share_dir.iterdir())


def test_refuses_a_junction_and_leaves_its_target_alone(
    shared: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    link = junction(shared / SHARE, outside)
    with pytest.raises(UnsafePath):
        files.remove_empty_dir(shared, SHARE)
    assert link.exists() and (outside / "secret.txt").read_text() == "secret"


def test_refuses_a_file_in_the_folders_place(shared: Path) -> None:
    (shared / SHARE).write_bytes(b"x")
    with pytest.raises(UnsafePath):
        files.remove_empty_dir(shared, SHARE)
    assert (shared / SHARE).read_bytes() == b"x"


def test_never_deletes_recursively(
    share_dir: Path, shared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("rmtree must never be used")

    monkeypatch.setattr(shutil, "rmtree", boom)
    monkeypatch.setattr(files, "_rmtree", boom)
    (share_dir / "x.txt").write_bytes(b"x")
    with pytest.raises(NotEmpty):
        files.remove_empty_dir(shared, SHARE)
    (share_dir / "x.txt").unlink()
    assert files.remove_empty_dir(shared, SHARE) is True
