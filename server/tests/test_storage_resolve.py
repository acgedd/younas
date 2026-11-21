"""resolve() and ensure_space_root(): reparse points, containment, length, missing parts."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from yournas.storage import paths as paths_module
from yournas.storage.errors import InvalidPath, NotFound, UnsafePath
from yournas.storage.paths import MAX_REAL_PATH, ensure_space_root, resolve


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


@pytest.fixture
def space(tmp_path: Path) -> Path:
    s = tmp_path / "users" / "u1"
    s.mkdir(parents=True)
    (s / "docs").mkdir()
    (s / "docs" / "a.txt").write_text("a")
    (s / "top.txt").write_text("t")
    return s


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    o = tmp_path / "outside"
    o.mkdir()
    (o / "secret.txt").write_text("secret")
    (o / "sub").mkdir()
    return o


def test_root_resolves_to_itself(space: Path) -> None:
    assert resolve(space, (), must_exist=True) == Path(os.path.realpath(space))


def test_existing_file_and_dir(space: Path) -> None:
    assert resolve(space, ("docs", "a.txt"), must_exist=True).read_text() == "a"
    assert resolve(space, ("docs",), must_exist=True).is_dir()


def test_missing_requires_flag(space: Path) -> None:
    with pytest.raises(NotFound):
        resolve(space, ("nope",), must_exist=True)
    with pytest.raises(NotFound):
        resolve(space, ("docs", "nope", "deeper"), must_exist=True)
    got = resolve(space, ("docs", "nope", "deeper"), must_exist=False)
    assert got == Path(os.path.realpath(space), "docs", "nope", "deeper")
    assert not got.exists()


def test_file_in_middle_is_not_found(space: Path) -> None:
    for must_exist in (True, False):
        with pytest.raises(NotFound):
            resolve(space, ("top.txt", "x"), must_exist=must_exist)


def test_case_insensitive_lookup_stays_inside(space: Path) -> None:
    got = resolve(space, ("DOCS", "A.TXT"), must_exist=True)
    assert got.read_text() == "a"


def test_missing_space_root(tmp_path: Path) -> None:
    with pytest.raises(NotFound):
        resolve(tmp_path / "gone", ("a",), must_exist=False)


def test_space_root_that_is_a_file(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x")
    with pytest.raises(UnsafePath):
        resolve(f, (), must_exist=False)


def test_length_limit(space: Path) -> None:
    base = len(os.path.realpath(space))
    budget = MAX_REAL_PATH - 1 - base - 1  # longest allowed single extra component
    ok = ("a" * budget,)
    assert len(str(resolve(space, ok, must_exist=False))) == MAX_REAL_PATH - 1
    with pytest.raises(InvalidPath):
        resolve(space, ("a" * (budget + 1),), must_exist=False)
    with pytest.raises(InvalidPath):
        resolve(space, ("a" * 100, "b" * 100, "c" * 100), must_exist=False)


def test_traversal_attempts_never_reach_the_filesystem(space: Path, outside: Path) -> None:
    for raw_parts in [("..", "outside"), ("docs", "..", "..", "outside"), (str(outside),)]:
        with pytest.raises(InvalidPath):
            resolve(space, raw_parts, must_exist=False)


def test_cross_user_names_cannot_be_reached(tmp_path: Path) -> None:
    a, b = tmp_path / "users" / "a", tmp_path / "users" / "b"
    a.mkdir(parents=True)
    b.mkdir()
    (b / "private.txt").write_text("b")
    for parts in [("..", "b", "private.txt"), ("..\\b",), ("../b",)]:
        with pytest.raises(InvalidPath):
            resolve(a, parts, must_exist=True)


def test_junction_as_child_of_space_root(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    for parts in [("link",), ("link", "secret.txt"), ("link", "sub"), ("link", "new")]:
        for must_exist in (True, False):
            with pytest.raises(UnsafePath):
                resolve(space, parts, must_exist=must_exist)


def test_junction_in_the_middle_of_a_path(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "docs" / "mid", outside)
    for must_exist in (True, False):
        with pytest.raises(UnsafePath):
            resolve(space, ("docs", "mid", "sub", "x.txt"), must_exist=must_exist)
    # the sibling files stay reachable
    assert resolve(space, ("docs", "a.txt"), must_exist=True).exists()


def test_junction_pointing_inside_the_same_space_is_still_refused(
    space: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "alias", space / "docs")
    with pytest.raises(UnsafePath):
        resolve(space, ("alias", "a.txt"), must_exist=True)


def test_junction_to_another_users_space(
    tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    a, b = tmp_path / "users" / "a", tmp_path / "users" / "b"
    a.mkdir(parents=True)
    b.mkdir()
    (b / "private.txt").write_text("b")
    junction(a / "peek", b)
    with pytest.raises(UnsafePath):
        resolve(a, ("peek", "private.txt"), must_exist=True)


def test_dangling_junction_is_unsafe_not_missing(
    space: Path, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    gone = tmp_path / "gone"
    gone.mkdir()
    junction(space / "dangling", gone)
    gone.rmdir()
    with pytest.raises(UnsafePath):
        resolve(space, ("dangling",), must_exist=False)


def test_space_root_itself_a_junction(
    tmp_path: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    link = junction(tmp_path / "users-link", outside)
    with pytest.raises(UnsafePath):
        resolve(link, ("secret.txt",), must_exist=True)


def test_symlink_if_available(space: Path, outside: Path) -> None:
    try:
        os.symlink(outside, space / "sl", target_is_directory=True)
        os.symlink(outside / "secret.txt", space / "sf.txt")
    except OSError:
        pytest.skip("symlinks need privilege or developer mode")
    for parts in [("sl",), ("sl", "secret.txt"), ("sf.txt",)]:
        with pytest.raises(UnsafePath):
            resolve(space, parts, must_exist=True)


def test_error_messages_hide_server_paths(space: Path) -> None:
    with pytest.raises(NotFound) as info:
        resolve(space, ("missing",), must_exist=True)
    text = str(info.value) + repr(info.value) + repr(info.value.args) + info.value.detail
    assert str(space) not in text and "users" not in text
    assert str(info.value) == "not found"


def test_unsafe_and_not_found_look_identical(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    with pytest.raises(UnsafePath) as unsafe:
        resolve(space, ("link",), must_exist=True)
    with pytest.raises(NotFound) as missing:
        resolve(space, ("nope",), must_exist=True)
    assert str(unsafe.value) == str(missing.value)


# --------------------------------------------------------------------------- ensure_space_root


def test_ensure_space_root_creates_lazily_and_is_idempotent(tmp_path: Path) -> None:
    base = tmp_path / "users"
    base.mkdir()
    first = ensure_space_root(base, "u_abc123")
    assert first.is_dir() and first.parent == Path(os.path.realpath(base))
    assert ensure_space_root(base, "u_abc123") == first


@pytest.mark.parametrize(
    "name",
    ["", "..", ".", "a/b", "a\\b", "a b", "a.b", "é", "x" * 65, "a\n", "a\x00", "C:", "../x"],
    ids=repr,
)
def test_ensure_space_root_rejects_bad_names(tmp_path: Path, name: str) -> None:
    base = tmp_path / "users"
    base.mkdir()
    with pytest.raises(InvalidPath):
        ensure_space_root(base, name)
    assert list(base.iterdir()) == []


def test_ensure_space_root_accepts_64_chars(tmp_path: Path) -> None:
    base = tmp_path / "users"
    base.mkdir()
    assert ensure_space_root(base, "A" * 64).name == "A" * 64


def test_ensure_space_root_refuses_a_file(tmp_path: Path) -> None:
    base = tmp_path / "users"
    base.mkdir()
    (base / "u1").write_text("x")
    with pytest.raises(UnsafePath):
        ensure_space_root(base, "u1")


def test_ensure_space_root_refuses_a_junction(
    tmp_path: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    base = tmp_path / "users"
    base.mkdir()
    junction(base / "u1", outside)
    with pytest.raises(UnsafePath):
        ensure_space_root(base, "u1")


def test_ensure_space_root_refuses_a_junction_base(
    tmp_path: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    link = junction(tmp_path / "users", outside)
    with pytest.raises(UnsafePath):
        ensure_space_root(link, "u1")
    assert not (outside / "u1").exists()


def test_ensure_space_root_missing_base(tmp_path: Path) -> None:
    with pytest.raises(NotFound):
        ensure_space_root(tmp_path / "nope", "u1")


# ---- resolve must not depend on the validator ------------------------------------------------

HOSTILE_PARTS = [
    ("newdir", "..", "..", "x"),
    ("..",),
    (".",),
    ("docs", "..", "..", "outside", "x"),
    ("a/b",),
    (r"a\b",),
    ("C:",),
    (r"C:\Windows",),
    ("a:stream",),
    ("a\x00b",),
    ("...",),
    ("x.",),
    ("x ",),
    ("",),
    ("\\\\?\\C:\\",),
    ("/abs",),
]


@pytest.fixture
def no_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    """The syntax layer lets everything through, as if it had a bug."""
    monkeypatch.setattr(paths_module, "validate_relative_path", lambda raw: tuple(raw.split("/")))
    monkeypatch.setattr(paths_module, "_recheck", lambda parts: None)


@pytest.mark.parametrize("must_exist", [True, False])
@pytest.mark.parametrize("parts", HOSTILE_PARTS, ids=repr)
def test_hostile_components_are_refused_even_with_the_validator_bypassed(
    space: Path, outside: Path, no_validator: None, parts: tuple[str, ...], must_exist: bool
) -> None:
    with pytest.raises(InvalidPath):
        resolve(space, parts, must_exist=must_exist)
    assert sorted(p.name for p in space.iterdir()) == ["docs", "top.txt"]
    assert sorted(p.name for p in outside.iterdir()) == ["secret.txt", "sub"]


def test_final_path_check_alone_stops_an_escape_through_a_missing_component(
    space: Path, outside: Path, no_validator: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even with the validator AND the component check gone, `newdir/../../x` (a missing
    component before the dots, which no lstat sees) cannot produce a path outside the space."""
    monkeypatch.setattr(paths_module, "_unsafe_part", lambda part: False)
    with pytest.raises(UnsafePath):
        resolve(space, ("newdir", "..", "..", "x"), must_exist=False)
    assert not (space.parent / "x").exists()
    assert not (space / "newdir").exists()


def test_junction_is_still_refused_with_the_validator_bypassed(
    space: Path, outside: Path, no_validator: None, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    for parts in [("link",), ("link", "secret.txt"), ("link", "new")]:
        for must_exist in (True, False):
            with pytest.raises(UnsafePath):
                resolve(space, parts, must_exist=must_exist)


@pytest.mark.parametrize(
    "name",
    ["file name.txt", "a.b.c", "é", "日本語", "~tmp", "a-b_c (1).txt", "a$b", "CONSOLE", ".hidden"],
)
def test_ordinary_windows_names_still_resolve(space: Path, name: str) -> None:
    target = resolve(space, (name,), must_exist=False)
    assert target == Path(os.path.realpath(space)) / name
