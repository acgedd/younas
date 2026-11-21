"""File operations: listing, mkdir, delete, ranged reads, resumable-upload primitives."""

from __future__ import annotations

import os
import stat
import subprocess
import threading
import unicodedata
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from yournas.storage import files
from yournas.storage.errors import (
    AlreadyExists,
    Busy,
    InvalidPath,
    IsADirectoryErr,
    NotADirectoryErr,
    NotEmpty,
    NotFound,
    OffsetMismatch,
    RangeNotSatisfiable,
    TooLarge,
    UnsafePath,
)


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
    return s


@pytest.fixture
def tmp_stage(tmp_path: Path) -> Path:
    t = tmp_path / ".yournas-tmp"
    t.mkdir()
    return t


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    o = tmp_path / "outside"
    o.mkdir()
    (o / "secret.txt").write_text("secret")
    (o / "sub").mkdir()
    (o / "sub" / "deep.txt").write_text("deep")
    return o


def write(path: Path, data: bytes | str = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


def sort_key(name: str) -> tuple[str, str]:
    return name.casefold(), name


def list_all(space: Path, parts: tuple[str, ...] = (), limit: int = 1000) -> list[str]:
    names: list[str] = []
    after: str | None = None
    while True:
        page = files.list_dir(space, parts, limit=limit, after=after)
        names += [e.name for e in page.entries]
        if page.next_after is None:
            return names
        after = page.next_after


# --------------------------------------------------------------------------- list_dir


def test_list_empty_root(space: Path) -> None:
    page = files.list_dir(space, (), limit=10, after=None)
    assert page.entries == () and page.next_after is None


def test_list_entry_fields(space: Path) -> None:
    write(space / "f.bin", b"12345")
    (space / "d").mkdir()
    page = files.list_dir(space, (), limit=10, after=None)
    by_name = {e.name: e for e in page.entries}
    f, d = by_name["f.bin"], by_name["d"]
    assert (f.kind, f.size) == ("file", 5)
    assert (d.kind, d.size) == ("dir", None)
    assert abs(f.modified - (space / "f.bin").stat().st_mtime) < 1e-6
    assert isinstance(f.modified, float)


def test_list_sorted_case_insensitively(space: Path) -> None:
    names = ["b", "A", "a2", "B1", "_x", "10", "9", "é", "Z", "文"]
    for n in names:
        write(space / n)
    got = list_all(space)
    assert got == sorted(names, key=sort_key)
    assert got.index("A") < got.index("a2") < got.index("b") < got.index("B1")


@pytest.mark.parametrize("limit", [1, 2, 3, 7, 24, 25, 26, 1000])
def test_pagination_covers_everything_once(space: Path, limit: int) -> None:
    names = [f"{c}{i:02d}" for i, c in enumerate("abcdeABCDEfgFGhiHI" * 2)][:25]
    for n in names:
        write(space / n)
    got = list_all(space, limit=limit)
    assert got == sorted(names, key=sort_key)
    assert len(got) == len(set(got)) == 25


def test_pagination_page_boundaries(space: Path) -> None:
    for i in range(8):
        write(space / f"f{i}")
    p1 = files.list_dir(space, (), limit=4, after=None)
    assert [e.name for e in p1.entries] == ["f0", "f1", "f2", "f3"] and p1.next_after == "f3"
    p2 = files.list_dir(space, (), limit=4, after=p1.next_after)
    assert [e.name for e in p2.entries] == ["f4", "f5", "f6", "f7"]
    assert p2.next_after is None  # exact multiple: no phantom empty page


def test_cursor_survives_deleting_the_cursor_entry(space: Path) -> None:
    for i in range(6):
        write(space / f"f{i}")
    p1 = files.list_dir(space, (), limit=3, after=None)
    (space / p1.entries[-1].name).unlink()
    p2 = files.list_dir(space, (), limit=3, after=p1.next_after)
    assert [e.name for e in p2.entries] == ["f3", "f4", "f5"]


def test_cursor_ignores_new_entries_before_it(space: Path) -> None:
    for n in ("b", "c", "d", "e"):
        write(space / n)
    p1 = files.list_dir(space, (), limit=2, after=None)
    write(space / "a")  # sorts before the cursor
    write(space / "cc")  # sorts after it
    p2 = files.list_dir(space, (), limit=10, after=p1.next_after)
    assert [e.name for e in p2.entries] == ["cc", "d", "e"]


def test_unknown_cursor_is_just_a_position(space: Path) -> None:
    for n in ("a", "c", "e"):
        write(space / n)
    page = files.list_dir(space, (), limit=10, after="b")
    assert [e.name for e in page.entries] == ["c", "e"]


def test_list_skips_junctions_and_does_not_follow(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    write(space / "real.txt")
    (space / "realdir").mkdir()
    junction(space / "link", outside)
    assert list_all(space) == ["real.txt", "realdir"]
    with pytest.raises(UnsafePath):
        files.list_dir(space, ("link",), limit=10, after=None)


def test_list_skips_symlinks_if_available(space: Path, outside: Path) -> None:
    try:
        os.symlink(outside, space / "sl", target_is_directory=True)
        os.symlink(outside / "secret.txt", space / "sf.txt")
    except OSError:
        pytest.skip("symlinks need privilege or developer mode")
    write(space / "ok.txt")
    assert list_all(space) == ["ok.txt"]


def _create_raw(directory: Path, name: str) -> bool:
    """Create a file whose name Win32 would normally refuse, via the \\\\?\\ prefix."""
    try:
        with open("\\\\?\\" + str(directory) + "\\" + name, "wb") as fh:
            fh.write(b"x")
    except OSError:
        return False
    return True


def test_list_hides_names_that_cannot_be_addressed(space: Path) -> None:
    write(space / "good.txt")
    nfd = unicodedata.normalize("NFD", "café.txt")
    hidden = [nfd]
    if _create_raw(space, "trailing."):
        hidden.append("trailing.")
    if _create_raw(space, "con.txt"):
        hidden.append("con.txt")
    write(space / nfd)
    got = list_all(space)
    assert "good.txt" in got
    for name in hidden:
        assert name not in got
    # and the hidden items do not eat page slots
    page = files.list_dir(space, (), limit=1, after=None)
    assert [e.name for e in page.entries] == ["good.txt"] and page.next_after is None


def test_list_nested_and_errors(space: Path) -> None:
    write(space / "d" / "e" / "f.txt")
    assert list_all(space, ("d", "e")) == ["f.txt"]
    with pytest.raises(NotADirectoryErr):
        files.list_dir(space, ("d", "e", "f.txt"), limit=5, after=None)
    with pytest.raises(NotFound):
        files.list_dir(space, ("nope",), limit=5, after=None)
    with pytest.raises(InvalidPath):
        files.list_dir(space, ("..",), limit=5, after=None)


@pytest.mark.parametrize("limit", [0, -1], ids=repr)
def test_list_rejects_bad_limit(space: Path, limit: int) -> None:
    with pytest.raises(ValueError):
        files.list_dir(space, (), limit=limit, after=None)


# --------------------------------------------------------------------------- stat_item


def test_stat_item(space: Path) -> None:
    write(space / "d" / "f.txt", b"abc")
    f = files.stat_item(space, ("d", "f.txt"))
    assert (f.name, f.kind, f.size) == ("f.txt", "file", 3)
    d = files.stat_item(space, ("d",))
    assert (d.name, d.kind, d.size) == ("d", "dir", None)
    root = files.stat_item(space, ())
    assert (root.name, root.kind) == ("", "dir")
    with pytest.raises(NotFound):
        files.stat_item(space, ("missing",))


def test_stat_item_refuses_junction(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    with pytest.raises(UnsafePath):
        files.stat_item(space, ("link",))


# --------------------------------------------------------------------------- make_dir


def test_make_dir_basic_and_nested(space: Path) -> None:
    entry = files.make_dir(space, ("a",))
    assert entry.kind == "dir" and (space / "a").is_dir()
    files.make_dir(space, ("a", "b"))
    assert (space / "a" / "b").is_dir()


def test_make_dir_is_single_level(space: Path) -> None:
    with pytest.raises(NotFound):
        files.make_dir(space, ("x", "y"))
    assert not (space / "x").exists()


def test_make_dir_existing_is_already_exists(space: Path) -> None:
    (space / "Docs").mkdir()
    write(space / "f.txt")
    for parts in [("Docs",), ("docs",), ("DOCS",), ("f.txt",), ("F.TXT",)]:
        with pytest.raises(AlreadyExists):
            files.make_dir(space, parts)
    assert sorted(os.listdir(space)) == ["Docs", "f.txt"]


def test_make_dir_refuses_root(space: Path) -> None:
    with pytest.raises(InvalidPath):
        files.make_dir(space, ())


def test_make_dir_under_a_file(space: Path) -> None:
    write(space / "f.txt")
    with pytest.raises(NotFound):
        files.make_dir(space, ("f.txt", "sub"))


def test_make_dir_through_junction(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    with pytest.raises(UnsafePath):
        files.make_dir(space, ("link", "evil"))
    assert not (outside / "evil").exists()


@pytest.mark.parametrize("bad", ["con", "a.", "a:b", "..", "x*"], ids=repr)
def test_make_dir_bad_names_are_invalid_paths(space: Path, bad: str) -> None:
    with pytest.raises(InvalidPath):
        files.make_dir(space, (bad,))


# --------------------------------------------------------------------------- delete_item


def test_delete_file(space: Path) -> None:
    write(space / "f.txt")
    assert files.delete_item(space, ("f.txt",), recursive=False) == 1
    assert not (space / "f.txt").exists()
    with pytest.raises(NotFound):
        files.delete_item(space, ("f.txt",), recursive=False)


def test_delete_read_only_file(space: Path) -> None:
    f = write(space / "ro.txt")
    os.chmod(f, stat.S_IREAD)
    assert not os.access(f, os.W_OK)
    assert files.delete_item(space, ("ro.txt",), recursive=False) == 1
    assert not f.exists()


def test_delete_file_held_open_is_busy(space: Path) -> None:
    f = write(space / "busy.txt")
    with open(f, "rb"):
        with pytest.raises(Busy):
            files.delete_item(space, ("busy.txt",), recursive=False)
        assert f.exists()
    assert files.delete_item(space, ("busy.txt",), recursive=False) == 1


def test_delete_empty_dir_and_nonempty_without_recursive(space: Path) -> None:
    (space / "empty").mkdir()
    write(space / "full" / "f.txt")
    assert files.delete_item(space, ("empty",), recursive=False) == 1
    with pytest.raises(NotEmpty):
        files.delete_item(space, ("full",), recursive=False)
    assert (space / "full" / "f.txt").exists()


def test_delete_read_only_empty_dir(space: Path) -> None:
    d = space / "rodir"
    d.mkdir()
    os.chmod(d, stat.S_IREAD)
    assert files.delete_item(space, ("rodir",), recursive=False) == 1
    assert not d.exists()


def test_delete_recursive_counts_everything(space: Path) -> None:
    write(space / "t" / "a.txt")
    write(space / "t" / "s" / "b.txt")
    write(space / "t" / "s" / "u" / "c.txt")
    ro = write(space / "t" / "s" / "ro.txt")
    os.chmod(ro, stat.S_IREAD)
    # 4 files + dirs t, s, u
    assert files.delete_item(space, ("t",), recursive=True) == 7
    assert not (space / "t").exists()


def test_delete_recursive_does_not_follow_junction(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    write(space / "tree" / "mine.txt")
    (space / "tree" / "sub").mkdir()
    junction(space / "tree" / "link", outside)
    junction(space / "tree" / "sub" / "deep", outside / "sub")
    # mine.txt, link, sub/deep, sub, tree
    assert files.delete_item(space, ("tree",), recursive=True) == 5
    assert not (space / "tree").exists()
    assert (outside / "secret.txt").read_text() == "secret"
    assert (outside / "sub" / "deep.txt").read_text() == "deep"


def test_delete_recursive_does_not_follow_symlinks_if_available(space: Path, outside: Path) -> None:
    (space / "tree").mkdir()
    try:
        os.symlink(outside, space / "tree" / "sl", target_is_directory=True)
        os.symlink(outside / "secret.txt", space / "tree" / "sf.txt")
    except OSError:
        pytest.skip("symlinks need privilege or developer mode")
    files.delete_item(space, ("tree",), recursive=True)
    assert not (space / "tree").exists()
    assert (outside / "secret.txt").exists() and (outside / "sub" / "deep.txt").exists()


def test_delete_a_junction_directly_is_refused(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    for recursive in (False, True):
        with pytest.raises(UnsafePath):
            files.delete_item(space, ("link",), recursive=recursive)
    with pytest.raises(UnsafePath):
        files.delete_item(space, ("link", "secret.txt"), recursive=True)
    assert (outside / "secret.txt").exists()


def test_delete_refuses_space_root(space: Path) -> None:
    write(space / "keep.txt")
    for recursive in (False, True):
        with pytest.raises(InvalidPath):
            files.delete_item(space, (), recursive=recursive)
    assert (space / "keep.txt").exists()


def test_delete_missing(space: Path) -> None:
    with pytest.raises(NotFound):
        files.delete_item(space, ("nope", "deeper"), recursive=True)


# --------------------------------------------------------------------------- open_for_read


def test_open_for_read(space: Path) -> None:
    write(space / "d" / "f.bin", b"0123456789")
    with files.open_for_read(space, ("d", "f.bin")) as of:
        assert of.size == 10
        assert abs(of.mtime - (space / "d" / "f.bin").stat().st_mtime) < 1e-6
        assert of.fh.read() == b"0123456789"
    assert of.fh.closed


def test_open_for_read_does_not_block_other_readers(space: Path) -> None:
    f = write(space / "f.bin", b"abc")
    with files.open_for_read(space, ("f.bin",)), open(f, "rb") as other:
        assert other.read() == b"abc"


def test_open_for_read_errors(
    space: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    (space / "dir").mkdir()
    junction(space / "link", outside)
    with pytest.raises(IsADirectoryErr):
        files.open_for_read(space, ("dir",))
    with pytest.raises(NotFound):
        files.open_for_read(space, ("nope",))
    with pytest.raises(UnsafePath):
        files.open_for_read(space, ("link", "secret.txt"))
    with pytest.raises(InvalidPath):
        files.open_for_read(space, ("..", "outside"))


# --------------------------------------------------------------------------- iter_range

DATA = bytes(range(256)) * 20  # 5120 bytes


@pytest.mark.parametrize(
    ("start", "length", "chunk"),
    [
        (0, 5120, 256 * 1024),
        (0, 5120, 1000),
        (0, 1, 1),
        (5119, 1, 4096),
        (100, 0, 10),
        (100, 2000, 333),
        (1000, 4120, 1024),
        (0, 5120, 5120),
        (4000, 5000, 512),  # asks for more than exists: stops at EOF
    ],
    ids=lambda v: str(v),
)
def test_iter_range_matches_slice(space: Path, start: int, length: int, chunk: int) -> None:
    write(space / "f", DATA)
    with files.open_for_read(space, ("f",)) as of:
        out = b"".join(files.iter_range(of.fh, start, length, chunk))
    assert out == DATA[start : start + length]


def test_iter_range_chunks_never_exceed_chunk(space: Path) -> None:
    write(space / "f", DATA)
    with files.open_for_read(space, ("f",)) as of:
        sizes = [len(c) for c in files.iter_range(of.fh, 10, 3000, 700)]
    assert sizes == [700, 700, 700, 700, 200]


def test_iter_range_close_flag(space: Path) -> None:
    write(space / "f", DATA)
    of = files.open_for_read(space, ("f",))
    gen = files.iter_range(of.fh, 0, 100, 10, close=True)
    next(gen)
    gen.close()
    assert of.fh.closed
    of2 = files.open_for_read(space, ("f",))
    list(files.iter_range(of2.fh, 0, 100, 10, close=True))
    assert of2.fh.closed
    of3 = files.open_for_read(space, ("f",))
    list(files.iter_range(of3.fh, 0, 100, 10))
    assert not of3.fh.closed
    of3.close()


@pytest.mark.parametrize("args", [(-1, 1, 10), (0, -1, 10), (0, 1, 0)], ids=repr)
def test_iter_range_rejects_bad_args(space: Path, args: tuple[int, int, int]) -> None:
    write(space / "f", DATA)
    with files.open_for_read(space, ("f",)) as of, pytest.raises(ValueError):
        next(files.iter_range(of.fh, *args))


# --------------------------------------------------------------------------- parse_range_header

R = files.RangeSpec
RANGE_CASES: dict[str, tuple[str | None, int, files.RangeSpec | None]] = {
    "none": (None, 100, None),
    "empty": ("", 100, None),
    "closed": ("bytes=0-9", 100, R(0, 10)),
    "single-byte": ("bytes=5-5", 100, R(5, 1)),
    "open-ended": ("bytes=90-", 100, R(90, 10)),
    "open-from-zero": ("bytes=0-", 100, R(0, 100)),
    "suffix": ("bytes=-10", 100, R(90, 10)),
    "suffix-bigger-than-file": ("bytes=-500", 100, R(0, 100)),
    "end-clamped": ("bytes=50-5000", 100, R(50, 50)),
    "last-byte": ("bytes=99-99", 100, R(99, 1)),
    "whole-file": ("bytes=0-99", 100, R(0, 100)),
    "case-insensitive-unit": ("BYTES=0-9", 100, R(0, 10)),
    "spaces": ("  bytes= 0-9 ", 100, R(0, 10)),
    "multiple-ranges-ignored": ("bytes=0-4,10-14", 100, None),
    "multiple-with-suffix-ignored": ("bytes=0-4,-5", 100, None),
    "other-unit-ignored": ("items=0-4", 100, None),
    "no-equals-ignored": ("bytes", 100, None),
    "no-dash-ignored": ("bytes=5", 100, None),
    "garbage-ignored": ("bytes=abc-def", 100, None),
    "dash-only-ignored": ("bytes=-", 100, None),
    "inverted-ignored": ("bytes=10-5", 100, None),
    "negative-start-ignored": ("bytes=--5", 100, None),
    "inner-space-ignored": ("bytes=0 -5", 100, None),
    "unicode-digits-ignored": ("bytes=١-٩", 100, None),
    "huge-numbers-clamped": ("bytes=0-" + "9" * 5000, 100, R(0, 100)),
    "empty-file-no-range": ("bytes=0-", 0, "unsat"),  # type: ignore[dict-item]
}


@pytest.mark.parametrize(
    ("header", "size", "expected"), RANGE_CASES.values(), ids=RANGE_CASES.keys()
)
def test_parse_range(header: str | None, size: int, expected: files.RangeSpec | str | None) -> None:
    if expected == "unsat":
        with pytest.raises(RangeNotSatisfiable) as info:
            files.parse_range_header(header, size)
        assert info.value.size == size
    else:
        assert files.parse_range_header(header, size) == expected


UNSATISFIABLE = {
    "start-at-size": ("bytes=100-", 100),
    "start-past-size": ("bytes=500-600", 100),
    "huge-start": ("bytes=" + "9" * 5000 + "-", 100),
    "suffix-zero": ("bytes=-0", 100),
    "suffix-on-empty-file": ("bytes=-5", 0),
}


@pytest.mark.parametrize(("header", "size"), UNSATISFIABLE.values(), ids=UNSATISFIABLE.keys())
def test_parse_range_unsatisfiable(header: str, size: int) -> None:
    with pytest.raises(RangeNotSatisfiable) as info:
        files.parse_range_header(header, size)
    assert info.value.size == size


def test_range_spec_end_is_inclusive() -> None:
    spec = files.parse_range_header("bytes=10-19", 100)
    assert spec is not None and (spec.start, spec.end, spec.length) == (10, 19, 10)


# --------------------------------------------------------------------------- uploads


def new_id(n: int = 1) -> str:
    return f"{n:032x}"


@pytest.mark.parametrize(
    "upload_id",
    [
        "",
        "abc",
        "A" * 32,
        "g" * 32,
        "a" * 31,
        "a" * 33,
        "../" + "a" * 29,
        "a" * 31 + "\n",
        "a/" + "a" * 30,
    ],
    ids=repr,
)
def test_staging_path_rejects_bad_ids(tmp_stage: Path, upload_id: str) -> None:
    with pytest.raises(InvalidPath):
        files.staging_path(tmp_stage, upload_id)


def test_staging_path_is_inside_tmp(tmp_stage: Path) -> None:
    p = files.staging_path(tmp_stage, new_id(7))
    assert p.parent == tmp_stage and new_id(7) in p.name


def test_create_staging_is_create_only(tmp_stage: Path) -> None:
    p = files.create_staging(tmp_stage, new_id())
    assert p.exists() and p.stat().st_size == 0
    with pytest.raises(AlreadyExists):
        files.create_staging(tmp_stage, new_id())


def test_create_staging_refuses_junction_tmp(
    tmp_path: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    link = junction(tmp_path / "tmp-link", outside)
    with pytest.raises(UnsafePath):
        files.create_staging(link, new_id())
    assert sorted(os.listdir(outside)) == ["secret.txt", "sub"]


def test_append_sequence_returns_sizes(tmp_stage: Path) -> None:
    p = files.create_staging(tmp_stage, new_id())
    assert files.append_chunk(p, 0, b"hello ") == 6
    assert files.append_chunk(p, 6, b"world") == 11
    assert files.append_chunk(p, 11, [b"!", b"!", b"?"]) == 14
    assert files.append_chunk(p, 14, b"") == 14
    assert files.append_chunk(p, 14, bytearray(b"\n")) == 15
    assert p.read_bytes() == b"hello world!!?\n"


@pytest.mark.parametrize("offset", [0, 3, 6, 100], ids=repr)
def test_append_offset_mismatch(tmp_stage: Path, offset: int) -> None:
    p = files.create_staging(tmp_stage, new_id())
    files.append_chunk(p, 0, b"abcd")
    with pytest.raises(OffsetMismatch) as info:
        files.append_chunk(p, offset, b"zzz")
    assert info.value.actual == 4
    assert p.read_bytes() == b"abcd"


def test_append_negative_offset(tmp_stage: Path) -> None:
    p = files.create_staging(tmp_stage, new_id())
    with pytest.raises(ValueError):
        files.append_chunk(p, -1, b"x")


def test_append_to_missing_staging(tmp_stage: Path) -> None:
    with pytest.raises(NotFound):
        files.append_chunk(files.staging_path(tmp_stage, new_id()), 0, b"x")


def test_failed_iterable_rolls_back_to_the_expected_offset(tmp_stage: Path) -> None:
    p = files.create_staging(tmp_stage, new_id())
    files.append_chunk(p, 0, b"base")

    def boom() -> Iterator[bytes]:
        yield b"part1"
        yield b"part2"
        raise ConnectionError("client went away")

    with pytest.raises(ConnectionError):
        files.append_chunk(p, 4, boom())
    assert p.read_bytes() == b"base"
    assert files.append_chunk(p, 4, b"+more") == 9  # client can resume at its known offset


def test_max_size_enforced_from_the_byte_count(tmp_stage: Path) -> None:
    p = files.create_staging(tmp_stage, new_id())
    files.append_chunk(p, 0, b"12345", max_size=10)
    with pytest.raises(TooLarge):
        files.append_chunk(p, 5, iter([b"123", b"4567"]), max_size=10)
    assert p.read_bytes() == b"12345"
    assert files.append_chunk(p, 5, b"67890", max_size=10) == 10  # exactly at the limit
    with pytest.raises(TooLarge):
        files.append_chunk(p, 10, b"x", max_size=10)


def test_append_refuses_a_junction_in_place_of_staging(
    tmp_stage: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    link = junction(files.staging_path(tmp_stage, new_id()), outside)
    with pytest.raises(UnsafePath):
        files.append_chunk(link, 0, b"x")


def test_discard_staging(tmp_stage: Path) -> None:
    p = files.create_staging(tmp_stage, new_id())
    assert files.discard_staging(p) is True and not p.exists()
    assert files.discard_staging(p) is True  # already gone
    q = files.create_staging(tmp_stage, new_id(2))
    os.chmod(q, stat.S_IREAD)
    assert files.discard_staging(q) is True and not q.exists()
    r = files.create_staging(tmp_stage, new_id(3))
    with open(r, "rb"):
        assert files.discard_staging(r) is False  # locked: left for the startup sweep
    assert files.discard_staging(r) is True


def test_free_bytes(tmp_path: Path) -> None:
    assert files.free_bytes(tmp_path) > 0
    with pytest.raises(NotFound):
        files.free_bytes(tmp_path / "does" / "not" / "exist")


def stage(tmp_stage: Path, content: bytes, n: int = 1) -> Path:
    p = files.create_staging(tmp_stage, new_id(n))
    files.append_chunk(p, 0, content)
    return p


def test_finalize_new_file(space: Path, tmp_stage: Path) -> None:
    p = stage(tmp_stage, b"payload")
    entry = files.finalize(p, space, ("up.bin",), overwrite=False)
    assert (entry.name, entry.kind, entry.size) == ("up.bin", "file", 7)
    assert (space / "up.bin").read_bytes() == b"payload"
    assert not p.exists()


def test_finalize_into_subfolder(space: Path, tmp_stage: Path) -> None:
    (space / "d").mkdir()
    files.finalize(stage(tmp_stage, b"x"), space, ("d", "f"), overwrite=False)
    assert (space / "d" / "f").read_bytes() == b"x"


def test_finalize_without_overwrite_keeps_existing(space: Path, tmp_stage: Path) -> None:
    write(space / "f.txt", b"old")
    p = stage(tmp_stage, b"new")
    with pytest.raises(AlreadyExists):
        files.finalize(p, space, ("f.txt",), overwrite=False)
    assert (space / "f.txt").read_bytes() == b"old"
    assert p.exists()  # the caller decides whether to discard


def test_finalize_overwrite_replaces_file(space: Path, tmp_stage: Path) -> None:
    write(space / "f.txt", b"old")
    entry = files.finalize(stage(tmp_stage, b"new!"), space, ("f.txt",), overwrite=True)
    assert entry.size == 4 and (space / "f.txt").read_bytes() == b"new!"
    assert os.listdir(space) == ["f.txt"]


def test_finalize_overwrite_of_read_only_file(space: Path, tmp_stage: Path) -> None:
    f = write(space / "ro.txt", b"old")
    os.chmod(f, stat.S_IREAD)
    files.finalize(stage(tmp_stage, b"new"), space, ("ro.txt",), overwrite=True)
    assert f.read_bytes() == b"new"


def test_finalize_overwrite_of_file_held_open_is_busy(space: Path, tmp_stage: Path) -> None:
    f = write(space / "busy.txt", b"old")
    p = stage(tmp_stage, b"new")
    with open(f, "rb"):
        with pytest.raises(Busy):
            files.finalize(p, space, ("busy.txt",), overwrite=True)
        assert f.read_bytes() == b"old" and p.exists()


@pytest.mark.parametrize("overwrite", [False, True], ids=["no-overwrite", "overwrite"])
@pytest.mark.parametrize("requested", ["Report.txt", "report.txt", "REPORT.TXT"])
def test_finalize_case_insensitive_collision(
    space: Path, tmp_stage: Path, overwrite: bool, requested: str
) -> None:
    write(space / "Report.txt", b"old")
    p = stage(tmp_stage, b"new")
    if overwrite:
        files.finalize(p, space, (requested,), overwrite=True)
        assert len(os.listdir(space)) == 1  # never two files differing by case
        assert (space / "Report.txt").read_bytes() == b"new"
    else:
        with pytest.raises(AlreadyExists):
            files.finalize(p, space, (requested,), overwrite=False)
        assert os.listdir(space) == ["Report.txt"]
        assert (space / "Report.txt").read_bytes() == b"old"


@pytest.mark.parametrize("overwrite", [False, True], ids=["no-overwrite", "overwrite"])
def test_finalize_never_replaces_a_directory(space: Path, tmp_stage: Path, overwrite: bool) -> None:
    write(space / "Folder" / "keep.txt", b"keep")
    p = stage(tmp_stage, b"file")
    for name in ("Folder", "folder"):
        with pytest.raises(IsADirectoryErr):
            files.finalize(p, space, (name,), overwrite=overwrite)
    assert (space / "Folder" / "keep.txt").read_bytes() == b"keep"
    assert p.exists()


def test_finalize_parent_must_exist(space: Path, tmp_stage: Path) -> None:
    p = stage(tmp_stage, b"x")
    with pytest.raises(NotFound):
        files.finalize(p, space, ("nope", "f"), overwrite=False)
    write(space / "afile")
    with pytest.raises(NotFound):
        files.finalize(p, space, ("afile", "f"), overwrite=False)
    assert not (space / "nope").exists()


def test_finalize_refuses_space_root_and_bad_names(space: Path, tmp_stage: Path) -> None:
    p = stage(tmp_stage, b"x")
    with pytest.raises(InvalidPath):
        files.finalize(p, space, (), overwrite=True)
    for bad in ("..", "con", "a.", "a:b"):
        with pytest.raises(InvalidPath):
            files.finalize(p, space, (bad,), overwrite=True)
    with pytest.raises(InvalidPath):
        files.finalize(p, space, ("a", ".."), overwrite=True)


def test_finalize_through_junction(
    space: Path, tmp_stage: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    junction(space / "link", outside)
    p = stage(tmp_stage, b"evil")
    for parts in [("link", "f"), ("link", "secret.txt"), ("link",)]:
        with pytest.raises(UnsafePath):
            files.finalize(p, space, parts, overwrite=True)
    assert (outside / "secret.txt").read_text() == "secret"
    assert not (outside / "f").exists()


def test_finalize_missing_or_unsafe_staging(
    space: Path, tmp_stage: Path, outside: Path, junction: Callable[[Path, Path], Path]
) -> None:
    with pytest.raises(NotFound):
        files.finalize(files.staging_path(tmp_stage, new_id()), space, ("f",), overwrite=False)
    link = junction(files.staging_path(tmp_stage, new_id(2)), outside)
    with pytest.raises(UnsafePath):
        files.finalize(link, space, ("f",), overwrite=False)
    assert (outside / "secret.txt").exists()


def test_finalize_path_too_long(space: Path, tmp_stage: Path) -> None:
    p = stage(tmp_stage, b"x")
    with pytest.raises(InvalidPath):
        files.finalize(p, space, ("a" * 250,), overwrite=False)


def test_concurrent_finalize_without_overwrite_has_exactly_one_winner(
    space: Path, tmp_stage: Path
) -> None:
    n = 8
    staged = [stage(tmp_stage, f"writer-{i}".encode(), n=i + 1) for i in range(n)]
    results: list[object] = [None] * n
    barrier = threading.Barrier(n)

    def run(i: int) -> None:
        barrier.wait()
        try:
            results[i] = files.finalize(staged[i], space, ("race.txt",), overwrite=False)
        except Exception as exc:
            results[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [i for i, r in enumerate(results) if isinstance(r, files.Entry)]
    assert len(winners) == 1
    assert all(isinstance(r, AlreadyExists) for i, r in enumerate(results) if i not in winners)
    assert (space / "race.txt").read_bytes() == f"writer-{winners[0]}".encode()
    assert os.listdir(space) == ["race.txt"]


# --------------------------------------------------------------------------- misc


def test_cross_space_isolation(tmp_path: Path) -> None:
    a, b = tmp_path / "users" / "a", tmp_path / "users" / "b"
    a.mkdir(parents=True)
    b.mkdir()
    write(b / "private.txt", b"b-only")
    assert list_all(a) == []
    for call in (
        lambda: files.open_for_read(a, ("..", "b", "private.txt")),
        lambda: files.stat_item(a, ("..", "b")),
        lambda: files.delete_item(a, ("..", "b"), recursive=True),
        lambda: files.make_dir(a, ("..", "c")),
        lambda: files.list_dir(a, ("..",), limit=5, after=None),
    ):
        with pytest.raises(InvalidPath):
            call()
    assert (b / "private.txt").read_bytes() == b"b-only"


def test_errors_carry_no_server_paths(space: Path, tmp_path: Path) -> None:
    write(space / "f.txt")
    caught: list[Exception] = []
    calls: tuple[Callable[[], object], ...] = (
        lambda: files.stat_item(space, ("missing",)),
        lambda: files.make_dir(space, ("f.txt",)),
        lambda: files.delete_item(space, ("missing",), recursive=False),
        lambda: files.open_for_read(space, ("missing",)),
    )
    for call in calls:
        try:
            call()
        except Exception as raised:
            caught.append(raised)
    assert len(caught) == 4
    for err in caught:
        text = str(err) + repr(err) + repr(err.args) + getattr(err, "detail", "")
        assert str(tmp_path) not in text and "users" not in text and "f.txt" not in text
