"""Path validation: table-driven rejects/accepts, normalization, and a hostile-alphabet fuzz."""

from __future__ import annotations

import random
import unicodedata
from pathlib import Path

import pytest

from yournas.storage.errors import InvalidPath
from yournas.storage.paths import (
    MAX_COMPONENT,
    MAX_COMPONENTS,
    MAX_TOTAL,
    resolve,
    validate_relative_path,
)

REJECTED: dict[str, str] = {
    # control characters
    "nul-byte": "a\x00b",
    "nul-only": "\x00",
    "soh": "a\x01b",
    "tab": "a\tb",
    "newline": "a\nb",
    "carriage-return": "a\rb",
    "unit-separator": "a\x1fb",
    "delete": "a\x7fb",
    "c1-control": "a\x85b",
    "c1-nbsp-area": "a\x9fb",
    "lone-surrogate": "a\ud800b",
    "bidi-override": "a\u202eb",
    "bidi-isolate": "a\u2066b",
    # separators and anchors
    "backslash": "a\\b",
    "backslash-only": "\\",
    "backslash-traversal": "..\\..\\x",
    "leading-slash": "/a",
    "root-slash": "/",
    "posix-absolute": "/etc/passwd",
    "unc-forward": "//host/share/x",
    "unc-backslash": "\\\\host\\share\\x",
    "device-namespace": "\\\\?\\C:\\x",
    "device-namespace-fwd": "//?/C:/x",
    "drive-letter": "C:/x",
    "drive-relative": "C:x",
    "drive-only": "C:",
    "drive-in-middle": "a/C:/x",
    "ads-stream": "a.txt:stream",
    "ads-data": "a.txt::$DATA",
    "ads-dir": "dir:$I30:$INDEX_ALLOCATION",
    "empty-middle": "a//b",
    "empty-triple": "a///b",
    "trailing-slash": "a/",
    "only-slashes": "//",
    # dots
    "dot": ".",
    "dot-middle": "a/./b",
    "dotdot": "..",
    "dotdot-middle": "a/../b",
    "dotdot-end": "a/..",
    "dotdot-lead": "../a",
    "dotdot-deep": "a/b/../../../etc",
    "dots-only": "...",
    "dotdot-trailing-dots": "..../x",
    # trailing dots/spaces
    "trailing-dot": "a.",
    "trailing-dot-deep": "a/b.",
    "trailing-space": "a ",
    "trailing-space-deep": "a/b /c",
    "trailing-dot-space": "a. ",
    "only-space": " ",
    # forbidden characters
    "lt": "a<b",
    "gt": "a>b",
    "colon": "a:b",
    "quote": 'a"b',
    "pipe": "a|b",
    "question": "a?b",
    "star": "a*b",
    # reserved device names (case-insensitive, with extension, trailing stuff)
    "con": "CON",
    "con-lower": "con",
    "con-mixed": "CoN",
    "con-ext": "con.txt",
    "con-ext-multi": "con.tar.gz",
    "con-trailing-dot": "CON.",
    "con-space-ext": "con .txt",
    "con-deep": "a/CON/b",
    "prn": "PRN",
    "aux": "aux",
    "aux-ext": "AUX.log",
    "nul": "NUL",
    "nul-dot": "NUL.",
    "nul-ext": "nul.txt",
    "conin": "CONIN$",
    "conout": "conout$",
    "clock": "CLOCK$",
    "com0": "COM0",
    "com1": "COM1",
    "com9": "com9",
    "com1-ext": "COM1.txt",
    "com-sup1": "COM\u00b9",
    "com-sup2": "COM\u00b2",
    "com-sup3": "com\u00b3.txt",
    "lpt0": "LPT0",
    "lpt1": "lpt1",
    "lpt9": "LPT9",
    "lpt9-ext": "Lpt9.dat",
    "lpt-sup1": "LPT\u00b9",
    "lpt-sup2": "LPT\u00b2",
    "lpt-sup3": "LPT\u00b3.x",
    # size limits
    "component-256": "a" * (MAX_COMPONENT + 1),
    "component-256-deep": "x/" + "a" * (MAX_COMPONENT + 1),
    "total-too-long": "/".join(["a" * 100] * 11),
    "too-deep": "/".join(["a"] * (MAX_COMPONENTS + 1)),
    "huge-input": "a" * 5_000_000,
}


@pytest.mark.parametrize("raw", REJECTED.values(), ids=REJECTED.keys())
def test_rejected(raw: str) -> None:
    with pytest.raises(InvalidPath):
        validate_relative_path(raw)


@pytest.mark.parametrize("raw", [None, 5, b"a/b", ["a"], ("a",), 1.5], ids=repr)
def test_non_str_rejected(raw: object) -> None:
    with pytest.raises(InvalidPath):
        validate_relative_path(raw)  # type: ignore[arg-type]


ZWJ_FAMILY = "\U0001f468‍\U0001f469‍\U0001f467"

ACCEPTED: dict[str, tuple[str, tuple[str, ...]]] = {
    "empty-is-root": ("", ()),
    "simple": ("a", ("a",)),
    "nested": ("a/b/c.txt", ("a", "b", "c.txt")),
    "cjk": ("\u6587\u4ef6/\u5831\u544a.docx", ("\u6587\u4ef6", "\u5831\u544a.docx")),
    "emoji": ("\U0001f4c1/\U0001f600.png", ("\U0001f4c1", "\U0001f600.png")),
    "zwj-emoji": (ZWJ_FAMILY, (ZWJ_FAMILY,)),
    "arabic": ("\u0645\u0644\u0641.txt", ("\u0645\u0644\u0641.txt",)),
    "inner-space": ("my file.txt", ("my file.txt",)),
    "leading-space": (" a", (" a",)),
    "hidden-dot": (".hidden", (".hidden",)),
    "multi-dot": ("a.b.c", ("a.b.c",)),
    "parens": ("file (1).txt", ("file (1).txt",)),
    "punctuation": ("a;b,c=d@e#f%g&h+i", ("a;b,c=d@e#f%g&h+i",)),
    "dollar": ("$MFT", ("$MFT",)),
    "tilde": ("PROGRA~1", ("PROGRA~1",)),
    "console-not-con": ("CONSOLE", ("CONSOLE",)),
    "com10": ("COM10", ("COM10",)),
    "comx": ("COMX", ("COMX",)),
    "com-alone": ("COM", ("COM",)),
    "lpt-alone": ("LPT", ("LPT",)),
    "con-prefix-ext": ("console.txt", ("console.txt",)),
    "nul-prefix": ("nullable", ("nullable",)),
    "aux-suffix": ("auxiliary.txt", ("auxiliary.txt",)),
    "dot-con": (".con", (".con",)),
    "component-255": ("a" * MAX_COMPONENT, ("a" * MAX_COMPONENT,)),
    "64-components": ("/".join(["a"] * MAX_COMPONENTS), ("a",) * MAX_COMPONENTS),
    "total-1024": (
        "/".join(["a" * 127] * 7) + "/" + "a" * (MAX_TOTAL - 7 * 128),
        ("a" * 127,) * 7 + ("a" * (MAX_TOTAL - 7 * 128),),
    ),
}


@pytest.mark.parametrize(("raw", "expected"), ACCEPTED.values(), ids=ACCEPTED.keys())
def test_accepted(raw: str, expected: tuple[str, ...]) -> None:
    assert validate_relative_path(raw) == expected


def test_nfd_and_nfc_are_equivalent() -> None:
    nfc = "caf\u00e9/\u00c5ngstr\u00f6m"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfd != nfc
    assert validate_relative_path(nfd) == validate_relative_path(nfc) == tuple(nfc.split("/"))


def test_hangul_jamo_composes() -> None:
    jamo = "\u1112\u1161\u11ab"
    assert validate_relative_path(jamo) == ("\ud55c",)


def test_normalization_happens_before_validation() -> None:
    # U+212A KELVIN SIGN normalizes to "K"; checks must see the normalized text.
    assert validate_relative_path("\u212a") == ("K",)
    # U+037E GREEK QUESTION MARK normalizes to ";" (allowed), U+FF1A fullwidth colon is not ":".
    assert validate_relative_path("a\u037eb") == ("a;b",)
    assert validate_relative_path("a\uff1ab") == ("a\uff1ab",)


def test_normalization_expansion_cannot_exceed_limits() -> None:
    # U+0344 expands from 1 to 2 code points under NFC; the limit applies after normalization.
    with pytest.raises(InvalidPath):
        validate_relative_path("\u0344" * (MAX_COMPONENT // 2 + 1))


def test_error_never_echoes_input() -> None:
    secret = "TOPSECRET-\\..\\name"
    with pytest.raises(InvalidPath) as info:
        validate_relative_path(secret)
    exc = info.value
    assert "TOPSECRET" not in str(exc) + repr(exc) + repr(exc.args) + exc.detail
    assert str(exc) == "invalid path"


def test_invalid_path_is_a_value_error() -> None:
    assert issubclass(InvalidPath, ValueError)


@pytest.mark.parametrize(
    "parts",
    [("a/b",), ("..",), (".",), ("",), ("a", ""), ("a\\b",), ("CON",), ("e\u0301",), ("a ",)],
    ids=repr,
)
def test_resolve_rechecks_parts(tmp_path: Path, parts: tuple[str, ...]) -> None:
    with pytest.raises(InvalidPath):
        resolve(tmp_path, parts, must_exist=False)


@pytest.mark.parametrize("parts", [["a"], "a", None, ("a", 1)], ids=repr)
def test_resolve_rejects_non_tuple_parts(tmp_path: Path, parts: object) -> None:
    with pytest.raises(InvalidPath):
        resolve(tmp_path, parts, must_exist=False)  # type: ignore[arg-type]


HOSTILE = [
    ".",
    ".",
    "..",
    "/",
    "/",
    "\\",
    ":",
    "*",
    "?",
    "<",
    ">",
    "|",
    '"',
    " ",
    "\x00",
    "\x1f",
    "\x7f",
    "a",
    "A",
    "c",
    "C",
    "o",
    "O",
    "n",
    "N",
    "1",
    "9",
    "0",
    "$",
    "~",
    "CON",
    "NUL",
    "COM1",
    "lpt2",
    "AUX",
    "prn",
    "..",
    "../",
    "./",
    "\u00e9",
    "e\u0301",
    "\u00b9",
    "\u212a",
    "\u202e",
    "\u6587",
    "\U0001f600",
    "\ud800",
    "\uff0e",
    "\uff0f",
    "%2e",
    "%2f",
    "\u0344",
]


def test_fuzz_validate_then_resolve_stays_inside(tmp_path: Path) -> None:
    space = tmp_path / "space"
    space.mkdir()
    real_space = str(space.resolve()).lower()
    rng = random.Random(20261003)
    accepted = 0
    for _ in range(20000):
        raw = "".join(rng.choice(HOSTILE) for _ in range(rng.randint(0, 8)))
        try:
            parts = validate_relative_path(raw)
        except InvalidPath:
            continue
        accepted += 1
        assert all(p not in ("", ".", "..") for p in parts)
        assert not any(c in p for p in parts for c in '/\\:*?"<>|\x00')
        path = resolve(space, parts, must_exist=False)
        assert str(path).lower().startswith(real_space)
        assert path.resolve().is_relative_to(space.resolve())
    assert accepted > 500  # the alphabet must actually produce accepted values too
