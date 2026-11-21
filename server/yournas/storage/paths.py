"""Path validation and resolution: the ONLY place client input becomes a filesystem path.

Two steps, both fail closed:
  1. `validate_relative_path` turns a client string into NFC-normalized components (syntax).
  2. `resolve` joins the components onto a space root and checks every existing component with
     lstat (no reparse points), containment, and total length (filesystem).

Residual risk (documented in docs/SECURITY.md): a local writer who swaps a directory for a
junction between `resolve` and the following open/rename can still win a race. The service
account must be the only writer to the storage root.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from pathlib import Path

from .errors import InvalidPath, NotFound, UnsafePath
from .root import is_reparse_stat

MAX_COMPONENT = 255
MAX_TOTAL = 1024
MAX_COMPONENTS = 64
MAX_REAL_PATH = 240  # exclusive upper bound on the resolved absolute path (MAX_PATH safety)

_FORBIDDEN = frozenset('<>:"|?*\\')
_BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
# Reserved with or without an extension or trailing spaces. Superscript digits are reserved too.
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|(?:COM|LPT)[0-9¹²³])")
_SPACE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")


def _bad(reason: str) -> InvalidPath:
    return InvalidPath(reason)


def _check_component(part: str) -> None:
    if not part:
        raise _bad("empty-component")
    if part in (".", ".."):
        raise _bad("dot-component")
    if len(part) > MAX_COMPONENT:
        raise _bad("component-too-long")
    if part[-1] in ". ":
        raise _bad("trailing-dot-or-space")
    for ch in part:
        o = ord(ch)
        if o < 0x20 or 0x7F <= o <= 0x9F:
            raise _bad("control-char")
        if 0xD800 <= o <= 0xDFFF:
            raise _bad("surrogate")
        if ch in _FORBIDDEN:
            raise _bad("forbidden-char")
        if ch in _BIDI:
            raise _bad("bidi-control")
    base = part.split(".", 1)[0].rstrip(" ")
    if _DEVICE.fullmatch(base.upper()):
        raise _bad("reserved-name")


def validate_relative_path(raw: str) -> tuple[str, ...]:
    """Syntax-check a client path and return its NFC components ("" -> () = the space root)."""
    if not isinstance(raw, str):
        raise _bad("not-a-string")
    if len(raw) > MAX_TOTAL:
        raise _bad("too-long")
    if not raw:
        return ()
    try:
        norm = unicodedata.normalize("NFC", raw)
    except (ValueError, UnicodeError):  # pragma: no cover - defensive
        raise _bad("not-normalizable") from None
    if len(norm) > MAX_TOTAL:
        raise _bad("too-long")
    parts = tuple(norm.split("/"))
    if len(parts) > MAX_COMPONENTS:
        raise _bad("too-deep")
    for part in parts:
        _check_component(part)
    return parts


def _recheck(parts: tuple[str, ...]) -> None:
    """Callers pass components, but nothing is trusted: a part may not smuggle a separator."""
    if not isinstance(parts, tuple) or not all(isinstance(p, str) for p in parts):
        raise _bad("bad-parts")
    if validate_relative_path("/".join(parts)) != parts:
        raise _bad("not-normalized")


def _unsafe_part(part: object) -> bool:
    """Second, independent check made by `resolve` itself (it does not call the validator): a
    component that could mean anything but one plain name on Windows. Stricter than needed on
    purpose; every name the validator accepts passes."""
    if not isinstance(part, str) or not part or part in (".", ".."):
        return True
    if part[-1] in ". ":
        return True  # Win32 strips these, so "..." or "x." would name another entry
    return any(ch in "/\\:" or ord(ch) < 0x20 for ch in part)  # separator, drive, stream, NUL


def _norm(p: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.fspath(p))


def _contained(path: str, root: str) -> bool:
    a, b = _norm(path), _norm(root)
    try:
        return os.path.commonpath([a, b]) == b
    except ValueError:  # different drives
        return False


def _lstat(path: Path) -> os.stat_result | None:
    """lstat, or None if the entry is missing. Anything else is treated as unsafe."""
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise UnsafePath("lstat-failed") from None


def resolve(space_root: Path, parts: tuple[str, ...], *, must_exist: bool) -> Path:
    """Map validated components onto `space_root`, returning the real path.

    Every existing component must be a plain directory (or, last, a plain file): symlinks,
    junctions, mount points and any other reparse point raise UnsafePath. Missing trailing
    components are allowed only when `must_exist` is False.

    `resolve` does not trust the validator alone: it rejects `.`/`..`, separators, drive and
    stream markers and trailing dots/spaces in any component itself, and checks that the final
    path (missing tail included) is normalized and inside the space root.

    Raises InvalidPath (syntax / too long), NotFound (missing), UnsafePath (reparse or
    containment). Callers should answer NotFound and UnsafePath identically.
    """
    _recheck(parts)
    if not isinstance(parts, tuple) or any(_unsafe_part(p) for p in parts):
        raise _bad("unsafe-component")  # not relying on the validator alone
    root_st = _lstat(space_root)
    if root_st is None:
        raise NotFound("space-root-missing")
    if is_reparse_stat(root_st) or not stat.S_ISDIR(root_st.st_mode):
        raise UnsafePath("space-root-not-plain-dir")
    real_root = os.path.realpath(space_root)

    current = Path(real_root)
    missing: tuple[str, ...] = ()
    last = len(parts) - 1
    for i, part in enumerate(parts):
        candidate = current / part
        st = _lstat(candidate)
        if st is None:
            if must_exist:
                raise NotFound("missing")
            missing = parts[i:]
            break
        if is_reparse_stat(st):
            raise UnsafePath("reparse-point")
        if stat.S_ISDIR(st.st_mode):
            pass
        elif stat.S_ISREG(st.st_mode):
            if i != last:
                raise NotFound("file-in-path")
        else:
            raise UnsafePath("special-file")
        current = candidate

    real_existing = os.path.realpath(current)
    if not _contained(real_existing, real_root):
        raise UnsafePath("escapes-root")
    final = Path(real_existing, *missing)
    # The missing tail was never looked at on disk: the whole result must already be in normal
    # form (no "..", no doubled separators) and still lie inside the space root.
    if os.path.normpath(final) != str(final) or not _contained(str(final), real_root):
        raise UnsafePath("escapes-root")
    if len(str(final)) >= MAX_REAL_PATH:
        raise InvalidPath("path-too-long")
    return final


def check_space_name(name: str) -> None:
    """A space folder name (user id, share id) is a short [A-Za-z0-9_] token, never a path."""
    if not isinstance(name, str) or not _SPACE_NAME.fullmatch(name):
        raise InvalidPath("bad-space-name")


def ensure_space_root(base: Path, name: str) -> Path:
    """Lazily create `base/<name>` (e.g. users/<user_id>) and return its real path."""
    check_space_name(name)
    base_st = _lstat(base)
    if base_st is None:
        raise NotFound("base-missing")
    if is_reparse_stat(base_st) or not stat.S_ISDIR(base_st.st_mode):
        raise UnsafePath("base-not-plain-dir")
    target = base / name
    st = _lstat(target)
    if st is None:
        try:
            target.mkdir()
        except FileExistsError:
            pass  # lost a race with another creator; verified below
        except OSError:
            raise UnsafePath("mkdir-failed") from None
        st = _lstat(target)
    if st is None or is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("space-root-not-plain-dir")
    real = os.path.realpath(target)
    if not _contained(real, os.path.realpath(base)):
        raise UnsafePath("escapes-base")
    return Path(real)


def open_space_root(base: Path, name: str) -> Path:
    """Real path of the existing folder `base/<name>`. Unlike `ensure_space_root` it never
    creates anything: a missing folder is NotFound. Used for shares, whose folder exists only
    because the share was created."""
    check_space_name(name)
    base_st = _lstat(base)
    if base_st is None:
        raise NotFound("base-missing")
    if is_reparse_stat(base_st) or not stat.S_ISDIR(base_st.st_mode):
        raise UnsafePath("base-not-plain-dir")
    target = base / name
    st = _lstat(target)
    if st is None:
        raise NotFound("space-missing")
    if is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("space-root-not-plain-dir")
    real = os.path.realpath(target)
    if not _contained(real, os.path.realpath(base)):
        raise UnsafePath("escapes-base")
    return Path(real)
