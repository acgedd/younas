"""Authorization: the one place that turns a space id into a folder on disk.

A space is `home` (the caller's private folder, always their own) or `share:<id>`. What a user may
do in a space is decided here, from the database, on every call: grants are never cached, so a
revoked grant, a downgraded level, a deleted share or a disabled account takes effect on the very
next request.

Rules (docs/SECURITY.md, Phase 4):
- Default deny. Anything that is not an explicit rule gives `Level.NONE`, including malformed
  ids, unknown or deleted shares, disabled or unknown users, and any error while deciding.
- `NONE` answers 404 `not_found`, byte for byte what an unknown space answers, so nobody can tell
  an ungranted space from one that does not exist. A level that is too low answers 403.
- The owner role grants nothing here. The owner reads a share only through a grant row like
  everybody else, and never reaches another user's `home`.
- Authorization happens before any filesystem access. A denied call creates nothing. The folder
  of a share is created by share creation (`Permissions.shares.create`) and never lazily.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Literal

from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields
from yournas.storage import files
from yournas.storage.errors import InvalidPath, NotFound, StorageError, UnsafePath
from yournas.storage.paths import ensure_space_root, open_space_root
from yournas.storage.root import StorageRoot

log = logging.getLogger("yournas.permissions")

HOME_SPACE = "home"
SHARE_PREFIX = "share:"
SHARE_ID = re.compile(r"s_[0-9a-f]{16}")
_SHARE_SPACE = re.compile(r"share:(s_[0-9a-f]{16})")
DENIED_LOG_INTERVAL_SECONDS = 60.0
_DENIED_LOG_MAX_KEYS = 2048


class Level(IntEnum):
    """What a user may do in a space. Ordered: a higher level includes the lower ones."""

    NONE = 0
    READ = 1
    WRITE = 2


class Action(StrEnum):
    LIST = "list"  # list a folder, stat an item
    READ = "read"  # download
    UPLOAD = "upload"
    MKDIR = "mkdir"
    DELETE = "delete"
    THUMBNAIL_WRITE = "thumbnail_write"
    # choose or clear the cover of a month (docs/DESIGN-NOTES.md#month-covers)
    COVER_WRITE = "cover_write"


# Minimum level for each action. An action missing from this table is refused (403).
NEEDS: Mapping[Action, Level] = {
    Action.LIST: Level.READ,
    Action.READ: Level.READ,
    Action.UPLOAD: Level.WRITE,
    Action.MKDIR: Level.WRITE,
    Action.DELETE: Level.WRITE,
    Action.THUMBNAIL_WRITE: Level.WRITE,
    Action.COVER_WRITE: Level.WRITE,
}


@dataclass(frozen=True)
class SpaceAccess:
    """A granted request: the real root folder of the space, the level the user holds and the
    scope of what the server stores about the space. `space` is the id the client sent, and
    `home` is the same string for every user, so anything stored per space is keyed by `scope`."""

    root: Path
    level: Level
    space: str
    scope: str


def home_scope(user_id: str) -> str:
    return "u:" + user_id


def share_scope(share_id: str) -> str:
    return "s:" + share_id


@dataclass(frozen=True)
class SpaceInfo:
    """One entry of the caller's space list (GET /spaces, /auth/me)."""

    id: str
    name: str
    access: Literal["read", "write"]


def share_space_id(share_id: str) -> str:
    return SHARE_PREFIX + share_id


def parse_share_space(space: object) -> str | None:
    """The share id inside a `share:<id>` space id, or None for anything else (home included)."""
    if not isinstance(space, str):
        return None
    m = _SHARE_SPACE.fullmatch(space)
    return m.group(1) if m else None


def _space_type(space: object) -> str:
    """Coarse class of a space id for the log. Never the id itself: it is client input."""
    if space == HOME_SPACE:
        return "home"
    if isinstance(space, str) and space.startswith(SHARE_PREFIX):
        return "share"
    return "other"


def _access(level: Level) -> Literal["read", "write"]:
    return "write" if level >= Level.WRITE else "read"


def _not_found() -> AppError:
    return AppError(404)  # the same object shape as api.common.not_found()


def _forbidden() -> AppError:
    return AppError(403)


class ShareDirs:
    """The folders of shares under `shared/`. They are created when a share is created and
    removed only when empty; nothing else ever creates or deletes one."""

    def __init__(self, storage: StorageRoot) -> None:
        self._storage = storage

    @staticmethod
    def new_id() -> str:
        """A fresh share id. Random, so ids are never reused after a share is deleted."""
        return "s_" + secrets.token_hex(8)

    @staticmethod
    def _checked(share_id: str) -> str:
        if not isinstance(share_id, str) or SHARE_ID.fullmatch(share_id) is None:
            raise InvalidPath("bad-share-id")
        return share_id

    def create(self, share_id: str) -> Path:
        """Create `shared/<share_id>` (idempotent) and return its real path. Raises StorageError."""
        return ensure_space_root(self._storage.shared, self._checked(share_id))

    def is_empty(self, share_id: str) -> bool:
        """True if the folder is missing or holds no entry at all (invisible names count)."""
        return files.dir_is_empty(self._storage.shared, self._checked(share_id))

    def remove_if_empty(self, share_id: str) -> bool:
        """rmdir of an empty share folder, never a recursive delete. Raises NotEmpty/UnsafePath."""
        return files.remove_empty_dir(self._storage.shared, self._checked(share_id))


class Permissions:
    def __init__(
        self,
        db: Database,
        storage: StorageRoot,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._db = db
        self._storage = storage
        self._clock = clock
        self.shares = ShareDirs(storage)
        self._denied_guard = threading.Lock()
        self._denied_logged: dict[tuple[str, str, str], float] = {}

    # ---- decisions ---------------------------------------------------------------------

    def level_for(self, user_id: str, space: str) -> Level:
        """The user's level in `space`. NONE unless a rule grants more; any error is NONE."""
        try:
            return self._level(user_id, space)
        except Exception as exc:  # fail closed, whatever went wrong
            log.error("permission_check_failed", extra=error_fields(exc))
            return Level.NONE

    def _level(self, user_id: str, space: str) -> Level:
        if not isinstance(user_id, str) or not user_id or not isinstance(space, str):
            return Level.NONE
        if space == HOME_SPACE:
            # Everybody who is an enabled account has their own private space and nobody else's.
            with self._db.read() as conn:
                row = conn.execute(
                    "SELECT 1 FROM users WHERE id = ? AND disabled = 0", (user_id,)
                ).fetchone()
            return Level.WRITE if row is not None else Level.NONE
        share_id = parse_share_space(space)
        if share_id is None:
            return Level.NONE
        with self._db.read() as conn:
            row = conn.execute(
                "SELECT g.level FROM grants g "
                "JOIN shares s ON s.id = g.share_id "
                "JOIN users u ON u.id = g.user_id "
                "WHERE g.share_id = ? AND g.user_id = ? AND u.disabled = 0",
                (share_id, user_id),
            ).fetchone()
        if row is None:
            return Level.NONE
        if row["level"] == "write":
            return Level.WRITE
        if row["level"] == "read":
            return Level.READ
        return Level.NONE  # a value the schema does not allow: deny

    def require(self, user_id: str, space: str, action: Action) -> Level:
        """The decision alone, from the database and with no disk access, so it can run again
        inside a transaction: 404 for no access (identical to an unknown space), 403 for read-only
        access to a write action."""
        level = self.level_for(user_id, space)
        if level is Level.NONE:
            self._log_denied(user_id, space, action)
            raise _not_found()
        needed = NEEDS.get(action)
        if needed is None or level < needed:
            self._log_denied(user_id, space, action)
            raise _forbidden()
        return level

    def authorize(self, user_id: str, space: str, action: Action) -> SpaceAccess:
        """Allow `action` in `space` or raise AppError (see `require`). On success the root folder
        is returned; it is looked up only after the decision, and never created for a share."""
        level = self.require(user_id, space, action)
        share_id = parse_share_space(space)
        scope = home_scope(user_id) if share_id is None else share_scope(share_id)
        return SpaceAccess(self._root(user_id, space), level, space, scope)

    def _root(self, user_id: str, space: str) -> Path:
        try:
            share_id = parse_share_space(space)
            if share_id is None:
                return ensure_space_root(self._storage.users, user_id)  # home, own id only
            return open_space_root(self._storage.shared, share_id)
        except (NotFound, UnsafePath, InvalidPath) as exc:
            # A granted share whose folder is gone or unsafe: nothing to serve, and nothing is
            # created to make up for it.
            log.error("space_root_unavailable", extra={"space_type": _space_type(space)})
            raise _not_found() from exc
        except StorageError as exc:
            log.error("space_root_failed", extra=error_fields(exc))
            raise AppError(500, "internal_error", "Internal Server Error") from None

    def spaces_for(self, user_id: str) -> list[SpaceInfo]:
        """The spaces the user can open: `home` first, then granted shares ordered by name
        (case-insensitive, then id). A disabled or unknown user, or any error, gives an empty
        list."""
        try:
            if self._level(user_id, HOME_SPACE) is Level.NONE:
                return []
            with self._db.read() as conn:
                rows = conn.execute(
                    "SELECT s.id, s.name, g.level FROM grants g "
                    "JOIN shares s ON s.id = g.share_id "
                    "JOIN users u ON u.id = g.user_id "
                    "WHERE g.user_id = ? AND u.disabled = 0 "
                    "ORDER BY s.name COLLATE NOCASE, s.id",
                    (user_id,),
                ).fetchall()
        except Exception as exc:  # fail closed
            log.error("spaces_lookup_failed", extra=error_fields(exc))
            return []
        spaces = [SpaceInfo(HOME_SPACE, "My files", "write")]
        for r in rows:
            level = Level.WRITE if r["level"] == "write" else Level.READ
            if r["level"] not in ("read", "write") or not SHARE_ID.fullmatch(str(r["id"])):
                continue
            spaces.append(SpaceInfo(share_space_id(str(r["id"])), str(r["name"]), _access(level)))
        return spaces

    # ---- logging -----------------------------------------------------------------------

    def _log_denied(self, user_id: str, space: object, action: object) -> None:
        """permission_denied, rate limited per (user, space type, action): a client hammering a
        forbidden space cannot flood the log. The space id itself (client input) is not logged."""
        try:
            key = (str(user_id)[:64], _space_type(space), str(action))
            now = self._clock()
            with self._denied_guard:
                last = self._denied_logged.get(key)
                if last is not None and now - last < DENIED_LOG_INTERVAL_SECONDS:
                    return
                if len(self._denied_logged) >= _DENIED_LOG_MAX_KEYS:
                    self._denied_logged.clear()
                self._denied_logged[key] = now
            log.warning(
                "permission_denied",
                extra={"user_id": key[0], "space_type": key[1], "action": key[2]},
            )
        except Exception as exc:  # logging must never turn a denial into something else
            log.debug("permission_log_failed", extra=error_fields(exc))
