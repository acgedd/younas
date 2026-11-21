"""yournas.permissions against a real database and a real storage root."""

from __future__ import annotations

import os
import secrets
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from yournas import permissions as perm_module
from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.permissions import (
    HOME_SPACE,
    NEEDS,
    Action,
    Level,
    Permissions,
    ShareDirs,
    SpaceAccess,
    SpaceInfo,
    parse_share_space,
)
from yournas.storage.errors import InvalidPath, NotEmpty, UnsafePath
from yournas.storage.root import StorageRoot, open_storage


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Env:
    def __init__(self, db: Database, storage: StorageRoot, clock: Clock) -> None:
        self.db = db
        self.storage = storage
        self.clock = clock
        self.perms = Permissions(db, storage, clock)
        self.owner = self.add_user("owner", role="owner")
        self.alice = self.add_user("alice")
        self.bob = self.add_user("bob")

    def add_user(self, name: str, *, role: str = "user", disabled: bool = False) -> str:
        user_id = "u_" + secrets.token_hex(8)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, disabled, created_at, "
                "password_changed_at) VALUES (?, ?, 'h', ?, ?, 1, 1)",
                (user_id, name, role, int(disabled)),
            )
        return user_id

    def add_share(self, name: str, *, create_dir: bool = True, share_id: str | None = None) -> str:
        share_id = share_id or self.perms.shares.new_id()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO shares (id, name, created_at, created_by) VALUES (?, ?, 1, ?)",
                (share_id, name, self.owner),
            )
        if create_dir:
            self.perms.shares.create(share_id)
        return share_id

    def grant(self, share_id: str, user_id: str, level: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO grants (share_id, user_id, level, created_at) "
                "VALUES (?, ?, ?, 1)",
                (share_id, user_id, level),
            )

    def revoke(self, share_id: str, user_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "DELETE FROM grants WHERE share_id = ? AND user_id = ?", (share_id, user_id)
            )

    def set_disabled(self, user_id: str, disabled: bool) -> None:
        with self.db.transaction() as conn:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))

    def tree(self) -> set[str]:
        """Everything under the storage root except the database folder, as relative paths."""
        found: set[str] = set()
        root = self.storage.root
        for dirpath, dirnames, filenames in os.walk(root):
            for name in (*dirnames, *filenames):
                found.add(str(Path(dirpath, name).relative_to(root)))
        return found


@pytest.fixture
def env(tmp_path: Path, storage_root: Path) -> Iterator[Env]:
    db = Database(tmp_path / "perm.db")
    yield Env(db, open_storage(storage_root), Clock())
    db.close()


def share_space(share_id: str) -> str:
    return f"share:{share_id}"


def denial(perms: Permissions, user_id: str, space: str, action: Action) -> AppError:
    with pytest.raises(AppError) as exc:
        perms.authorize(user_id, space, action)
    return exc.value


def shape(err: AppError) -> tuple[Any, ...]:
    return (err.status_code, err.code, err.message, err.headers, err.extra)


# --------------------------------------------------------------------------- tables


def test_levels_are_ordered() -> None:
    assert Level.NONE < Level.READ < Level.WRITE


def test_needs_covers_every_action_exactly() -> None:
    assert set(NEEDS) == set(Action)
    assert NEEDS[Action.LIST] is Level.READ
    assert NEEDS[Action.READ] is Level.READ
    assert NEEDS[Action.UPLOAD] is Level.WRITE
    assert NEEDS[Action.MKDIR] is Level.WRITE
    assert NEEDS[Action.DELETE] is Level.WRITE


def test_action_values_are_the_documented_words() -> None:
    assert {a.value for a in Action} == {"list", "read", "upload", "mkdir", "delete"}


def test_home_space_id_matches_the_api_constant() -> None:
    from yournas.api.common import HOME_SPACE as API_HOME

    assert HOME_SPACE == API_HOME == "home"


@pytest.mark.parametrize(
    ("space", "expected"),
    [
        ("share:s_0123456789abcdef", "s_0123456789abcdef"),
        ("home", None),
        ("share:", None),
        ("share:s_0123456789ABCDEF", None),  # upper case
        ("share:s_0123456789abcde", None),  # 15
        ("share:s_0123456789abcdef0", None),  # 17
        ("share:s_0123456789abcdeg", None),
        ("share:s_0123456789abcdef\n", None),
        ("share:s_0123456789abcdef/..", None),
        ("share:../s_0123456789abcdef", None),
        (" share:s_0123456789abcdef", None),
        ("Share:s_0123456789abcdef", None),
        ("share:s_٠١٢٣٤٥٦٧٨٩abcdef", None),  # non-ASCII digits
        (None, None),
        (5, None),
    ],
)
def test_parse_share_space(space: object, expected: str | None) -> None:
    assert parse_share_space(space) == expected


# --------------------------------------------------------------------------- default deny


def test_a_user_without_a_grant_has_no_access_to_a_share(env: Env) -> None:
    sid = env.add_share("Photos")
    assert env.perms.level_for(env.alice, share_space(sid)) is Level.NONE
    for action in Action:
        assert denial(env.perms, env.alice, share_space(sid), action).status_code == 404


def test_grants_belong_to_one_user_only(env: Env) -> None:
    sid = env.add_share("Photos")
    env.grant(sid, env.alice, "write")
    assert env.perms.level_for(env.alice, share_space(sid)) is Level.WRITE
    assert env.perms.level_for(env.bob, share_space(sid)) is Level.NONE


def test_grants_are_per_share(env: Env) -> None:
    s1, s2 = env.add_share("One"), env.add_share("Two")
    env.grant(s1, env.alice, "read")
    assert env.perms.level_for(env.alice, share_space(s1)) is Level.READ
    assert env.perms.level_for(env.alice, share_space(s2)) is Level.NONE


@pytest.mark.parametrize(
    "space",
    [
        "",
        "Home",
        "HOME",
        "home ",
        " home",
        "home/",
        "home/..",
        "users",
        "users/u_x",
        "shared",
        "shared/s_0123456789abcdef",
        "share",
        "share:",
        "share:home",
        "share:s_",
        "share:s_0123456789abcdeg",
        "share:s_0123456789ABCDEF",
        "share:s_0123456789abcdef0",
        "share:s_0123456789abcdef/",
        "share:s_0123456789abcdef\n",
        "share:../home",
        "share:s_0123456789abcdef/../../users",
        "..",
        "C:\\",
        "\\\\host\\share",
        "x" * 5000,
        "home\x00",
    ],
)
def test_malformed_space_ids_get_the_same_404_as_an_unknown_space(env: Env, space: str) -> None:
    unknown = denial(env.perms, env.alice, "share:s_ffffffffffffffff", Action.LIST)
    for action in Action:
        err = denial(env.perms, env.alice, space, action)
        assert shape(err) == shape(unknown)
        assert err.status_code == 404
    assert env.perms.level_for(env.alice, space) is Level.NONE


def test_non_string_inputs_are_denied(env: Env) -> None:
    for space in (None, 0, b"home", ["home"]):
        assert env.perms.level_for(env.alice, space) is Level.NONE  # type: ignore[arg-type]
    for user in (None, "", 7):
        assert env.perms.level_for(user, HOME_SPACE) is Level.NONE  # type: ignore[arg-type]
        assert env.perms.level_for(user, "share:s_0123456789abcdef") is Level.NONE  # type: ignore[arg-type]


def test_an_unknown_user_has_nothing_not_even_a_home(env: Env) -> None:
    for user in ("u_" + "0" * 16, "../x", "u_x/../y"):
        assert env.perms.level_for(user, HOME_SPACE) is Level.NONE
        assert denial(env.perms, user, HOME_SPACE, Action.LIST).status_code == 404
    assert env.perms.spaces_for("u_" + "0" * 16) == []


# --------------------------------------------------------------------------- home


def test_home_is_write_for_its_own_user_and_maps_to_their_folder(env: Env) -> None:
    for action in Action:
        access = env.perms.authorize(env.alice, HOME_SPACE, action)
        assert isinstance(access, SpaceAccess)
        assert access.level is Level.WRITE
        assert access.space == HOME_SPACE
        assert access.root == (env.storage.users / env.alice).resolve()
    assert (env.storage.users / env.alice).is_dir()


def test_two_users_get_two_different_homes(env: Env) -> None:
    a = env.perms.authorize(env.alice, HOME_SPACE, Action.LIST).root
    b = env.perms.authorize(env.bob, HOME_SPACE, Action.LIST).root
    assert a != b and a.parent == b.parent


def test_the_owner_role_gives_no_access_to_anyone_elses_files(env: Env) -> None:
    sid = env.add_share("Private")
    env.grant(sid, env.alice, "write")
    env.perms.authorize(env.alice, HOME_SPACE, Action.LIST)
    # the owner's "home" is the owner's own folder, never alice's
    owner_home = env.perms.authorize(env.owner, HOME_SPACE, Action.LIST).root
    assert owner_home == (env.storage.users / env.owner).resolve()
    assert owner_home != (env.storage.users / env.alice).resolve()
    # and an ungranted share stays a 404 for the owner
    for action in Action:
        assert denial(env.perms, env.owner, share_space(sid), action).status_code == 404
    assert env.perms.level_for(env.owner, share_space(sid)) is Level.NONE


def test_the_owner_needs_a_grant_like_everybody_else(env: Env) -> None:
    sid = env.add_share("Mine")
    assert env.perms.level_for(env.owner, share_space(sid)) is Level.NONE
    env.grant(sid, env.owner, "write")
    assert env.perms.level_for(env.owner, share_space(sid)) is Level.WRITE
    env.grant(sid, env.owner, "read")
    assert denial(env.perms, env.owner, share_space(sid), Action.DELETE).status_code == 403


def test_a_disabled_user_has_no_home(env: Env) -> None:
    env.set_disabled(env.alice, True)
    assert env.perms.level_for(env.alice, HOME_SPACE) is Level.NONE
    assert denial(env.perms, env.alice, HOME_SPACE, Action.LIST).status_code == 404
    env.set_disabled(env.alice, False)
    assert env.perms.level_for(env.alice, HOME_SPACE) is Level.WRITE


# --------------------------------------------------------------------------- shares


@pytest.mark.parametrize("action", list(Action))
@pytest.mark.parametrize("level", ["read", "write"])
def test_read_versus_write_per_action(env: Env, level: str, action: Action) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, level)
    allowed = (Level.READ if level == "read" else Level.WRITE) >= NEEDS[action]
    if allowed:
        access = env.perms.authorize(env.alice, share_space(sid), action)
        assert access.level.name.lower() == level
        assert access.root == (env.storage.shared / sid).resolve()
        assert access.space == share_space(sid)
    else:
        err = denial(env.perms, env.alice, share_space(sid), action)
        assert (err.status_code, err.code) == (403, "forbidden")


def test_read_grant_allows_exactly_list_and_read(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "read")
    ok = {
        a
        for a in Action
        if _try(env.perms, env.alice, share_space(sid), a)  # noqa: SIM118 - helper
    }
    assert ok == {Action.LIST, Action.READ}


def test_write_grant_allows_every_action(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")
    assert all(_try(env.perms, env.alice, share_space(sid), a) for a in Action)


def _try(perms: Permissions, user: str, space: str, action: Action) -> bool:
    try:
        perms.authorize(user, space, action)
    except AppError:
        return False
    return True


def test_an_action_missing_from_the_table_is_forbidden(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")
    err = denial(env.perms, env.alice, share_space(sid), "chmod")  # type: ignore[arg-type]
    assert err.status_code == 403


def test_grants_are_never_cached(env: Env) -> None:
    sid = env.add_share("Docs")
    space = share_space(sid)
    env.grant(sid, env.alice, "write")
    env.perms.authorize(env.alice, space, Action.UPLOAD)
    env.grant(sid, env.alice, "read")  # downgrade
    assert denial(env.perms, env.alice, space, Action.UPLOAD).status_code == 403
    env.perms.authorize(env.alice, space, Action.READ)
    env.revoke(sid, env.alice)
    assert denial(env.perms, env.alice, space, Action.READ).status_code == 404
    env.grant(sid, env.alice, "write")  # regrant
    env.perms.authorize(env.alice, space, Action.DELETE)


def test_a_deleted_share_denies_at_once_and_drops_its_grants(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")
    with env.db.transaction() as conn:
        conn.execute("DELETE FROM shares WHERE id = ?", (sid,))
    assert env.perms.level_for(env.alice, share_space(sid)) is Level.NONE
    assert denial(env.perms, env.alice, share_space(sid), Action.LIST).status_code == 404
    assert env.perms.spaces_for(env.alice) == [SpaceInfo("home", "My files", "write")]


def test_a_share_id_is_not_reused_for_a_new_share(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")
    with env.db.transaction() as conn:
        conn.execute("DELETE FROM shares WHERE id = ?", (sid,))
    fresh = env.add_share("Docs")  # same name, new id
    assert fresh != sid
    assert env.perms.level_for(env.alice, share_space(fresh)) is Level.NONE


def test_a_disabled_user_loses_every_share_and_gets_them_back_when_enabled(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")
    env.set_disabled(env.alice, True)
    for action in Action:
        assert denial(env.perms, env.alice, share_space(sid), action).status_code == 404
    assert env.perms.spaces_for(env.alice) == []
    env.set_disabled(env.alice, False)
    env.perms.authorize(env.alice, share_space(sid), Action.UPLOAD)


def test_a_valid_share_id_with_no_share_is_denied(env: Env) -> None:
    space = share_space("s_" + "0" * 16)
    assert env.perms.level_for(env.alice, space) is Level.NONE
    assert denial(env.perms, env.alice, space, Action.LIST).status_code == 404


def test_a_granted_share_whose_folder_is_missing_is_404_and_nothing_is_created(env: Env) -> None:
    sid = env.add_share("Docs", create_dir=False)
    env.grant(sid, env.alice, "write")
    before = env.tree()
    for action in Action:
        assert denial(env.perms, env.alice, share_space(sid), action).status_code == 404
    assert env.tree() == before
    assert not (env.storage.shared / sid).exists()


def test_a_share_folder_replaced_by_a_junction_is_refused(
    env: Env, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    sid = env.add_share("Docs", create_dir=False)
    env.grant(sid, env.alice, "write")
    outside = tmp_path / "outside"
    outside.mkdir()
    junction(env.storage.shared / sid, outside)
    assert denial(env.perms, env.alice, share_space(sid), Action.LIST).status_code == 404


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


# --------------------------------------------------------------------------- 404 identity


def test_every_kind_of_no_access_is_byte_identical(env: Env) -> None:
    ungranted = env.add_share("Secret")
    env.grant(ungranted, env.bob, "write")
    gone = env.add_share("Gone")
    env.grant(gone, env.alice, "write")
    with env.db.transaction() as conn:
        conn.execute("DELETE FROM shares WHERE id = ?", (gone,))
    disabled_target = env.add_share("Other")
    env.grant(disabled_target, env.alice, "read")
    spaces = [
        share_space(ungranted),
        share_space(gone),
        share_space("s_" + "1" * 16),
        "share:nonsense",
        "home/../" + env.bob,
        "users/" + env.bob,
    ]
    errors = [denial(env.perms, env.alice, s, a) for s in spaces for a in Action]
    assert len({shape(e) for e in errors}) == 1
    only = errors[0]
    assert (only.status_code, only.code, only.message) == (404, "not_found", "Not Found")


def test_the_404_matches_the_apis_not_found(env: Env) -> None:
    from yournas.api.common import not_found

    ref = not_found()
    err = denial(env.perms, env.alice, "share:s_" + "2" * 16, Action.READ)
    assert shape(err) == shape(ref)


def test_a_too_low_level_is_a_plain_403(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "read")
    err = denial(env.perms, env.alice, share_space(sid), Action.MKDIR)
    assert (err.status_code, err.code, err.message) == (403, "forbidden", "Forbidden")
    assert err.headers is None and err.extra is None


# --------------------------------------------------------------------------- no side effects


def test_denied_calls_create_nothing_on_disk(env: Env) -> None:
    ungranted = env.add_share("Secret")
    env.grant(ungranted, env.bob, "write")
    readonly = env.add_share("Read only")
    env.grant(readonly, env.alice, "read")
    env.perms.authorize(env.bob, HOME_SPACE, Action.LIST)  # bob's home exists already
    before = env.tree()
    spaces = [
        share_space(ungranted),
        share_space("s_" + "3" * 16),
        "share:s_",
        "share:../x",
        "users/u_abc",
        "../x",
        "",
    ]
    for space in spaces:
        for action in Action:
            assert not _try(env.perms, env.alice, space, action)
    for action in (Action.UPLOAD, Action.MKDIR, Action.DELETE):
        assert not _try(env.perms, env.alice, share_space(readonly), action)
    for user in ("u_" + "9" * 16, "../x", ""):
        assert not _try(env.perms, user, HOME_SPACE, Action.LIST)
    assert env.tree() == before
    assert not (env.storage.users / env.alice).exists()  # alice never opened her home


def test_authorize_decides_before_it_touches_the_filesystem(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> Path:
        raise AssertionError("filesystem touched before authorization")

    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "read")
    monkeypatch.setattr(perm_module, "ensure_space_root", boom)
    monkeypatch.setattr(perm_module, "open_space_root", boom)
    for space in (share_space(sid), "share:s_" + "4" * 16, "garbage"):
        assert not _try(env.perms, env.alice, space, Action.UPLOAD)
    assert not _try(env.perms, env.bob, share_space(sid), Action.LIST)
    env.set_disabled(env.alice, True)
    assert not _try(env.perms, env.alice, HOME_SPACE, Action.LIST)


def test_authorize_never_creates_a_share_folder(env: Env) -> None:
    sid = env.add_share("Docs", create_dir=False)
    env.grant(sid, env.alice, "write")
    assert not _try(env.perms, env.alice, share_space(sid), Action.MKDIR)
    assert not (env.storage.shared / sid).exists()


# --------------------------------------------------------------------------- fail closed


def test_any_error_while_deciding_denies(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")

    def broken() -> Any:
        raise RuntimeError("database exploded")

    monkeypatch.setattr(env.db, "read", broken)
    assert env.perms.level_for(env.alice, HOME_SPACE) is Level.NONE
    assert env.perms.level_for(env.alice, share_space(sid)) is Level.NONE
    assert denial(env.perms, env.alice, share_space(sid), Action.LIST).status_code == 404
    assert denial(env.perms, env.alice, HOME_SPACE, Action.LIST).status_code == 404
    assert env.perms.spaces_for(env.alice) == []


def test_a_missing_table_denies(env: Env) -> None:
    with env.db.transaction() as conn:
        conn.execute("DROP TABLE grants")
    sid = "s_" + "5" * 16
    assert env.perms.level_for(env.alice, share_space(sid)) is Level.NONE
    assert env.perms.level_for(env.alice, HOME_SPACE) is Level.WRITE  # home needs no grants


def test_a_broken_filesystem_is_an_error_not_a_grant(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yournas.storage.errors import StorageIOError

    def boom(*_a: object, **_k: object) -> Path:
        raise StorageIOError("errno=5")

    monkeypatch.setattr(perm_module, "ensure_space_root", boom)
    err = denial(env.perms, env.alice, HOME_SPACE, Action.LIST)
    assert (err.status_code, err.code) == (500, "internal_error")


def test_the_log_failure_path_never_changes_the_outcome(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("logging broke")

    monkeypatch.setattr(perm_module.log, "warning", boom)
    assert denial(env.perms, env.alice, "share:s_" + "6" * 16, Action.LIST).status_code == 404


# --------------------------------------------------------------------------- spaces_for


def test_spaces_for_lists_home_first_then_shares_by_name(env: Env) -> None:
    banana = env.add_share("banana")
    apple = env.add_share("Apple")
    cherry = env.add_share("cherry")
    zed = env.add_share("Zed")
    hidden = env.add_share("Hidden")
    for sid, level in ((banana, "write"), (apple, "read"), (cherry, "read"), (zed, "write")):
        env.grant(sid, env.alice, level)
    env.grant(hidden, env.bob, "write")
    assert env.perms.spaces_for(env.alice) == [
        SpaceInfo("home", "My files", "write"),
        SpaceInfo(share_space(apple), "Apple", "read"),
        SpaceInfo(share_space(banana), "banana", "write"),
        SpaceInfo(share_space(cherry), "cherry", "read"),
        SpaceInfo(share_space(zed), "Zed", "write"),
    ]


def test_spaces_for_nobody_else_sees_a_share(env: Env) -> None:
    sid = env.add_share("Docs")
    env.grant(sid, env.alice, "write")
    assert [s.id for s in env.perms.spaces_for(env.bob)] == ["home"]
    assert [s.id for s in env.perms.spaces_for(env.owner)] == ["home"]


def test_spaces_for_matches_authorize(env: Env) -> None:
    readable, writable = env.add_share("R"), env.add_share("W")
    env.grant(readable, env.alice, "read")
    env.grant(writable, env.alice, "write")
    for info in env.perms.spaces_for(env.alice):
        level = env.perms.level_for(env.alice, info.id)
        assert level.name.lower() == info.access
        env.perms.authorize(env.alice, info.id, Action.LIST)


def test_spaces_for_does_not_touch_the_filesystem(env: Env) -> None:
    sid = env.add_share("Docs", create_dir=False)
    env.grant(sid, env.alice, "write")
    before = env.tree()
    env.perms.spaces_for(env.alice)
    assert env.tree() == before


def test_spaces_for_orders_equal_names_by_id(env: Env) -> None:
    # Names are unique ignoring case in the schema, so a tie cannot happen there. The ORDER BY
    # still ends with the id, which makes the order total.
    a, b = env.add_share("A"), env.add_share("B")
    env.grant(a, env.alice, "read")
    env.grant(b, env.alice, "read")
    assert [s.name for s in env.perms.spaces_for(env.alice)[1:]] == ["A", "B"]


def test_space_info_is_a_plain_value(env: Env) -> None:
    info = SpaceInfo("home", "My files", "write")
    assert info == SpaceInfo("home", "My files", "write")
    with pytest.raises(AttributeError):
        info.name = "x"  # type: ignore[misc]


# --------------------------------------------------------------------------- denial log


def test_denials_are_logged_with_user_and_space_type_only(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    secret_space = "share:s_deadbeefdeadbeef"
    with caplog.at_level("WARNING", logger="yournas.permissions"):
        denial(env.perms, env.alice, secret_space, Action.READ)
    (record,) = [r for r in caplog.records if r.message == "permission_denied"]
    assert record.user_id == env.alice  # type: ignore[attr-defined]
    assert record.space_type == "share"  # type: ignore[attr-defined]
    assert record.action == "read"  # type: ignore[attr-defined]
    assert "deadbeef" not in repr(record.__dict__)


def test_denial_log_is_rate_limited_per_user_type_and_action(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    def count() -> int:
        return len([r for r in caplog.records if r.message == "permission_denied"])

    with caplog.at_level("WARNING", logger="yournas.permissions"):
        for _ in range(50):
            denial(env.perms, env.alice, "share:s_" + "7" * 16, Action.LIST)
        assert count() == 1
        denial(env.perms, env.alice, "share:s_" + "7" * 16, Action.READ)  # other action
        denial(env.perms, env.bob, "share:s_" + "7" * 16, Action.LIST)  # other user
        denial(env.perms, env.alice, "garbage", Action.LIST)  # other space type
        assert count() == 4
        env.clock.now += 61
        denial(env.perms, env.alice, "share:s_" + "7" * 16, Action.LIST)
        assert count() == 5


def test_denial_log_memory_is_bounded(env: Env) -> None:
    for i in range(perm_module._DENIED_LOG_MAX_KEYS + 10):
        env.perms._log_denied(f"u_{i}", "garbage", Action.LIST)
    assert len(env.perms._denied_logged) <= perm_module._DENIED_LOG_MAX_KEYS


# --------------------------------------------------------------------------- share folders


def test_new_share_ids_are_random_and_well_formed() -> None:
    ids = {ShareDirs.new_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(perm_module.SHARE_ID.fullmatch(i) for i in ids)


def test_share_dir_lifecycle(env: Env) -> None:
    sid = ShareDirs.new_id()
    shares = env.perms.shares
    assert shares.is_empty(sid) is True  # missing counts as empty
    path = shares.create(sid)
    assert path == (env.storage.shared / sid).resolve() and path.is_dir()
    assert shares.create(sid) == path  # idempotent
    (path / "f.txt").write_bytes(b"x")
    assert shares.is_empty(sid) is False
    with pytest.raises(NotEmpty):
        shares.remove_if_empty(sid)
    assert (path / "f.txt").read_bytes() == b"x"
    (path / "f.txt").unlink()
    assert shares.is_empty(sid) is True
    assert shares.remove_if_empty(sid) is True
    assert not path.exists()
    assert shares.remove_if_empty(sid) is True  # already gone


@pytest.mark.parametrize(
    "bad", ["", "home", "s_", "s_xyz", "../s_0123456789abcdef", "s_0123456789ABCDEF", "x/y"]
)
def test_share_dir_helpers_refuse_anything_but_a_share_id(env: Env, bad: str) -> None:
    before = env.tree()
    for fn in (
        env.perms.shares.create,
        env.perms.shares.is_empty,
        env.perms.shares.remove_if_empty,
    ):
        with pytest.raises(InvalidPath):
            fn(bad)
    assert env.tree() == before


def test_share_dir_removal_refuses_a_link(
    env: Env, tmp_path: Path, junction: Callable[[Path, Path], Path]
) -> None:
    sid = ShareDirs.new_id()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    junction(env.storage.shared / sid, outside)
    assert env.perms.shares.is_empty(sid) is False
    with pytest.raises(UnsafePath):
        env.perms.shares.remove_if_empty(sid)
    assert (outside / "keep.txt").read_text() == "keep"
