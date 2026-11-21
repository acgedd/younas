"""Audit log: allowlisted content only, newest-first paging, retention."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from yournas import audit
from yournas.audit import AuditError, AuditFilter, AuditLog
from yournas.core.database import Database

DAY = 86400
NOW = 1_800_000_000


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "audit.db")
    yield database
    database.close()


def add(
    db: Database,
    n: int = 1,
    *,
    at: int = NOW,
    action: str = "share_created",
    actor: str = "u_owner",
    target: str = "s_" + "a" * 16,
) -> None:
    with db.transaction() as conn:
        for _ in range(n):
            audit.record(conn, actor, action, "share", target, None, now=at)


def rows(db: Database) -> list[sqlite3.Row]:
    with db.read() as conn:
        return conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()


# --------------------------------------------------------------------------- record


def test_record_stores_one_row(db: Database) -> None:
    with db.transaction() as conn:
        row_id = audit.record(conn, "u_owner", "user_created", "user", "u_" + "1" * 16, None, now=7)
    (r,) = rows(db)
    assert r["id"] == row_id
    assert (r["at"], r["actor_id"], r["action"]) == (7, "u_owner", "user_created")
    assert (r["target_type"], r["target_id"], r["detail"]) == ("user", "u_" + "1" * 16, None)


def test_detail_is_stored_as_json(db: Database) -> None:
    detail = {"level": "write", "size": 12, "kind": "file", "depth": 2, "overwrite": True}
    with db.transaction() as conn:
        audit.record(conn, "u_a", "upload_completed", "share", "s_" + "b" * 16, detail)
    (r,) = rows(db)
    assert json.loads(r["detail"]) == detail
    assert r["at"] > 0  # real clock when no `now` is given


def test_empty_detail_is_null(db: Database) -> None:
    with db.transaction() as conn:
        audit.record(conn, "u_a", "share_deleted", "share", "s_" + "b" * 16, {})
    assert rows(db)[0]["detail"] is None


@pytest.mark.parametrize(
    "key",
    [
        "username",
        "name",
        "share_name",
        "filename",
        "path",
        "rel_path",
        "token",
        "password",
        "temporary_password",
        "password_hash",
        "ip",
        "user_id",
        "",
        "Level",
    ],
)
def test_detail_keys_outside_the_allowlist_are_refused(db: Database, key: str) -> None:
    with pytest.raises(AuditError) as exc, db.transaction() as conn:
        audit.record(conn, "u_a", "grant_set", "grant", "s_x:u_y", {key: "write"})
    assert key not in str(exc.value) or key == ""
    assert rows(db) == []


def test_detail_key_that_is_not_a_string_is_refused(db: Database) -> None:
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "grant_set", "grant", "s_x:u_y", {1: "write"})  # type: ignore[dict-item]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("level", 1),
        ("level", True),
        ("level", None),
        ("level", "Write"),  # upper case
        ("level", "photos/2024"),  # a path
        ("level", "my share"),  # a name with a space
        ("level", "x" * 17),  # too long
        ("level", ""),
        ("kind", ["file"]),
        ("size", "12"),
        ("size", -1),
        ("size", 1.5),
        ("size", True),
        ("size", 2**63),
        ("depth", "2"),
        ("disabled", 1),
        ("disabled", "true"),
        ("overwrite", 0),
        ("count", None),
        ("count", {"a": 1}),
    ],
)
def test_detail_values_of_the_wrong_type_or_shape_are_refused(
    db: Database, key: str, value: object
) -> None:
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "item_deleted", "share", "s_" + "a" * 16, {key: value})
    assert rows(db) == []


def test_a_secret_cannot_hide_in_an_allowed_key(db: Database) -> None:
    token = "x" * 43
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "item_deleted", "share", "s_" + "a" * 16, {"kind": token})
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "item_deleted", "share", "s_" + "a" * 16, {"kind": "Tr0ub4dor3"})
    assert rows(db) == []


def test_one_bad_key_refuses_the_whole_entry(db: Database) -> None:
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "grant_set", "grant", "s_x:u_y", {"level": "read", "name": "a"})
    assert rows(db) == []


@pytest.mark.parametrize(
    "action", ["login_failed", "", "USER_CREATED", "file_read", "user_created "]
)
def test_unknown_actions_are_refused(db: Database, action: str) -> None:
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", action, "user", "u_b")
    assert rows(db) == []


@pytest.mark.parametrize("target_type", ["", "file", "path", "User"])
def test_unknown_target_types_are_refused(db: Database, target_type: str) -> None:
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "user_created", target_type, "u_b")


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "alice smith",  # a name
        "photos/2024/a.txt",  # a path
        "C:\\data\\x",
        "a.txt",
        "..",
        "x" * 81,
        "nämé",
        "tok\nen",
    ],
)
def test_ids_must_be_plain_identifiers(db: Database, bad_id: str) -> None:
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, "u_a", "item_deleted", "share", bad_id)
    with pytest.raises(AuditError), db.transaction() as conn:
        audit.record(conn, bad_id, "item_deleted", "share", "s_" + "a" * 16)
    assert rows(db) == []


def test_a_refused_entry_rolls_back_the_callers_change(db: Database) -> None:
    # The caller's change and its audit row share one transaction: when record refuses, the
    # exception propagates and the transaction (with the caller's change) rolls back.
    with pytest.raises(AuditError), db.transaction() as conn:
        conn.execute(
            "INSERT INTO shares (id, name, created_at, created_by) VALUES ('s_1', 'n', 1, 'u')"
        )
        audit.record(conn, "u_a", "share_created", "share", "s_1", {"name": "n"})
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 0


def test_a_failing_insert_rolls_the_change_back(db: Database) -> None:
    with pytest.raises(sqlite3.Error), db.transaction() as conn:
        conn.execute(
            "INSERT INTO shares (id, name, created_at, created_by) VALUES ('s_1', 'n', 1, 'u')"
        )
        conn.execute("DROP TABLE audit_log")
        audit.record(conn, "u_a", "share_created", "share", "s_1")
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0


def test_grant_target_id_holds_share_and_user_ids(db: Database) -> None:
    with db.transaction() as conn:
        audit.record(
            conn, "u_o", "grant_set", "grant", "s_" + "a" * 16 + ":u_" + "b" * 16, {"level": "read"}
        )
    assert rows(db)[0]["target_id"].count(":") == 1


def test_audit_log_has_no_name_or_path_column(db: Database) -> None:
    with db.read() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)")}
    assert cols == {"id", "at", "actor_id", "action", "target_type", "target_id", "detail"}


# --------------------------------------------------------------------------- list / cursor


def test_newest_first_and_fields(db: Database) -> None:
    with db.transaction() as conn:
        audit.record(conn, "u_a", "share_created", "share", "s_1", None, now=1)
        audit.record(conn, "u_a", "grant_set", "grant", "s_1:u_b", {"level": "read"}, now=2)
        audit.record(
            conn, "u_b", "item_deleted", "share", "s_1", {"kind": "dir", "depth": 3}, now=3
        )
    page = audit.list_events(db)
    assert [e.action for e in page.events] == ["item_deleted", "grant_set", "share_created"]
    assert page.next_cursor is None
    first = page.events[0]
    assert (first.at, first.actor_id, first.target_type, first.target_id) == (
        3,
        "u_b",
        "share",
        "s_1",
    )
    assert first.detail == {"kind": "dir", "depth": 3}
    assert page.events[2].detail is None


def test_paging_covers_every_row_once(db: Database) -> None:
    add(db, 25)
    seen: list[int] = []
    cursor = None
    pages = 0
    while True:
        after = None if cursor is None else audit.decode_cursor(cursor)
        page = audit.list_events(db, limit=10, after_id=after)
        seen += [e.id for e in page.events]
        pages += 1
        cursor = page.next_cursor
        if cursor is None:
            break
    assert pages == 3
    assert seen == sorted(seen, reverse=True)
    assert len(seen) == len(set(seen)) == 25


def test_exact_multiple_of_the_page_size_has_no_extra_cursor(db: Database) -> None:
    add(db, 10)
    page = audit.list_events(db, limit=10)
    assert len(page.events) == 10 and page.next_cursor is None


def test_new_rows_do_not_shift_an_open_cursor(db: Database) -> None:
    add(db, 12)
    first = audit.list_events(db, limit=5)
    assert first.next_cursor is not None
    add(db, 3)  # newer rows arrive while the client pages
    second = audit.list_events(db, limit=5, after_id=audit.decode_cursor(first.next_cursor))
    assert [e.id for e in second.events] == [7, 6, 5, 4, 3]


def test_limit_is_clamped(db: Database) -> None:
    add(db, 3)
    assert len(audit.list_events(db, limit=0).events) == 1
    assert len(audit.list_events(db, limit=-5).events) == 1
    assert len(audit.list_events(db, limit=10**9).events) == 3
    add(db, audit.MAX_LIMIT + 5)
    assert len(audit.list_events(db, limit=10**9).events) == audit.MAX_LIMIT


def test_filters(db: Database) -> None:
    with db.transaction() as conn:
        audit.record(conn, "u_a", "share_created", "share", "s_1", None, now=1)
        audit.record(conn, "u_b", "share_created", "share", "s_2", None, now=2)
        audit.record(conn, "u_a", "share_deleted", "share", "s_1", None, now=3)

    def ids(f: AuditFilter) -> list[int]:
        return [e.id for e in audit.list_events(db, filters=f).events]

    assert ids(AuditFilter(action="share_created")) == [2, 1]
    assert ids(AuditFilter(actor_id="u_a")) == [3, 1]
    assert ids(AuditFilter(target_id="s_1")) == [3, 1]
    assert ids(AuditFilter(action="share_created", actor_id="u_a", target_id="s_1")) == [1]
    assert ids(AuditFilter(action="nope")) == []
    assert ids(AuditFilter(actor_id="x' OR '1'='1")) == []  # a value, never SQL


def test_a_damaged_detail_column_does_not_break_listing(db: Database) -> None:
    add(db, 1)
    with db.transaction() as conn:
        conn.execute("UPDATE audit_log SET detail = '{not json'")
    assert audit.list_events(db).events[0].detail is None
    with db.transaction() as conn:
        conn.execute("""UPDATE audit_log SET detail = '{"level":"read","name":"leak"}'""")
    assert audit.list_events(db).events[0].detail == {"level": "read"}


def test_cursor_round_trip_and_opaque() -> None:
    cursor = audit.encode_cursor(12345)
    assert audit.decode_cursor(cursor) == 12345
    assert "12345" not in cursor
    assert all(ch.isalnum() or ch in "-_" for ch in cursor)


@pytest.mark.parametrize(
    "bad",
    ["", "!!!", "abc", "YTE6", "YTE6LTE", "YTE6MS4w", "x" * 100, "YTI6MQ", "YTE6" + "A" * 40],
)
def test_malformed_cursors_are_refused(bad: str) -> None:
    with pytest.raises(AuditError):
        audit.decode_cursor(bad)


def test_cursor_for_a_huge_number_is_refused() -> None:
    with pytest.raises(AuditError):
        audit.decode_cursor(audit.encode_cursor(2**64))


# --------------------------------------------------------------------------- prune


def test_prune_by_age(db: Database) -> None:
    add(db, 1, at=NOW - 400 * DAY)
    add(db, 1, at=NOW - 366 * DAY)
    add(db, 1, at=NOW - 364 * DAY)
    add(db, 1, at=NOW)
    assert audit.prune(db, NOW) == 2
    assert [r["at"] for r in rows(db)] == [NOW - 364 * DAY, NOW]


def test_prune_keeps_a_row_exactly_at_the_limit(db: Database) -> None:
    add(db, 1, at=NOW - 365 * DAY)
    assert audit.prune(db, NOW) == 0


def test_prune_by_count_keeps_the_newest(db: Database) -> None:
    add(db, 10)
    assert audit.prune(db, NOW, max_rows=4) == 6
    assert [r["id"] for r in rows(db)] == [7, 8, 9, 10]
    assert audit.prune(db, NOW, max_rows=4) == 0


def test_prune_by_count_with_fewer_rows_deletes_nothing(db: Database) -> None:
    add(db, 3)
    assert audit.prune(db, NOW, max_rows=10) == 0
    assert len(rows(db)) == 3


def test_prune_applies_both_limits(db: Database) -> None:
    add(db, 3, at=NOW - 500 * DAY)
    add(db, 6, at=NOW - 1)
    assert audit.prune(db, NOW, max_rows=4) == 5
    assert [r["id"] for r in rows(db)] == [6, 7, 8, 9]


def test_ids_are_not_reused_after_pruning(db: Database) -> None:
    add(db, 3)
    audit.prune(db, NOW, max_rows=1)
    add(db, 1)
    assert [r["id"] for r in rows(db)] == [3, 4]


def test_prune_default_retention_is_a_year_and_100k_rows() -> None:
    assert audit.DEFAULT_MAX_AGE_DAYS == 365
    assert audit.DEFAULT_MAX_ROWS == 100_000


def test_prune_refuses_nonsense_limits(db: Database) -> None:
    for kwargs in ({"max_age_days": 0}, {"max_rows": 0}, {"max_rows": -1}):
        with pytest.raises(ValueError):
            audit.prune(db, NOW, **kwargs)


# --------------------------------------------------------------------------- AuditLog helper


class Clock:
    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_maybe_prune_runs_at_most_once_a_day(db: Database) -> None:
    clock = Clock()
    log = AuditLog(db, clock, max_rows=2)
    add(db, 5)
    assert log.maybe_prune() == 3  # first call always runs
    add(db, 5)
    clock.now += DAY - 1
    assert log.maybe_prune() is None  # too soon
    assert len(rows(db)) == 7
    clock.now += 1
    assert log.maybe_prune() == 5
    assert len(rows(db)) == 2


def test_maybe_prune_uses_the_clock_for_the_age_limit(db: Database) -> None:
    clock = Clock(NOW + 400 * DAY)
    add(db, 2, at=NOW)
    assert AuditLog(db, clock).maybe_prune() == 2


def test_maybe_prune_swallows_database_errors(
    db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    log = AuditLog(db, Clock())
    with db.transaction() as conn:
        conn.execute("DROP TABLE audit_log")
    with caplog.at_level("WARNING", logger="yournas.audit"):
        assert log.maybe_prune() is None
    assert any(r.message == "audit_prune_failed" for r in caplog.records)


def test_audit_log_record_uses_its_clock(db: Database) -> None:
    log = AuditLog(db, Clock(1234.9))
    with db.transaction() as conn:
        log.record(conn, "u_o", "user_created", "user", "u_" + "1" * 16)
    assert rows(db)[0]["at"] == 1234
    assert log.list_events().events[0].action == "user_created"


def test_audit_log_record_enforces_the_allowlist(db: Database) -> None:
    log = AuditLog(db, Clock())
    with pytest.raises(AuditError), db.transaction() as conn:
        log.record(conn, "u_o", "share_created", "share", "s_1", {"name": "Holiday photos"})


# --------------------------------------------------------------------------- retention (flood)

MANAGEMENT = {
    "user_created",
    "user_disabled",
    "user_enabled",
    "password_reset",
    "sessions_revoked",
    "share_created",
    "share_renamed",
    "share_deleted",
    "grant_set",
    "grant_removed",
    "password_changed",
}
FILE_EVENTS = {"folder_created", "upload_completed", "item_deleted"}


def actions(db: Database) -> list[str]:
    return [str(r["action"]) for r in rows(db)]


def quiet_log(db: Database, max_rows: int) -> AuditLog:
    """An AuditLog whose once-a-day prune has already run, so only the write-time trim acts."""
    log = AuditLog(db, max_rows=max_rows)
    log.maybe_prune()
    return log


def test_every_audit_action_is_classified_as_file_or_management_on_purpose() -> None:
    # A new action must be classified here by hand: a security event must never become evictable
    # as an "ordinary file event" by accident.
    assert audit.FILE_ACTIONS == FILE_EVENTS
    assert audit.MANAGEMENT_ACTIONS == MANAGEMENT
    assert audit.FILE_ACTIONS | audit.MANAGEMENT_ACTIONS == audit.ACTIONS
    assert not audit.FILE_ACTIONS & audit.MANAGEMENT_ACTIONS


def test_prune_by_count_evicts_old_file_events_before_newer_management_events(
    db: Database,
) -> None:
    add(db, 3, action="user_created")  # ids 1-3, the oldest rows in the table
    add(db, 7, action="item_deleted")  # ids 4-10
    assert audit.prune(db, NOW, max_rows=6) == 4
    assert [r["id"] for r in rows(db)] == [1, 2, 3, 8, 9, 10]
    assert actions(db) == ["user_created"] * 3 + ["item_deleted"] * 3


def test_prune_by_count_reaches_the_cap_exactly(db: Database) -> None:
    add(db, 2, action="grant_set")
    add(db, 20, action="folder_created")
    audit.prune(db, NOW, max_rows=10)
    assert len(rows(db)) == 10


def test_prune_touches_management_events_only_when_no_file_event_is_left(db: Database) -> None:
    add(db, 5, action="share_created")  # ids 1-5
    add(db, 2, action="upload_completed")  # ids 6-7
    assert audit.prune(db, NOW, max_rows=4) == 3
    assert [r["id"] for r in rows(db)] == [2, 3, 4, 5]  # both file events, then the oldest other


def test_prune_by_age_still_deletes_old_management_events(db: Database) -> None:
    add(db, 1, at=NOW - 400 * DAY, action="user_created")
    add(db, 1, at=NOW, action="user_created")
    assert audit.prune(db, NOW) == 1


def test_a_flood_of_file_events_cannot_push_out_management_events(db: Database) -> None:
    add(db, 4, action="user_created")
    add(db, 1000, action="folder_created")
    add(db, 1000, action="item_deleted")
    audit.prune(db, NOW, max_rows=50)
    kept = actions(db)
    assert len(kept) == 50
    assert kept.count("user_created") == 4
    assert kept.count("item_deleted") == 46  # the newest file events survive


def test_a_file_event_trims_the_oldest_file_events_in_its_own_transaction(db: Database) -> None:
    add(db, 3, action="grant_set")
    log = quiet_log(db, 5)
    for _ in range(10):
        log.record_committed("u_a", "folder_created", "share", "s_" + "a" * 16, {"depth": 1})
    assert len(rows(db)) == 5
    assert actions(db) == ["grant_set"] * 3 + ["folder_created"] * 2
    assert [r["id"] for r in rows(db)][-2:] == [12, 13]


def test_a_flood_through_the_write_path_stays_at_the_cap(db: Database) -> None:
    log = quiet_log(db, 50)
    add(db, 2, action="share_created")
    for _ in range(400):
        log.record_committed("u_a", "item_deleted", "share", "s_" + "a" * 16, {"kind": "file"})
    assert len(rows(db)) == 50
    assert actions(db).count("share_created") == 2
    assert rows(db)[-1]["id"] == 402  # the newest event is never the one evicted


def test_one_write_evicts_a_bounded_number_of_rows(db: Database) -> None:
    log = quiet_log(db, 100)
    add(db, 300, action="folder_created")
    log.record_committed("u_a", "folder_created", "share", "s_" + "a" * 16)
    assert len(rows(db)) == 301 - audit.WRITE_TRIM_BATCH


def test_a_management_event_never_evicts_anything_on_write(db: Database) -> None:
    log = quiet_log(db, 5)
    add(db, 10, action="item_deleted")
    log.record_committed("u_a", "grant_set", "grant", "s_" + "a" * 16 + ":u_" + "b" * 16)
    assert len(rows(db)) == 11


def test_the_new_file_event_survives_when_only_management_events_fill_the_table(
    db: Database,
) -> None:
    log = quiet_log(db, 5)
    add(db, 5, action="user_created")
    log.record_committed("u_a", "item_deleted", "share", "s_" + "a" * 16)
    # The cap is only restored by the daily prune.
    assert actions(db) == ["user_created"] * 5 + ["item_deleted"]


def test_a_failed_trim_rolls_the_new_event_back(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    add(db, 6, action="folder_created")

    def boom(*args: object, **kwargs: object) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(audit, "_delete_oldest", boom)
    log = quiet_log(db, 5)
    with pytest.raises(sqlite3.OperationalError):
        log.record_committed("u_a", "item_deleted", "share", "s_" + "a" * 16)
    assert len(rows(db)) == 6
    assert "item_deleted" not in actions(db)
