"""Persistent login throttling with exponential backoff.

Every attempt is charged *before* the password is checked, so parallel guesses cannot slip past
the limit while a slow hash verification is running. A correct login clears the account counter
and refunds the address counter by one; a locked key rejects the attempt without charging it, so
hammering a locked account does not extend the lock.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable

from yournas.core.database import Database

ACCOUNT_FREE_FAILURES = 5
ADDRESS_FREE_FAILURES = 20
FIRST_LOCK_SECONDS = 15
MAX_LOCK_SECONDS = 15 * 60
# A key that saw no failure for this long starts again from zero.
DECAY_SECONDS = 24 * 3600
_PURGE_EVERY_SECONDS = 60
MAX_THROTTLE_ROWS = 10_000


class Throttled(Exception):  # noqa: N818 - reads better at the call site
    def __init__(self, retry_after: int) -> None:
        super().__init__(f"throttled for {retry_after}s")
        self.retry_after = retry_after


def lock_seconds(failures: int, free_failures: int) -> int:
    """Lock length after `failures` charged attempts. 0 while still within the free allowance."""
    over = failures - free_failures
    if over < 0:
        return 0
    return min(MAX_LOCK_SECONDS, FIRST_LOCK_SECONDS << min(over, 10))


class LoginThrottle:
    def __init__(self, db: Database, clock: Callable[[], float] = time.time) -> None:
        self._db = db
        self._clock = clock
        self._last_purge = 0.0

    def _now(self) -> int:
        return int(self._clock())

    def begin(self, account_key: str, address_key: str | None) -> None:
        """Charge one attempt to each key, or raise Throttled if any key is locked."""
        keys = [(account_key, ACCOUNT_FREE_FAILURES)]
        if address_key is not None:
            keys.append((address_key, ADDRESS_FREE_FAILURES))
        now = self._now()
        with self._db.transaction() as conn:
            self._purge(conn, now)
            state: dict[str, int] = {}
            retry_after = 0
            for key, _free in keys:
                row = conn.execute(
                    "SELECT failures, locked_until, updated_at FROM login_throttle WHERE key = ?",
                    (key,),
                ).fetchone()
                failures = 0
                if row is not None and row["updated_at"] >= now - DECAY_SECONDS:
                    failures = int(row["failures"])
                    # Clamped: a clock that jumped ahead and back must not lock for longer
                    # than the maximum.
                    remaining = min(int(row["locked_until"]) - now, MAX_LOCK_SECONDS)
                    retry_after = max(retry_after, remaining)
                state[key] = failures
            if retry_after > 0:
                raise Throttled(retry_after)  # rolls the transaction back: nothing is charged
            for key, free in keys:
                failures = state[key] + 1
                wait = lock_seconds(failures, free)
                conn.execute(
                    "INSERT INTO login_throttle (key, failures, locked_until, updated_at) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET "
                    "failures = excluded.failures, locked_until = excluded.locked_until, "
                    "updated_at = excluded.updated_at",
                    (key, failures, now + wait if wait else 0, now),
                )

    def succeed(self, account_key: str, address_key: str | None) -> None:
        now = self._now()
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM login_throttle WHERE key = ?", (account_key,))
            if address_key is not None:
                conn.execute(
                    "UPDATE login_throttle SET failures = MAX(failures - 1, 0), "
                    "locked_until = CASE WHEN failures - 1 < ? THEN 0 ELSE locked_until END, "
                    "updated_at = ? WHERE key = ?",
                    (ADDRESS_FREE_FAILURES, now, address_key),
                )

    def _purge(self, conn: sqlite3.Connection, now: int) -> None:
        if now - self._last_purge < _PURGE_EVERY_SECONDS:
            return
        self._last_purge = float(now)
        conn.execute("DELETE FROM login_throttle WHERE updated_at < ?", (now - DECAY_SECONDS,))
        # Usernames are attacker-chosen, so the table needs a hard cap. Rows that are not locked
        # go first (oldest first), so a flood of fake names cannot unlock a locked account.
        count = int(conn.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0])
        if count > MAX_THROTTLE_ROWS:
            conn.execute(
                "DELETE FROM login_throttle WHERE key IN "
                "(SELECT key FROM login_throttle ORDER BY (locked_until > ?) ASC, updated_at ASC "
                "LIMIT ?)",
                (now, count - MAX_THROTTLE_ROWS),
            )
