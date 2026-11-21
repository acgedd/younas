"""Users, login, sessions and password changes. All time comes from an injectable clock."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from yournas.audit import AuditLog
from yournas.auth.passwords import PasswordPolicyError, PasswordService, validate_new_password
from yournas.auth.throttle import LoginThrottle, Throttled
from yournas.core.database import Database
from yournas.core.errors import AppError

log = logging.getLogger("yournas.auth")

Role = Literal["owner", "user"]

USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,31}")
MAX_LOGIN_USERNAME_LENGTH = 64
MAX_SESSIONS_PER_USER = 10
# last_seen_at is refreshed at most this often, so a busy client does not write on every request.
_TOUCH_INTERVAL_SECONDS = 60
_REVOKED_KEEP_SECONDS = 24 * 3600
_TOKEN_MAX_LENGTH = 128
# Names an administrator cannot hand out: they would pass for the owner or the system itself.
RESERVED_USERNAMES = frozenset({"owner", "admin", "system", "root"})
_TEMP_PASSWORD_BYTES = 12
# A temporary password (an account with must_change_password = 1) works for this long after it was
# issued. `password_changed_at` is the issue time: create_user and reset_password set it to "now"
# together with the flag, and change_password clears the flag. Dead from this age on, like a
# session at its expires_at. A permanent password never expires.
TEMP_PASSWORD_LIFETIME_SECONDS = 7 * 24 * 3600


def temporary_password_expired(must_change: object, changed_at: int, now: int) -> bool:
    return bool(must_change) and now - changed_at >= TEMP_PASSWORD_LIFETIME_SECONDS


def _temporary_password_expired_error() -> AppError:
    return AppError(
        401,
        "temporary_password_expired",
        "This temporary password has expired. Ask the owner for a new one.",
    )


class UsernameError(ValueError):
    """The username is not acceptable. The message is safe to show."""


@dataclass(frozen=True)
class User:
    id: str
    username: str
    role: Role


@dataclass(frozen=True)
class AuthContext:
    user: User
    token_hash: str
    # True while the account still has an administrator-issued temporary password.
    must_change: bool


@dataclass(frozen=True)
class LoginResult:
    token: str
    expires_at: int
    user: User
    must_change_password: bool


@dataclass(frozen=True)
class UserRecord:
    """One row of the administrator's user list. Never carries a hash or a token."""

    id: str
    username: str
    role: Role
    disabled: bool
    created_at: int
    must_change_password: bool


class OwnerProtectedError(AppError):
    """The owner account cannot be disabled or have its password reset by an administrator."""

    def __init__(self) -> None:
        super().__init__(400, "cannot_modify_owner", "The owner account cannot be modified")


def normalize_username(raw: str) -> str:
    """Canonical stored form. Raises UsernameError if it is not an acceptable new username."""
    name = raw.casefold()
    if not USERNAME_PATTERN.fullmatch(name):
        raise UsernameError(
            "username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit"
        )
    return name


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def session_not_revoked(conn: sqlite3.Connection, token_hash: str) -> bool:
    """Inside a caller's transaction: the session still exists and was not revoked (logout,
    sign out everywhere, a password change or reset, an owner's revoke) since it authenticated
    the request. For a write whose body arrives long after `authenticate` ran."""
    row = conn.execute(
        "SELECT revoked_at FROM sessions WHERE token_hash = ?", (token_hash,)
    ).fetchone()
    return row is not None and row["revoked_at"] is None


def _user_not_found() -> AppError:
    return AppError(404)


def generate_temporary_password(username: str) -> str:
    """A random one-time password that satisfies the password policy (regenerated until it does)."""
    while True:
        candidate = secrets.token_urlsafe(_TEMP_PASSWORD_BYTES)
        try:
            validate_new_password(candidate, username=username)
        except PasswordPolicyError:
            continue
        return candidate


def _username_taken() -> AppError:
    return AppError(409, "username_taken", "That username is not available")


def _invalid_credentials() -> AppError:
    return AppError(401, "invalid_credentials", "Invalid username or password")


def _throttled_error(retry_after: int) -> AppError:
    return AppError(
        429,
        "too_many_attempts",
        "Too many failed attempts. Try again later.",
        {"Retry-After": str(retry_after)},
    )


class AuthService:
    def __init__(
        self,
        db: Database,
        passwords: PasswordService,
        *,
        idle_seconds: int,
        lifetime_seconds: int,
        clock: Callable[[], float] = time.time,
        throttle: LoginThrottle | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._db = db
        self._passwords = passwords
        self._idle = idle_seconds
        self._lifetime = lifetime_seconds
        self._clock = clock
        self._throttle = throttle or LoginThrottle(db, clock)
        self._audit = audit or AuditLog(db, clock)

    def _now(self) -> int:
        return int(self._clock())

    # ---- users -------------------------------------------------------------------------

    def owner_exists(self) -> bool:
        with self._db.read() as conn:
            return conn.execute("SELECT 1 FROM users WHERE role = 'owner'").fetchone() is not None

    def create_owner(self, username: str, password: str) -> User:
        """Create the one owner account. Called only from the local CLI."""
        name = normalize_username(username)
        validate_new_password(password, username=name)
        password_hash = self._passwords.hash(password)  # slow: outside the DB lock
        now = self._now()
        user_id = "u_" + secrets.token_hex(8)
        try:
            with self._db.transaction() as conn:
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, role, disabled, "
                    "created_at, password_changed_at) VALUES (?, ?, ?, 'owner', 0, ?, ?)",
                    (user_id, name, password_hash, now, now),
                )
        except sqlite3.IntegrityError:
            raise UsernameError("an owner already exists or the username is taken") from None
        log.info("owner_created", extra={"user_id": user_id})
        return User(user_id, name, "owner")

    # ---- login -------------------------------------------------------------------------

    def login(self, username: str, password: str, client_ip: str | None) -> LoginResult:
        name = username.casefold()[:MAX_LOGIN_USERNAME_LENGTH]
        account_key = "acct:" + name
        address_key = "ip:" + client_ip if client_ip else None

        try:
            self._throttle.begin(account_key, address_key)
        except Throttled as exc:
            log.warning("login_throttled", extra={"client_ip": client_ip})
            raise _throttled_error(exc.retry_after) from None

        with self._db.read() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, role, disabled, must_change_password, "
                "password_changed_at FROM users WHERE username = ?",
                (name,),
            ).fetchone()

        if row is None:
            self._passwords.verify_dummy(password)
            log.warning("login_failed", extra={"client_ip": client_ip, "user_known": False})
            raise _invalid_credentials()

        verified = self._passwords.verify(row["password_hash"], password)
        if not verified or row["disabled"]:
            # A disabled account is verified first so it is indistinguishable from a wrong password.
            log.warning(
                "login_failed",
                extra={"client_ip": client_ip, "user_known": True, "user_id": row["id"]},
            )
            raise _invalid_credentials()

        if temporary_password_expired(
            row["must_change_password"], int(row["password_changed_at"]), self._now()
        ):
            # Only said after the password was verified, so this reveals nothing to a guesser.
            # No session, no rehash, and the attempt stays charged to the throttle.
            log.warning(
                "login_failed",
                extra={"client_ip": client_ip, "user_id": row["id"], "temporary_expired": True},
            )
            raise _temporary_password_expired_error()

        verified_hash = row["password_hash"]
        if self._passwords.needs_rehash(verified_hash):
            new_hash = self._passwords.hash(password)  # slow: outside the DB lock
            with self._db.transaction() as conn:
                # Only if the hash is still the one just verified: a password change made in
                # between must not be overwritten with the old password.
                rehashed = conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
                    (new_hash, row["id"], verified_hash),
                ).rowcount
            if rehashed == 1:
                verified_hash = new_hash

        user = User(row["id"], row["username"], row["role"])
        token, expires_at = self._create_session(user.id, verified_hash)
        self._throttle.succeed(account_key, address_key)
        log.info("login_success", extra={"user_id": user.id, "client_ip": client_ip})
        return LoginResult(token, expires_at, user, bool(row["must_change_password"]))

    def _create_session(self, user_id: str, verified_hash: str) -> tuple[str, int]:
        """Start a session, but only if the account is still enabled and its password is still
        the one that was verified. The check and the insert share one transaction, so a disable,
        reset or password change that ran while the (slow) verification was going cannot be
        outlived by a session from the login that started before it."""
        token = secrets.token_urlsafe(32)  # 256 bits
        now = self._now()
        expires_at = now + self._lifetime
        with self._db.transaction() as conn:
            still_valid = conn.execute(
                "SELECT 1 FROM users WHERE id = ? AND disabled = 0 AND password_hash = ?",
                (user_id, verified_hash),
            ).fetchone()
            if still_valid is None:
                log.warning(
                    "login_failed",
                    extra={"user_known": True, "user_id": user_id, "changed_during_login": True},
                )
                raise _invalid_credentials()
            conn.execute(
                "DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ? "
                "OR (revoked_at IS NOT NULL AND revoked_at < ?)",
                (now, now - self._idle, now - _REVOKED_KEEP_SECONDS),
            )
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (hash_token(token), user_id, now, now, expires_at),
            )
            # Keep the newest MAX_SESSIONS_PER_USER live sessions; drop the older ones.
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN ("
                "SELECT token_hash FROM sessions WHERE user_id = ? AND revoked_at IS NULL "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?)",
                (user_id, user_id, MAX_SESSIONS_PER_USER),
            )
        return token, expires_at

    # ---- sessions ----------------------------------------------------------------------

    def authenticate(self, token: str) -> AuthContext | None:
        """The context for a valid live session, else None. Never raises for a bad token."""
        if not token or len(token) > _TOKEN_MAX_LENGTH or not token.isascii():
            return None
        token_hash = hash_token(token)
        now = self._now()
        with self._db.read() as conn:
            row = conn.execute(
                "SELECT s.last_seen_at, s.expires_at, s.revoked_at, "
                "u.id, u.username, u.role, u.disabled, u.must_change_password, "
                "u.password_changed_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
        if (
            row is None
            or row["revoked_at"] is not None
            or row["disabled"]
            # A pending session opened with a temporary password dies with that password.
            or temporary_password_expired(
                row["must_change_password"], int(row["password_changed_at"]), now
            )
            or now >= row["expires_at"]
            or now - row["last_seen_at"] > self._idle
        ):
            return None
        if now - row["last_seen_at"] >= _TOUCH_INTERVAL_SECONDS:
            with self._db.transaction() as conn:
                conn.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (now, token_hash)
                )
        return AuthContext(
            User(row["id"], row["username"], row["role"]),
            token_hash,
            bool(row["must_change_password"]),
        )

    def logout(self, ctx: AuthContext) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (self._now(), ctx.token_hash),
            )
        log.info("logout", extra={"user_id": ctx.user.id})

    # ---- password change ---------------------------------------------------------------

    def change_password(self, ctx: AuthContext, current: str, new: str) -> None:
        # The current password is checked under the same throttle as login: a stolen session
        # token must not become a free password-guessing oracle.
        account_key = "acct:" + ctx.user.username
        try:
            self._throttle.begin(account_key, None)
        except Throttled as exc:
            raise _throttled_error(exc.retry_after) from None

        with self._db.read() as conn:
            row = conn.execute(
                "SELECT password_hash, must_change_password, password_changed_at "
                "FROM users WHERE id = ?",
                (ctx.user.id,),
            ).fetchone()
        if row is None or not self._passwords.verify(row["password_hash"], current):
            log.warning("password_change_failed", extra={"user_id": ctx.user.id})
            raise AppError(403, "invalid_current_password", "Current password is incorrect")
        if temporary_password_expired(
            row["must_change_password"], int(row["password_changed_at"]), self._now()
        ):
            # The temporary password expired after this session was opened (authenticate has
            # not seen it yet, or the clock moved between the two checks).
            log.warning("password_change_failed", extra={"user_id": ctx.user.id, "expired": True})
            raise _temporary_password_expired_error()

        if new == current:
            raise AppError(400, "password_unchanged", "The new password must be different")
        try:
            validate_new_password(new, username=ctx.user.username)
        except PasswordPolicyError as exc:
            raise AppError(400, "weak_password", str(exc)) from None
        self._throttle.succeed(account_key, None)

        new_hash = self._passwords.hash(new)
        now = self._now()
        with self._db.transaction() as conn:
            # Only if the hash is still the one just verified (no concurrent change).
            changed = conn.execute(
                "UPDATE users SET password_hash = ?, password_changed_at = ?, "
                "must_change_password = 0 WHERE id = ? AND password_hash = ?",
                (new_hash, now, ctx.user.id, row["password_hash"]),
            ).rowcount
            if changed != 1:
                raise AppError(409, "conflict", "Password was changed concurrently; try again")
            conn.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL "
                "AND token_hash != ?",
                (now, ctx.user.id, ctx.token_hash),
            )
            self._audit.record(conn, ctx.user.id, "password_changed", "user", ctx.user.id)
        log.info("password_changed", extra={"user_id": ctx.user.id})
        self._audit.maybe_prune()

    # ---- account administration (owner only; the routes enforce that) ------------------

    def list_users(self) -> list[UserRecord]:
        with self._db.read() as conn:
            rows = conn.execute(
                "SELECT id, username, role, disabled, created_at, must_change_password "
                "FROM users ORDER BY created_at, rowid"
            ).fetchall()
        return [
            UserRecord(
                r["id"],
                r["username"],
                r["role"],
                bool(r["disabled"]),
                int(r["created_at"]),
                bool(r["must_change_password"]),
            )
            for r in rows
        ]

    def create_user(self, actor_id: str, username: str) -> tuple[User, str]:
        """A new account with role "user" and a one-time temporary password, which must be
        changed at first login. The password is returned once and is never stored or logged."""
        try:
            name = normalize_username(username)
        except UsernameError as exc:
            raise AppError(400, "invalid_username", str(exc)) from None
        if name in RESERVED_USERNAMES:
            raise _username_taken()
        temp_password = generate_temporary_password(name)
        password_hash = self._passwords.hash(temp_password)  # slow: outside the DB lock
        now = self._now()
        user_id = "u_" + secrets.token_hex(8)
        try:
            with self._db.transaction() as conn:
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, role, disabled, "
                    "created_at, password_changed_at, must_change_password) "
                    "VALUES (?, ?, ?, 'user', 0, ?, ?, 1)",
                    (user_id, name, password_hash, now, now),
                )
                self._audit.record(conn, actor_id, "user_created", "user", user_id)
        except sqlite3.IntegrityError:
            raise _username_taken() from None
        log.info("user_created", extra={"user_id": user_id, "actor_id": actor_id})
        self._audit.maybe_prune()
        return User(user_id, name, "user"), temp_password

    def set_disabled(self, actor_id: str, user_id: str, disabled: bool) -> None:
        """Disable or enable an account. Disabling also revokes all its sessions in the same
        transaction; enabling does not bring them back."""
        with self._db.transaction() as conn:
            self._require_non_owner(conn, user_id)
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            revoked = self._revoke_all(conn, user_id) if disabled else 0
            self._audit.record(
                conn,
                actor_id,
                "user_disabled" if disabled else "user_enabled",
                "user",
                user_id,
                {"count": revoked} if disabled else None,
            )
        log.info(
            "user_disabled" if disabled else "user_enabled",
            extra={"user_id": user_id, "actor_id": actor_id},
        )
        self._audit.maybe_prune()

    def reset_password(self, actor_id: str, user_id: str) -> str:
        """Give the account a new temporary password (returned once), force a change at next
        login, end all its sessions and clear its login lockout."""
        with self._db.read() as conn:
            username = self._require_non_owner(conn, user_id)
        temp_password = generate_temporary_password(username)
        password_hash = self._passwords.hash(temp_password)  # slow: outside the DB lock
        now = self._now()
        with self._db.transaction() as conn:
            username = self._require_non_owner(conn, user_id)  # re-checked under the lock
            conn.execute(
                "UPDATE users SET password_hash = ?, password_changed_at = ?, "
                "must_change_password = 1 WHERE id = ?",
                (password_hash, now, user_id),
            )
            revoked = self._revoke_all(conn, user_id)
            conn.execute("DELETE FROM login_throttle WHERE key = ?", ("acct:" + username,))
            self._audit.record(
                conn, actor_id, "password_reset", "user", user_id, {"count": revoked}
            )
        log.info("password_reset", extra={"user_id": user_id, "actor_id": actor_id})
        self._audit.maybe_prune()
        return temp_password

    def revoke_sessions(self, actor_id: str, user_id: str) -> int:
        """End every live session of the account. Returns how many were ended."""
        with self._db.transaction() as conn:
            exists = conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone()
            if exists is None:
                raise _user_not_found()
            count = self._revoke_all(conn, user_id)
            self._audit.record(
                conn, actor_id, "sessions_revoked", "user", user_id, {"count": count}
            )
        log.info("sessions_revoked", extra={"user_id": user_id, "actor_id": actor_id})
        self._audit.maybe_prune()
        return count

    def _require_non_owner(self, conn: sqlite3.Connection, user_id: str) -> str:
        """The username of an existing non-owner account (404, or OwnerProtectedError)."""
        row = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise _user_not_found()
        if row["role"] == "owner":
            raise OwnerProtectedError()
        return str(row["username"])

    def _revoke_all(self, conn: sqlite3.Connection, user_id: str) -> int:
        return conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (self._now(), user_id),
        ).rowcount
