"""Argon2id password hashing and the password policy."""

from __future__ import annotations

import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
# Each Argon2 run allocates 64 MiB. Cap concurrent runs process-wide so a burst of logins
# (the thread pool has ~40 workers) queues instead of exhausting RAM.
MAX_CONCURRENT_HASHES = 2
_HASH_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_HASHES)
MIN_DISTINCT_CHARACTERS = 5
# Passwords of 12+ characters that are in every attacker's first-guess list.
_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "12345678901234",
        "123456123456",
        "qwertyuiopas",
        "qwertyuiop12",
        "qwertyqwerty",
        "password1234",
        "password12345",
        "passwordpassword",
        "iloveyou1234",
        "administrator",
        "letmein12345",
        "welcome12345",
        "changeme1234",
        "abcdefghijkl",
    }
)


class PasswordPolicyError(ValueError):
    """The password is not acceptable. The message is safe to show to the user."""


def validate_new_password(password: str, *, username: str | None = None) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    if not password.strip():
        raise PasswordPolicyError("password must not be only whitespace")
    if username is not None and password.casefold() == username.casefold():
        raise PasswordPolicyError("password must not equal the username")
    if len(set(password)) < MIN_DISTINCT_CHARACTERS or password.casefold() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("password is too easy to guess")


class PasswordService:
    """Wraps argon2-cffi. Parameters are embedded in each stored hash, so raising them later
    only needs `needs_rehash` (checked at login)."""

    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        # Library defaults are the RFC 9106 low-memory profile (Argon2id, t=3, m=64 MiB, p=4).
        self._hasher = hasher or PasswordHasher()
        # Verified against when the account does not exist, so that an unknown user costs the
        # same time as a wrong password.
        self._dummy_hash = self._hasher.hash("yournas-dummy-password-for-timing")

    def hash(self, password: str) -> str:
        with _HASH_SLOTS:
            return self._hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            with _HASH_SLOTS:
                return self._hasher.verify(stored_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password: str) -> None:
        self.verify(self._dummy_hash, password)

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return False
