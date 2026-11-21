from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from yournas.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    PasswordService,
    validate_new_password,
)

CHEAP = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def test_hash_is_argon2id_and_verifies() -> None:
    svc = PasswordService(CHEAP)
    stored = svc.hash("correct horse battery")
    assert stored.startswith("$argon2id$")
    assert "correct horse battery" not in stored
    assert svc.verify(stored, "correct horse battery")
    assert not svc.verify(stored, "correct horse batterY")


def test_same_password_gets_different_salts() -> None:
    svc = PasswordService(CHEAP)
    assert svc.hash("correct horse battery") != svc.hash("correct horse battery")


@pytest.mark.parametrize("garbage", ["", "plaintext", "$argon2id$broken", "$2b$12$notargon"])
def test_garbage_stored_hash_never_verifies_and_never_raises(garbage: str) -> None:
    assert PasswordService(CHEAP).verify(garbage, "anything at all") is False


def test_needs_rehash_when_parameters_change() -> None:
    old = PasswordService(CHEAP).hash("correct horse battery")
    stronger = PasswordService(PasswordHasher(time_cost=2, memory_cost=8, parallelism=1))
    assert stronger.needs_rehash(old)
    assert not PasswordService(CHEAP).needs_rehash(old)
    assert stronger.needs_rehash("not a hash") is False


def test_default_parameters_are_argon2id_with_real_cost() -> None:
    stored = PasswordService().hash("correct horse battery")
    assert stored.startswith("$argon2id$")
    assert "m=65536" in stored  # 64 MiB


def test_policy_accepts_reasonable_passwords() -> None:
    validate_new_password(("abcde" * MIN_PASSWORD_LENGTH)[:MIN_PASSWORD_LENGTH])
    validate_new_password("pässwörd with ünicode 密碼密碼")
    validate_new_password(("vwxyz" * MAX_PASSWORD_LENGTH)[:MAX_PASSWORD_LENGTH])


@pytest.mark.parametrize(
    "password",
    ["", "short", "a" * (MIN_PASSWORD_LENGTH - 1), " " * 20, "x" * (MAX_PASSWORD_LENGTH + 1)],
    ids=["empty", "short", "just-under-min", "whitespace", "over-max"],
)
def test_policy_rejects_bad_passwords(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        validate_new_password(password)


def test_policy_rejects_password_equal_to_username() -> None:
    with pytest.raises(PasswordPolicyError):
        validate_new_password("Alice.Example.1", username="alice.example.1")
