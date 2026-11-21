from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from argon2 import PasswordHasher
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv
from fastapi.testclient import TestClient

from yournas.auth.passwords import PasswordService
from yournas.auth.service import AuthService
from yournas.auth.throttle import (
    ACCOUNT_FREE_FAILURES,
    ADDRESS_FREE_FAILURES,
    MAX_LOCK_SECONDS,
    lock_seconds,
)

LOGIN = "/api/v1/auth/login"
OUTSIDE = "203.0.113.5"  # documentation range: stands for a remote client
OTHER_OUTSIDE = "203.0.113.6"


def attempt(client: TestClient, name: str, password: str = "definitely wrong") -> httpx.Response:
    response: httpx.Response = client.post(LOGIN, json={"username": name, "password": password})
    return response


def throttle_keys(env: AuthEnv) -> set[str]:
    with env.db.read() as conn:
        return {row[0] for row in conn.execute("SELECT key FROM login_throttle")}


def test_lock_schedule() -> None:
    free = ACCOUNT_FREE_FAILURES
    assert [lock_seconds(n, free) for n in range(free)] == [0] * free
    assert [lock_seconds(free + i, free) for i in range(7)] == [15, 30, 60, 120, 240, 480, 900]
    assert lock_seconds(10_000, free) == MAX_LOCK_SECONDS == 900


# ---- per account -------------------------------------------------------------------------


def test_account_locks_after_five_failures_then_recovers(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    assert [attempt(client, OWNER_NAME).status_code for _ in range(5)] == [401] * 5
    locked = attempt(client, OWNER_NAME, OWNER_PASSWORD)  # even the right password is refused
    assert locked.status_code == 429
    assert locked.json()["error"]["code"] == "too_many_attempts"
    assert locked.headers["retry-after"] == "15"
    auth_env.clock.advance(14)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 429
    auth_env.clock.advance(1)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200


def test_success_clears_the_account_counter(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for _ in range(4):
        attempt(client, OWNER_NAME)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200
    assert [attempt(client, OWNER_NAME).status_code for _ in range(4)] == [401] * 4


def test_hammering_a_locked_account_does_not_extend_the_lock(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for _ in range(5):
        attempt(client, OWNER_NAME)
    assert [attempt(client, OWNER_NAME).status_code for _ in range(50)] == [429] * 50
    auth_env.clock.advance(15)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200


def test_backoff_doubles_with_each_further_failure(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for _ in range(5):
        attempt(client, OWNER_NAME)
    auth_env.clock.advance(15)
    assert attempt(client, OWNER_NAME).status_code == 401  # sixth failure
    r = attempt(client, OWNER_NAME)
    assert r.status_code == 429 and r.headers["retry-after"] == "30"


def test_unknown_usernames_are_throttled_exactly_like_real_ones(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    real = [attempt(client, OWNER_NAME) for _ in range(6)]
    ghost = [attempt(client, "nobody-here") for _ in range(6)]
    assert [r.status_code for r in real] == [r.status_code for r in ghost] == [401] * 5 + [429]
    assert real[-1].headers["retry-after"] == ghost[-1].headers["retry-after"]


def test_usernames_are_throttled_case_insensitively(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for name in ("OWNER", "Owner", "owner", "oWnEr", "OWNER"):
        attempt(client, name)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 429


def test_lock_survives_a_restart(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for _ in range(5):
        attempt(client, OWNER_NAME)
    restarted = AuthService(
        auth_env.db,
        PasswordService(PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)),
        idle_seconds=3600,
        lifetime_seconds=86400,
        clock=auth_env.clock,
    )
    auth_env.app.state.auth = restarted  # a fresh service object: counters come from SQLite
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 429


def test_old_failures_decay(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for _ in range(4):
        attempt(client, OWNER_NAME)
    auth_env.clock.advance(25 * 3600)
    for _ in range(4):  # 8 in total, but the first 4 are a day old
        assert attempt(client, OWNER_NAME).status_code == 401
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200


def test_stale_rows_are_purged(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for name in ("aaa", "bbb", "ccc"):
        attempt(client, name)
    assert {"acct:aaa", "acct:bbb", "acct:ccc"} <= throttle_keys(auth_env)
    auth_env.clock.advance(25 * 3600)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200
    assert not any(key.startswith("acct:") for key in throttle_keys(auth_env))


def test_parallel_guesses_cannot_outrun_the_limit(auth_env: AuthEnv) -> None:
    """Attempts are charged before the password is checked, so a burst gets exactly 5 tries."""

    def one(_: int) -> int:
        return attempt(auth_env.client(), OWNER_NAME).status_code

    with ThreadPoolExecutor(max_workers=12) as pool:
        codes = list(pool.map(one, range(12)))
    assert codes.count(401) == 5 and codes.count(429) == 7


# ---- per address -------------------------------------------------------------------------


def test_address_locks_across_different_usernames(auth_env: AuthEnv) -> None:
    attacker = auth_env.client(OUTSIDE)
    codes = [attempt(attacker, f"user{i}").status_code for i in range(ADDRESS_FREE_FAILURES)]
    assert codes == [401] * ADDRESS_FREE_FAILURES
    refused = attempt(attacker, "yet-another")
    assert refused.status_code == 429 and refused.headers["retry-after"] == "15"
    # Another address is unaffected, and so is the owner's own account.
    assert attempt(auth_env.client(OTHER_OUTSIDE), OWNER_NAME, OWNER_PASSWORD).status_code == 200


def test_a_good_login_refunds_one_address_failure(auth_env: AuthEnv) -> None:
    client = auth_env.client(OUTSIDE)
    for i in range(ADDRESS_FREE_FAILURES - 1):
        attempt(client, f"user{i}")
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200
    assert attempt(client, "one-more").status_code == 401  # not locked yet
    assert attempt(client, "and-another").status_code == 429


def test_loopback_without_a_trusted_proxy_has_no_address_throttle(auth_env: AuthEnv) -> None:
    client = auth_env.client("127.0.0.1", **{"X-Forwarded-For": "203.0.113.9"})
    codes = {attempt(client, f"user{i}").status_code for i in range(ADDRESS_FREE_FAILURES + 5)}
    assert codes == {401}
    assert not any(key.startswith("ip:") for key in throttle_keys(auth_env))


def test_trusted_proxy_uses_the_last_forwarded_address(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(trust_forwarded_for=True)
    codes = []
    for i in range(ADDRESS_FREE_FAILURES + 1):
        # The client controls the first entries; the proxy appends the real address last.
        client = env.client("127.0.0.1", **{"X-Forwarded-For": f"198.51.100.{i}, 203.0.113.9"})
        codes.append(attempt(client, f"user{i}").status_code)
    assert codes == [401] * ADDRESS_FREE_FAILURES + [429]
    assert "ip:203.0.113.9" in throttle_keys(env)
    assert not any(k.startswith("ip:198.51.100.") for k in throttle_keys(env))


@pytest.mark.parametrize("header", ["", "not-an-ip", "203.0.113.9, garbage", "999.1.1.1"])
def test_trusted_proxy_with_an_unusable_header_gives_no_address(
    make_auth_env: Callable[..., AuthEnv], header: str
) -> None:
    env = make_auth_env(trust_forwarded_for=True)
    client = env.client("127.0.0.1", **{"X-Forwarded-For": header})
    assert attempt(client, "someone").status_code == 401
    assert not any(key.startswith("ip:") for key in throttle_keys(env))


def test_forwarded_header_from_a_remote_peer_is_never_trusted(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(trust_forwarded_for=True)
    status = 0
    for i in range(ADDRESS_FREE_FAILURES + 1):
        client = env.client(OUTSIDE, **{"X-Forwarded-For": f"198.51.100.{i}"})
        status = attempt(client, f"user{i}").status_code
    assert status == 429  # keyed on the real peer, not on the spoofed header
    assert f"ip:{OUTSIDE}" in throttle_keys(env)
    assert not any(k.startswith("ip:198.51.100.") for k in throttle_keys(env))
