"""Behaviour of the browser upload queue (static/js/transfers.js), run under Node.

The pytest suite cannot execute JavaScript, so tests/js/transfers_scenarios.mjs runs the real
api.js and transfers.js against an in-memory fake of the upload API and prints the outcome of each
scenario. Each scenario below pins a bug that was found in review (see the comments in the .mjs).
The tests skip when Node (22 or newer) is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCENARIOS = Path(__file__).resolve().parent / "js" / "transfers_scenarios.mjs"


def _node() -> str | None:
    node = shutil.which("node")
    if node is None:
        return None
    out = subprocess.run([node, "--version"], capture_output=True, text=True, check=False)
    try:
        major = int(out.stdout.strip().lstrip("v").split(".")[0])
    except ValueError:
        return None
    return node if major >= 22 else None


@pytest.fixture(scope="module")
def outcomes() -> dict[str, dict[str, Any]]:
    node = _node()
    if node is None:
        pytest.skip("Node 22 or newer is needed to run the browser-side scenarios")
    run = subprocess.run(
        [node, str(SCENARIOS)], capture_output=True, text=True, timeout=60, check=False
    )
    assert run.returncode == 0, run.stderr
    return {item["name"]: item for item in json.loads(run.stdout)}


def test_a_normal_upload_finishes(outcomes: dict[str, dict[str, Any]]) -> None:
    r = outcomes["normal"]
    assert (r["state"], r["patches"], r["metas"]) == ("done", 3, 0)


def test_a_lost_reply_to_the_last_chunk_is_confirmed_not_reported_as_not_found(
    outcomes: dict[str, dict[str, Any]],
) -> None:
    r = outcomes["lost-final-reply"]
    assert r["state"] == "done", r
    assert r["metas"] == 1  # it asked the server whether the file is in place


def test_a_second_chunk_in_flight_is_retried(outcomes: dict[str, dict[str, Any]]) -> None:
    """The server answers 409 upload_busy (not 423 busy) for a chunk that overlaps another."""
    r = outcomes["upload-busy"]
    assert r["state"] == "done", r
    assert r["patches"] == 4


def test_a_full_disk_is_not_retried(outcomes: dict[str, dict[str, Any]]) -> None:
    r = outcomes["disk-full"]
    assert (r["state"], r["tag"], r["patches"]) == ("error", "NO SPACE", 1)


def test_all_bytes_sent_is_not_done_unless_the_file_is_in_place(
    outcomes: dict[str, dict[str, Any]],
) -> None:
    r = outcomes["staged-not-finished"]
    assert r["state"] == "error", r
    assert r["metas"] == 1


def test_an_endless_offset_mismatch_gives_up(outcomes: dict[str, dict[str, Any]]) -> None:
    r = outcomes["mismatch-loop"]
    assert r["state"] == "error"
    assert r["patches"] <= 10


def test_cancel_during_create_drops_the_staged_upload(
    outcomes: dict[str, dict[str, Any]],
) -> None:
    r = outcomes["cancel-during-create"]
    assert (r["state"], r["deletes"], r["patches"]) == ("cancelled", 1, 0)


def test_a_download_too_big_for_a_browser_is_refused_before_any_request(
    outcomes: dict[str, dict[str, Any]],
) -> None:
    r = outcomes["download-too-large"]
    assert (r["state"], r["tag"], r["requests"]) == ("error", "TOO LARGE", 0)
