"""Integration tests for the encrypted disk cache, using the real platform encryption."""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import msal
import pytest
from msal_extensions.persistence import PersistenceDecryptionError

from azure_auth import CacheFileEmpty
from azure_auth.auth.cache import build_cache
from tests import cache_aging

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is only available on Windows"),
]

_ACCESS_TOKEN = "access-token-that-must-not-appear-on-disk"
_REFRESH_TOKEN = "refresh-token-that-must-survive-ageing"
_CREDENTIAL = msal.TokenCache.CredentialType


@pytest.fixture
def restart(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    """Forget the disk caches this process has open, as a restart would.

    Args:
        monkeypatch: Restores the real list of open caches afterwards.

    Returns:
        A function that forgets them; the next ``build_cache`` reads the file afresh.
    """
    return lambda: monkeypatch.setattr("azure_auth.auth.cache._disk_caches", {})


def _event(token: str, scope: str = "https://graph.microsoft.com/.default") -> dict[str, object]:
    """Build the event an MSAL cache records after a token response.

    Args:
        token: The access token.
        scope: The token's scope; a scope of its own keeps a token from replacing another.

    Returns:
        An ``add()`` payload.
    """
    return {
        "client_id": "app",
        "scope": [scope],
        "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "response": {"access_token": token, "expires_in": 3600, "token_type": "Bearer"},
    }


def _tokens(path: Path) -> list[str]:
    """Read the access tokens the file holds, as a new process would.

    Args:
        path: The cache file.

    Returns:
        Every stored access token.
    """
    found = build_cache("disk", path).search(_CREDENTIAL.ACCESS_TOKEN, query={"client_id": "app"})
    return sorted(entry["secret"] for entry in found)


def test_tokens_survive_a_restart_and_are_not_stored_in_clear_text(
    tmp_path: Path, restart: Callable[[], None]
) -> None:
    path = tmp_path / "nested" / "cache.bin"
    first = build_cache("disk", path)
    first.add(_event(_ACCESS_TOKEN))
    first.flush()

    restart()

    assert _tokens(path) == [_ACCESS_TOKEN]
    assert _ACCESS_TOKEN.encode("ascii") not in path.read_bytes()
    # The file is built beside the cache file and renamed over it; nothing is left beside it.
    assert sorted(p.name for p in path.parent.iterdir() if p.suffix != ".lockfile") == ["cache.bin"]


def test_an_aged_access_token_is_dropped_and_its_refresh_token_kept(
    tmp_path: Path, restart: Callable[[], None]
) -> None:
    # The live refresh test ages the cache instead of waiting an hour. That shortcut only
    # proves anything if an aged entry behaves like an expired one: gone for MSAL's lookup,
    # seen by another process opening the file, with the refresh token still there to redeem.
    path = tmp_path / "cache.bin"
    cache = build_cache("disk", path)
    cache.add(
        {
            "client_id": "app",
            "scope": ["https://graph.microsoft.com/User.Read"],
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "response": {
                "access_token": _ACCESS_TOKEN,
                "refresh_token": _REFRESH_TOKEN,
                "expires_in": 3600,
                "token_type": "Bearer",
            },
        }
    )
    query = {"client_id": "app"}
    assert list(cache.search(_CREDENTIAL.ACCESS_TOKEN, query=query))

    assert cache_aging.expire_access_tokens(cache) == 1

    restart()
    later_process = build_cache("disk", path)
    access = later_process.search(_CREDENTIAL.ACCESS_TOKEN, query=query)
    refresh = later_process.search(_CREDENTIAL.REFRESH_TOKEN, query=query)
    assert list(access) == []
    assert [entry["secret"] for entry in refresh] == [_REFRESH_TOKEN]
    # MSAL's lookup deletes the expired entry for good; nothing is left to age a second time.
    assert cache_aging.expire_access_tokens(later_process) == 0


def test_threads_sharing_the_file_keep_every_token(
    tmp_path: Path, restart: Callable[[], None]
) -> None:
    # Many threads writing at once, as a GDAP run with several jobs does, through the real
    # encryption and file lock: none may fail, and none may drop another's token.
    path = tmp_path / "cache.bin"
    threads, writes = 8, 3
    start = threading.Barrier(threads)

    def write(number: int) -> None:
        cache = build_cache("disk", path)
        start.wait()
        for turn in range(writes):
            cache.add(_event(f"token-{number}-{turn}", scope=f"Scope{number}x{turn}.Read"))
            cache.flush()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for future in [pool.submit(write, number) for number in range(threads)]:
            future.result()

    restart()
    assert len(set(_tokens(path))) == threads * writes


def test_two_processes_flushing_keep_each_others_tokens(
    tmp_path: Path, restart: Callable[[], None]
) -> None:
    # Two runs on one file, each with its own copy in memory: a flush rereads what the other
    # wrote before writing, under the real file lock, so neither drops the other's tokens.
    path = tmp_path / "cache.bin"
    first = build_cache("disk", path)
    first.add(_event("first-1", scope="First1.Read"))
    first.flush()
    restart()
    second = build_cache("disk", path)
    second.add(_event("second", scope="Second.Read"))
    second.flush()
    first.add(_event("first-2", scope="First2.Read"))
    first.flush()

    restart()
    assert _tokens(path) == ["first-1", "first-2", "second"]


def test_a_write_that_fails_midway_leaves_the_old_file_whole(
    tmp_path: Path, restart: Callable[[], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    # msal-extensions emptied the file before filling it, so a process killed in between left
    # 0 bytes, which no later process can decrypt. The new file is built beside the old one:
    # a write that dies before the rename leaves the old file as it was.
    path = tmp_path / "cache.bin"
    cache = build_cache("disk", path)
    cache.add(_event("kept"))
    cache.flush()

    def die(source: str, target: str) -> None:
        raise OSError("killed before the rename")

    monkeypatch.setattr(os, "replace", die)
    cache.add(_event("lost", scope="Lost.Read"))
    with pytest.raises(OSError, match="killed"):
        cache.flush()
    monkeypatch.undo()

    restart()
    assert _tokens(path) == ["kept"]

    # The change stayed pending; the next flush writes it, over the half-finished file too.
    cache.flush()
    restart()
    assert _tokens(path) == ["kept", "lost"]
    assert not path.with_name(path.name + ".tmp").exists()


@pytest.mark.regression
def test_an_empty_cache_file_names_itself_in_the_error(tmp_path: Path) -> None:
    # Seen 2026-10-22: a GDAP run's 5 MB cache left at 0 bytes, which DPAPI refuses with
    # nothing but "WinError 87" (ERROR_INVALID_PARAMETER, for a blob of no length).
    path = tmp_path / "cache.bin"
    path.write_bytes(b"")
    cache = build_cache("disk", path)

    with pytest.raises(CacheFileEmpty) as info:
        cache.search(_CREDENTIAL.ACCESS_TOKEN, query={"client_id": "app"})

    assert str(path) in str(info.value)
    cause = info.value.__cause__
    assert isinstance(cause, PersistenceDecryptionError)
    assert cause.errno == 87
