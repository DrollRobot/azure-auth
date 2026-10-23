"""Unit tests for token cache construction and the disk cache's writing.

The disk cache's real behaviour -- surviving a restart, and never holding a token in clear
text -- is proved against the platform's own encryption in
``tests/integration/test_disk_cache.py``. What is checked here, on plain files standing in for
the encrypted one: that a memory cache really is process-local and touches no file, that an
unknown kind is refused, that a disk cache which cannot be encrypted raises rather than
quietly falling back to something weaker, that changes wait in memory until a flush and no
process's tokens are lost to another's, that an empty cache file is reported as such, and
that the process's exit writes what is left.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import msal
import msal_extensions
import pytest
from msal_extensions.persistence import PersistenceDecryptionError

from azure_auth import CacheEncryptionUnavailable, CacheFileEmpty
from azure_auth.auth.cache import (
    DiskTokenCache,
    _flush_open_caches,
    _replace,
    build_cache,
    default_cache_path,
)

pytestmark = pytest.mark.unit

_TOKEN = "token-that-must-stay-in-memory"
_ACCESS_TOKEN = msal.TokenCache.CredentialType.ACCESS_TOKEN


@pytest.fixture(autouse=True)
def _no_open_disk_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start each test as a new process would, with no disk cache open yet.

    Args:
        monkeypatch: Restores the real list of open caches afterwards.
    """
    monkeypatch.setattr("azure_auth.auth.cache._disk_caches", {})


def _entry(
    token: str = _TOKEN, scope: str = "https://graph.microsoft.com/.default"
) -> dict[str, Any]:
    """Build the event an MSAL cache records after a token response.

    Args:
        token: Access token to store.
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


def _tokens(cache: Any) -> list[str]:
    """Return the access tokens a cache holds.

    Args:
        cache: The cache to read.

    Returns:
        Every stored access token.
    """
    found = cache.search(_ACCESS_TOKEN, query={"client_id": "app"})
    return [entry["secret"] for entry in found]


# ---------------------------------------------------------------------------- memory cache


def test_memory_cache_keeps_what_it_is_given() -> None:
    cache = build_cache("memory")
    cache.add(_entry())

    assert _tokens(cache) == [_TOKEN]


def test_memory_caches_are_independent_of_each_other() -> None:
    # Two contexts asking for a memory cache must not see each other's tokens; a shared
    # default would leak one tenant's tokens into another's context.
    first = build_cache("memory")
    second = build_cache("memory")
    first.add(_entry())

    assert _tokens(first) == [_TOKEN]
    assert _tokens(second) == []


def test_memory_cache_writes_nothing_to_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A memory cache must not quietly persist. Point the default cache location at an empty
    # directory and confirm nothing appears in it.
    monkeypatch.setattr(
        "azure_auth.auth.cache.default_cache_path", lambda: tmp_path / "msal_token_cache.bin"
    )
    cache = build_cache("memory")
    cache.add(_entry())

    assert list(tmp_path.iterdir()) == []


def test_memory_cache_dies_with_the_object() -> None:
    build_cache("memory").add(_entry())

    assert _tokens(build_cache("memory")) == []


# ---------------------------------------------------------------------------- choosing a kind


def test_an_unknown_kind_is_refused() -> None:
    with pytest.raises(ValueError, match="must be 'memory' or 'disk'"):
        build_cache("sqlite")  # type: ignore[arg-type]


def test_the_default_disk_path_is_a_file_in_a_per_user_directory() -> None:
    path = default_cache_path()

    assert path.name == "msal_token_cache.bin"
    # Where platformdirs puts it differs per platform -- Windows adds a "Cache" directory
    # below the application's own -- so only the application directory is worth asserting.
    assert "azure-auth" in path.parts
    assert path.is_absolute()


# ------------------------------------------------------------------- refusing a weak disk cache


def test_a_disk_cache_that_cannot_be_encrypted_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # msal-extensions raises when it cannot encrypt. Falling back to a plaintext file would
    # put refresh tokens on disk in the clear, so this must fail instead.
    def explode(location: str) -> Any:
        raise OSError("no keyring here")

    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", explode)

    with pytest.raises(CacheEncryptionUnavailable, match="Cannot create an encrypted token cache"):
        build_cache("disk", tmp_path / "cache.bin")


def test_a_persistence_that_reports_itself_unencrypted_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Some platforms hand back a persistence object that works but is not encrypted. Trusting
    # the call to have raised is not enough; the result has to be checked as well.
    class PlaintextPersistence:
        is_encrypted = False

    monkeypatch.setattr(
        "msal_extensions.build_encrypted_persistence", lambda location: PlaintextPersistence()
    )

    with pytest.raises(CacheEncryptionUnavailable, match="is not encrypted"):
        build_cache("disk", tmp_path / "cache.bin")


def test_a_disk_cache_creates_the_directory_it_needs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Persistence:
        is_encrypted = True

    monkeypatch.setattr(
        "msal_extensions.build_encrypted_persistence", lambda location: Persistence()
    )
    monkeypatch.setattr(
        "azure_auth.auth.cache.DiskTokenCache", lambda persistence: msal.TokenCache()
    )

    build_cache("disk", tmp_path / "deeply" / "nested" / "cache.bin")

    assert (tmp_path / "deeply" / "nested").is_dir()


# ---------------------------------------------------------------------- sharing a disk cache


# msal-extensions ships no types, so mypy sees its class as Any.
class _PlainPersistence(msal_extensions.FilePersistence):  # type: ignore[misc]
    """A plain file standing in for the encrypted one; the cache treats both the same."""

    is_encrypted = True


class _UndecryptablePersistence(_PlainPersistence):
    """A file whose content cannot be decrypted, reported as DPAPI reports it."""

    def load(self) -> str:
        """Fail as msal-extensions does for a file DPAPI refuses.

        Raises:
            PersistenceDecryptionError: Always.
        """
        raise PersistenceDecryptionError(
            err_no=87, message="Decryption failed: [WinError 87]", location=self.get_location()
        )


@pytest.fixture
def plain_disk(monkeypatch: pytest.MonkeyPatch) -> Callable[[Path], Any]:
    """Make disk caches plain files.

    Args:
        monkeypatch: Restores msal-extensions afterwards.

    Returns:
        A function opening the cache on a file as another process would: a cache object of
        its own, which has to read the file to see anything.
    """
    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", _PlainPersistence)
    return lambda path: DiskTokenCache(_PlainPersistence(str(path)))


def test_contexts_naming_one_file_share_one_disk_cache(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    # Each context holding its own copy of the file is what let one context's save drop
    # another's tokens.
    path = tmp_path / "cache.bin"

    first = build_cache("disk", path)

    assert build_cache("disk", str(path)) is first
    assert build_cache("disk", tmp_path / "elsewhere" / ".." / "cache.bin") is first
    assert build_cache("disk", tmp_path / "other.bin") is not first


@pytest.mark.regression
def test_threads_writing_one_disk_cache_keep_every_token(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    # Measured 2026-10-19 in a GDAP run of 274 tenants, several at a time: threads waiting on
    # the file lock failed with LockError after five seconds, and a direct sign-in's tokens
    # vanished from the file. Each thread here opens the cache as its own context would.
    path = tmp_path / "cache.bin"
    threads = 8
    start = threading.Barrier(threads)

    def write(number: int) -> None:
        cache = build_cache("disk", path)
        start.wait()
        cache.add(_entry(f"token-{number}", scope=f"Scope{number}.Read"))

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for future in [pool.submit(write, number) for number in range(threads)]:
            future.result()
    build_cache("disk", path).flush()

    assert sorted(_tokens(plain_disk(path))) == sorted(f"token-{n}" for n in range(threads))


# ---------------------------------------------------------------------- writing the file


def test_changes_wait_in_memory_until_the_cache_is_flushed(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    path = tmp_path / "cache.bin"
    cache = build_cache("disk", path)
    cache.add(_entry())

    assert _tokens(cache) == [_TOKEN]
    assert not path.exists()

    cache.flush()

    assert _tokens(plain_disk(path)) == [_TOKEN]


def test_a_flush_with_nothing_to_write_writes_nothing(
    tmp_path: Path, plain_disk: Callable[[Path], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every write encrypts and writes the whole file, so a flush that has nothing new, as a
    # tenant whose tokens were all cached leaves behind, must not write it again.
    saves: list[str] = []
    save = _PlainPersistence.save

    def counting(self: _PlainPersistence, content: str) -> None:
        saves.append(content)
        save(self, content)

    monkeypatch.setattr(_PlainPersistence, "save", counting)
    cache = build_cache("disk", tmp_path / "cache.bin")
    cache.add(_entry())

    cache.flush()
    cache.flush()
    build_cache("disk", tmp_path / "cache.bin").flush()

    assert len(saves) == 1


def test_a_flush_keeps_what_another_process_wrote_meanwhile(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    # Two runs sharing the file: this one holds a token unwritten while the other writes its
    # own. This one's flush has to write both, not just its own copy over the other's.
    path = tmp_path / "cache.bin"
    mine = build_cache("disk", path)
    mine.add(_entry("mine"))
    other = plain_disk(path)
    other.add(_entry("theirs", scope="Other.Read"))
    other.flush()

    mine.flush()

    assert sorted(_tokens(plain_disk(path))) == ["mine", "theirs"]


def test_a_search_sees_another_process_write_and_keeps_its_own_unwritten_tokens(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    path = tmp_path / "cache.bin"
    mine = build_cache("disk", path)
    mine.add(_entry("mine"))
    other = plain_disk(path)
    other.add(_entry("theirs", scope="Other.Read"))
    other.flush()

    assert sorted(_tokens(mine)) == ["mine", "theirs"]


def test_a_deletion_survives_rereading_the_file(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    # MSAL deletes expired tokens as it searches. One deleted here but not yet written would
    # come back with the file, were the file's copy not corrected by the unwritten changes.
    path = tmp_path / "cache.bin"
    mine = build_cache("disk", path)
    mine.add(_entry("expired"))
    mine.flush()
    other = plain_disk(path)
    other.add(_entry("theirs", scope="Other.Read"))
    other.flush()
    expired = next(e for e in mine.search(_ACCESS_TOKEN) if e["secret"] == "expired")
    mine.remove_at(expired)

    assert _tokens(mine) == ["theirs"]

    mine.flush()

    assert _tokens(plain_disk(path)) == ["theirs"]


# ------------------------------------------------------------------ a file that cannot be read


@pytest.mark.regression
def test_an_empty_cache_file_is_reported_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seen 2026-10-22: a GDAP run's 5 MB cache left at 0 bytes by a run killed while writing
    # it. DPAPI refuses an empty file with nothing but "WinError 87", so every later run died
    # with a traceback that named no cause. The error has to name the file and say what to do,
    # with msal-extensions' own error chained behind it.
    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", _UndecryptablePersistence)
    path = tmp_path / "cache.bin"
    path.write_bytes(b"")
    cache = build_cache("disk", path)

    with pytest.raises(CacheFileEmpty, match=r"is empty \(0 bytes\)") as info:
        _tokens(cache)

    assert info.value.path == str(path)
    assert str(path) in str(info.value)
    assert "Delete the file" in str(info.value)
    assert isinstance(info.value.__cause__, PersistenceDecryptionError)


def test_a_file_that_cannot_be_decrypted_for_another_reason_raises_as_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file with content DPAPI refuses, such as one encrypted under another Windows account,
    # is not empty, and nothing more precise than msal-extensions' error can be said of it.
    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", _UndecryptablePersistence)
    path = tmp_path / "cache.bin"
    path.write_bytes(b"not something DPAPI wrote")
    cache = build_cache("disk", path)

    with pytest.raises(PersistenceDecryptionError):
        _tokens(cache)


# ------------------------------------------------------------------------- at the process's exit


def test_the_exit_hook_writes_every_open_cache(
    tmp_path: Path, plain_disk: Callable[[Path], Any]
) -> None:
    build_cache("disk", tmp_path / "one.bin").add(_entry("one"))
    build_cache("disk", tmp_path / "two.bin").add(_entry("two"))

    _flush_open_caches()

    assert _tokens(plain_disk(tmp_path / "one.bin")) == ["one"]
    assert _tokens(plain_disk(tmp_path / "two.bin")) == ["two"]


def test_a_cache_that_cannot_be_written_at_exit_is_logged_not_raised(
    tmp_path: Path,
    plain_disk: Callable[[Path], Any],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def refuse(self: _PlainPersistence, content: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(_PlainPersistence, "save", refuse)
    path = tmp_path / "cache.bin"
    build_cache("disk", path).add(_entry())

    with caplog.at_level(logging.WARNING, logger="azure_auth.auth.cache"):
        _flush_open_caches()

    assert "disk full" in caplog.text
    assert str(path) in caplog.text


# ------------------------------------------------------------------- replacing the file whole


def test_replacing_the_file_waits_out_a_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Windows a process reading the cache denies the rename for the milliseconds its read
    # takes (PermissionError, WinError 5). The rename has to try again, not fail the flush.
    source, target = tmp_path / "new", tmp_path / "old"
    source.write_text("new")
    target.write_text("old")
    denials = [PermissionError("in use"), PermissionError("in use")]
    replace = os.replace

    def busy_then_free(src: str, dst: str) -> None:
        if denials:
            raise denials.pop()
        replace(src, dst)

    monkeypatch.setattr(os, "replace", busy_then_free)
    monkeypatch.setattr("azure_auth.auth.cache._REPLACE_WAIT", 0)

    _replace(str(source), str(target))

    assert target.read_text() == "new"
    assert not source.exists()


def test_a_reader_that_never_lets_go_fails_the_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def always_busy(src: str, dst: str) -> None:
        raise PermissionError("in use")

    monkeypatch.setattr(os, "replace", always_busy)
    monkeypatch.setattr("azure_auth.auth.cache._REPLACE_WAIT", 0)

    with pytest.raises(PermissionError, match="in use"):
        _replace(str(tmp_path / "new"), str(tmp_path / "old"))
