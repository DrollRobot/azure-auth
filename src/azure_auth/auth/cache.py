"""Token cache construction.

Two caches exist: an in-memory cache that dies with the process, and an encrypted cache on
disk. There is deliberately no unencrypted disk cache. When the platform cannot encrypt,
asking for a disk cache raises instead of quietly doing something weaker.

Every context in a process that names the same disk cache file gets the same cache object
(:class:`DiskTokenCache`), and its threads take turns at it. It keeps its changes in memory
and writes the file when asked (:meth:`DiskTokenCache.flush`, which
``AuthContext.flush_cache()`` calls) and when the process exits. On Windows, where the file
holds the tokens, each write builds the new file beside the old one and renames it into
place, so a process stopped mid-write leaves the old file whole.
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Literal

import msal
import msal_extensions
import platformdirs
from msal_extensions.persistence import PersistenceDecryptionError

from azure_auth.auth.errors import CacheEncryptionUnavailable, CacheFileEmpty

logger = logging.getLogger(__name__)

CacheKind = Literal["memory", "disk"]

_APP_NAME = "azure-auth"
_CACHE_FILE_NAME = "msal_token_cache.bin"
# msal-extensions' name for the lock file, so anything of its own on the same cache file waits
# on the same lock.
_LOCK_SUFFIX = ".lockfile"
# The new file is built here, beside the cache file, then renamed over it.
_TEMP_SUFFIX = ".tmp"
# On Windows, a process reading the cache file denies the rename for the milliseconds its read
# takes: try for about a second.
_REPLACE_ATTEMPTS = 20
_REPLACE_WAIT = 0.05

# The disk caches this process has opened, by the file's full path, so every context naming
# a file shares one copy of it in memory.
_disk_caches: dict[str, DiskTokenCache] = {}
_disk_caches_guard = threading.Lock()


# msal-extensions ships no types, so mypy sees its class as Any.
class _AtomicDpapiPersistence(msal_extensions.FilePersistenceWithDataProtection):  # type: ignore[misc]
    """msal-extensions' DPAPI-encrypted file, built whole beside the old one and renamed over it.

    msal-extensions empties the cache file and then fills it, so a process stopped between the
    two leaves an empty file that no later process can decrypt (seen 2026-10-22, after a GDAP
    run: a 5 MB cache left at 0 bytes). Here the new content is written to a file beside it
    first. The rename is one step, so the cache file is always a whole one, old or new.
    """

    def save(self, content: str) -> None:
        """Encrypt and write the content to a file beside the cache file, then rename it over.

        Args:
            content: The serialized cache.
        """
        location = self.get_location()
        temp = location + _TEMP_SUFFIX
        msal_extensions.FilePersistenceWithDataProtection(temp).save(content)
        _replace(temp, location)


def _replace(source: str, target: str) -> None:
    """Rename a file over another, waiting out a reader that briefly denies it.

    On Windows, a file another process has open cannot be renamed over, and a process reading
    the cache holds the file open for the milliseconds the read takes.

    Args:
        source: The file to rename.
        target: The file to replace.

    Raises:
        PermissionError: If the target stayed in use for about a second.
    """
    for attempt in range(1, _REPLACE_ATTEMPTS + 1):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS:
                raise
            time.sleep(_REPLACE_WAIT)


# msal ships no types either.
class DiskTokenCache(msal.SerializableTokenCache):  # type: ignore[misc]
    """The encrypted disk cache: changed in memory, written to its file by :meth:`flush`.

    Writing the file means encrypting and writing all of it, and MSAL changes the cache several
    times for every token it gets: the token, the refresh token, the ID token, the account and
    the application's metadata are each a change, and it drops expired tokens as it searches.
    msal-extensions' ``PersistedTokenCache`` writes the file on each change, which in a run
    across hundreds of tenants means thousands of writes of a file several megabytes large.
    This cache applies each change in memory and remembers it; :meth:`flush` writes the file
    once for all of them. ``AuthContext.flush_cache()`` calls it, and so does the process's
    exit, for every cache :func:`build_cache` opened. A process killed outright writes nothing
    more; the tokens it got are gotten again next time, from the sign-in the file holds.

    Other processes may write the file between flushes. Before each search, and before each
    flush, the file is read again if it has changed, and this process's unwritten changes are
    applied on top, so it keeps seeing its own tokens and a flush drops nobody's. A flush holds
    msal-extensions' file lock from that read to its write, so two processes flushing at once
    take turns.

    Threads: every read and write first takes msal's own lock around the in-memory copy, which
    waits as long as it takes, so the file lock only ever stands between processes. It has to
    be msal's lock: msal holds it while adding a token, which calls :meth:`modify`, so a lock
    taken in the other order could deadlock.
    """

    def __init__(self, persistence: Any) -> None:
        """Wrap the encrypted file.

        Args:
            persistence: The msal-extensions persistence object keeping the file.
        """
        super().__init__()
        self._persistence = persistence
        self._lock_location = persistence.get_location() + _LOCK_SUFFIX
        # The file as this object last read or wrote it (:func:`_stamp`), to notice another
        # process's write.
        self._file_stamp: tuple[int, int] | None = None
        # The changes applied in memory and not yet written, in order: modify()'s arguments.
        self._pending: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []

    @property
    def path(self) -> str:
        """The cache file."""
        return str(self._persistence.get_location())

    def modify(
        self,
        credential_type: str,
        old_entry: dict[str, Any],
        new_key_value_pairs: dict[str, Any] | None = None,
    ) -> None:
        """Change one entry in memory, for the next :meth:`flush` to write.

        Args:
            credential_type: The kind of entry, an ``msal.TokenCache.CredentialType``.
            old_entry: The entry to change.
            new_key_value_pairs: The fields to change, or None to delete the entry.
        """
        with self._lock:
            super().modify(credential_type, old_entry, new_key_value_pairs)
            self._pending.append((credential_type, old_entry, new_key_value_pairs))

    def search(self, credential_type: str, **kwargs: Any) -> Any:
        """Reread the file if another process changed it, then search.

        Args:
            credential_type: The kind of entry, an ``msal.TokenCache.CredentialType``.
            **kwargs: Passed on to ``msal.TokenCache.search``.

        Returns:
            msal's generator of matching entries, which takes the lock again as it runs.

        Raises:
            CacheFileEmpty: If the file is there but empty.
        """
        with self._lock:
            self._reload_if_changed()
            return super().search(credential_type, **kwargs)

    def flush(self) -> None:
        """Write the unwritten changes to the file; nothing when there are none.

        Raises:
            CacheFileEmpty: If the file is there but empty.
            OSError: If the file could not be written. The changes stay for the next flush.
        """
        with self._lock:
            if not self._pending:
                return
            with msal_extensions.CrossPlatLock(self._lock_location):
                self._reload_if_changed()
                self._persistence.save(self.serialize())
                self._file_stamp = _stamp(self.path)
            self._pending.clear()

    def _reload_if_changed(self) -> None:
        """Reread the file if it changed since last read or written, keeping unwritten changes.

        Raises:
            CacheFileEmpty: If the file is there but empty, chained from msal-extensions' own
                error, which says only that decryption failed (``WinError 87``).
            PersistenceDecryptionError: msal-extensions' own, for any other file that cannot be
                decrypted, such as one encrypted under another Windows account.
        """
        stamp = _stamp(self.path)
        if stamp is None or stamp == self._file_stamp:
            return  # No file yet, which the first flush creates, or the file as last seen.
        try:
            state = self._persistence.load()
        except PersistenceDecryptionError as exc:
            if stamp[1] == 0:
                raise CacheFileEmpty(
                    f"The token cache file {self.path} is empty (0 bytes), so it cannot be "
                    "decrypted. A process stopped while writing it can leave it so. Delete the "
                    "file and sign in again.",
                    path=self.path,
                ) from exc
            raise
        self.deserialize(state)
        self._file_stamp = stamp
        for change in self._pending:
            super().modify(*change)


def _stamp(path: str) -> tuple[int, int] | None:
    """Describe a file as last written: its modification time and size.

    Two writes within one tick of the file system's clock, about 15 ms on Windows, get the same
    modification time; the size tells them apart when a token was added or dropped.

    Args:
        path: The file.

    Returns:
        The modification time in nanoseconds and the size in bytes, or None for no file.
    """
    try:
        status = os.stat(path)
    except OSError:
        return None
    return (status.st_mtime_ns, status.st_size)


def _flush_open_caches() -> None:
    """Write every open disk cache's unwritten changes, as the process exits.

    A failure is logged, not raised: nothing can retry at exit, and the tokens are gotten again
    next time.
    """
    for cache in list(_disk_caches.values()):
        try:
            cache.flush()
        except Exception as exc:
            logger.warning("Could not write the token cache %s at exit: %s", cache.path, exc)


atexit.register(_flush_open_caches)


def default_cache_path() -> Path:
    """Return the default location of the encrypted disk cache.

    Returns:
        A file path under the per-user cache directory of this platform.
    """
    return Path(platformdirs.user_cache_dir(_APP_NAME, appauthor=False)) / _CACHE_FILE_NAME


def build_cache(kind: CacheKind, cache_path: str | Path | None = None) -> Any:
    """Create the MSAL token cache for an :class:`~azure_auth.AuthContext`.

    Args:
        kind: ``memory`` for a process-local cache, ``disk`` for an encrypted file.
        cache_path: File to use for the disk cache. Defaults to :func:`default_cache_path`.

    Returns:
        An ``msal.TokenCache`` (or subclass) instance. A memory cache is new on every call; a
        disk cache (:class:`DiskTokenCache`) is the same object on every call in this process
        that names the same file.

    Raises:
        CacheEncryptionUnavailable: If ``kind`` is ``disk`` and the platform cannot encrypt
            the file (for example Linux without libsecret).
        ValueError: If ``kind`` is not a known cache kind.
    """
    if kind == "memory":
        return msal.TokenCache()
    if kind != "disk":
        raise ValueError(f"cache must be 'memory' or 'disk', not {kind!r}")

    path = Path(cache_path) if cache_path is not None else default_cache_path()
    key = os.path.normcase(path.resolve())
    with _disk_caches_guard:
        cache = _disk_caches.get(key)
        if cache is None:
            cache = _disk_caches[key] = _open_disk_cache(path)
    return cache


def _open_disk_cache(path: Path) -> DiskTokenCache:
    """Open the encrypted disk cache at a file, creating its directory.

    Args:
        path: The cache file.

    Returns:
        The cache.

    Raises:
        CacheEncryptionUnavailable: If the platform cannot encrypt the file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        persistence = msal_extensions.build_encrypted_persistence(str(path))
    except Exception as exc:
        raise CacheEncryptionUnavailable(
            f"Cannot create an encrypted token cache on this platform: {exc}. "
            "Use cache='memory' instead."
        ) from exc
    if not getattr(persistence, "is_encrypted", False):
        raise CacheEncryptionUnavailable(
            "The token cache persistence on this platform is not encrypted. "
            "Use cache='memory' instead."
        )
    if isinstance(persistence, msal_extensions.FilePersistenceWithDataProtection):
        # Windows: the file holds the tokens, so it is replaced whole. Elsewhere the tokens are
        # in the keychain or libsecret, and the file only carries the time of the last write.
        persistence = _AtomicDpapiPersistence(str(path))
    return DiskTokenCache(persistence)
