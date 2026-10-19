"""Token cache construction.

Two caches exist: an in-memory cache that dies with the process, and an encrypted cache on
disk. There is deliberately no unencrypted disk cache. When the platform cannot encrypt,
asking for a disk cache raises instead of quietly doing something weaker.

Every context in a process that names the same disk cache file gets the same cache object,
and its threads take turns at it (:class:`_ThreadSafePersistedTokenCache`).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Literal

import msal
import msal_extensions
import platformdirs

from azure_auth.auth.errors import CacheEncryptionUnavailable

CacheKind = Literal["memory", "disk"]

_APP_NAME = "azure-auth"
_CACHE_FILE_NAME = "msal_token_cache.bin"

# The disk caches this process has opened, by the file's full path, so every context naming
# a file shares one copy of it in memory.
_disk_caches: dict[str, Any] = {}
_disk_caches_guard = threading.Lock()


# msal-extensions ships no types, so mypy sees its class as Any.
class _ThreadSafePersistedTokenCache(msal_extensions.PersistedTokenCache):  # type: ignore[misc]
    """An encrypted disk cache that the threads of one process take turns at.

    msal-extensions guards the file with a lock built for separate processes: a thread waits
    at most five seconds for it, then fails with ``LockError``, and a read takes no lock at
    all. Threads sharing a large cache file wait longer than that, and a read during another
    thread's write can miss the write, so the next save drops its tokens. Here every read and
    write first takes msal's own lock around the in-memory copy, which waits as long as it
    takes, so the file lock only ever stands between processes. It has to be msal's lock:
    msal holds it while adding a token, which writes, so a second lock taken in the other
    order could deadlock.
    """

    def modify(
        self,
        credential_type: str,
        old_entry: dict[str, Any],
        new_key_value_pairs: dict[str, Any] | None = None,
    ) -> None:
        """Change one entry and write the file, once no other thread is using the cache.

        Args:
            credential_type: The kind of entry, an ``msal.TokenCache.CredentialType``.
            old_entry: The entry to change.
            new_key_value_pairs: The fields to change, or None to delete the entry.
        """
        with self._lock:
            super().modify(credential_type, old_entry, new_key_value_pairs)

    def search(self, credential_type: str, **kwargs: Any) -> Any:
        """Reread the file if it changed, once no other thread is using the cache, then search.

        Args:
            credential_type: The kind of entry, an ``msal.TokenCache.CredentialType``.
            **kwargs: Passed on to ``msal.TokenCache.search``.

        Returns:
            msal's generator of matching entries, which takes the lock again as it runs.
        """
        with self._lock:
            return super().search(credential_type, **kwargs)


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
        disk cache is the same object on every call in this process that names the same file.

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


def _open_disk_cache(path: Path) -> Any:
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
    return _ThreadSafePersistedTokenCache(persistence)
