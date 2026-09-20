"""Token cache construction.

Two caches exist: an in-memory cache that dies with the process, and an encrypted cache on
disk. There is deliberately no unencrypted disk cache. When the platform cannot encrypt,
asking for a disk cache raises instead of quietly doing something weaker.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import msal
import msal_extensions
import platformdirs

from azure_auth.auth.errors import CacheEncryptionUnavailable

CacheKind = Literal["memory", "disk"]

_APP_NAME = "azure-auth"
_CACHE_FILE_NAME = "msal_token_cache.bin"


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
        An ``msal.TokenCache`` (or subclass) instance.

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
    return msal_extensions.PersistedTokenCache(persistence)
