"""Unit tests for token cache construction.

The disk cache's real behaviour -- surviving a restart, and never holding a token in clear
text -- is proved against the platform's own encryption in
``tests/integration/test_disk_cache.py``. What is checked here is the choosing: that a memory
cache really is process-local and touches no file, that an unknown kind is refused, and that
a disk cache which cannot be encrypted raises rather than quietly falling back to something
weaker.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import msal
import pytest

from azure_auth import CacheEncryptionUnavailable
from azure_auth.auth.cache import build_cache, default_cache_path

pytestmark = pytest.mark.unit

_TOKEN = "token-that-must-stay-in-memory"


def _entry(token: str = _TOKEN) -> dict[str, Any]:
    """Build the event an MSAL cache records after a token response.

    Args:
        token: Access token to store.

    Returns:
        An ``add()`` payload.
    """
    return {
        "client_id": "app",
        "scope": ["https://graph.microsoft.com/.default"],
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
    found = cache.search(msal.TokenCache.CredentialType.ACCESS_TOKEN, query={"client_id": "app"})
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
        "msal_extensions.PersistedTokenCache", lambda persistence: msal.TokenCache()
    )

    build_cache("disk", tmp_path / "deeply" / "nested" / "cache.bin")

    assert (tmp_path / "deeply" / "nested").is_dir()
