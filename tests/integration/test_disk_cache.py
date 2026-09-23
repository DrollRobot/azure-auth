"""Integration test for the encrypted disk cache, using the real platform encryption."""

from __future__ import annotations

import sys
from pathlib import Path

import msal
import pytest

from azure_auth.auth.cache import build_cache
from tests import cache_aging

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is only available on Windows"),
]

_ACCESS_TOKEN = "access-token-that-must-not-appear-on-disk"
_REFRESH_TOKEN = "refresh-token-that-must-survive-ageing"


def test_tokens_survive_a_restart_and_are_not_stored_in_clear_text(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "cache.bin"
    first = build_cache("disk", path)
    first.add(
        {
            "client_id": "app",
            "scope": ["https://graph.microsoft.com/.default"],
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "response": {
                "access_token": _ACCESS_TOKEN,
                "expires_in": 3600,
                "token_type": "Bearer",
            },
        }
    )

    second = build_cache("disk", path)
    found = list(
        second.search(msal.TokenCache.CredentialType.ACCESS_TOKEN, query={"client_id": "app"})
    )

    assert [entry["secret"] for entry in found] == [_ACCESS_TOKEN]
    assert _ACCESS_TOKEN.encode("ascii") not in path.read_bytes()


def test_an_aged_access_token_is_dropped_and_its_refresh_token_kept(tmp_path: Path) -> None:
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
    assert list(cache.search(msal.TokenCache.CredentialType.ACCESS_TOKEN, query=query))

    assert cache_aging.expire_access_tokens(cache) == 1

    later_process = build_cache("disk", path)
    access = later_process.search(msal.TokenCache.CredentialType.ACCESS_TOKEN, query=query)
    refresh = later_process.search(msal.TokenCache.CredentialType.REFRESH_TOKEN, query=query)
    assert list(access) == []
    assert [entry["secret"] for entry in refresh] == [_REFRESH_TOKEN]
    # MSAL's lookup deletes the expired entry for good; nothing is left to age a second time.
    assert cache_aging.expire_access_tokens(later_process) == 0
