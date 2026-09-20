"""Integration test for the encrypted disk cache, using the real platform encryption."""

from __future__ import annotations

import sys
from pathlib import Path

import msal
import pytest

from azure_auth.auth.cache import build_cache

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is only available on Windows"),
]

_ACCESS_TOKEN = "access-token-that-must-not-appear-on-disk"


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
