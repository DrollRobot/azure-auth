"""Forced browser sign-ins, one per first-party client id."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from azure_auth import AuthContext, AzureClient, ExchangeClient, GraphClient
from azure_auth.clients import ResourceClient
from tests.live.support import (
    LIVE_GRAPH_SCOPES,
    TENANT,
    USERNAME,
    _flag,
    cached_user_auth,
    needs_user,
    walkthrough_if_waiting,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
@pytest.mark.interactive
async def test_interactive_login_then_graph_me(cache_path: Path) -> None:
    """A forced browser sign-in to the Graph client id works and signs in the right user.

    The sign-in is forced, so the interactive flow runs even when the cache could have
    answered: the point is to test it, not to get a token. It asks for every scope the live
    Graph tests use, so its consent screen covers them all and they find their tokens in the
    cache afterwards. When the consent test ran first, this is also what consents to the
    grants its fixture revoked.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with GraphClient(auth, scopes=LIVE_GRAPH_SCOPES) as graph:
        with walkthrough_if_waiting(
            f"Sign-in prompt for {USERNAME}, asking for {', '.join(LIVE_GRAPH_SCOPES)}. Sign"
            " in, and accept the consent screen if one appears.",
            f"The browser may still be signed in as the non-administrator from the consent"
            f" test. If it offers that account, choose 'Use another account' and sign in as"
            f" {USERNAME}; signing in as the wrong one fails this test.",
        ):
            await graph.login(force=True)
        me = await graph.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()


# The Exchange Online PowerShell client id serves both the Exchange and the IPPS tests.
_needs_exchange_or_ipps = pytest.mark.skipif(
    "1" not in (os.environ.get("AZURE_AUTH_TEST_EXCHANGE"), os.environ.get("AZURE_AUTH_TEST_IPPS")),
    reason="set AZURE_AUTH_TEST_EXCHANGE=1 or AZURE_AUTH_TEST_IPPS=1",
)


@needs_user
@pytest.mark.interactive
@pytest.mark.parametrize(
    ("make_client", "application"),
    [
        pytest.param(
            ExchangeClient,
            "Exchange Online PowerShell",
            marks=_needs_exchange_or_ipps,
            id="exchange",
        ),
        pytest.param(AzureClient, "Azure PowerShell", marks=_flag("AZURE_AUTH_TEST_ARM"), id="arm"),
    ],
)
async def test_interactive_login_to_another_first_party_client(
    make_client: Callable[[AuthContext], ResourceClient], application: str, cache_path: Path
) -> None:
    """A forced browser sign-in works for each first-party client id besides Graph's.

    Each resource client defaults to its own Microsoft application, and a refresh token for
    one cannot be spent on another, so each needs its own interactive sign-in. This does that
    sign-in, and then checks what the live tests rely on: a context that may not prompt finds
    the token in the cache.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with make_client(auth) as client:
        with walkthrough_if_waiting(
            f"Sign-in prompt for {USERNAME} against the {application} client id, a different"
            " application from the Graph one. Sign in and accept.",
        ):
            await client.login(force=True)

    cached = cached_user_auth(cache_path)
    token = await cached.aio.acquire_token(client.scopes, client_id=client.client_id)
    assert token.token
