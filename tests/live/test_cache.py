"""The disk cache across runs: silent reuse, and a refresh once the access token has expired."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from azure.core.credentials import AccessTokenInfo

from azure_auth import AuthContext, GraphClient, InteractionRequired
from azure_auth.auth.cache import build_cache
from tests import cache_aging
from tests.live.support import _flag, cached_user_auth, needs_user, require_cached_sign_in

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# What the refresh tests sign in for. Anything every user may consent to would do.
REFRESH_SCOPES = ["User.Read"]

# The slow refresh test refuses to wait longer than this. Entra issues access tokens for a
# randomised 60 to 90 minutes, so anything longer means the token is not what was expected.
LONG_REFRESH_LIMIT_SECONDS = 2 * 60 * 60


async def assert_refreshed_without_prompting(
    auth: AuthContext, graph: GraphClient, expired: AccessTokenInfo, user_id: str
) -> None:
    """Call Graph once more and check a new token arrived with nobody asked to sign in.

    Both refresh tests end here, so the fast one (an aged cache) and the slow one (a real
    hour) are held to the same outcome, which is what lets the slow one vouch for the fast.

    Args:
        auth: The context behind ``graph``. Prompting is switched off on it.
        graph: A client whose last token has expired.
        expired: The token it last sent.
        user_id: Object id ``/me`` returned before the token expired.
    """
    # Prompting being off is what proves the new token came from the refresh token. With it
    # on, a broken refresh would open a browser, somebody would sign in, and the test would
    # pass. Live contexts already have it off; it is set again so this check never depends
    # on how the caller built its context.
    auth._interactive_allowed = False
    try:
        me = await graph.get("/me", params={"$select": "id"})
    except InteractionRequired as error:
        pytest.fail(f"refreshing the expired token needed a sign-in: {error}")
    renewed = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

    assert me["id"] == user_id
    assert renewed.token != expired.token, "the expired token was used again; nothing refreshed"
    assert renewed.expires_on > time.time(), "the refreshed token has already expired"


@needs_user
async def test_disk_cache_makes_the_second_run_silent(cache_path: Path) -> None:
    # A second context on the same cache file stands in for a second script run. It cannot
    # prompt, which proves the token really came from the cache.
    second_run = cached_user_auth(cache_path)
    async with GraphClient(second_run, scopes=["User.Read"]) as graph:
        require_cached_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
    assert me["id"]


@needs_user
async def test_an_expired_access_token_is_refreshed_without_prompting(cache_path: Path) -> None:
    """A later run whose cached access token has expired gets a new one from the refresh token.

    Nothing had run longer than about 90 seconds against a live tenant, so the refresh path
    had never executed -- and it is exactly what a script run twice an hour apart depends on.
    Rather than wait for the token to expire, this ages it in the cache file. The cost is that
    it partly tests the ageing, which is why the ageing has its own integration test and the
    slow test below waits out a real token lifetime to confirm this one.

    A second context stands in for the later run. The first one would not do: its in-process
    memo still holds the token with its real expiry, so it would never look at the cache.
    """
    auth = cached_user_auth(cache_path)
    async with GraphClient(auth, scopes=REFRESH_SCOPES) as graph:
        require_cached_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
        expiring = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

    aged = cache_aging.expire_access_tokens(build_cache("disk", cache_path))
    assert aged, "the disk cache held no access token to expire"

    later_run = cached_user_auth(cache_path)
    async with GraphClient(later_run, scopes=REFRESH_SCOPES) as graph:
        await assert_refreshed_without_prompting(later_run, graph, expiring, str(me["id"]))


@needs_user
@_flag("AZURE_AUTH_TEST_LONG_REFRESH")
@pytest.mark.slow
async def test_a_real_token_lifetime_ends_in_a_silent_refresh(cache_path: Path) -> None:
    """One long-running client outlives its access token and carries on without a prompt.

    This is the truthful version of the ageing test above: nothing is faked, the test simply
    waits until the token has expired. Run it by hand, once, to confirm the ageing models what
    really happens; it is too slow for a routine run.

    It keeps one context and one client for the whole wait, as a long-running process would,
    so it also covers what the fast test cannot: the context's in-process memo declining a
    token within ``_REFRESH_MARGIN_SECONDS`` of expiry, and handing the request to MSAL.
    """
    auth = cached_user_auth(cache_path)
    async with GraphClient(auth, scopes=REFRESH_SCOPES) as graph:
        require_cached_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
        expiring = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

        # A minute past expiry, so a little clock skew cannot land the call just before it.
        wait = expiring.expires_on - time.time() + 60
        assert wait < LONG_REFRESH_LIMIT_SECONDS, f"the token lives {wait / 60:.0f} minutes"
        print(f"  waiting {wait / 60:.0f} minutes for the access token to expire")
        await asyncio.sleep(wait)

        await assert_refreshed_without_prompting(auth, graph, expiring, str(me["id"]))
