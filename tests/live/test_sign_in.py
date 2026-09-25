"""Forced browser sign-ins, one per first-party client id."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from azure_auth import (
    AuthContext,
    AuthError,
    AzureClient,
    ConsentRequired,
    ExchangeClient,
    GraphClient,
    InteractionRequired,
)
from azure_auth.clients import ResourceClient
from tests.live.support import (
    BASELINE_SCOPES,
    TENANT,
    USERNAME,
    _flag,
    cached_user_auth,
    needs_user,
    walkthrough,
    walkthrough_if_waiting,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# What the cancel test asks for. It must need admin consent and must not be granted in the
# tenant, so that the administrator's sign-in stops at a consent screen, which is the one
# page with a Cancel button. So it must not be in BASELINE_SCOPES (already granted: no
# screen), nor UNGRANTED_SCOPE (an Accept by mistake would break the .default test), nor
# NONADMIN_SCOPE. Admin consent rather than user consent on purpose: an Accept by mistake then
# creates a tenant-wide grant, which the consent test's revoke removes and the baseline does
# not put back, so the mistake heals itself. A per-user grant for the administrator would be
# spared by that revoke for ever.
CANCEL_SCOPE = "Domain.Read.All"


@needs_user
@pytest.mark.interactive
async def test_interactive_login_then_graph_me(cache_path: Path) -> None:
    """A forced browser sign-in to the Graph client id works and signs in the right user.

    The sign-in is forced, so the interactive flow runs even when the cache could have
    answered: the point is to test it, not to get a token. It asks for the baseline scopes,
    the same ones the tenant already holds, so no consent screen is expected; the token it
    leaves in the cache serves the tests that follow.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with GraphClient(auth, scopes=BASELINE_SCOPES) as graph:
        with walkthrough_if_waiting(
            f"Sign-in prompt for {USERNAME}, asking for {', '.join(BASELINE_SCOPES)}. Sign"
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


@needs_user
@pytest.mark.interactive
async def test_a_cancelled_sign_in_is_reported_and_not_retried() -> None:
    """Cancelling the browser sign-in raises an error that says so, and opens nothing else.

    The one page in the sign-in with a Cancel button is Entra's consent screen, so this asks
    for a scope the tenant has not granted (``CANCEL_SCOPE``) to make that screen appear.

    What Entra actually answers, measured 2026-09-25: ``consent_required`` with
    ``AADSTS65004: User declined to consent to access the app``. That is *not* the bare
    ``access_denied`` a non-administrator gets from "Need admin approval" (``test_consent.py``),
    so the two are distinguishable after all. The package reports this one as
    :class:`ConsentRequired`, carrying the scope and the tenant, with Entra's own words in the
    message -- and opens no second browser window.

    Closing the window instead of pressing Cancel is not a cancel: MSAL waits for a redirect
    that never arrives, because the package passes it no ``timeout``.

    The context has its own memory cache, so nothing here touches the cache the other live
    tests share.
    """
    walkthrough(
        f"Sign-in as {USERNAME}. The browser is probably still signed in, so this step may"
        " pass by itself; if it asks, pick or type the admin.",
        f"A consent screen listing {CANCEL_SCOPE}. Click CANCEL. Do NOT click Accept: that"
        f" grants {CANCEL_SCOPE} tenant-wide, and this test fails until the consent test's"
        " revoke, or scripts/revoke_consent.py, removes it again.",
    )
    auth = AuthContext(TENANT, username=USERNAME)
    async with GraphClient(auth, scopes=[CANCEL_SCOPE]) as graph:
        try:
            await graph.login(force=True)
        except AuthError as error:
            caught = error
        else:
            pytest.fail(
                f"the sign-in succeeded, so nothing was cancelled: either Accept was clicked,"
                f" or {CANCEL_SCOPE} is already granted in this tenant. Revoke it and run again."
            )

    message = str(caught)
    assert "Signed in as" not in message, "the browser signed in as somebody else"
    # Entra's own explanation reaches the caller, and the exception says which scopes in
    # which tenant went unconsented, so a caller can decide what to do about it.
    assert isinstance(caught, ConsentRequired), f"expected ConsentRequired, got {message}"
    assert "AADSTS65004" in message
    assert "declined" in message
    # The client resolves scopes to their full form (https://graph.microsoft.com/...), and
    # the exception carries what was actually requested.
    assert caught.scopes == tuple(graph.scopes)
    assert caught.tenant_id == TENANT
    # Not this: it would mean the package took the decline for a missing sign-in.
    assert not isinstance(caught, InteractionRequired)
