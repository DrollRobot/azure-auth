"""Forced browser sign-ins, one per first-party client id."""

from __future__ import annotations

import os
import time
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
    token_claims,
    token_user,
    walkthrough,
    walkthrough_if_waiting,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# What the cancel and timeout tests ask for. It must not be granted, so that the
# administrator's sign-in stops at a consent screen, the one page with a Cancel button. Being
# outside BASELINE_SCOPES is enough: every test starts from exactly the baseline, and an
# Accept by mistake is taken back out by restore_baseline after the test.
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
            f"Sign in as {USERNAME}. Other account offered: click 'Use another account'.",
            "Consent screen, if shown: click Accept.",
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
    the token in the cache, and the token is for the configured user and the client's
    resource. There is no ``/me`` on these resources, so the token itself is the witness.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with make_client(auth) as client:
        with walkthrough_if_waiting(
            f"Sign in as {USERNAME} ({application}).",
            "Consent screen, if shown: click Accept.",
        ):
            await client.login(force=True)

    cached = cached_user_auth(cache_path)
    token = await cached.aio.acquire_token(client.scopes, client_id=client.client_id)
    assert token.token
    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource


@needs_user
@pytest.mark.interactive
async def test_a_cancelled_sign_in_is_reported_and_not_retried() -> None:
    """Cancelling the browser sign-in raises an error that says so, and opens nothing else.

    The one page in the sign-in with a Cancel button is Entra's consent screen, so this asks
    for a scope the baseline does not grant (``CANCEL_SCOPE``) to make that screen appear.

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
        f"Sign in as {USERNAME}, if asked.",
        f"Consent screen ({CANCEL_SCOPE}): click CANCEL.",
    )
    auth = AuthContext(TENANT, username=USERNAME)
    async with GraphClient(auth, scopes=[CANCEL_SCOPE]) as graph:
        try:
            await graph.login(force=True)
        except AuthError as error:
            caught = error
        else:
            pytest.fail(
                f"the sign-in succeeded, so nothing was cancelled: the baseline does not grant"
                f" {CANCEL_SCOPE}, so Accept must have been clicked"
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


# How long the timeout test waits. The default is two minutes, which is right for a person
# and wrong for a test; the point here is only that the limit is real.
TIMEOUT_SECONDS = 5


@needs_user
@pytest.mark.interactive
async def test_an_unanswered_sign_in_times_out() -> None:
    """A browser sign-in that nobody completes fails after ``interactive_timeout`` seconds.

    A closed browser window is the case this guards: MSAL would otherwise wait for a redirect
    that never arrives. Nobody needs to close anything here -- leaving the page alone has the
    same effect, and is easier to get right.

    The sign-in asks for ``CANCEL_SCOPE``, which the baseline does not grant, so that it stops
    at a consent screen rather than completing silently from the browser session. Nothing is
    granted, because nobody clicks.
    Marked ``interactive`` because it opens a browser tab on the desktop and leaves it there,
    not because anyone has to act.
    """
    walkthrough(
        f"Consent screen ({CANCEL_SCOPE}): click NOTHING.",
        f"After {TIMEOUT_SECONDS}s: close the tab.",
    )
    auth = AuthContext(TENANT, username=USERNAME, interactive_timeout=TIMEOUT_SECONDS)
    async with GraphClient(auth, scopes=[CANCEL_SCOPE]) as graph:
        started = time.monotonic()
        with pytest.raises(
            AuthError, match=f"not completed within {TIMEOUT_SECONDS} seconds"
        ) as caught:
            await graph.login(force=True)
        elapsed = time.monotonic() - started

    assert not isinstance(caught.value, (ConsentRequired, InteractionRequired))
    # It waited the timeout, and not much more: the limit is real and not a fluke.
    assert TIMEOUT_SECONDS <= elapsed <= TIMEOUT_SECONDS + 30, f"gave up after {elapsed:.0f}s"
