"""Forced sign-ins: one per first-party client id, and the ways a sign-in can end without one."""

from __future__ import annotations

import importlib.util
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest

from azure_auth import (
    AuthContext,
    AuthError,
    AzureClient,
    BrokerUnavailable,
    ConsentRequired,
    ExchangeClient,
    GraphClient,
    InteractionRequired,
)
from azure_auth.clients import ResourceClient
from tests.live.support import (
    BASELINE_SCOPES,
    SIGN_IN_TIMEOUT_SECONDS,
    TENANT,
    USERNAME,
    cached_user_auth,
    needs_arm_or_keyvault,
    needs_exchange_sign_in,
    needs_graph,
    needs_user,
    sign_in_step,
    token_claims,
    token_user,
    walkthrough,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# What the cancel test asks for. It must not be granted, so that the administrator's sign-in
# stops at a consent screen, the one page with a Cancel button. Being outside BASELINE_SCOPES
# is enough: every test starts from exactly the baseline, and an Accept by mistake is taken
# back out by restore_baseline after the test.
CANCEL_SCOPE = "Domain.Read.All"


@needs_user
@needs_graph
@pytest.mark.interactive
async def test_interactive_login_then_graph_me(cache_path: Path) -> None:
    """A forced browser sign-in to the Graph client id works and signs in the right user.

    The sign-in is forced, so the account picker comes up even when the cache could have
    answered: the point is to test it, not to get a token. It asks for the baseline scopes,
    the same ones the tenant already holds, so no consent screen is expected; the token it
    leaves in the cache serves the tests that follow.
    """
    walkthrough(sign_in_step("browser"), "Consent screen, if shown: click Accept.")
    auth = AuthContext(
        TENANT,
        username=USERNAME,
        cache="disk",
        cache_path=cache_path,
        interactive_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )
    async with GraphClient(auth, scopes=BASELINE_SCOPES) as graph:
        await graph.login(force=True)
        me = await graph.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()


@needs_user
@pytest.mark.interactive
@pytest.mark.parametrize(
    ("make_client", "application"),
    [
        pytest.param(
            ExchangeClient,
            "Exchange Online PowerShell",
            marks=needs_exchange_sign_in,
            id="exchange",
        ),
        pytest.param(AzureClient, "Azure PowerShell", marks=needs_arm_or_keyvault, id="arm"),
    ],
)
async def test_interactive_login_to_another_first_party_client(
    make_client: Callable[[AuthContext], ResourceClient], application: str, cache_path: Path
) -> None:
    """A forced browser sign-in works for each first-party client id besides Graph's.

    Each resource client defaults to its own Microsoft application, and a refresh token for
    one cannot be spent on another, so each needs its own interactive sign-in. This does that
    sign-in, and then checks that a context that may not prompt finds the token in the cache,
    and that the token is for the configured user and the client's resource. There is no
    ``/me`` on these resources, so the token itself is the witness.
    """
    walkthrough(sign_in_step("browser"), "Consent screen, if shown: click Accept.")
    auth = AuthContext(
        TENANT,
        username=USERNAME,
        cache="disk",
        cache_path=cache_path,
        interactive_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )
    async with make_client(auth) as client:
        await client.login(force=True)

    cached = cached_user_auth(cache_path)
    token = await cached.aio.acquire_token(client.scopes, client_id=client.client_id)
    assert token.token
    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource


# The two ways a person signs in.
SIGN_IN_PATHS = [
    pytest.param(
        True,
        id="broker",
        marks=pytest.mark.skipif(
            sys.platform != "win32" or importlib.util.find_spec("pymsalruntime") is None,
            reason="the broker needs Windows and the broker extra",
        ),
    ),
    pytest.param(False, id="browser"),
]


@needs_user
@pytest.mark.interactive
@pytest.mark.parametrize("broker", SIGN_IN_PATHS)
async def test_signing_in_as_somebody_else_is_refused(broker: bool) -> None:
    """A person who picks another account than the one asked for gets no token.

    The context is set up for a user who does not exist, and the person picks the configured
    user at the account picker: a real account, but not the one asked for. The package must
    refuse it, through the broker and in the browser alike. The check reads the identity
    token the sign-in returns, so a pass also shows that both return one naming the user.

    Azure PowerShell is the application because it exists in every tenant and needs no
    access to anything to sign in.
    """
    nobody = f"nobody-{uuid.uuid4().hex[:8]}@{USERNAME.rsplit('@', 1)[-1]}"
    walkthrough(sign_in_step("WAM" if broker else "browser"))
    auth = AuthContext(
        TENANT,
        username=nobody,
        broker=broker,
        broker_fallback=False,
        interactive_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )
    async with AzureClient(auth) as client:
        with pytest.raises(AuthError) as caught:
            await client.login(force=True)

    message = str(caught.value)
    print(f"signed in as somebody else: {message}")
    assert not isinstance(caught.value, BrokerUnavailable)
    assert f"signed in as '{USERNAME.lower()}'" in message.lower()
    assert nobody in message


@needs_user
@needs_graph
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
    that never arrives, until the timeout.

    The context has its own memory cache, so nothing here touches the cache the other live
    tests share.
    """
    walkthrough(sign_in_step("browser"), "Consent screen: click CANCEL.")
    auth = AuthContext(TENANT, username=USERNAME, interactive_timeout=SIGN_IN_TIMEOUT_SECONDS)
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


# How long the timeout test waits. The point here is only that the limit is real.
TIMEOUT_SECONDS = 5


@needs_user
async def test_an_unanswered_sign_in_times_out() -> None:
    """A browser sign-in that nobody completes fails after ``interactive_timeout`` seconds.

    A page that never returns to the application is the case this guards: a closed window,
    or a Conditional Access block, whose page returns to MSAL's listener with no parameters
    and leaves MSAL waiting (measured 2026-09-29). The sign-in is forced, so it stops at the
    account picker whatever the browser holds, and nobody answers it.

    It leaves a browser tab open, but nobody has to act, so it is not ``interactive``. Azure
    PowerShell is the application because it exists in every tenant and nothing is granted.
    """
    auth = AuthContext(TENANT, username=USERNAME, interactive_timeout=TIMEOUT_SECONDS)
    async with AzureClient(auth) as client:
        started = time.monotonic()
        with pytest.raises(
            AuthError, match=f"not completed within {TIMEOUT_SECONDS} seconds"
        ) as caught:
            await client.login(force=True)
        elapsed = time.monotonic() - started

    assert not isinstance(caught.value, (ConsentRequired, InteractionRequired))
    # It waited the timeout, and not much more: the limit is real and not a fluke.
    assert TIMEOUT_SECONDS <= elapsed <= TIMEOUT_SECONDS + 30, f"gave up after {elapsed:.0f}s"
