"""Sign-in through the Windows authentication broker (WAM).

The broker holds the refresh token, not MSAL: a broker sign-in leaves MSAL's cache with the
account and an access token, and no refresh token. So a token renewed from a cache with no
refresh token in it can only have come from the broker, which is how these tests tell a
broker sign-in from a browser one. They keep a disk cache of their own for that reason; in the
shared one, a browser sign-in's refresh token could answer instead.

A broker sign-in on a computer that is not joined to the tenant ends by offering to keep the
account signed in to every application. Accepting registers the computer with the
organization, so the walkthrough says to decline; the tests need only this application.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import msal
import pytest

from azure_auth import AuthContext, AuthError, AzureClient, BrokerUnavailable, ExchangeClient
from azure_auth.auth.cache import build_cache
from azure_auth.clients import ResourceClient
from tests.live.support import (
    TENANT,
    USERNAME,
    _flag,
    needs_exchange_or_ipps,
    needs_user,
    require_cached_sign_in,
    sign_in_step,
    token_claims,
    token_user,
    walkthrough,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.live,
    pytest.mark.anyio,
    pytest.mark.skipif(sys.platform != "win32", reason="the broker is Windows only"),
    pytest.mark.skipif(
        importlib.util.find_spec("pymsalruntime") is None, reason="install the broker extra"
    ),
]

# The first-party applications with the broker's redirect URI registered, one per resource.
BROKER_CLIENTS = [
    pytest.param(
        ExchangeClient, "Exchange Online PowerShell", marks=needs_exchange_or_ipps, id="exchange"
    ),
    pytest.param(AzureClient, "Azure PowerShell", marks=_flag("AZURE_AUTH_TEST_ARM"), id="arm"),
]


@pytest.fixture(scope="module")
def broker_cache_path(cache_path: Path) -> Path:
    """The broker tests' own disk cache, beside the one the browser sign-ins fill.

    Only broker sign-ins write to it, so it never holds a refresh token (module docstring).
    """
    return cache_path.with_name("live_tests_broker_token_cache.bin")


def broker_auth(cache_path: Path) -> AuthContext:
    """Return a user-flow context that signs in through the broker or not at all.

    Args:
        cache_path: The broker tests' disk cache.

    Returns:
        The context. With the fallback off, a broker that cannot be used raises
        :class:`BrokerUnavailable` instead of opening the browser.
    """
    return AuthContext(
        TENANT,
        username=USERNAME,
        broker=True,
        broker_fallback=False,
        cache="disk",
        cache_path=cache_path,
    )


def cache_entries(cache_path: Path, kind: str) -> list[dict[str, Any]]:
    """Read the configured user's entries of one kind out of a disk cache.

    Args:
        cache_path: The disk cache.
        kind: An ``msal.TokenCache.CredentialType``.

    Returns:
        The entries belonging to the configured user.
    """
    cache = build_cache("disk", cache_path)
    accounts = [
        account
        for account in cache.search(msal.TokenCache.CredentialType.ACCOUNT)
        if str(account.get("username", "")).lower() == USERNAME.lower()
    ]
    if kind == msal.TokenCache.CredentialType.ACCOUNT:
        return accounts
    homes = {account["home_account_id"] for account in accounts}
    return [entry for entry in cache.search(kind) if entry.get("home_account_id") in homes]


def assert_the_broker_holds_the_sign_in(cache_path: Path) -> None:
    """Check that the cached sign-in is the broker's, and the refresh token with it.

    Args:
        cache_path: The broker tests' disk cache.
    """
    accounts = cache_entries(cache_path, msal.TokenCache.CredentialType.ACCOUNT)
    assert [account.get("account_source") for account in accounts] == ["broker"]
    refresh_tokens = cache_entries(cache_path, msal.TokenCache.CredentialType.REFRESH_TOKEN)
    assert not refresh_tokens, "MSAL holds a refresh token, so the browser signed in"


@needs_user
@pytest.mark.interactive
@pytest.mark.parametrize(("make_client", "application"), BROKER_CLIENTS)
async def test_a_broker_sign_in_is_the_brokers(
    make_client: Callable[[AuthContext], ResourceClient],
    application: str,
    broker_cache_path: Path,
) -> None:
    """A forced sign-in through the broker signs in the configured user; the broker keeps it.

    Forced, the broker shows its account picker even for an account it holds, so somebody
    always has to pick.
    """
    walkthrough(sign_in_step("WAM"))
    auth = broker_auth(broker_cache_path)
    async with make_client(auth) as client:
        await client.login(force=True)
        token = await auth.aio.acquire_token(client.scopes, client_id=client.client_id)

    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource
    assert_the_broker_holds_the_sign_in(broker_cache_path)


@needs_user
@pytest.mark.parametrize(("make_client", "application"), BROKER_CLIENTS)
async def test_the_broker_renews_a_token_without_prompting(
    make_client: Callable[[AuthContext], ResourceClient],
    application: str,
    broker_cache_path: Path,
) -> None:
    """A context that may not prompt gets a new token from the broker's sign-in.

    ``force_refresh`` skips the cached access token, and MSAL has no refresh token of its own,
    so the token can only come from the broker.
    """
    auth = broker_auth(broker_cache_path)
    auth._interactive_allowed = False
    async with make_client(auth) as client:
        require_cached_sign_in(client)
        token = await auth.aio.acquire_token(
            client.scopes, client_id=client.client_id, force_refresh=True
        )

    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource
    assert_the_broker_holds_the_sign_in(broker_cache_path)


# How long the cancel test lets a browser wait, should one open after all. Nobody answers it.
FALLBACK_TIMEOUT_SECONDS = 5


@needs_user
@pytest.mark.interactive
async def test_a_cancelled_broker_sign_in_opens_no_browser() -> None:
    """Cancelling the broker's window is the person's answer, not a broken broker.

    The fallback is on, so a broker failure would open the browser; a cancel must not. The
    sign-in is forced, so the broker shows its account picker even for an account it holds.
    """
    walkthrough("Close the WAM window with the X in its title bar.")
    auth = AuthContext(
        TENANT, username=USERNAME, broker=True, interactive_timeout=FALLBACK_TIMEOUT_SECONDS
    )
    async with AzureClient(auth) as client:
        with pytest.raises(AuthError) as caught:
            await client.login(force=True)

    print(f"a cancelled broker sign-in: {caught.value}")
    assert not isinstance(caught.value, BrokerUnavailable)
    assert "Status_UserCanceled" in str(caught.value)
    assert (client.client_id, False) not in auth._apps, "the browser was set up after a cancel"
