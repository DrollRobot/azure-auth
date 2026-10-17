"""Sign-in through the Windows authentication broker (WAM).

The broker holds the refresh token, not MSAL: a broker sign-in leaves MSAL's cache with the
account and an access token, and no refresh token. So a token renewed from a cache with no
refresh token in it can only have come from the broker, which is how these tests tell a
broker sign-in from a browser one. They keep a disk cache of their own for that reason; in the
shared one, a browser sign-in's refresh token could answer instead.

A broker sign-in also leaves the account with Windows. MSAL asks Windows for it by name only
when MSAL's own cache holds it; with that cache empty, MSAL asks without naming an account, and
Windows answers with one of its own choosing.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, NoReturn

import msal
import pytest

from azure_auth import (
    AuthContext,
    AuthError,
    AzureClient,
    BrokerUnavailable,
    ExchangeClient,
    GraphClient,
    IppsClient,
)
from azure_auth.auth.cache import build_cache
from azure_auth.clients import ResourceClient
from azure_auth.clients.keyvault import KeyVaultClient
from tests.live.support import (
    BROKER_CACHE_NAME,
    GDAP_TENANT,
    KEYVAULT_SECRET_NAME,
    KEYVAULT_URL,
    TENANT,
    USERNAME,
    _flag,
    ensure_sign_in,
    ensure_token,
    needs_broker,
    needs_exchange,
    needs_gdap_tenant,
    needs_graph,
    needs_ipps,
    needs_keyvault,
    needs_user,
    sign_in_step,
    sign_in_to_vault,
    token_claims,
    token_user,
    walkthrough,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.live,
    pytest.mark.anyio,
    needs_broker,
    pytest.mark.skipif(sys.platform != "win32", reason="the broker is Windows only"),
    pytest.mark.skipif(
        importlib.util.find_spec("pymsalruntime") is None, reason="install the broker extra"
    ),
]


async def read_graph(client: GraphClient) -> None:
    """Read the signed-in user, proving Graph accepts the broker's token.

    Args:
        client: A Graph client signed in through the broker.
    """
    me = await client.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()


async def read_exchange(client: ExchangeClient) -> None:
    """Read the user's own mailbox, proving Exchange accepts the broker's token.

    The user's own mailbox, because any user with one may read it; ``Get-OrganizationConfig``
    needs an Exchange admin role, and Exchange refuses it with a bare 403 without one.

    Args:
        client: An Exchange client signed in through the broker.
    """
    mailbox = await client.run("Get-Mailbox", Identity=USERNAME)
    assert len(mailbox) == 1
    assert mailbox[0]["UserPrincipalName"].lower() == USERNAME.lower()


async def read_ipps(client: IppsClient) -> None:
    """List the sensitivity labels, proving Security & Compliance accepts the broker's token.

    Args:
        client: An IPPS client signed in through the broker.
    """
    labels = await client.run("Get-Label")
    assert isinstance(labels, list)


async def read_arm(client: AzureClient) -> None:
    """List the user's subscriptions, proving ARM accepts the broker's token.

    An empty list also comes back from a tenant the user cannot reach, so it is not a pass;
    ``AZURE_AUTH_TEST_ARM`` says this user really has a subscription.

    Args:
        client: An ARM client signed in through the broker.
    """
    subscriptions = await client.get_all("/subscriptions", api_version="2022-12-01")
    assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert all(subscription.get("subscriptionId") for subscription in subscriptions)


# Each client with its first-party application, and a read-only call that proves the resource
# accepts the broker's token. IPPS signs in to the same application as Exchange, for a
# different resource.
BROKER_CLIENTS = [
    pytest.param(
        GraphClient, "Microsoft Graph Command Line Tools", read_graph, marks=needs_graph, id="graph"
    ),
    pytest.param(
        ExchangeClient,
        "Exchange Online PowerShell",
        read_exchange,
        marks=needs_exchange,
        id="exchange",
    ),
    pytest.param(IppsClient, "Exchange Online PowerShell", read_ipps, marks=needs_ipps, id="ipps"),
    pytest.param(
        AzureClient, "Azure PowerShell", read_arm, marks=_flag("AZURE_AUTH_TEST_ARM"), id="arm"
    ),
]


@pytest.fixture(scope="module")
def broker_cache_path(cache_path: Path) -> Path:
    """The broker tests' own disk cache, beside the one the browser sign-ins fill.

    Only broker sign-ins write to it, so it never holds a refresh token (module docstring).
    """
    return cache_path.with_name(BROKER_CACHE_NAME)


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
@pytest.mark.parametrize(("make_client", "application", "read"), BROKER_CLIENTS)
async def test_a_broker_sign_in_is_the_brokers(
    make_client: Callable[[AuthContext], ResourceClient],
    application: str,
    read: Callable[[Any], Awaitable[None]],
    broker_cache_path: Path,
) -> None:
    """A forced sign-in through the broker signs in the configured user; the broker keeps it.

    Forced, the broker shows its account picker even for an account it holds, so somebody
    always has to pick. A read-only call then shows the resource accepts the token.
    """
    walkthrough(sign_in_step("WAM"))
    auth = broker_auth(broker_cache_path)
    async with make_client(auth) as client:
        await client.login(force=True)
        token = await auth.aio.acquire_token(client.scopes, client_id=client.client_id)
        await read(client)

    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource
    assert_the_broker_holds_the_sign_in(broker_cache_path)


@needs_user
@pytest.mark.cached_credential
@pytest.mark.parametrize(("make_client", "application", "read"), BROKER_CLIENTS)
async def test_the_broker_renews_a_token_without_prompting(
    make_client: Callable[[AuthContext], ResourceClient],
    application: str,
    read: Callable[[Any], Awaitable[None]],
    broker_cache_path: Path,
) -> None:
    """A context that may not prompt gets a new token from the broker's sign-in.

    ``force_refresh`` skips the cached access token, and MSAL has no refresh token of its own,
    so the token can only come from the broker. When the broker holds no sign-in, a context
    that may prompt makes one first. A read-only call then shows the resource accepts the
    renewed token.
    """
    auth = broker_auth(broker_cache_path)
    auth._interactive_allowed = False
    async with make_client(auth) as client:
        ensure_token(broker_auth(broker_cache_path), client.scopes, client.client_id)
        token = await auth.aio.acquire_token(
            client.scopes, client_id=client.client_id, force_refresh=True
        )
        await read(client)

    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource
    assert_the_broker_holds_the_sign_in(broker_cache_path)


@needs_user
@needs_keyvault
async def test_the_key_vault_client_reads_a_secret_through_the_broker(
    broker_cache_path: Path,
) -> None:
    """The Key Vault client reads a secret on a token the broker issued.

    The vault's token is asked for through the Azure SDK, which calls the context's
    ``get_token`` rather than a resource client, with the scope the vault's challenge names.
    The broker tests' cache never holds a refresh token, so a sign-in found there is the
    broker's. The secret's value is never printed (``tests/live/test_keyvault_client.py``).
    """
    auth = broker_auth(broker_cache_path)
    sign_in_to_vault(auth)
    async with KeyVaultClient(auth, KEYVAULT_URL) as vault:
        value = await vault.get_secret(KEYVAULT_SECRET_NAME)

    has_value = bool(value)
    assert has_value, f"the secret {KEYVAULT_SECRET_NAME!r} came back empty"
    assert_the_broker_holds_the_sign_in(broker_cache_path)


def no_window(*args: Any, **kwargs: Any) -> NoReturn:
    """Stand in for the broker's window, so a sign-in that reaches for it fails at once.

    Args:
        *args: Whatever MSAL passes.
        **kwargs: Whatever MSAL passes.

    Raises:
        AssertionError: Always.
    """
    raise AssertionError("MSAL asked the broker to show its window")


def windows_default_account(auth: AuthContext, client: ResourceClient) -> str | None:
    """Ask Windows which account it signs in with when no account is named.

    This is the request MSAL sends when its cache is empty, sent here directly, outside the
    package, so a test can know what Windows will answer before the package asks.

    Args:
        auth: The context, for its authority.
        client: The client, for its application and scopes.

    Returns:
        The account's user name, or ``None`` when Windows signs nobody in.
    """
    from msal.broker import _signin_silently

    response = _signin_silently(auth.authority, client.client_id, list(client.scopes))
    if "error" in response:
        return None
    return str(response.get("id_token_claims", {}).get("preferred_username") or "") or None


@needs_user
@pytest.mark.parametrize(("make_client", "application", "read"), BROKER_CLIENTS)
async def test_the_broker_signs_in_with_nobody_at_the_desk(
    make_client: Callable[[AuthContext], ResourceClient],
    application: str,
    read: Callable[[Any], Awaitable[None]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A context with nothing cached signs in through the broker without a window.

    Windows holds the account from an earlier broker sign-in, such as the forced one above.
    MSAL's broker sign-in, not forced, asks Windows silently first and shows the window only
    when that fails. The window is taken away here, so a sign-in that would need a person
    fails at once instead of waiting for one, and the test never needs anybody. The cache
    starts empty, so the token cannot have come from an earlier sign-in of this application.
    MSAL's own log, shown on a failure, says what the silent attempt returned.

    With its cache empty, MSAL asks Windows without naming the account, so this works only
    where Windows' default account is the configured user. The test asks Windows first. When
    the default is someone else, which the tenant refuses (AADSTS50020, AADSTS90072; measured
    2026-10-14), the sign-in is expected to fail, and the test reports that as an expected
    failure. If it signs in all the same, the test fails, so the run reports the day the
    package learns to name the account.
    """
    caplog.set_level(logging.DEBUG, logger="msal")
    monkeypatch.setattr("msal.broker._signin_interactively", no_window)
    cache_path = tmp_path / "cache.bin"
    auth = broker_auth(cache_path)
    async with make_client(auth) as client:
        default = windows_default_account(auth, client)
        if (default or "").lower() != USERNAME.lower():
            try:
                await client.login()
            except BrokerUnavailable:
                pytest.xfail(
                    f"Windows signs in {default or 'nobody'} by default, not {USERNAME}, and"
                    " MSAL does not name the account"
                )
            pytest.fail(
                f"signed in although Windows signs in {default or 'nobody'} by default: the"
                " package names the account now, so this case should pass"
            )
        await client.login()
        token = await auth.aio.acquire_token(client.scopes, client_id=client.client_id)
        await read(client)

    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert token_claims(token.token)["aud"] == client.resource
    assert_the_broker_holds_the_sign_in(cache_path)


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
        try:
            await client.login(force=True)
        except AuthError as exc:
            error = exc
        else:
            token = await auth.aio.acquire_token(client.scopes, client_id=client.client_id)
            browser = (client.client_id, False) in auth._apps
            pytest.fail(
                f"no error; signed in as {token_user(token.token)}, "
                f"{'by the browser' if browser else 'by the broker'}"
            )

    print(f"a cancelled broker sign-in: {error}")
    assert not isinstance(error, BrokerUnavailable)
    assert "Status_UserCanceled" in str(error)
    assert (client.client_id, False) not in auth._apps, "the browser was set up after a cancel"


@needs_user
@needs_gdap_tenant
@pytest.mark.interactive
@pytest.mark.regression
async def test_a_customers_exchange_token_leaves_the_account_findable(tmp_path: Path) -> None:
    """A GDAP customer's Exchange token does not hide the account from later requests.

    Through the broker, MSAL saves an account entry for every tenant it gets a token in. A
    customer tenant's Exchange token was saved under a placeholder username, and MSAL, which
    describes the account by its entry saved last, then found nobody by the real one: every
    later silent request failed with "No cached token", in every tenant (measured
    2026-10-16). The test checks the broker still saves the placeholder, then forces a second
    request past every cached access token, so the account has to be found again. The cache is
    the test's own, so the customer's entries reach no other test.
    """
    cache_path = tmp_path / "cache.bin"
    auth = broker_auth(cache_path)
    async with ExchangeClient(auth) as home:
        ensure_sign_in(home)
    customer = auth.for_tenant(GDAP_TENANT)
    async with ExchangeClient(customer) as exchange:
        await customer.aio.acquire_token(exchange.scopes, client_id=exchange.client_id)
        names = [
            str(entry.get("username")).lower()
            for entry in build_cache("disk", cache_path).search(
                msal.TokenCache.CredentialType.ACCOUNT
            )
            if entry.get("realm") == customer.tenant.id
        ]
        assert names, "the broker saved no account entry for the customer tenant"
        assert USERNAME.lower() not in names, (
            f"the customer's Exchange entry is saved as {names}: the broker no longer saves a "
            "placeholder username, so this test reproduces nothing"
        )
        token = await customer.aio.acquire_token(
            exchange.scopes, client_id=exchange.client_id, force_refresh=True
        )

    assert token_claims(token.token)["tid"] == customer.tenant.id
