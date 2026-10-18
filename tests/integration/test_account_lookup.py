"""Finding the user's cached account through the real MSAL, with the cache the broker leaves.

The broker saves an account entry for every tenant it hands a token out in. A GDAP customer
tenant's Exchange token is saved under a placeholder username, and MSAL describes the
account by whichever entry was saved last, so its own lookup by username then finds nobody
(``.local/research/broker-and-conditional-access.md``, measured 2026-10-16). These tests fill
a real MSAL cache with the entries the broker wrote in that run and look the account up
through a real MSAL application. The broker itself is never called: a cached access token
answers, which MSAL finds only once it has been handed the right account.
"""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import msal
import pytest

from azure_auth import AuthContext, Tenant
from azure_auth.clouds import COMMERCIAL
from azure_auth.constants import EXCHANGE_POWERSHELL_CLIENT_ID, GRAPH_CLI_CLIENT_ID

pytestmark = pytest.mark.integration

LOGIN = "https://login.microsoftonline.com"
HOME = "11111111-1111-1111-1111-111111111111"
CUSTOMER = "22222222-2222-2222-2222-222222222222"
OTHER_CUSTOMER = "33333333-3333-3333-3333-333333333333"
# The tenant of every personal Microsoft account.
CONSUMERS = "9188040d-6c67-4c5b-b112-36a304b66dad"
OBJECT_ID = "f0000000-0000-0000-0000-00000000000f"
USER = "admin@partner.com"
# The username a customer tenant's Exchange token was saved under (live, 2026-10-16).
PLACEHOLDER = f"user_{OBJECT_ID.replace('-', '')}@partner.com"
GRAPH_SCOPE = "https://graph.microsoft.com/Organization.Read.All"
EXCHANGE_SCOPE = "https://outlook.office365.com/.default"


def _b64(claims: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()


class FakeEntra:
    """Entra ID's discovery document, for any tenant; any other request fails the test."""

    def get(self, url: str, **kwargs: Any) -> Any:
        tenant = urlsplit(url).path.split("/")[1]
        if url != f"{LOGIN}/{tenant}/v2.0/.well-known/openid-configuration":
            raise AssertionError(f"unexpected request: GET {url}")
        body = {
            "authorization_endpoint": f"{LOGIN}/{tenant}/oauth2/v2.0/authorize",
            "token_endpoint": f"{LOGIN}/{tenant}/oauth2/v2.0/token",
            "issuer": f"{LOGIN}/{tenant}/v2.0",
        }
        return SimpleNamespace(status_code=200, text=json.dumps(body), headers={})

    def post(self, url: str, **kwargs: Any) -> Any:
        raise AssertionError(f"unexpected request: POST {url}")

    def close(self) -> None:
        pass


class MsalOver:
    """The ``msal`` module, with every application sending its requests to :class:`FakeEntra`."""

    def __getattr__(self, name: str) -> Any:
        return getattr(msal, name)

    def PublicClientApplication(self, *args: Any, **kwargs: Any) -> Any:
        return msal.PublicClientApplication(*args, http_client=FakeEntra(), **kwargs)


def broker_token(
    cache: msal.TokenCache,
    *,
    tenant: str,
    client_id: str,
    scope: str,
    username: str,
    home: str = HOME,
) -> None:
    """Save a token the way MSAL saves one the broker handed out.

    The event has the shape MSAL logged for each broker token in the live run: the broker's
    account id, ``grant_type`` ``broker``, and the broker's ID token claims.

    Args:
        cache: The cache to save into.
        tenant: The tenant the token is for.
        client_id: The application it was handed to.
        scope: Its scope.
        username: The ``preferred_username`` of its ID token.
        home: The user's home tenant.
    """
    account_id = OBJECT_ID if tenant == home else f"{OBJECT_ID}.{home}.{tenant}"
    response = {
        "access_token": f"{client_id}-token-for-{tenant}",
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": scope,
        "client_info": _b64({"uid": OBJECT_ID, "utid": home}),
        "id_token_claims": {"oid": OBJECT_ID, "tid": tenant, "preferred_username": username},
        "_account_id": account_id,
    }
    cache.add(
        {
            "client_id": client_id,
            "scope": [scope],
            "token_endpoint": f"{LOGIN}/{tenant}/oauth2/v2.0/token",
            "environment": "login.microsoftonline.com",
            "grant_type": "broker",
            "_account_id": account_id,
            "response": response,
            "data": {},
        }
    )


@pytest.fixture
def cache(monkeypatch: pytest.MonkeyPatch) -> msal.TokenCache:
    """The token cache every context in the test is given, through the real MSAL."""
    cache = msal.TokenCache()
    monkeypatch.setattr("azure_auth.auth.context.build_cache", lambda *args: cache)
    monkeypatch.setattr("azure_auth.auth.context.msal", MsalOver())
    return cache


@pytest.fixture
def gdap_cache(cache: msal.TokenCache) -> msal.TokenCache:
    """The cache the live run left: home sign-ins, then two customers' tokens.

    The other customer's Graph token is saved before the customer's Exchange token, so the
    Exchange token's entry, with the placeholder username, is the last one saved.
    """
    broker_token(
        cache, tenant=HOME, client_id=GRAPH_CLI_CLIENT_ID, scope=GRAPH_SCOPE, username=USER
    )
    broker_token(
        cache,
        tenant=OTHER_CUSTOMER,
        client_id=GRAPH_CLI_CLIENT_ID,
        scope=GRAPH_SCOPE,
        username=USER,
    )
    broker_token(
        cache,
        tenant=CUSTOMER,
        client_id=EXCHANGE_POWERSHELL_CLIENT_ID,
        scope=EXCHANGE_SCOPE,
        username=PLACEHOLDER,
    )
    return cache


def test_msal_alone_finds_no_account_after_a_customers_exchange_token(
    gdap_cache: msal.TokenCache,
) -> None:
    # Why AuthContext does not ask MSAL by username. If this starts passing with an account,
    # MSAL describes accounts by their home entry now, and the workaround can go.
    app = msal.PublicClientApplication(
        GRAPH_CLI_CLIENT_ID,
        authority=f"{LOGIN}/{OTHER_CUSTOMER}",
        token_cache=gdap_cache,
        http_client=FakeEntra(),
    )
    assert [account["username"] for account in app.get_accounts()] == [PLACEHOLDER]
    assert app.get_accounts(username=USER) == []


@pytest.mark.regression
def test_a_customers_exchange_token_does_not_hide_the_account(
    gdap_cache: msal.TokenCache,
) -> None:
    auth = AuthContext(Tenant(HOME, COMMERCIAL), username=USER)
    customer = auth.get_tenant_context(OTHER_CUSTOMER)

    token = customer.acquire_token([GRAPH_SCOPE], client_id=GRAPH_CLI_CLIENT_ID)

    assert token.token == f"{GRAPH_CLI_CLIENT_ID}-token-for-{OTHER_CUSTOMER}"


def test_a_guest_with_no_home_entry_is_found_as_msal_describes_it(
    cache: msal.TokenCache,
) -> None:
    # A personal account invited as a guest has no entry in its home tenant.
    broker_token(
        cache,
        tenant=CUSTOMER,
        client_id=GRAPH_CLI_CLIENT_ID,
        scope=GRAPH_SCOPE,
        username=USER,
        home=CONSUMERS,
    )
    auth = AuthContext(Tenant(CUSTOMER, COMMERCIAL), username=USER)

    token = auth.acquire_token([GRAPH_SCOPE], client_id=GRAPH_CLI_CLIENT_ID)

    assert token.token == f"{GRAPH_CLI_CLIENT_ID}-token-for-{CUSTOMER}"
