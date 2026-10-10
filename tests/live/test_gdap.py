"""One home-tenant sign-in, then silent sibling contexts on GDAP customer tenants.

Every test here only reads, so it can run against any customer tenant. A sign-in window
can open only in the home tenant: a sibling context, which is what reaches a customer tenant,
never prompts, so no consent screen can come up there. The Exchange tests send every request
through :class:`~tests.live.support.ReadOnlyCmdlets`, which fails the test, without sending,
any request that is not one of its read-only cmdlets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from azure_auth import (
    AuthContext,
    ConsentRequired,
    ExchangeClient,
    GraphClient,
    InteractionRequired,
)
from azure_auth.clients.invoke_command import SYSTEM_MAILBOX
from azure_auth.sync import ExchangeClient as BlockingExchangeClient
from tests.live.support import (
    GDAP_SCOPES,
    GDAP_TENANT,
    USERNAME,
    ReadOnlyCmdlets,
    _flag,
    ensure_sign_in,
    ensure_token,
    live_user_auth,
    needs_gdap_tenant,
    needs_graph,
    needs_user,
    token_claims,
    token_user,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
@needs_graph
@_flag("AZURE_AUTH_TEST_GDAP")
async def test_gdap_loop_reaches_customer_tenants_without_prompting(
    user_auth: AuthContext,
) -> None:
    async with GraphClient(user_auth, scopes=GDAP_SCOPES) as home:
        ensure_sign_in(home)
        customers = await home.list_customer_tenant_ids()
    assert customers, "the home tenant has no GDAP customers"

    reached = 0
    skipped: list[str] = []
    for tenant_id in customers[:5]:
        sibling = user_auth.for_tenant(tenant_id)
        async with GraphClient(sibling, scopes=GDAP_SCOPES[1:]) as graph:
            try:
                organization = await graph.get_all("/organization")
            except (ConsentRequired, InteractionRequired) as error:
                # Expected for a customer tenant without consent; the error names the tenant.
                skipped.append(error.tenant_id)
                continue
        assert organization[0]["id"] == tenant_id
        reached += 1
    assert reached, "no customer tenant could be reached silently"
    assert set(skipped) <= set(customers)


@needs_user
@needs_gdap_tenant
async def test_gdap_reads_a_customers_exchange_without_prompting(
    user_auth: AuthContext,
) -> None:
    """The home-tenant Exchange sign-in reads a customer's Exchange through GDAP.

    Nobody signs in to the customer tenant. The partner user's home-tenant refresh token is
    spent there, and what comes back is a token from the customer tenant (``tid``) for the
    same user. Exchange then decides, from the user's GDAP roles, whether to answer. The
    token's ``wids`` claim is printed, to compare with the roles in the GDAP relationship.

    The partner user has no mailbox in the customer tenant, so the client routes the request
    through the tenant's system mailbox; the routing header shows it did.

    An organization's ``Name`` is its initial domain, and looking that up must land on the
    same tenant: the answer came from the customer, not from home.
    """
    async with ExchangeClient(user_auth) as home:
        ensure_sign_in(home)
    sibling = user_auth.for_tenant(GDAP_TENANT)
    assert sibling is not user_auth, "AZURE_AUTH_TEST_GDAP_TENANT_ID names the home tenant"

    guard = ReadOnlyCmdlets()
    async with ExchangeClient(sibling, transport=guard) as exchange:
        try:
            token = await sibling.aio.acquire_token(exchange.scopes, client_id=exchange.client_id)
        except (ConsentRequired, InteractionRequired) as error:
            pytest.fail(f"the home sign-in does not reach {GDAP_TENANT} silently: {error}")
        config = await exchange.run("Get-OrganizationConfig")

    claims = token_claims(token.token)
    print(f"GDAP Exchange: roles in the customer tenant's token (wids): {claims.get('wids')}")
    assert claims["tid"] == sibling.tenant.id
    assert claims["aud"] == user_auth.tenant.cloud.exchange
    assert (token_user(token.token) or "").lower() == USERNAME.lower()

    request = guard.requests[0]
    assert sibling.tenant.id in request.url.path
    assert request.headers["X-AnchorMailbox"] == f"APP:{SYSTEM_MAILBOX}@{sibling.tenant.id}"

    assert len(config) == 1
    assert user_auth.for_tenant(config[0]["Name"]) is sibling


@needs_user
@needs_gdap_tenant
def test_the_blocking_exchange_client_reads_a_customers_exchange(cache_path: Path) -> None:
    """The generated blocking Exchange client reaches a customer through GDAP too."""
    home = live_user_auth(cache_path)
    sibling = home.for_tenant(GDAP_TENANT)
    with BlockingExchangeClient(sibling, transport=ReadOnlyCmdlets()) as exchange:
        ensure_token(home, exchange.scopes, exchange.client_id)
        config = exchange.run("Get-OrganizationConfig")
    assert len(config) == 1
