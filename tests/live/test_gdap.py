"""One home-tenant sign-in, then silent contexts from get_tenant_context() on GDAP customer tenants.

Every test here only reads, so it can run against any customer tenant. A sign-in window
can open only in the home tenant: a context from get_tenant_context(), which is what reaches a
customer tenant, never prompts, so no consent screen can come up there. The Exchange tests
send every request through :class:`~tests.live.support.ReadOnlyCmdlets`, which fails the
test, without sending, any request that is not one of its read-only cmdlets.
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
    ReadOnlyCmdlets,
    _flag,
    ensure_sign_in,
    ensure_token,
    live_user_auth,
    needs_gdap_tenant,
    needs_graph,
    needs_user,
    token_claims,
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
        customers = await home.list_customers()
    assert customers, "the home tenant has no GDAP customers"
    # Every customer comes with its id and name, each tenant once.
    assert all(customer["tenantId"] and customer["displayName"] for customer in customers)
    tenant_ids = [customer["tenantId"] for customer in customers]
    assert len(set(tenant_ids)) == len(customers)
    print(f"{len(customers)} customers: " + ", ".join(c["displayName"] for c in customers[:5]))

    reached = 0
    skipped: list[str] = []
    for tenant_id in tenant_ids[:5]:
        customer = user_auth.get_tenant_context(tenant_id)
        async with GraphClient(customer, scopes=GDAP_SCOPES[1:]) as graph:
            try:
                organization = await graph.get_all("/organization")
            except (ConsentRequired, InteractionRequired) as error:
                # Expected for a customer tenant without consent; the error names the tenant.
                skipped.append(error.tenant_id)
                continue
        assert organization[0]["id"] == tenant_id
        reached += 1
    assert reached, "no customer tenant could be reached silently"
    assert set(skipped) <= set(tenant_ids)


@needs_user
@needs_gdap_tenant
async def test_gdap_reads_a_customers_exchange_without_prompting(
    user_auth: AuthContext,
) -> None:
    """The home-tenant Exchange sign-in reads a customer's Exchange through GDAP.

    Nobody signs in to the customer tenant. The partner user's home-tenant refresh token is
    spent there, and what comes back is a token from the customer tenant (``tid``) for a user
    the home tenant signed in (``idp``). Exchange then decides, from the user's GDAP roles,
    whether to answer. The token's ``wids`` claim is printed, to compare with the roles in the
    GDAP relationship.

    The partner user has no mailbox in the customer tenant, so the client routes the request
    through the tenant's system mailbox; the routing header shows it did.

    An organization's ``Name`` is its initial domain, and looking that up must land on the
    same tenant: the answer came from the customer, not from home.
    """
    async with ExchangeClient(user_auth) as home:
        ensure_sign_in(home)
        home_token = await user_auth.aio.acquire_token(home.scopes, client_id=home.client_id)
    customer = user_auth.get_tenant_context(GDAP_TENANT)
    assert customer is not user_auth, "AZURE_AUTH_TEST_GDAP_TENANT_ID names the home tenant"

    guard = ReadOnlyCmdlets()
    async with ExchangeClient(customer, transport=guard) as exchange:
        try:
            token = await customer.aio.acquire_token(exchange.scopes, client_id=exchange.client_id)
        except (ConsentRequired, InteractionRequired) as error:
            pytest.fail(f"the home sign-in does not reach {GDAP_TENANT} silently: {error}")
        config = await exchange.run("Get-OrganizationConfig")

    claims = token_claims(token.token)
    print(f"GDAP Exchange: roles in the customer tenant's token (wids): {claims.get('wids')}")
    assert claims["tid"] == customer.tenant.id
    assert claims["aud"] == user_auth.tenant.cloud.exchange
    # A customer-tenant token carries no upn and no oid, and its unique_name is the display
    # name. Measured 2026-10-15: its idp, the issuer that signed the user in, is the home
    # tenant, and its email is user_<home object id, without hyphens>@<home domain>.
    assert claims["idp"].rstrip("/").rsplit("/", 1)[-1] == user_auth.tenant.id
    home_id = token_claims(home_token.token)["oid"].replace("-", "")
    assert claims["email"].lower().startswith(f"user_{home_id}@")

    request = guard.requests[0]
    assert customer.tenant.id in request.url.path
    assert request.headers["X-AnchorMailbox"] == f"APP:{SYSTEM_MAILBOX}@{customer.tenant.id}"

    assert len(config) == 1
    assert user_auth.get_tenant_context(config[0]["Name"]) is customer


@needs_user
@needs_gdap_tenant
async def test_gdap_reads_a_customers_mailboxes_without_prompting(user_auth: AuthContext) -> None:
    """The REST read behind ``Get-EXOMailbox`` reaches a customer through GDAP too.

    It reads the audit property set of every mailbox, and nothing else. Whether the customer
    tenant's GET endpoint accepts the system-mailbox routing header that ``InvokeCommand`` needs
    under GDAP, or wants the partner user's UPN as the PowerShell module sends, is what a
    run of this test settles; the header sent is printed with the result.
    """
    async with ExchangeClient(user_auth) as home:
        ensure_sign_in(home)
    customer = user_auth.get_tenant_context(GDAP_TENANT)

    guard = ReadOnlyCmdlets()
    async with ExchangeClient(customer, transport=guard) as exchange:
        mailboxes = await exchange.mailboxes(
            PropertySet="Audit",
            RecipientTypeDetails=[
                "UserMailbox",
                "SharedMailbox",
                "RoomMailbox",
                "EquipmentMailbox",
            ],
            select=["DefaultAuditSet", "UserPrincipalName", "RecipientTypeDetails"],
        )

    request = guard.requests[0]
    assert request.method == "GET"
    assert request.url.path.endswith(f"/{customer.tenant.id}/Mailbox")
    print(
        f"GDAP Exchange read: {len(mailboxes)} mailboxes with"
        f" X-AnchorMailbox {request.headers['X-AnchorMailbox']}"
    )
    assert request.headers["X-AnchorMailbox"] == f"APP:{SYSTEM_MAILBOX}@{customer.tenant.id}"
    assert mailboxes, "the customer tenant has no mailboxes"
    assert all(isinstance(mailbox["DefaultAuditSet"], list) for mailbox in mailboxes)
    assert all(mailbox["UserPrincipalName"] for mailbox in mailboxes)


@needs_user
@needs_gdap_tenant
def test_the_blocking_exchange_client_reads_a_customers_exchange(cache_path: Path) -> None:
    """The generated blocking Exchange client reaches a customer through GDAP too."""
    home = live_user_auth(cache_path)
    customer = home.get_tenant_context(GDAP_TENANT)
    with BlockingExchangeClient(customer, transport=ReadOnlyCmdlets()) as exchange:
        ensure_token(home, exchange.scopes, exchange.client_id)
        config = exchange.run("Get-OrganizationConfig")
    assert len(config) == 1
