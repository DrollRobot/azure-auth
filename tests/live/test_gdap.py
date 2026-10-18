"""One home-tenant sign-in, then silent sibling contexts on GDAP customer tenants.

Every test here only reads, so it can run against any customer tenant. A sign-in window
can open only in the home tenant: a sibling context, which is what reaches a customer tenant,
never prompts, so no consent screen can come up there. The Exchange and Security & Compliance
tests send every request through :class:`~tests.live.support.ReadOnlyCmdlets`, which fails the
test, without sending, any request that is not one of its read-only cmdlets.

The home sign-in is the browser's, and the customer-tenant tokens come from its refresh token.
The Windows broker issues customer-tenant tokens too, but without the GDAP role claims, and
Graph refuses those with "User was not found" (measured 2026-10-17). The broker is not
covered here.

The per-customer tests run once for every tenant in ``AZURE_AUTH_TEST_GDAP_TENANT_IDS``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from azure_auth import (
    AuthContext,
    AzureClient,
    AzureError,
    ConsentRequired,
    ExchangeClient,
    GraphClient,
    InteractionRequired,
    IppsClient,
)
from azure_auth.clients.invoke_command import SYSTEM_MAILBOX
from azure_auth.sync import ExchangeClient as BlockingExchangeClient
from azure_auth.sync import GraphClient as BlockingGraphClient
from tests.live.support import (
    GDAP_SCOPES,
    GDAP_TENANTS,
    ReadOnlyCmdlets,
    _flag,
    cached_user_auth,
    ensure_sign_in,
    ensure_token,
    live_user_auth,
    needs_gdap_tenant,
    needs_graph,
    needs_user,
    token_claims,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# Microsoft Graph's own application id; its service principal exists in every tenant.
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# What a customer may have granted the application, from the least to the most, and the one
# small read each grant allows. A customer's Graph test runs the first read whose scope the
# token carries, and nothing more. ``/me`` is not on the list: a GDAP partner has no user
# object in the customer tenant, and ``/me`` answers 400 there (measured 2026-10-17). The
# organization record is the least a tenant exposes, and ``User.Read`` is enough to read it.
MINIMAL_READS: list[tuple[str, str, dict[str, str]]] = [
    ("User.Read", "/organization", {"$select": "id"}),
    ("Organization.Read.All", "/organization", {"$select": "id"}),
    ("Directory.Read.All", "/organization", {"$select": "id"}),
    ("User.ReadBasic.All", "/users", {"$top": "1", "$select": "id"}),
    ("User.Read.All", "/users", {"$top": "1", "$select": "id"}),
    ("Group.Read.All", "/groups", {"$top": "1", "$select": "id"}),
    (
        "Application.Read.All",
        "/servicePrincipals",
        {"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id"},
    ),
]

# Every per-customer test runs once per configured customer tenant.
each_customer = pytest.mark.parametrize("tenant", GDAP_TENANTS)


def minimal_read(scp: str) -> tuple[str, str, dict[str, str]] | None:
    """Return the most minimal read of ``MINIMAL_READS`` a token's scopes allow.

    Args:
        scp: The token's ``scp`` claim, space-separated scope names.

    Returns:
        The scope, path and query of the read, or ``None`` when the token carries none of
        the listed scopes.
    """
    held = {scope.lower() for scope in scp.split()}
    return next((read for read in MINIMAL_READS if read[0].lower() in held), None)


def home_tenant_of(claims: dict[str, object]) -> str:
    """Return the tenant that signed the user in, from a token's ``idp`` claim.

    Args:
        claims: The token's claims.

    Returns:
        The tenant id at the end of the issuer URL.
    """
    return str(claims["idp"]).rstrip("/").rsplit("/", 1)[-1]


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
    assert set(skipped) <= set(tenant_ids)


@needs_user
@needs_gdap_tenant
@each_customer
async def test_gdap_reads_a_customers_directory_without_prompting(
    user_auth: AuthContext, tenant: str
) -> None:
    """Graph answers a directory read in a customer tenant with the home sign-in's token.

    The sibling asks for ``.default``, so the token carries exactly the scopes the customer
    has granted the application. Customers grant different scopes, so the test reads the
    least the token allows (``MINIMAL_READS``), one request, and says which. A customer that
    has granted the application nothing refuses the token request itself (AADSTS65001),
    reported as ``ConsentRequired``; the test skips there, since the consent is the customer's
    to give, and likewise when none of the listed scopes is granted.

    The token must carry the GDAP roles (``wids``): Graph resolves the partner through them.
    Measured 2026-10-17: a token without them, which is what the broker issues, gets
    ``403 Authentication_Unauthorized: User was not found`` on every call.
    """
    async with GraphClient(user_auth, scopes=GDAP_SCOPES) as home:
        ensure_sign_in(home)
    sibling = user_auth.for_tenant(tenant)
    assert sibling is not user_auth, f"{tenant} is the home tenant"

    async with GraphClient(sibling) as graph:
        try:
            token = await sibling.aio.acquire_token(graph.scopes, client_id=graph.client_id)
        except ConsentRequired as error:
            pytest.skip(f"{tenant} has not consented to {graph.client_id}: {error}")
        claims = token_claims(token.token)
        assert claims["tid"] == sibling.tenant.id
        assert home_tenant_of(claims) == user_auth.tenant.id
        assert claims.get("wids"), "the customer-tenant token carries no GDAP roles (wids)"
        scp = str(claims.get("scp", ""))
        print(f"GDAP Graph {tenant}: {len(claims['wids'])} roles (wids), scp: {scp}")

        read = minimal_read(scp)
        if read is None:
            pytest.skip(f"{tenant} grants none of the scopes the minimal reads need: {scp}")
        scope, path, params = read
        answer = await graph.get(path, params=params)
        print(f"GDAP Graph {tenant}: read {path} with {scope}, {len(answer['value'])} returned")
        assert isinstance(answer["value"], list)
        if path == "/organization":
            assert answer["value"][0]["id"] == sibling.tenant.id


@needs_user
@needs_gdap_tenant
@each_customer
async def test_gdap_reads_a_customers_exchange_without_prompting(
    user_auth: AuthContext, tenant: str
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
    sibling = user_auth.for_tenant(tenant)
    assert sibling is not user_auth, f"{tenant} is the home tenant"

    guard = ReadOnlyCmdlets()
    async with ExchangeClient(sibling, transport=guard) as exchange:
        try:
            token = await sibling.aio.acquire_token(exchange.scopes, client_id=exchange.client_id)
        except (ConsentRequired, InteractionRequired) as error:
            pytest.fail(f"the home sign-in does not reach {tenant} silently: {error}")
        config = await exchange.run("Get-OrganizationConfig")

    claims = token_claims(token.token)
    print(
        f"GDAP Exchange {tenant}: roles in the customer tenant's token (wids): {claims.get('wids')}"
    )
    assert claims["tid"] == sibling.tenant.id
    assert claims["aud"] == user_auth.tenant.cloud.exchange
    # A customer-tenant token carries no upn and no oid, and its unique_name is the display
    # name. Measured 2026-10-15: its idp, the issuer that signed the user in, is the home
    # tenant, and its email is user_<home object id, without hyphens>@<home domain>.
    assert home_tenant_of(claims) == user_auth.tenant.id
    home_id = token_claims(home_token.token)["oid"].replace("-", "")
    assert claims["email"].lower().startswith(f"user_{home_id}@")

    request = guard.requests[0]
    assert sibling.tenant.id in request.url.path
    assert request.headers["X-AnchorMailbox"] == f"APP:{SYSTEM_MAILBOX}@{sibling.tenant.id}"

    assert len(config) == 1
    assert user_auth.for_tenant(config[0]["Name"]) is sibling


@needs_user
@needs_gdap_tenant
@each_customer
async def test_gdap_reads_a_customers_mailboxes_without_prompting(
    user_auth: AuthContext, tenant: str
) -> None:
    """The REST read behind ``Get-EXOMailbox`` reaches a customer through GDAP too.

    It reads the audit property set of every mailbox, and nothing else. Whether the customer
    tenant's GET endpoint accepts the system-mailbox routing header that ``InvokeCommand`` needs
    under GDAP, or wants the partner user's UPN as the PowerShell module sends, is what a
    run of this test settles; the header sent is printed with the result.
    """
    async with ExchangeClient(user_auth) as home:
        ensure_sign_in(home)
    sibling = user_auth.for_tenant(tenant)

    guard = ReadOnlyCmdlets()
    async with ExchangeClient(sibling, transport=guard) as exchange:
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
    assert request.url.path.endswith(f"/{sibling.tenant.id}/Mailbox")
    print(
        f"GDAP Exchange read {tenant}: {len(mailboxes)} mailboxes with"
        f" X-AnchorMailbox {request.headers['X-AnchorMailbox']}"
    )
    assert request.headers["X-AnchorMailbox"] == f"APP:{SYSTEM_MAILBOX}@{sibling.tenant.id}"
    # A customer with no mailboxes answers with an empty list; that is an answer, not a failure.
    assert all(isinstance(mailbox["DefaultAuditSet"], list) for mailbox in mailboxes)
    assert all(mailbox["UserPrincipalName"] for mailbox in mailboxes)


@needs_user
@needs_gdap_tenant
@each_customer
async def test_gdap_reads_a_customers_compliance_labels_without_prompting(
    user_auth: AuthContext, tenant: str
) -> None:
    """Security & Compliance answers a read in a customer tenant with the home sign-in's token.

    The same application signs in to Exchange and to Security & Compliance, so the home
    Exchange sign-in is enough; the sibling's token is for the compliance resource. Whether
    the service accepts the GDAP route at all, and the system-mailbox routing header the
    client sends for a sibling (named by tenant id, which the app flow's measurement of
    2026-10-10 says the service refuses), is what a run settles. The header is printed with
    the result.
    """
    async with ExchangeClient(user_auth) as home:
        ensure_sign_in(home)
    sibling = user_auth.for_tenant(tenant)
    assert sibling is not user_auth, f"{tenant} is the home tenant"

    guard = ReadOnlyCmdlets()
    async with IppsClient(sibling, transport=guard) as ipps:
        try:
            token = await sibling.aio.acquire_token(ipps.scopes, client_id=ipps.client_id)
        except (ConsentRequired, InteractionRequired) as error:
            pytest.fail(f"the home sign-in does not reach IPPS in {tenant} silently: {error}")
        labels = await ipps.run("Get-Label")

    claims = token_claims(token.token)
    assert claims["tid"] == sibling.tenant.id
    assert claims["aud"] == user_auth.tenant.cloud.ipps
    assert home_tenant_of(claims) == user_auth.tenant.id
    request = guard.requests[0]
    print(
        f"GDAP IPPS {tenant}: {len(labels)} labels with"
        f" X-AnchorMailbox {request.headers['X-AnchorMailbox']}"
    )
    assert isinstance(labels, list)


@needs_user
@needs_gdap_tenant
@each_customer
async def test_gdap_gets_a_customers_arm_token_without_prompting(
    user_auth: AuthContext, tenant: str
) -> None:
    """Entra issues the home sign-in an ARM token for a customer tenant; what ARM lists is reported.

    GDAP grants roles in a customer's Microsoft 365 directory, not Azure access, so an empty
    subscription list is the expected answer and not a failure. What the test holds to is
    the token: the customer tenant issued it, for ARM, to the user the home tenant signed
    in. A refusal from ARM itself is reported, not failed; anything else that goes wrong is.
    """
    async with AzureClient(user_auth) as home:
        ensure_sign_in(home)
    sibling = user_auth.for_tenant(tenant)
    assert sibling is not user_auth, f"{tenant} is the home tenant"

    async with AzureClient(sibling) as arm:
        try:
            token = await sibling.aio.acquire_token(arm.scopes, client_id=arm.client_id)
        except (ConsentRequired, InteractionRequired) as error:
            pytest.fail(f"the home sign-in does not reach ARM in {tenant} silently: {error}")
        claims = token_claims(token.token)
        assert claims["tid"] == sibling.tenant.id
        assert home_tenant_of(claims) == user_auth.tenant.id
        try:
            subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
        except AzureError as error:
            print(f"GDAP ARM {tenant}: /subscriptions refused: {error}")
        else:
            print(f"GDAP ARM {tenant}: {len(subscriptions)} subscriptions visible")
            assert all(s.get("subscriptionId") for s in subscriptions)


@needs_user
@needs_gdap_tenant
def test_the_blocking_exchange_client_reads_a_customers_exchange(cache_path: Path) -> None:
    """The generated blocking Exchange client reaches a customer through GDAP too."""
    home = live_user_auth(cache_path)
    sibling = home.for_tenant(GDAP_TENANTS[0])
    with BlockingExchangeClient(sibling, transport=ReadOnlyCmdlets()) as exchange:
        ensure_token(home, exchange.scopes, exchange.client_id)
        config = exchange.run("Get-OrganizationConfig")
    assert len(config) == 1


@needs_user
@needs_gdap_tenant
@pytest.mark.cached_credential
def test_the_disk_cache_reaches_customer_tenants_without_prompting(cache_path: Path) -> None:
    """A fresh context on the disk cache reaches the customer tenants with nobody asked.

    This is the unattended run the cache exists for: one browser sign-in earlier, then
    customer after customer from the refresh token it saved. Prompting is switched off, so a
    cache that did not answer fails here instead of opening a window. Runs after the other
    live tests, which fill the cache. A customer that has not consented to the application
    is skipped, as everywhere else.
    """
    home = cached_user_auth(cache_path)
    reached: list[str] = []
    for tenant in GDAP_TENANTS:
        sibling = home.for_tenant(tenant)
        with BlockingGraphClient(sibling) as graph:
            try:
                organization = graph.get_all("/organization", params={"$select": "id"})
            except ConsentRequired:
                continue
        assert organization[0]["id"] == sibling.tenant.id
        reached.append(tenant)
    print(f"GDAP from the disk cache: {len(reached)} of {len(GDAP_TENANTS)} customers reached")
    assert reached, "no customer tenant could be reached from the cache"
