"""Live end-to-end tests against a real tenant.

Nothing here runs unless the environment names a tenant. User-flow tests open a browser (or
the broker) the first time; after that the encrypted disk cache keeps them silent.

Environment variables:

* ``AZURE_AUTH_TEST_TENANT_ID`` and ``AZURE_AUTH_TEST_USERNAME``: user-flow tests.
* ``AZURE_AUTH_TEST_APP_CLIENT_ID`` and ``AZURE_AUTH_TEST_CERT_THUMBPRINT``: app-flow tests
  with a certificate in ``CurrentUser\\My`` (needs ``Organization.Read.All`` on Graph).
* ``AZURE_AUTH_TEST_GDAP=1``: the user is a partner user with GDAP customers.
* ``AZURE_AUTH_TEST_EXCHANGE=1`` / ``AZURE_AUTH_TEST_IPPS=1``: the user may run Exchange /
  Security & Compliance cmdlets.

No secret is read from the environment; app flows use the certificate store.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from azure_auth import (
    AuthContext,
    AzureClient,
    ConsentRequired,
    ExchangeClient,
    GraphClient,
    InteractionRequired,
    IppsClient,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

TENANT = os.environ.get("AZURE_AUTH_TEST_TENANT_ID", "")
USERNAME = os.environ.get("AZURE_AUTH_TEST_USERNAME", "")
APP_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_APP_CLIENT_ID", "")
THUMBPRINT = os.environ.get("AZURE_AUTH_TEST_CERT_THUMBPRINT", "")

needs_user = pytest.mark.skipif(
    not (TENANT and USERNAME),
    reason="set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_USERNAME",
)
needs_app = pytest.mark.skipif(
    not (TENANT and APP_CLIENT_ID and THUMBPRINT),
    reason="set AZURE_AUTH_TEST_TENANT_ID, _APP_CLIENT_ID and _CERT_THUMBPRINT",
)


def _flag(name: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(os.environ.get(name) != "1", reason=f"set {name}=1")


@pytest.fixture(scope="module")
def cache_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("azure-auth-live") / "cache.bin"


@pytest.fixture
def user_auth(cache_path: Path) -> AuthContext:
    return AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)


@needs_user
async def test_interactive_login_then_graph_me(user_auth: AuthContext) -> None:
    async with GraphClient(user_auth, scopes=["User.Read"]) as graph:
        await graph.login()
        me = await graph.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()


@needs_user
async def test_disk_cache_makes_the_second_run_silent(cache_path: Path) -> None:
    # A second context on the same cache file stands in for a second script run. Turning
    # prompting off proves the token really came from the cache.
    second_run = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    second_run._interactive_allowed = False
    async with GraphClient(second_run, scopes=["User.Read"]) as graph:
        me = await graph.get("/me", params={"$select": "id"})
    assert me["id"]


@needs_user
async def test_arm_lists_subscriptions(user_auth: AuthContext) -> None:
    async with AzureClient(user_auth) as arm:
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    assert isinstance(subscriptions, list)


@needs_user
@_flag("AZURE_AUTH_TEST_GDAP")
async def test_gdap_loop_reaches_customers_without_prompting(user_auth: AuthContext) -> None:
    scopes = ["DelegatedAdminRelationship.Read.All", "Organization.Read.All"]
    async with GraphClient(user_auth, scopes=scopes) as partner:
        await partner.login()
        customers = await partner.list_customer_tenant_ids()
    assert customers, "the partner tenant has no GDAP customers"

    reached = 0
    skipped: list[str] = []
    for tenant_id in customers[:5]:
        async with GraphClient(user_auth.for_tenant(tenant_id), scopes=scopes[1:]) as graph:
            try:
                organization = await graph.get_all("/organization")
            except (ConsentRequired, InteractionRequired) as error:
                # Expected for a customer without consent; the error names the tenant.
                skipped.append(error.tenant_id)
                continue
        assert organization[0]["id"] == tenant_id
        reached += 1
    assert reached, "no customer tenant could be reached silently"
    assert set(skipped) <= set(customers)


@needs_user
@_flag("AZURE_AUTH_TEST_EXCHANGE")
async def test_exchange_runs_a_cmdlet(user_auth: AuthContext) -> None:
    async with ExchangeClient(user_auth) as exchange:
        config = await exchange.run("Get-OrganizationConfig")
    assert config
    assert "Name" in config[0]


@needs_user
@_flag("AZURE_AUTH_TEST_IPPS")
async def test_ipps_runs_a_cmdlet_through_the_regional_host(user_auth: AuthContext) -> None:
    async with IppsClient(user_auth) as ipps:
        labels = await ipps.run("Get-Label")
        assert isinstance(labels, list)
        assert ipps.base_url.endswith("ps.compliance.protection.outlook.com")


@needs_app
async def test_app_flow_with_a_store_certificate() -> None:
    auth = AuthContext(TENANT, client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT)
    async with GraphClient(auth) as graph:
        organization = await graph.get_all("/organization")
    assert organization
    # Which algorithm Entra ID accepted for this key is worth knowing; see plan section 4.
    print(f"client assertion algorithm in use: {auth._credential.algorithm}")  # type: ignore[union-attr]
