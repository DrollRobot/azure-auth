"""Every Microsoft cloud, against the real services.

Most of this needs no account anywhere. OpenID Connect discovery is public, every service
answers an unauthenticated request with a challenge that names the sign-in host it trusts,
and the device code endpoint says whether an application exists in a cloud. So the cloud
table in :mod:`azure_auth.clouds`, the tenant lookup, and a context finding its own cloud are all
tested against the real Government, DoD and China clouds from a commercial tenant. What does
need an account is signing in and calling a service; that runs in the configured tenant's
cloud, whichever it is.

The reference tenants are public organisations whose cloud is a matter of public record
(checked 2026-09-29). If one ever moves, pick another from the same cloud: any domain
discovery answers for will do.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import re
import uuid
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from azure_auth import (
    AmbiguousTenant,
    AuthContext,
    AuthError,
    ExchangeClient,
    GraphClient,
    GraphError,
    InteractionRequired,
    IppsClient,
    Tenant,
    TenantNotFound,
)
from azure_auth.clients import ArmClient, ResourceClient
from azure_auth.clouds import CHINA, CLOUDS, COMMERCIAL, US_GOV, US_GOV_DOD, Cloud
from azure_auth.constants import (
    AZURE_POWERSHELL_CLIENT_ID,
    EXCHANGE_POWERSHELL_CLIENT_ID,
    GRAPH_CLI_CLIENT_ID,
)
from tests.consent_reset import GRAPH_APP_ID
from tests.live.support import (
    APP_CLIENT_ID,
    BASELINE_SCOPES,
    SIGN_IN_TIMEOUT_SECONDS,
    TENANT,
    THUMBPRINT,
    USERNAME,
    _flag,
    ensure_sign_in,
    live_cloud,
    live_tenant,
    needs_app,
    needs_graph,
    needs_user,
    sign_in_step,
    tenant_domain,
    token_claims,
    walkthrough,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live]

# One public tenant per cloud, by domain: (domain, cloud, tenant_region_sub_scope).
REFERENCE_TENANTS = {
    "commercial": ("microsoft.com", COMMERCIAL, None),
    "gcc": ("nasa.gov", COMMERCIAL, "GCC"),
    "gcc-high": ("gov.uiowa.edu", US_GOV, "DODCON"),
    "dod": ("armyeitaas.onmicrosoft.us", US_GOV_DOD, "DOD"),
    "china": ("vgc.partner.onmschina.cn", CHINA, None),
}

# Names that are a different tenant in each of two clouds: (name, the clouds).
AMBIGUOUS_TENANTS = {
    # The China cloud's operator: its domain is verified in a commercial and a China tenant.
    "domain": ("21vianet.com", {COMMERCIAL, CHINA}),
    # Microsoft's own services tenant: one GUID, a commercial and a US government tenant.
    "guid": ("f8cdef31-a31e-4b4a-93e4-5f571e91255a", {COMMERCIAL, US_GOV}),
}

# The service principals that answer each service's challenge, in every cloud; Graph's is
# GRAPH_APP_ID in consent_reset, which needs it too.
EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
IPPS_APP_ID = "00000007-0000-0ff1-ce00-000000000000"

_CHALLENGE_FIELD = re.compile(r'(\w+)="([^"]*)"')


def reference_tenant(cloud: Cloud) -> Tenant:
    """Return a public tenant in ``cloud``, looked up."""
    domain = next(domain for domain, where, _ in REFERENCE_TENANTS.values() if where is cloud)
    return Tenant.lookup(domain)


def challenge(response: httpx.Response) -> dict[str, str]:
    """Read the fields of a ``WWW-Authenticate: Bearer`` challenge."""
    return dict(_CHALLENGE_FIELD.findall(response.headers.get("WWW-Authenticate", "")))


def unsigned_jwt() -> str:
    """Build a token that is well formed and signed by nobody.

    Security & Compliance answers a token it cannot parse with a 500 and no challenge
    (measured 2026-09-26); a well-formed one gets the 401 and the challenge.
    """

    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{encode({'alg': 'RS256', 'typ': 'JWT'})}.{encode({'aud': 'x'})}.{encode('sig')}"


def unauthenticated_client(
    make: Callable[[AuthContext], ResourceClient], tenant: Tenant
) -> ResourceClient:
    """Build a client only to read the URLs it would use; it never requests a token."""
    auth = AuthContext(tenant, username="nobody@example.invalid", client_id="unused")
    return make(auth)


# ---------------------------------------------------------------------------- lookup


@pytest.mark.parametrize(
    ("domain", "cloud", "sub_scope"), REFERENCE_TENANTS.values(), ids=REFERENCE_TENANTS.keys()
)
def test_a_tenant_is_found_in_its_cloud_by_domain_and_by_id(
    domain: str, cloud: Cloud, sub_scope: str | None
) -> None:
    by_domain = Tenant.lookup(domain)
    by_id = Tenant.lookup(by_domain.id)

    assert by_domain.cloud is cloud
    assert by_domain.region_sub_scope == sub_scope
    assert by_domain == by_id
    assert (by_domain.domain, by_id.domain) == (domain, None)
    print(f"{domain}: {by_domain.id} in {cloud.name} ({by_domain.region_scope})")


@pytest.mark.parametrize(
    ("tenant", "clouds"), AMBIGUOUS_TENANTS.values(), ids=AMBIGUOUS_TENANTS.keys()
)
def test_a_name_that_is_a_tenant_in_two_clouds_is_ambiguous(
    tenant: str, clouds: set[Cloud]
) -> None:
    with pytest.raises(AmbiguousTenant) as caught:
        Tenant.lookup(tenant)

    found = {candidate.cloud: candidate.id for candidate in caught.value.candidates}
    assert set(found) == clouds
    print(f"{tenant}: { ({cloud.name: guid for cloud, guid in found.items()}) }")


@pytest.mark.parametrize(
    "tenant", ["no-such-tenant-4f1c.onmicrosoft.com", "0" * 8 + "-0000-0000-0000-" + "0" * 12]
)
def test_a_tenant_that_does_not_exist_is_not_found(tenant: str) -> None:
    with pytest.raises(TenantNotFound):
        Tenant.lookup(tenant)


# ---------------------------------------------------------------------------- the table


@pytest.mark.parametrize("cloud", CLOUDS, ids=lambda cloud: cloud.name)
def test_every_service_in_the_table_trusts_its_clouds_sign_in(cloud: Cloud) -> None:
    """Each service host is real, is the service it should be, and trusts the right cloud.

    No token is needed: every service answers a request without a usable one with a 401 and
    a challenge naming the sign-in host it trusts, and (except Resource Manager) the service
    principal it is. A host from the wrong cloud names the wrong sign-in host; a typo does
    not resolve.
    """
    tenant = reference_tenant(cloud)
    graph = unauthenticated_client(GraphClient, tenant)
    arm = unauthenticated_client(ArmClient, tenant)
    exchange = unauthenticated_client(ExchangeClient, tenant)
    ipps = unauthenticated_client(IppsClient, tenant)
    invoke = f"/adminapi/beta/{tenant.id}/InvokeCommand"
    body = {"CmdletInput": {"CmdletName": "Get-OrganizationConfig"}}

    with httpx.Client(timeout=30) as http:
        answers = {
            "graph": http.get(f"{graph.base_url}/organization"),
            "arm": http.get(f"{arm.base_url}/subscriptions", params={"api-version": "2022-12-01"}),
            # Exchange asks for Basic credentials until it is shown a bearer token.
            "exchange": http.post(
                f"{exchange.base_url}{invoke}", json=body, headers={"Authorization": "Bearer x"}
            ),
            "ipps": http.post(
                f"{ipps.base_url}{invoke}",
                json=body,
                headers={"Authorization": f"Bearer {unsigned_jwt()}"},
            ),
        }

    expected_app = {"graph": GRAPH_APP_ID, "exchange": EXCHANGE_APP_ID, "ipps": IPPS_APP_ID}
    for service, response in answers.items():
        fields = challenge(response)
        signs_in_at = httpx.URL(fields.get("authorization_uri", "")).host
        print(f"{cloud.name} {service}: {response.request.url.host} trusts {signs_in_at}")
        assert response.status_code == 401, f"{service}: {response.status_code}"
        assert signs_in_at in cloud.login_hosts, f"{service} trusts {signs_in_at}"
        if service in expected_app:
            assert fields.get("client_id") == expected_app[service], service


@pytest.mark.parametrize("cloud", CLOUDS, ids=lambda cloud: cloud.name)
def test_the_first_party_applications_in_the_table_are_the_ones_published(cloud: Cloud) -> None:
    """Each cloud's ``first_party_client_ids`` is exactly the defaults Microsoft publishes there.

    A device code request for an application names no tenant (``organizations``) and signs
    nobody in; the code it returns expires unused. An application that does not exist in the
    cloud is refused the same way a made-up id is (AADSTS50059, measured 2026-09-27).
    """
    made_up = "11111111-2222-3333-4444-555555555555"
    defaults = (GRAPH_CLI_CLIENT_ID, AZURE_POWERSHELL_CLIENT_ID, EXCHANGE_POWERSHELL_CLIENT_ID)
    url = f"{cloud.authority_host}/organizations/oauth2/v2.0/devicecode"
    with httpx.Client(timeout=30) as http:
        published = {
            client_id
            for client_id in (*defaults, made_up)
            if "user_code"
            in http.post(url, data={"client_id": client_id, "scope": "openid"}).json()
        }
    assert published == cloud.first_party_client_ids


# ---------------------------------------------------------------------------- the context


@pytest.mark.parametrize(
    ("domain", "cloud"),
    [(domain, cloud) for domain, cloud, _ in REFERENCE_TENANTS.values()],
    ids=REFERENCE_TENANTS.keys(),
)
def test_a_context_finds_its_tenants_cloud_by_itself(domain: str, cloud: Cloud) -> None:
    """Given only a domain name, the context and its clients address the right cloud.

    Nothing here signs in: the cloud is known once the context exists.
    """
    auth = AuthContext(domain, username=f"nobody@{domain}")

    assert auth.tenant.cloud is cloud
    assert auth.tenant.domain == domain
    assert auth.authority == f"{cloud.authority_host}/{auth.tenant.id}"
    assert GraphClient(auth, client_id="unused").base_url.startswith(cloud.graph)
    assert ExchangeClient(auth).resource == cloud.exchange


@pytest.mark.parametrize(
    ("domain", "cloud"),
    [(domain, cloud) for domain, cloud, _ in REFERENCE_TENANTS.values()],
    ids=REFERENCE_TENANTS.keys(),
)
def test_the_sign_in_library_sets_up_in_every_cloud(domain: str, cloud: Cloud) -> None:
    """MSAL accepts each cloud's sign-in host and gets as far as needing somebody to sign in.

    The context may not prompt and has no cached account, so it stops there with
    :class:`InteractionRequired`. Getting there means MSAL fetched the tenant's discovery
    document from that cloud's sign-in host and took its token endpoint from it; only public
    endpoints are asked.
    """
    auth = AuthContext(domain, username=f"nobody@{domain}")
    auth._can_prompt = False

    with pytest.raises(InteractionRequired):
        auth.acquire_token([f"{cloud.arm}/.default"])

    (app,) = auth._apps.values()
    assert httpx.URL(app.authority.token_endpoint).host in cloud.login_hosts


@pytest.mark.parametrize(
    ("tenant", "clouds"), AMBIGUOUS_TENANTS.values(), ids=AMBIGUOUS_TENANTS.keys()
)
def test_a_context_for_an_ambiguous_name_takes_the_tenant_looked_up_in_its_cloud(
    tenant: str, clouds: set[Cloud]
) -> None:
    # The name is a tenant in each cloud; looking it up in one says which is meant.
    with pytest.raises(AmbiguousTenant):
        AuthContext(tenant, username="nobody@example.invalid")
    for cloud in clouds:
        auth = AuthContext(Tenant.lookup(tenant, cloud), username="nobody@example.invalid")
        assert auth.tenant.cloud is cloud


def test_a_context_for_a_tenant_that_does_not_exist_fails_when_it_is_created() -> None:
    with pytest.raises(TenantNotFound):
        AuthContext("no-such-tenant-4f1c.onmicrosoft.com", username="nobody@example.invalid")


@needs_app
@pytest.mark.parametrize("cloud", CLOUDS, ids=lambda cloud: cloud.name)
def test_an_app_given_the_wrong_cloud_fails_at_sign_in(cloud: Cloud) -> None:
    """A tenant built by hand with the wrong cloud is taken as given; Entra refuses it.

    What Entra answers, measured 2026-09-29: the certificate assertion is addressed to the
    wrong cloud's token endpoint, and is refused with AADSTS700023 ("Client assertion
    audience claim does not match Realm issuer").
    """
    if cloud == live_cloud():
        pytest.skip(f"the configured tenant lives in {cloud.name}")
    auth = AuthContext(
        Tenant(live_tenant().id, cloud), client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT
    )

    with pytest.raises(AuthError, match="AADSTS700023"):
        auth.acquire_token([f"{cloud.graph}/.default"])


# Where a failed app sign-in may be sent: the configured tenant, and Microsoft's own services
# tenant in US Government, which is Microsoft's to receive it. Its GUID is a commercial tenant
# too (AMBIGUOUS_TENANTS), so it is built by hand with its cloud rather than looked up. No
# Microsoft-owned DoD or China tenant is known.
FAIR_GAME_TENANTS: dict[str, Callable[[], str | Tenant]] = {
    "configured": lambda: TENANT,
    "usgov-services": lambda: Tenant(AMBIGUOUS_TENANTS["guid"][0], US_GOV),
}


@needs_app
@pytest.mark.parametrize("make_tenant", FAIR_GAME_TENANTS.values(), ids=FAIR_GAME_TENANTS.keys())
def test_an_app_sign_in_reaches_its_clouds_token_server(
    make_tenant: Callable[[], str | Tenant],
) -> None:
    """A certificate sign-in is answered by the token server of the tenant's own cloud.

    The application id is made up, so Entra answers that no such application exists
    (AADSTS700016). That answer means the request reached the right token server with an
    assertion it could read; a wrong server or a malformed assertion is refused differently.

    The check needs no account in any cloud, but it sends a failed sign-in to whichever tenant
    it names, so it only names the tenants in ``FAIR_GAME_TENANTS``. The US Government one is
    the only sign-in these tests make outside the configured tenant's cloud.
    """
    auth = AuthContext(
        make_tenant(), client_id=str(uuid.uuid4()), certificate_thumbprint=THUMBPRINT
    )

    with pytest.raises(AuthError, match="AADSTS700016"):
        auth.acquire_token([f"{auth.tenant.cloud.graph}/.default"])

    (app,) = auth._apps.values()
    assert httpx.URL(app.authority.token_endpoint).host in auth.tenant.cloud.login_hosts


# ---------------------------------------------------------------------------- signed in


def discovered_auth(cache_path: Path) -> AuthContext:
    """A context built by a caller who knows only the user: the tenant is their domain in it."""
    return AuthContext(
        tenant_domain(cache_path),
        username=USERNAME,
        cache="disk",
        cache_path=cache_path,
        browser_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )


@needs_user
@needs_graph
@pytest.mark.anyio
async def test_a_cloud_of_the_callers_own_is_used_as_given(cache_path: Path) -> None:
    """A :class:`Cloud` the caller built is used as it is, from sign-in to a Graph call.

    It has the tenant's own endpoints under another name, so the only thing tested is that a
    cloud outside the table is taken as given.
    """
    custom = dataclasses.replace(live_cloud(), name="Custom")
    auth = AuthContext(
        Tenant(live_tenant().id, custom),
        username=USERNAME,
        cache="disk",
        cache_path=cache_path,
        browser_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )
    async with GraphClient(auth, scopes=BASELINE_SCOPES) as graph:
        ensure_sign_in(graph)
        organization = await graph.get_all("/organization", params={"$select": "id"})

    assert auth.tenant.cloud is custom
    assert [item["id"] for item in organization] == [live_tenant().id]


@needs_user
@needs_graph
@pytest.mark.interactive
@pytest.mark.anyio
async def test_a_user_given_the_wrong_cloud_is_refused() -> None:
    """A tenant built with the wrong cloud: the sign-in succeeds and the first request fails.

    Measured 2026-09-29, a Commercial tenant set to USGov: the tenant's own cloud signs the
    user in and issues a token for the wrong cloud's Graph (``iss`` sts.windows.net, ``aud``
    https://graph.microsoft.us), and that Graph refuses it with 401
    ``InvalidAuthenticationToken: InvalidCloudInstance``.
    """
    wrong = COMMERCIAL if live_cloud() != COMMERCIAL else US_GOV
    walkthrough(sign_in_step("browser"))
    auth = AuthContext(
        Tenant(live_tenant().id, wrong),
        username=USERNAME,
        browser_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )
    async with GraphClient(auth, scopes=["User.Read"]) as graph:
        await graph.login(pick_account=True)
        token = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)
        claims = token_claims(token.token)
        print(f"{TENANT} as {wrong.name}: token aud={claims.get('aud')} iss={claims.get('iss')}")
        with pytest.raises(GraphError) as caught:
            await graph.get("/me", params={"$select": "id"})

    assert claims["aud"] == wrong.graph
    assert httpx.URL(claims["iss"]).host in live_cloud().login_hosts
    assert (caught.value.status, caught.value.code) == (401, "InvalidAuthenticationToken")
    assert "InvalidCloudInstance" in str(caught.value)


@needs_user
def test_the_configured_tenant_is_the_same_by_id_and_by_the_users_domain(
    cache_path: Path,
) -> None:
    by_id = Tenant.lookup(TENANT)
    by_domain = Tenant.lookup(tenant_domain(cache_path))

    assert by_id == by_domain
    assert by_id.cloud == live_cloud()
    print(f"configured tenant: {by_id.id} in {by_id.cloud.name}, {by_id.region_scope}")


@needs_user
@needs_graph
@pytest.mark.anyio
async def test_a_discovered_context_reaches_graph_in_its_cloud(cache_path: Path) -> None:
    auth = discovered_auth(cache_path)
    async with GraphClient(auth, scopes=BASELINE_SCOPES) as graph:
        ensure_sign_in(graph)
        token = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)
        organization = await graph.get_all("/organization", params={"$select": "id"})

    tenant_guid = live_tenant().id
    assert auth.tenant.cloud == live_cloud()
    assert graph.base_url.startswith(auth.tenant.cloud.graph)
    assert token_claims(token.token)["tid"] == tenant_guid
    assert [item["id"] for item in organization] == [tenant_guid]
    # The context holds the tenant the token is really for, and the domain it was given.
    assert auth.tenant.id == tenant_guid
    assert auth.tenant.domain == tenant_domain(cache_path)
    assert auth.get_tenant_context(tenant_guid) is auth


@needs_user
@_flag("AZURE_AUTH_TEST_EXCHANGE")
@pytest.mark.anyio
async def test_a_discovered_context_runs_exchange_cmdlets_in_its_cloud(cache_path: Path) -> None:
    auth = discovered_auth(cache_path)
    async with ExchangeClient(auth) as exchange:
        ensure_sign_in(exchange)
        token = await auth.aio.acquire_token(exchange.scopes, client_id=exchange.client_id)
        config = await exchange.run("Get-OrganizationConfig")

    assert token_claims(token.token)["aud"] == auth.tenant.cloud.exchange
    assert config[0]["Name"]


@needs_user
@_flag("AZURE_AUTH_TEST_IPPS")
@pytest.mark.anyio
async def test_a_discovered_context_runs_compliance_cmdlets_in_its_cloud(
    cache_path: Path,
) -> None:
    auth = discovered_auth(cache_path)
    async with IppsClient(auth) as ipps:
        ensure_sign_in(ipps)
        labels = await ipps.run("Get-Label")

    assert isinstance(labels, list)
    assert httpx.URL(ipps.base_url).host.endswith(f".{httpx.URL(auth.tenant.cloud.ipps).host}")
