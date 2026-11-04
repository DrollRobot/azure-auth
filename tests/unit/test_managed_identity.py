"""Unit tests for the managed identity flow, with the host's identity endpoint faked.

The real msal managed identity client runs in the middle; the endpoint is answered at the
``requests`` adapter the context's session sends through, so each test sees the exact
request the endpoint would get. The host is described through its environment variables, as
msal reads them.
"""

from __future__ import annotations

import io
import json
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
import requests
from urllib3.response import HTTPResponse

from azure_auth import (
    ArmClient,
    AuthContext,
    AuthError,
    ExchangeClient,
    GraphClient,
    IppsClient,
    ManagedIdentityUnavailable,
    NetworkError,
    Tenant,
)
from azure_auth.auth import context as context_module
from azure_auth.clouds import COMMERCIAL, US_GOV
from tests.fakes import FakeLookup
from tests.http import Recorder, fake_jwt, ok

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "66666666-7777-8888-9999-000000000000"
IDENTITY_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SYSTEM_CLIENT_ID = "ffffffff-0000-1111-2222-333333333333"
VAULT_SCOPE = "https://vault.azure.net/.default"
GOV_VAULT_SCOPE = "https://vault.usgovcloudapi.net/.default"
CONTAINER_APPS_ENDPOINT = "http://localhost:42356/msi/token"
IDENTITY_HEADER = "the-identity-header-" + "x" * 32
IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"

# Every variable msal reads to tell the hosts apart.
HOST_VARIABLES = (
    "IDENTITY_ENDPOINT",
    "IDENTITY_HEADER",
    "IDENTITY_SERVER_THUMBPRINT",
    "MSI_ENDPOINT",
    "MSI_SECRET",
    "IMDS_ENDPOINT",
    "AZURE_POD_IDENTITY_AUTHORITY_HOST",
    "AZUREPS_HOST_ENVIRONMENT",
)

Answer = Callable[[requests.PreparedRequest], requests.Response]


def respond(
    request: requests.PreparedRequest,
    status: int,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """Build the response a real connection would have produced."""
    content = (
        body.encode()
        if isinstance(body, str)
        else b""
        if body is None
        else json.dumps(body).encode()
    )
    raw = HTTPResponse(
        body=io.BytesIO(content),
        headers={"Content-Type": "application/json", **(headers or {})},
        status=status,
        preload_content=False,
    )
    return requests.adapters.HTTPAdapter().build_response(request, raw)


def token(client_id: str = IDENTITY_CLIENT_ID, tenant: str = TENANT, **claims: Any) -> str:
    """An access token as the identity endpoint issues them: v1 claims, unsigned."""
    return fake_jwt(tid=tenant, appid=client_id, oid="identity-object-id", ver="1.0", **claims)


def app_service_answer(
    request: requests.PreparedRequest, access_token: str = token(), expires_in: int = 86400
) -> requests.Response:
    """What the App Service-style endpoint (Container Apps, Functions) answers with."""
    return respond(
        request,
        200,
        {
            "access_token": access_token,
            "expires_on": str(int(time.time()) + expires_in),
            "resource": parse_qs(urlsplit(request.url or "").query)["resource"][0],
            "token_type": "Bearer",
            "client_id": IDENTITY_CLIENT_ID,
        },
    )


def imds_answer(
    request: requests.PreparedRequest, access_token: str = token(), expires_in: int = 86400
) -> requests.Response:
    """What the instance metadata endpoint of a virtual machine answers with."""
    return respond(
        request,
        200,
        {
            "access_token": access_token,
            "expires_in": str(expires_in),
            "expires_on": str(int(time.time()) + expires_in),
            "resource": parse_qs(urlsplit(request.url or "").query)["resource"][0],
            "token_type": "Bearer",
        },
    )


class FakeEndpoint(requests.adapters.HTTPAdapter):
    """The identity endpoint: records every request and answers as scripted.

    Attributes:
        requests: Every request, in order.
        sends: The keyword arguments of every send, holding the timeout.
    """

    def __init__(self, answer: Answer) -> None:
        super().__init__()
        self.answer = answer
        self.requests: list[requests.PreparedRequest] = []
        self.sends: list[dict[str, Any]] = []

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        self.requests.append(request)
        self.sends.append(kwargs)
        return self.answer(request)

    @property
    def params(self) -> list[dict[str, str]]:
        """The query of every request, one value per name."""
        return [
            {name: values[0] for name, values in parse_qs(urlsplit(r.url or "").query).items()}
            for r in self.requests
        ]


@pytest.fixture(autouse=True)
def no_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test off Azure: no host variable set."""
    for name in HOST_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEndpoint]:
    """The fake endpoint, answering App Service style, mounted on the context's session."""
    fake = FakeEndpoint(app_service_answer)
    session: requests.Session | None = None

    def http_client() -> requests.Session:
        nonlocal session
        session = context_module._IdentitySession()
        session.mount("http://", fake)
        session.mount("https://", fake)
        return session

    monkeypatch.setattr(context_module, "_managed_identity_http_client", http_client)
    yield fake
    if session is not None:
        session.close()


@pytest.fixture
def container_apps(monkeypatch: pytest.MonkeyPatch, endpoint: FakeEndpoint) -> FakeEndpoint:
    """A Container Apps job: the App Service-style variables are set."""
    monkeypatch.setenv("IDENTITY_ENDPOINT", CONTAINER_APPS_ENDPOINT)
    monkeypatch.setenv("IDENTITY_HEADER", IDENTITY_HEADER)
    return endpoint


@pytest.fixture
def vm(endpoint: FakeEndpoint) -> FakeEndpoint:
    """A virtual machine: no host variable, the instance metadata endpoint answers."""
    endpoint.answer = imds_answer
    return endpoint


def identity_auth(**kwargs: Any) -> AuthContext:
    """A user-assigned managed identity context in the fake tenant, without a lookup."""
    kwargs.setdefault("tenant", Tenant(TENANT, COMMERCIAL))
    return AuthContext(managed_identity=True, client_id=IDENTITY_CLIENT_ID, **kwargs)


# ---------------------------------------------------------------------------- requests


def test_a_container_apps_job_asks_its_endpoint_with_the_header(
    container_apps: FakeEndpoint,
) -> None:
    auth = identity_auth()

    info = auth.acquire_token([VAULT_SCOPE])

    (request,) = container_apps.requests
    assert request.method == "GET"
    assert (request.url or "").startswith(CONTAINER_APPS_ENDPOINT + "?")
    assert request.headers["X-IDENTITY-HEADER"] == IDENTITY_HEADER
    assert container_apps.params == [
        {
            "api-version": "2019-08-01",
            "resource": "https://vault.azure.net",
            "client_id": IDENTITY_CLIENT_ID,
        }
    ]
    assert info.token == token()
    assert info.token_type == "Bearer"
    assert 86300 < info.expires_on - time.time() <= 86400


def test_a_virtual_machine_asks_the_instance_metadata_endpoint(vm: FakeEndpoint) -> None:
    identity_auth().acquire_token([VAULT_SCOPE])

    (request,) = vm.requests
    assert (request.url or "").startswith(IMDS + "?")
    assert request.headers["Metadata"] == "true"
    assert vm.params[0]["api-version"] == "2018-02-01"
    assert vm.params[0]["client_id"] == IDENTITY_CLIENT_ID
    assert vm.params[0]["resource"] == "https://vault.azure.net"


def test_a_system_assigned_identity_names_no_client_id(vm: FakeEndpoint) -> None:
    vm.answer = lambda request: imds_answer(request, token(client_id=SYSTEM_CLIENT_ID))
    auth = AuthContext(Tenant(TENANT, COMMERCIAL), managed_identity=True)
    assert auth.client_id is None

    auth.acquire_token([VAULT_SCOPE])

    assert "client_id" not in vm.params[0]
    # The token names the identity, so the context knows its client id from then on.
    assert auth.client_id == SYSTEM_CLIENT_ID
    assert auth.resolve_client_id() == SYSTEM_CLIENT_ID


def test_every_request_carries_the_endpoints_timeout(container_apps: FakeEndpoint) -> None:
    identity_auth().acquire_token([VAULT_SCOPE])

    assert container_apps.sends[0]["timeout"] == (2.0, 10.0)


def test_the_session_retries_a_throttled_or_failing_answer_but_never_a_connection() -> None:
    session = context_module._IdentitySession()
    adapter = session.get_adapter("http://localhost/")
    assert isinstance(adapter, requests.adapters.HTTPAdapter)
    retry = adapter.max_retries

    assert session.trust_env is False
    assert (retry.total, retry.connect, retry.read, retry.status) == (2, 0, 0, 2)
    assert set(retry.status_forcelist) == {429, 500, 502, 503, 504}
    assert retry.respect_retry_after_header is True
    assert retry.raise_on_status is False


@pytest.mark.parametrize(
    ("scope", "resource"),
    [
        (VAULT_SCOPE, "https://vault.azure.net"),
        (GOV_VAULT_SCOPE, "https://vault.usgovcloudapi.net"),
        ("https://management.core.windows.net//.default", "https://management.core.windows.net/"),
        ("https://graph.microsoft.us/.default", "https://graph.microsoft.us"),
    ],
)
def test_the_resource_is_the_scope_without_default(
    container_apps: FakeEndpoint, scope: str, resource: str
) -> None:
    identity_auth().acquire_token([scope])

    assert container_apps.params[0]["resource"] == resource


@pytest.mark.parametrize(
    "scopes",
    [
        [VAULT_SCOPE, GOV_VAULT_SCOPE],
        ["https://graph.microsoft.com/User.Read.All"],
        ["/.default"],
    ],
)
def test_anything_but_one_default_scope_is_refused(
    container_apps: FakeEndpoint, scopes: list[str]
) -> None:
    with pytest.raises(ValueError, match="one resource at a time"):
        identity_auth().acquire_token(scopes)
    assert container_apps.requests == []


# ---------------------------------------------------------------------------- the cache


def test_a_second_request_is_answered_from_the_cache(container_apps: FakeEndpoint) -> None:
    auth = identity_auth()

    first = auth.acquire_token([VAULT_SCOPE])
    second = auth.acquire_token([VAULT_SCOPE])
    auth.acquire_token_silently([VAULT_SCOPE])
    auth.login(client_id=None, scopes=[VAULT_SCOPE], pick_account=True)

    assert first.token == second.token
    assert len(container_apps.requests) == 1
    assert auth._issued_by_entra([VAULT_SCOPE], None) is False


def test_a_token_near_expiry_is_fetched_again(container_apps: FakeEndpoint) -> None:
    container_apps.answer = lambda request: app_service_answer(request, expires_in=200)
    auth = identity_auth()

    auth.acquire_token([VAULT_SCOPE])
    auth.acquire_token([VAULT_SCOPE])

    assert len(container_apps.requests) == 2


def test_a_claims_challenge_and_force_refresh_each_ask_again(
    container_apps: FakeEndpoint,
) -> None:
    auth = identity_auth()

    auth.acquire_token([VAULT_SCOPE])
    auth.acquire_token([VAULT_SCOPE], claims='{"access_token": {}}')
    auth.acquire_token([VAULT_SCOPE], force_refresh=True)
    auth.acquire_token([VAULT_SCOPE])

    assert len(container_apps.requests) == 3
    assert auth._issued_by_entra([VAULT_SCOPE], None) is False


def test_different_resources_get_different_tokens(container_apps: FakeEndpoint) -> None:
    auth = identity_auth()

    auth.acquire_token([VAULT_SCOPE])
    auth.acquire_token([GOV_VAULT_SCOPE])

    assert [p["resource"] for p in container_apps.params] == [
        "https://vault.azure.net",
        "https://vault.usgovcloudapi.net",
    ]


# ---------------------------------------------------------------------------- tenant and cloud


def test_a_tenant_is_looked_up_as_for_every_flow(
    container_apps: FakeEndpoint, fake_lookup: FakeLookup
) -> None:
    fake_lookup.cloud = US_GOV
    auth = AuthContext("contoso.us", managed_identity=True, client_id=IDENTITY_CLIENT_ID)

    assert fake_lookup.names == ["contoso.us"]
    assert auth.tenant.cloud is US_GOV
    assert auth.tenant.domain == "contoso.us"
    assert repr(auth).endswith("flow='managed_identity')")


def test_a_cloud_alone_needs_no_lookup_and_learns_the_tenant_from_the_token(
    container_apps: FakeEndpoint, fake_lookup: FakeLookup
) -> None:
    auth = AuthContext(cloud="USGov", managed_identity=True, client_id=IDENTITY_CLIENT_ID)

    assert fake_lookup.calls == []
    assert auth.tenant == Tenant(None, US_GOV)
    assert auth.tenant.id is None
    assert str(auth.tenant) == "<tenant not yet known, in USGov>"
    with pytest.raises(AuthError, match="not known yet"):
        _ = auth.tenant.guid
    with pytest.raises(AuthError, match="not known yet"):
        _ = auth.authority

    auth.acquire_token([GOV_VAULT_SCOPE])

    assert auth.tenant == Tenant(TENANT, US_GOV)
    assert auth.authority == f"https://login.microsoftonline.us/{TENANT}"


def test_a_client_is_built_on_a_cloud_before_any_token(container_apps: FakeEndpoint) -> None:
    auth = AuthContext(cloud=US_GOV, managed_identity=True, client_id=IDENTITY_CLIENT_ID)

    graph = GraphClient(auth)

    assert graph.resource == "https://graph.microsoft.us"
    assert graph.client_id == IDENTITY_CLIENT_ID
    assert container_apps.requests == []


def test_a_token_for_another_tenant_than_given_is_refused(container_apps: FakeEndpoint) -> None:
    container_apps.answer = lambda request: app_service_answer(request, token(tenant=OTHER_TENANT))
    auth = AuthContext("contoso.com", managed_identity=True, client_id=IDENTITY_CLIENT_ID)

    with pytest.raises(AuthError, match=f"for tenant {OTHER_TENANT}, but the context was built"):
        auth.acquire_token([VAULT_SCOPE])
    # The same every time: the token is in the cache, and still for the wrong tenant.
    with pytest.raises(AuthError, match="own tenant only"):
        auth.acquire_token([VAULT_SCOPE])


def test_an_sdk_request_for_another_tenant_is_refused(container_apps: FakeEndpoint) -> None:
    auth = identity_auth()

    assert auth.get_token(VAULT_SCOPE, tenant_id=TENANT).token == token()
    assert auth.get_token_info(VAULT_SCOPE, options={"tenant_id": TENANT.upper()}).token == token()
    with pytest.raises(AuthError, match=f"tenant {OTHER_TENANT} was asked for"):
        auth.get_token(VAULT_SCOPE, tenant_id=OTHER_TENANT)
    with pytest.raises(AuthError, match="own tenant only"):
        auth.get_token_info(VAULT_SCOPE, options={"tenant_id": OTHER_TENANT})


async def test_the_async_view_refuses_another_tenant_too(container_apps: FakeEndpoint) -> None:
    auth = identity_auth().aio

    first = await auth.get_token(VAULT_SCOPE, tenant_id=TENANT)
    second = await auth.acquire_token([VAULT_SCOPE])
    third = await auth.get_token_info(VAULT_SCOPE)

    assert first.token == second.token == third.token == token()
    assert len(container_apps.requests) == 1
    with pytest.raises(AuthError, match="own tenant only"):
        await auth.get_token(VAULT_SCOPE, tenant_id=OTHER_TENANT)
    with pytest.raises(AuthError, match="own tenant only"):
        await auth.get_token_info(VAULT_SCOPE, options={"tenant_id": OTHER_TENANT})


def test_get_tenant_context_serves_the_own_tenant_only(container_apps: FakeEndpoint) -> None:
    auth = identity_auth()

    assert auth.get_tenant_context(TENANT.upper()) is auth
    with pytest.raises(ValueError, match="own tenant only"):
        auth.get_tenant_context(OTHER_TENANT)
    with pytest.raises(ValueError, match="own tenant only"):
        auth.get_tenant_context("customer.example")


# ---------------------------------------------------------------------------- errors


def test_off_azure_the_flow_fails_at_once_as_unavailable(endpoint: FakeEndpoint) -> None:
    def refused(request: requests.PreparedRequest) -> requests.Response:
        raise requests.ConnectTimeout("timed out")

    endpoint.answer = refused

    with pytest.raises(ManagedIdentityUnavailable, match="no managed identity endpoint") as info:
        identity_auth().acquire_token([VAULT_SCOPE])

    assert "169.254.169.254 within 2 seconds" in str(info.value)
    assert "ConnectTimeout" in str(info.value)
    assert endpoint.sends[0]["timeout"] == (2.0, 10.0)


def test_an_answer_that_is_not_a_token_response_is_unavailable(endpoint: FakeEndpoint) -> None:
    endpoint.answer = lambda request: respond(request, 404, "<html>not found</html>")

    with pytest.raises(ManagedIdentityUnavailable, match="not a token response"):
        identity_auth().acquire_token([VAULT_SCOPE])


def test_an_advertised_endpoint_that_does_not_answer_is_a_network_error(
    container_apps: FakeEndpoint,
) -> None:
    def down(request: requests.PreparedRequest) -> requests.Response:
        raise requests.ConnectionError("connection refused")

    container_apps.answer = down

    with pytest.raises(NetworkError, match="App Service") as info:
        identity_auth().acquire_token([VAULT_SCOPE])

    assert "connection refused" in str(info.value)
    assert IDENTITY_HEADER not in str(info.value)


def test_a_wrong_client_id_on_container_apps_is_an_auth_error(
    container_apps: FakeEndpoint,
) -> None:
    container_apps.answer = lambda request: respond(
        request,
        400,
        {"statusCode": 400, "message": "No Managed Identity found for specified ClientId."},
    )

    with pytest.raises(AuthError) as info:
        identity_auth().acquire_token([VAULT_SCOPE])

    message = str(info.value)
    assert message.startswith(
        "The App Service (IDENTITY_ENDPOINT) managed identity endpoint refused"
    )
    assert (
        f"for https://vault.azure.net for the user-assigned identity {IDENTITY_CLIENT_ID}"
        in message
    )
    assert "No Managed Identity found for specified ClientId" in message
    assert IDENTITY_HEADER not in message
    assert info.value.error == "invalid_scope"  # msal's label for every App Service refusal
    assert not isinstance(info.value, ManagedIdentityUnavailable | NetworkError)


def test_a_wrong_client_id_on_a_virtual_machine_is_an_auth_error(vm: FakeEndpoint) -> None:
    vm.answer = lambda request: respond(
        request, 400, {"error": "invalid_request", "error_description": "Identity not found"}
    )

    with pytest.raises(AuthError, match="Identity not found") as info:
        AuthContext(Tenant(TENANT, COMMERCIAL), managed_identity=True).acquire_token([VAULT_SCOPE])

    assert "instance metadata (169.254.169.254)" in str(info.value)
    assert "for the system-assigned identity" in str(info.value)
    assert info.value.error == "invalid_request"


def test_an_endpoint_msal_cannot_use_is_an_auth_error(
    monkeypatch: pytest.MonkeyPatch, container_apps: FakeEndpoint
) -> None:
    # Service Fabric's endpoint must be HTTPS; msal refuses an HTTP one itself.
    monkeypatch.setenv("IDENTITY_SERVER_THUMBPRINT", "0" * 40)

    with pytest.raises(AuthError, match=r"cannot be used.*HTTPS") as info:
        identity_auth().acquire_token([VAULT_SCOPE])

    assert not isinstance(info.value, ManagedIdentityUnavailable | NetworkError)


# ---------------------------------------------------------------------------- the constructor


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({}, "needs tenant= or cloud="),
        ({"tenant": TENANT, "cloud": "Commercial"}, "not both"),
        ({"tenant": TENANT, "username": "admin@contoso.com"}, "username is not used"),
        ({"tenant": TENANT, "client_secret": "s3cret"}, "no secret or certificate"),
        ({"tenant": TENANT, "certificate_pfx": b"pfx"}, "no secret or certificate"),
        ({"tenant": TENANT, "broker": True}, "broker is not used"),
        ({"tenant": TENANT, "browser": "msedge"}, "browser is not used"),
        ({"tenant": TENANT, "before_browser_opens": print}, "before_browser_opens is not used"),
        ({"tenant": TENANT, "client_id": "not-a-guid"}, "client id is a GUID"),
        ({"cloud": "Mars"}, "Unknown cloud"),
    ],
)
def test_a_managed_identity_refuses_what_it_cannot_use(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        AuthContext(managed_identity=True, **kwargs)


def test_cloud_is_only_for_a_managed_identity() -> None:
    with pytest.raises(ValueError, match="cloud= is only for managed_identity=True"):
        AuthContext(TENANT, cloud="Commercial", username="admin@contoso.com")
    with pytest.raises(ValueError, match="tenant is required"):
        AuthContext()


def test_a_managed_identity_is_an_app_flow_without_a_credential(
    container_apps: FakeEndpoint,
) -> None:
    auth = identity_auth()

    assert auth.is_managed_identity is True
    assert auth.is_app_flow is True
    assert auth.username is None
    assert auth.home is auth
    assert auth.client_id == IDENTITY_CLIENT_ID
    assert auth._given.credential is None
    with pytest.raises(ValueError, match="App flows always request"):
        GraphClient(auth, scopes=["User.Read.All"])


# ---------------------------------------------------------------------------- the clients


async def test_the_graph_client_sends_the_identitys_token(container_apps: FakeEndpoint) -> None:
    recorder = Recorder([ok({"value": [{"id": TENANT}]})])
    auth = identity_auth()

    async with GraphClient(auth, transport=recorder.transport) as graph:
        organization = await graph.get_all("/organization")

    assert organization == [{"id": TENANT}]
    assert recorder.requests[0].headers["Authorization"] == f"Bearer {token()}"
    assert container_apps.params[0]["resource"] == "https://graph.microsoft.com"


async def test_the_arm_client_sends_the_identitys_token_in_its_cloud(
    container_apps: FakeEndpoint,
) -> None:
    recorder = Recorder([ok({"value": [{"subscriptionId": "sub"}]})])
    auth = AuthContext(cloud=US_GOV, managed_identity=True)

    async with ArmClient(auth, transport=recorder.transport) as arm:
        assert arm.client_id is None
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")

    assert subscriptions == [{"subscriptionId": "sub"}]
    assert recorder.urls()[0].startswith("https://management.usgovcloudapi.net/")
    assert container_apps.params[0]["resource"] == "https://management.usgovcloudapi.net"
    assert "client_id" not in container_apps.params[0]
    assert arm.client_id == IDENTITY_CLIENT_ID  # named by the token


async def test_a_clients_login_gets_the_token_silently(container_apps: FakeEndpoint) -> None:
    recorder = Recorder([])
    auth = identity_auth()

    async with GraphClient(auth, transport=recorder.transport) as graph:
        await graph.login(pick_account=True, fresh=True)

    assert len(container_apps.requests) == 1
    assert recorder.requests == []


def test_exchange_and_ipps_clients_route_as_an_app(container_apps: FakeEndpoint) -> None:
    auth = identity_auth()

    exchange = ExchangeClient(auth)
    ipps = IppsClient(auth)

    assert exchange.client_id == ipps.client_id == IDENTITY_CLIENT_ID
    assert exchange.scopes == ("https://outlook.office365.com/.default",)
    assert ipps.scopes == ("https://ps.compliance.protection.outlook.com/.default",)


def test_a_client_on_a_system_assigned_identity_learns_its_client_id(
    vm: FakeEndpoint,
) -> None:
    vm.answer = lambda request: imds_answer(request, token(client_id=SYSTEM_CLIENT_ID))
    auth = AuthContext(Tenant(TENANT, COMMERCIAL), managed_identity=True)
    graph = GraphClient(auth)

    assert graph.client_id is None
    auth.acquire_token(graph.scopes)
    assert graph.client_id == SYSTEM_CLIENT_ID


def test_the_blocking_graph_client_works_on_a_managed_identity(
    container_apps: FakeEndpoint,
) -> None:
    from azure_auth.sync import GraphClient as BlockingGraphClient

    recorder = Recorder([ok({"value": []})])
    with BlockingGraphClient(identity_auth(), transport=httpx2.MockTransport(recorder)) as graph:
        assert graph.get_all("/organization") == []

    assert recorder.requests[0].headers["Authorization"] == f"Bearer {token()}"


# ---------------------------------------------------------------------------- odd answers


def test_an_opaque_token_teaches_the_context_nothing(container_apps: FakeEndpoint) -> None:
    container_apps.answer = lambda request: app_service_answer(request, "opaque-token")
    auth = AuthContext(cloud="Commercial", managed_identity=True)

    info = auth.acquire_token([VAULT_SCOPE])

    assert info.token == "opaque-token"
    assert auth.tenant.id is None
    assert auth.client_id is None
    with pytest.raises(ValueError, match="not known until its first token"):
        auth.resolve_client_id()


def test_an_advertised_endpoint_that_stops_answering_is_a_network_error(
    container_apps: FakeEndpoint,
) -> None:
    def silent(request: requests.PreparedRequest) -> requests.Response:
        raise requests.ReadTimeout("read timed out")

    container_apps.answer = silent

    with pytest.raises(NetworkError, match="read timed out"):
        identity_auth().acquire_token([VAULT_SCOPE])


def test_the_real_session_is_what_the_client_sends_through() -> None:
    session = context_module._managed_identity_http_client()
    try:
        assert isinstance(session, context_module._IdentitySession)
    finally:
        session.close()
