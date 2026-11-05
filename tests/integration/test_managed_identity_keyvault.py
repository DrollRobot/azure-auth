"""The Azure Key Vault SDK, given a managed identity context as its credential.

The SDK learns the vault's sign-in from the challenge to its first request: the tenant and the
resource. Both reach the context through ``get_token``. The vault, the host's identity endpoint
and, for an application whose credential is the identity, Entra ID are faked at the
``requests`` adapter; the real SDK, msal and the context run.
"""

from __future__ import annotations

import io
import json
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from azure.core.pipeline.transport import AsyncioRequestsTransport
from azure.keyvault.secrets._shared import http_challenge_cache
from azure.keyvault.secrets.aio import SecretClient
from urllib3.response import HTTPResponse

from azure_auth import AuthContext, AuthError, KeyVaultError, Tenant
from azure_auth.auth import managed_identity as managed_identity_module
from azure_auth.clients.keyvault import KeyVaultClient
from azure_auth.clouds import COMMERCIAL, US_GOV, Cloud
from tests.http import fake_jwt
from tests.identity import JWT_BEARER, FakeEntra, MsalOver

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "66666666-7777-8888-9999-000000000000"
IDENTITY_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APP_CLIENT_ID = "12121212-3434-5656-7878-909090909090"
ENDPOINT = "http://localhost:42356/msi/token"
SECRET_VALUE = "the-secret-value"

VAULTS = {
    COMMERCIAL: ("https://identity-test.vault.azure.net", "https://vault.azure.net"),
    US_GOV: ("https://identity-test.vault.usgovcloudapi.net", "https://vault.usgovcloudapi.net"),
}


def respond(
    request: requests.PreparedRequest,
    status: int,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """Build the response a real connection would have produced."""
    content = b"" if body is None else json.dumps(body).encode()
    raw = HTTPResponse(
        body=io.BytesIO(content),
        headers={"Content-Type": "application/json", **(headers or {})},
        status=status,
        preload_content=False,
    )
    return requests.adapters.HTTPAdapter().build_response(request, raw)


class FakeVault(requests.adapters.HTTPAdapter):
    """A vault in one cloud: a challenge naming its tenant and resource, then the secret."""

    def __init__(self, cloud: Cloud, tenant: str = TENANT) -> None:
        super().__init__()
        self.cloud = cloud
        self.tenant = tenant
        self.tokens: list[str] = []

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        if "Authorization" not in request.headers:
            challenge = (
                f'Bearer authorization="{self.cloud.authority_host}/{self.tenant}", '
                f'resource="{VAULTS[self.cloud][1]}"'
            )
            return respond(request, 401, headers={"WWW-Authenticate": challenge})
        self.tokens.append(request.headers["Authorization"].removeprefix("Bearer "))
        name = urlsplit(request.url or "").path.split("/")[2]
        return respond(
            request,
            200,
            {"value": SECRET_VALUE, "id": f"{VAULTS[self.cloud][0]}/secrets/{name}/v1"},
        )


class FakeEndpoint(requests.adapters.HTTPAdapter):
    """The identity endpoint of a Container Apps job: one token per resource asked for."""

    def __init__(self) -> None:
        super().__init__()
        self.resources: list[str] = []

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        resource = parse_qs(urlsplit(request.url or "").query)["resource"][0]
        self.resources.append(resource)
        return respond(
            request,
            200,
            {
                "access_token": fake_jwt(tid=TENANT, appid=IDENTITY_CLIENT_ID, aud=resource),
                "expires_on": str(int(time.time()) + 86400),
                "resource": resource,
                "token_type": "Bearer",
            },
        )


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEndpoint]:
    """The host's identity endpoint, where msal sends the context's token requests.

    The SDK keeps each vault's challenge for the process, so every test starts without one,
    and leaves none behind for the other test modules.
    """
    http_challenge_cache.clear()
    monkeypatch.setenv("IDENTITY_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("IDENTITY_HEADER", "header")
    monkeypatch.delenv("IDENTITY_SERVER_THUMBPRINT", raising=False)
    fake = FakeEndpoint()
    session = managed_identity_module.IdentitySession()
    session.mount(ENDPOINT, fake)
    monkeypatch.setattr(managed_identity_module, "http_client", lambda: session)
    yield fake
    session.close()
    http_challenge_cache.clear()


async def read_secret(auth: AuthContext, vault: FakeVault) -> str:
    """Read one secret through the package's wrapper over the SDK, from the fake vault."""
    url = VAULTS[vault.cloud][0]
    with requests.Session() as session:
        session.mount(url, vault)
        transport = AsyncioRequestsTransport(session=session)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                "azure_auth.clients.keyvault.SecretClient",
                lambda *args, **kwargs: SecretClient(*args, transport=transport, **kwargs),
            )
            async with KeyVaultClient(auth, url) as client:
                return await client.get_secret("db-password")


@pytest.mark.parametrize("cloud", [COMMERCIAL, US_GOV], ids=["Commercial", "USGov"])
async def test_the_vaults_challenge_drives_the_token_request(
    endpoint: FakeEndpoint, cloud: Cloud
) -> None:
    vault = FakeVault(cloud)
    auth = AuthContext(Tenant(TENANT, cloud), managed_identity=True, client_id=IDENTITY_CLIENT_ID)

    value = await read_secret(auth, vault)

    assert value == SECRET_VALUE
    # The resource is the one the vault named, with no cloud table involved.
    assert endpoint.resources == [VAULTS[cloud][1]]
    assert vault.tokens == [fake_jwt(tid=TENANT, appid=IDENTITY_CLIENT_ID, aud=VAULTS[cloud][1])]


async def test_a_context_given_its_cloud_learns_the_tenant_from_the_vaults_token(
    endpoint: FakeEndpoint,
) -> None:
    auth = AuthContext(cloud=US_GOV, managed_identity=True, client_id=IDENTITY_CLIENT_ID)
    assert auth.tenant.id is None

    await read_secret(auth, FakeVault(US_GOV))

    assert auth.tenant == Tenant(TENANT, US_GOV)


async def test_a_vault_in_another_tenant_is_refused_with_the_reason(
    endpoint: FakeEndpoint,
) -> None:
    auth = AuthContext(Tenant(TENANT, COMMERCIAL), managed_identity=True)

    with pytest.raises((AuthError, KeyVaultError)) as info:
        await read_secret(auth, FakeVault(COMMERCIAL, tenant=OTHER_TENANT))

    # The SDK may wrap the credential's error; either way the reason is ours.
    error: BaseException | None = info.value
    while error is not None and not isinstance(error, AuthError):
        error = error.__cause__ or error.__context__
    assert isinstance(error, AuthError)
    assert f"tenant {OTHER_TENANT} was asked for" in str(error)


@pytest.fixture
def entra(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEntra]:
    """Entra ID, where the context's msal applications send their requests."""
    fake = FakeEntra()
    with requests.Session() as session:
        session.mount("https://", fake)
        monkeypatch.setattr("azure_auth.auth.context.msal", MsalOver(session))
        yield fake


def app_auth(cloud: Cloud = COMMERCIAL) -> AuthContext:
    """An application whose credential is the host's identity."""
    return AuthContext(
        Tenant(TENANT, cloud),
        client_id=APP_CLIENT_ID,
        managed_identity_client_id=IDENTITY_CLIENT_ID,
    )


@pytest.mark.parametrize("cloud", [COMMERCIAL, US_GOV], ids=["Commercial", "USGov"])
async def test_an_application_whose_credential_is_the_identity_reads_the_vault(
    endpoint: FakeEndpoint, entra: FakeEntra, cloud: Cloud
) -> None:
    vault = FakeVault(cloud)

    value = await read_secret(app_auth(cloud), vault)

    assert value == SECRET_VALUE
    # The identity's token is for the exchange, never for the vault...
    assert endpoint.resources == [cloud.token_exchange_audience]
    (form,) = entra.forms
    assert form["client_id"] == APP_CLIENT_ID
    assert form["client_assertion_type"] == JWT_BEARER
    assert form["client_assertion"] == fake_jwt(
        tid=TENANT, appid=IDENTITY_CLIENT_ID, aud=cloud.token_exchange_audience
    )
    # ...which gets the application's, for the resource the vault named.
    assert form["scope"] == f"{VAULTS[cloud][1]}/.default"
    assert vault.tokens == entra.tokens


async def test_a_vault_in_another_tenant_is_refused_for_the_application_too(
    endpoint: FakeEndpoint, entra: FakeEntra
) -> None:
    with pytest.raises((AuthError, KeyVaultError)) as info:
        await read_secret(app_auth(), FakeVault(COMMERCIAL, tenant=OTHER_TENANT))

    error: BaseException | None = info.value
    while error is not None and not isinstance(error, AuthError):
        error = error.__cause__ or error.__context__
    assert isinstance(error, AuthError)
    assert f"tenant {OTHER_TENANT} was asked for" in str(error)
    assert "multi-tenant applications are not supported" in str(error)
    assert {url.split("/")[3] for url in entra.token_urls} <= {TENANT}
