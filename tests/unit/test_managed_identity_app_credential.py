"""Unit tests for an application whose credential is the host's managed identity.

The identity endpoint and Entra ID are both faked at the ``requests`` adapter
(``tests/identity.py``), with the real msal managed identity client and confidential client
application in the middle, so each test sees the exact requests the two services would get.
"""

from __future__ import annotations

from typing import Any

import pytest
import requests
from msal import TokenCache

from azure_auth import (
    AuthContext,
    AuthError,
    GraphClient,
    ManagedIdentityUnavailable,
    NetworkError,
    Tenant,
)
from azure_auth.auth.credentials import ManagedIdentityAssertionCredential
from azure_auth.clouds import CHINA, COMMERCIAL, US_GOV, US_GOV_DOD, Cloud
from tests.http import Recorder, ok
from tests.identity import (
    APP_CLIENT_ID,
    CONTAINER_APPS_ENDPOINT,
    IDENTITY_CLIENT_ID,
    IDENTITY_HEADER,
    IMDS,
    JWT_BEARER,
    OTHER_TENANT,
    TENANT,
    FakeEndpoint,
    FakeEntra,
    respond,
    token,
)

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

EXCHANGE = "api://AzureADTokenExchange"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
VAULT_SCOPE = "https://vault.azure.net/.default"
ARM_SCOPE = "https://management.azure.com/.default"
TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# Entra's answers to an assertion no federated credential of the application matches: when
# the application has some, but none for the identity (Microsoft's documented text), and when it
# has none at all (measured 2026-11-05; the application's name changed).
NO_MATCH = (
    "AADSTS70021: No matching federated identity record found for presented assertion. "
    f"Assertion Issuer: 'https://login.microsoftonline.com/{TENANT}/v2.0'. Assertion Subject: "
    f"'identity-object-id'. Assertion Audience: '{EXCHANGE}'. Trace ID: trace-id "
    "Correlation ID: correlation-id Timestamp: 2026-11-05 12:00:00Z"
)
NONE_CONFIGURED = (
    f"AADSTS70025: The client '{APP_CLIENT_ID}'(Test application) has no configured federated "
    "identity credentials. Trace ID: trace-id Correlation ID: correlation-id Timestamp: "
    "2026-11-05 12:00:00Z"
)


def app_auth(cloud: Cloud = COMMERCIAL, **kwargs: Any) -> AuthContext:
    """An application in the fake tenant whose credential is the test identity, no lookup."""
    kwargs.setdefault("client_id", APP_CLIENT_ID)
    return AuthContext(
        Tenant(TENANT, cloud), managed_identity_client_id=IDENTITY_CLIENT_ID, **kwargs
    )


def refuse_with(status: int, body: dict[str, Any]) -> Any:
    """Script an answer of Entra ID's token endpoint."""

    def answer(request: requests.PreparedRequest, form: dict[str, str]) -> requests.Response:
        return respond(request, status, body)

    return answer


# ---------------------------------------------------------------------------- the exchange


def test_a_container_apps_job_presents_its_identitys_token_to_entra(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    info = app_auth().acquire_token([GRAPH_SCOPE])

    (request,) = container_apps.requests
    assert (request.url or "").startswith(CONTAINER_APPS_ENDPOINT + "?")
    assert request.headers["X-IDENTITY-HEADER"] == IDENTITY_HEADER
    assert container_apps.params == [
        {"api-version": "2019-08-01", "resource": EXCHANGE, "client_id": IDENTITY_CLIENT_ID}
    ]
    (form,) = entra.forms
    assert entra.token_urls == [TOKEN_ENDPOINT]
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == APP_CLIENT_ID
    assert form["scope"] == GRAPH_SCOPE
    assert form["client_assertion_type"] == JWT_BEARER
    assert form["client_assertion"] == token()
    assert info.token == entra.tokens[0]


def test_a_virtual_machine_asks_the_instance_metadata_endpoint(
    vm: FakeEndpoint, entra: FakeEntra
) -> None:
    app_auth().acquire_token([GRAPH_SCOPE])

    (request,) = vm.requests
    assert (request.url or "").startswith(IMDS + "?")
    assert vm.params[0]["resource"] == EXCHANGE
    assert vm.params[0]["client_id"] == IDENTITY_CLIENT_ID
    assert entra.forms[0]["client_assertion"] == token()


@pytest.mark.parametrize(
    ("cloud", "audience"),
    [
        (COMMERCIAL, "api://AzureADTokenExchange"),
        (US_GOV, "api://AzureADTokenExchangeUSGov"),
        (US_GOV_DOD, "api://AzureADTokenExchangeUSGov"),
        (CHINA, "api://AzureADTokenExchangeChina"),
    ],
    ids=lambda value: value.name if isinstance(value, Cloud) else None,
)
def test_the_identitys_token_is_for_the_clouds_exchange_audience(
    container_apps: FakeEndpoint, entra: FakeEntra, cloud: Cloud, audience: str
) -> None:
    app_auth(cloud).acquire_token([f"{cloud.arm}/.default"])

    assert container_apps.params[0]["resource"] == audience
    assert entra.token_urls == [f"{cloud.authority_host}/{TENANT}/oauth2/v2.0/token"]


def test_the_identity_client_id_is_used_in_its_canonical_spelling(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    auth = AuthContext(
        Tenant(TENANT, COMMERCIAL),
        client_id=APP_CLIENT_ID,
        managed_identity_client_id=IDENTITY_CLIENT_ID.upper(),
    )

    auth.acquire_token([GRAPH_SCOPE])

    assert container_apps.params[0]["client_id"] == IDENTITY_CLIENT_ID


def test_a_token_up_front_comes_from_entra_now(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    auth = app_auth()

    info = auth.acquire_token_silently([VAULT_SCOPE])

    assert info.token == entra.tokens[0]
    assert len(container_apps.requests) == len(entra.forms) == 1
    assert auth._issued_by_entra([VAULT_SCOPE], None) is True


# ---------------------------------------------------------------------------- the caches


def test_one_identity_token_serves_every_resource(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    auth = app_auth()

    for scope in (GRAPH_SCOPE, VAULT_SCOPE, ARM_SCOPE, VAULT_SCOPE):
        auth.acquire_token([scope])

    assert len(container_apps.requests) == 1
    assert [form["scope"] for form in entra.forms] == [GRAPH_SCOPE, VAULT_SCOPE, ARM_SCOPE]
    assert {form["client_assertion"] for form in entra.forms} == {token()}


def test_a_claims_challenge_and_force_refresh_ask_entra_again(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    auth = app_auth()

    auth.acquire_token([GRAPH_SCOPE])
    auth.acquire_token([GRAPH_SCOPE], claims='{"access_token": {"nbf": {"essential": true}}}')
    auth.acquire_token([GRAPH_SCOPE], force_refresh=True)

    assert len(entra.forms) == 3
    assert "nbf" in entra.forms[1]["claims"]
    # The identity's token is still good, so the endpoint is asked once.
    assert len(container_apps.requests) == 1


def test_the_identitys_token_stays_out_of_the_contexts_cache(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    auth = app_auth()

    auth.acquire_token([GRAPH_SCOPE])

    cached = [
        entry["secret"]
        for entry in auth._given.cache.search(TokenCache.CredentialType.ACCESS_TOKEN)
    ]
    assert cached == entra.tokens
    assert token() not in cached


# ---------------------------------------------------------------------------- errors


def test_off_azure_it_is_unavailable_and_nothing_reaches_entra(
    endpoint: FakeEndpoint, entra: FakeEntra
) -> None:
    def refused(request: requests.PreparedRequest) -> requests.Response:
        raise requests.ConnectTimeout("timed out")

    endpoint.answer = refused

    with pytest.raises(ManagedIdentityUnavailable, match="no managed identity endpoint"):
        app_auth().acquire_token_silently([GRAPH_SCOPE])

    assert entra.forms == []


def test_an_identity_the_host_does_not_have_is_refused_by_the_endpoint(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    container_apps.answer = lambda request: respond(
        request,
        400,
        {"statusCode": 400, "message": "No Managed Identity found for specified ClientId."},
    )

    with pytest.raises(AuthError) as info:
        app_auth().acquire_token([GRAPH_SCOPE])

    message = str(info.value)
    assert f"refused a token for {EXCHANGE} for the user-assigned identity" in message
    assert IDENTITY_CLIENT_ID in message
    assert "No Managed Identity found" in message
    assert not isinstance(info.value, ManagedIdentityUnavailable | NetworkError)
    assert entra.forms == []


def test_an_advertised_endpoint_that_does_not_answer_is_a_network_error(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    def down(request: requests.PreparedRequest) -> requests.Response:
        raise requests.ConnectionError("connection refused")

    container_apps.answer = down

    with pytest.raises(NetworkError, match="connection refused"):
        app_auth().acquire_token([GRAPH_SCOPE])

    assert entra.forms == []


@pytest.mark.parametrize(
    ("status", "error", "description", "code"),
    [
        (400, "invalid_request", NO_MATCH, 70021),
        (401, "invalid_client", NONE_CONFIGURED, 70025),
    ],
    ids=["no matching record", "none configured"],
)
def test_entra_refusing_the_exchange_gives_entras_reason_and_whose_token_it_was(
    container_apps: FakeEndpoint,
    entra: FakeEntra,
    status: int,
    error: str,
    description: str,
    code: int,
) -> None:
    entra.answer = refuse_with(
        status,
        {
            "error": error,
            "error_description": description,
            "error_codes": [code],
            "trace_id": "trace-id",
            "correlation_id": "correlation-id",
        },
    )

    with pytest.raises(AuthError) as info:
        app_auth().acquire_token_silently([GRAPH_SCOPE])

    message = str(info.value)
    assert message.startswith(f"{error}: AADSTS{code}: ")
    assert message.endswith(
        f"12:00:00Z. Application {APP_CLIENT_ID} presented the token of the user-assigned "
        f"managed identity {IDENTITY_CLIENT_ID} as its credential."
    )
    assert info.value.error_codes == frozenset({code})
    assert info.value.correlation_id == "correlation-id"
    assert token() not in message
    # Asked once: no retry, and no other flow.
    assert len(entra.forms) == 1
    assert len(container_apps.requests) == 1


def test_an_app_flow_without_a_client_id_is_refused(container_apps: FakeEndpoint) -> None:
    auth = AuthContext(Tenant(TENANT, COMMERCIAL), managed_identity_client_id=IDENTITY_CLIENT_ID)

    with pytest.raises(ValueError, match="App flows need a client_id"):
        auth.acquire_token([GRAPH_SCOPE])
    assert container_apps.requests == []


# ---------------------------------------------------------------------------- tenants


def test_only_its_own_tenant_is_served(container_apps: FakeEndpoint, entra: FakeEntra) -> None:
    auth = app_auth()

    assert auth.get_tenant_context(TENANT.upper()) is auth
    with pytest.raises(ValueError, match="own tenant only; multi-tenant applications are not"):
        auth.get_tenant_context(OTHER_TENANT)
    with pytest.raises(ValueError, match="own tenant only"):
        auth.get_tenant_context("customer.example")
    assert entra.forms == []


def test_an_sdk_request_for_another_tenant_is_refused(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    auth = app_auth()

    assert auth.get_token(VAULT_SCOPE, tenant_id=TENANT).token == entra.tokens[0]
    with pytest.raises(AuthError, match=f"tenant {OTHER_TENANT} was asked for.*own tenant only"):
        auth.get_token(VAULT_SCOPE, tenant_id=OTHER_TENANT)
    with pytest.raises(AuthError, match="own tenant only"):
        auth.get_token_info(VAULT_SCOPE, options={"tenant_id": OTHER_TENANT})
    # Every token request went to the context's own tenant.
    assert set(entra.token_urls) == {TOKEN_ENDPOINT}


def test_the_multi_tenant_stub_reaches_another_tenant_with_the_same_assertion(
    monkeypatch: pytest.MonkeyPatch, container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    """Multi-tenant applications are not supported yet; this keeps their stub working."""
    monkeypatch.setattr(ManagedIdentityAssertionCredential, "other_tenants", True)
    auth = app_auth()

    customer = auth.get_tenant_context(OTHER_TENANT)
    auth.acquire_token([GRAPH_SCOPE])
    customer.acquire_token([GRAPH_SCOPE])

    assert customer is not auth
    assert customer.home is auth
    assert entra.token_urls == [
        TOKEN_ENDPOINT,
        f"https://login.microsoftonline.com/{OTHER_TENANT}/oauth2/v2.0/token",
    ]
    assert {form["client_assertion"] for form in entra.forms} == {token()}
    assert len(container_apps.requests) == 1


# ---------------------------------------------------------------------------- the constructor


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"managed_identity_client_id": "not-a-guid"}, r"client id \(a GUID\)"),
        ({"client_secret": "s3cret"}, "Give only one of"),
        ({"certificate_thumbprint": "A" * 40}, "Give only one of"),
        ({"managed_identity": True}, "is an application's credential"),
        ({"cloud": "Commercial"}, "cloud= is only for managed_identity=True"),
        ({"username": "admin@contoso.com"}, "username is not used for app flows"),
        ({"broker": True}, "broker is only available for user flows"),
        ({"browser": "msedge"}, "browser is only available for user flows"),
        ({"before_browser_opens": print}, "before_browser_opens is only available"),
    ],
)
def test_the_constructor_refuses_what_the_credential_cannot_use(
    kwargs: dict[str, Any], match: str
) -> None:
    kwargs.setdefault("managed_identity_client_id", IDENTITY_CLIENT_ID)
    with pytest.raises(ValueError, match=match):
        AuthContext(TENANT, client_id=APP_CLIENT_ID, **kwargs)


def test_it_is_an_app_flow(container_apps: FakeEndpoint) -> None:
    auth = app_auth()

    assert auth.is_app_flow is True
    assert auth.is_managed_identity is False
    assert auth.client_id == APP_CLIENT_ID
    assert auth.username is None
    assert repr(auth).endswith("flow='app')")
    assert repr(auth._given.credential) == (
        f"ManagedIdentityAssertionCredential(identity_client_id='{IDENTITY_CLIENT_ID}')"
    )
    with pytest.raises(ValueError, match="App flows always request"):
        GraphClient(auth, scopes=["User.Read.All"])
    assert container_apps.requests == []


# ---------------------------------------------------------------------------- the clients


async def test_the_graph_client_sends_the_applications_token(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    recorder = Recorder([ok({"value": [{"id": TENANT}]})])

    async with GraphClient(app_auth(), transport=recorder.transport) as graph:
        assert graph.client_id == APP_CLIENT_ID
        organization = await graph.get_all("/organization")

    assert organization == [{"id": TENANT}]
    assert recorder.requests[0].headers["Authorization"] == f"Bearer {entra.tokens[0]}"
    assert entra.forms[0]["scope"] == GRAPH_SCOPE
    assert container_apps.params[0]["resource"] == EXCHANGE


async def test_a_clients_login_gets_the_token_now(
    container_apps: FakeEndpoint, entra: FakeEntra
) -> None:
    recorder = Recorder([])

    async with GraphClient(app_auth(), transport=recorder.transport) as graph:
        await graph.login(fresh=True)

    assert len(entra.forms) == 1
    assert recorder.requests == []
