"""Fakes for the host's managed identity endpoint and for Entra ID's token endpoint.

Both are ``requests`` adapters, so the real msal runs in the middle and each test sees the exact
request the service would get. The identity endpoint is reached through the session
``azure_auth.auth.managed_identity.http_client`` returns; Entra ID through the session msal's
applications are given (:class:`MsalOver`). The host is described through its environment
variables, as msal reads them.
"""

from __future__ import annotations

import io
import json
import time
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlsplit

import msal
import requests
from urllib3.response import HTTPResponse

from tests.http import fake_jwt

TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "66666666-7777-8888-9999-000000000000"
IDENTITY_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APP_CLIENT_ID = "12121212-3434-5656-7878-909090909090"
CONTAINER_APPS_ENDPOINT = "http://localhost:42356/msi/token"
IDENTITY_HEADER = "the-identity-header-" + "x" * 32
IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

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
EntraAnswer = Callable[[requests.PreparedRequest, dict[str, str]], requests.Response]


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


class FakeEntra(requests.adapters.HTTPAdapter):
    """Entra ID in every cloud, for an application's sign-in.

    It answers msal's discovery of a tenant's endpoints, and issues a new token for every
    client credentials request, unless :attr:`answer` is scripted otherwise.

    Attributes:
        answer: Answers a token request, given the request and its form.
        forms: The form of every token request, holding the client assertion.
        token_urls: The URL of every token request.
        tokens: Every access token issued.
    """

    def __init__(self) -> None:
        super().__init__()
        self.answer: EntraAnswer = self.issue
        self.forms: list[dict[str, str]] = []
        self.token_urls: list[str] = []
        self.tokens: list[str] = []

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        url = urlsplit(request.url or "")
        host = f"https://{url.netloc}"
        if request.method == "GET" and url.path.endswith("/v2.0/.well-known/openid-configuration"):
            tenant = url.path.split("/")[1]
            return respond(
                request,
                200,
                {
                    "authorization_endpoint": f"{host}/{tenant}/oauth2/v2.0/authorize",
                    "token_endpoint": f"{host}/{tenant}/oauth2/v2.0/token",
                    "issuer": f"{host}/{tenant}/v2.0",
                },
            )
        if request.method == "GET" and url.path == "/common/discovery/instance":
            discovery = f"{host}/common/v2.0/.well-known/openid-configuration"
            return respond(
                request,
                200,
                {
                    "tenant_discovery_endpoint": discovery,
                    "metadata": [
                        {
                            "preferred_network": url.netloc,
                            "preferred_cache": url.netloc,
                            "aliases": [url.netloc],
                        }
                    ],
                },
            )
        if request.method == "POST" and url.path.endswith("/oauth2/v2.0/token"):
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            form = dict(parse_qsl(body or ""))
            self.forms.append(form)
            self.token_urls.append(f"{host}{url.path}")
            return self.answer(request, form)
        raise AssertionError(f"unexpected request to Entra ID: {request.method} {request.url}")

    def issue(self, request: requests.PreparedRequest, form: dict[str, str]) -> requests.Response:
        """Issue a new application token for the tenant the request went to."""
        tenant = urlsplit(request.url or "").path.split("/")[1]
        access = fake_jwt(tid=tenant, appid=form.get("client_id"), uti=uuid.uuid4().hex)
        self.tokens.append(access)
        return respond(
            request, 200, {"access_token": access, "token_type": "Bearer", "expires_in": 3599}
        )


def entra_refusal(description: str, *, error: str = "invalid_client", code: int) -> EntraAnswer:
    """Script Entra ID's refusal of a token request, as its token endpoint sends it."""

    def answer(request: requests.PreparedRequest, form: dict[str, str]) -> requests.Response:
        return respond(
            request,
            400 if error != "invalid_client" else 401,
            {
                "error": error,
                "error_description": description,
                "error_codes": [code],
                "trace_id": "trace-id",
                "correlation_id": "correlation-id",
            },
        )

    return answer


class MsalOver:
    """The ``msal`` module, with every application sending its requests through one session."""

    def __init__(self, session: requests.Session) -> None:
        self._session = session

    def __getattr__(self, name: str) -> Any:
        return getattr(msal, name)

    def PublicClientApplication(self, *args: Any, **kwargs: Any) -> Any:
        return msal.PublicClientApplication(*args, http_client=self._session, **kwargs)

    def ConfidentialClientApplication(self, *args: Any, **kwargs: Any) -> Any:
        return msal.ConfidentialClientApplication(*args, http_client=self._session, **kwargs)
