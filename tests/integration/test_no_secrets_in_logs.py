"""No secret reaches a log at DEBUG, through the real MSAL, Azure SDK and ``httpx`` code.

Each test runs the package against fake Entra ID, Key Vault and resource servers, captures
every record of every logger at DEBUG (:mod:`tests.logs`), and looks for each secret the run
handled: client secrets, client assertions, private keys, access and refresh tokens, Key
Vault secret values and secret cmdlet parameters.

MSAL and the Azure SDK send their requests through ``requests``; a session whose adapters
answer like the services stands in for the network. The resource clients get an ``httpx``
mock transport, as in the unit tests.
"""

from __future__ import annotations

import base64
import functools
import io
import json
import logging
import uuid
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import msal
import pytest
import requests
from azure.core.pipeline.transport import AsyncioRequestsTransport, RequestsTransport
from azure.keyvault.secrets import SecretClient as BlockingSecretClient
from azure.keyvault.secrets.aio import SecretClient
from urllib3.response import HTTPResponse

from azure_auth import AuthContext, ExchangeClient, GraphClient, GraphError, InvokeCommandError
from azure_auth.clients.keyvault import KeyVaultClient
from azure_auth.constants import GRAPH_CLI_CLIENT_ID
from azure_auth.sync.keyvault import KeyVaultClient as BlockingKeyVaultClient
from tests.certs import make_certificate
from tests.http import Recorder, fake_jwt, ok
from tests.logs import all_logs_at_debug, assert_no_secrets, find_secrets

pytestmark = [pytest.mark.integration, pytest.mark.acceptance, pytest.mark.anyio]

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "99999999-8888-7777-6666-555555555555"
USER = "admin@contoso.com"
LOGIN = "https://login.microsoftonline.com"
VAULT = "https://contoso.vault.azure.net"
GRAPH = "https://graph.microsoft.com"

CLIENT_SECRET = "client-secret-" + uuid.uuid4().hex
VAULT_SECRET = "vault-secret-" + uuid.uuid4().hex
CMDLET_PASSWORD = "cmdlet-password-" + uuid.uuid4().hex


def respond(
    request: requests.PreparedRequest,
    status: int,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """Build the response a real connection would have produced.

    Args:
        request: The request being answered.
        status: HTTP status code.
        body: JSON body, or ``None`` for none.
        headers: Response headers.

    Returns:
        The response.
    """
    content = b"" if body is None else json.dumps(body).encode()
    raw = HTTPResponse(
        body=io.BytesIO(content),
        headers={"Content-Type": "application/json", **(headers or {})},
        status=status,
        preload_content=False,
    )
    return requests.adapters.HTTPAdapter().build_response(request, raw)


class NoNetwork(requests.adapters.HTTPAdapter):
    """Fails any request that no fake answers, so nothing reaches a real host."""

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"unexpected request: {request.method} {request.url}")


def _b64(claims: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()


def id_token() -> str:
    """An ID token for the user, unsigned; MSAL reads it without checking the signature."""
    return fake_jwt(
        iss=f"{LOGIN}/{TENANT}/v2.0",
        aud=GRAPH_CLI_CLIENT_ID,
        tid=TENANT,
        oid="user-object-id",
        sub="user-subject",
        preferred_username=USER,
        iat=0,
        exp=4102444800,
    )


def client_info() -> str:
    """The ``client_info`` Entra ID returns to a user sign-in."""
    return _b64({"uid": "user-object-id", "utid": TENANT})


class FakeEntra(requests.adapters.HTTPAdapter):
    """Entra ID's discovery document and token endpoint, issuing new tokens every time.

    Attributes:
        access_tokens: Every access token issued.
        refresh_tokens: Every refresh token issued.
        forms: The form of every token request, holding the client secret or assertion.
    """

    def __init__(self) -> None:
        super().__init__()
        self.access_tokens: list[str] = []
        self.refresh_tokens: list[str] = []
        self.forms: list[dict[str, str]] = []

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        path = urlsplit(request.url or "").path
        if request.method == "GET" and path == f"/{TENANT}/v2.0/.well-known/openid-configuration":
            return respond(
                request,
                200,
                {
                    "authorization_endpoint": f"{LOGIN}/{TENANT}/oauth2/v2.0/authorize",
                    "token_endpoint": f"{LOGIN}/{TENANT}/oauth2/v2.0/token",
                    "issuer": f"{LOGIN}/{TENANT}/v2.0",
                },
            )
        if request.method == "GET" and path == "/common/discovery/instance":
            # MSAL asks which hosts are aliases of one another before it searches its cache.
            hosts = ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com"]
            discovery = f"{LOGIN}/common/v2.0/.well-known/openid-configuration"
            return respond(
                request,
                200,
                {
                    "tenant_discovery_endpoint": discovery,
                    "metadata": [
                        {
                            "preferred_network": hosts[0],
                            "preferred_cache": hosts[1],
                            "aliases": hosts,
                        }
                    ],
                },
            )
        if request.method == "POST" and path == f"/{TENANT}/oauth2/v2.0/token":
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            form = dict(parse_qsl(body or ""))
            self.forms.append(form)
            return respond(request, 200, self.issue(form))
        raise AssertionError(f"unexpected request to Entra ID: {request.method} {request.url}")

    def issue(self, form: dict[str, str]) -> dict[str, Any]:
        """Issue tokens for one token request.

        Args:
            form: The request's form.

        Returns:
            The token response: an access token, and for a user also a refresh token.
        """
        access = fake_jwt(tid=TENANT, uti=uuid.uuid4().hex)
        self.access_tokens.append(access)
        result: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        if form.get("grant_type") == "refresh_token":
            refresh = "refresh-" + uuid.uuid4().hex
            self.refresh_tokens.append(refresh)
            result |= {
                "refresh_token": refresh,
                "scope": form.get("scope", ""),
                "id_token": id_token(),
                "client_info": client_info(),
            }
        return result


class FakeVault(requests.adapters.HTTPAdapter):
    """A vault: a challenge for a request without a token, then the secret."""

    def send(self, request: requests.PreparedRequest, *args: Any, **kwargs: Any) -> Any:
        if "Authorization" not in request.headers:
            challenge = (
                f'Bearer authorization="{LOGIN}/{TENANT}", resource="https://vault.azure.net"'
            )
            return respond(request, 401, headers={"WWW-Authenticate": challenge})
        name = urlsplit(request.url or "").path.split("/")[2]
        return respond(
            request,
            200,
            {
                "value": VAULT_SECRET,
                "id": f"{VAULT}/secrets/{name}/{VERSION}",
                "attributes": {"enabled": True},
            },
        )


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


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> Iterator[requests.Session]:
    """A session that reaches only the fake Entra ID and vault; MSAL sends through it."""
    with requests.Session() as session:
        session.mount("https://", NoNetwork())
        session.mount("http://", NoNetwork())
        session.mount(f"{VAULT}/", FakeVault())
        monkeypatch.setattr("azure_auth.auth.context.msal", MsalOver(session))
        yield session


@pytest.fixture
def entra(session: requests.Session) -> FakeEntra:
    fake = FakeEntra()
    session.mount(f"{LOGIN}/", fake)
    return fake


def app_auth(**credential: Any) -> AuthContext:
    """An app-flow context for the fake tenant; its GUID and cloud need no lookup."""
    return AuthContext(TENANT, cloud="Commercial", client_id=CLIENT_ID, **credential)


def app_secrets(entra: FakeEntra) -> dict[str, list[str]]:
    """The secrets of a client-secret app flow: the secret and every token issued."""
    return {"client secret": [CLIENT_SECRET], "access token": entra.access_tokens}


# ---------------------------------------------------------------------------- Key Vault

# The SDK learns the vault's sign-in from a challenge to its first request, and keeps it for
# the process. Later reads send the token at once, which takes another path through the SDK's
# logging, so each test reads twice: once by name, then by version.
VERSION = "0123456789abcdef0123456789abcdef"


async def read_vault_secret(session: requests.Session, **sdk_options: Any) -> list[str]:
    """Read a secret twice with the asynchronous client, as an app with a client secret.

    Args:
        session: The session the SDK sends through.
        **sdk_options: Passed to the SDK's ``SecretClient``.

    Returns:
        The values read.
    """
    transport = AsyncioRequestsTransport(session=session)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            "azure_auth.clients.keyvault.SecretClient",
            functools.partial(SecretClient, transport=transport, **sdk_options),
        )
        async with KeyVaultClient(app_auth(client_secret=CLIENT_SECRET), VAULT) as vault:
            return [
                await vault.get_secret("db-password"),
                await vault.get_secret("db-password", VERSION),
            ]


async def test_reading_a_vault_secret_logs_no_secret(
    session: requests.Session, entra: FakeEntra
) -> None:
    with all_logs_at_debug() as records:
        values = await read_vault_secret(session)
    assert values == [VAULT_SECRET, VAULT_SECRET]
    assert_no_secrets(records, {"Key Vault secret value": [VAULT_SECRET], **app_secrets(entra)})


def test_the_blocking_client_reads_a_vault_secret_without_logging_it(
    session: requests.Session, entra: FakeEntra, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "azure_auth._sync.keyvault.SecretClient",
        functools.partial(BlockingSecretClient, transport=RequestsTransport(session=session)),
    )
    auth = app_auth(client_secret=CLIENT_SECRET)
    with all_logs_at_debug() as records, BlockingKeyVaultClient(auth, VAULT) as vault:
        values = [vault.get_secret("db-password"), vault.get_secret("db-password", VERSION)]
    assert values == [VAULT_SECRET, VAULT_SECRET]
    assert_no_secrets(records, {"Key Vault secret value": [VAULT_SECRET], **app_secrets(entra)})


async def test_the_check_finds_what_the_sdk_network_trace_logs(
    session: requests.Session, entra: FakeEntra
) -> None:
    """With the SDK's network trace on, the secret and the token are in the log, and found.

    ``logging_enable=True`` makes the Azure SDK log every request and response in full at
    DEBUG: the ``Authorization`` header and the body holding the secret. This proves the
    capture and the search see such a leak, so the tests above passing means something.
    """
    with all_logs_at_debug() as records:
        await read_vault_secret(session, logging_enable=True)
    found = find_secrets(records, {"Key Vault secret value": [VAULT_SECRET], **app_secrets(entra)})
    assert {"Key Vault secret value", "access token"} <= found.keys()


# ---------------------------------------------------------------------------- MSAL


async def test_a_certificate_sign_in_logs_neither_key_nor_assertion(
    session: requests.Session, entra: FakeEntra
) -> None:
    certificate = make_certificate()
    recorder = Recorder([ok({"id": "1"})])
    with all_logs_at_debug() as records:
        auth = app_auth(
            certificate_pem=certificate.certificate_pem,
            private_key_pem=certificate.private_key_pem,
        )
        async with GraphClient(auth, transport=recorder.transport) as graph:
            await graph.get("/organization")
    assertions = [form["client_assertion"] for form in entra.forms]
    key_lines = [line for line in certificate.private_key_pem.splitlines() if "-----" not in line]
    assert assertions
    assert_no_secrets(
        records,
        {
            "client assertion": assertions,
            "private key": key_lines,
            "access token": entra.access_tokens,
        },
    )


async def test_refreshing_a_user_token_logs_no_token(
    session: requests.Session, entra: FakeEntra
) -> None:
    """A cached refresh token is redeemed for a new access token, and neither is logged.

    The cache is seeded the way a sign-in fills it, with a token for another scope, so the
    request needs MSAL to redeem the refresh token.
    """
    seeded_access = fake_jwt(tid=TENANT, uti=uuid.uuid4().hex)
    seeded_refresh = "refresh-" + uuid.uuid4().hex
    recorder = Recorder([ok({"id": "1"})])
    with all_logs_at_debug() as records:
        auth = AuthContext(TENANT, cloud="Commercial", username=USER)
        auth._cache.add(
            {
                "client_id": GRAPH_CLI_CLIENT_ID,
                "scope": [f"{GRAPH}/User.Read"],
                "token_endpoint": f"{LOGIN}/{TENANT}/oauth2/v2.0/token",
                "response": {
                    "access_token": seeded_access,
                    "refresh_token": seeded_refresh,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": id_token(),
                    "client_info": client_info(),
                },
                "data": {},
            }
        )
        async with GraphClient(auth, transport=recorder.transport) as graph:
            await graph.get("/me")
    assert [form["grant_type"] for form in entra.forms] == ["refresh_token"]
    assert_no_secrets(
        records,
        {
            "refresh token": [seeded_refresh, *entra.refresh_tokens],
            "access token": [seeded_access, *entra.access_tokens],
        },
    )


# ---------------------------------------------------------------------------- resource clients


async def test_resource_requests_retries_and_errors_log_no_token(
    session: requests.Session, entra: FakeEntra, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request, a retry after a 401 and after a 429, and an error the caller logs.

    The caller logs the error the way an application would, with its traceback, so the
    exception must not carry the token either.
    """

    async def no_wait(delay: float) -> None:
        pass

    monkeypatch.setattr("azure_auth.clients.base.asyncio.sleep", no_wait)
    recorder = Recorder(
        [
            ok({"id": "1"}),
            ok({"error": {"code": "InvalidAuthenticationToken"}}, status=401),
            ok({"id": "1"}),
            ok(status=429, headers={"Retry-After": "0"}),
            ok({"id": "1"}),
            ok({"error": {"code": "Authorization_RequestDenied"}}, status=403),
        ]
    )
    with all_logs_at_debug() as records:
        async with GraphClient(
            app_auth(client_secret=CLIENT_SECRET), transport=recorder.transport
        ) as graph:
            await graph.get("/organization")
            await graph.get("/organization")
            await graph.get("/organization")
            try:
                await graph.get("/organization")
            except GraphError:
                logging.getLogger("application").exception("Graph refused the request")
    assert len(entra.access_tokens) == 2  # the 401 had a new token fetched
    assert_no_secrets(records, app_secrets(entra))


async def test_a_secret_cmdlet_parameter_is_not_logged(
    session: requests.Session, entra: FakeEntra
) -> None:
    """A password passed to a cmdlet is in neither the log nor the error the caller logs."""
    recorder = Recorder(
        [
            ok({"value": []}),
            ok({"error": {"code": "BadRequest", "message": "The password is too short."}}, 400),
        ]
    )
    with all_logs_at_debug() as records:
        async with ExchangeClient(
            app_auth(client_secret=CLIENT_SECRET), transport=recorder.transport
        ) as exchange:
            await exchange.run("Set-Mailbox", Identity=USER, Password=CMDLET_PASSWORD)
            try:
                await exchange.run("Set-Mailbox", Identity=USER, Password=CMDLET_PASSWORD)
            except InvokeCommandError:
                logging.getLogger("application").exception("Exchange refused the cmdlet")
    assert CMDLET_PASSWORD in recorder.requests[0].content.decode()
    assert_no_secrets(records, {"cmdlet password": [CMDLET_PASSWORD], **app_secrets(entra)})
