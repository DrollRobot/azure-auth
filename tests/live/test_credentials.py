"""App-only sign-in with a certificate, against the real token endpoint."""

from __future__ import annotations

import secrets
from pathlib import Path

import httpx
import pytest

from azure_auth import AuthContext, AuthError, ExchangeClient, GraphClient, IppsClient
from azure_auth.sync import GraphClient as BlockingGraphClient
from tests.certs import make_certificate
from tests.live.support import (
    APP_CLIENT_ID,
    MACHINE_THUMBPRINT,
    TENANT,
    live_app_auth,
    needs_app,
    needs_exchange,
    needs_ipps,
    needs_machine_certificate,
    sign_in_once_accepted,
    token_claims,
    upload_temporary_certificate,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_app
async def test_app_flow_with_a_store_certificate() -> None:
    auth = live_app_auth()
    async with GraphClient(auth) as graph:
        organization = await graph.get_all("/organization")
    assert organization
    # Which algorithm Entra ID accepted for this key is worth knowing; see plan section 4.
    print(f"client assertion algorithm in use: {auth._credential.algorithm}")  # type: ignore[union-attr]


@needs_machine_certificate
async def test_app_flow_with_a_local_machine_certificate() -> None:
    """A certificate in ``LocalMachine\\My`` signs in like one in ``CurrentUser\\My``."""
    auth = AuthContext(
        TENANT,
        client_id=APP_CLIENT_ID,
        certificate_thumbprint=MACHINE_THUMBPRINT,
        certificate_store="LocalMachine",
    )
    async with GraphClient(auth) as graph:
        organization = await graph.get_all("/organization")
    assert organization


@needs_app
@pytest.mark.destructive_remote
@pytest.mark.parametrize("form", ["pem", "pfx"])
async def test_app_flow_with_a_certificate_file(form: str) -> None:
    """A certificate given as PEM text or as a password-protected PFX archive signs in.

    The certificate is made for the test and uploaded to the application, which is why the
    test is ``destructive_remote``; the baseline restore after it takes the certificate off.
    The password is made at run time too, so no password is written anywhere.
    """
    certificate = upload_temporary_certificate()
    if form == "pem":
        auth = AuthContext(
            TENANT,
            client_id=APP_CLIENT_ID,
            certificate_pem=certificate.certificate_pem,
            private_key_pem=certificate.private_key_pem,
        )
    else:
        password = secrets.token_urlsafe()
        auth = AuthContext(
            TENANT,
            client_id=APP_CLIENT_ID,
            certificate_pfx=certificate.pfx(password),
            certificate_password=password,
        )
    sign_in_once_accepted(auth, [f"{auth.tenant.cloud.graph}/.default"])

    async with GraphClient(auth) as graph:
        organization = await graph.get_all("/organization")
    assert organization


@needs_app
def test_the_blocking_client_calls_graph_as_an_app() -> None:
    """The generated blocking client signs in with a certificate, not only as a user."""
    with BlockingGraphClient(live_app_auth()) as graph:
        organization = graph.get_all("/organization")
    assert organization


@needs_app
@needs_exchange
async def test_exchange_runs_a_cmdlet_as_an_app() -> None:
    """An app-only token runs an Exchange cmdlet, routed through the tenant's system mailbox.

    The token is the witness that no user is involved: it carries the application's
    ``roles``, not a user's ``upn`` or ``scp``.
    """
    auth = live_app_auth()
    async with ExchangeClient(auth) as exchange:
        token = await auth.aio.acquire_token(exchange.scopes)
        config = await exchange.run("Get-OrganizationConfig")

    claims = token_claims(token.token)
    assert claims["aud"] == auth.tenant.cloud.exchange
    assert "Exchange.ManageAsApp" in claims.get("roles", [])
    assert "upn" not in claims
    assert "scp" not in claims
    assert config[0]["Name"]


@needs_app
@needs_ipps
async def test_ipps_runs_a_cmdlet_as_an_app() -> None:
    """An app-only token runs a Security & Compliance cmdlet through the regional host.

    The service finds the tenant of an app-only request only by its domain (measured
    2026-10-10). Given a GUID, the client asks Exchange for the domain first.
    """
    async with IppsClient(live_app_auth()) as ipps:
        labels = await ipps.run("Get-Label")

    assert isinstance(labels, list)
    assert httpx.URL(ipps.base_url).host.endswith(f".{httpx.URL(ipps.resource).host}")


@needs_app
def test_a_certificate_the_app_does_not_hold_is_refused() -> None:
    """A PEM certificate that was never uploaded to the application is refused by Entra.

    The certificate is made for this test and exists nowhere else. Entra reading the
    assertion MSAL built from the PEM pair and naming the missing key (AADSTS700027) shows
    the PEM path reaches the token endpoint intact.
    """
    certificate = make_certificate("azure-auth live test, never uploaded")
    auth = AuthContext(
        TENANT,
        client_id=APP_CLIENT_ID,
        certificate_pem=certificate.certificate_pem,
        private_key_pem=certificate.private_key_pem,
    )

    with pytest.raises(AuthError, match="AADSTS700027"):
        auth.acquire_token([f"{auth.tenant.cloud.graph}/.default"])


@needs_app
def test_an_app_token_is_kept_on_disk_until_a_refresh_is_forced(tmp_path: Path) -> None:
    """A second context reading the same disk cache reuses the app token; a forced refresh
    gets a new one from Entra.

    Entra issues a different token on every request, so an identical token can only have come
    from the cache.
    """
    cache_path = tmp_path / "app-cache.bin"
    first_run = live_app_auth(cache="disk", cache_path=cache_path)
    scopes = [f"{first_run.tenant.cloud.graph}/.default"]
    issued = first_run.acquire_token(scopes)

    second_run = live_app_auth(cache="disk", cache_path=cache_path)
    cached = second_run.acquire_token(scopes)
    refreshed = second_run.acquire_token(scopes, force_refresh=True)

    assert cached.token == issued.token
    assert refreshed.token != issued.token
