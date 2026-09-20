"""Unit tests for the Exchange and Security & Compliance cmdlet clients."""

from __future__ import annotations

import httpx
import pytest

from azure_auth import AuthContext
from azure_auth.clients import ExchangeClient, InvokeCommandError, IppsClient
from azure_auth.clients.invoke_command import SYSTEM_MAILBOX, tenant_id_from_token
from azure_auth.constants import EXCHANGE_POWERSHELL_CLIENT_ID
from tests.fakes import FakeMsal, token_result
from tests.http import Recorder, fake_jwt, ok

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

USER = "admin@partner.com"
TENANT_GUID = "11111111-2222-3333-4444-555555555555"
EXCHANGE = f"https://outlook.office365.com/adminapi/beta/{TENANT_GUID}/InvokeCommand"
IPPS_HOST = "ps.compliance.protection.outlook.com"


@pytest.fixture
def auth(fake_msal: FakeMsal) -> AuthContext:
    token = fake_jwt(tid=TENANT_GUID)
    fake_msal.accounts = [{"username": USER}]
    fake_msal.silent = lambda call: token_result(token)
    fake_msal.for_client = lambda call: token_result(token)
    return AuthContext("partner.onmicrosoft.com", username=USER)


async def test_cmdlet_request_shape(auth: AuthContext, fake_msal: FakeMsal) -> None:
    recorder = Recorder([ok({"value": [{"Alias": "a"}]}, headers={"X-Warnings": "slow cmdlet"})])
    async with ExchangeClient(auth, page_size=50, transport=recorder.transport) as exchange:
        result = await exchange.run("Get-Mailbox", Identity="a@partner.com", IncludeInactive=True)

    request = recorder.requests[0]
    assert result == [{"Alias": "a"}]
    assert exchange.last_warnings == ["slow cmdlet"]
    assert (request.method, str(request.url)) == ("POST", EXCHANGE)
    assert recorder.bodies() == [
        {
            "CmdletInput": {
                "CmdletName": "Get-Mailbox",
                "Parameters": {"Identity": "a@partner.com", "IncludeInactive": True},
            }
        }
    ]
    assert request.headers["X-AnchorMailbox"] == f"UPN:{USER}"
    assert request.headers["X-CmdletName"] == "Get-Mailbox"
    assert request.headers["Prefer"] == "odata.maxpagesize=50"
    assert request.headers["Content-Type"] == "application/json;odata.metadata=minimal"
    assert len(request.headers["connection-id"]) == len(request.headers["client-request-id"]) == 36
    assert fake_msal.apps[0].client_id == EXCHANGE_POWERSHELL_CLIENT_ID
    assert fake_msal.calls[0].scopes == ["https://outlook.office365.com/.default"]


async def test_paging_posts_the_same_body_to_the_next_link(auth: AuthContext) -> None:
    next_link = f"{EXCHANGE}?$skiptoken=page2"
    pages = [ok({"value": [{"n": 1}], "@odata.nextLink": next_link}), ok({"value": [{"n": 2}]})]
    recorder = Recorder(pages)
    exchange = ExchangeClient(auth, transport=recorder.transport)

    assert await exchange.run("Get-Mailbox") == [{"n": 1}, {"n": 2}]
    assert [r.method for r in recorder.requests] == ["POST", "POST"]
    assert recorder.bodies()[0] == recorder.bodies()[1]
    assert (
        recorder.requests[0].headers["connection-id"]
        == (recorder.requests[1].headers["connection-id"])
    )
    assert (
        recorder.requests[0].headers["client-request-id"]
        != (recorder.requests[1].headers["client-request-id"])
    )


async def test_app_flow_routes_through_the_system_mailbox(auth: AuthContext) -> None:
    app = AuthContext("contoso.onmicrosoft.com", client_id="app", client_secret="s3cret")
    recorder = Recorder([ok({"value": []})])

    await ExchangeClient(app, transport=recorder.transport).run("Get-Mailbox")

    anchor = recorder.requests[0].headers["X-AnchorMailbox"]
    assert anchor == f"APP:{SYSTEM_MAILBOX}@{TENANT_GUID}"


async def test_gdap_sibling_routes_through_the_customer_system_mailbox(auth: AuthContext) -> None:
    recorder = Recorder([ok({"value": []})])
    exchange = ExchangeClient(
        auth.for_tenant("customer.onmicrosoft.com"), transport=recorder.transport
    )

    await exchange.run("Get-Mailbox")

    assert recorder.requests[0].headers["X-AnchorMailbox"] == f"APP:{SYSTEM_MAILBOX}@{TENANT_GUID}"


async def test_anchor_mailbox_can_be_overridden(auth: AuthContext) -> None:
    recorder = Recorder([ok({"value": []})])
    exchange = ExchangeClient(
        auth,
        anchor_mailbox="UPN:shared@partner.com",
        api_version="v1.0",
        transport=recorder.transport,
    )

    await exchange.run("Get-Mailbox")

    assert recorder.requests[0].headers["X-AnchorMailbox"] == "UPN:shared@partner.com"
    assert "/adminapi/v1.0/" in str(recorder.requests[0].url)


async def test_cmdlet_failure_becomes_invoke_command_error(auth: AuthContext) -> None:
    body = {"error": {"code": "NotFound", "message": "|ManagementObjectNotFound|no such mailbox"}}
    exchange = ExchangeClient(auth, transport=Recorder([ok(body, 404)]).transport)

    with pytest.raises(InvokeCommandError, match="no such mailbox") as caught:
        await exchange.run("Get-Mailbox", Identity="missing")

    assert (caught.value.status, caught.value.code) == (404, "NotFound")


async def test_undecodable_token_falls_back_to_the_configured_tenant(fake_msal: FakeMsal) -> None:
    recorder = Recorder([ok({"value": []})])
    exchange = ExchangeClient(
        AuthContext("tenant-guid", username=USER), transport=recorder.transport
    )

    await exchange.run("Get-Mailbox")

    assert "/adminapi/beta/tenant-guid/InvokeCommand" in str(recorder.requests[0].url)


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (fake_jwt(tid=TENANT_GUID), TENANT_GUID),
        (fake_jwt(sub="x"), None),
        ("opaque", None),
        ("a.%%%.c", None),
        ("a.W10.c", None),
    ],
)
def test_tenant_id_is_read_from_the_token(token: str, expected: str | None) -> None:
    assert tenant_id_from_token(token) == expected


# ---------------------------------------------------------------------------- IPPS redirect


async def test_ipps_follows_the_regional_redirect_with_its_token(
    auth: AuthContext, fake_msal: FakeMsal
) -> None:
    regional = f"https://nam12b.{IPPS_HOST}"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == IPPS_HOST:
            return httpx.Response(302, headers={"Location": f"{regional}/adminapi/beta/x"})
        return ok({"value": [{"Name": "label"}]})

    recorder = Recorder(handler)
    ipps = IppsClient(auth, transport=recorder.transport)

    first = await ipps.run("Get-Label")
    second = await ipps.run("Get-Label")

    assert first == second == [{"Name": "label"}]
    regional_host = f"nam12b.{IPPS_HOST}"
    assert [r.url.host for r in recorder.requests] == [IPPS_HOST, regional_host, regional_host]
    assert all(r.headers["Authorization"].startswith("Bearer ") for r in recorder.requests)
    assert ipps.base_url == regional
    assert fake_msal.calls[0].scopes == [f"https://{IPPS_HOST}/.default"]


async def test_ipps_ignores_a_redirect_to_a_foreign_host_name(auth: AuthContext) -> None:
    recorder = Recorder(
        lambda request: (
            httpx.Response(302, headers={"Location": "https://evil.example/adminapi"})
            if request.url.host == IPPS_HOST
            else ok({"value": ["regional"]})
        )
    )
    ipps = IppsClient(auth, transport=recorder.transport)

    await ipps.run("Get-Label")

    # Only the first label of the redirect host is used; the request stays on the service.
    assert [r.url.host for r in recorder.requests] == [IPPS_HOST, f"evil.{IPPS_HOST}"]


async def test_next_link_on_a_foreign_host_is_refused(auth: AuthContext) -> None:
    recorder = Recorder([ok({"value": [], "@odata.nextLink": "https://evil.example/next"})])
    exchange = ExchangeClient(auth, transport=recorder.transport)

    with pytest.raises(ValueError, match="Refusing to send a token"):
        await exchange.run("Get-Mailbox")
