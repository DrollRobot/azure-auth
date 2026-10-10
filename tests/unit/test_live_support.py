"""Unit tests for the pure helpers in ``tests/live/support.py``.

``restore_baseline`` itself signs in to Entra and edits grants, and is exercised by every live
run. What is tested here are the checks it makes: that a token missing a baseline scope is
caught, and that the tenant-wide grant is what has to carry the baseline. Scopes beyond the
baseline are found in the grants, not the token, so the token check does not report them.

The GDAP tests' read-only guard is tested here too, offline, because the live tests that use it
must never be the first place it is seen to refuse a write.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from azure_auth import AuthContext, ExchangeClient, Tenant
from azure_auth.clouds import COMMERCIAL
from azure_auth.sync import ExchangeClient as BlockingExchangeClient
from tests.fakes import FakeMsal, token_result
from tests.http import Recorder, fake_jwt, ok
from tests.live.support import (
    BASELINE_SCOPES,
    ReadOnlyCmdlets,
    _holds_baseline,
    missing_scopes,
    token_claims,
    token_scopes,
    token_user,
)

pytestmark = [pytest.mark.unit]


def jwt_with(scp: str | None) -> str:
    """Build an unsigned JWT whose payload carries the given ``scp`` claim, or none.

    Args:
        scp: The space-separated scopes, or ``None`` for a payload without the claim.

    Returns:
        A three-segment token. The segments are unpadded, as Entra's are.
    """

    def segment(claims: dict[str, str]) -> str:
        raw = json.dumps(claims).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    payload = {} if scp is None else {"scp": scp}
    return f"{segment({'alg': 'none'})}.{segment(payload)}.signature"


def test_token_scopes_reads_the_scp_claim() -> None:
    token = jwt_with("User.Read Application.Read.All")
    assert token_scopes(token) == {"User.Read", "Application.Read.All"}


def test_token_scopes_is_empty_without_the_claim() -> None:
    assert token_scopes(jwt_with(None)) == set()


def test_missing_scopes_names_what_the_token_lacks() -> None:
    token = jwt_with("User.Read")
    assert missing_scopes(token, ["User.Read", "AuditLog.Read.All"]) == {"AuditLog.Read.All"}


def test_missing_scopes_is_empty_when_the_token_carries_more_than_required() -> None:
    # Only what is missing is reported; what is beyond the baseline is read from the grants.
    token = jwt_with("User.Read AuditLog.Read.All Mail.Read")
    assert missing_scopes(token, ["User.Read"]) == set()


def test_token_claims_reads_the_payload() -> None:
    assert token_claims(fake_jwt(tid="t", scp="a b")) == {"tid": "t", "scp": "a b"}


def test_token_user_takes_the_v2_claim_first_and_the_v1_claims_after() -> None:
    assert token_user(fake_jwt(preferred_username="a@x.com", upn="b@x.com")) == "a@x.com"
    assert token_user(fake_jwt(upn="b@x.com")) == "b@x.com"
    assert token_user(fake_jwt(unique_name="c@x.com")) == "c@x.com"
    assert token_user(fake_jwt(sub="nobody")) is None


def test_the_baseline_has_to_be_in_a_tenant_wide_grant() -> None:
    scopes = " ".join(BASELINE_SCOPES)
    assert _holds_baseline([{"consentType": "AllPrincipals", "scope": f"{scopes} Extra"}])
    # A per-user grant covers only its user, not the non-administrator or anyone else.
    assert not _holds_baseline([{"consentType": "Principal", "scope": scopes}])
    assert not _holds_baseline(
        [{"consentType": "AllPrincipals", "scope": " ".join(BASELINE_SCOPES[1:])}]
    )
    assert not _holds_baseline([])


TENANT_GUID = "11111111-2222-3333-4444-555555555555"
INVOKE_COMMAND = f"https://outlook.office365.com/adminapi/beta/{TENANT_GUID}/InvokeCommand"


def invoke_command(cmdlet: str) -> httpx.Request:
    """Build the request an Exchange client sends to run a cmdlet.

    Args:
        cmdlet: The cmdlet's name.

    Returns:
        The request.
    """
    body = {"CmdletInput": {"CmdletName": cmdlet, "Parameters": {}}}
    return httpx.Request("POST", INVOKE_COMMAND, json=body)


def test_the_read_only_guard_sends_a_listed_cmdlet() -> None:
    recorder = Recorder([ok({"value": []})])
    guard = ReadOnlyCmdlets(recorder.transport)
    response = guard.handle_request(invoke_command("Get-OrganizationConfig"))
    assert response.status_code == 200
    assert len(recorder.requests) == len(guard.requests) == 1


@pytest.mark.parametrize(
    "request_",
    [
        invoke_command("Set-OrganizationConfig"),
        invoke_command("Remove-Mailbox"),
        invoke_command("Get-Mailbox"),
        httpx.Request("POST", INVOKE_COMMAND, content=b"not json"),
        httpx.Request("POST", INVOKE_COMMAND, json={"CmdletInput": {"CmdletName": ["Get-X"]}}),
        httpx.Request("GET", INVOKE_COMMAND),
        httpx.Request(
            "POST",
            INVOKE_COMMAND.replace("InvokeCommand", "Other"),
            json={"CmdletInput": {"CmdletName": "Get-OrganizationConfig"}},
        ),
    ],
    ids=["write", "remove", "unlisted-read", "no-json", "odd-name", "get", "other-endpoint"],
)
def test_the_read_only_guard_refuses_anything_else_unsent(request_: httpx.Request) -> None:
    recorder = Recorder([ok()])
    guard = ReadOnlyCmdlets(recorder.transport)
    with pytest.raises(pytest.fail.Exception, match="refused to send"):
        guard.handle_request(request_)
    assert recorder.requests == guard.requests == []


@pytest.mark.anyio
async def test_the_read_only_guard_checks_asynchronous_requests_too() -> None:
    recorder = Recorder([ok({"value": []})])
    guard = ReadOnlyCmdlets(recorder.transport)
    await guard.handle_async_request(invoke_command("Get-OrganizationConfig"))
    with pytest.raises(pytest.fail.Exception, match="refused to send"):
        await guard.handle_async_request(invoke_command("Set-OrganizationConfig"))
    assert len(recorder.requests) == 1


@pytest.fixture
def exchange_auth(fake_msal: FakeMsal) -> AuthContext:
    """A user-flow context whose every token request succeeds, for the Exchange clients."""
    token = fake_jwt(tid=TENANT_GUID)
    fake_msal.accounts = [{"username": "admin@partner.com"}]
    fake_msal.silent = lambda call: token_result(token)
    return AuthContext(Tenant(TENANT_GUID, COMMERCIAL), username="admin@partner.com")


@pytest.mark.anyio
async def test_no_exchange_client_can_get_a_write_past_the_read_only_guard(
    exchange_auth: AuthContext,
) -> None:
    """The refusal reaches the caller through the client, which neither sends nor retries.

    The clients catch exceptions to retry and to report errors; the guard fails the test with
    a ``BaseException``, which they cannot catch.
    """
    recorder = Recorder([ok({"value": [{"Name": "partner.onmicrosoft.com"}]})])
    guard = ReadOnlyCmdlets(recorder.transport)
    async with ExchangeClient(exchange_auth, transport=guard) as exchange:
        assert await exchange.run("Get-OrganizationConfig") == [{"Name": "partner.onmicrosoft.com"}]
        with pytest.raises(pytest.fail.Exception, match="refused to send"):
            await exchange.run("Set-OrganizationConfig", Confirm=False)
    guard = ReadOnlyCmdlets(recorder.transport)
    with (
        BlockingExchangeClient(exchange_auth, transport=guard) as blocking,
        pytest.raises(pytest.fail.Exception, match="refused to send"),
    ):
        blocking.run("Remove-Mailbox", Identity="a@partner.com", Confirm=False)
    assert [body["CmdletInput"]["CmdletName"] for body in recorder.bodies()] == [
        "Get-OrganizationConfig"
    ]
