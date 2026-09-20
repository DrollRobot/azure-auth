"""Unit tests for the generated blocking clients.

The asynchronous clients carry the detailed tests. These prove that the generated mirror
works end to end without an event loop: tokens, retries, paging, polling and redirects.
"""

from __future__ import annotations

import inspect

import httpx
import pytest

from azure_auth import AuthContext, clients, sync
from azure_auth.clients import GraphError
from azure_auth.sync import AzureClient, ExchangeClient, GraphClient, IppsClient
from tests.fakes import FakeMsal, token_result
from tests.http import Recorder, fake_jwt, ok

pytestmark = pytest.mark.unit

USER = "admin@partner.com"
GRAPH = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com"
TENANT_GUID = "11111111-2222-3333-4444-555555555555"
IPPS_HOST = "ps.compliance.protection.outlook.com"


@pytest.fixture
def auth(fake_msal: FakeMsal) -> AuthContext:
    token = fake_jwt(tid=TENANT_GUID)
    fake_msal.accounts = [{"username": USER}]
    fake_msal.silent = lambda call: token_result(token)
    return AuthContext("tenant", username=USER)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []
    monkeypatch.setattr("azure_auth._sync.base.time.sleep", delays.append)
    return delays


def test_mirror_has_the_same_public_surface() -> None:
    assert set(sync.__all__) <= set(clients.__all__)
    for name in sync.__all__:
        blocking, asynchronous = getattr(sync, name), getattr(clients, name)
        public = {member for member in dir(asynchronous) if not member.startswith("_")}
        renamed = {"close" if member == "aclose" else member for member in public}
        assert renamed <= set(dir(blocking)), name
        assert not any(
            inspect.iscoroutinefunction(getattr(blocking, member)) for member in dir(blocking)
        )


def test_graph_pages_and_retries_without_an_event_loop(
    auth: AuthContext, sleeps: list[float]
) -> None:
    next_link = f"{GRAPH}/users?$skiptoken=abc"
    recorder = Recorder(
        [
            ok(status=429, headers={"Retry-After": "2"}),
            ok({"value": [1], "@odata.nextLink": next_link}),
            ok({"value": [2]}),
        ]
    )
    with GraphClient(auth, scopes=["User.Read.All"], transport=recorder.transport) as graph:
        graph.login()
        assert graph.get_all("/users") == [1, 2]

    assert sleeps == [2.0]
    assert recorder.requests[0].headers["Authorization"].startswith("Bearer ")


def test_graph_error_is_shared_with_the_async_clients(auth: AuthContext) -> None:
    body = {"error": {"code": "Forbidden", "message": "no"}}
    graph = GraphClient(auth, transport=Recorder([ok(body, 403)]).transport)
    with pytest.raises(GraphError, match="Forbidden: no"):
        graph.get("/users")


def test_arm_waits_for_a_long_running_operation(
    auth: AuthContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    delays: list[float] = []
    monkeypatch.setattr("azure_auth._sync.arm.time.sleep", delays.append)
    operation = f"{ARM}/subscriptions/s/operations/op?api-version=2021-04-01"
    recorder = Recorder(
        [
            ok(status=202, headers={"Azure-AsyncOperation": operation, "Retry-After": "4"}),
            ok({"status": "Succeeded"}),
            ok({"name": "rg"}),
        ]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = arm.send("PUT", "/subscriptions/s/resourceGroups/rg", api_version="2021-04-01")

    assert arm.wait(started) == {"name": "rg"}
    assert delays == [4.0]


def test_exchange_runs_a_cmdlet(auth: AuthContext) -> None:
    recorder = Recorder([ok({"value": [{"Alias": "a"}]})])
    exchange = ExchangeClient(auth, transport=recorder.transport)

    assert exchange.run("Get-Mailbox", ResultSize=1) == [{"Alias": "a"}]
    assert f"/adminapi/beta/{TENANT_GUID}/InvokeCommand" in str(recorder.requests[0].url)
    assert recorder.requests[0].headers["X-AnchorMailbox"] == f"UPN:{USER}"


def test_ipps_follows_the_regional_redirect(auth: AuthContext) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == IPPS_HOST:
            return httpx.Response(302, headers={"Location": f"https://eur05b.{IPPS_HOST}/x"})
        return ok({"value": [{"Name": "label"}]})

    recorder = Recorder(handler)
    ipps = IppsClient(auth, transport=recorder.transport)

    assert ipps.run("Get-Label") == [{"Name": "label"}]
    assert [r.url.host for r in recorder.requests] == [IPPS_HOST, f"eur05b.{IPPS_HOST}"]
    assert recorder.requests[1].headers["Authorization"].startswith("Bearer ")
