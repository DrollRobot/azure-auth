"""Unit tests for the Azure Resource Manager client."""

from __future__ import annotations

import httpx
import pytest

from azure_auth import AuthContext
from azure_auth.clients import AzureClient, AzureError
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID
from tests.fakes import FakeMsal
from tests.http import Recorder, ok

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

ARM = "https://management.azure.com"
GROUP = "/subscriptions/sub/resourceGroups/rg"
OPERATION = f"{ARM}/subscriptions/sub/operations/op1?api-version=2021-04-01"


@pytest.fixture
def auth(fake_msal: FakeMsal) -> AuthContext:
    return AuthContext("tenant", username="admin@contoso.com")


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("azure_auth.clients.arm.asyncio.sleep", fake_sleep)
    return delays


async def test_api_version_is_added_to_every_verb(auth: AuthContext, fake_msal: FakeMsal) -> None:
    recorder = Recorder(lambda request: ok({"name": "rg"}))
    arm = AzureClient(auth, transport=recorder.transport)

    await arm.get(GROUP, api_version="2021-04-01", params={"$expand": "x"})
    await arm.put(GROUP, {"location": "westeurope"}, api_version="2021-04-01")
    await arm.patch(GROUP, {"tags": {}}, api_version="2021-04-01")
    await arm.post(f"{GROUP}/validate", api_version="2021-04-01")
    await arm.delete(GROUP, api_version="2021-04-01")

    assert [r.method for r in recorder.requests] == ["GET", "PUT", "PATCH", "POST", "DELETE"]
    assert all(r.url.params["api-version"] == "2021-04-01" for r in recorder.requests)
    assert recorder.requests[0].url.params["$expand"] == "x"
    assert fake_msal.apps[0].client_id == AZURE_POWERSHELL_CLIENT_ID
    assert fake_msal.calls[0].scopes == ["https://management.azure.com/.default"]


async def test_get_all_follows_next_link_as_given(auth: AuthContext) -> None:
    next_link = f"{ARM}/subscriptions?api-version=2022-12-01&$skiptoken=abc"
    recorder = Recorder([ok({"value": ["a"], "nextLink": next_link}), ok({"value": ["b"]})])
    arm = AzureClient(auth, transport=recorder.transport)

    assert await arm.get_all("/subscriptions", api_version="2022-12-01") == ["a", "b"]
    assert recorder.requests[1].url.params.get_list("api-version") == ["2022-12-01"]


async def test_error_becomes_azure_error(auth: AuthContext) -> None:
    body = {"error": {"code": "ResourceGroupNotFound", "message": "gone"}}
    recorder = Recorder([ok(body, 404, {"x-ms-request-id": "arm-1"})])
    arm = AzureClient(auth, transport=recorder.transport)

    with pytest.raises(AzureError) as caught:
        await arm.get(GROUP, api_version="2021-04-01")

    assert (caught.value.code, caught.value.request_id) == ("ResourceGroupNotFound", "arm-1")


# ---------------------------------------------------------------------------- long-running


async def test_put_polls_the_operation_then_reads_the_resource(
    auth: AuthContext, sleeps: list[float]
) -> None:
    recorder = Recorder(
        [
            ok(
                {"properties": {"provisioningState": "Creating"}},
                201,
                {"Azure-AsyncOperation": OPERATION, "Retry-After": "3"},
            ),
            ok({"status": "InProgress"}, headers={"Retry-After": "9"}),
            ok({"status": "Succeeded"}),
            ok({"properties": {"provisioningState": "Succeeded"}}),
        ]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("PUT", GROUP, api_version="2021-04-01", json={"location": "x"})
    result = await arm.wait(started)

    assert result == {"properties": {"provisioningState": "Succeeded"}}
    assert sleeps == [3.0, 9.0]
    assert recorder.urls()[1:] == [OPERATION, OPERATION, f"{ARM}{GROUP}?api-version=2021-04-01"]


async def test_post_operation_returns_the_location_result(
    auth: AuthContext, sleeps: list[float]
) -> None:
    location = f"{ARM}/subscriptions/sub/operationresults/op1?api-version=2021-04-01"
    recorder = Recorder(
        [
            ok(status=202, headers={"Azure-AsyncOperation": OPERATION, "Location": location}),
            ok({"status": "Succeeded"}),
            ok({"output": 42}),
        ]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("POST", f"{GROUP}/export", api_version="2021-04-01")

    assert await arm.wait(started, poll_interval=0.5) == {"output": 42}
    assert sleeps == [0.5]
    assert recorder.urls()[-1] == location


async def test_operation_without_location_returns_its_status(
    auth: AuthContext, sleeps: list[float]
) -> None:
    recorder = Recorder(
        [
            ok(status=202, headers={"Azure-AsyncOperation": OPERATION}),
            ok({"status": "Succeeded", "properties": {"x": 1}}),
        ]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("DELETE", GROUP, api_version="2021-04-01")

    assert await arm.wait(started) == {"status": "Succeeded", "properties": {"x": 1}}
    assert sleeps == [5.0]


@pytest.mark.parametrize("state", ["Failed", "Canceled"])
async def test_failed_operation_raises(auth: AuthContext, sleeps: list[float], state: str) -> None:
    failure = {"status": state, "error": {"code": "QuotaExceeded", "message": "too many"}}
    recorder = Recorder(
        [
            ok(status=202, headers={"Azure-AsyncOperation": OPERATION}),
            ok(failure, headers={"x-ms-request-id": "arm-2"}),
        ]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("DELETE", GROUP, api_version="2021-04-01")
    with pytest.raises(AzureError, match=f"Operation {state} QuotaExceeded: too many") as caught:
        await arm.wait(started)

    assert (caught.value.code, caught.value.request_id) == ("QuotaExceeded", "arm-2")
    assert caught.value.body == failure


async def test_location_only_operation_is_polled_until_done(
    auth: AuthContext, sleeps: list[float]
) -> None:
    location = f"{ARM}/subscriptions/sub/operationresults/op2?api-version=2021-04-01"
    recorder = Recorder(
        [
            ok(status=202, headers={"Location": location}),
            ok(status=202, headers={"Location": location, "Retry-After": "2"}),
            ok(status=204),
        ]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("DELETE", GROUP, api_version="2021-04-01")

    assert await arm.wait(started) is None
    assert sleeps == [5.0, 2.0]


async def test_completed_response_is_returned_as_is(auth: AuthContext, sleeps: list[float]) -> None:
    arm = AzureClient(auth, transport=Recorder([ok({"done": True})]).transport)
    started = await arm.send("PUT", GROUP, api_version="2021-04-01")
    assert await arm.wait(started) == {"done": True}
    assert sleeps == []


async def test_wait_times_out(auth: AuthContext, sleeps: list[float]) -> None:
    recorder = Recorder(
        lambda request: ok({"status": "InProgress"}, 202, {"Azure-AsyncOperation": OPERATION})
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("DELETE", GROUP, api_version="2021-04-01")
    with pytest.raises(TimeoutError, match="still running"):
        await arm.wait(started, timeout=-1)


async def test_operation_url_on_another_host_is_refused(
    auth: AuthContext, sleeps: list[float]
) -> None:
    recorder = Recorder(
        [httpx.Response(202, headers={"Azure-AsyncOperation": "https://evil.example/op"})]
    )
    arm = AzureClient(auth, transport=recorder.transport)

    started = await arm.send("DELETE", GROUP, api_version="2021-04-01")
    with pytest.raises(ValueError, match="Refusing to send a token"):
        await arm.wait(started)
