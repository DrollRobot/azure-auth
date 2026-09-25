"""Unit tests for the resource client base and the Graph client."""

from __future__ import annotations

import base64
import datetime
import email.utils
from typing import Any

import httpx
import pytest

from azure_auth import AuthContext
from azure_auth.clients import GraphClient, GraphError
from azure_auth.clients.base import claims_from_challenge, retry_delay
from azure_auth.constants import GRAPH_CLI_CLIENT_ID
from tests.fakes import FakeMsal, token_result
from tests.http import Recorder, ok

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

USER = "admin@partner.com"
GRAPH = "https://graph.microsoft.com/v1.0"


@pytest.fixture
def auth(fake_msal: FakeMsal) -> AuthContext:
    return AuthContext("tenant", username=USER)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Make retries instant and record how long each would have waited."""
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("azure_auth.clients.base.asyncio.sleep", fake_sleep)
    return delays


# ---------------------------------------------------------------------------- configuration


async def test_request_carries_a_token_for_the_graph_defaults(
    auth: AuthContext, fake_msal: FakeMsal
) -> None:
    recorder = Recorder([ok({"id": "1"})])
    async with GraphClient(
        auth, scopes=["User.Read.All", "openid"], transport=recorder.transport
    ) as graph:
        body = await graph.get("/me", params={"$select": "id"})

    request = recorder.requests[0]
    assert body == {"id": "1"}
    assert str(request.url) == f"{GRAPH}/me?%24select=id"
    assert request.headers["Authorization"] == "Bearer interactive"
    assert fake_msal.apps[0].client_id == GRAPH_CLI_CLIENT_ID
    # MSAL rejects the reserved OpenID Connect scopes, so the client drops them.
    assert fake_msal.calls[0].scopes == ["https://graph.microsoft.com/User.Read.All"]
    assert GraphClient(auth, scopes=["openid", "email"]).scopes == ("email",)
    assert GraphClient(auth, scopes=["offline_access"]).scopes == (
        "https://graph.microsoft.com/.default",
    )


async def test_without_scopes_the_default_scope_is_requested(
    auth: AuthContext, fake_msal: FakeMsal
) -> None:
    graph = GraphClient(auth, api_version="beta", transport=Recorder([ok({})]).transport)
    await graph.get("users")
    assert graph.scopes == ("https://graph.microsoft.com/.default",)
    assert graph.base_url == "https://graph.microsoft.com/beta"


async def test_client_id_precedence(fake_msal: FakeMsal) -> None:
    context_id = AuthContext("tenant", username=USER, client_id="context-app")
    assert GraphClient(context_id).client_id == "context-app"
    assert GraphClient(context_id, client_id="client-app").client_id == "client-app"
    assert GraphClient(AuthContext("tenant", username=USER)).client_id == (GRAPH_CLI_CLIENT_ID)


async def test_app_flow_rules(fake_msal: FakeMsal) -> None:
    with pytest.raises(ValueError, match="App flows need a client_id"):
        GraphClient(AuthContext("tenant", client_secret="s3cret"))
    app = AuthContext("tenant", client_id="app", client_secret="s3cret")
    with pytest.raises(ValueError, match="do not pass scopes"):
        GraphClient(app, scopes=["User.Read.All"])

    recorder = Recorder([ok({})])
    graph = GraphClient(
        AuthContext("tenant", client_secret="s3cret"),
        client_id="late-app",
        transport=recorder.transport,
    )
    await graph.get("/users")

    assert fake_msal.apps[0].client_id == "late-app"
    assert fake_msal.calls[0].scopes == ["https://graph.microsoft.com/.default"]
    assert recorder.requests[0].headers["Authorization"] == "Bearer app"


async def test_login_uses_the_clients_id_and_scopes(auth: AuthContext, fake_msal: FakeMsal) -> None:
    graph = GraphClient(auth, scopes=["User.Read.All"])
    await graph.login()
    await graph.login(force=True)

    assert fake_msal.methods() == ["interactive", "interactive"]
    assert fake_msal.apps[0].client_id == GRAPH_CLI_CLIENT_ID
    assert fake_msal.calls[0].scopes == ["https://graph.microsoft.com/User.Read.All"]
    assert graph.auth is auth


# ---------------------------------------------------------------------------- verbs


async def test_write_verbs_send_json_and_tolerate_empty_responses(auth: AuthContext) -> None:
    recorder = Recorder([ok({"id": "new"}, 201), ok(status=204), ok(status=204), ok(status=204)])
    graph = GraphClient(auth, transport=recorder.transport)

    created = await graph.post("/users", {"displayName": "A"})
    patched = await graph.patch("/users/1", {"displayName": "B"}, headers={"If-Match": "*"})
    replaced = await graph.put("/users/1/photo", {"x": 1})
    deleted = await graph.delete("/users/1")

    assert (created, patched, replaced, deleted) == ({"id": "new"}, None, None, None)
    assert [r.method for r in recorder.requests] == ["POST", "PATCH", "PUT", "DELETE"]
    assert recorder.bodies() == [{"displayName": "A"}, {"displayName": "B"}, {"x": 1}]
    assert recorder.requests[1].headers["If-Match"] == "*"


# ---------------------------------------------------------------------------- errors


async def test_error_response_becomes_graph_error(auth: AuthContext) -> None:
    body = {"error": {"code": "Request_ResourceNotFound", "message": "No such user"}}
    graph = GraphClient(
        auth, transport=Recorder([ok(body, 404, {"request-id": "req-1"})]).transport
    )

    with pytest.raises(GraphError, match="404 Request_ResourceNotFound: No such user") as caught:
        await graph.get("/users/missing")

    error = caught.value
    assert (error.status, error.code, error.request_id) == (
        404,
        "Request_ResourceNotFound",
        "req-1",
    )
    assert error.body == body


async def test_non_json_error_keeps_the_text(auth: AuthContext) -> None:
    graph = GraphClient(
        auth, transport=Recorder([httpx.Response(502, text="Bad gateway")]).transport
    )
    with pytest.raises(GraphError) as caught:
        await graph.get("/users")
    assert (caught.value.status, caught.value.code, caught.value.body) == (502, None, "Bad gateway")


async def test_oauth_style_error_is_understood(auth: AuthContext) -> None:
    body = {"error": "invalid_request", "error_description": "nope"}
    graph = GraphClient(auth, transport=Recorder([ok(body, 400)]).transport)
    with pytest.raises(GraphError, match="invalid_request: nope"):
        await graph.get("/users")


# ---------------------------------------------------------------------------- throttling


async def test_throttled_request_waits_for_retry_after(
    auth: AuthContext, sleeps: list[float]
) -> None:
    recorder = Recorder(
        [ok(status=429, headers={"Retry-After": "7"}), ok(status=503), ok({"ok": 1})]
    )
    graph = GraphClient(auth, transport=recorder.transport)

    assert await graph.get("/users") == {"ok": 1}
    assert sleeps == [7.0, 4.0]
    assert len(recorder.requests) == 3


async def test_throttling_gives_up_after_max_retries(
    auth: AuthContext, sleeps: list[float]
) -> None:
    recorder = Recorder(lambda request: ok(status=429, headers={"Retry-After": "1"}))
    graph = GraphClient(auth, max_retries=2, transport=recorder.transport)

    with pytest.raises(GraphError) as caught:
        await graph.get("/users")

    assert caught.value.status == 429
    assert sleeps == [1.0, 1.0]
    assert len(recorder.requests) == 3


def test_retry_delay_understands_dates_and_caps_the_wait() -> None:
    soon = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=30)
    dated = httpx.Response(429, headers={"Retry-After": email.utils.format_datetime(soon)})
    assert 25 <= retry_delay(dated, 1, 120) <= 30
    naive = soon.strftime("%a, %d %b %Y %H:%M:%S -0000")
    assert 25 <= retry_delay(httpx.Response(429, headers={"Retry-After": naive}), 1, 120) <= 30
    assert retry_delay(httpx.Response(429, headers={"Retry-After": "600"}), 1, 120) == 120
    assert retry_delay(httpx.Response(429, headers={"Retry-After": "soon"}), 3, 120) == 8
    assert retry_delay(httpx.Response(429), 10, 120) == 30
    assert retry_delay(httpx.Response(429, headers={"Retry-After": "-5"}), 1, 120) == 0


# ---------------------------------------------------------------------------- 401 handling


def challenge(claims: str) -> dict[str, str]:
    encoded = base64.b64encode(claims.encode()).decode()
    return {"WWW-Authenticate": f'Bearer realm="", error="insufficient_claims", claims="{encoded}"'}


async def test_claims_challenge_is_passed_to_msal(auth: AuthContext, fake_msal: FakeMsal) -> None:
    claims = '{"access_token":{"nbf":{"essential":true,"value":"1"}}}'
    fake_msal.accounts = [{"username": USER}]
    fake_msal.silent = lambda call: token_result(
        "challenged" if call.kwargs["claims_challenge"] else "first"
    )
    recorder = Recorder([ok(status=401, headers=challenge(claims)), ok({"ok": 1})])
    graph = GraphClient(auth, transport=recorder.transport)

    assert await graph.get("/me") == {"ok": 1}
    assert [c.kwargs["claims_challenge"] for c in fake_msal.calls] == [None, claims]
    assert recorder.requests[1].headers["Authorization"] == "Bearer challenged"


async def test_plain_401_forces_one_token_refresh(auth: AuthContext, fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [{"username": USER}]
    fake_msal.silent = lambda call: token_result()
    recorder = Recorder([ok(status=401), ok(status=401)])
    graph = GraphClient(auth, transport=recorder.transport)

    with pytest.raises(GraphError) as caught:
        await graph.get("/me")

    assert caught.value.status == 401
    assert [c.kwargs["force_refresh"] for c in fake_msal.calls] == [False, True]
    assert len(recorder.requests) == 2


@pytest.mark.parametrize("header", [None, "Bearer realm=x", 'Bearer claims="%%%"'])
def test_unusable_challenges_yield_no_claims(header: str | None) -> None:
    assert claims_from_challenge(header) is None


# ---------------------------------------------------------------------------- paging


async def test_get_all_follows_next_links(auth: AuthContext) -> None:
    next_link = f"{GRAPH}/users?$skiptoken=abc"
    recorder = Recorder([ok({"value": [1, 2], "@odata.nextLink": next_link}), ok({"value": [3]})])
    graph = GraphClient(auth, transport=recorder.transport)

    items = await graph.get_all(
        "/users", params={"$top": 2}, headers={"ConsistencyLevel": "eventual"}
    )

    assert items == [1, 2, 3]
    assert recorder.urls() == [f"{GRAPH}/users?%24top=2", next_link]
    assert all(r.headers["ConsistencyLevel"] == "eventual" for r in recorder.requests)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/v1.0/users",
        "http://graph.microsoft.com/x",
        "https://graph.microsoft.com@evil.example/v1.0/users",
        "https://someone@graph.microsoft.com/v1.0/users",
    ],
)
async def test_token_is_never_sent_to_another_host(auth: AuthContext, url: str) -> None:
    recorder = Recorder([ok({"value": [], "@odata.nextLink": url})])
    graph = GraphClient(auth, transport=recorder.transport)

    with pytest.raises(ValueError, match="Refusing to send a token"):
        await graph.get_all("/users")

    assert len(recorder.requests) == 1


# ---------------------------------------------------------------------------- batch


async def test_batch_is_chunked_and_order_is_restored(auth: AuthContext) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        import json

        items = json.loads(request.content)["requests"]
        responses = [{"id": item["id"], "status": 200, "body": item["url"]} for item in items]
        return ok({"responses": list(reversed(responses))})

    recorder = Recorder(handler)
    graph = GraphClient(auth, transport=recorder.transport)
    requests: list[dict[str, Any]] = [{"method": "GET", "url": f"/users/{n}"} for n in range(45)]
    requests[0] = {"id": "first", "method": "POST", "url": "/users", "body": {"a": 1}}

    responses = await graph.batch(requests)

    assert [len(body["requests"]) for body in recorder.bodies()] == [20, 20, 5]
    assert recorder.urls() == [f"{GRAPH}/$batch"] * 3
    assert responses[0]["id"] == "first"
    assert [r["body"] for r in responses[1:]] == [f"/users/{n}" for n in range(1, 45)]
    first = recorder.bodies()[0]["requests"][0]
    assert first["headers"] == {"Content-Type": "application/json"}
    assert recorder.bodies()[0]["requests"][1]["id"] == "1"


# ---------------------------------------------------------------------------- GDAP helper


async def test_managed_tenants_come_from_delegated_admin_customers(auth: AuthContext) -> None:
    recorder = Recorder(
        [ok({"value": [{"tenantId": "t1", "displayName": "A"}, {"tenantId": "t2"}]})]
    )
    graph = GraphClient(auth, transport=recorder.transport)

    assert await graph.list_managed_tenant_ids() == ["t1", "t2"]
    assert recorder.urls() == [f"{GRAPH}/tenantRelationships/delegatedAdminCustomers"]
