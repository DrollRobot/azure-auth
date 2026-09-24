"""The Graph client against the real service: paging, batching, ``.default``, throttling, and
the blocking mirror.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from azure_auth import AuthContext, ConsentRequired, GraphClient, GraphError, InteractionRequired
from azure_auth.sync import GraphClient as BlockingGraphClient
from tests.live.support import USERNAME, cached_user_auth, needs_user, require_cached_sign_in

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# A delegated scope nobody in the tenant has granted the Graph command-line application. The
# .default test asserts it is missing from a .default token and cannot be had without a
# prompt. It must not be anything the live tests ask for (RESET_SCOPES, NONADMIN_SCOPE, the
# scopes of the other tests), or the suite would grant it and the test would fail. A tenant
# where it has been granted anyway needs another one named here.
UNGRANTED_SCOPE = os.environ.get("AZURE_AUTH_TEST_UNGRANTED_SCOPE", "Mail.ReadWrite")

# How many audit log requests go out at once, how many the test sends before giving up, and
# how many times a refused one is retried.
#
# Microsoft documents five requests per ten seconds per application per tenant for these
# resources, the lowest limit Graph publishes, but enforcement is erratic rather than a rate:
# measured 2026-09-22, minutes apart on one tenant, the same burst was refused 15 times, then
# twice, then not at all. So the test escalates in waves and skips a run that is never
# refused. Waves stay small because a refused wave retries as a whole, and 50 at once could
# not drain inside five retries; retries are generous for the same reason.
# (Directory reads are no use here: 5000 requests to /me at 85 a second were all answered.)
THROTTLE_BURST = 20
THROTTLE_MAX_REQUESTS = 100
THROTTLE_RETRIES = 8


def token_scopes(token: str) -> set[str]:
    """Read the delegated scopes out of an access token, without validating it.

    Graph access tokens are JWTs whose ``scp`` claim lists the delegated permissions Entra
    actually issued, which may differ from what was asked for. Nothing here checks the
    signature; the token came straight from Entra and is only being inspected.

    Args:
        token: A Graph access token.

    Returns:
        The scope names, such as ``{"User.Read", "Application.Read.All"}``.
    """
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return set(str(claims.get("scp", "")).split())


class StatusCounter(httpx.AsyncBaseTransport):
    """A real network transport that counts the status of every response.

    A client retries a throttled request itself, so a 429 that was waited out never reaches
    the caller. This sits beneath the retry loop and sees every response, including the ones
    that were retried, which is the only way to tell "retried and succeeded" from "was never
    throttled at all".
    """

    def __init__(self) -> None:
        """Wrap the default ``httpx`` network transport."""
        self._inner = httpx.AsyncHTTPTransport()
        self.statuses: collections.Counter[int] = collections.Counter()
        self.retry_after: list[str | None] = []

    @property
    def throttled(self) -> int:
        """How many responses were 429 or 503, the statuses the client retries."""
        return self.statuses[429] + self.statuses[503]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send the request over the network and count the response's status.

        A throttled response also has its ``Retry-After`` recorded, ``None`` when the header
        is absent, because which of the client's two waits ran depends on that.

        Args:
            request: The outgoing request.

        Returns:
            The response, untouched.
        """
        response = await self._inner.handle_async_request(request)
        self.statuses[response.status_code] += 1
        if response.status_code in (429, 503):
            self.retry_after.append(response.headers.get("Retry-After"))
        return response

    async def aclose(self) -> None:
        """Close the wrapped transport."""
        await self._inner.aclose()


@needs_user
async def test_graph_paging_follows_next_links(user_auth: AuthContext) -> None:
    """``get_all`` walks every page of a Graph collection.

    Until this ran, no live Graph call had ever returned more than one page, so the
    ``@odata.nextLink`` loop was unproven against the real service -- the Exchange endpoint
    proves its own paging, but Graph's is separate code. ``$top`` forces the service to page a
    collection that would otherwise arrive whole, so this does not depend on the tenant being
    large.

    Service principals are used because every tenant has dozens of them, and because reading
    them needs ``Application.Read.All``, which the interactive Graph sign-in already asks for.
    """
    page_size = 5
    async with GraphClient(user_auth, scopes=["Application.Read.All"]) as graph:
        require_cached_sign_in(graph)
        pages = 0
        async for page in graph.iter_pages("/servicePrincipals", params={"$top": str(page_size)}):
            pages += 1
            assert len(page.get("value", [])) <= page_size
            if pages > 20:
                break
        principals = await graph.get_all("/servicePrincipals", params={"$top": str(page_size)})

    assert pages > 1, f"the tenant returned everything in one page of {page_size}; nothing paged"
    ids = [principal["id"] for principal in principals]
    assert len(ids) > page_size, "get_all returned no more than a single page"
    # A next-link loop that re-sends the first page's query would repeat itself forever; a
    # loop that drops the link would stop early. Both show up as a wrong number of unique ids.
    assert len(ids) == len(set(ids)), "get_all returned the same object more than once"
    print(f"graph paging: {pages} pages at $top={page_size}, {len(ids)} unique objects")


@needs_user
async def test_post_sends_a_batch_and_the_answers_come_back_in_order(
    user_auth: AuthContext,
) -> None:
    """``post`` sends a JSON body to Graph, and ``batch`` makes sense of the answer.

    No live call had ever been made with ``post``. ``$batch`` is the one POST that changes
    nothing and needs no permission beyond what its inner requests need, so it exercises
    ``post`` and ``batch`` together without writing to the tenant.

    The last inner request asks for a user by an id that cannot exist, with a scope that
    would not allow reading other users anyway. Either way it fails, and ``batch`` promises
    to hand that failure back in its place rather than raise.
    """
    requests = [
        {"method": "GET", "url": "/me?$select=id"},
        {"method": "GET", "url": "/me?$select=userPrincipalName"},
        {"method": "GET", "url": "/users/00000000-0000-0000-0000-000000000000"},
    ]
    async with GraphClient(user_auth, scopes=["User.Read"]) as graph:
        require_cached_sign_in(graph)
        responses = await graph.batch(requests)

    assert [response["id"] for response in responses] == ["0", "1", "2"]
    assert responses[0]["status"] == 200
    assert responses[0]["body"]["id"]
    assert responses[1]["status"] == 200
    assert responses[1]["body"]["userPrincipalName"].lower() == USERNAME.lower()
    assert responses[2]["status"] >= 400, "a request for a user that cannot exist succeeded"


@needs_user
async def test_default_scope_carries_only_what_the_tenant_already_granted(
    user_auth: AuthContext, cache_path: Path
) -> None:
    """A client with no ``scopes`` gets what was consented before, and nothing more.

    A Graph client without ``scopes`` asks for ``.default``. In a delegated flow Entra
    answers that with the permissions already granted to the application in the tenant --
    it is not a way to ask for new ones. That is the reason ``scopes=`` exists, and until
    this ran the evidence for it was only Microsoft's documentation.

    Two things show it. The ``.default`` token lacks a scope nobody granted. And asking for
    that scope by name cannot be done silently: it needs a consent prompt, which a context
    that may not prompt refuses with an error instead of opening.
    """
    async with GraphClient(user_auth) as graph:
        require_cached_sign_in(graph)
        token = await user_auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)
    granted = token_scopes(token.token)
    print(f".default token scopes: {' '.join(sorted(granted))}")

    assert granted, "the .default token carries no delegated scopes at all"
    assert UNGRANTED_SCOPE not in granted, (
        f"{UNGRANTED_SCOPE} is granted in this tenant; set AZURE_AUTH_TEST_UNGRANTED_SCOPE to a"
        " scope that is not"
    )

    async with GraphClient(cached_user_auth(cache_path), scopes=[UNGRANTED_SCOPE]) as graph:
        with pytest.raises((ConsentRequired, InteractionRequired)):
            await graph.get("/me", params={"$select": "id"})


@needs_user
@pytest.mark.slow
async def test_graph_throttling_is_waited_out(user_auth: AuthContext) -> None:
    """Requests that Graph throttles are retried and then succeed.

    ``max_retries`` had never run against the real service. The audit log is the honest way
    to provoke it: it carries the lowest limit Graph publishes, so bursts are refused
    without putting any load worth the name on the tenant.

    Whether a burst is refused at all is up to Graph, and it is not consistent: see
    THROTTLE_BURST. So this escalates in waves until a refusal arrives or the budget runs
    out, and skips when the service will not play, whether it refused nothing or kept
    refusing past the last retry. Both are the service's mood rather than a defect in the
    client, and neither gathers the evidence this test exists for.

    Microsoft documents that these resources answer 429 *without* a ``Retry-After`` header.
    They send one: 1, 2, 3 and 10 seconds were all seen. The test asserts neither way and
    prints what arrived, because which of the client's two waits runs depends on it, and only
    a live run can say. Both waits are covered offline.

    It stops at the first wave that is refused, so it costs 100 requests at the very most.
    It is marked ``slow`` because waiting out a refusal took 18 to 70 seconds over four runs,
    which is most of the budget the routine run is allowed.
    """
    counter = StatusCounter()
    sent = 0
    answers: list[Any] = []
    gave_up = ""
    async with GraphClient(
        user_auth, scopes=["AuditLog.Read.All"], transport=counter, max_retries=THROTTLE_RETRIES
    ) as graph:
        require_cached_sign_in(graph)
        while sent < THROTTLE_MAX_REQUESTS and not counter.throttled:
            wave = min(THROTTLE_BURST, THROTTLE_MAX_REQUESTS - sent)
            # $top=1 keeps every answer tiny: the limit counts requests, not what they return.
            try:
                answers.extend(
                    await asyncio.gather(
                        *(
                            graph.get("/auditLogs/directoryAudits", params={"$top": "1"})
                            for _ in range(wave)
                        )
                    )
                )
            except GraphError as error:
                if error.status != 429:
                    raise
                gave_up = f"Graph was still refusing after {THROTTLE_RETRIES} retries"
            sent += wave

    headers = [value if value is not None else "(absent)" for value in counter.retry_after]
    print(
        f"graph throttling: {sent} requests, statuses {dict(counter.statuses)}, "
        f"Retry-After: {headers or '(nothing was throttled)'}"
    )
    if gave_up:
        pytest.skip(gave_up)
    if not counter.throttled:
        pytest.skip(f"Graph answered {sent} audit log requests without throttling any of them")
    assert len(answers) == sent
    assert all("value" in answer for answer in answers), "a throttled request never succeeded"


@needs_user
def test_the_blocking_client_calls_graph(cache_path: Path) -> None:
    """The generated blocking client works against the real service, not only its mirror tests.

    The blocking clients are generated from the asynchronous ones and unit-tested through the
    same generated tests, but none had ever made a live call.
    """
    with BlockingGraphClient(cached_user_auth(cache_path), scopes=["User.Read"]) as graph:
        require_cached_sign_in(graph)
        me = graph.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()
