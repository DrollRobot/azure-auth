"""The Graph client against the real service: paging, batching, ``.default``, throttling, the
blocking mirror and, behind the destructive gate, writes.
"""

from __future__ import annotations

import asyncio
import collections
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest

from azure_auth import AuthContext, ConsentRequired, GraphClient, GraphError, NetworkError
from azure_auth.sync import GraphClient as BlockingGraphClient
from tests.live.support import (
    UNGRANTED_SCOPE,
    cached_user_auth,
    ensure_sign_in,
    is_test_user,
    live_user_auth,
    needs_graph,
    needs_user,
    tenant_domain,
    token_scopes,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio, needs_graph]

# What the grant test adds to the application's grant. Read-only, and outside BASELINE_SCOPES:
# the test is destructive_remote, so restore_baseline takes it back out afterwards.
GRANT_TEST_SCOPE = "Sites.Read.All"

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

# What the write test needs: creating, changing and deleting a user, and purging it from the
# recycle bin. Both are in BASELINE_SCOPES, so the sign-in is silent.
WRITE_SCOPES = ["User.ReadWrite.All", "User.DeleteRestore.All"]

# Graph's directory is replicated, so an object just created, or just deleted, can be "not
# found" by the next request when that one lands where the change has not reached. The write
# test retries a 404 for this long, looking this often.
REPLICATION_TIMEOUT = 120.0
POLL_SECONDS = 5.0


class StatusCounter(httpx2.AsyncBaseTransport):
    """A real network transport that counts the status of every response.

    A client retries a throttled request itself, so a 429 that was waited out never reaches
    the caller. This sits beneath the retry loop and sees every response, including the ones
    that were retried, which is the only way to tell "retried and succeeded" from "was never
    throttled at all".
    """

    def __init__(self) -> None:
        """Wrap the default ``httpx2`` network transport."""
        self._inner = httpx2.AsyncHTTPTransport()
        self.statuses: collections.Counter[int] = collections.Counter()
        self.retry_after: list[str | None] = []

    @property
    def throttled(self) -> int:
        """How many responses were 429 or 503, the statuses the client retries."""
        return self.statuses[429] + self.statuses[503]

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
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
async def test_a_request_that_gets_no_answer_in_time_is_a_network_error(
    user_auth: AuthContext,
) -> None:
    """A request to Graph that times out raises NetworkError, not the HTTP library's error.

    No TLS handshake completes in a millisecond. The token comes first, from MSAL, which the
    timeout does not apply to.
    """
    async with GraphClient(user_auth, scopes=["Application.Read.All"], timeout=0.001) as graph:
        ensure_sign_in(graph)
        with pytest.raises(NetworkError) as caught:
            await graph.get("/organization")

    assert str(caught.value).startswith(f"GET {graph.base_url}/organization failed: ")
    assert isinstance(caught.value.__cause__, httpx2.TimeoutException)


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
        ensure_sign_in(graph)
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
        ensure_sign_in(graph)
        responses = await graph.batch(requests)

    assert [response["id"] for response in responses] == ["0", "1", "2"]
    assert responses[0]["status"] == 200
    assert responses[0]["body"]["id"]
    assert responses[1]["status"] == 200
    assert is_test_user(responses[1]["body"]["userPrincipalName"])
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

    Two things show it, with ``UNGRANTED_SCOPE``, which the baseline leaves out. The
    ``.default`` token lacks it. And asking for it by name cannot be done silently: it needs a
    consent prompt, which a context that may not prompt refuses with an error instead of
    opening.

    Both requests go to Entra (``force_refresh``): a cached access token would answer for
    whatever was granted when it was issued, not for what is granted now.
    """
    async with GraphClient(user_auth) as graph:
        ensure_sign_in(graph)
        token = await user_auth.aio.acquire_token(
            graph.scopes, client_id=graph.client_id, force_refresh=True
        )
    granted = token_scopes(token.token)
    print(f".default token scopes: {' '.join(sorted(granted))}")

    assert granted, "the .default token carries no delegated scopes at all"
    assert UNGRANTED_SCOPE not in granted

    ungranted = cached_user_auth(cache_path)
    async with GraphClient(ungranted, scopes=[UNGRANTED_SCOPE]) as graph:
        with pytest.raises(ConsentRequired):
            await ungranted.aio.acquire_token(
                graph.scopes, client_id=graph.client_id, force_refresh=True
            )


@needs_user
@pytest.mark.destructive_remote
async def test_grant_when_possible_adds_a_missing_scope_where_no_prompt_can_appear(
    user_auth: AuthContext, cache_path: Path
) -> None:
    """A context that may not prompt grants the application a missing scope, then uses it.

    The same code path a GDAP customer tenant's context takes: the client checks what the
    tenant has granted, finds ``GRANT_TEST_SCOPE`` missing, sees the context cannot prompt,
    and, with ``grant_when_possible``, adds the scope to the application's tenant-wide grant
    and waits for a token that carries it. The baseline grants
    ``DelegatedPermissionGrant.ReadWrite.All``, which the grant needs.

    First, without the flag, the same request is refused with what is granted and missing,
    and nothing is asked of Entra for the missing scope. Marked ``destructive_remote``: the
    grant changes, and ``restore_baseline`` takes the scope back out after the test, pass or
    fail.
    """
    async with GraphClient(user_auth) as default:
        ensure_sign_in(default)
        granted = await default.granted_scopes()
    held = {scope.lower() for scope in granted}
    assert "delegatedpermissiongrant.readwrite.all" in held, "the baseline lacks the grant scope"
    assert GRANT_TEST_SCOPE.lower() not in held, f"the baseline already grants {GRANT_TEST_SCOPE}"

    quiet = cached_user_auth(cache_path)
    async with GraphClient(quiet, scopes=[GRANT_TEST_SCOPE]) as plain:
        with pytest.raises(ConsentRequired) as caught:
            await plain.login()
    assert caught.value.missing == (GRANT_TEST_SCOPE,)
    assert "could grant itself the requested scopes" in str(caught.value)

    started = time.monotonic()
    async with GraphClient(quiet, scopes=[GRANT_TEST_SCOPE], grant_when_possible=True) as graph:
        await graph.login()
        token = await quiet.aio.acquire_token(graph.scopes, client_id=graph.client_id)
    waited = time.monotonic() - started
    print(f"grant_when_possible: token carries {GRANT_TEST_SCOPE} after {waited:.0f}s")
    assert GRANT_TEST_SCOPE.lower() in {scope.lower() for scope in token_scopes(token.token)}


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
        ensure_sign_in(graph)
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
    with BlockingGraphClient(live_user_auth(cache_path), scopes=["User.Read"]) as graph:
        ensure_sign_in(graph)
        me = graph.get("/me", params={"$select": "userPrincipalName"})
    assert is_test_user(me["userPrincipalName"])


async def _once_replicated(call: Callable[[], Awaitable[Any]]) -> tuple[Any, float]:
    """Make a request about an object that may not have replicated yet.

    A 404 is retried every ``POLL_SECONDS`` until ``REPLICATION_TIMEOUT``; any other failure,
    or a 404 that outlives the timeout, is raised.

    Args:
        call: Makes the request.

    Returns:
        The answer, and how long the object took to be found, in seconds.
    """
    started = time.monotonic()
    while True:
        try:
            return await call(), time.monotonic() - started
        except GraphError as error:
            if error.status != 404 or time.monotonic() - started > REPLICATION_TIMEOUT:
                raise
        await asyncio.sleep(POLL_SECONDS)


@needs_user
@pytest.mark.destructive_remote
async def test_graph_creates_changes_and_removes_an_object(
    user_auth: AuthContext, cache_path: Path
) -> None:
    """``post``, ``patch``, ``put`` and ``delete`` change the real directory, not only ``$batch``.

    No live call had ever been made with ``patch``, ``put`` or ``delete``, and ``post`` only
    through ``$batch``. A user is the one directory object that takes every verb: it is
    created, its job title is changed, a manager is assigned (the one JSON ``PUT`` Graph has
    on a plain directory object), the assignment is removed, and the user is deleted. A
    deleted user sits in the recycle bin for thirty days, so it is purged as well, which is
    what ``User.DeleteRestore.All`` is in the baseline for; the rest is ``User.ReadWrite.All``.

    The account is disabled from the start, with a random password nobody is told, so it can
    never sign in. It is named after the test with a random suffix, addressed by its id once
    it exists, and deleted and purged in a ``finally`` so a failed assertion does not leave it
    behind. Graph answers each write with ``204 No Content``, which the client returns as
    ``None``, so every change is read back to prove it happened.

    The first read of the new user and the purge of the deleted one retry a 404
    (:func:`_once_replicated`); the waits are printed, since only a live run can say how long
    they take. Measured 2026-10-10: both 0s, so neither has yet been seen to retry.
    """
    marker = uuid.uuid4().hex[:8]
    nickname = f"azure-auth-live-test-{marker}"
    name = f"azure-auth live test {marker}"
    title = f"changed {marker}"
    async with GraphClient(user_auth, scopes=WRITE_SCOPES) as graph:
        ensure_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
        created = await graph.post(
            "/users",
            {
                "accountEnabled": False,
                "displayName": name,
                "mailNickname": nickname,
                # The domain the signed-in user is named under is verified in the tenant.
                "userPrincipalName": f"{nickname}@{tenant_domain(cache_path)}",
                "passwordProfile": {
                    "password": secrets.token_urlsafe(32),
                    "forceChangePasswordNextSignIn": True,
                },
            },
        )
        user_id = created["id"]
        try:
            assert created["displayName"] == name
            _, create_wait = await _once_replicated(
                lambda: graph.get(f"/users/{user_id}", params={"$select": "id"})
            )

            assert await graph.patch(f"/users/{user_id}", {"jobTitle": title}) is None
            changed = await graph.get(f"/users/{user_id}", params={"$select": "jobTitle"})
            assert changed["jobTitle"] == title

            manager_ref = {"@odata.id": f"{graph.base_url}/users/{me['id']}"}
            assert await graph.put(f"/users/{user_id}/manager/$ref", manager_ref) is None
            manager = await graph.get(f"/users/{user_id}/manager", params={"$select": "id"})
            assert manager["id"] == me["id"]

            assert await graph.delete(f"/users/{user_id}/manager/$ref") is None
            with pytest.raises(GraphError) as unassigned:
                await graph.get(f"/users/{user_id}/manager", params={"$select": "id"})
            assert unassigned.value.status == 404, str(unassigned.value)
        finally:
            await graph.delete(f"/users/{user_id}")
            _, purge_wait = await _once_replicated(
                lambda: graph.delete(f"/directory/deletedItems/{user_id}")
            )

        with pytest.raises(GraphError) as gone:
            await graph.get(f"/users/{user_id}", params={"$select": "id"})
        assert gone.value.status == 404, str(gone.value)

    print(f"graph write: read back after {create_wait:.0f}s, purged after {purge_wait:.0f}s")
