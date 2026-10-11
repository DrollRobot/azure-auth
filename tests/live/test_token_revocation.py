"""A token revoked underneath a running client: continuous access evaluation, live.

Every sign-in declares that it handles claims challenges (``CP1``), so Graph issues tokens
that live about a day and takes them back early by challenge: a 401 whose
``WWW-Authenticate`` header carries the claims a new token must satisfy. The client answers
it by acquiring a token with those claims and sending the request again
(``clients/base.py``); an Azure SDK client answers it by calling the credential's
``get_token`` with them. Neither had run against the real service until this did.

The event here is the account's own sign-in sessions being revoked, which kills every refresh
token with them, so the token the challenge asks for can only come from a new sign-in: the
one interactive step. Revoking sessions is what an administrator does to a compromised
account, so it is the case that matters most.
"""

from __future__ import annotations

import asyncio
import collections
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from azure_auth import AuthContext, GraphClient, InteractionRequired
from azure_auth.clients.base import claims_from_challenge
from azure_auth.constants import GRAPH_CLI_CLIENT_ID
from tests.live.support import (
    cached_user_auth,
    ensure_sign_in,
    expire_cached_access_tokens,
    live_cloud,
    needs_graph,
    needs_user,
    sign_in_step,
    walkthrough,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio, needs_graph]

# What the test signs in for: reading /me, and revoking the account's sessions, which the
# second allows. Both are in BASELINE_SCOPES, so the sign-in is silent.
SCOPES = ["User.Read", "User.ReadWrite.All"]

# How long Graph may take to refuse the revoked token, and how often it is asked. Microsoft
# says "a small delay of a few minutes" and nothing more precise; the delay is printed.
CHALLENGE_TIMEOUT_SECONDS = 15 * 60
CHALLENGE_POLL_SECONDS = 10.0


class ChallengeWatcher(httpx.AsyncBaseTransport):
    """A real network transport that sees the 401 the client answers, and calls the person.

    The client retries a challenged request itself, so the 401 never reaches the test. This
    sits beneath the retry loop, counts every response's status and keeps the
    ``WWW-Authenticate`` header of each 401. On the first one it prints the walkthrough and
    sounds the alarm: the client is about to answer the challenge, and with the sessions
    revoked that is a browser sign-in only the person at the desktop can complete.
    """

    def __init__(self) -> None:
        """Wrap the default ``httpx`` network transport."""
        self._inner = httpx.AsyncHTTPTransport()
        self.statuses: collections.Counter[int] = collections.Counter()
        self.challenges: list[str | None] = []
        self.challenged_at: float | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send the request over the network and record the response's status.

        Args:
            request: The outgoing request.

        Returns:
            The response, untouched.
        """
        response = await self._inner.handle_async_request(request)
        self.statuses[response.status_code] += 1
        if response.status_code == httpx.codes.UNAUTHORIZED:
            self.challenges.append(response.headers.get("WWW-Authenticate"))
            if self.challenged_at is None:
                self.challenged_at = time.monotonic()
                walkthrough(sign_in_step("browser"))
        return response

    async def aclose(self) -> None:
        """Close the wrapped transport."""
        await self._inner.aclose()


def challenge_not_before(claims: str) -> int | None:
    """Read the earliest issue time a claims challenge will accept.

    A revocation challenge asks for a token issued after the event:
    ``{"access_token": {"nbf": {"essential": true, "value": "<seconds>"}}}``.

    Args:
        claims: The challenge's claims, as JSON.

    Returns:
        The time, in seconds since the epoch, or ``None`` when the challenge asks for
        something else.
    """
    try:
        return int(json.loads(claims)["access_token"]["nbf"]["value"])
    except (ValueError, TypeError, KeyError):
        return None


@needs_user
@pytest.mark.interactive
@pytest.mark.slow
async def test_a_revoked_sessions_challenge_is_answered_by_a_new_sign_in(
    user_auth: AuthContext, cache_path: Path
) -> None:
    """Graph challenges a token whose sessions were revoked; the client and the credential answer.

    The signed-in user revokes their own sessions through the client, then keeps calling
    ``/me`` through it, with the same token, until Graph refuses it. The refusal is a 401 with
    a claims challenge (the watcher beneath the client sees it); the client acquires a token
    with those claims, which with the refresh token dead is a browser sign-in; and the same
    call then succeeds with a new token. Graph accepting it is the proof that it meets the
    challenge. The token's own times cannot show it: Entra stamps ``iat`` and ``nbf`` five
    minutes before the token is issued (measured 2026-10-11), so a token issued after the time
    the challenge names still reads as issued before it. How long the challenge took to
    arrive, and how many calls the revoked token answered first, are printed: only a live run
    can say.

    Then the credential, as an SDK client calls it on the same challenge: ``get_token`` with
    the claims. That context signs in to the Graph command-line application too, whose
    refresh token the sign-in just renewed, so the claims must be met without a prompt. A
    prompt here would mean Entra wanted a sign-in for a claims request a live session can
    satisfy, which is worth failing on rather than answering. The token it hands back is tried
    against Graph by plain HTTP.

    Interactive: the revocation ends the browser's session as well, so the sign-in cannot
    complete by itself. It ends every other sign-in the account holds too, in every
    application, so it runs first among the interactive tests (``conftest.py``), whose forced
    sign-ins refill the caches after it. On the way out the caches' access tokens are expired
    (:func:`expire_cached_access_tokens`), so a test whose application no forced sign-in
    renewed signs in where it is announced, rather than being refused on its first request.
    """
    graph_url = live_cloud().graph
    watcher = ChallengeWatcher()
    async with GraphClient(user_auth, scopes=SCOPES, transport=watcher) as graph:
        ensure_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
        revoked = await user_auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)
        await graph.post("/me/revokeSignInSessions")
        revoked_at = time.monotonic()
        try:
            calls = 0
            answered: Any = None
            while (challenged_at := watcher.challenged_at) is None:
                waited = time.monotonic() - revoked_at
                if waited > CHALLENGE_TIMEOUT_SECONDS:
                    pytest.fail(
                        f"Graph still accepted the revoked token {waited:.0f}s after the"
                        f" sessions were revoked, on all {calls} calls"
                    )
                await asyncio.sleep(CHALLENGE_POLL_SECONDS)
                answered = await graph.get("/me", params={"$select": "id"})
                calls += 1
            renewed = await user_auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

            header = watcher.challenges[0]
            claims = claims_from_challenge(header)
            print(
                f"token revocation: challenged after {challenged_at - revoked_at:.0f}s, on call"
                f" {calls}; statuses {dict(watcher.statuses)}; claims {claims}"
            )
            assert watcher.statuses[401] == 1, "the token acquired with the claims was refused"
            assert claims is not None, f"the 401 carried no claims challenge: {header!r}"
            not_before = challenge_not_before(claims)
            assert not_before is not None, f"the challenge asks for something else: {claims}"
            assert answered["id"] == me["id"]
            assert renewed.token != revoked.token, "the call succeeded with the revoked token"

            # The SDK side: azure-core reads the claims out of the challenge and calls
            # get_token with them, and enable_cae, on the credential it was given.
            sdk = cached_user_auth(cache_path, client_id=GRAPH_CLI_CLIENT_ID)
            try:
                sdk_token = await sdk.aio.get_token(
                    f"{graph_url}/.default", claims=claims, enable_cae=True
                )
            except InteractionRequired as error:
                pytest.fail(f"the credential's claims request needed a sign-in: {error}")
            assert sdk_token.token != revoked.token
            async with httpx.AsyncClient() as http:
                response = await http.get(
                    f"{graph_url}/v1.0/me",
                    params={"$select": "id"},
                    headers={"Authorization": f"Bearer {sdk_token.token}"},
                )
            assert response.status_code == 200, response.text
            assert response.json()["id"] == me["id"]
        finally:
            expired = expire_cached_access_tokens(cache_path)
            print(
                f"token revocation: expired {expired} cached access token(s) the revocation killed"
            )
