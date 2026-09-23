"""Live end-to-end tests against a real tenant.

Nothing here runs unless the environment names a tenant.

Only tests of interactive sign-in itself are marked ``interactive``: a forced browser sign-in
for each first-party client id, and the consent test. They need a human at this desktop, and
they leave their tokens in an encrypted disk cache that outlives the run.

Every other user-flow test only *uses* a signed-in account, so it is ``live`` but not
``interactive``. It cannot open a prompt: it takes its token from that cache, and skips when
there is none. So sign in once, then run the rest unattended for as long as the refresh token
lasts::

    uv run --env-file .env pytest tests/live -s -m interactive --no-cov        # user present
    uv run --env-file .env pytest tests/live -s -m "not interactive" --no-cov  # unattended

Environment variables:

* ``AZURE_AUTH_TEST_TENANT_ID`` and ``AZURE_AUTH_TEST_USERNAME``: user-flow tests.
* ``AZURE_AUTH_TEST_APP_CLIENT_ID`` and ``AZURE_AUTH_TEST_CERT_THUMBPRINT``: app-flow tests
  with a certificate in ``CurrentUser\\My`` (needs ``Organization.Read.All`` on Graph).
* ``AZURE_AUTH_TEST_NONADMIN_USERNAME``: a second user in the same tenant who may *not*
  consent. Naming one runs the consent test; leaving it blank skips it.
* ``AZURE_AUTH_TEST_ARM=1``: the user can see at least one Azure subscription. A tenant with
  no Azure access still answers ``/subscriptions`` with an empty list, which is why this is a
  flag and not something the test can work out for itself.
* ``AZURE_AUTH_TEST_GDAP=1``: the user is a partner user with GDAP customers.
* ``AZURE_AUTH_TEST_EXCHANGE=1`` / ``AZURE_AUTH_TEST_IPPS=1``: the user may run Exchange /
  Security & Compliance cmdlets.
* ``AZURE_AUTH_TEST_UNGRANTED_SCOPE``: a delegated Graph scope the tenant has never granted
  the Graph command-line application. Defaults to ``Mail.ReadWrite``.
* ``AZURE_AUTH_TEST_LONG_REFRESH=1``: run the test that waits out a real access token
  lifetime, about an hour.
* ``AZURE_AUTH_TEST_THROTTLE=1``: run the test that sends Graph requests until it is
  throttled. ``AZURE_AUTH_TEST_THROTTLE_REQUESTS`` caps how many (default 5000).
* ``AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS``: how long a sign-in may take before the alarm
  sounds (default 5). A browser that is still signed in answers faster than this.

No secret is read from the environment; app flows use the certificate store.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import contextlib
import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest
from azure.core.credentials import AccessTokenInfo

from azure_auth import (
    AuthContext,
    AuthError,
    AzureClient,
    ConsentRequired,
    ExchangeClient,
    GraphClient,
    InteractionRequired,
    IppsClient,
)
from azure_auth.auth.cache import build_cache, default_cache_path
from azure_auth.clients import ResourceClient
from azure_auth.sync import GraphClient as BlockingGraphClient
from azure_auth.sync import ResourceClient as BlockingResourceClient
from tests import alert_user, cache_aging, consent_reset

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# What the consent-reset fixture signs in with: deleting a grant needs the first, resolving
# the application's service principal the second, and /me the third.
RESET_SCOPES = [
    "DelegatedPermissionGrant.ReadWrite.All",
    "Application.Read.All",
    "User.Read",
]

# How long to wait after deleting a grant before expecting a sign-in to be refused. Empirical:
# there is no propagation signal to poll. Override with AZURE_AUTH_TEST_CONSENT_SETTLE_SECONDS.
SETTLE_SECONDS = float(os.environ.get("AZURE_AUTH_TEST_CONSENT_SETTLE_SECONDS", "45"))

# What the non-administrator asks for. It must need admin consent, and it must NOT be one of
# RESET_SCOPES above.
#
# Entra grants an admin-consent-required permission to the whole tenant -- there is no
# "only for me" form of it -- so the administrator consenting to RESET_SCOPES necessarily
# creates an AllPrincipals grant carrying those scopes, which covers every user including this
# one. Overlap therefore hands the non-administrator the very access the test expects them to
# be refused, and the test fails with "DID NOT RAISE". That is a loud failure rather than a
# silent pass, so this cannot fake a green run -- but it wasted several live runs before the
# cause was understood, which is why it is written down here.
NONADMIN_SCOPE = "User.ReadWrite.All"

# A delegated scope nobody in the tenant has granted the Graph command-line application. The
# .default test asserts it is missing from a .default token and cannot be had without a
# prompt. It must not be anything this module asks for (RESET_SCOPES, NONADMIN_SCOPE, the
# scopes of the other tests), or the suite would grant it and the test would fail. A tenant
# where it has been granted anyway needs another one named here.
UNGRANTED_SCOPE = os.environ.get("AZURE_AUTH_TEST_UNGRANTED_SCOPE", "Mail.ReadWrite")

# What the refresh tests sign in for. Anything every user may consent to would do.
REFRESH_SCOPES = ["User.Read"]

# The GDAP test's scopes, on the partner tenant and on each customer.
GDAP_SCOPES = ["DelegatedAdminRelationship.Read.All", "Organization.Read.All"]

# Every Graph scope a live test uses. The interactive Graph sign-in asks for all of them at
# once, so its consent screen covers the lot and the live tests find them in the cache. A
# live test that needs a new Graph scope must add it here, or it will only ever skip.
LIVE_GRAPH_SCOPES = [
    "User.Read",
    "Application.Read.All",
    *(GDAP_SCOPES if os.environ.get("AZURE_AUTH_TEST_GDAP") == "1" else []),
]

# The slow refresh test refuses to wait longer than this. Entra issues access tokens for a
# randomised 60 to 90 minutes, so anything longer means the token is not what was expected.
LONG_REFRESH_LIMIT_SECONDS = 2 * 60 * 60

# How long a forced sign-in may take before the person at the desktop is called. A browser
# that is still signed in answers it by itself well inside this; a sign-in page waiting for
# somebody does not. Override with AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS.
PROMPT_ALARM_SECONDS = float(os.environ.get("AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS", "5"))

# How many requests the throttling test may send before giving up, and how many at once.
THROTTLE_REQUESTS = int(os.environ.get("AZURE_AUTH_TEST_THROTTLE_REQUESTS", "5000"))
THROTTLE_CONCURRENCY = 50

TENANT = os.environ.get("AZURE_AUTH_TEST_TENANT_ID", "")
USERNAME = os.environ.get("AZURE_AUTH_TEST_USERNAME", "")
NONADMIN = os.environ.get("AZURE_AUTH_TEST_NONADMIN_USERNAME", "")
APP_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_APP_CLIENT_ID", "")
THUMBPRINT = os.environ.get("AZURE_AUTH_TEST_CERT_THUMBPRINT", "")

needs_user = pytest.mark.skipif(
    not (TENANT and USERNAME),
    reason="set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_USERNAME",
)
needs_nonadmin = pytest.mark.skipif(
    not (TENANT and NONADMIN),
    reason="set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_NONADMIN_USERNAME",
)
needs_app = pytest.mark.skipif(
    not (TENANT and APP_CLIENT_ID and THUMBPRINT),
    reason="set AZURE_AUTH_TEST_TENANT_ID, _APP_CLIENT_ID and _CERT_THUMBPRINT",
)


def _flag(name: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(os.environ.get(name) != "1", reason=f"set {name}=1")


def cached_user_auth(cache_path: Path) -> AuthContext:
    """Return a user-flow context that can never open a sign-in prompt.

    Every test that only *uses* a signed-in account is marked ``live`` and not
    ``interactive``, so it runs unattended under ``-m "not interactive"``. That is only true
    if it cannot prompt, so its context has prompting switched off: tokens come from the
    cache the interactive tests filled, or not at all.

    Args:
        cache_path: The shared disk cache.

    Returns:
        The context.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    auth._interactive_allowed = False
    return auth


def require_cached_sign_in(client: ResourceClient | BlockingResourceClient) -> None:
    """Skip the test unless its client can get a token from the cache.

    A missing sign-in is a missing precondition, like a missing environment variable, so it
    skips rather than fails. Only the two errors that mean "somebody has to sign in or
    consent" are treated that way; any other failure is left to fail the test.

    The token is kept, so the test that follows uses it without asking again.

    Args:
        client: The client the test is about to use. Its context must not prompt.
    """
    try:
        client.auth.acquire_token(client.scopes, client_id=client.client_id)
    except (InteractionRequired, ConsentRequired) as error:
        pytest.skip(
            f"no cached sign-in for client {client.client_id} with {' '.join(client.scopes)}"
            f" ({type(error).__name__}); sign in first with: pytest tests/live -s -m interactive"
        )


def walkthrough(*steps: str) -> None:
    """Tell the person at the desktop what they are about to see, and sound the alarm.

    An interactive test blocks on a browser window, and a window that is not understood gets
    answered wrongly: clicking "Sign in with that account" on a "Need admin approval" page, or
    closing the tab rather than returning to the application, both break a run in ways that
    look like product failures. So each test states its prompts in order, and what to do with
    each one.

    Call this directly only when somebody will certainly have to act, such as a second user
    signing in. Otherwise use :func:`walkthrough_if_waiting`.

    Needs ``pytest -s``; without it pytest captures this and the person sees nothing.

    Args:
        *steps: What will appear, in order, and what to click.
    """
    line = "=" * 78
    print(f"\n{line}\n  WHAT YOU WILL SEE, IN ORDER -- this test waits for you:\n")
    for number, step in enumerate(steps, 1):
        print(f"    {number}. {step}")
    print(f"\n{line}\n", flush=True)
    alert_user.main_for_tests()


@contextlib.contextmanager
def walkthrough_if_waiting(*steps: str) -> Iterator[None]:
    """Announce a sign-in only if it is still waiting after ``PROMPT_ALARM_SECONDS``.

    Wrap a forced sign-in, ``login(force=True)``. It always opens a browser window, but a
    browser that is still signed in often answers it by itself, and nobody needs calling for
    that. So the sign-in is timed, and only when it is still waiting after the delay does
    :func:`walkthrough` print the steps and sound the alarm. An alarm on every test would
    teach the person to ignore it.

    Args:
        *steps: What will appear, in order, and what to click.

    Yields:
        Nothing; the body is the sign-in.
    """
    # A timer thread, so it fires whether the sign-in blocks this thread (the blocking
    # client) or a worker thread (the asynchronous clients hand MSAL to asyncio.to_thread).
    timer = threading.Timer(PROMPT_ALARM_SECONDS, walkthrough, args=steps)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


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


async def assert_refreshed_without_prompting(
    auth: AuthContext, graph: GraphClient, expired: AccessTokenInfo, user_id: str
) -> None:
    """Call Graph once more and check a new token arrived with nobody asked to sign in.

    Both refresh tests end here, so the fast one (an aged cache) and the slow one (a real
    hour) are held to the same outcome, which is what lets the slow one vouch for the fast.

    Args:
        auth: The context behind ``graph``. Prompting is switched off on it.
        graph: A client whose last token has expired.
        expired: The token it last sent.
        user_id: Object id ``/me`` returned before the token expired.
    """
    # Prompting being off is what proves the new token came from the refresh token. With it
    # on, a broken refresh would open a browser, somebody would sign in, and the test would
    # pass. Live contexts already have it off; it is set again so this check never depends
    # on how the caller built its context.
    auth._interactive_allowed = False
    try:
        me = await graph.get("/me", params={"$select": "id"})
    except InteractionRequired as error:
        pytest.fail(f"refreshing the expired token needed a sign-in: {error}")
    renewed = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

    assert me["id"] == user_id
    assert renewed.token != expired.token, "the expired token was used again; nothing refreshed"
    assert renewed.expires_on > time.time(), "the refreshed token has already expired"


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

    @property
    def throttled(self) -> int:
        """How many responses were 429 or 503, the statuses the client retries."""
        return self.statuses[429] + self.statuses[503]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send the request over the network and count the response's status.

        Args:
            request: The outgoing request.

        Returns:
            The response, untouched.
        """
        response = await self._inner.handle_async_request(request)
        self.statuses[response.status_code] += 1
        return response

    async def aclose(self) -> None:
        """Close the wrapped transport."""
        await self._inner.aclose()


@pytest.fixture(scope="module")
def cache_path() -> Path:
    """The encrypted disk cache the interactive tests fill and the live tests read.

    It outlives the run, so one interactive sign-in serves the live tests of later,
    unattended runs until the refresh token lapses. It sits beside the package's default
    cache, in the per-user cache directory, but in a file of its own, so test tokens and
    real ones never mix.
    """
    return default_cache_path().with_name("live_tests_token_cache.bin")


@pytest.fixture
def user_auth(cache_path: Path) -> AuthContext:
    return cached_user_auth(cache_path)


@pytest.fixture
async def consent_reset_to_baseline(cache_path: Path) -> str:
    """Revoke the application's consent, leaving only the administrator's own grant.

    The consent test can only mean anything on a tenant where the application has *not* been
    consented: otherwise the non-administrator signs in silently and the test passes without
    any consent having happened. Making that a documented manual step would mean the test
    quietly stops testing anything the first time someone forgets, so the test carries its own
    precondition.

    The administrator's own grant is spared. It is what this fixture needs to make these calls
    at all, and revoking it would only force the administrator to re-consent every run to
    restore tooling access -- which exercises nothing. Every tenant-wide grant goes, because a
    tenant-wide grant is precisely what would let the non-administrator through.

    Returns:
        The signed-in administrator's object id, for the test to report on.
    """
    walkthrough(
        f"Sign-in prompt for the ADMIN, {USERNAME}. Sign in.",
        "Consent prompt for the admin, listing DelegatedPermissionGrant.ReadWrite.All and"
        " Application.Read.All. Tick 'Consent on behalf of your organization' if offered,"
        " then click Accept. (These scopes are always granted tenant-wide anyway.)",
        f"A pause of about {SETTLE_SECONDS:.0f}s while the reset propagates. Nothing to do.",
        f"Sign-in prompt for the NON-ADMIN, {NONADMIN}. Pick or type that account -- not the"
        " admin. If it signs in as the admin without asking, the test fails and tells you to"
        " clear your browser cookies for login.microsoftonline.com.",
        "'Need admin approval' for the non-admin. Click 'Return to the application without"
        " granting consent'. Do NOT click 'Sign in with that account', and do NOT just close"
        " the tab -- closing it leaves the test waiting for a redirect that never arrives.",
    )
    admin = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with GraphClient(admin, scopes=RESET_SCOPES) as graph:
        me = await graph.get("/me", params={"$select": "id"})
        before = await consent_reset.find_grants(
            graph,
            str(
                (await consent_reset.service_principal(graph, consent_reset.GRAPH_CLI_CLIENT_ID))[
                    "id"
                ]
            ),
        )
        for grant in before:
            print(f"  before reset: {consent_reset.describe(grant)}")
        result = await consent_reset.reset_to_baseline(graph, keep_principal_id=str(me["id"]))

    assert result.ok, f"could not reset consent: {result.failed}"
    print(
        f"consent reset: {len(result.deleted)} deleted, {len(result.kept)} kept, "
        f"confirmed after {result.rounds} round(s)"
    )

    if result.deleted:
        # Confirming the deletion through /oauth2PermissionGrants is not enough. That is the
        # read path; a sign-in is served by the token issuance path, which catches up
        # separately. Measured 2026-09-20: a reset that re-read clean was followed seconds
        # later by a token issued to a user the deleted grant had covered.
        #
        # There is no propagation signal to poll, so this is an empirical wait. Raise it if
        # the test starts passing and failing at random; that symptom means it is too short.
        print(f"  waiting {SETTLE_SECONDS}s for the deletion to reach token issuance")
        await asyncio.sleep(SETTLE_SECONDS)
    return str(me["id"])


@needs_user
@pytest.mark.interactive
async def test_interactive_login_then_graph_me(cache_path: Path) -> None:
    """A forced browser sign-in to the Graph client id works and signs in the right user.

    The sign-in is forced, so the interactive flow runs even when the cache could have
    answered: the point is to test it, not to get a token. It asks for every scope the live
    Graph tests use, so its consent screen covers them all and they find their tokens in the
    cache afterwards.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with GraphClient(auth, scopes=LIVE_GRAPH_SCOPES) as graph:
        with walkthrough_if_waiting(
            f"Sign-in prompt for {USERNAME}, asking for {', '.join(LIVE_GRAPH_SCOPES)}. Sign"
            " in, and accept the consent screen if one appears.",
        ):
            await graph.login(force=True)
        me = await graph.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()


# The Exchange Online PowerShell client id serves both the Exchange and the IPPS tests.
_needs_exchange_or_ipps = pytest.mark.skipif(
    "1" not in (os.environ.get("AZURE_AUTH_TEST_EXCHANGE"), os.environ.get("AZURE_AUTH_TEST_IPPS")),
    reason="set AZURE_AUTH_TEST_EXCHANGE=1 or AZURE_AUTH_TEST_IPPS=1",
)


@needs_user
@pytest.mark.interactive
@pytest.mark.parametrize(
    ("make_client", "application"),
    [
        pytest.param(
            ExchangeClient,
            "Exchange Online PowerShell",
            marks=_needs_exchange_or_ipps,
            id="exchange",
        ),
        pytest.param(AzureClient, "Azure PowerShell", marks=_flag("AZURE_AUTH_TEST_ARM"), id="arm"),
    ],
)
async def test_interactive_login_to_another_first_party_client(
    make_client: Callable[[AuthContext], ResourceClient], application: str, cache_path: Path
) -> None:
    """A forced browser sign-in works for each first-party client id besides Graph's.

    Each resource client defaults to its own Microsoft application, and a refresh token for
    one cannot be spent on another, so each needs its own interactive sign-in. This does that
    sign-in, and then checks what the live tests rely on: a context that may not prompt finds
    the token in the cache.
    """
    auth = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    async with make_client(auth) as client:
        with walkthrough_if_waiting(
            f"Sign-in prompt for {USERNAME} against the {application} client id, a different"
            " application from the Graph one. Sign in and accept.",
        ):
            await client.login(force=True)

    cached = cached_user_auth(cache_path)
    token = await cached.aio.acquire_token(client.scopes, client_id=client.client_id)
    assert token.token


@needs_user
async def test_disk_cache_makes_the_second_run_silent(cache_path: Path) -> None:
    # A second context on the same cache file stands in for a second script run. It cannot
    # prompt, which proves the token really came from the cache.
    second_run = cached_user_auth(cache_path)
    async with GraphClient(second_run, scopes=["User.Read"]) as graph:
        require_cached_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
    assert me["id"]


@needs_user
@_flag("AZURE_AUTH_TEST_ARM")
async def test_arm_lists_subscriptions(user_auth: AuthContext) -> None:
    async with AzureClient(user_auth) as arm:
        require_cached_sign_in(arm)
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    # An empty list would also come back from a tenant the user cannot reach at all, so it
    # must not count as a pass; the flag says this user really has a subscription.
    assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert all(s.get("subscriptionId") for s in subscriptions)


@needs_user
@_flag("AZURE_AUTH_TEST_GDAP")
async def test_gdap_loop_reaches_customers_without_prompting(user_auth: AuthContext) -> None:
    async with GraphClient(user_auth, scopes=GDAP_SCOPES) as partner:
        require_cached_sign_in(partner)
        customers = await partner.list_customer_tenant_ids()
    assert customers, "the partner tenant has no GDAP customers"

    reached = 0
    skipped: list[str] = []
    for tenant_id in customers[:5]:
        sibling = user_auth.for_tenant(tenant_id)
        async with GraphClient(sibling, scopes=GDAP_SCOPES[1:]) as graph:
            try:
                organization = await graph.get_all("/organization")
            except (ConsentRequired, InteractionRequired) as error:
                # Expected for a customer without consent; the error names the tenant.
                skipped.append(error.tenant_id)
                continue
        assert organization[0]["id"] == tenant_id
        reached += 1
    assert reached, "no customer tenant could be reached silently"
    assert set(skipped) <= set(customers)


@needs_user
@_flag("AZURE_AUTH_TEST_EXCHANGE")
async def test_exchange_runs_a_cmdlet(user_auth: AuthContext) -> None:
    async with ExchangeClient(user_auth) as exchange:
        require_cached_sign_in(exchange)
        config = await exchange.run("Get-OrganizationConfig")
    assert config
    assert "Name" in config[0]


@needs_user
@_flag("AZURE_AUTH_TEST_IPPS")
async def test_ipps_runs_a_cmdlet_through_the_regional_host(user_auth: AuthContext) -> None:
    async with IppsClient(user_auth) as ipps:
        require_cached_sign_in(ipps)
        labels = await ipps.run("Get-Label")
        assert isinstance(labels, list)
        assert ipps.base_url.endswith("ps.compliance.protection.outlook.com")


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
async def test_an_expired_access_token_is_refreshed_without_prompting(cache_path: Path) -> None:
    """A later run whose cached access token has expired gets a new one from the refresh token.

    Nothing had run longer than about 90 seconds against a live tenant, so the refresh path
    had never executed -- and it is exactly what a script run twice an hour apart depends on.
    Rather than wait for the token to expire, this ages it in the cache file. The cost is that
    it partly tests the ageing, which is why the ageing has its own integration test and the
    slow test below waits out a real token lifetime to confirm this one.

    A second context stands in for the later run. The first one would not do: its in-process
    memo still holds the token with its real expiry, so it would never look at the cache.
    """
    auth = cached_user_auth(cache_path)
    async with GraphClient(auth, scopes=REFRESH_SCOPES) as graph:
        require_cached_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
        expiring = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

    aged = cache_aging.expire_access_tokens(build_cache("disk", cache_path))
    assert aged, "the disk cache held no access token to expire"

    later_run = cached_user_auth(cache_path)
    async with GraphClient(later_run, scopes=REFRESH_SCOPES) as graph:
        await assert_refreshed_without_prompting(later_run, graph, expiring, str(me["id"]))


@needs_user
@_flag("AZURE_AUTH_TEST_LONG_REFRESH")
@pytest.mark.slow
async def test_a_real_token_lifetime_ends_in_a_silent_refresh(cache_path: Path) -> None:
    """One long-running client outlives its access token and carries on without a prompt.

    This is the truthful version of the ageing test above: nothing is faked, the test simply
    waits until the token has expired. Run it by hand, once, to confirm the ageing models what
    really happens; it is too slow for a routine run.

    It keeps one context and one client for the whole wait, as a long-running process would,
    so it also covers what the fast test cannot: the context's in-process memo declining a
    token within ``_REFRESH_MARGIN_SECONDS`` of expiry, and handing the request to MSAL.
    """
    auth = cached_user_auth(cache_path)
    async with GraphClient(auth, scopes=REFRESH_SCOPES) as graph:
        require_cached_sign_in(graph)
        me = await graph.get("/me", params={"$select": "id"})
        expiring = await auth.aio.acquire_token(graph.scopes, client_id=graph.client_id)

        # A minute past expiry, so a little clock skew cannot land the call just before it.
        wait = expiring.expires_on - time.time() + 60
        assert wait < LONG_REFRESH_LIMIT_SECONDS, f"the token lives {wait / 60:.0f} minutes"
        print(f"  waiting {wait / 60:.0f} minutes for the access token to expire")
        await asyncio.sleep(wait)

        await assert_refreshed_without_prompting(auth, graph, expiring, str(me["id"]))


@needs_user
@_flag("AZURE_AUTH_TEST_THROTTLE")
@pytest.mark.slow
async def test_graph_throttling_is_waited_out(user_auth: AuthContext) -> None:
    """Requests that Graph throttles are retried after ``Retry-After`` and then succeed.

    ``max_retries`` had never been exercised against the real service. The only way to make
    Graph throttle is to send it more than it will take, so this sends ``/me`` requests in
    waves until it sees a 429 or 503, and requires every request to have succeeded in the end.

    It is a deliberate load test on the tenant, which is why it needs its own flag. It fails,
    rather than passing, if the budget runs out before Graph ever throttled: a run that was
    never throttled has tested nothing.
    """
    counter = StatusCounter()
    sent = 0
    async with GraphClient(user_auth, scopes=["User.Read"], transport=counter) as graph:
        require_cached_sign_in(graph)
        print(f"  sending up to {THROTTLE_REQUESTS} requests until Graph throttles")
        while sent < THROTTLE_REQUESTS and not counter.throttled:
            wave = min(THROTTLE_CONCURRENCY, THROTTLE_REQUESTS - sent)
            # A request still throttled after max_retries raises GraphError here, which fails
            # the test with Graph's own answer.
            answers = await asyncio.gather(
                *(graph.get("/me", params={"$select": "id"}) for _ in range(wave))
            )
            sent += wave
            assert all(answer["id"] for answer in answers)

    print(f"graph throttling: {sent} requests, statuses {dict(counter.statuses)}")
    assert counter.throttled, (
        f"Graph never throttled {sent} requests; raise AZURE_AUTH_TEST_THROTTLE_REQUESTS"
    )


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


@needs_user
@needs_nonadmin
@pytest.mark.interactive
@pytest.mark.destructive_remote
@pytest.mark.slow
async def test_a_user_who_may_not_consent_is_refused_with_a_useful_error(
    consent_reset_to_baseline: str,
) -> None:
    """A non-administrator asking for an admin-consent-required scope is refused clearly.

    What Entra actually does, measured against a live tenant on 2026-09-20: the user is shown
    "Need admin approval", and leaving that page returns a bare ``access_denied`` -- no AADSTS
    code, no description, nothing that distinguishes it from pressing Cancel on an ordinary
    consent screen.

    So this is *not* a :class:`ConsentRequired`, and :meth:`AuthContext._consent` does not run.
    It cannot: retrying with ``prompt=consent`` would reopen the same "Need admin approval"
    page, and treating a cancellation as a reason to reopen the browser would be worse than
    the error. What the package owes the caller here is an error that says what happened, so
    that is what this asserts.

    Marked ``destructive_remote``: the fixture deletes consent grants in the tenant, so it
    needs ``--run-destructive-remote`` and a tenant marked disposable (see
    ``tests/verify_remote_disposable.py``).

    Two sign-in windows appear. The administrator's, for the reset, then the
    non-administrator's. On the second, click "Return to the application without granting
    consent" -- closing the window instead leaves MSAL waiting for a redirect that never comes.
    """
    auth = AuthContext(TENANT, username=NONADMIN)
    async with GraphClient(auth, scopes=[NONADMIN_SCOPE]) as graph:
        with pytest.raises(AuthError) as caught:
            await graph.get("/users", params={"$top": "1"})

    message = str(caught.value)
    # Signing in as the wrong account produces an AuthError too, and would otherwise look like
    # a pass. It means the browser reused an existing session instead of asking for this user.
    assert "Signed in as" not in message, (
        "the browser signed in as somebody else; sign out of the tenant in the browser first"
    )
    # A bare "access_denied" tells whoever reads the traceback nothing at all.
    assert "access_denied" in message
    assert NONADMIN_SCOPE in message
    assert TENANT in message
    assert "Need admin approval" in message
    # ConsentRequired would have meant the retry ran; it must not have.
    assert not isinstance(caught.value, ConsentRequired)


@needs_app
async def test_app_flow_with_a_store_certificate() -> None:
    auth = AuthContext(TENANT, client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT)
    async with GraphClient(auth) as graph:
        organization = await graph.get_all("/organization")
    assert organization
    # Which algorithm Entra ID accepted for this key is worth knowing; see plan section 4.
    print(f"client assertion algorithm in use: {auth._credential.algorithm}")  # type: ignore[union-attr]
