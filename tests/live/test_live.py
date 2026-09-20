"""Live end-to-end tests against a real tenant.

Nothing here runs unless the environment names a tenant. User-flow tests open a browser (or
the broker) the first time; after that the encrypted disk cache keeps them silent.

Every test that opens a sign-in prompt is marked ``interactive`` and needs a human at this
desktop. Only the app flow, which signs itself with a certificate, does not::

    uv run --env-file .env pytest tests/live -m "not interactive"   # unattended
    uv run --env-file .env pytest tests/live -m interactive         # user present

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

No secret is read from the environment; app flows use the certificate store.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

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
from tests import alert_user, consent_reset

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
# creates an AllPrincipals grant carrying those scopes. If the test asked for one of them, the
# reset fixture's own sign-in would hand the non-administrator the very access the test
# expects them to be refused. Keeping the two sets disjoint is what makes this test mean
# anything, whatever order things propagate in.
NONADMIN_SCOPE = "User.ReadWrite.All"

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


def walkthrough(*steps: str) -> None:
    """Tell the person at the desktop what they are about to see, and sound the alarm.

    An interactive test blocks on a browser window, and a window that is not understood gets
    answered wrongly: clicking "Sign in with that account" on a "Need admin approval" page, or
    closing the tab rather than returning to the application, both break a run in ways that
    look like product failures. So each test states its prompts in order, and what to do with
    each one, before the first one opens.

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


@pytest.fixture(scope="module")
def cache_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("azure-auth-live") / "cache.bin"


@pytest.fixture
def user_auth(cache_path: Path) -> AuthContext:
    return AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)


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
async def test_interactive_login_then_graph_me(user_auth: AuthContext) -> None:
    walkthrough(
        f"Sign-in prompt for {USERNAME}, asking for User.Read. Sign in and accept.",
    )
    async with GraphClient(user_auth, scopes=["User.Read"]) as graph:
        await graph.login()
        me = await graph.get("/me", params={"$select": "userPrincipalName"})
    assert me["userPrincipalName"].lower() == USERNAME.lower()


@needs_user
@pytest.mark.interactive
async def test_disk_cache_makes_the_second_run_silent(cache_path: Path) -> None:
    # A second context on the same cache file stands in for a second script run. Turning
    # prompting off proves the token really came from the cache.
    second_run = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    second_run._interactive_allowed = False
    async with GraphClient(second_run, scopes=["User.Read"]) as graph:
        me = await graph.get("/me", params={"$select": "id"})
    assert me["id"]


@needs_user
@_flag("AZURE_AUTH_TEST_ARM")
@pytest.mark.interactive
async def test_arm_lists_subscriptions(user_auth: AuthContext) -> None:
    walkthrough(
        f"Sign-in prompt for {USERNAME} against the Azure PowerShell client id, which'"
        "s a different application from the Graph one, so it asks again. Sign in and"
        " accept.",
    )
    async with AzureClient(user_auth) as arm:
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    # An empty list would also come back from a tenant the user cannot reach at all, so it
    # must not count as a pass; the flag says this user really has a subscription.
    assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert all(s.get("subscriptionId") for s in subscriptions)


@needs_user
@_flag("AZURE_AUTH_TEST_GDAP")
@pytest.mark.interactive
async def test_gdap_loop_reaches_customers_without_prompting(user_auth: AuthContext) -> None:
    walkthrough(
        f"Sign-in prompt for the partner user {USERNAME}, asking for"
        " DelegatedAdminRelationship.Read.All. Sign in and accept.",
        "No further prompts. Customer tenants are reached silently from that one"
        " sign-in; that is the point of the test.",
    )
    scopes = ["DelegatedAdminRelationship.Read.All", "Organization.Read.All"]
    async with GraphClient(user_auth, scopes=scopes) as partner:
        await partner.login()
        customers = await partner.list_customer_tenant_ids()
    assert customers, "the partner tenant has no GDAP customers"

    reached = 0
    skipped: list[str] = []
    for tenant_id in customers[:5]:
        async with GraphClient(user_auth.for_tenant(tenant_id), scopes=scopes[1:]) as graph:
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
@pytest.mark.interactive
async def test_exchange_runs_a_cmdlet(user_auth: AuthContext) -> None:
    walkthrough(
        f"Sign-in prompt for {USERNAME} against the Exchange Online PowerShell client"
        " id. Sign in and accept.",
    )
    async with ExchangeClient(user_auth) as exchange:
        config = await exchange.run("Get-OrganizationConfig")
    assert config
    assert "Name" in config[0]


@needs_user
@_flag("AZURE_AUTH_TEST_IPPS")
@pytest.mark.interactive
async def test_ipps_runs_a_cmdlet_through_the_regional_host(user_auth: AuthContext) -> None:
    walkthrough(
        "Possibly a sign-in prompt for the Security & Compliance scope. It reuses the"
        " Exchange client id, so it may be silent if that test ran first.",
    )
    async with IppsClient(user_auth) as ipps:
        labels = await ipps.run("Get-Label")
        assert isinstance(labels, list)
        assert ipps.base_url.endswith("ps.compliance.protection.outlook.com")


@needs_user
@pytest.mark.interactive
async def test_graph_paging_follows_next_links(user_auth: AuthContext) -> None:
    """``get_all`` walks every page of a Graph collection.

    Until this ran, no live Graph call had ever returned more than one page, so the
    ``@odata.nextLink`` loop was unproven against the real service -- the Exchange endpoint
    proves its own paging, but Graph's is separate code. ``$top`` forces the service to page a
    collection that would otherwise arrive whole, so this does not depend on the tenant being
    large.

    Service principals are used because every tenant has dozens of them, and because reading
    them needs ``Application.Read.All``, which the consent fixture already asks for.
    """
    page_size = 5
    walkthrough(
        f"Sign-in prompt for {USERNAME}, asking for Application.Read.All. Sign in, and"
        " accept the consent screen if one appears.",
    )
    async with GraphClient(user_auth, scopes=["Application.Read.All"]) as graph:
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
@needs_nonadmin
@pytest.mark.interactive
@pytest.mark.destructive_remote
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
