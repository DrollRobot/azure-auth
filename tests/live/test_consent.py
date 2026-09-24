"""A user who may not consent, against a tenant reset so that the application is not consented."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from azure_auth import AuthContext, AuthError, ConsentRequired, GraphClient
from tests import consent_reset
from tests.live.support import NONADMIN, TENANT, USERNAME, needs_nonadmin, needs_user, walkthrough

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
        f"Then the Graph sign-in test, as {USERNAME} again, with a consent screen: it grants"
        " back what this reset revoked, which is why it comes after. The browser is still"
        f" signed in as {NONADMIN} at that point, so choose 'Use another account' if it offers"
        " that one.",
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

    It runs before the Graph sign-in test on purpose (``test_consent.py`` collects before
    ``test_sign_in.py``). Its fixture revokes the Graph application's grants and puts nothing
    back; the Graph sign-in test that follows is what grants them again, through the consent
    screen the missing grants provoke. The Exchange and ARM sign-ins are other applications
    and restore nothing here.

    It also leaves the browser signed in as the non-administrator, which that test's
    walkthrough warns about.
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
