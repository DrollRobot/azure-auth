"""A user who may not consent, against a tenant whose consent is revoked for the test."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from azure_auth import AuthContext, AuthError, ConsentRequired, GraphClient
from tests import consent_reset
from tests.live.support import (
    NONADMIN,
    TENANT,
    USERNAME,
    ensure_consent_baseline,
    needs_nonadmin,
    needs_user,
    walkthrough,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# What the revoking fixture signs in with: deleting a grant needs the first, resolving the
# application's service principal the second, and /me the third. All three are in
# BASELINE_SCOPES, so this sign-in is silent: the token is already in the cache.
REVOKE_SCOPES = [
    "DelegatedPermissionGrant.ReadWrite.All",
    "Application.Read.All",
    "User.Read",
]

# How long to wait after deleting a grant before expecting a sign-in to be refused. Empirical:
# there is no propagation signal to poll. Override with AZURE_AUTH_TEST_CONSENT_SETTLE_SECONDS.
SETTLE_SECONDS = float(os.environ.get("AZURE_AUTH_TEST_CONSENT_SETTLE_SECONDS", "45"))

# What the non-administrator asks for. It must need admin consent, and it must NOT be in
# BASELINE_SCOPES.
#
# Entra grants an admin-consent-required permission to the whole tenant -- there is no
# "only for me" form of it -- so the administrator consenting to the baseline necessarily
# creates an AllPrincipals grant carrying those scopes, which covers every user including this
# one. Overlap therefore hands the non-administrator the very access the test expects them to
# be refused, and the test fails with "DID NOT RAISE". That is a loud failure rather than a
# silent pass, so this cannot fake a green run -- but it wasted several live runs before the
# cause was understood, which is why it is written down here.
NONADMIN_SCOPE = "User.ReadWrite.All"


@pytest.fixture
async def consent_revoked(cache_path: Path) -> AsyncIterator[str]:
    """Revoke the application's consent for the test, and restore the baseline afterwards.

    The consent test can only mean anything on a tenant where the application has *not* been
    consented: otherwise the non-administrator signs in silently and the test passes without
    any consent having happened. Making that a documented manual step would mean the test
    quietly stops testing anything the first time someone forgets, so the test carries its own
    precondition.

    Every tenant-wide grant goes, because a tenant-wide grant is precisely what would let the
    non-administrator through. The administrator's own grant is spared; revoking it would
    exercise nothing.

    On the way out, pass or fail, :func:`ensure_consent_baseline` puts the grants back: the
    administrator signs in again and accepts the consent screen. Whatever happened here, the
    next test starts at baseline.

    Yields:
        The signed-in administrator's object id, for the test to report on.
    """
    admin = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    try:
        async with GraphClient(admin, scopes=REVOKE_SCOPES) as graph:
            me = await graph.get("/me", params={"$select": "id"})
            principal = await consent_reset.service_principal(
                graph, consent_reset.GRAPH_CLI_CLIENT_ID
            )
            before = await consent_reset.find_grants(graph, str(principal["id"]))
            for grant in before:
                print(f"  before revoking: {consent_reset.describe(grant)}")
            result = await consent_reset.revoke_grants(graph, keep_principal_id=str(me["id"]))

        assert result.ok, f"could not revoke consent: {result.failed}"
        print(
            f"consent revoked: {len(result.deleted)} deleted, {len(result.kept)} kept, "
            f"confirmed after {result.rounds} round(s)"
        )

        if result.deleted:
            # Confirming the deletion through /oauth2PermissionGrants is not enough. That is
            # the read path; a sign-in is served by the token issuance path, which catches up
            # separately. Measured 2026-09-20: a revocation that re-read clean was followed
            # seconds later by a token issued to a user the deleted grant had covered.
            #
            # There is no propagation signal to poll, so this is an empirical wait. Raise it
            # if the test starts passing and failing at random; that symptom means it is too
            # short.
            print(f"  waiting {SETTLE_SECONDS}s for the deletion to reach token issuance")
            await asyncio.sleep(SETTLE_SECONDS)

        # The alarm sounds here, not at the start of the fixture: the admin's sign-in above
        # is silent, and the revocation and the settle wait need nobody. A beep a minute
        # before the first prompt teaches the person to ignore it.
        walkthrough(
            f"Sign-in prompt for the NON-ADMIN, {NONADMIN}. Pick or type that account -- not"
            " the admin. If it signs in as the admin without asking, the test fails and tells"
            " you to clear your browser cookies for login.microsoftonline.com.",
            "'Need admin approval' for the non-admin. Click 'Return to the application without"
            " granting consent'. Do NOT click 'Sign in with that account', and do NOT just close"
            " the tab -- closing it leaves the test waiting for a redirect that never arrives.",
            f"Sign-in prompt for the ADMIN again, {USERNAME}, to restore the baseline. The"
            f" browser is signed in as {NONADMIN} at that point, so choose 'Use another"
            " account'. Then a consent screen: tick 'Consent on behalf of your organization'"
            " if offered, and Accept.",
        )
        yield str(me["id"])
    finally:
        # Whatever happened above, including a revocation that failed half way, the tenant
        # goes back to baseline before the next test. Forced: the grants are known to be
        # gone, so the consent screen is coming and there is nothing to probe.
        await asyncio.to_thread(ensure_consent_baseline, cache_path, force=True)


@needs_user
@needs_nonadmin
@pytest.mark.interactive
@pytest.mark.destructive_remote
@pytest.mark.slow
async def test_a_user_who_may_not_consent_is_refused_with_a_useful_error(
    consent_revoked: str,
) -> None:
    """A non-administrator asking for an admin-consent-required scope is refused clearly.

    What Entra actually does, measured against a live tenant on 2026-09-20: the user is shown
    "Need admin approval", and leaving that page returns a bare ``access_denied`` -- no AADSTS
    code, no description. (Pressing Cancel on an ordinary consent screen is different:
    ``consent_required`` with ``AADSTS65004``, measured 2026-09-25; see
    ``test_a_cancelled_sign_in_is_reported_and_not_retried``.)

    So this is *not* a :class:`ConsentRequired`, and :meth:`AuthContext._consent` does not run.
    It cannot: retrying with ``prompt=consent`` would reopen the same "Need admin approval"
    page, and treating a cancellation as a reason to reopen the browser would be worse than
    the error. What the package owes the caller here is an error that says what happened, so
    that is what this asserts.

    Marked ``destructive_remote``: the fixture deletes consent grants in the tenant, so it
    needs ``--run-destructive-remote`` and a tenant marked disposable (see
    ``tests/verify_remote_disposable.py``).

    Two prompts need the person. The non-administrator's sign-in: on its "Need admin approval"
    page, click "Return to the application without granting consent" -- closing the window
    instead leaves MSAL waiting for a redirect that never comes. Then the administrator's
    sign-in and consent screen in the fixture's teardown, which restores the baseline.
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
