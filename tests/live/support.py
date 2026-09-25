"""What the live tests share: the environment, the skip markers and the sign-in helpers.

Environment variables:

* ``AZURE_AUTH_TEST_TENANT_ID`` and ``AZURE_AUTH_TEST_USERNAME``: user-flow tests.
* ``AZURE_AUTH_TEST_APP_CLIENT_ID`` and ``AZURE_AUTH_TEST_CERT_THUMBPRINT``: app-flow tests
  with a certificate in ``CurrentUser\\My`` (needs ``Organization.Read.All`` on Graph).
* ``AZURE_AUTH_TEST_NONADMIN_USERNAME``: a second user in the same tenant who may *not*
  consent. Naming one runs the consent test; leaving it blank skips it.
* ``AZURE_AUTH_TEST_ARM=1``: the user can see at least one Azure subscription. A tenant with
  no Azure access still answers ``/subscriptions`` with an empty list, which is why this is a
  flag and not something the test can work out for itself.
* ``AZURE_AUTH_TEST_GDAP=1``: the user's home tenant manages other tenants through GDAP.
* ``AZURE_AUTH_TEST_EXCHANGE=1`` / ``AZURE_AUTH_TEST_IPPS=1``: the user may run Exchange /
  Security & Compliance cmdlets.
* ``AZURE_AUTH_TEST_UNGRANTED_SCOPE``: a delegated Graph scope the tenant has never granted
  the Graph command-line application. Defaults to ``Mail.ReadWrite``.
* ``AZURE_AUTH_TEST_LONG_REFRESH=1``: run the test that waits out a real access token
  lifetime, about an hour.
* ``AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS``: how long a sign-in may take before the alarm
  sounds (default 5). A browser that is still signed in answers faster than this.

No secret is read from the environment; app flows use the certificate store.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

from azure_auth import AuthContext, ConsentRequired, InteractionRequired
from azure_auth.clients import ResourceClient
from azure_auth.constants import GRAPH_CLI_CLIENT_ID
from azure_auth.sync import ResourceClient as BlockingResourceClient
from tests import alert_user

# The GDAP test's scopes, on the home tenant and on each managed tenant.
GDAP_SCOPES = ["DelegatedAdminRelationship.Read.All", "Organization.Read.All"]

# The consent baseline: every Graph scope a live test needs, granted to the Graph
# command-line application in the tenant. It is a floor, not an exact state. A tenant at
# baseline holds at least these; grants beyond them are fine and left alone.
# `ensure_consent_baseline` brings the tenant here before the first test that uses the shared
# sign-in, and again after any test that revokes consent.
#
# A live test that needs a new Graph scope adds it here, or it only ever skips. Two scopes
# must never appear here: NONADMIN_SCOPE in test_consent.py, which the non-administrator has
# to be refused, and UNGRANTED_SCOPE in test_graph_client.py, which has to stay ungranted.
BASELINE_SCOPES = [
    "User.Read",
    "Application.Read.All",
    # The throttling test reads the audit log, the one resource with a limit low enough to
    # trip on purpose.
    "AuditLog.Read.All",
    # The consent test's fixture deletes grants, which needs this.
    "DelegatedPermissionGrant.ReadWrite.All",
    *(GDAP_SCOPES if os.environ.get("AZURE_AUTH_TEST_GDAP") == "1" else []),
]

# How long a forced sign-in may take before the person at the desktop is called. A browser
# that is still signed in answers it by itself well inside this; a sign-in page waiting for
# somebody does not. Override with AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS.
PROMPT_ALARM_SECONDS = float(os.environ.get("AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS", "5"))

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


def cached_user_auth(cache_path: Path, *, tenant: str = TENANT) -> AuthContext:
    """Return a user-flow context that can never open a sign-in prompt.

    Every test that only *uses* a signed-in account is marked ``live`` and not
    ``interactive``, so it runs unattended under ``-m "not interactive"``. That is only true
    if it cannot prompt, so its context has prompting switched off: tokens come from the
    cache the interactive tests filled, or not at all.

    Args:
        cache_path: The shared disk cache.
        tenant: The tenant to address, by id or by a verified domain name. The default is
            the configured one; a test that wants the same tenant under another name passes
            it here, and the cache still answers because MSAL keys tokens by the tenant id
            that the authority resolves to.

    Returns:
        The context.
    """
    auth = AuthContext(tenant, username=USERNAME, cache="disk", cache_path=cache_path)
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


def token_claims(token: str) -> dict[str, Any]:
    """Read the claims out of an access token, without validating it.

    Nothing here checks the signature; the token came straight from Entra and is only
    being inspected.

    Args:
        token: A JWT access token.

    Returns:
        The payload claims.
    """
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return dict(claims)


def token_scopes(token: str) -> set[str]:
    """Read the delegated scopes out of an access token, without validating it.

    Access tokens are JWTs whose ``scp`` claim lists the delegated permissions Entra
    actually issued, which may differ from what was asked for.

    Args:
        token: An access token.

    Returns:
        The scope names, such as ``{"User.Read", "Application.Read.All"}``.
    """
    return set(str(token_claims(token).get("scp", "")).split())


def token_user(token: str) -> str | None:
    """Read the signed-in user's name out of an access token.

    A v2 token names the user in ``preferred_username``; a v1 token, which the Exchange and
    ARM resources issue, in ``upn`` (or ``unique_name`` for an account without one).

    Args:
        token: An access token from a user flow.

    Returns:
        The user principal name, or ``None`` when the token names nobody.
    """
    claims = token_claims(token)
    for name in ("preferred_username", "upn", "unique_name"):
        if claims.get(name):
            return str(claims[name])
    return None


def missing_scopes(token: str, required: Iterable[str]) -> set[str]:
    """Return the scopes in ``required`` that ``token`` does not carry.

    Args:
        token: A Graph access token.
        required: The scopes it should carry.

    Returns:
        The required scopes absent from the token's ``scp`` claim; empty when all are there.
        Scopes the token carries beyond ``required`` are not reported: the baseline is a floor.
    """
    return set(required) - token_scopes(token)


def ensure_consent_baseline(cache_path: Path, *, force: bool) -> None:
    """Bring the tenant to the consent baseline: at least ``BASELINE_SCOPES``, granted.

    Only a human accepting Entra's consent screen grants consent, so this signs the
    administrator in asking for every baseline scope. Entra shows the screen for whatever is
    missing, and accepting it is the grant. An administrator can do that from nothing, so it
    does not matter what state the tenant was left in.

    With ``force=False`` the sign-in is silent when it can be. The token request still goes
    to Entra with the refresh token (``force_refresh``), because a cached access token is
    served without asking Entra and so cannot tell whether the tenant still holds the grant.
    Entra refuses the refresh once consent is gone, and the refusal opens the prompt. With
    ``force=True`` the prompt opens regardless, for a caller that has just revoked and knows
    the screen is coming.

    The token that comes back is then checked for every baseline scope, so a declined or
    partly accepted consent screen fails here and not three tests later.

    Blocking, so a session-scoped fixture can call it. Prompts through
    :func:`walkthrough_if_waiting`, so the person is only called when there is something to do.

    Args:
        cache_path: The shared disk cache; the token lands there for the tests to use.
        force: Prompt even when a silent sign-in would do.
    """
    admin = AuthContext(TENANT, username=USERNAME, cache="disk", cache_path=cache_path)
    with walkthrough_if_waiting(
        f"Sign-in prompt for the ADMIN, {USERNAME}, asking for {', '.join(BASELINE_SCOPES)}."
        " If the browser offers another account, choose 'Use another account'; signing in as"
        " anyone else fails here.",
        "A consent screen listing those scopes. Tick 'Consent on behalf of your organization'"
        " if offered, then Accept. This grants the tests' baseline.",
    ):
        if force:
            admin.login(client_id=GRAPH_CLI_CLIENT_ID, scopes=BASELINE_SCOPES, force=True)
        token = admin.acquire_token(
            BASELINE_SCOPES, client_id=GRAPH_CLI_CLIENT_ID, force_refresh=True
        )
    missing = missing_scopes(token.token, BASELINE_SCOPES)
    if missing:
        pytest.fail(
            f"the tenant is not at the consent baseline: {USERNAME} signed in, but the token"
            f" lacks {' '.join(sorted(missing))}. Was the consent screen declined?"
        )
    print(f"consent baseline: {USERNAME} holds {' '.join(sorted(BASELINE_SCOPES))}")
