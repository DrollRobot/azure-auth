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
* ``AZURE_AUTH_TEST_GDAP=1``: the user is a partner user with GDAP customers.
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

import contextlib
import os
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from azure_auth import AuthContext, ConsentRequired, InteractionRequired
from azure_auth.clients import ResourceClient
from azure_auth.sync import ResourceClient as BlockingResourceClient
from tests import alert_user

# The GDAP test's scopes, on the partner tenant and on each customer.
GDAP_SCOPES = ["DelegatedAdminRelationship.Read.All", "Organization.Read.All"]

# Every Graph scope a live test uses. The interactive Graph sign-in asks for all of them at
# once, so its consent screen covers the lot and the live tests find them in the cache. A
# live test that needs a new Graph scope must add it here, or it will only ever skip.
LIVE_GRAPH_SCOPES = [
    "User.Read",
    "Application.Read.All",
    # The throttling test reads the audit log, the one resource with a limit low enough to
    # trip on purpose. Admin consent, and the consent reset deletes it like any other
    # tenant-wide grant, so the next interactive sign-in grants it again.
    "AuditLog.Read.All",
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
