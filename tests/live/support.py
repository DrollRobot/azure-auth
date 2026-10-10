"""What the live tests share: the environment, the skip markers and the sign-in helpers.

Environment variables:

* ``AZURE_AUTH_TEST_TENANT_ID`` and ``AZURE_AUTH_TEST_USERNAME``: user-flow tests. The
  tenant may be in any cloud; every context the tests build finds which by itself.
* ``AZURE_AUTH_TEST_GRAPH=1``: the user may sign in to Microsoft Graph Command Line Tools in
  the tenant. The Graph tests and the consent baseline need it; without it they skip, and the
  Exchange and ARM tests run on their own. A tenant can block the application, and the China
  cloud does not have it.
* ``AZURE_AUTH_TEST_APP_CLIENT_ID`` and ``AZURE_AUTH_TEST_CERT_THUMBPRINT``: app-flow tests
  with a certificate in ``CurrentUser\\My`` (needs ``Organization.Read.All`` on Graph). With
  ``AZURE_AUTH_TEST_EXCHANGE`` or ``_IPPS`` set, the application runs cmdlets too, and needs
  ``Exchange.ManageAsApp`` and the Exchange or Compliance Administrator role. The tests
  upload throwaway certificates to the application and take them off again, so it should be
  one made for them.
* ``AZURE_AUTH_TEST_MACHINE_CERT_THUMBPRINT``: a second certificate uploaded to the same
  application, in ``LocalMachine\\My``. The account running the tests must be able to read
  its private key.
* ``AZURE_AUTH_TEST_NONADMIN_USERNAME``: a second user in the same tenant who may *not*
  consent. Naming one runs the consent test; leaving it blank skips it.
* ``AZURE_AUTH_TEST_ARM=1``: the user, and the test application when one is configured, can
  see at least one Azure subscription (the application needs Reader on one). A tenant with
  no Azure access still answers ``/subscriptions`` with an empty list, which is why this is a
  flag and not something the test can work out for itself.
* ``AZURE_AUTH_TEST_GDAP=1``: the user's home tenant manages other tenants through GDAP.
* ``AZURE_AUTH_TEST_GDAP_TENANT_ID``: a customer tenant the user reaches through GDAP, by
  id or verified domain. Naming one runs the GDAP Exchange tests, which only read
  (:class:`ReadOnlyCmdlets`).
* ``AZURE_AUTH_TEST_EXCHANGE=1`` / ``AZURE_AUTH_TEST_IPPS=1``: the user may run Exchange /
  Security & Compliance cmdlets.
* ``AZURE_AUTH_TEST_KEYVAULT_URL`` and ``AZURE_AUTH_TEST_KEYVAULT_SECRET_NAME``: a vault in the
  tenant and the name of a secret in it the user, and the test application when one is
  configured, may read (Key Vault Secrets User, or an access policy allowing Get). Naming
  both runs the Key Vault tests. They read the value but never print it, so it should be a
  throwaway made for them.
* ``AZURE_AUTH_TEST_PROPAGATION_TIMEOUT_SECONDS``: how long :func:`restore_baseline` waits for
  Entra to catch up with a grant change: a new grant to show up, or a removed scope to stop
  being issued (default 300).
* ``AZURE_AUTH_TEST_LONG_REFRESH=1``: run the test that waits out a real access token
  lifetime, about an hour.
* ``AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS``: how long a sign-in may take before the alarm
  sounds (default 5). A browser that is still signed in answers faster than this.

No secret is read from the environment; app flows use the certificate store, and the Key
Vault tests are given their secret's name, not its value.
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import contextlib
import functools
import hashlib
import json
import os
import threading
import time
from collections.abc import Callable, Coroutine, Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

import httpx
import pytest

from azure_auth import (
    AuthContext,
    AuthError,
    Cloud,
    ConsentRequired,
    GraphClient,
    InteractionRequired,
    Tenant,
)
from azure_auth.auth import cng
from azure_auth.clients import ResourceClient
from azure_auth.constants import GRAPH_CLI_CLIENT_ID
from azure_auth.sync import GraphClient as BlockingGraphClient
from azure_auth.sync import ResourceClient as BlockingResourceClient
from tests import alert_user, consent_reset
from tests.certs import TestCertificate, make_certificate

# The GDAP test's scopes, on the home tenant and on each customer tenant.
GDAP_SCOPES = ["DelegatedAdminRelationship.Read.All", "Organization.Read.All"]

# The consent baseline: exactly the Graph scopes the Graph command-line application is
# granted in the tenant while the live tests run, no more and no fewer. restore_baseline()
# puts the tenant there at the start of every live run and after every test that can change
# consent, so every test starts from it and none has to arrange anything.
#
# A live test that needs a new Graph scope adds it here, or it only ever skips. A scope a test
# needs *not* granted must never appear here, and needs nothing else: the baseline leaves it
# out. Those are NONADMIN_SCOPE (test_consent.py), CANCEL_SCOPE (test_sign_in.py) and
# UNGRANTED_SCOPE (test_graph_client.py).
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

# What reading and rewriting the application's grants needs. Both are in BASELINE_SCOPES, so a
# sign-in for them is silent.
GRANT_ADMIN_SCOPES = ["DelegatedPermissionGrant.ReadWrite.All", "Application.Read.All"]

# How long restore_baseline() waits for Entra to catch up with a grant change -- a grant just
# consented to showing up in the grant list, a scope just taken out no longer being issued --
# and how often it looks. Override the first with AZURE_AUTH_TEST_PROPAGATION_TIMEOUT_SECONDS.
PROPAGATION_TIMEOUT_SECONDS = float(
    os.environ.get("AZURE_AUTH_TEST_PROPAGATION_TIMEOUT_SECONDS", "300")
)
PROPAGATION_POLL_SECONDS = 10.0

# How long a sign-in that may be silent can take before the person at the desktop is called.
# A browser that is still signed in answers well inside this; a sign-in page waiting for
# somebody does not. Override with AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS.
PROMPT_ALARM_SECONDS = float(os.environ.get("AZURE_AUTH_TEST_PROMPT_ALARM_SECONDS", "5"))

# How long a test's browser sign-in waits before it fails. Enough to type a password and
# approve MFA; half the package default, so a sign-in that can never finish -- stopped at a
# Conditional Access block, which never returns to the test -- costs a minute, not two.
SIGN_IN_TIMEOUT_SECONDS = 60

TENANT = os.environ.get("AZURE_AUTH_TEST_TENANT_ID", "")
USERNAME = os.environ.get("AZURE_AUTH_TEST_USERNAME", "")
GRAPH = os.environ.get("AZURE_AUTH_TEST_GRAPH") == "1"
NONADMIN = os.environ.get("AZURE_AUTH_TEST_NONADMIN_USERNAME", "")
APP_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_APP_CLIENT_ID", "")
THUMBPRINT = os.environ.get("AZURE_AUTH_TEST_CERT_THUMBPRINT", "")
MACHINE_THUMBPRINT = os.environ.get("AZURE_AUTH_TEST_MACHINE_CERT_THUMBPRINT", "")
KEYVAULT_URL = os.environ.get("AZURE_AUTH_TEST_KEYVAULT_URL", "")
KEYVAULT_SECRET_NAME = os.environ.get("AZURE_AUTH_TEST_KEYVAULT_SECRET_NAME", "")
GDAP_TENANT = os.environ.get("AZURE_AUTH_TEST_GDAP_TENANT_ID", "")

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
needs_machine_certificate = pytest.mark.skipif(
    not (TENANT and APP_CLIENT_ID and MACHINE_THUMBPRINT),
    reason="set AZURE_AUTH_TEST_TENANT_ID, _APP_CLIENT_ID and _MACHINE_CERT_THUMBPRINT",
)
needs_keyvault = pytest.mark.skipif(
    not (KEYVAULT_URL and KEYVAULT_SECRET_NAME),
    reason="set AZURE_AUTH_TEST_KEYVAULT_URL and AZURE_AUTH_TEST_KEYVAULT_SECRET_NAME",
)
needs_gdap_tenant = pytest.mark.skipif(not GDAP_TENANT, reason="set AZURE_AUTH_TEST_GDAP_TENANT_ID")


def _flag(name: str) -> pytest.MarkDecorator:
    return pytest.mark.skipif(os.environ.get(name) != "1", reason=f"set {name}=1")


needs_graph = _flag("AZURE_AUTH_TEST_GRAPH")
needs_exchange = _flag("AZURE_AUTH_TEST_EXCHANGE")
needs_ipps = _flag("AZURE_AUTH_TEST_IPPS")

# The Exchange Online PowerShell client id serves the Exchange, the IPPS and the GDAP Exchange
# tests, so a sign-in to it needs only one of them.
needs_exchange_sign_in = pytest.mark.skipif(
    not (
        "1" in (os.environ.get("AZURE_AUTH_TEST_EXCHANGE"), os.environ.get("AZURE_AUTH_TEST_IPPS"))
        or GDAP_TENANT
    ),
    reason="set AZURE_AUTH_TEST_EXCHANGE=1, _IPPS=1 or _GDAP_TENANT_ID",
)

# The Azure PowerShell client id serves both the ARM and the Key Vault tests, so a sign-in to
# it needs only one of them.
needs_arm_or_keyvault = pytest.mark.skipif(
    not (os.environ.get("AZURE_AUTH_TEST_ARM") == "1" or KEYVAULT_URL),
    reason="set AZURE_AUTH_TEST_ARM=1 or AZURE_AUTH_TEST_KEYVAULT_URL",
)

# What restore_baseline keeps. The consent baseline needs the administrator and the Graph
# command-line application; the application's certificates need the application.
KEEPS_CONSENT = bool(TENANT and USERNAME and GRAPH)
KEEPS_CERTIFICATES = bool(TENANT and APP_CLIENT_ID and THUMBPRINT)

# The common name of every certificate a test uploads to the application. restore_baseline
# takes each one back off; the certificates the application is configured with stay.
TEMPORARY_CERTIFICATE_NAME = "azure-auth live test temporary"

# The audience addKey and removeKey require of their proof, fixed by Graph.
_KEY_PROOF_AUDIENCE = "00000002-0000-0000-c000-000000000000"


@functools.cache
def live_tenant() -> Tenant:
    """Return the configured tenant, looked up once per run.

    Returns:
        The tenant.
    """
    return Tenant.lookup(TENANT)


def live_cloud() -> Cloud:
    """Return the cloud the configured tenant lives in.

    Returns:
        The cloud.
    """
    return live_tenant().cloud


def graph_scopes(scopes: Iterable[str]) -> list[str]:
    """Qualify short Graph scope names with the Graph resource of the tenant's cloud.

    A bare ``User.Read`` means commercial Graph; the resource tokens are for differs per
    cloud, so a direct token request names it.

    Args:
        scopes: Short names such as ``User.Read``.

    Returns:
        The full scopes, such as ``https://graph.microsoft.com/User.Read``.
    """
    return [f"{live_cloud().graph}/{scope}" for scope in scopes]


def live_user_auth(cache_path: Path, *, tenant: str = TENANT) -> AuthContext:
    """Return the user-flow context the live tests use: the shared cache first, then a prompt.

    A token comes from the encrypted disk cache when it holds one. When it does not, the
    browser opens for the configured user. Sign in through :func:`ensure_sign_in`, so the
    person at the desktop is called when a window is waiting.

    Args:
        cache_path: The shared disk cache.
        tenant: The tenant to address, by id or by a verified domain name. The default is
            the configured one; a test that wants the same tenant under another name passes
            it here, and the cache still answers because MSAL keys tokens by the tenant id
            that the authority resolves to.

    Returns:
        The context.
    """
    return AuthContext(
        tenant,
        username=USERNAME,
        cache="disk",
        cache_path=cache_path,
        interactive_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )


def live_app_auth(**kwargs: Any) -> AuthContext:
    """Return a context that signs in as the test application with the store certificate.

    Args:
        **kwargs: Further ``AuthContext`` arguments, such as the cache.

    Returns:
        The context.
    """
    return AuthContext(TENANT, client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT, **kwargs)


def cached_user_auth(cache_path: Path, *, tenant: str = TENANT) -> AuthContext:
    """Return a user-flow context that can never open a sign-in prompt.

    Only for what must not prompt: a test of signing in from the cache, where a prompt would
    hide a cache that did not answer, and a check that Entra refuses something, where a
    prompt would open a window instead of the refusal. Every other test uses
    :func:`live_user_auth`.

    Args:
        cache_path: The shared disk cache.
        tenant: As for :func:`live_user_auth`.

    Returns:
        The context.
    """
    auth = AuthContext(tenant, username=USERNAME, cache="disk", cache_path=cache_path)
    auth._interactive_allowed = False
    return auth


def ensure_token(auth: AuthContext, scopes: Sequence[str], client_id: str | None = None) -> None:
    """Make sure the context can get a token for the scopes, signing in when it has to.

    A cached sign-in answers silently. Without one, the browser or the broker's window opens,
    and if it is still waiting after ``PROMPT_ALARM_SECONDS`` the person at the desktop is
    called (:func:`walkthrough_if_waiting`). The token is kept, so the test that follows uses
    it without asking again.

    Args:
        auth: The context the test is about to use.
        scopes: The scopes the test's requests will need.
        client_id: The client id they will be made with; the context's default when omitted.
    """
    with walkthrough_if_waiting(sign_in_step("WAM" if auth._broker else "browser")):
        auth.acquire_token(scopes, client_id=client_id)


def sign_in_to_vault(auth: AuthContext) -> None:
    """Make sure the context can get a token for the vault, signing in when it has to.

    The client asks for its token through the Azure SDK, which learns the resource from the
    vault's challenge to a first, unauthenticated request. The scope is worked out here the
    way that challenge gives it: the vault's host without the vault's name, so
    ``contoso.vault.azure.net`` is ``https://vault.azure.net/.default`` in every cloud.

    Args:
        auth: The context the test is about to use.
    """
    host = urlsplit(KEYVAULT_URL).hostname or ""
    ensure_token(auth, [f"https://{host.partition('.')[2]}/.default"])


def ensure_sign_in(client: ResourceClient | BlockingResourceClient) -> None:
    """Make sure the client can get a token, signing in when it has to.

    Args:
        client: The client the test is about to use.
    """
    ensure_token(client.auth, client.scopes, client.client_id)


# The only cmdlets the GDAP tests may run, each of which only reads, so the tests can run against
# any customer tenant. ReadOnlyCmdlets refuses every other.
GDAP_CMDLETS = frozenset({"Get-OrganizationConfig"})


class ReadOnlyCmdlets(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """A transport that sends nothing but ``InvokeCommand`` requests for ``GDAP_CMDLETS``.

    The GDAP tests only read, so they can run against any customer tenant. A test that calls
    only read cmdlets is a promise; this makes it a check. Every request is read before it leaves
    the machine, and one that does not run a listed cmdlet fails the test without being sent.
    It serves the asynchronous and the blocking clients alike, and keeps what it sent.

    Attributes:
        requests: Every request it let through, in order.
    """

    def __init__(self, inner: httpx.MockTransport | None = None) -> None:
        """Send over the network, or through ``inner``.

        Args:
            inner: A mock transport to send through instead, for testing the guard itself.
        """
        self._sync: httpx.BaseTransport = inner or httpx.HTTPTransport()
        self._async: httpx.AsyncBaseTransport = inner or httpx.AsyncHTTPTransport()
        self.requests: list[httpx.Request] = []

    def _check(self, request: httpx.Request) -> None:
        """Fail the test, with the request unsent, unless it runs a listed cmdlet.

        ``pytest.fail`` raises a ``BaseException``, so no ``except Exception`` in the client
        can catch the refusal and carry on.

        Args:
            request: The outgoing request.
        """
        try:
            cmdlet = json.loads(request.content)["CmdletInput"]["CmdletName"]
        except (ValueError, TypeError, KeyError):
            cmdlet = None
        allowed = isinstance(cmdlet, str) and cmdlet in GDAP_CMDLETS
        if not (
            allowed and request.method == "POST" and request.url.path.endswith("/InvokeCommand")
        ):
            pytest.fail(
                f"refused to send {request.method} {request.url.path} ({cmdlet or 'no cmdlet'}):"
                f" the GDAP tests may only run {', '.join(sorted(GDAP_CMDLETS))}",
                pytrace=False,
            )
        self.requests.append(request)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Check the request, then send it (blocking clients).

        Args:
            request: The outgoing request.

        Returns:
            The response, untouched.
        """
        self._check(request)
        return self._sync.handle_request(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Check the request, then send it (asynchronous clients).

        Args:
            request: The outgoing request.

        Returns:
            The response, untouched.
        """
        self._check(request)
        return await self._async.handle_async_request(request)

    def close(self) -> None:
        """Close the blocking transport."""
        self._sync.close()

    async def aclose(self) -> None:
        """Close the asynchronous transport."""
        await self._async.aclose()


def sign_in_step(window: Literal["WAM", "browser"], user: str = USERNAME) -> str:
    """The walkthrough step for a sign-in.

    Args:
        window: Where the sign-in appears: the broker's window or the browser.
        user: The account to sign in with.

    Returns:
        The step.
    """
    return f"In the {window} window, sign in with {user}."


def walkthrough(*steps: str) -> None:
    """Tell the person at the desktop what they are about to see, and sound the alarm.

    An interactive test blocks on a browser window, and a window that is not understood gets
    answered wrongly: clicking "Sign in with that account" on a "Need admin approval" page, or
    closing the tab rather than returning to the application, both break a run in ways that
    look like product failures. So each test states its prompts in order, and what to do with
    each one.

    Each step is an instruction and nothing else: "In the WAM window, sign in with X.",
    "Consent screen: click CANCEL." It names the window the person acts in (WAM or browser),
    not the application. No reasons, no explanation, no hints on finding a window, no
    fallbacks, and no step for a prompt that has not been seen to appear. Explanations belong
    in the test's docstring.

    Call this directly only when somebody will certainly have to act, such as a second user
    signing in. Otherwise use :func:`walkthrough_if_waiting`.

    Needs ``pytest -s``; without it pytest captures this and the person sees nothing.

    Args:
        *steps: The instructions, in order.
    """
    line = "=" * 78
    print(f"\n{line}\n  DO THIS, IN ORDER:\n")
    for number, step in enumerate(steps, 1):
        print(f"    {number}. {step}")
    print(f"\n{line}\n", flush=True)
    alert_user.main_for_tests()


@contextlib.contextmanager
def walkthrough_if_waiting(*steps: str) -> Iterator[None]:
    """Announce a sign-in only if it is still waiting after ``PROMPT_ALARM_SECONDS``.

    Wrap a sign-in that is not forced but may still open a window: the baseline restore's,
    and every test's first sign-in (:func:`ensure_token`). A browser that is still signed in
    answers it by itself, and nobody needs calling for that. So the sign-in is timed, and
    only when it is still waiting after the delay does :func:`walkthrough` print the steps and
    sound the alarm. An alarm on every test would teach the person to ignore it. A forced
    sign-in always waits for the person at the account picker, so it calls
    :func:`walkthrough` before it starts.

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
    """
    return set(required) - token_scopes(token)


def _consent_to_baseline(cache_path: Path, *, force: bool) -> None:
    """Make sure every baseline scope is granted: the adding half of :func:`restore_baseline`.

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

    Prompts through :func:`walkthrough_if_waiting`, so the person is only called when there is
    something to do.

    Args:
        cache_path: The shared disk cache; the token lands there for the tests to use.
        force: Prompt even when a silent sign-in would do.
    """
    admin = AuthContext(
        TENANT,
        username=USERNAME,
        cache="disk",
        cache_path=cache_path,
        interactive_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )
    scopes = graph_scopes(BASELINE_SCOPES)
    with walkthrough_if_waiting(
        sign_in_step("browser"),
        "Consent screen: tick 'Consent on behalf of your organization'. Click Accept.",
    ):
        if force:
            admin.login(client_id=GRAPH_CLI_CLIENT_ID, scopes=scopes, force=True)
        token = admin.acquire_token(scopes, client_id=GRAPH_CLI_CLIENT_ID, force_refresh=True)
    missing = missing_scopes(token.token, BASELINE_SCOPES)
    if missing:
        pytest.fail(
            f"the tenant is not at the consent baseline: {USERNAME} signed in, but the token"
            f" lacks {' '.join(sorted(missing))}. Was the consent screen declined?"
        )


_T = TypeVar("_T")


def _run(coroutine: Coroutine[Any, Any, _T]) -> _T:
    """Run a coroutine to completion from blocking code, whatever thread that is.

    The baseline is restored from fixtures, some of which run while an asynchronous test's
    event loop exists, so the coroutine gets a thread and a loop of its own.

    Args:
        coroutine: The coroutine.

    Returns:
        Its result.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


async def _grants_now(cache_path: Path) -> list[dict[str, Any]]:
    """Read the Graph application's consent grants as the administrator."""
    async with GraphClient(cached_user_auth(cache_path), scopes=GRANT_ADMIN_SCOPES) as graph:
        return await consent_reset.application_grants(graph)


async def _strip(cache_path: Path) -> consent_reset.StripResult:
    """Take every scope beyond the baseline out of the Graph application's grants."""
    async with GraphClient(cached_user_auth(cache_path), scopes=GRANT_ADMIN_SCOPES) as graph:
        return await consent_reset.strip_grants(graph, BASELINE_SCOPES)


async def _wait_until_refused(auth: AuthContext, scope: str) -> float:
    """Wait until Entra refuses to issue ``scope`` silently.

    Taking a scope out of a grant is not the end of it. A grant is read from one path and a
    token issued from another, which catches up separately: measured 2026-09-20, a deleted
    grant still let a user sign in silently seconds later. So Entra itself is asked, with a
    refresh (``force_refresh``: a cached access token would answer without asking), until it
    says no.

    Args:
        auth: A context that may not prompt, signed in to the Graph application.
        scope: The scope, short form.

    Returns:
        How many seconds it took.
    """
    started = time.monotonic()
    full = f"{auth.tenant.cloud.graph}/{scope}"
    while True:
        try:
            await auth.aio.acquire_token([full], client_id=GRAPH_CLI_CLIENT_ID, force_refresh=True)
        except (ConsentRequired, InteractionRequired):
            return time.monotonic() - started
        waited = time.monotonic() - started
        if waited > PROPAGATION_TIMEOUT_SECONDS:
            pytest.fail(
                f"Entra still issues {scope} {waited:.0f}s after it was taken out of every"
                " grant; raise AZURE_AUTH_TEST_PROPAGATION_TIMEOUT_SECONDS if it is just slow"
            )
        await asyncio.sleep(PROPAGATION_POLL_SECONDS)


def _holds_baseline(grants: list[dict[str, Any]]) -> bool:
    """Whether a tenant-wide grant carries every baseline scope."""
    return any(
        grant.get("consentType") == "AllPrincipals"
        and set(BASELINE_SCOPES) <= consent_reset.grant_scopes(grant)
        for grant in grants
    )


def _wait_for_baseline_grant(cache_path: Path) -> list[dict[str, Any]] | None:
    """Read the grants until a tenant-wide one carries the baseline, or time runs out.

    The grant list lags behind consent: measured 2026-09-29, a consent screen accepted for the
    organization was followed by two empty reads, three seconds apart, while the grant was
    live; later reads in the same run found it. So a missing grant is re-read before it is
    believed.

    Args:
        cache_path: The shared disk cache, holding the administrator's sign-in.

    Returns:
        The grants once the baseline is among them, or ``None`` if it never showed up.
    """
    started = time.monotonic()
    while True:
        grants = _run(_grants_now(cache_path))
        waited = time.monotonic() - started
        if _holds_baseline(grants):
            if waited >= PROPAGATION_POLL_SECONDS:
                print(f"  the baseline grant showed up in the grant list after {waited:.0f}s")
            return grants
        if waited > PROPAGATION_TIMEOUT_SECONDS:
            return None
        time.sleep(PROPAGATION_POLL_SECONDS)


def _b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url, as JWTs require."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _key_proof(object_id: str) -> str:
    """Build the proof ``addKey`` and ``removeKey`` require, signed with the store certificate.

    The application proves it holds one of its keys before it may change them, and needs no
    Graph permission for it: a JWT signed by a certificate it already holds, issued by the
    application's object id. ``x5t`` names the certificate by its SHA-1 thumbprint, which is
    the thumbprint itself.

    Args:
        object_id: The application's object id, not its client id.

    Returns:
        The signed JWT.
    """
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(bytes.fromhex(THUMBPRINT))}
    claims = {"aud": _KEY_PROOF_AUDIENCE, "iss": object_id, "nbf": now, "exp": now + 600}
    signing_input = ".".join(_b64url(json.dumps(part).encode()) for part in (header, claims))
    digest = hashlib.sha256(signing_input.encode("ascii")).digest()
    return f"{signing_input}.{_b64url(cng.sign_digest(THUMBPRINT, digest, padding='pkcs1'))}"


def _application(graph: BlockingGraphClient) -> dict[str, Any]:
    """Read the test application's object id and certificates, as the application itself.

    An application may read its own registration with no Graph permission for it (measured
    2026-10-10, holding only ``Organization.Read.All``).
    """
    return dict(
        graph.get(
            f"/applications(appId='{APP_CLIENT_ID}')", params={"$select": "id,keyCredentials"}
        )
    )


def upload_temporary_certificate() -> TestCertificate:
    """Make a certificate and upload it to the test application, as the application itself.

    It is named :data:`TEMPORARY_CERTIFICATE_NAME`, so :func:`restore_baseline` takes it off
    again. Entra does not accept it at once; sign in with :func:`sign_in_once_accepted`.

    Returns:
        The certificate, with its private key.
    """
    certificate = make_certificate(TEMPORARY_CERTIFICATE_NAME)
    with BlockingGraphClient(live_app_auth()) as graph:
        object_id = _application(graph)["id"]
        graph.post(
            f"/applications/{object_id}/addKey",
            json={
                "keyCredential": {
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "key": base64.b64encode(certificate.der).decode("ascii"),
                },
                "passwordCredential": None,
                "proof": _key_proof(object_id),
            },
        )
    return certificate


def sign_in_once_accepted(auth: AuthContext, scopes: Sequence[str]) -> None:
    """Sign in with a certificate just uploaded, waiting until Entra accepts it.

    Measured 2026-10-10: a certificate added with ``addKey`` was refused ``AADSTS700027``
    three seconds later and accepted ten seconds after that.

    Args:
        auth: An app-flow context holding the new certificate.
        scopes: The scopes to sign in for.
    """
    started = time.monotonic()
    while True:
        try:
            auth.acquire_token(scopes)
            return
        except AuthError as error:
            waited = time.monotonic() - started
            if "AADSTS700027" not in str(error) or waited > PROPAGATION_TIMEOUT_SECONDS:
                raise
        time.sleep(PROPAGATION_POLL_SECONDS)


def _temporary_certificates(graph: BlockingGraphClient) -> tuple[str, list[str]]:
    """Read the test application's object id and the key ids of the certificates tests uploaded.

    Args:
        graph: A Graph client signed in as the application.

    Returns:
        The object id, and the key ids of the certificates named
        :data:`TEMPORARY_CERTIFICATE_NAME`.
    """
    application = _application(graph)
    return application["id"], [
        key["keyId"]
        for key in application["keyCredentials"]
        if key.get("displayName") == f"CN={TEMPORARY_CERTIFICATE_NAME}"
    ]


def _remove_temporary_certificates(may_remove: Callable[[], bool]) -> None:
    """Take every certificate a test uploaded back off the test application.

    They are the ones named :data:`TEMPORARY_CERTIFICATE_NAME`; the certificates the
    application is configured with stay. Removed with ``removeKey``, as the application.

    The application's certificate list lags behind a removal: measured 2026-10-10, removed
    certificates were still listed by the next restore, a minute or more later, which removed
    them again. So this re-reads the list until the removed ones are gone (10 s in the run
    after).

    Args:
        may_remove: Whether the tenant is marked disposable. Only called when there is
            something to take off.
    """
    with BlockingGraphClient(live_app_auth()) as graph:
        object_id, temporary = _temporary_certificates(graph)
        if not temporary:
            return
        if not may_remove():
            pytest.fail(
                f"the test application holds {len(temporary)} certificate(s) a test uploaded,"
                " and the tenant is not marked disposable (tests/verify_remote_disposable.py),"
                " so they were left alone"
            )
        for key_id in temporary:
            graph.post(
                f"/applications/{object_id}/removeKey",
                json={"keyId": key_id, "proof": _key_proof(object_id)},
            )
        started = time.monotonic()
        while still_listed := set(temporary) & set(_temporary_certificates(graph)[1]):
            waited = time.monotonic() - started
            if waited > PROPAGATION_TIMEOUT_SECONDS:
                pytest.fail(
                    f"{len(still_listed)} certificate(s) taken off the test application are"
                    f" still listed {waited:.0f}s later; raise"
                    " AZURE_AUTH_TEST_PROPAGATION_TIMEOUT_SECONDS if it is just slow"
                )
            time.sleep(PROPAGATION_POLL_SECONDS)
    print(
        f"  took {len(temporary)} test certificate(s) off the test application;"
        f" gone from its list after {time.monotonic() - started:.0f}s"
    )


def restore_baseline(cache_path: Path, *, may_remove: Callable[[], bool]) -> None:
    """Bring the tenant to exactly the baseline, whatever state it is in.

    Two parts, each when the run is configured for it:

    * Consent (:data:`KEEPS_CONSENT`): the Graph command-line application is granted exactly
      ``BASELINE_SCOPES`` (:func:`_restore_consent`).
    * Certificates (:data:`KEEPS_CERTIFICATES`): the test application holds no certificate a
      test uploaded (:func:`_remove_temporary_certificates`).

    Both read what the tenant holds, never assume it, and change it only when ``may_remove``
    says the tenant is marked disposable. Blocking, so fixtures of any scope can call it.

    Args:
        cache_path: The shared disk cache, holding the administrator's sign-in.
        may_remove: Whether this tenant may have things taken out. Only called when there is
            something to take out.
    """
    if KEEPS_CONSENT:
        _restore_consent(cache_path, may_remove=may_remove)
    if KEEPS_CERTIFICATES:
        _remove_temporary_certificates(may_remove)


def _restore_consent(cache_path: Path, *, may_remove: Callable[[], bool]) -> None:
    """Bring the tenant to exactly the consent baseline, whatever state it is in.

    What the tenant holds is read, never assumed, and fixed in both directions:

    1. Missing: the administrator signs in for every baseline scope. That is silent when they
       are granted, and a consent screen when not; accepting it is the grant, and only a
       person can do that. The token alone is not trusted to say they are granted, because a
       deleted grant keeps issuing tokens for a while, so the tenant-wide grant is read as
       well, re-read until it catches up (the list lags behind a consent just given), and the
       consent screen is forced when it still lacks any of them.
    2. Beyond: every other scope is taken out of every grant of the application, each grant
       keeping its baseline scopes, so nobody is asked to consent again. Then this waits
       until Entra refuses to issue each scope it took out, so the next test cannot be handed
       one the grant no longer carries.

    Taking grants away changes the tenant, so step 2 runs only when ``may_remove`` says the
    tenant is marked disposable. Otherwise the run fails, naming what is beyond the baseline.
    Blocking, so fixtures of any scope can call it.

    Args:
        cache_path: The shared disk cache, holding the administrator's sign-in.
        may_remove: Whether scopes may be taken out of this tenant's grants. Only called when
            there is something to take out.
    """
    _consent_to_baseline(cache_path, force=False)
    found = _wait_for_baseline_grant(cache_path)
    if found is None:
        print("  no tenant-wide grant carries the baseline; asking for consent")
        _consent_to_baseline(cache_path, force=True)
        found = _wait_for_baseline_grant(cache_path)
        if found is None:
            pytest.fail(
                "no tenant-wide grant carries every baseline scope, even"
                f" {PROPAGATION_TIMEOUT_SECONDS:.0f}s after a sign-in for them that Entra"
                " accepted; raise AZURE_AUTH_TEST_PROPAGATION_TIMEOUT_SECONDS if it is just slow"
            )
    grants = found

    beyond = sorted(
        {
            scope
            for grant in grants
            for scope in consent_reset.grant_scopes(grant)
            - set(BASELINE_SCOPES)
            - consent_reset.OIDC_SCOPES
        }
    )
    if beyond:
        if not may_remove():
            pytest.fail(
                f"the tenant grants {' '.join(beyond)} beyond the baseline, and it is not marked"
                " disposable (tests/verify_remote_disposable.py), so they were left alone"
            )
        stripped = _run(_strip(cache_path))
        if not stripped.ok:
            pytest.fail(f"could not take the tenant down to the baseline: {stripped.failed}")
        auth = cached_user_auth(cache_path)
        for scope in sorted(stripped.removed):
            waited = _run(_wait_until_refused(auth, scope))
            print(f"  took {scope} out of the grants; Entra refused it after {waited:.0f}s")
    print(f"consent baseline: exactly {' '.join(sorted(BASELINE_SCOPES))}")
