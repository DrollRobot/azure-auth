"""The Exchange and Security & Compliance clients against the real ``InvokeCommand`` endpoint.

Every test here uses the delegated sign-in to the Exchange Online PowerShell client id that
``test_sign_in.py`` leaves in the shared cache, and none can prompt. Together they cover what
a delegated user does with the client: the token is theirs and for the right resource, a
cmdlet runs, results page, parameters of every kind reach the cmdlet, failures come back as
:class:`InvokeCommandError` with the cmdlet's own reason, a domain name works as the tenant,
the blocking mirrors work, and, behind the destructive gate, an object is created, changed
and removed.

Measured facts that shaped these tests are in each docstring, dated.
"""

from __future__ import annotations

import asyncio
import collections
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

from azure_auth import AuthContext, ExchangeClient, InvokeCommandError, IppsClient
from azure_auth.constants import EXCHANGE_RESOURCE
from azure_auth.sync import ExchangeClient as BlockingExchangeClient
from azure_auth.sync import IppsClient as BlockingIppsClient
from tests.live.support import (
    USERNAME,
    _flag,
    cached_user_auth,
    needs_user,
    require_cached_sign_in,
    token_claims,
    token_scopes,
    token_user,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

needs_exchange = _flag("AZURE_AUTH_TEST_EXCHANGE")
needs_ipps = _flag("AZURE_AUTH_TEST_IPPS")

# Two results a page, so that any tenant with three recipients pages, and a cap on how
# many pages are walked at that size, so a large tenant does not turn this into a crawl.
PAGE_SIZE = 2
MAX_PAGES = 25


class Recording(httpx.AsyncBaseTransport):
    """A real network transport that records every request it sends.

    The client builds its request URL and headers internally; this is the only place they
    can be seen from a test without reaching into the client.
    """

    def __init__(self, *drop: str) -> None:
        """Wrap the default transport, dropping the named request headers on the way out.

        Args:
            *drop: Header names to remove from every request before it is sent.
        """
        self._inner = httpx.AsyncHTTPTransport()
        self._drop = {name.lower() for name in drop}
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send the request over the network, minus the dropped headers, and record it.

        Args:
            request: The outgoing request.

        Returns:
            The response, untouched.
        """
        for name in list(request.headers):
            if name.lower() in self._drop:
                del request.headers[name]
        self.requests.append(request)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        """Close the wrapped transport."""
        await self._inner.aclose()


@needs_user
@needs_exchange
async def test_exchange_runs_a_cmdlet_as_the_signed_in_user(user_auth: AuthContext) -> None:
    """The cached Exchange sign-in belongs to the configured user, and a cmdlet runs with it.

    There is no ``/me`` on this resource, so the token is the witness for who signed in: a v1
    token with ``upn`` for the user and ``aud`` for the Exchange resource. Its ``scp`` shows
    the Exchange Online PowerShell application's pre-authorised delegated permissions
    (measured 2026-09-25: ``AdminApi.AccessAsUser.All`` among five others), which is what
    lets a first-party client id work with no application of one's own.

    ``Get-Mailbox`` for the user's own mailbox then shows the service agrees about who is
    calling, and that a string parameter reaches the cmdlet.
    """
    async with ExchangeClient(user_auth) as exchange:
        require_cached_sign_in(exchange)
        token = await user_auth.aio.acquire_token(exchange.scopes, client_id=exchange.client_id)
        config = await exchange.run("Get-OrganizationConfig")
        mailbox = await exchange.run("Get-Mailbox", Identity=USERNAME)

    claims = token_claims(token.token)
    assert claims["aud"] == EXCHANGE_RESOURCE
    assert (token_user(token.token) or "").lower() == USERNAME.lower()
    assert "AdminApi.AccessAsUser.All" in token_scopes(token.token)
    print(f"exchange token scopes: {' '.join(sorted(token_scopes(token.token)))}")

    assert len(config) == 1
    assert config[0]["Name"]
    assert len(mailbox) == 1
    assert mailbox[0]["UserPrincipalName"].lower() == USERNAME.lower()
    assert exchange.last_warnings == []


@needs_user
@needs_exchange
async def test_exchange_paging_follows_next_links(user_auth: AuthContext) -> None:
    """``iter_pages`` walks every page, and ``run`` returns the same objects.

    Paging was settled by hand on 2026-09-20 (POSTing the same body to ``@odata.nextLink``);
    this is the same check as a test. ``page_size`` is the ``odata.maxpagesize`` preference,
    which the service honours, so a tenant of any size pages.

    Recipients rather than mailboxes, because every tenant has more of them: groups and the
    discovery mailbox count, licences do not.
    """
    async with ExchangeClient(user_auth, page_size=PAGE_SIZE) as exchange:
        require_cached_sign_in(exchange)
        pages = 0
        paged: list[str] = []
        async for page in exchange.iter_pages("Get-Recipient"):
            pages += 1
            values = page.get("value", [])
            assert len(values) <= PAGE_SIZE
            paged.extend(recipient["Identity"] for recipient in values)
            if pages >= MAX_PAGES:
                break
    async with ExchangeClient(user_auth) as exchange:
        everyone = {recipient["Identity"] for recipient in await exchange.run("Get-Recipient")}

    assert pages > 1, f"everything arrived in one page of {PAGE_SIZE}; nothing paged"
    assert len(paged) == len(set(paged)), "a page repeated an object"
    assert set(paged) <= everyone
    if pages < MAX_PAGES:
        assert set(paged) == everyone, "the pages stopped before the end"
    print(f"exchange paging: {pages} pages at {PAGE_SIZE} a page, {len(paged)} objects")


@needs_user
@needs_exchange
async def test_cmdlet_parameters_of_every_kind_reach_the_cmdlet(user_auth: AuthContext) -> None:
    """A list, a plain value and a switch are all applied by the service.

    ``Parameters`` is a hash table in the request body, so the question is whether the
    service turns each JSON type into what the cmdlet expects. A list becomes a multi-valued
    parameter (measured 2026-09-25: two recipient types return exactly the sum of each on
    its own), a string a plain one, and ``True`` a switch, which an unknown parameter would
    have refused with a 400.
    """
    async with ExchangeClient(user_auth) as exchange:
        require_cached_sign_in(exchange)
        everyone = await exchange.run("Get-Recipient")
        by_type = collections.Counter(recipient["RecipientTypeDetails"] for recipient in everyone)
        if len(by_type) < 2:
            pytest.skip("the tenant has recipients of only one type; nothing to tell apart")
        (first, _), (second, _) = by_type.most_common(2)
        both = await exchange.run("Get-Recipient", RecipientTypeDetails=[first, second])
        one = await exchange.run("Get-Recipient", RecipientTypeDetails=first)
        with_deleted = await exchange.run("Get-Recipient", IncludeSoftDeletedRecipients=True)

    assert collections.Counter(recipient["RecipientTypeDetails"] for recipient in both) == {
        first: by_type[first],
        second: by_type[second],
    }
    assert len(one) == by_type[first]
    assert {recipient["RecipientTypeDetails"] for recipient in one} == {first}
    assert len(with_deleted) >= len(everyone)
    print(
        f"exchange parameters: {dict(by_type)}; list -> {len(both)}, switch -> {len(with_deleted)}"
    )


@needs_user
@needs_exchange
async def test_cmdlet_failures_carry_the_cmdlets_own_reason(user_auth: AuthContext) -> None:
    """Every kind of cmdlet failure is an :class:`InvokeCommandError` that says why.

    Measured 2026-09-25. A missing object is a 404 ``NotFound`` and a bad parameter a 400
    ``BadRequest``, both with a generic ``error.message`` and the real reason in
    ``error.details``; the client puts that reason first, after the cmdlet's name.

    An unknown cmdlet is stranger: a 403 whose body is NUL bytes, declared ``gzip`` and not
    gzip at all. Until the client read bodies itself, that surfaced as an ``httpx``
    decoding error and the 403 was lost. Now it is an error like the others, with a message
    that says what the empty answer means.
    """
    missing = str(uuid.uuid4())
    async with ExchangeClient(user_auth) as exchange:
        require_cached_sign_in(exchange)
        with pytest.raises(InvokeCommandError) as not_found:
            await exchange.run("Get-Mailbox", Identity=missing)
        with pytest.raises(InvokeCommandError) as bad_parameter:
            await exchange.run("Get-Mailbox", NoSuchParameter=1)
        with pytest.raises(InvokeCommandError) as unknown:
            await exchange.run("Get-NoSuchCmdlet")

    error = not_found.value
    assert (error.status, error.code) == (404, "NotFound")
    assert str(error).startswith("Get-Mailbox failed: ")
    assert "couldn't be found" in str(error)
    assert missing in str(error)
    assert error.request_id
    assert isinstance(error.body, dict)

    error = bad_parameter.value
    assert (error.status, error.code) == (400, "BadRequest")
    assert str(error).startswith("Get-Mailbox failed: ")
    assert "NoSuchParameter" in str(error)

    error = unknown.value
    assert error.status == 403
    assert str(error).startswith("Get-NoSuchCmdlet failed: ")
    assert "does not know" in str(error)
    print(f"exchange errors: 404 -> {str(not_found.value)[:120]}...")


@needs_user
@needs_exchange
async def test_a_domain_name_works_as_the_tenant(cache_path: Path) -> None:
    """A context given a verified domain still addresses ``InvokeCommand`` by tenant GUID.

    The endpoint wants the GUID in its path, and the client reads it from the token's
    ``tid`` claim rather than trusting what the context was given. The user's own UPN domain
    is a verified domain of the tenant, so it serves as the name. No prompt: MSAL keys the
    cache by the tenant id the authority resolves to, so the existing sign-in answers
    (measured 2026-09-25).
    """
    domain = USERNAME.rsplit("@", 1)[1]
    recording = Recording()
    async with ExchangeClient(
        cached_user_auth(cache_path, tenant=domain), transport=recording
    ) as exchange:
        require_cached_sign_in(exchange)
        config = await exchange.run("Get-OrganizationConfig")

    assert config
    path = recording.requests[0].url.path
    _, _, tenant, _ = path.strip("/").split("/")
    assert tenant != domain
    assert uuid.UUID(tenant)


@needs_user
@needs_exchange
@pytest.mark.parametrize(
    "dropped",
    [("X-ResponseFormat",), ("X-CmdletName",), ("X-ResponseFormat", "X-CmdletName")],
    ids=lambda names: "+".join(names),
)
async def test_the_reconstructed_headers_are_not_required(
    user_auth: AuthContext, dropped: tuple[str, ...]
) -> None:
    """``X-ResponseFormat`` and ``X-CmdletName`` are accepted, and not required.

    Neither header is in the ExchangeOnlineManagement module; both were reconstructed from
    memory. The service answers the same cmdlet the same way with either or both absent
    (measured 2026-09-25), so they are diagnostics, not protocol. The client keeps sending
    them, and reads the cmdlet name back out of ``X-CmdletName`` for its error messages.
    """
    recording = Recording(*dropped)
    async with ExchangeClient(user_auth, transport=recording) as exchange:
        require_cached_sign_in(exchange)
        config = await exchange.run("Get-OrganizationConfig")

    assert config
    assert config[0]["Name"]
    sent = recording.requests[-1].headers
    assert not any(name in sent for name in dropped)


@needs_user
@needs_ipps
async def test_ipps_runs_a_cmdlet_through_the_regional_host(user_auth: AuthContext) -> None:
    """Security & Compliance answers from a regional host, and refuses with a proper body.

    The first call is redirected (302) to a regional host, which the client follows with its
    token and keeps. An unknown cmdlet here is a 403 ``Forbidden`` with a JSON body that names
    the cmdlet (measured 2026-09-25), unlike Exchange's empty one.
    """
    async with IppsClient(user_auth) as ipps:
        require_cached_sign_in(ipps)
        labels = await ipps.run("Get-Label")
        with pytest.raises(InvokeCommandError) as unknown:
            await ipps.run("Get-NoSuchCmdlet")

    assert isinstance(labels, list)
    host = httpx.URL(ipps.base_url).host
    assert host != IppsClient.HOST
    assert host.endswith(f".{IppsClient.HOST}"), f"no regional host was taken: {host}"
    error = unknown.value
    assert (error.status, error.code) == (403, "Forbidden")
    assert str(error).startswith("Get-NoSuchCmdlet failed: ")
    assert "Get-NoSuchCmdlet" in str(error)
    print(f"ipps: {len(labels)} labels from {host}")


@needs_user
@needs_exchange
def test_the_blocking_exchange_client_runs_a_cmdlet(cache_path: Path) -> None:
    """The generated blocking Exchange client works against the real service."""
    with BlockingExchangeClient(cached_user_auth(cache_path)) as exchange:
        require_cached_sign_in(exchange)
        config = exchange.run("Get-OrganizationConfig")
    assert config
    assert config[0]["Name"]


@needs_user
@needs_ipps
def test_the_blocking_ipps_client_runs_a_cmdlet(cache_path: Path) -> None:
    """The generated blocking Security & Compliance client follows the redirect too."""
    with BlockingIppsClient(cached_user_auth(cache_path)) as ipps:
        require_cached_sign_in(ipps)
        labels = ipps.run("Get-Label")
    assert isinstance(labels, list)
    assert httpx.URL(ipps.base_url).host.endswith(f".{IppsClient.HOST}")


# Exchange's directory is replicated, and a request may land on any domain controller. An
# object created by one request is "not found" by the next when that one lands on a
# controller the creation has not reached: measured 2026-09-25, a mail contact read back by
# name six seconds after New-MailContact was refused with a 404, and was there minutes later.
# So every request that follows a creation retries a 404 until this much time has passed.
REPLICATION_TIMEOUT = 300.0
POLL_SECONDS = 5.0


async def _run_when_replicated(
    exchange: ExchangeClient, cmdlet: str, **parameters: Any
) -> tuple[list[dict[str, Any]], float]:
    """Run a cmdlet against an object that may not have replicated yet.

    A 404 is retried every ``POLL_SECONDS`` until ``REPLICATION_TIMEOUT``; any other failure,
    or a 404 that outlives the timeout, is raised.

    Args:
        exchange: The client.
        cmdlet: The cmdlet.
        **parameters: Its parameters.

    Returns:
        The cmdlet's output, and how long the object took to be found, in seconds.
    """
    started = time.monotonic()
    while True:
        try:
            return await exchange.run(cmdlet, **parameters), time.monotonic() - started
        except InvokeCommandError as error:
            if error.status != 404 or time.monotonic() - started > REPLICATION_TIMEOUT:
                raise
        await asyncio.sleep(POLL_SECONDS)


@needs_user
@needs_exchange
@pytest.mark.destructive_remote
@pytest.mark.slow
async def test_exchange_creates_changes_and_removes_an_object(user_auth: AuthContext) -> None:
    """``New-``, ``Set-`` and ``Remove-`` cmdlets work, so the client can write, not only read.

    A mail contact is the lightest object Exchange has: no mailbox, no licence, no membership.
    It is named after the test with a random suffix, addressed by its GUID once it exists, and
    removed in a ``finally`` so a failed assertion does not leave it behind. ``Confirm=False``
    is passed to ``Remove-``, as the PowerShell module would, because there is nobody to
    answer a confirmation prompt; the service accepts it (measured 2026-09-25).

    Every request after the creation goes through :func:`_run_when_replicated`, because
    the directory is replicated and the object is not everywhere at once. The waits are
    printed, since only a live run can say how long that takes.

    ``Set-MailContact`` with nothing to change is the one write that changes nothing, and it
    is how Exchange's warnings are provoked: it completes and warns that no settings were
    modified. That warning is the only evidence that ``last_warnings`` sees real ones.

    Marked ``slow``: replication can take minutes.
    """
    marker = uuid.uuid4().hex[:8]
    name = f"azure-auth live test {marker}"
    address = f"azure-auth-live-test-{marker}@example.com"
    async with ExchangeClient(user_auth) as exchange:
        require_cached_sign_in(exchange)
        created = await exchange.run("New-MailContact", Name=name, ExternalEmailAddress=address)
        assert len(created) == 1, created
        guid = created[0]["Guid"]
        try:
            assert created[0]["Name"] == name
            assert created[0]["ExternalEmailAddress"].lower().endswith(address)
            found, read_wait = await _run_when_replicated(
                exchange, "Get-MailContact", Identity=guid
            )
            assert [contact["Name"] for contact in found] == [name]
            _, set_wait = await _run_when_replicated(exchange, "Set-MailContact", Identity=guid)
            warnings = list(exchange.last_warnings)
        finally:
            _, remove_wait = await _run_when_replicated(
                exchange, "Remove-MailContact", Identity=guid, Confirm=False
            )

        # Gone means a 404 on a read. A read that lands on a controller the removal has not
        # reached still answers, so this waits for the same window.
        deadline = time.monotonic() + REPLICATION_TIMEOUT
        while True:
            gone: InvokeCommandError | None = None
            try:
                await exchange.run("Get-MailContact", Identity=guid)
            except InvokeCommandError as error:
                gone = error
            if gone is not None:
                assert gone.status == 404, str(gone)
                break
            if time.monotonic() > deadline:
                pytest.fail(f"{name!r} still reads back {REPLICATION_TIMEOUT:.0f}s after removal")
            await asyncio.sleep(POLL_SECONDS)

    print(
        f"exchange write: read back after {read_wait:.0f}s, changed after {set_wait:.0f}s,"
        f" removed after {remove_wait:.0f}s; warnings from a no-op Set-MailContact: {warnings}"
    )
    assert warnings, "a Set- cmdlet that changed nothing produced no warning"
    assert any("modified" in warning for warning in warnings)
