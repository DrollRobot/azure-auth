"""The Exchange client's REST reads against the real admin API.

These are the endpoints behind the ``Get-EXO*`` cmdlets: plain OData GETs beside
``InvokeCommand``, read out of the ExchangeOnlineManagement module and documented nowhere.
Every test here uses the delegated Exchange sign-in from the shared cache, signing in when
there is none, and only reads. Together they cover each of the nine reads, paging, one
object by identity, the failure shapes, an app-only sign-in and the blocking mirror.

What a live run shows that the module could not is printed: the routing header the GET
endpoints accept, the body of a key-path read, and the error bodies.
"""

from __future__ import annotations

import functools
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from azure_auth import AuthContext, ExchangeClient, InvokeCommandError
from azure_auth.clients.exchange import encode_identity
from azure_auth.sync import ExchangeClient as BlockingExchangeClient
from tests.live.support import (
    USERNAME,
    Recording,
    ensure_sign_in,
    live_app_auth,
    live_user_auth,
    needs_app,
    needs_exchange,
    needs_user,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

# Two results a page, so that any tenant with three recipients pages, and a cap on how
# many pages are walked at that size, so a large tenant does not turn this into a crawl.
PAGE_SIZE = 2
MAX_PAGES = 25

# The audit property set of every mailbox, plus two properties. In PowerShell:
# Get-EXOMailbox -PropertySets Audit -RecipientTypeDetails ... -Properties ...
AUDIT_QUERY: dict[str, Any] = {
    "PropertySet": "Audit",
    "RecipientTypeDetails": ["UserMailbox", "SharedMailbox", "RoomMailbox", "EquipmentMailbox"],
    "select": ["DefaultAuditSet", "UserPrincipalName", "RecipientTypeDetails"],
}


def keys(obj: dict[str, Any]) -> list[str]:
    """Return an object's property names without OData's annotations, for printing.

    Args:
        obj: An object the service answered with.

    Returns:
        The names, sorted.
    """
    return sorted(name for name in obj if not name.startswith("@"))


def names(user: str) -> bool:
    """Tell whether a string names the configured user, whatever its case.

    Args:
        user: A property value.

    Returns:
        ``True`` for the user's UPN.
    """
    return user.lower() == USERNAME.lower()


@needs_user
@needs_exchange
async def test_mailboxes_read_returns_the_audit_property_set(user_auth: AuthContext) -> None:
    """A property set read: every mailbox's audit settings, and little else.

    The read is ``PropertySet=Audit`` with ``$select`` for three properties. The user's own
    mailbox is in the answer with its audit sets as lists,
    and with fewer properties than ``Get-Mailbox`` returns for it, which is the point of the
    read. The same read without ``$select`` shows whether the property set alone carries
    ``UserPrincipalName`` (printed), and the request shows the routing header the endpoint
    accepted.
    """
    recording = Recording()
    async with ExchangeClient(user_auth, transport=recording) as exchange:
        ensure_sign_in(exchange)
        audited = await exchange.mailboxes(**AUDIT_QUERY)
        audit_only = await exchange.mailboxes(PropertySet="Audit")
        everything = await exchange.run("Get-Mailbox", Identity=USERNAME)

    mine = [mailbox for mailbox in audited if names(mailbox["UserPrincipalName"])]
    assert len(mine) == 1, f"the user's mailbox is not among the {len(audited)} audited"
    assert isinstance(mine[0]["DefaultAuditSet"], list)
    assert mine[0]["RecipientTypeDetails"] == "UserMailbox"
    assert len(keys(mine[0])) < len(everything[0])
    request = recording.requests[0]
    assert request.method == "GET"
    assert request.url.path.endswith("/Mailbox")
    assert exchange.last_warnings == []
    print(
        f"exchange rest: {len(audited)} audited mailboxes, {len(keys(mine[0]))} properties"
        f" against {len(everything[0])} from Get-Mailbox; routing header"
        f" {request.headers['X-AnchorMailbox']}; PropertySet=Audit alone returns"
        f" {keys(audit_only[0])}"
    )


@needs_user
@needs_exchange
async def test_reads_page_by_a_get_on_each_next_link(user_auth: AuthContext) -> None:
    """``iter_get_pages`` walks every page by GET, and ``get`` returns the same objects.

    The module GETs ``@odata.nextLink``, where ``InvokeCommand`` POSTs its body to it. Two
    recipients a page, as the cmdlet paging test does, because every tenant has more
    recipients than mailboxes.
    """
    async with ExchangeClient(user_auth, page_size=PAGE_SIZE) as exchange:
        ensure_sign_in(exchange)
        pages = 0
        paged: list[str] = []
        async for page in exchange.iter_get_pages("Recipient"):
            pages += 1
            values = page.get("value", [])
            assert len(values) <= PAGE_SIZE
            paged.extend(recipient["Identity"] for recipient in values)
            if pages >= MAX_PAGES:
                break
    async with ExchangeClient(user_auth) as exchange:
        everyone = {recipient["Identity"] for recipient in await exchange.recipients()}

    assert pages > 1, f"everything arrived in one page of {PAGE_SIZE}; nothing paged"
    assert len(paged) == len(set(paged)), "a page repeated an object"
    assert set(paged) <= everyone
    if pages < MAX_PAGES:
        assert set(paged) == everyone, "the pages stopped before the end"
    print(f"exchange rest paging: {pages} pages at {PAGE_SIZE} a page, {len(paged)} objects")


@needs_user
@needs_exchange
@pytest.mark.parametrize(
    ("read", "entity"),
    [("mailboxes", "Mailbox"), ("cas_mailboxes", "CasMailbox"), ("recipients", "Recipient")],
)
async def test_each_collection_reads_whole_and_one_by_identity(
    user_auth: AuthContext, read: str, entity: str
) -> None:
    """Each collection answers in full, and a key path with the encoded identity finds one.

    The user's UPN is the identity. What a key path answers with, the object itself or
    ``value`` with one element, is printed.
    """
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        everyone = await getattr(exchange, read)()
        one = await getattr(exchange, read)(USERNAME)
        shapes: list[str] = []
        key_path = f"{entity}('{encode_identity(USERNAME)}')"
        async for page in exchange.iter_get_pages(key_path, isEncoded="true"):
            shapes.append("value" if "value" in page else "the object")

    assert everyone
    assert len(one) == 1
    assert any(isinstance(value, str) and names(value) for value in one[0].values())
    print(
        f"exchange rest {read}: {len(everyone)} objects, {len(keys(everyone[0]))} properties"
        f" each; a key path answers with {shapes}"
    )


@needs_user
@needs_exchange
async def test_a_mailboxs_permissions_are_read(user_auth: AuthContext) -> None:
    """Permissions on the user's mailbox: everyone's, the owner's entry, and one user's.

    ``user=`` is tried for the first trustee named by address, when there is one, and for
    the owner, who usually holds the mailbox as ``NT AUTHORITY\\SELF`` and has no entry under
    their own name. A user without an entry is a 404 ``No permissions were found for the
    user``, not an empty list (measured 2026-10-15).
    """
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        everyone = await exchange.mailbox_permissions(USERNAME)
        owner = await exchange.mailbox_permissions(USERNAME, owner=True)
        named = [str(entry["User"]) for entry in everyone if "@" in str(entry["User"])]
        one = await exchange.mailbox_permissions(USERNAME, user=named[0]) if named else []
        refused: InvokeCommandError | None = None
        own: list[dict[str, Any]] = []
        try:
            own = await exchange.mailbox_permissions(USERNAME, user=USERNAME)
        except InvokeCommandError as error:
            refused = error

    # One entry per trustee, each with a PermissionList; the cmdlet flattens that list into one
    # row per permission (measured 2026-10-15).
    assert everyone
    assert all(entry["User"] and entry["PermissionList"] for entry in everyone)
    assert all("AccessRights" in item for entry in everyone for item in entry["PermissionList"])
    assert owner
    assert all(entry["IsOwner"] for entry in owner)
    if named:
        assert one
        assert {str(entry["User"]) for entry in one} == {named[0]}
    if refused is not None:
        assert refused.status == 404, str(refused)
        assert "No permissions were found" in str(refused)
    print(
        f"exchange rest permissions: {len(everyone)} entries, owner {owner[0]['User']!r},"
        f" {len(one)} for {named[0] if named else 'nobody named by address'},"
        f" {len(own)} for the owner by name; keys {keys(everyone[0])}"
    )


@needs_user
@needs_exchange
async def test_a_folders_permissions_are_read(user_auth: AuthContext) -> None:
    """Permissions on the user's calendar, the folder every mailbox has and shares."""
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        entries = await exchange.mailbox_folder_permissions(USERNAME, "\\Calendar")

    assert entries
    assert all(entry["User"] and entry["AccessRights"] for entry in entries)
    print(f"exchange rest folder permissions: {len(entries)} entries; keys {keys(entries[0])}")


@needs_user
@needs_exchange
async def test_a_mailboxs_statistics_are_read(user_auth: AuthContext) -> None:
    """The user's mailbox statistics, and its folders', whole and for one folder scope."""
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        statistics = await exchange.mailbox_statistics(USERNAME)
        folders = await exchange.mailbox_folder_statistics(USERNAME)
        inbox = await exchange.mailbox_folder_statistics(USERNAME, folder_scope="Inbox")

    assert len(statistics) == 1
    assert "ItemCount" in statistics[0]
    assert folders
    assert all("Name" in folder for folder in folders)
    assert 0 < len(inbox) < len(folders)
    print(
        f"exchange rest statistics: {statistics[0]['ItemCount']} items, {len(folders)} folders,"
        f" {len(inbox)} under the inbox; keys {keys(statistics[0])}"
    )


@needs_user
@needs_exchange
async def test_a_mailboxs_mobile_devices_are_read(user_auth: AuthContext) -> None:
    """The user's devices by mailbox, and, when there is one, one device by its identity.

    The identity form puts the device in a header rather than the path. Without a device to
    name it goes unexercised, and the result says so.
    """
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        devices = await exchange.mobile_device_statistics(USERNAME)
        one = (
            await exchange.mobile_device_statistics(device=devices[0]["Identity"])
            if devices
            else None
        )

    assert isinstance(devices, list)
    if one is None:
        print("exchange rest devices: the user has none; the device-by-identity form is untried")
        return
    assert len(one) == 1
    print(f"exchange rest devices: {len(devices)}; one by identity has keys {keys(one[0])}")


@needs_user
@needs_exchange
async def test_recipient_permissions_are_read(user_auth: AuthContext) -> None:
    """Send As permissions: of every recipient, of the user, and the user's by right."""
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        everyone = await exchange.recipient_permissions()
        mine = await exchange.recipient_permissions(USERNAME)
        send_as = await exchange.recipient_permissions(USERNAME, access_rights="SendAs")

    assert everyone
    assert all("RecipientPermission" in recipient for recipient in everyone)
    assert len(mine) == 1
    assert isinstance(mine[0]["RecipientPermission"], list)
    assert isinstance(send_as, list)
    print(
        f"exchange rest recipient permissions: {len(everyone)} recipients,"
        f" {len(mine[0]['RecipientPermission'])} entries on the user, {len(send_as)} by right;"
        f" keys {keys(everyone[0])}"
    )


@needs_user
@needs_exchange
async def test_read_failures_are_odata_errors(user_auth: AuthContext) -> None:
    """What a bad property, a bad property set, an unknown path and a missing object answer.

    The module reads failures as plain OData errors: ``error.message``, with the status. The
    outcomes are printed. The two that must fail are asserted; the two the service might
    wave through are only reported.
    """
    missing = str(uuid.uuid4())
    async with ExchangeClient(user_auth) as exchange:
        ensure_sign_in(exchange)
        probes: dict[str, Callable[[], Awaitable[list[dict[str, Any]]]]] = {
            "bad property": functools.partial(exchange.mailboxes, select="NoSuchProperty"),
            "bad property set": functools.partial(exchange.mailboxes, PropertySet="NoSuchSet"),
            "unknown path": functools.partial(exchange.get, "NoSuchEntity"),
            "missing object": functools.partial(exchange.mailboxes, missing),
        }
        outcomes: dict[str, InvokeCommandError | int] = {}
        for name, probe in probes.items():
            try:
                outcomes[name] = len(await probe())
            except InvokeCommandError as error:
                outcomes[name] = error

    for name, outcome in outcomes.items():
        if isinstance(outcome, int):
            print(f"exchange rest error, {name}: answered with {outcome} objects")
            continue
        body = outcome.body
        odata = body.get("error") if isinstance(body, dict) else None
        shape: list[str] | str = sorted(odata) if isinstance(odata, dict) else type(body).__name__
        print(
            f"exchange rest error, {name}: {outcome.status} {outcome.code!r}; error keys"
            f" {shape}; {str(outcome)[:200]}"
        )
    for name in ("unknown path", "missing object"):
        outcome = outcomes[name]
        assert isinstance(outcome, InvokeCommandError), f"{name} did not fail"
        assert outcome.status >= 400
        assert str(outcome).startswith("GET ")
        assert f"-> {outcome.status}" in str(outcome)


@needs_app
@needs_exchange
async def test_reads_work_for_an_app() -> None:
    """An app-only token reads mailboxes through the routing header its cmdlets use.

    The PowerShell module routes an application's REST reads with
    ``UPN:SystemMailbox{...}@<domain>``. The client sends ``APP:SystemMailbox{...}@<GUID>``,
    which ``InvokeCommand`` accepts from an app (measured 2026-10-10). Whether the GET
    endpoints accept it too is what this run settles; the header is printed with the result.
    """
    recording = Recording()
    async with ExchangeClient(live_app_auth(), transport=recording) as exchange:
        mailboxes = await exchange.mailboxes(PropertySet="Minimum")

    assert mailboxes
    print(
        f"exchange rest as an app: {len(mailboxes)} mailboxes with X-AnchorMailbox"
        f" {recording.requests[0].headers['X-AnchorMailbox']}"
    )


@needs_user
@needs_exchange
def test_the_blocking_exchange_client_reads_mailboxes(cache_path: Path) -> None:
    """The generated blocking client reads against the real service."""
    with BlockingExchangeClient(live_user_auth(cache_path)) as exchange:
        ensure_sign_in(exchange)
        mailboxes = exchange.mailboxes(**AUDIT_QUERY)
    assert mailboxes
    assert all(isinstance(mailbox["DefaultAuditSet"], list) for mailbox in mailboxes)
