"""Reset an application's consent in a tenant, back to a known baseline.

Shared by ``scripts/revoke_consent.py`` (run by hand) and the consent fixture in
``tests/live/test_live.py`` (run as part of a ``destructive_remote`` test), so both take
exactly the same path through Graph.

Consent cannot be tested repeatably without a way to un-consent: once an application has been
granted its scopes, every later sign-in is silent and the consent code never runs again.

Nothing here is part of the package's public API.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from azure_auth import GraphClient, ResourceError

# How hard to try when a delete is refused for a grant the list query just returned. Graph
# serves these from replicas that lag each other, so a grant can be listed on one and unknown
# to the next. Observed 2026-09-20: a sign-in created a grant, the list returned it, and the
# delete answered "400 Request_BadRequest: Permission being updated or deleted is not found."
_DELETE_ATTEMPTS = 4
_DELETE_BACKOFF_SECONDS = 2.0

# The same lag runs the other way: a grant created moments earlier can be missing from the
# list, so one pass that deletes nothing is not evidence of a clean tenant. Observed
# 2026-09-20: a sign-in consented on behalf of the organization, the list reported no grants
# at all, and the grant was nonetheless live enough for another user to sign in silently on
# it. So the reset re-lists until it has seen a round with nothing left to delete.
_SETTLE_ROUNDS = 5
_SETTLE_BACKOFF_SECONDS = 3.0

# Microsoft's first-party client that the user-flow clients sign in as. Listed in the portal
# as "Microsoft Graph Command Line Tools"; it was called "Microsoft Graph PowerShell" before,
# which is the name the package constant and the design notes still use.
GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"


@dataclass
class ResetResult:
    """What a reset did.

    Attributes:
        deleted: Ids of the grants that were removed.
        kept: Ids of the grants that were deliberately left in place.
        failed: Ids that could not be removed, with the reason.
        rounds: How many times the grants had to be re-listed before a round came back with
            nothing left to delete. More than one means Graph was still catching up.
    """

    deleted: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    rounds: int = 0

    @property
    def ok(self) -> bool:
        """Whether the baseline was reached and confirmed by a clean re-read."""
        return not self.failed and self.rounds > 0


async def service_principal(graph: GraphClient, client_id: str) -> dict[str, Any]:
    """Look up the service principal of an application in the signed-in tenant.

    Args:
        graph: The Graph client to ask.
        client_id: Application (client) id.

    Returns:
        The service principal, with ``id`` and ``displayName``.

    Raises:
        ResourceError: If it cannot be read. A 404 means the application has never been used
            in this tenant, so it has no service principal and therefore no grants.
    """
    principal: dict[str, Any] = await graph.get(
        f"/servicePrincipals(appId='{client_id}')?$select=id,displayName"
    )
    return principal


async def find_grants(graph: GraphClient, principal_id: str) -> list[dict[str, Any]]:
    """Return the consent grants whose client is the given service principal.

    The server-side ``$filter`` is asked first. An empty answer from it is not taken at face
    value: the filter is served from a replica that can lag a grant created moments earlier,
    and "no grants found" would otherwise read exactly like "nothing to revoke", making a
    reset that did nothing look like a success. Observed against a live tenant on 2026-09-20:
    a sign-in consented, and the filter still reported nothing while the grant was plainly in
    use. So an empty result is re-checked against the unfiltered list. That list can come from
    the same replica, so this narrows the window rather than closing it.

    Args:
        graph: The Graph client to ask.
        principal_id: Object id of the client service principal.

    Returns:
        The matching grants.
    """
    filtered = await graph.get_all(
        "/oauth2PermissionGrants", params={"$filter": f"clientId eq '{principal_id}'"}
    )
    if filtered:
        return list(filtered)

    everything = await graph.get_all("/oauth2PermissionGrants")
    return [grant for grant in everything if grant.get("clientId") == principal_id]


def describe(grant: dict[str, Any]) -> str:
    """Summarise one grant for a human reading a terminal.

    Args:
        grant: An ``oauth2PermissionGrant``.

    Returns:
        A one-line description: who it covers and which scopes it carries.
    """
    if grant.get("consentType") == "AllPrincipals":
        who = "everyone in the tenant"
    else:
        who = f"user {grant.get('principalId', '?')}"
    scopes = " ".join(sorted(str(grant.get("scope", "")).split())) or "(no scopes)"
    return f"{who}: {scopes}"


async def _is_gone(graph: GraphClient, grant_id: str) -> bool:
    """Ask whether a grant has genuinely stopped existing.

    Args:
        graph: The Graph client to ask.
        grant_id: Id of the grant.

    Returns:
        ``True`` only on a definite 404. Any other answer, including an error, counts as
        "still there", so a reset never reports success it cannot prove.
    """
    try:
        await graph.get(f"/oauth2PermissionGrants/{grant_id}")
    except ResourceError as error:
        return error.status == 404
    return False


async def _delete_grant(graph: GraphClient, grant_id: str) -> str | None:
    """Delete one consent grant, tolerating Graph's replica lag.

    A delete can be refused for a grant the list query returned moments earlier, because the
    two are served from replicas that lag each other. That refusal is not evidence the grant
    is gone, so it is checked: if the grant really has disappeared the goal is met, and if it
    has not, the delete is tried again.

    Args:
        graph: The Graph client to use.
        grant_id: Id of the grant to delete.

    Returns:
        ``None`` once the grant is gone, or the last error message if it survived.
    """
    last = ""
    for attempt in range(_DELETE_ATTEMPTS):
        try:
            await graph.delete(f"/oauth2PermissionGrants/{grant_id}")
        except ResourceError as error:
            last = str(error)
            if await _is_gone(graph, grant_id):
                return None
            if attempt < _DELETE_ATTEMPTS - 1:
                await asyncio.sleep(_DELETE_BACKOFF_SECONDS)
            continue
        return None
    return last


async def reset_to_baseline(
    graph: GraphClient,
    *,
    client_id: str = GRAPH_CLI_CLIENT_ID,
    keep_principal_id: str | None = None,
) -> ResetResult:
    """Delete an application's consent grants, optionally sparing one user's own grant.

    The baseline is "nobody has consented to this application, except possibly the one user
    named by ``keep_principal_id``". That exception exists because the caller doing the
    revoking needs consent to make these very calls: revoking its own grant would make the
    next run prompt again purely to restore tooling access, which tests nothing. Every
    tenant-wide (``AllPrincipals``) grant is removed regardless, since that is what would let
    an unrelated user sign in silently and make a consent test pass without consenting.

    Args:
        graph: A Graph client whose identity holds ``DelegatedPermissionGrant.ReadWrite.All``.
        client_id: Application whose grants are removed.
        keep_principal_id: Object id of a user whose own grant should survive, or ``None`` to
            remove every grant.

    Returns:
        What was deleted, kept and failed.
    """
    result = ResetResult()
    try:
        principal = await service_principal(graph, client_id)
    except ResourceError as error:
        if error.status == 404:
            # The application has no service principal here, so it has never been consented
            # to and there is nothing to reset. That is a confirmed baseline, not a failure
            # to reach one, so it counts as a round; otherwise `ok` would be False for a
            # tenant that is already in exactly the state being asked for.
            result.rounds = 1
            return result
        raise
    principal_id = str(principal["id"])

    def spared(grant: dict[str, Any]) -> bool:
        """Whether this grant is the one user's own grant that survives a reset."""
        return (
            keep_principal_id is not None
            and grant.get("consentType") != "AllPrincipals"
            and str(grant.get("principalId", "")) == keep_principal_id
        )

    clean_reads = 0
    for attempt in range(_SETTLE_ROUNDS):
        grants = await find_grants(graph, principal_id)
        result.kept = [str(grant["id"]) for grant in grants if spared(grant)]
        doomed = [grant for grant in grants if not spared(grant)]
        if not doomed:
            # One clean read is not proof: an empty answer is exactly what a lagging replica
            # returns for a grant that was created moments ago and is already usable. Require
            # two in a row, with a pause between them, before believing it.
            clean_reads += 1
            if clean_reads >= 2:
                result.rounds = attempt + 1
                return result
            await asyncio.sleep(_SETTLE_BACKOFF_SECONDS)
            continue
        clean_reads = 0

        for grant in doomed:
            grant_id = str(grant["id"])
            failure = await _delete_grant(graph, grant_id)
            if failure is None:
                result.deleted.append(grant_id)
                result.failed.pop(grant_id, None)
            else:
                result.failed[grant_id] = failure

        if attempt < _SETTLE_ROUNDS - 1:
            await asyncio.sleep(_SETTLE_BACKOFF_SECONDS)

    result.rounds = _SETTLE_ROUNDS
    still_there = await find_grants(graph, principal_id)
    for grant in still_there:
        if not spared(grant):
            result.failed.setdefault(
                str(grant["id"]), f"still present after {_SETTLE_ROUNDS} rounds: {describe(grant)}"
            )
    return result
