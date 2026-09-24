"""Unit tests for the consent reset used by the live consent test.

``tests/consent_reset.py`` is test-support code, which is the category that makes *other*
tests lie when it is wrong: a reset that reports success without having reset anything turns
the live consent test into a test of nothing. It also has the most delicate logic in the
suite, because ``/oauth2PermissionGrants`` is eventually consistent in both directions and
both of its workarounds were written after a live run failed in a confusing way.

So the lag is modelled here rather than waited for: :class:`FakeGraph` can hide grants from a
read, fail a delete, or fail a delete while removing the grant anyway.
"""

from __future__ import annotations

from typing import Any

import pytest

from azure_auth import ResourceError
from tests import consent_reset

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

SP_ID = "sp-graph-cli"
ADMIN = "admin-object-id"
OTHER = "other-object-id"


def grant(
    grant_id: str,
    *,
    principal: str | None = None,
    scope: str = "User.Read.All",
) -> dict[str, Any]:
    """Build an ``oauth2PermissionGrant``.

    Args:
        grant_id: Its id.
        principal: Object id of the one user it covers, or ``None`` for a tenant-wide grant.
        scope: Space-separated scopes it carries.

    Returns:
        The grant as Graph returns it.
    """
    body: dict[str, Any] = {
        "id": grant_id,
        "clientId": SP_ID,
        "resourceId": "resource-graph",
        "scope": scope,
    }
    if principal is None:
        body["consentType"] = "AllPrincipals"
    else:
        body["consentType"] = "Principal"
        body["principalId"] = principal
    return body


class FakeGraph:
    """A Graph stand-in holding one application's consent grants.

    Attributes:
        hidden_reads: How many upcoming list calls report nothing whatever the store holds,
            standing in for a replica that has not caught up.
        delete_failures: Grant id to the number of times deleting it raises before working.
        vanishing: Grant ids whose delete raises but removes the grant anyway, which is what
            a lagging delete looks like from the caller's side.
    """

    def __init__(self, *grants: dict[str, Any], principal_missing: bool = False) -> None:
        """Set up a tenant.

        Args:
            *grants: The grants it starts with.
            principal_missing: Answer 404 for the service principal, as a tenant where the
                application has never been used does.
        """
        self.store = {str(item["id"]): item for item in grants}
        self.principal_missing = principal_missing
        self.hidden_reads = 0
        self.delete_failures: dict[str, int] = {}
        self.vanishing: set[str] = set()
        self.deleted: list[str] = []
        self.reads = 0
        self.filtered_reads = 0
        self.delete_attempts: list[str] = []

    async def get(self, path: str, *, params: Any = None, headers: Any = None) -> Any:
        """Read a service principal or a single grant."""
        if path.startswith("/servicePrincipals"):
            if self.principal_missing:
                raise ResourceError("not found", status=404, code="Request_ResourceNotFound")
            return {"id": SP_ID, "displayName": "Microsoft Graph Command Line Tools"}
        grant_id = path.rsplit("/", 1)[-1]
        if grant_id in self.store:
            return self.store[grant_id]
        raise ResourceError("not found", status=404, code="Request_ResourceNotFound")

    async def get_all(self, path: str, *, params: Any = None, headers: Any = None) -> list[Any]:
        """List grants, possibly pretending not to see them yet."""
        self.reads += 1
        if params and "$filter" in params:
            self.filtered_reads += 1
        if self.hidden_reads > 0:
            self.hidden_reads -= 1
            return []
        return list(self.store.values())

    async def delete(self, path: str, *, params: Any = None, headers: Any = None) -> None:
        """Delete a grant, failing as scripted."""
        grant_id = path.rsplit("/", 1)[-1]
        self.delete_attempts.append(grant_id)
        remaining = self.delete_failures.get(grant_id, 0)
        if remaining:
            self.delete_failures[grant_id] = remaining - 1
            if grant_id in self.vanishing:
                self.store.pop(grant_id, None)
            raise ResourceError(
                "Permission being updated or deleted is not found.",
                status=400,
                code="Request_BadRequest",
            )
        self.store.pop(grant_id, None)
        self.deleted.append(grant_id)


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the reset's backoffs instant."""

    async def fake_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr("tests.consent_reset.asyncio.sleep", fake_sleep)


async def reset(graph: FakeGraph, keep: str | None = None) -> consent_reset.ResetResult:
    """Run a reset against a fake tenant.

    Args:
        graph: The fake tenant.
        keep: Object id whose own grant survives.

    Returns:
        What the reset did.
    """
    return await consent_reset.revoke_grants(graph, keep_principal_id=keep)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------- the simple cases


async def test_a_tenant_with_no_service_principal_has_nothing_to_revoke() -> None:
    # The application has never been used here, so there is nothing to revoke. That has to
    # count as success: no grants is exactly the state the caller asked for.
    result = await reset(FakeGraph(principal_missing=True))

    assert result.ok
    assert result.deleted == []


async def test_every_grant_goes_when_no_principal_is_spared() -> None:
    graph = FakeGraph(grant("a", principal=OTHER), grant("b"))

    result = await reset(graph)

    assert result.ok
    assert sorted(result.deleted) == ["a", "b"]
    assert graph.store == {}


async def test_the_named_users_own_grant_is_spared() -> None:
    graph = FakeGraph(grant("mine", principal=ADMIN), grant("theirs", principal=OTHER))

    result = await reset(graph, keep=ADMIN)

    assert result.ok
    assert result.deleted == ["theirs"]
    assert result.kept == ["mine"]
    assert "mine" in graph.store


async def test_a_tenant_wide_grant_is_never_spared() -> None:
    # A tenant-wide grant covers everybody, so leaving one in place would let any user sign
    # in silently -- which is precisely what a consent test needs not to happen. It goes even
    # when it carries the spared user's own principal id.
    graph = FakeGraph({**grant("wide"), "principalId": ADMIN})

    result = await reset(graph, keep=ADMIN)

    assert result.deleted == ["wide"]
    assert result.kept == []


# ---------------------------------------------------------------------------- reads that lag


async def test_one_clean_read_is_not_enough() -> None:
    # A replica that has not caught up answers an empty list, which is indistinguishable from
    # a clean tenant. Believing the first one would report a reset that never happened.
    graph = FakeGraph(grant("late"))
    graph.hidden_reads = 1

    result = await reset(graph)

    assert result.ok
    assert result.deleted == ["late"]
    assert result.rounds >= 2


async def test_a_genuinely_clean_tenant_still_needs_two_reads() -> None:
    graph = FakeGraph()

    result = await reset(graph)

    assert result.ok
    assert result.deleted == []
    assert graph.reads >= 2


async def test_an_empty_filtered_read_falls_back_to_the_unfiltered_list() -> None:
    # find_grants asks with a $filter first; Graph serves that from a replica that can lag,
    # so an empty answer is re-checked against the unfiltered list before being believed.
    graph = FakeGraph(grant("only"))

    found = await consent_reset.find_grants(graph, SP_ID)  # type: ignore[arg-type]

    assert [item["id"] for item in found] == ["only"]
    assert graph.filtered_reads == 1


# ---------------------------------------------------------------------------- deletes that lag


async def test_a_delete_that_fails_but_removed_the_grant_counts_as_done() -> None:
    # Observed live: the delete answers "Permission being updated or deleted is not found"
    # for a grant the list returned moments earlier, and the grant is gone regardless. The
    # refusal is not evidence either way, so the grant itself is checked.
    graph = FakeGraph(grant("ghost"))
    graph.delete_failures["ghost"] = 1
    graph.vanishing.add("ghost")

    result = await reset(graph)

    assert result.ok
    assert result.deleted == ["ghost"]
    assert graph.delete_attempts == ["ghost"]


async def test_a_delete_is_retried_while_the_grant_is_still_there() -> None:
    graph = FakeGraph(grant("stubborn"))
    graph.delete_failures["stubborn"] = 2

    result = await reset(graph)

    assert result.ok
    assert result.deleted == ["stubborn"]
    assert graph.delete_attempts == ["stubborn"] * 3


async def test_a_grant_that_will_not_die_is_reported_rather_than_ignored() -> None:
    # Silence here would be the worst outcome: the live consent test would run against a
    # tenant that still grants the access it expects to be refused.
    graph = FakeGraph(grant("immortal"))
    graph.delete_failures["immortal"] = 99

    result = await reset(graph)

    assert not result.ok
    assert "immortal" in result.failed
    assert "Permission being updated or deleted is not found" in result.failed["immortal"]


async def test_a_read_error_is_not_swallowed() -> None:
    class Broken(FakeGraph):
        async def get(self, path: str, *, params: Any = None, headers: Any = None) -> Any:
            raise ResourceError("boom", status=403, code="Authorization_RequestDenied")

    with pytest.raises(ResourceError, match="boom"):
        await reset(Broken())


# ---------------------------------------------------------------------------- reporting


def test_describe_names_who_a_grant_covers_and_what_it_carries() -> None:
    assert "everyone in the tenant" in consent_reset.describe(grant("a", scope="X Y"))
    assert "X Y" in consent_reset.describe(grant("a", scope="X Y"))
    assert OTHER in consent_reset.describe(grant("b", principal=OTHER))


def test_describe_handles_a_grant_with_no_scopes() -> None:
    assert "(no scopes)" in consent_reset.describe(grant("a", scope=""))
