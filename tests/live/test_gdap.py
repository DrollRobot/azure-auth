"""One home-tenant sign-in, then silent sibling contexts on each GDAP managed tenant."""

from __future__ import annotations

import pytest

from azure_auth import AuthContext, ConsentRequired, GraphClient, InteractionRequired
from tests.live.support import GDAP_SCOPES, _flag, needs_user, require_cached_sign_in

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
@_flag("AZURE_AUTH_TEST_GDAP")
async def test_gdap_loop_reaches_managed_tenants_without_prompting(
    user_auth: AuthContext,
) -> None:
    async with GraphClient(user_auth, scopes=GDAP_SCOPES) as home:
        require_cached_sign_in(home)
        managed = await home.list_managed_tenant_ids()
    assert managed, "the home tenant manages no tenants through GDAP"

    reached = 0
    skipped: list[str] = []
    for tenant_id in managed[:5]:
        sibling = user_auth.for_tenant(tenant_id)
        async with GraphClient(sibling, scopes=GDAP_SCOPES[1:]) as graph:
            try:
                organization = await graph.get_all("/organization")
            except (ConsentRequired, InteractionRequired) as error:
                # Expected for a managed tenant without consent; the error names the tenant.
                skipped.append(error.tenant_id)
                continue
        assert organization[0]["id"] == tenant_id
        reached += 1
    assert reached, "no managed tenant could be reached silently"
    assert set(skipped) <= set(managed)
