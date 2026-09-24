"""One partner sign-in, then silent sibling contexts on each GDAP customer."""

from __future__ import annotations

import pytest

from azure_auth import AuthContext, ConsentRequired, GraphClient, InteractionRequired
from tests.live.support import GDAP_SCOPES, _flag, needs_user, require_cached_sign_in

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
@_flag("AZURE_AUTH_TEST_GDAP")
async def test_gdap_loop_reaches_customers_without_prompting(user_auth: AuthContext) -> None:
    async with GraphClient(user_auth, scopes=GDAP_SCOPES) as partner:
        require_cached_sign_in(partner)
        customers = await partner.list_customer_tenant_ids()
    assert customers, "the partner tenant has no GDAP customers"

    reached = 0
    skipped: list[str] = []
    for tenant_id in customers[:5]:
        sibling = user_auth.for_tenant(tenant_id)
        async with GraphClient(sibling, scopes=GDAP_SCOPES[1:]) as graph:
            try:
                organization = await graph.get_all("/organization")
            except (ConsentRequired, InteractionRequired) as error:
                # Expected for a customer without consent; the error names the tenant.
                skipped.append(error.tenant_id)
                continue
        assert organization[0]["id"] == tenant_id
        reached += 1
    assert reached, "no customer tenant could be reached silently"
    assert set(skipped) <= set(customers)
