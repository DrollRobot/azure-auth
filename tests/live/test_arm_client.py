"""The ARM client against the real service."""

from __future__ import annotations

import pytest

from azure_auth import AuthContext, AzureClient
from tests.live.support import _flag, needs_user, require_cached_sign_in

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
@_flag("AZURE_AUTH_TEST_ARM")
async def test_arm_lists_subscriptions(user_auth: AuthContext) -> None:
    async with AzureClient(user_auth) as arm:
        require_cached_sign_in(arm)
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    # An empty list would also come back from a tenant the user cannot reach at all, so it
    # must not count as a pass; the flag says this user really has a subscription.
    assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert all(s.get("subscriptionId") for s in subscriptions)
