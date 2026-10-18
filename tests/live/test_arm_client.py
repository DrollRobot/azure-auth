"""The ARM client against the real service: listing, a long-running operation, and the
blocking mirror.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import httpx
import pytest
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.resource.subscriptions.aio import SubscriptionClient as AsyncSubscriptionClient

from azure_auth import ArmClient, AuthContext
from azure_auth.sync import ArmClient as BlockingArmClient
from tests.live.support import (
    _flag,
    ensure_sign_in,
    live_app_auth,
    live_user_auth,
    needs_app,
    needs_user,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

needs_arm = _flag("AZURE_AUTH_TEST_ARM")

# A subscription-scope template with nothing in it. What-If of it predicts no change, whatever
# the subscription holds.
EMPTY_TEMPLATE = {
    "$schema": (
        "https://schema.management.azure.com/schemas/2018-05-01/"
        "subscriptionDeploymentTemplate.json#"
    ),
    "contentVersion": "1.0.0.0",
    "resources": [],
}


@needs_user
@needs_arm
async def test_arm_lists_subscriptions(user_auth: AuthContext) -> None:
    async with ArmClient(user_auth) as arm:
        ensure_sign_in(arm)
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    # An empty list would also come back from a tenant the user cannot reach at all, so it
    # must not count as a pass; the flag says this user really has a subscription.
    assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert all(s.get("subscriptionId") for s in subscriptions)


@needs_user
@needs_arm
async def test_an_azure_sdk_client_lists_subscriptions_with_the_context(
    user_auth: AuthContext,
) -> None:
    """Azure's own management client, given the context, lists what the ARM client lists.

    Every ``azure-mgmt-*`` client asks its credential for a token through ``get_token``: the
    asynchronous one is handed ``auth.aio``, the blocking one ``auth`` itself. The package's
    own ARM client is the witness. The cloud's ARM host and scope are passed, since the SDK
    defaults to the commercial cloud's.
    """
    arm_url = user_auth.tenant.cloud.arm
    scopes = [f"{arm_url}/.default"]
    async with ArmClient(user_auth) as arm:
        ensure_sign_in(arm)
        expected = {
            s["subscriptionId"]
            for s in await arm.get_all("/subscriptions", api_version="2022-12-01")
        }
    async with AsyncSubscriptionClient(
        user_auth.aio, base_url=arm_url, credential_scopes=scopes
    ) as sdk:
        listed = {s.subscription_id async for s in sdk.subscriptions.list()}
    with SubscriptionClient(user_auth, base_url=arm_url, credential_scopes=scopes) as sdk:
        blocking = {s.subscription_id for s in sdk.subscriptions.list()}

    assert expected, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert listed == expected
    assert blocking == expected


@needs_app
@needs_arm
async def test_arm_lists_subscriptions_as_an_app() -> None:
    """An app-only token lists the subscriptions the application holds a role on."""
    async with ArmClient(live_app_auth()) as arm:
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    assert subscriptions, "the test application can see no subscriptions; give it Reader on one"
    assert all(s.get("subscriptionId") for s in subscriptions)


@needs_user
@needs_arm
async def test_wait_follows_a_long_running_operation_to_its_result(
    user_auth: AuthContext,
) -> None:
    """``wait`` polls a long-running operation until Resource Manager hands back its result.

    ``wait`` had never followed a real operation. What-If of an empty template at subscription
    scope is a long-running operation that changes nothing: Resource Manager answers 202 with
    a ``Location`` to poll, which answers 202 until the comparison is done and then 200 with
    the result, an empty list of changes. It needs
    ``Microsoft.Resources/deployments/whatIf/action`` on the subscription, which Contributor
    has and Reader does not, so this runs as the user, against the first subscription they see.

    The deployment name is only a correlation id; What-If stores no deployment under it.
    ``location`` is where a deployment would be stored, and is required at subscription scope.
    Whether the operation is long-running at all is up to Resource Manager; a 200 at once
    proves nothing about ``wait``, so that skips rather than passes. Measured 2026-10-10: 202
    with ``Location`` and ``Retry-After: 15``, no ``Azure-AsyncOperation``, and the first
    poll brought the result.
    """
    name = f"azure-auth-live-test-{uuid.uuid4().hex[:8]}"
    async with ArmClient(user_auth) as arm:
        ensure_sign_in(arm)
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
        assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
        subscription = subscriptions[0]["subscriptionId"]
        started = await arm.send(
            "POST",
            f"/subscriptions/{subscription}/providers/Microsoft.Resources/deployments/{name}"
            "/whatIf",
            api_version="2021-04-01",
            json={
                "location": "eastus",
                "properties": {"mode": "Incremental", "template": EMPTY_TEMPLATE},
            },
        )
        # The Location URL carries a signed blob a screen wide; only its presence is printed.
        polled = [name for name in ("Azure-AsyncOperation", "Location") if name in started.headers]
        retry_after = started.headers.get("Retry-After", "(absent)")
        waited = time.monotonic()
        result = await arm.wait(started, timeout=300)
        waited = time.monotonic() - waited

    print(
        f"arm what-if: answered {started.status_code} with {' and '.join(polled) or 'no poll URL'},"
        f" Retry-After {retry_after}; result after {waited:.0f}s"
    )
    if started.status_code != httpx.codes.ACCEPTED:
        pytest.skip(f"What-If answered {started.status_code} at once; nothing to wait for")
    assert result["status"] == "Succeeded", result
    assert result["properties"]["changes"] == [], result


@needs_user
@needs_arm
def test_the_blocking_client_lists_subscriptions(cache_path: Path) -> None:
    """The generated blocking client works against the real service, not only its mirror tests."""
    with BlockingArmClient(live_user_auth(cache_path)) as arm:
        ensure_sign_in(arm)
        subscriptions = arm.get_all("/subscriptions", api_version="2022-12-01")
    assert subscriptions, "the user can see no subscriptions; AZURE_AUTH_TEST_ARM is wrong"
    assert all(s.get("subscriptionId") for s in subscriptions)
