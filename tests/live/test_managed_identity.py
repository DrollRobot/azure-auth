"""The managed identity flow on a real Azure host, through its identity endpoint.

Needs ``AZURE_AUTH_TEST_MANAGED_IDENTITY_CLIENT_ID``: a user-assigned identity attached to the
host these tests run on, with ``Key Vault Secrets User`` on the test vault and ``Reader`` on
the subscription. The identity has no Entra app role, so the Graph test proves the token's
audience and host, not a role: Graph answers 403 for an identity without one.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import pytest

from azure_auth import ArmClient, AuthContext, AuthError, GraphClient
from azure_auth.clients.errors import GraphError
from azure_auth.clients.keyvault import KeyVaultClient
from azure_auth.sync.keyvault import KeyVaultClient as BlockingKeyVaultClient
from tests.live.support import (
    KEYVAULT_SECRET_NAME,
    KEYVAULT_URL,
    TENANT,
    _flag,
    live_cloud,
    live_tenant,
    needs_keyvault,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

IDENTITY_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_MANAGED_IDENTITY_CLIENT_ID", "")

needs_managed_identity = pytest.mark.skipif(
    not (TENANT and IDENTITY_CLIENT_ID),
    reason="set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_MANAGED_IDENTITY_CLIENT_ID",
)
needs_arm = _flag("AZURE_AUTH_TEST_ARM")

# A refusal must come back well within this; the endpoint is on the host.
REFUSAL_SECONDS = 30


def identity_auth(**kwargs: Any) -> AuthContext:
    """Return a context for the test identity, with the tenant looked up as for every flow."""
    return AuthContext(TENANT, managed_identity=True, client_id=IDENTITY_CLIENT_ID, **kwargs)


@needs_managed_identity
@needs_keyvault
async def test_the_identity_reads_a_vault_secret() -> None:
    auth = identity_auth()
    async with KeyVaultClient(auth, KEYVAULT_URL) as vault:
        value = await vault.get_secret(KEYVAULT_SECRET_NAME)
    has_value = bool(value)
    assert has_value, f"the secret {KEYVAULT_SECRET_NAME!r} came back empty"
    assert auth.tenant == live_tenant()


@needs_managed_identity
@needs_keyvault
def test_the_identity_reads_a_vault_secret_given_its_cloud_only() -> None:
    auth = AuthContext(cloud=live_cloud(), managed_identity=True, client_id=IDENTITY_CLIENT_ID)
    assert auth.tenant.id is None
    with BlockingKeyVaultClient(auth, KEYVAULT_URL) as vault:
        value = vault.get_secret(KEYVAULT_SECRET_NAME)
    has_value = bool(value)
    assert has_value, f"the secret {KEYVAULT_SECRET_NAME!r} came back empty"
    # The vault's token named the tenant.
    assert auth.tenant == live_tenant()


@needs_managed_identity
@needs_arm
async def test_the_identity_lists_subscriptions() -> None:
    async with ArmClient(identity_auth()) as arm:
        subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
    assert subscriptions, "the identity can see no subscription; is it a Reader on one?"
    assert all(s.get("subscriptionId") for s in subscriptions)


@needs_managed_identity
async def test_graph_accepts_the_identitys_token() -> None:
    """Graph takes the token as valid: 200 with a role, 403 for insufficient privileges without.

    Anything else -- a token for the wrong audience, the wrong cloud's host, a rejected
    signature -- is a different status or code, and fails.
    """
    async with GraphClient(identity_auth()) as graph:
        try:
            organization = await graph.get_all("/organization")
        except GraphError as exc:
            refusal: GraphError | None = exc
            organization = []
        else:
            refusal = None
    if refusal is not None:
        assert (refusal.status, refusal.code) == (403, "Authorization_RequestDenied"), str(refusal)
    else:
        assert [item["id"] for item in organization] == [live_tenant().id]


@needs_managed_identity
def test_a_made_up_client_id_is_refused_at_once() -> None:
    made_up = str(uuid.uuid4())
    auth = AuthContext(TENANT, managed_identity=True, client_id=made_up)
    started = time.monotonic()
    with pytest.raises(AuthError) as info:
        auth.acquire_token_silently(["https://vault.azure.net/.default"])
    assert time.monotonic() - started < REFUSAL_SECONDS
    assert made_up in str(info.value)
    assert "refused" in str(info.value)
