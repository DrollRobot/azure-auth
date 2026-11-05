"""An application whose credential is a managed identity, on a real Azure host.

Needs ``AZURE_AUTH_TEST_MANAGED_IDENTITY_CLIENT_ID``: a user-assigned identity attached to the
host these tests run on, in the tenant of ``AZURE_AUTH_TEST_TENANT_ID``. Then:

- ``AZURE_AUTH_TEST_MANAGED_IDENTITY_APP_CLIENT_ID``: an application in that tenant whose
  federated credential trusts the identity, with ``Key Vault Secrets User`` on the test vault.
  Graph proves the token's audience and host, not a role: 200 with one, 403 without.
- ``AZURE_AUTH_TEST_NO_FEDERATION_APP_CLIENT_ID``: an application in that tenant with no
  federated credential for the identity, which Entra ID refuses the exchange for.

The identity's own token comes from this host; the application's from Entra ID.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from azure_auth import AuthContext, AuthError, GraphClient, ManagedIdentityUnavailable
from azure_auth.clients.errors import GraphError
from azure_auth.clients.keyvault import KeyVaultClient
from tests.live.support import (
    KEYVAULT_SECRET_NAME,
    KEYVAULT_URL,
    TENANT,
    live_cloud,
    live_tenant,
    needs_keyvault,
    token_claims,
)

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]

IDENTITY_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_MANAGED_IDENTITY_CLIENT_ID", "")
TRUSTING_APP_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_MANAGED_IDENTITY_APP_CLIENT_ID", "")
NO_FEDERATION_APP_CLIENT_ID = os.environ.get("AZURE_AUTH_TEST_NO_FEDERATION_APP_CLIENT_ID", "")

needs_managed_identity = pytest.mark.skipif(
    not (TENANT and IDENTITY_CLIENT_ID),
    reason="set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_MANAGED_IDENTITY_CLIENT_ID",
)
needs_trusting_app = pytest.mark.skipif(
    not (TENANT and IDENTITY_CLIENT_ID and TRUSTING_APP_CLIENT_ID),
    reason="set AZURE_AUTH_TEST_TENANT_ID, _MANAGED_IDENTITY_CLIENT_ID and "
    "_MANAGED_IDENTITY_APP_CLIENT_ID",
)
needs_no_federation_app = pytest.mark.skipif(
    not (TENANT and IDENTITY_CLIENT_ID and NO_FEDERATION_APP_CLIENT_ID),
    reason="set AZURE_AUTH_TEST_TENANT_ID, _MANAGED_IDENTITY_CLIENT_ID and "
    "_NO_FEDERATION_APP_CLIENT_ID",
)

# A refusal must come back well within this: the endpoint is on the host, and Entra answers
# a refused exchange at once.
REFUSAL_SECONDS = 30

# Entra's codes for an assertion no federated credential of the application matches: 70021
# when the application has federated credentials but none for this identity, 70025 when it has
# none at all (measured 2026-11-05).
NO_MATCHING_FEDERATED_CREDENTIAL = frozenset({70021, 70025})


def app_auth(app_client_id: str, identity_client_id: str = IDENTITY_CLIENT_ID) -> AuthContext:
    """Return a context for an application whose credential is the identity."""
    return AuthContext(
        TENANT, client_id=app_client_id, managed_identity_client_id=identity_client_id
    )


@needs_trusting_app
def test_the_application_gets_a_token_up_front() -> None:
    auth = app_auth(TRUSTING_APP_CLIENT_ID)

    info = auth.acquire_token_silently([f"{live_cloud().graph}/.default"])

    claims = token_claims(info.token)
    assert (claims.get("appid") or claims.get("azp")) == TRUSTING_APP_CLIENT_ID
    assert claims.get("tid") == live_tenant().id


@needs_trusting_app
@needs_keyvault
async def test_the_application_reads_a_vault_secret() -> None:
    async with KeyVaultClient(app_auth(TRUSTING_APP_CLIENT_ID), KEYVAULT_URL) as vault:
        value = await vault.get_secret(KEYVAULT_SECRET_NAME)
    has_value = bool(value)
    assert has_value, f"the secret {KEYVAULT_SECRET_NAME!r} came back empty"


@needs_trusting_app
async def test_graph_accepts_the_applications_token() -> None:
    """Graph takes the token as valid: 200 with a role, 403 for insufficient privileges without.

    Anything else -- a token for the wrong audience, the wrong cloud's host, a rejected
    signature -- is a different status or code, and fails.
    """
    async with GraphClient(app_auth(TRUSTING_APP_CLIENT_ID)) as graph:
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


@needs_no_federation_app
def test_an_application_that_does_not_trust_the_identity_is_refused_with_entras_reason() -> None:
    auth = app_auth(NO_FEDERATION_APP_CLIENT_ID)
    started = time.monotonic()

    with pytest.raises(AuthError) as info:
        auth.acquire_token_silently([f"{live_cloud().graph}/.default"])

    assert time.monotonic() - started < REFUSAL_SECONDS
    assert info.value.error_codes & NO_MATCHING_FEDERATED_CREDENTIAL, str(info.value)
    assert IDENTITY_CLIENT_ID in str(info.value)
    assert NO_FEDERATION_APP_CLIENT_ID in str(info.value)
    assert not isinstance(info.value, ManagedIdentityUnavailable)


@needs_managed_identity
def test_an_identity_the_host_does_not_have_is_refused_at_once() -> None:
    made_up = str(uuid.uuid4())
    # Refused by the host's endpoint, so the application's id is never sent anywhere.
    auth = app_auth(str(uuid.uuid4()), identity_client_id=made_up)
    started = time.monotonic()

    with pytest.raises(AuthError) as info:
        auth.acquire_token_silently([f"{live_cloud().graph}/.default"])

    assert time.monotonic() - started < REFUSAL_SECONDS
    assert made_up in str(info.value)
    assert "refused" in str(info.value)
    assert not isinstance(info.value, ManagedIdentityUnavailable)
