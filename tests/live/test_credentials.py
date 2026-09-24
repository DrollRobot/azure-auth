"""App-only sign-in with a certificate from the Windows store, against the real token endpoint."""

from __future__ import annotations

import pytest

from azure_auth import AuthContext, GraphClient
from tests.live.support import APP_CLIENT_ID, TENANT, THUMBPRINT, needs_app

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_app
async def test_app_flow_with_a_store_certificate() -> None:
    auth = AuthContext(TENANT, client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT)
    async with GraphClient(auth) as graph:
        organization = await graph.get_all("/organization")
    assert organization
    # Which algorithm Entra ID accepted for this key is worth knowing; see plan section 4.
    print(f"client assertion algorithm in use: {auth._credential.algorithm}")  # type: ignore[union-attr]
