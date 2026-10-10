"""No secret reaches a log at DEBUG, against the real services.

The integration tests (``tests/integration/test_no_secrets_in_logs.py``) cover the code paths
against fakes. These add what only real services and connections log: the network libraries
under MSAL, the Azure SDK and ``httpx``, and whatever Entra ID and the services send back.

Each test captures every record of every logger at DEBUG (:mod:`tests.logs`), then looks for
each secret it handled. No secret is printed: a failure names the kind and where it was logged.
"""

from __future__ import annotations

from pathlib import Path

import msal
import pytest

from azure_auth import AuthContext, GraphClient
from azure_auth.auth.credentials import CertStoreCredential
from azure_auth.clients.keyvault import KeyVaultClient
from azure_auth.sync import GraphClient as BlockingGraphClient
from azure_auth.sync.keyvault import KeyVaultClient as BlockingKeyVaultClient
from tests.live.support import (
    APP_CLIENT_ID,
    KEYVAULT_SECRET_NAME,
    KEYVAULT_URL,
    TENANT,
    THUMBPRINT,
    ensure_sign_in,
    live_user_auth,
    needs_app,
    needs_graph,
    needs_keyvault,
    needs_user,
    sign_in_to_vault,
)
from tests.logs import all_logs_at_debug, assert_no_secrets

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.acceptance, pytest.mark.anyio]


def held_tokens(
    auth: AuthContext, into: dict[str, list[str]] | None = None
) -> dict[str, list[str]]:
    """Collect every access and refresh token the context holds, in its cache and in memory.

    Args:
        auth: The context.
        into: Tokens collected earlier, to add to. A refreshed token replaces the old one in
            the cache, so a test that refreshes collects before and after.

    Returns:
        The tokens, by kind.
    """
    kinds = msal.TokenCache.CredentialType
    tokens = into if into is not None else {"access token": [], "refresh token": []}
    tokens["access token"] += [item["secret"] for item in auth._cache.search(kinds.ACCESS_TOKEN)]
    tokens["access token"] += [info.token for info in auth._tokens.values()]
    tokens["refresh token"] += [item["secret"] for item in auth._cache.search(kinds.REFRESH_TOKEN)]
    return tokens


@needs_user
@needs_keyvault
async def test_reading_a_vault_secret_logs_no_secret(cache_path: Path) -> None:
    """The asynchronous and the blocking client each read the secret twice.

    The SDK keeps the vault's sign-in from its first challenge, so a second read sends the
    token at once, which takes another path through the SDK's logging.
    """
    with all_logs_at_debug() as records:
        auth = live_user_auth(cache_path)
        sign_in_to_vault(auth)
        async with KeyVaultClient(auth, KEYVAULT_URL) as vault:
            values = [
                await vault.get_secret(KEYVAULT_SECRET_NAME),
                await vault.get_secret(KEYVAULT_SECRET_NAME),
            ]
        with BlockingKeyVaultClient(auth, KEYVAULT_URL) as blocking:
            values += [
                blocking.get_secret(KEYVAULT_SECRET_NAME),
                blocking.get_secret(KEYVAULT_SECRET_NAME),
            ]
    one_value = len(set(values)) == 1
    assert one_value, "the four reads did not all give the same value"
    assert_no_secrets(records, {"Key Vault secret value": values[:1], **held_tokens(auth)})


@needs_user
@needs_graph
async def test_graph_requests_and_a_token_refresh_log_no_token(cache_path: Path) -> None:
    """Requests from both clients, and a refresh token redeemed for a new access token."""
    with all_logs_at_debug() as records:
        auth = live_user_auth(cache_path)
        async with GraphClient(auth) as graph:
            ensure_sign_in(graph)
            await graph.get("/me")
            tokens = held_tokens(auth)
            await auth.aio.acquire_token(
                graph.scopes, client_id=graph.client_id, force_refresh=True
            )
            await graph.get("/me")
        with BlockingGraphClient(auth) as blocking:
            blocking.get("/me")
    assert_no_secrets(records, held_tokens(auth, into=tokens))


@needs_app
async def test_a_store_certificate_sign_in_logs_no_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client assertion signed with the store certificate is not logged, nor the token."""
    assertions: list[str] = []
    build = CertStoreCredential.build_assertion

    def recorded(self: CertStoreCredential, *, client_id: str, token_endpoint: str) -> str:
        assertion = build(self, client_id=client_id, token_endpoint=token_endpoint)
        assertions.append(assertion)
        return assertion

    monkeypatch.setattr(CertStoreCredential, "build_assertion", recorded)
    with all_logs_at_debug() as records:
        auth = AuthContext(TENANT, client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT)
        async with GraphClient(auth) as graph:
            await graph.get_all("/organization")
    assert assertions, "no assertion was built, so the sign-in did not use the certificate"
    assert_no_secrets(records, {"client assertion": assertions, **held_tokens(auth)})
