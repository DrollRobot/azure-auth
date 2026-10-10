"""The Key Vault client against a real vault: reading secrets, asynchronously and blocking.

The secret's value is never printed. pytest shows the operands of a failed comparison, so
every comparison with the value is made first and only its outcome asserted.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets.aio import SecretClient

from azure_auth import AuthContext
from azure_auth.clients.keyvault import KeyVaultClient
from azure_auth.sync.keyvault import KeyVaultClient as BlockingKeyVaultClient
from tests.live.support import (
    KEYVAULT_SECRET_NAME,
    KEYVAULT_URL,
    live_user_auth,
    needs_keyvault,
    needs_user,
    sign_in_to_vault,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.live,
    pytest.mark.anyio,
    needs_user,
    needs_keyvault,
]


async def test_a_secret_is_read_by_name_and_by_version(user_auth: AuthContext) -> None:
    """The client reads a secret's latest value, and the same value by its version.

    The Azure SDK's own client, given ``auth.aio`` as the guide tells callers to for anything
    the wrapper does not cover, is the witness: it supplies the value and the version id the
    wrapper is checked against.
    """
    sign_in_to_vault(user_auth)
    async with SecretClient(KEYVAULT_URL, user_auth.aio) as sdk:
        expected = await sdk.get_secret(KEYVAULT_SECRET_NAME)
    has_value = bool(expected.value)
    assert has_value, f"the secret {KEYVAULT_SECRET_NAME!r} is empty; give it a throwaway value"
    assert expected.properties.version

    async with KeyVaultClient(user_auth, KEYVAULT_URL) as vault:
        latest = await vault.get_secret(KEYVAULT_SECRET_NAME)
        pinned = await vault.get_secret(KEYVAULT_SECRET_NAME, expected.properties.version)
    latest_matches = latest == expected.value
    pinned_matches = pinned == expected.value
    assert latest_matches, "the latest value differs from the one the SDK read"
    assert pinned_matches, "the value read by version differs from the one the SDK read"


async def test_a_missing_secret_is_not_found(user_auth: AuthContext) -> None:
    """A name the vault does not hold raises the SDK's not-found error, as documented."""
    sign_in_to_vault(user_auth)
    async with KeyVaultClient(user_auth, KEYVAULT_URL) as vault:
        with pytest.raises(ResourceNotFoundError):
            await vault.get_secret(f"azure-auth-missing-{uuid.uuid4().hex}")


def test_the_blocking_client_reads_a_secret(cache_path: Path) -> None:
    """The generated blocking client reads the secret the asynchronous one does.

    It hands the SDK ``auth`` itself rather than ``auth.aio``, so it is a path of its own
    through the Azure SDK credential protocol.
    """
    auth = live_user_auth(cache_path)
    sign_in_to_vault(auth)
    with BlockingKeyVaultClient(auth, KEYVAULT_URL) as vault:
        value = vault.get_secret(KEYVAULT_SECRET_NAME)
    has_value = bool(value)
    assert has_value, f"the secret {KEYVAULT_SECRET_NAME!r} came back empty"
