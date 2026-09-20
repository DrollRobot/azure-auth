"""Unit tests for the Key Vault wrapper, with the Azure SDK clients replaced by fakes."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from azure_auth import AuthContext
from azure_auth.clients.keyvault import KeyVaultClient
from tests.fakes import FakeMsal

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

VAULT = "https://contoso.vault.azure.net"


class FakeSdkClient:
    """Stands in for SecretClient, CertificateClient and CryptographyClient."""

    created: list[FakeSdkClient]

    def __init__(self, target: str, credential: Any) -> None:
        self.target = target
        self.credential = credential
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False
        FakeSdkClient.created.append(self)

    async def get_secret(self, name: str, version: str | None) -> Any:
        self.calls.append(("get_secret", name, version))
        return SimpleNamespace(value=None if name == "empty" else f"value-of-{name}")

    async def get_certificate(self, name: str) -> Any:
        self.calls.append(("get_certificate", name))
        return SimpleNamespace(cer=None if name == "empty" else bytearray(b"latest"))

    async def get_certificate_version(self, name: str, version: str) -> Any:
        self.calls.append(("get_certificate_version", name, version))
        return SimpleNamespace(cer=bytearray(b"pinned"))

    async def sign(self, algorithm: Any, digest: bytes) -> Any:
        self.calls.append(("sign", algorithm.value, digest))
        return SimpleNamespace(signature=bytearray(b"signature"))

    async def verify(self, algorithm: Any, digest: bytes, signature: bytes) -> Any:
        self.calls.append(("verify", algorithm.value, digest, signature))
        return SimpleNamespace(is_valid=signature == b"signature")

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch, fake_msal: FakeMsal) -> KeyVaultClient:
    FakeSdkClient.created = []
    for name in ("SecretClient", "CertificateClient", "CryptographyClient"):
        monkeypatch.setattr(f"azure_auth.clients.keyvault.{name}", FakeSdkClient)
    return KeyVaultClient(AuthContext("tenant", username="admin@contoso.com"), f"{VAULT}/")


async def test_sdk_clients_get_the_vault_and_the_async_credential(vault: KeyVaultClient) -> None:
    secrets, certificates = FakeSdkClient.created
    assert vault.vault_url == secrets.target == certificates.target == VAULT
    assert secrets.credential.sync.tenant_id == "tenant"


async def test_get_secret(vault: KeyVaultClient) -> None:
    assert await vault.get_secret("db-password") == "value-of-db-password"
    assert await vault.get_secret("db-password", "v2") == "value-of-db-password"
    assert FakeSdkClient.created[0].calls == [
        ("get_secret", "db-password", None),
        ("get_secret", "db-password", "v2"),
    ]
    with pytest.raises(ValueError, match="has no value"):
        await vault.get_secret("empty")


async def test_get_certificate(vault: KeyVaultClient) -> None:
    assert await vault.get_certificate("signing") == b"latest"
    assert await vault.get_certificate("signing", "v1") == b"pinned"
    with pytest.raises(ValueError, match="has no content"):
        await vault.get_certificate("empty")


async def test_sign_and_verify_use_one_client_per_key(vault: KeyVaultClient) -> None:
    signature = await vault.sign("signing", "PS256", b"digest")
    assert signature == b"signature"
    assert await vault.verify("signing", "PS256", b"digest", signature) is True
    assert await vault.verify("signing", "RS256", b"digest", b"forged", version="v1") is False

    crypto = FakeSdkClient.created[2:]
    assert [client.target for client in crypto] == [
        f"{VAULT}/keys/signing",
        f"{VAULT}/keys/signing/v1",
    ]
    assert crypto[0].calls == [
        ("sign", "PS256", b"digest"),
        ("verify", "PS256", b"digest", b"signature"),
    ]


async def test_closing_closes_every_sdk_client(vault: KeyVaultClient) -> None:
    async with vault:
        await vault.sign("signing", "RS256", b"digest")
    assert [client.closed for client in FakeSdkClient.created] == [True, True, True]
