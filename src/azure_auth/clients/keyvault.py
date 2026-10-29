"""Thin wrapper over the Azure Key Vault SDK clients.

The Azure SDK does the work; this wrapper only wires an :class:`~azure_auth.AuthContext` into
it and exposes the handful of calls that authentication code tends to need. Its calls raise
:class:`~azure_auth.KeyVaultError` and :class:`~azure_auth.NetworkError` in place of the
Azure SDK's exceptions. For anything else, use the SDK clients directly with
``credential=auth.aio``; they raise the Azure SDK's own exceptions.

Needs the ``keyvault`` extra: ``pip install azure-auth[keyvault]``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from types import TracebackType
from typing import Any, Self

from azure.core.exceptions import (
    AzureError,
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)

from azure_auth.auth.context import AuthContext
from azure_auth.clients.errors import KeyVaultError
from azure_auth.errors import network_error

try:
    from azure.keyvault.certificates.aio import CertificateClient
    from azure.keyvault.keys.crypto import SignatureAlgorithm
    from azure.keyvault.keys.crypto.aio import CryptographyClient
    from azure.keyvault.secrets.aio import SecretClient
except ImportError as exc:  # pragma: no cover (exercised only without the extra)
    raise ImportError(
        "KeyVaultClient needs the 'keyvault' extra: pip install azure-auth[keyvault]"
    ) from exc


def _vault_error(error: HttpResponseError) -> KeyVaultError:
    """Translate the Azure SDK's exception for an error status from the vault.

    Args:
        error: The exception, carrying the vault's response.

    Returns:
        The exception to raise, with the status, the vault's error code, its request id and
        the decoded response body.
    """
    # The SDK types the response as a minimal protocol; every response it raises with has
    # headers, and a request with a method and a URL.
    response: Any = error.response
    status = error.status_code or 0
    code = error.error.code if error.error else None
    detail = error.error.message if error.error else error.reason
    request_id = body = None
    summary = str(status)
    if response is not None:
        summary = f"{response.request.method} {response.request.url} -> {status}"
        request_id = response.headers.get("x-ms-request-id")
        try:
            body = response.text()
        except AzureError:  # the body was never read
            body = None
        else:
            with suppress(ValueError):
                body = json.loads(body)
    message = ": ".join(str(part) for part in (code, detail) if part)
    return KeyVaultError(
        f"{summary} {message}".rstrip(),
        status=status,
        code=code,
        request_id=request_id,
        body=body,
    )


@contextmanager
def _translated(vault_url: str) -> Iterator[None]:
    """Raise this package's exceptions in place of the Azure SDK's, for the calls inside.

    Args:
        vault_url: URL of the vault, for the message of a network failure.

    Yields:
        Nothing; the calls run in the ``with`` block.

    Raises:
        KeyVaultError: If the vault answered with an error status.
        NetworkError: If the vault could not be reached, or did not answer.
    """
    try:
        yield
    except HttpResponseError as exc:
        raise _vault_error(exc) from exc
    except (ServiceRequestError, ServiceResponseError) as exc:
        raise network_error(f"A request to {vault_url}", exc) from exc


class KeyVaultClient:
    """Secrets, certificates and signing keys of one vault.

    Example:
        >>> vault = KeyVaultClient(auth, "https://contoso.vault.azure.net")  # doctest: +SKIP
        >>> password = await vault.get_secret("service-password")  # doctest: +SKIP
    """

    def __init__(self, auth: AuthContext, vault_url: str) -> None:
        """Create the client. No network call is made.

        Args:
            auth: The authentication context to get tokens from. User flows use the Azure
                PowerShell client id unless the context names another.
            vault_url: URL of the vault, such as ``https://contoso.vault.azure.net``.
        """
        self._vault_url = vault_url.rstrip("/")
        self._credential = auth.aio
        self._secrets = SecretClient(self._vault_url, self._credential)
        self._certificates = CertificateClient(self._vault_url, self._credential)
        self._crypto: dict[str, CryptographyClient] = {}

    @property
    def vault_url(self) -> str:
        """URL of the vault."""
        return self._vault_url

    async def get_secret(self, name: str, version: str | None = None) -> str:
        """Read a secret value.

        Args:
            name: Name of the secret.
            version: Version to read. Defaults to the latest.

        Returns:
            The secret value.

        Raises:
            ValueError: If the secret has no value.
            KeyVaultError: If the vault refuses, such as with status 404 for no such secret or
                no such version of it.
            NetworkError: If the vault could not be reached.
        """
        with _translated(self._vault_url):
            secret = await self._secrets.get_secret(name, version)
        if secret.value is None:
            raise ValueError(f"Secret {name!r} has no value")
        return secret.value

    async def get_certificate(self, name: str, version: str | None = None) -> bytes:
        """Read the public part of a certificate.

        Args:
            name: Name of the certificate.
            version: Version to read. Defaults to the latest.

        Returns:
            The DER-encoded certificate, without its private key.

        Raises:
            ValueError: If the certificate has no content.
            KeyVaultError: If the vault refuses, such as with status 404 for no such
                certificate.
            NetworkError: If the vault could not be reached.
        """
        with _translated(self._vault_url):
            if version:
                certificate = await self._certificates.get_certificate_version(name, version)
            else:
                certificate = await self._certificates.get_certificate(name)
        if certificate.cer is None:
            raise ValueError(f"Certificate {name!r} has no content")
        return bytes(certificate.cer)

    def _crypto_client(self, key_name: str, version: str | None) -> CryptographyClient:
        """Return the cryptography client for one key.

        Args:
            key_name: Name of the key.
            version: Key version, or ``None`` for the latest.

        Returns:
            A memoised ``CryptographyClient``.
        """
        key_id = f"{self._vault_url}/keys/{key_name}" + (f"/{version}" if version else "")
        if key_id not in self._crypto:
            self._crypto[key_id] = CryptographyClient(key_id, self._credential)
        return self._crypto[key_id]

    async def sign(
        self,
        key_name: str,
        algorithm: SignatureAlgorithm | str,
        digest: bytes,
        *,
        version: str | None = None,
    ) -> bytes:
        """Sign a digest with a key that stays in the vault.

        Args:
            key_name: Name of the key.
            algorithm: Signature algorithm, such as ``PS256`` or ``RS256``.
            digest: The digest to sign, hashed to match ``algorithm``.
            version: Key version. Defaults to the latest.

        Returns:
            The signature.

        Raises:
            KeyVaultError: If the vault refuses, such as with status 404 for no such key.
            NetworkError: If the vault could not be reached.
        """
        client = self._crypto_client(key_name, version)
        with _translated(self._vault_url):
            result = await client.sign(SignatureAlgorithm(algorithm), digest)
        return bytes(result.signature)

    async def verify(
        self,
        key_name: str,
        algorithm: SignatureAlgorithm | str,
        digest: bytes,
        signature: bytes,
        *,
        version: str | None = None,
    ) -> bool:
        """Verify a signature with a key in the vault.

        Args:
            key_name: Name of the key.
            algorithm: Signature algorithm, such as ``PS256`` or ``RS256``.
            digest: The digest that was signed.
            signature: The signature to check.
            version: Key version. Defaults to the latest.

        Returns:
            Whether the signature is valid.

        Raises:
            KeyVaultError: If the vault refuses, such as with status 404 for no such key.
            NetworkError: If the vault could not be reached.
        """
        client = self._crypto_client(key_name, version)
        with _translated(self._vault_url):
            result = await client.verify(SignatureAlgorithm(algorithm), digest, signature)
        return bool(result.is_valid)

    async def aclose(self) -> None:
        """Close the underlying SDK clients."""
        await self._secrets.close()
        await self._certificates.close()
        for client in self._crypto.values():
            await client.close()

    async def __aenter__(self) -> Self:
        """Enter the context manager.

        Returns:
            This client.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        """Close the client when leaving the context manager."""
        await self.aclose()
