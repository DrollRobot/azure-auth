"""Application credentials and the client assertion used for certificate authentication.

Three kinds of credential are supported for app flows:

* a client secret,
* a certificate and private key supplied as PEM or PFX (MSAL signs the assertion),
* a certificate in the Windows certificate store whose key cannot be exported (this package
  signs the assertion through CNG, see :mod:`azure_auth.auth.cng`).

Secrets and key material are only ever held in memory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from azure_auth.auth import cng
from azure_auth.auth.errors import CertificateUnavailable

ASSERTION_LIFETIME_SECONDS = 600


def _b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url, as JWTs require.

    Args:
        data: Bytes to encode.

    Returns:
        The encoded text.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_client_assertion(
    *,
    client_id: str,
    token_endpoint: str,
    certificate_der: bytes,
    algorithm: str,
    sign: Callable[[bytes], bytes],
) -> str:
    """Build the signed JWT that proves possession of a certificate's private key.

    Args:
        client_id: Application (client) id; becomes ``iss`` and ``sub``.
        token_endpoint: Tenant-specific token endpoint; becomes ``aud``.
        certificate_der: DER encoding of the certificate; hashed into ``x5t#S256``.
        algorithm: ``PS256`` or ``RS256``; must match what ``sign`` produces.
        sign: Callable that signs a SHA-256 digest and returns the raw signature.

    Returns:
        The compact-serialised JWT.
    """
    now = int(time.time())
    header = {
        "alg": algorithm,
        "typ": "JWT",
        "x5t#S256": _b64url(hashlib.sha256(certificate_der).digest()),
    }
    claims = {
        "aud": token_endpoint,
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + ASSERTION_LIFETIME_SECONDS,
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode("utf-8"))
        for part in (header, claims)
    )
    signature = sign(hashlib.sha256(signing_input.encode("ascii")).digest())
    return f"{signing_input}.{_b64url(signature)}"


@dataclass(frozen=True)
class SecretCredential:
    """A client secret.

    Attributes:
        secret: The secret value.
    """

    secret: str = field(repr=False)

    def msal_client_credential(self, *, client_id: str, token_endpoint: str) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        Args:
            client_id: Application (client) id. Unused for secrets.
            token_endpoint: Tenant-specific token endpoint. Unused for secrets.

        Returns:
            The client secret.
        """
        return self.secret


@dataclass(frozen=True)
class PemCertificateCredential:
    """A certificate with an exportable private key, held as PEM text.

    Attributes:
        certificate_pem: The certificate in PEM format.
        private_key_pem: The private key in PEM format.
        passphrase: Passphrase protecting ``private_key_pem``, if it is encrypted.
    """

    certificate_pem: str
    private_key_pem: str = field(repr=False)
    passphrase: str | None = field(default=None, repr=False)

    @classmethod
    def from_pfx(cls, pfx: bytes | str | Path, password: str | None) -> PemCertificateCredential:
        """Build the credential from a PKCS#12 (PFX) archive.

        Args:
            pfx: The archive bytes, or a path to the file.
            password: Password protecting the archive, if any.

        Returns:
            The credential, with certificate and key converted to PEM in memory.

        Raises:
            CertificateUnavailable: If the archive cannot be read or lacks a key or
                certificate.
        """
        data = pfx if isinstance(pfx, bytes) else Path(pfx).read_bytes()
        try:
            key, certificate, _chain = pkcs12.load_key_and_certificates(
                data, password.encode("utf-8") if password else None
            )
        except ValueError as exc:
            raise CertificateUnavailable(f"Cannot read the PFX archive: {exc}") from exc
        if key is None or certificate is None:
            raise CertificateUnavailable("The PFX archive has no private key or no certificate")
        return cls(
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            private_key_pem=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
        )

    def msal_client_credential(self, *, client_id: str, token_endpoint: str) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        MSAL derives the SHA-256 thumbprint from ``public_certificate`` and signs the
        assertion itself.

        Args:
            client_id: Application (client) id. Unused; MSAL builds the assertion.
            token_endpoint: Tenant-specific token endpoint. Unused; MSAL builds the assertion.

        Returns:
            The credential dictionary.
        """
        credential = {
            "private_key": self.private_key_pem,
            "public_certificate": self.certificate_pem,
        }
        if self.passphrase:
            credential["passphrase"] = self.passphrase
        return credential


class CertStoreCredential:
    """A certificate in the Windows certificate store with a non-exportable key.

    Assertions are signed PS256 first, because Microsoft documents PS256 together with the
    ``x5t#S256`` header. When the key storage provider refuses PSS padding, or Entra ID
    rejects the PSS signature, the credential switches to RS256 and stays there.
    """

    def __init__(self, thumbprint: str, store_location: cng.StoreLocation = "CurrentUser") -> None:
        """Remember which certificate to use. Nothing is opened yet.

        Args:
            thumbprint: SHA-1 thumbprint of the certificate.
            store_location: ``CurrentUser`` or ``LocalMachine``; the ``My`` store is used.
        """
        self.thumbprint = cng.normalise_thumbprint(thumbprint)
        self.store_location: cng.StoreLocation = store_location
        self._padding: cng.Padding = "pss"
        self._certificate_der: bytes | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        """Describe the credential without touching the key.

        Returns:
            A short description.
        """
        return (
            f"CertStoreCredential(thumbprint={self.thumbprint!r}, "
            f"store_location={self.store_location!r}, algorithm={self.algorithm!r})"
        )

    @property
    def algorithm(self) -> str:
        """The JWT algorithm currently in use: ``PS256`` or ``RS256``."""
        return "PS256" if self._padding == "pss" else "RS256"

    def downgrade_to_rs256(self) -> bool:
        """Switch from PS256 to RS256.

        Returns:
            ``True`` if the algorithm changed, ``False`` if RS256 was already in use.
        """
        with self._lock:
            if self._padding == "pkcs1":
                return False
            self._padding = "pkcs1"
            return True

    def _sign(self, digest: bytes) -> bytes:
        """Sign a digest with the padding currently in use.

        Args:
            digest: The SHA-256 digest to sign.

        Returns:
            The raw signature.
        """
        return cng.sign_digest(
            self.thumbprint, digest, padding=self._padding, store_location=self.store_location
        )

    def build_assertion(self, *, client_id: str, token_endpoint: str) -> str:
        """Build a fresh client assertion for one tenant.

        The ``alg`` header is part of what gets signed, so when the key storage provider
        refuses PSS padding the whole assertion is rebuilt as RS256.

        Args:
            client_id: Application (client) id.
            token_endpoint: Tenant-specific token endpoint; becomes the ``aud`` claim.

        Returns:
            The signed JWT.
        """
        if self._certificate_der is None:
            self._certificate_der = cng.load_certificate_der(self.thumbprint, self.store_location)
        try:
            return build_client_assertion(
                client_id=client_id,
                token_endpoint=token_endpoint,
                certificate_der=self._certificate_der,
                algorithm=self.algorithm,
                sign=self._sign,
            )
        except cng.SignatureFailed:
            if not self.downgrade_to_rs256():
                raise
        return build_client_assertion(
            client_id=client_id,
            token_endpoint=token_endpoint,
            certificate_der=self._certificate_der,
            algorithm=self.algorithm,
            sign=self._sign,
        )

    def msal_client_credential(self, *, client_id: str, token_endpoint: str) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        The assertion callable is bound to one token endpoint, because the ``aud`` claim is
        tenant specific. MSAL calls it each time it sends a token request.

        Args:
            client_id: Application (client) id.
            token_endpoint: Tenant-specific token endpoint.

        Returns:
            A dictionary holding the assertion callable.
        """

        def assertion() -> str:
            return self.build_assertion(client_id=client_id, token_endpoint=token_endpoint)

        return {"client_assertion": assertion}


AppCredential = SecretCredential | PemCertificateCredential | CertStoreCredential
