"""Application credentials and the client assertion used for certificate authentication.

Four kinds of credential are supported for app flows:

* a client secret,
* a certificate and private key supplied as PEM or PFX (MSAL signs the assertion),
* a certificate in the Windows certificate store whose key cannot be exported (this package
  signs the assertion through CNG, see :mod:`azure_auth.auth.cng`),
* a user-assigned managed identity of the Azure host, whose token is the assertion.

Secrets, key material and the identity's tokens are only ever held in memory.
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
from typing import TYPE_CHECKING, Any, ClassVar

import msal
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import pkcs12

from azure_auth.auth import cng
from azure_auth.auth import managed_identity as host_identity
from azure_auth.auth.errors import CertificateUnavailable

if TYPE_CHECKING:
    from azure_auth.clouds import Cloud

ASSERTION_LIFETIME_SECONDS = 600

# PS256 is RSASSA-PSS with SHA-256 and a salt as long as the digest (RFC 7518, section 3.5).
_PS256_PADDING = PSS(mgf=MGF1(hashes.SHA256()), salt_length=32)


class _InvalidPssSignature(Exception):
    """The key storage provider signed with PSS, but the signature does not verify as PS256."""


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

    def msal_client_credential(self, *, client_id: str, token_endpoint: str, cloud: Cloud) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        Args:
            client_id: Application (client) id. Unused for secrets.
            token_endpoint: Tenant-specific token endpoint. Unused for secrets.
            cloud: The tenant's cloud. Unused for secrets.

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

    def msal_client_credential(self, *, client_id: str, token_endpoint: str, cloud: Cloud) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        MSAL derives the SHA-256 thumbprint from ``public_certificate`` and signs the
        assertion itself.

        Args:
            client_id: Application (client) id. Unused; MSAL builds the assertion.
            token_endpoint: Tenant-specific token endpoint. Unused; MSAL builds the assertion.
            cloud: The tenant's cloud. Unused.

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

    Assertions are signed PS256, because Microsoft documents PS256 together with the
    ``x5t#S256`` header. The credential switches to RS256, and stays there, when the key
    storage provider refuses PSS padding or returns a PSS signature that is not PS256. Both
    are detected here, before anything is sent. An error from Entra ID is never retried with
    the other algorithm: AADSTS700027 also means the certificate is not registered on the
    application, so a retry would mistake a configuration error for an algorithm problem.
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
        self._public_key: rsa.RSAPublicKey | None = None

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

    def _load_certificate(self) -> tuple[bytes, rsa.RSAPublicKey]:
        """Read the certificate once, keeping its public key for checking signatures.

        Returns:
            The DER-encoded certificate and its RSA public key.

        Raises:
            CertificateUnavailable: If the certificate cannot be found or holds no RSA key.
        """
        if self._certificate_der is None or self._public_key is None:
            der = cng.load_certificate_der(self.thumbprint, self.store_location)
            public_key = x509.load_der_x509_certificate(der).public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise CertificateUnavailable(
                    f"certificate {self.thumbprint} does not hold an RSA key"
                )
            self._certificate_der, self._public_key = der, public_key
        return self._certificate_der, self._public_key

    def _sign(self, digest: bytes, padding: cng.Padding) -> bytes:
        """Sign a digest, and check that a PSS signature really is PS256.

        A TPM 2.0 that is not in FIPS mode signs PSS with the longest salt the key allows,
        whatever salt length was requested, and the key storage provider still reports
        success. PS256 requires a salt as long as the digest, so Entra ID would reject the
        assertion. Verifying against the certificate catches that before it is sent. PKCS #1
        v1.5 has no parameter a provider could get wrong, so RS256 signatures are not checked.

        Args:
            digest: The SHA-256 digest to sign.
            padding: ``pss`` for PS256 or ``pkcs1`` for RS256.

        Returns:
            The raw signature.

        Raises:
            SignatureFailed: If the key storage provider refuses to sign with ``padding``.
            _InvalidPssSignature: If a PSS signature does not verify as PS256.
        """
        signature = cng.sign_digest(
            self.thumbprint, digest, padding=padding, store_location=self.store_location
        )
        if padding == "pss":
            _certificate_der, public_key = self._load_certificate()
            try:
                public_key.verify(signature, digest, _PS256_PADDING, Prehashed(hashes.SHA256()))
            except InvalidSignature:
                raise _InvalidPssSignature from None
        return signature

    def _build(self, client_id: str, token_endpoint: str, padding: cng.Padding) -> str:
        """Build and sign an assertion with one padding.

        The padding is passed in rather than read from the credential, so the ``alg``
        header always matches the signature even if another thread switches to RS256.

        Args:
            client_id: Application (client) id.
            token_endpoint: Tenant-specific token endpoint; becomes the ``aud`` claim.
            padding: ``pss`` for PS256 or ``pkcs1`` for RS256.

        Returns:
            The signed JWT.
        """
        certificate_der, _public_key = self._load_certificate()
        return build_client_assertion(
            client_id=client_id,
            token_endpoint=token_endpoint,
            certificate_der=certificate_der,
            algorithm="PS256" if padding == "pss" else "RS256",
            sign=lambda digest: self._sign(digest, padding),
        )

    def build_assertion(self, *, client_id: str, token_endpoint: str) -> str:
        """Build a fresh client assertion for one tenant.

        The ``alg`` header is part of what gets signed, so when PS256 fails the whole
        assertion is rebuilt as RS256.

        Args:
            client_id: Application (client) id.
            token_endpoint: Tenant-specific token endpoint; becomes the ``aud`` claim.

        Returns:
            The signed JWT.

        Raises:
            CertificateUnavailable: If the certificate cannot be found, holds no RSA key, or
                cannot sign even with PKCS #1 v1.5 padding.
        """
        if self._padding == "pss":
            try:
                return self._build(client_id, token_endpoint, "pss")
            except (cng.SignatureFailed, _InvalidPssSignature):
                self._padding = "pkcs1"
        return self._build(client_id, token_endpoint, "pkcs1")

    def msal_client_credential(self, *, client_id: str, token_endpoint: str, cloud: Cloud) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        The assertion callable is bound to one token endpoint, because the ``aud`` claim is
        tenant specific. MSAL calls it each time it sends a token request.

        Args:
            client_id: Application (client) id.
            token_endpoint: Tenant-specific token endpoint.
            cloud: The tenant's cloud. Unused; the token endpoint names it.

        Returns:
            A dictionary holding the assertion callable.
        """

        def assertion() -> str:
            return self.build_assertion(client_id=client_id, token_endpoint=token_endpoint)

        return {"client_assertion": assertion}


class ManagedIdentityAssertionCredential:
    """A user-assigned managed identity of the Azure host, as an application's credential.

    The application registration has a federated credential that trusts the identity. The
    client assertion is a token the identity gets from the host's identity endpoint for the
    cloud's token exchange audience (:attr:`~azure_auth.Cloud.token_exchange_audience`), and
    Entra ID takes it in place of a secret or a signed certificate assertion. Microsoft allows
    user-assigned identities only, in the application's own tenant.

    The identity's tokens are kept in this credential's own cache, in memory, whatever cache
    the context has: they are a credential, and never reach a disk cache. The identity's token
    serves every resource the application asks for, until it nears expiry; MSAL asks for the
    assertion only when it sends a request to Entra ID, never when its cache answers.

    Attributes:
        identity_client_id: The client id of the user-assigned identity.
        other_tenants: Whether a context may reach tenants other than its own with this
            credential. ``False``: Microsoft supports a multi-tenant application provisioned
            in another tenant reaching it this way, but this package does not yet (user,
            2026-11-05), and a context refuses any tenant but its own. Setting it ``True`` is
            all it takes to add it: :meth:`~azure_auth.AuthContext.get_tenant_context` then
            builds other tenants' contexts as for every other credential, and the assertion,
            tied to no tenant's token endpoint, serves them all.
    """

    other_tenants: ClassVar[bool] = False

    def __init__(self, identity_client_id: str) -> None:
        """Remember which identity to use. Nothing is requested yet.

        Args:
            identity_client_id: The client id (a GUID) of a user-assigned identity assigned
                to the host.
        """
        self.identity_client_id = identity_client_id
        self._client: Any = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        """Describe the credential without its tokens.

        Returns:
            A short description.
        """
        return f"ManagedIdentityAssertionCredential(identity_client_id={self.identity_client_id!r})"

    def _identity(self) -> Any:
        """Return the msal client for the identity, creating it once.

        Returns:
            An ``msal.ManagedIdentityClient`` on a cache of this credential's own.
        """
        with self._lock:
            if self._client is None:
                self._client = host_identity.identity_client(
                    self.identity_client_id, token_cache=msal.TokenCache()
                )
            return self._client

    def assertion(self, audience: str) -> str:
        """Get the identity's token for the token exchange audience.

        Args:
            audience: The cloud's token exchange audience.

        Returns:
            The token, from this credential's cache while it is fresh.

        Raises:
            ManagedIdentityUnavailable: If this host has no identity endpoint.
            NetworkError: If the host's endpoint could not be reached, or did not answer.
            AuthError: If the endpoint refused, such as for an identity not on this host.
        """
        result = host_identity.request_token(
            self._identity(), audience, client_id=self.identity_client_id
        )
        return str(result["access_token"])

    def msal_client_credential(self, *, client_id: str, token_endpoint: str, cloud: Cloud) -> Any:
        """Return the value MSAL expects as ``client_credential``.

        MSAL calls the assertion callable each time it sends a token request. An error the
        callable raises comes out of MSAL's token request unchanged.

        Args:
            client_id: Application (client) id. Unused; the identity's token names nobody.
            token_endpoint: Tenant-specific token endpoint. Unused; the assertion's audience
                is the cloud's, not a tenant's.
            cloud: The tenant's cloud, whose token exchange audience the token is for.

        Returns:
            A dictionary holding the assertion callable.
        """
        audience = cloud.token_exchange_audience

        def assertion() -> str:
            return self.assertion(audience)

        return {"client_assertion": assertion}


AppCredential = (
    SecretCredential
    | PemCertificateCredential
    | CertStoreCredential
    | ManagedIdentityAssertionCredential
)
