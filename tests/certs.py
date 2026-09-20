"""Throwaway certificates and keys generated at test time.

Nothing here is a real credential: every key is created in memory for one test run.
"""

from __future__ import annotations

import base64
import datetime
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


@dataclass
class TestCertificate:
    """A self-signed certificate with its private key."""

    __test__ = False  # not a test class, despite the name

    key: rsa.RSAPrivateKey
    certificate: x509.Certificate

    @property
    def der(self) -> bytes:
        """DER encoding of the certificate."""
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def certificate_pem(self) -> str:
        """PEM encoding of the certificate."""
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @property
    def private_key_pem(self) -> str:
        """Unencrypted PKCS#8 PEM encoding of the private key."""
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    def pfx(self, password: str | None = None) -> bytes:
        """PKCS#12 archive holding the key and the certificate."""
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        return pkcs12.serialize_key_and_certificates(
            b"test", self.key, self.certificate, None, encryption
        )

    def sign(self, digest_padding: str) -> Any:
        """Return a callable that signs a SHA-256 digest like the CNG signer does."""
        from cryptography.hazmat.primitives.asymmetric import utils

        def signer(digest: bytes) -> bytes:
            return self.key.sign(digest, _padding(digest_padding), utils.Prehashed(hashes.SHA256()))

        return signer


def _padding(name: str) -> padding.AsymmetricPadding:
    if name == "pss":
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    return padding.PKCS1v15()


def make_certificate(common_name: str = "azure-auth test") -> TestCertificate:
    """Create a self-signed RSA certificate valid for one day."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return TestCertificate(key, certificate)


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a compact JWT into header, claims, signing input and signature."""
    header_b64, claims_b64, signature_b64 = token.split(".")

    def decode(part: str) -> bytes:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

    return (
        json.loads(decode(header_b64)),
        json.loads(decode(claims_b64)),
        f"{header_b64}.{claims_b64}".encode("ascii"),
        decode(signature_b64),
    )


def verify_signature(
    public_key: rsa.RSAPublicKey, signing_input: bytes, signature: bytes, algorithm: str
) -> None:
    """Verify a JWT signature; raises ``InvalidSignature`` when it does not match."""
    public_key.verify(
        signature,
        signing_input,
        _padding("pss" if algorithm == "PS256" else "pkcs1"),
        hashes.SHA256(),
    )
