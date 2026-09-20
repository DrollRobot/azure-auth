"""Integration tests for the Windows certificate store signer.

These create a real self-signed certificate with a non-exportable private key in
``Cert:\\CurrentUser\\My`` and delete it afterwards, so they are ``destructive_local``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from azure_auth import CertificateUnavailable
from azure_auth.auth import cng
from azure_auth.auth.credentials import CertStoreCredential
from tests.certs import decode_jwt, verify_signature

pytestmark = [
    pytest.mark.integration,
    pytest.mark.destructive_local,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows certificate store only"),
]

_CREATE = (
    "$c = New-SelfSignedCertificate -Subject 'CN=azure-auth signer test' "
    "-CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy NonExportable "
    "-KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 "
    "-Provider 'Microsoft Software Key Storage Provider' -NotAfter (Get-Date).AddDays(1); "
    "$c.Thumbprint"
)


def _powershell(command: str) -> str:
    # Windows PowerShell cannot load its Security/PKI modules when it inherits the module
    # path of PowerShell 7, which is what happens when pytest is started from pwsh.
    environment = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(  # noqa: S603 (fixed argv list, no shell)
        [  # noqa: S607 (powershell.exe is resolved from the system path on purpose)
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$ErrorActionPreference = 'Stop'; {command}",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
    )
    return result.stdout.strip()


@pytest.fixture(scope="module")
def thumbprint() -> Iterator[str]:
    value = _powershell(_CREATE)
    assert len(value) == 40, f"certificate creation returned {value!r}"
    try:
        yield value
    finally:
        _powershell(f"Remove-Item -Path Cert:\\CurrentUser\\My\\{value} -DeleteKey")


@pytest.fixture(scope="module")
def public_key(thumbprint: str) -> rsa.RSAPublicKey:
    der = cng.load_certificate_der(thumbprint)
    assert hashlib.sha1(der).hexdigest().upper() == thumbprint  # noqa: S324 (thumbprint, not security)
    key = x509.load_der_x509_certificate(der).public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    return key


@pytest.mark.parametrize(("padding", "algorithm"), [("pss", "PS256"), ("pkcs1", "RS256")])
def test_signature_verifies_with_the_certificate(
    thumbprint: str, public_key: rsa.RSAPublicKey, padding: cng.Padding, algorithm: str
) -> None:
    message = b"header.claims"

    signature = cng.sign_digest(thumbprint, hashlib.sha256(message).digest(), padding=padding)

    assert len(signature) == 256
    verify_signature(public_key, message, signature, algorithm)


def test_assertion_is_signed_ps256_by_the_store_key(
    thumbprint: str, public_key: rsa.RSAPublicKey
) -> None:
    credential = CertStoreCredential(thumbprint.lower())

    token = credential.build_assertion(client_id="app", token_endpoint="https://login/token")

    header, claims, signing_input, signature = decode_jwt(token)
    assert (header["alg"], claims["aud"]) == ("PS256", "https://login/token")
    verify_signature(public_key, signing_input, signature, "PS256")


def test_digest_must_be_sha256(thumbprint: str) -> None:
    with pytest.raises(ValueError, match="32-byte"):
        cng.sign_digest(thumbprint, b"short", padding="pss")


def test_unknown_certificate_is_reported() -> None:
    with pytest.raises(CertificateUnavailable, match="not found in CurrentUser"):
        cng.load_certificate_der("00" * 20)


def test_missing_local_machine_certificate_is_reported() -> None:
    with pytest.raises(CertificateUnavailable, match="LocalMachine"):
        cng.sign_digest("00" * 20, b"\0" * 32, padding="pss", store_location="LocalMachine")
