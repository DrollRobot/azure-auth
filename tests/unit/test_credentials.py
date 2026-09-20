"""Unit tests for credentials, the client assertion, the cache and error mapping."""

from __future__ import annotations

import base64
import hashlib
import sys
import time
from pathlib import Path
from typing import Any

import msal
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from azure_auth import (
    AuthError,
    CacheEncryptionUnavailable,
    CertificateUnavailable,
    ConsentRequired,
    InteractionRequired,
)
from azure_auth.auth import cache as cache_module
from azure_auth.auth import cng
from azure_auth.auth.cache import build_cache, default_cache_path
from azure_auth.auth.credentials import (
    CertStoreCredential,
    PemCertificateCredential,
    SecretCredential,
    build_client_assertion,
)
from azure_auth.auth.errors import error_from_msal_result
from tests.certs import TestCertificate, decode_jwt, make_certificate, verify_signature

pytestmark = pytest.mark.unit

ENDPOINT = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
THUMBPRINT = "AB" * 20


@pytest.fixture(scope="module")
def certificate() -> TestCertificate:
    return make_certificate()


# ---------------------------------------------------------------------------- assertion


@pytest.mark.parametrize(("algorithm", "padding"), [("PS256", "pss"), ("RS256", "pkcs1")])
def test_assertion_structure_and_signature(
    certificate: TestCertificate, algorithm: str, padding: str
) -> None:
    before = int(time.time())

    token = build_client_assertion(
        client_id="app",
        token_endpoint=ENDPOINT,
        certificate_der=certificate.der,
        algorithm=algorithm,
        sign=certificate.sign(padding),
    )

    header, claims, signing_input, signature = decode_jwt(token)
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(certificate.der).digest())
    assert header == {
        "alg": algorithm,
        "typ": "JWT",
        "x5t#S256": thumbprint.rstrip(b"=").decode("ascii"),
    }
    assert (claims["aud"], claims["iss"], claims["sub"]) == (ENDPOINT, "app", "app")
    assert claims["nbf"] == claims["iat"] >= before
    assert claims["exp"] == claims["iat"] + 600
    assert len(claims["jti"]) == 36
    public_key = certificate.certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    verify_signature(public_key, signing_input, signature, algorithm)


def test_every_assertion_has_a_new_id(certificate: TestCertificate) -> None:
    def build() -> Any:
        token = build_client_assertion(
            client_id="app",
            token_endpoint=ENDPOINT,
            certificate_der=certificate.der,
            algorithm="RS256",
            sign=certificate.sign("pkcs1"),
        )
        return decode_jwt(token)[1]["jti"]

    assert build() != build()


# ---------------------------------------------------------------------------- cert store


def patch_cng(
    monkeypatch: pytest.MonkeyPatch, certificate: TestCertificate, *, refuse_pss: bool
) -> list[str]:
    """Replace the CNG calls with an in-memory key; return the list of paddings used."""
    paddings: list[str] = []

    def sign_digest(thumbprint: str, digest: bytes, *, padding: str, store_location: str) -> bytes:
        paddings.append(padding)
        if padding == "pss" and refuse_pss:
            raise cng.SignatureFailed("PSS not supported", status=0x80090029)
        signature: bytes = certificate.sign(padding)(digest)
        return signature

    monkeypatch.setattr(cng, "sign_digest", sign_digest)
    monkeypatch.setattr(cng, "load_certificate_der", lambda thumbprint, store: certificate.der)
    return paddings


def test_cert_store_credential_signs_ps256_first(
    monkeypatch: pytest.MonkeyPatch, certificate: TestCertificate
) -> None:
    paddings = patch_cng(monkeypatch, certificate, refuse_pss=False)
    credential = CertStoreCredential(THUMBPRINT)

    assertion = credential.msal_client_credential(client_id="app", token_endpoint=ENDPOINT)[
        "client_assertion"
    ]()

    header, claims, signing_input, signature = decode_jwt(assertion)
    assert (header["alg"], claims["aud"], paddings) == ("PS256", ENDPOINT, ["pss"])
    public_key = certificate.certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    verify_signature(public_key, signing_input, signature, "PS256")


def test_refused_pss_rebuilds_the_assertion_as_rs256(
    monkeypatch: pytest.MonkeyPatch, certificate: TestCertificate
) -> None:
    paddings = patch_cng(monkeypatch, certificate, refuse_pss=True)
    credential = CertStoreCredential(THUMBPRINT, "LocalMachine")

    first = credential.build_assertion(client_id="app", token_endpoint=ENDPOINT)
    second = credential.build_assertion(client_id="app", token_endpoint=ENDPOINT)

    header, _claims, signing_input, signature = decode_jwt(first)
    assert header["alg"] == "RS256"
    assert decode_jwt(second)[0]["alg"] == "RS256"
    assert paddings == ["pss", "pkcs1", "pkcs1"]
    assert credential.algorithm == "RS256"
    public_key = certificate.certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    verify_signature(public_key, signing_input, signature, "RS256")


def test_failure_with_pkcs1_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch, certificate: TestCertificate
) -> None:
    def sign_digest(*args: object, **kwargs: object) -> bytes:
        raise cng.SignatureFailed("no", status=1)

    monkeypatch.setattr(cng, "sign_digest", sign_digest)
    monkeypatch.setattr(cng, "load_certificate_der", lambda thumbprint, store: certificate.der)

    with pytest.raises(cng.SignatureFailed):
        CertStoreCredential(THUMBPRINT).build_assertion(client_id="app", token_endpoint=ENDPOINT)


def test_downgrade_reports_whether_it_changed_anything() -> None:
    credential = CertStoreCredential(THUMBPRINT)
    assert credential.downgrade_to_rs256() is True
    assert credential.downgrade_to_rs256() is False
    assert "RS256" in repr(credential)


@pytest.mark.parametrize("value", ["ab cd " * 10, "AB:" * 19 + "AB", "ab" * 20])
def test_thumbprint_is_normalised(value: str) -> None:
    assert len(cng.normalise_thumbprint(value)) == 40
    assert cng.normalise_thumbprint(value).isupper()


@pytest.mark.parametrize("value", ["", "AB" * 19, "ZZ" * 20, "AB" * 32])
def test_bad_thumbprint_is_rejected(value: str) -> None:
    with pytest.raises(CertificateUnavailable, match="SHA-1 thumbprint"):
        CertStoreCredential(value)


@pytest.mark.skipif(sys.platform == "win32", reason="covers the stub used off Windows")
def test_certificate_store_is_reported_as_unavailable_off_windows() -> None:
    with pytest.raises(CertificateUnavailable, match="Windows certificate store"):
        cng.load_certificate_der(THUMBPRINT)
    with pytest.raises(CertificateUnavailable, match="certificate_pem or certificate_pfx"):
        cng.sign_digest(THUMBPRINT, bytes(32), padding="pss")


# ---------------------------------------------------------------------------- PEM / PFX


def test_secret_credential_hides_its_value() -> None:
    credential = SecretCredential("s3cret")
    assert credential.msal_client_credential(client_id="a", token_endpoint="b") == "s3cret"
    assert "s3cret" not in repr(credential)


def test_pem_credential_lets_msal_compute_the_thumbprint(certificate: TestCertificate) -> None:
    credential = PemCertificateCredential(
        certificate.certificate_pem, certificate.private_key_pem, "passphrase"
    )

    value = credential.msal_client_credential(client_id="app", token_endpoint=ENDPOINT)

    assert value == {
        "private_key": certificate.private_key_pem,
        "public_certificate": certificate.certificate_pem,
        "passphrase": "passphrase",
    }
    assert "PRIVATE KEY" not in repr(credential)


@pytest.mark.parametrize("password", [None, "pfx-password"])
def test_pfx_is_converted_to_pem(
    certificate: TestCertificate, tmp_path: Path, password: str | None
) -> None:
    path = tmp_path / "cert.pfx"
    path.write_bytes(certificate.pfx(password))

    from_bytes = PemCertificateCredential.from_pfx(certificate.pfx(password), password)
    from_path = PemCertificateCredential.from_pfx(path, password)

    assert from_bytes.certificate_pem == certificate.certificate_pem
    assert from_path.private_key_pem == certificate.private_key_pem
    assert from_bytes.passphrase is None


def test_unreadable_pfx_is_reported(certificate: TestCertificate) -> None:
    with pytest.raises(CertificateUnavailable, match="Cannot read the PFX"):
        PemCertificateCredential.from_pfx(certificate.pfx("right"), "wrong")


# ---------------------------------------------------------------------------- cache


def test_memory_cache_is_a_plain_token_cache() -> None:
    assert type(build_cache("memory")) is msal.TokenCache


def test_unknown_cache_kind_is_rejected() -> None:
    with pytest.raises(ValueError, match="'memory' or 'disk'"):
        build_cache("plaintext")  # type: ignore[arg-type]


def test_default_cache_path_is_per_user() -> None:
    path = default_cache_path()
    assert path.name == "msal_token_cache.bin"
    assert path.parent.name == "azure-auth" or "azure-auth" in path.parts


def test_disk_cache_raises_when_encryption_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def no_libsecret(location: str) -> object:
        raise ImportError("No module named 'gi'")

    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", no_libsecret)

    with pytest.raises(CacheEncryptionUnavailable, match="cache='memory'"):
        build_cache("disk", tmp_path / "cache.bin")


def test_disk_cache_refuses_unencrypted_persistence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Plaintext:
        is_encrypted = False

    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", lambda location: Plaintext())

    with pytest.raises(CacheEncryptionUnavailable, match="not encrypted"):
        build_cache("disk", tmp_path / "cache.bin")


def test_package_never_references_plaintext_persistence() -> None:
    source = Path(cache_module.__file__).parent.parent
    offenders = [
        path.name
        for path in source.rglob("*.py")
        if "FilePersistence(" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


# ---------------------------------------------------------------------------- error mapping


def test_missing_result_means_interaction_required() -> None:
    error = error_from_msal_result(None, tenant_id="t", scopes=["a"])
    assert isinstance(error, InteractionRequired)
    assert (error.tenant_id, error.scopes) == ("t", ("a",))


@pytest.mark.parametrize(
    "result",
    [
        {"error": "invalid_grant", "suberror": "consent_required"},
        {"error": "invalid_grant", "classification": "consent_required"},
        {"error": "consent_required"},
        {"error": "invalid_grant", "error_codes": [65001]},
        {"error": "invalid_client", "error_codes": ["650057"]},
    ],
)
def test_consent_errors_are_recognised(result: dict[str, Any]) -> None:
    error = error_from_msal_result(result, tenant_id="customer", scopes=["User.Read.All"])
    assert isinstance(error, ConsentRequired)
    assert error.tenant_id == "customer"


@pytest.mark.parametrize("code", ["interaction_required", "login_required", "invalid_grant"])
def test_interaction_errors_are_recognised(code: str) -> None:
    error = error_from_msal_result({"error": code}, tenant_id="t", scopes=[])
    assert isinstance(error, InteractionRequired)


def test_other_errors_keep_their_description_but_not_the_dictionary() -> None:
    error = error_from_msal_result(
        {"error": "invalid_client", "error_description": " AADSTS7000215: bad secret ", "x": 1},
        tenant_id="t",
        scopes=[],
    )
    assert type(error) is AuthError
    assert str(error) == "invalid_client: AADSTS7000215: bad secret"
