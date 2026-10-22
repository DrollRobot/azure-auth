"""Unit tests for credentials, the client assertion, the cache and error mapping."""

from __future__ import annotations

import base64
import datetime
import hashlib
import sys
import time
from pathlib import Path
from typing import Any

import msal
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID

from azure_auth import (
    AuthError,
    CacheEncryptionUnavailable,
    CertificateUnavailable,
    ConsentRequired,
    InteractionRequired,
    Tenant,
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
from azure_auth.auth.errors import entra_error_codes, error_from_msal_result
from azure_auth.clouds import COMMERCIAL
from azure_auth.constants import GRAPH_CLI_CLIENT_ID
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
    monkeypatch: pytest.MonkeyPatch,
    certificate: TestCertificate,
    *,
    refuse_pss: bool,
    pss_salt_length: int = 32,
) -> list[str]:
    """Replace the CNG calls with an in-memory key; return the list of paddings used."""
    paddings: list[str] = []

    def sign_digest(thumbprint: str, digest: bytes, *, padding: str, store_location: str) -> bytes:
        paddings.append(padding)
        if padding == "pss" and refuse_pss:
            raise cng.SignatureFailed("PSS not supported", status=0x80090029)
        if padding == "pss" and pss_salt_length != 32:
            pss = PSS(mgf=MGF1(hashes.SHA256()), salt_length=pss_salt_length)
            return certificate.key.sign(digest, pss, Prehashed(hashes.SHA256()))
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
    assert "RS256" in repr(credential)
    public_key = certificate.certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    verify_signature(public_key, signing_input, signature, "RS256")


def test_pss_with_the_wrong_salt_length_rebuilds_the_assertion_as_rs256(
    monkeypatch: pytest.MonkeyPatch, certificate: TestCertificate
) -> None:
    # A TPM 2.0 outside FIPS mode signs PSS with the longest salt the key allows (222 bytes
    # for RSA 2048 with SHA-256) and reports success. Entra ID would reject it as PS256.
    paddings = patch_cng(monkeypatch, certificate, refuse_pss=False, pss_salt_length=222)
    credential = CertStoreCredential(THUMBPRINT)

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


def test_a_certificate_without_an_rsa_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "azure-auth ec test")])
    now = datetime.datetime.now(datetime.UTC)
    der = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    monkeypatch.setattr(cng, "load_certificate_der", lambda thumbprint, store: der)

    with pytest.raises(CertificateUnavailable, match="does not hold an RSA key"):
        CertStoreCredential(THUMBPRINT).build_assertion(client_id="app", token_endpoint=ENDPOINT)


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

TENANT = Tenant("11111111-2222-3333-4444-555555555555", COMMERCIAL)


def test_missing_result_means_interaction_required() -> None:
    error = error_from_msal_result(None, tenant=TENANT, scopes=["a"])
    assert isinstance(error, InteractionRequired)
    assert (error.tenant_id, error.scopes) == (TENANT.id, ("a",))


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
    error = error_from_msal_result(result, tenant=TENANT, scopes=["User.Read.All"])
    assert isinstance(error, ConsentRequired)
    assert error.tenant_id == TENANT.id


@pytest.mark.parametrize("code", ["interaction_required", "login_required", "invalid_grant"])
def test_interaction_errors_are_recognised(code: str) -> None:
    error = error_from_msal_result({"error": code}, tenant=TENANT, scopes=[])
    assert isinstance(error, InteractionRequired)
    assert error.error_codes == frozenset()


# Entra's answer to a refresh in a customer tenant whose policy wants newer MFA, in the shape
# MSAL returns it (seen live 2026-10-22; the ids and claims are made up).
STALE_MFA = {
    "error": "invalid_grant",
    "error_description": "AADSTS50078: Presented multi-factor authentication has expired due "
    "to policies configured by your administrator. Trace ID: trace-1 Correlation ID: corr-1 "
    "Timestamp: 2026-10-22 06:58:41Z",
    "error_codes": [50078],
    "suberror": "basic_action",
    "correlation_id": "corr-1",
    "trace_id": "trace-1",
    "claims": '{"access_token":{"capolids":{"essential":true,"values":["p1"]}}}',
}


@pytest.mark.parametrize(
    ("result", "kind"),
    [
        (STALE_MFA, InteractionRequired),
        ({**STALE_MFA, "error_codes": [65001]}, ConsentRequired),
        ({**STALE_MFA, "error": "invalid_client"}, AuthError),
    ],
    ids=["interaction", "consent", "other"],
)
def test_every_error_carries_entras_answer_in_its_fields(
    result: dict[str, Any], kind: type[AuthError]
) -> None:
    error = error_from_msal_result(result, tenant=TENANT, scopes=["a"])
    assert type(error) is kind
    assert (
        error.error,
        error.error_codes,
        error.suberror,
        error.correlation_id,
        error.trace_id,
        error.claims,
    ) == (
        result["error"],
        frozenset(result["error_codes"]),
        "basic_action",
        "corr-1",
        "trace-1",
        result["claims"],
    )
    # The message is Entra's, whole.
    assert str(error) == f"{result['error']}: {result['error_description']}"


def test_an_error_entra_gave_no_answer_for_has_empty_fields() -> None:
    error = error_from_msal_result(None, tenant=TENANT, scopes=["a"])
    assert (error.error, error.error_codes, error.correlation_id, error.claims) == (
        None,
        frozenset(),
        None,
        None,
    )
    assert AuthError("x").error_codes == frozenset()


def test_the_brokers_answer_gives_its_error_codes_and_sub_error() -> None:
    error = error_from_msal_result(BROKER_CONSENT_PII_ON, tenant=TENANT, scopes=["a"])
    assert (error.error, error.error_codes, error.suberror, error.trace_id) == (
        "broker_error",
        frozenset({65001}),
        "consent_required",
        None,
    )


def broker_error(status: str) -> dict[str, Any]:
    """Build what MSAL returns for a broker failure: the status only in the description."""
    return {
        "error": "broker_error",
        "error_description": f"(pii). Status: Response_Status.{status}, Error code: 1, Tag: 2",
    }


@pytest.mark.parametrize("status", ["Status_InteractionRequired", "Status_AccountUnusable"])
def test_broker_statuses_that_need_a_sign_in_are_interaction_required(status: str) -> None:
    error = error_from_msal_result(broker_error(status), tenant=TENANT, scopes=["a"])
    assert isinstance(error, InteractionRequired)
    assert status in str(error)


@pytest.mark.parametrize("status", ["Status_UserCanceled", "Status_Unexpected"])
def test_other_broker_statuses_are_plain_errors(status: str) -> None:
    error = error_from_msal_result(broker_error(status), tenant=TENANT, scopes=["a"])
    assert type(error) is AuthError


# Entra's answer to a silent broker request for a scope the tenant never granted, and what MSAL
# made of it with the broker's PII logging on and off (measured 2026-10-17).
ENTRA_CONSENT_TEXT = (
    "AADSTS65001: The user or administrator has not consented to use the application with ID "
    f"'{GRAPH_CLI_CLIENT_ID}' named 'Microsoft Graph Command Line Tools'. Send an interactive "
    "authorization request for this user and resource. Trace ID: <guid> Correlation ID: <guid> "
    "Timestamp: 2026-10-17 06:49:06Z"
)
BROKER_ENDING = (
    ". Status: Response_Status.Status_InteractionRequired, Error code: 3399614476, Tag: 557973645"
)
BROKER_CONSENT_PII_ON = {
    "error": "broker_error",
    "error_description": (
        f"SubError: consent_required V2Error: invalid_grant {ENTRA_CONSENT_TEXT}{BROKER_ENDING}"
    ),
}
BROKER_CONSENT_PII_OFF = {"error": "broker_error", "error_description": f"(pii){BROKER_ENDING}"}


def test_missing_consent_through_the_broker_is_consent_required_in_entras_words() -> None:
    error = error_from_msal_result(BROKER_CONSENT_PII_ON, tenant=TENANT, scopes=["User.Read.All"])
    assert isinstance(error, ConsentRequired)
    assert str(error) == (
        f"{ENTRA_CONSENT_TEXT} (broker: Status_InteractionRequired, SubError: consent_required)"
    )


def test_a_broker_error_without_a_sub_error_names_only_the_status() -> None:
    result = {
        "error": "broker_error",
        "error_description": f"AADSTS50105: The user is not assigned{BROKER_ENDING}",
    }
    error = error_from_msal_result(result, tenant=TENANT, scopes=["a"])
    assert str(error) == (
        "AADSTS50105: The user is not assigned (broker: Status_InteractionRequired)"
    )


def test_a_broker_error_without_entras_text_keeps_the_brokers_description() -> None:
    error = error_from_msal_result(BROKER_CONSENT_PII_OFF, tenant=TENANT, scopes=["a"])
    assert type(error) is InteractionRequired
    assert str(error) == f"broker_error: (pii){BROKER_ENDING}"


def test_the_broker_and_the_browser_give_entras_words_for_the_same_error() -> None:
    browser = {
        "error": "invalid_grant",
        "error_description": ENTRA_CONSENT_TEXT,
        "error_codes": [65001],
        "suberror": "consent_required",
    }
    errors = [
        error_from_msal_result(result, tenant=TENANT, scopes=["a"])
        for result in (browser, BROKER_CONSENT_PII_ON)
    ]
    assert [type(error) for error in errors] == [ConsentRequired, ConsentRequired]
    assert str(errors[0]) == f"invalid_grant: {ENTRA_CONSENT_TEXT}"
    assert str(errors[1]).startswith(ENTRA_CONSENT_TEXT)


@pytest.mark.parametrize(
    ("result", "codes"),
    [
        (None, set()),
        ({"error": "invalid_grant", "error_codes": [50076, "x"]}, {50076}),
        (BROKER_CONSENT_PII_ON, {65001}),
        (BROKER_CONSENT_PII_OFF, set()),
    ],
)
def test_entras_codes_are_read_from_the_browser_and_the_broker(
    result: dict[str, Any] | None, codes: set[int]
) -> None:
    assert entra_error_codes(result) == codes


def test_other_errors_keep_their_description_but_not_the_dictionary() -> None:
    error = error_from_msal_result(
        {"error": "invalid_client", "error_description": " AADSTS7000215: bad secret ", "x": 1},
        tenant=TENANT,
        scopes=[],
    )
    assert type(error) is AuthError
    assert str(error) == "invalid_client: AADSTS7000215: bad secret"
