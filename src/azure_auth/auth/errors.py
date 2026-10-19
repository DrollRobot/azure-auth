"""Exceptions raised while acquiring tokens.

MSAL reports failures as result dictionaries. Those dictionaries never reach callers of this
package; :func:`error_from_msal_result` turns them into the exception hierarchy below.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from azure_auth.auth.tenant import Tenant

# AADSTS codes that mean "an administrator or the user has not consented to this application".
_CONSENT_ERROR_CODES = frozenset({65001, 65004, 650052, 650056, 650057})
_CONSENT_MARKERS = frozenset({"consent_required"})
_INTERACTION_ERRORS = frozenset({"interaction_required", "login_required", "invalid_grant"})

# What Entra sends when a browser sign-in ends without a token. Observed against a live tenant
# on 2026-09-20: a user who may not consent is shown "Need admin approval", and leaving that
# page returns a bare ``access_denied`` -- no AADSTS code, no description, nothing to
# distinguish it from someone pressing Cancel on an ordinary consent screen. So it cannot be
# classified as a consent failure, and the message has to cover both readings.
_DECLINED_ERRORS = frozenset({"access_denied"})

# MSAL reports every failure of the Windows broker as ``broker_error`` and drops the broker's
# own status, which survives only in the description as ``Status: Response_Status.<name>``
# (msal 1.39 ``broker.py``; seen live 2026-09-29).
_BROKER_STATUS = re.compile(r"Status: (?:Response_Status\.)?(Status_\w+)")

# Broker statuses that mean somebody has to sign in: the two MSAL itself answers by opening the
# broker's window (msal 1.39 ``application.py``). Status_InteractionRequired seen live
# 2026-09-29, for an application the broker held no sign-in for.
_BROKER_INTERACTION_STATUSES = frozenset({"Status_InteractionRequired", "Status_AccountUnusable"})

# MSAL writes a broker failure's description as "<broker text>. Status: <status>, Error code:
# <n>, Tag: <n>" (msal 1.39 ``broker.py``). With the broker's PII logging on (context.py), the
# broker text is Entra's answer, such as "SubError: consent_required V2Error: invalid_grant
# AADSTS65001: The user or administrator has not consented ..."; with it off, "(pii)" (seen
# live 2026-10-17). The broker's error code and tag name a place in the broker's code, not a
# reason: one error code covered four different Entra errors in one run. The sub-error is kept
# in the message: it can say what Entra wants, such as ``user_password_expired``.
_BROKER_TEXT_END = ". Status: "
_BROKER_MARKERS = re.compile(r"(?:SubError|V2Error): (\w+)")
_BROKER_SUBERROR = re.compile(r"SubError: (\w+)")
_ENTRA_CODE = re.compile(r"AADSTS(\d+)")


class AuthError(Exception):
    """Base class for every authentication failure raised by this package."""


class InteractionRequired(AuthError):
    """A token could not be obtained silently and the user must sign in.

    Attributes:
        tenant_id: Tenant the token was requested from.
        scopes: Scopes that were requested.
    """

    def __init__(self, message: str, *, tenant_id: str, scopes: Sequence[str] = ()) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            tenant_id: Tenant the token was requested from.
            scopes: Scopes that were requested.
        """
        super().__init__(message)
        self.tenant_id = tenant_id
        self.scopes = tuple(scopes)


class ConsentRequired(AuthError):
    """The application lacks consent for the requested scopes in the tenant.

    Attributes:
        tenant_id: Tenant in which consent is missing.
        scopes: Scopes that were requested.
        granted: Short names of the scopes the tenant has granted the application, when that
            was checked (the Graph client checks before asking for named scopes); else empty.
        missing: Short names of the requested scopes the tenant has not granted, when that
            was checked; else empty.
    """

    def __init__(
        self,
        message: str,
        *,
        tenant_id: str,
        scopes: Sequence[str] = (),
        granted: Sequence[str] = (),
        missing: Sequence[str] = (),
    ) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            tenant_id: Tenant in which consent is missing.
            scopes: Scopes that were requested.
            granted: Short names of the scopes the tenant has granted, if known.
            missing: Short names of the requested scopes it has not granted, if known.
        """
        super().__init__(message)
        self.tenant_id = tenant_id
        self.scopes = tuple(scopes)
        self.granted = tuple(granted)
        self.missing = tuple(missing)


class AccountSelectionRequired(AuthError):
    """More than one cached account matches the configured username."""


class CertificateUnavailable(AuthError):
    """The configured certificate or its private key cannot be used."""


class CacheEncryptionUnavailable(AuthError):
    """An encrypted disk cache was requested but this platform cannot encrypt it."""


class BrokerUnavailable(AuthError):
    """The authentication broker was required but cannot be used."""


class TenantNotFound(AuthError):
    """No tenant by that id or domain name exists in the clouds that were asked.

    Attributes:
        name: The tenant id or domain name that was looked up.
    """

    def __init__(self, message: str, *, name: str) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            name: The tenant id or domain name that was looked up.
        """
        super().__init__(message)
        self.name = name


class AmbiguousTenant(AuthError):
    """A tenant id or domain name belongs to a different tenant in each of several clouds.

    Each cloud is a separate directory: a domain can be verified in a commercial tenant and
    in a China tenant, and a GUID can be both a commercial and a US government tenant. Look
    the name up with its cloud to choose: ``Tenant.lookup(name, cloud)``.

    Attributes:
        name: The tenant id or domain name that was looked up.
        candidates: One entry per tenant found.
    """

    def __init__(self, message: str, *, name: str, candidates: Sequence[Tenant]) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            name: The tenant id or domain name that was looked up.
            candidates: One entry per tenant found.
        """
        super().__init__(message)
        self.name = name
        self.candidates = tuple(candidates)


def broker_status(result: Mapping[str, Any] | None) -> str | None:
    """Read the Windows broker's own status out of a failed MSAL result.

    Args:
        result: The dictionary MSAL returned, or ``None``.

    Returns:
        The status, such as ``Status_UserCanceled``, or ``None`` when the result is not a
        broker failure or names no status.
    """
    if not result or result.get("error") != "broker_error":
        return None
    match = _BROKER_STATUS.search(str(result.get("error_description", "")))
    return match.group(1) if match else None


def _broker_text(result: Mapping[str, Any] | None) -> str:
    """Read the broker's own text out of a failed MSAL result.

    Args:
        result: The dictionary MSAL returned, or ``None``.

    Returns:
        The description without MSAL's status, error code and tag, or an empty string when
        the result is not a broker failure.
    """
    if not result or result.get("error") != "broker_error":
        return ""
    return str(result.get("error_description", "")).rpartition(_BROKER_TEXT_END)[0]


def _entra_reason(result: Mapping[str, Any] | None) -> str:
    """Read Entra's own error out of a broker failure: ``AADSTS<code>: <message>``.

    Args:
        result: The dictionary MSAL returned, or ``None``.

    Returns:
        Entra's error, or an empty string when the result is not a broker failure or the
        broker gave no AADSTS text, as with its PII logging off.
    """
    text = _broker_text(result)
    start = text.find("AADSTS")
    return text[start:].strip() if start >= 0 else ""


def entra_error_codes(result: Mapping[str, Any] | None) -> frozenset[int]:
    """Read the AADSTS codes Entra gave for a failed MSAL result.

    A browser sign-in's result lists them in ``error_codes``. The broker's has them only in its
    description, and only with the broker's PII logging on.

    Args:
        result: The dictionary MSAL returned, or ``None``.

    Returns:
        The codes; empty when Entra gave none, or there was no result.
    """
    if not result:
        return frozenset()
    codes = {int(code) for code in result.get("error_codes", ()) if str(code).isdigit()}
    codes.update(int(code) for code in _ENTRA_CODE.findall(_entra_reason(result)))
    return frozenset(codes)


def error_from_msal_result(
    result: Mapping[str, Any] | None,
    *,
    tenant: Tenant,
    scopes: Sequence[str],
) -> AuthError:
    """Translate a failed MSAL result into an exception.

    Args:
        result: The dictionary MSAL returned, or ``None`` when MSAL found nothing to return.
        tenant: Tenant the token was requested from.
        scopes: Scopes that were requested.

    Returns:
        The exception to raise. The MSAL dictionary itself is never exposed.
    """
    tenant_id = tenant.id
    if not result:
        return InteractionRequired(
            f"No cached token for tenant {tenant}; the user must sign in.",
            tenant_id=tenant_id,
            scopes=scopes,
        )

    error = str(result.get("error", "unknown_error"))
    description = str(result.get("error_description", "")).strip()
    markers = {error, str(result.get("suberror", "")), str(result.get("classification", ""))}
    markers.update(_BROKER_MARKERS.findall(_broker_text(result)))
    codes = entra_error_codes(result)
    message = f"{error}: {description}" if description else error
    reason = _entra_reason(result)
    if reason:
        broker = f"broker: {broker_status(result)}"
        suberror = _BROKER_SUBERROR.search(_broker_text(result))
        if suberror:
            broker += f", SubError: {suberror.group(1)}"
        message = f"{reason} ({broker})"

    if markers & _CONSENT_MARKERS or codes & _CONSENT_ERROR_CODES:
        return ConsentRequired(message, tenant_id=tenant_id, scopes=scopes)
    if error in _INTERACTION_ERRORS or broker_status(result) in _BROKER_INTERACTION_STATUSES:
        return InteractionRequired(message, tenant_id=tenant_id, scopes=scopes)
    if error in _DECLINED_ERRORS:
        return AuthError(
            f"{message}. No token was issued for {' '.join(scopes) or '(no scopes)'} in tenant "
            f"{tenant}. Either the sign-in was cancelled, or the account is not allowed to "
            "consent to these scopes and was shown 'Need admin approval' -- in which case an "
            "administrator has to grant them before this account can use them."
        )
    return AuthError(message)
