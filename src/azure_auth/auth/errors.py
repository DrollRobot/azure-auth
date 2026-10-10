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
    """

    def __init__(self, message: str, *, tenant_id: str, scopes: Sequence[str] = ()) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            tenant_id: Tenant in which consent is missing.
            scopes: Scopes that were requested.
        """
        super().__init__(message)
        self.tenant_id = tenant_id
        self.scopes = tuple(scopes)


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
    codes = {int(code) for code in result.get("error_codes", ()) if str(code).isdigit()}
    message = f"{error}: {description}" if description else error

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
