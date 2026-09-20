"""Exceptions raised while acquiring tokens.

MSAL reports failures as result dictionaries. Those dictionaries never reach callers of this
package; :func:`error_from_msal_result` turns them into the exception hierarchy below.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

# AADSTS codes that mean "an administrator or the user has not consented to this application".
_CONSENT_ERROR_CODES = frozenset({65001, 65004, 650052, 650056, 650057})
_CONSENT_MARKERS = frozenset({"consent_required"})
_INTERACTION_ERRORS = frozenset({"interaction_required", "login_required", "invalid_grant"})


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


def error_from_msal_result(
    result: Mapping[str, Any] | None,
    *,
    tenant_id: str,
    scopes: Sequence[str],
) -> AuthError:
    """Translate a failed MSAL result into an exception.

    Args:
        result: The dictionary MSAL returned, or ``None`` when MSAL found nothing to return.
        tenant_id: Tenant the token was requested from.
        scopes: Scopes that were requested.

    Returns:
        The exception to raise. The MSAL dictionary itself is never exposed.
    """
    if not result:
        return InteractionRequired(
            f"No cached token for tenant {tenant_id}; the user must sign in.",
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
    if error in _INTERACTION_ERRORS:
        return InteractionRequired(message, tenant_id=tenant_id, scopes=scopes)
    return AuthError(message)
