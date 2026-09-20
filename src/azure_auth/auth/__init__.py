"""Token acquisition: the authentication context, credentials, cache and errors."""

from __future__ import annotations

from azure_auth.auth.context import AsyncAuthContext, AuthContext
from azure_auth.auth.errors import (
    AccountSelectionRequired,
    AuthError,
    BrokerUnavailable,
    CacheEncryptionUnavailable,
    CertificateUnavailable,
    ConsentRequired,
    InteractionRequired,
)

__all__ = [
    "AccountSelectionRequired",
    "AsyncAuthContext",
    "AuthContext",
    "AuthError",
    "BrokerUnavailable",
    "CacheEncryptionUnavailable",
    "CertificateUnavailable",
    "ConsentRequired",
    "InteractionRequired",
]
