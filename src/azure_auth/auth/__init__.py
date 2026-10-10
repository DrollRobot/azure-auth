"""Token acquisition: the context, the tenant, credentials, cache and errors."""

from __future__ import annotations

from azure_auth.auth.context import AsyncAuthContext, AuthContext
from azure_auth.auth.errors import (
    AccountSelectionRequired,
    AmbiguousTenant,
    AuthError,
    BrokerUnavailable,
    CacheEncryptionUnavailable,
    CertificateUnavailable,
    ConsentRequired,
    InteractionRequired,
    TenantNotFound,
)
from azure_auth.auth.tenant import Tenant

__all__ = [
    "AccountSelectionRequired",
    "AmbiguousTenant",
    "AsyncAuthContext",
    "AuthContext",
    "AuthError",
    "BrokerUnavailable",
    "CacheEncryptionUnavailable",
    "CertificateUnavailable",
    "ConsentRequired",
    "InteractionRequired",
    "Tenant",
    "TenantNotFound",
]
