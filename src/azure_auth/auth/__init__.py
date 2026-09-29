"""Token acquisition: the context, tenant discovery, credentials, cache and errors."""

from __future__ import annotations

from azure_auth.auth.context import AsyncAuthContext, AuthContext
from azure_auth.auth.discovery import discover_tenant
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
    "TenantNotFound",
    "discover_tenant",
]
