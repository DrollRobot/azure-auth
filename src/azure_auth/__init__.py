"""Authentication helpers and thin clients for Microsoft cloud services.

Create one :class:`AuthContext`, hand it to the client for the resource you need, and make
requests; the client takes care of tokens. The clients exported here are asynchronous.
Blocking versions with the same names live in :mod:`azure_auth.sync`.

A context works in whichever Microsoft cloud its tenant lives in, found by looking the tenant
up; the clouds are in :mod:`azure_auth.clouds`.

Example:
    >>> from azure_auth import AuthContext, GraphClient
    >>> auth = AuthContext("contoso.com", username="admin@contoso.com")  # doctest: +SKIP
    >>> graph = GraphClient(auth, scopes=["User.Read.All"])  # doctest: +SKIP
    >>> graph.client_id  # doctest: +SKIP
    '14d82eec-204b-4c2f-b7e8-296a70dab67e'
"""

from __future__ import annotations

from azure_auth.auth import (
    AccountSelectionRequired,
    AmbiguousTenant,
    AsyncAuthContext,
    AuthContext,
    AuthError,
    BrokerUnavailable,
    CacheEncryptionUnavailable,
    CertificateUnavailable,
    ConsentRequired,
    InteractionRequired,
    TenantNotFound,
    discover_tenant,
)
from azure_auth.clients import (
    AzureClient,
    AzureError,
    ExchangeClient,
    GraphClient,
    GraphError,
    InvokeCommandError,
    IppsClient,
    ResourceError,
)
from azure_auth.clouds import Cloud, TenantInfo

__all__ = [
    "AccountSelectionRequired",
    "AmbiguousTenant",
    "AsyncAuthContext",
    "AuthContext",
    "AuthError",
    "AzureClient",
    "AzureError",
    "BrokerUnavailable",
    "CacheEncryptionUnavailable",
    "CertificateUnavailable",
    "Cloud",
    "ConsentRequired",
    "ExchangeClient",
    "GraphClient",
    "GraphError",
    "InteractionRequired",
    "InvokeCommandError",
    "IppsClient",
    "ResourceError",
    "TenantInfo",
    "TenantNotFound",
    "discover_tenant",
]
