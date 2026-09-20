"""Authentication helpers and thin clients for Microsoft cloud services.

Create one :class:`AuthContext`, hand it to the client for the resource you need, and make
requests; the client takes care of tokens. The clients exported here are asynchronous.
Blocking versions with the same names live in :mod:`azure_auth.sync`.

Example:
    >>> from azure_auth import AuthContext, GraphClient
    >>> auth = AuthContext("contoso.onmicrosoft.com", username="admin@contoso.com")
    >>> graph = GraphClient(auth, scopes=["User.Read.All"])
    >>> graph.client_id
    '14d82eec-204b-4c2f-b7e8-296a70dab67e'
"""

from __future__ import annotations

from azure_auth.auth import (
    AccountSelectionRequired,
    AsyncAuthContext,
    AuthContext,
    AuthError,
    BrokerUnavailable,
    CacheEncryptionUnavailable,
    CertificateUnavailable,
    ConsentRequired,
    InteractionRequired,
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

__all__ = [
    "AccountSelectionRequired",
    "AsyncAuthContext",
    "AuthContext",
    "AuthError",
    "AzureClient",
    "AzureError",
    "BrokerUnavailable",
    "CacheEncryptionUnavailable",
    "CertificateUnavailable",
    "ConsentRequired",
    "ExchangeClient",
    "GraphClient",
    "GraphError",
    "InteractionRequired",
    "InvokeCommandError",
    "IppsClient",
    "ResourceError",
]
