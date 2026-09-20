"""Blocking versions of the resource clients.

These mirror :mod:`azure_auth.clients` one to one: same classes, same methods, no ``await``.
They are generated from the asynchronous clients, so behaviour is identical.

Example:
    >>> from azure_auth import AuthContext
    >>> from azure_auth.sync import GraphClient
    >>> auth = AuthContext("contoso.onmicrosoft.com", username="admin@contoso.com")
    >>> with GraphClient(auth, scopes=["User.Read.All"]) as graph:  # doctest: +SKIP
    ...     users = graph.get_all("/users")

``KeyVaultClient`` needs the optional ``keyvault``
extra; import it from :mod:`azure_auth.sync.keyvault`.
"""

from __future__ import annotations

from azure_auth._sync import (
    AzureClient,
    ExchangeClient,
    GraphClient,
    InvokeCommandClient,
    IppsClient,
    ResourceClient,
)

__all__ = [
    "AzureClient",
    "ExchangeClient",
    "GraphClient",
    "InvokeCommandClient",
    "IppsClient",
    "ResourceClient",
]
