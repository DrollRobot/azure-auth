"""Thin asynchronous clients, one per resource.

``KeyVaultClient`` lives in :mod:`azure_auth.clients.keyvault` and is not imported here,
because it needs the optional ``keyvault`` extra.
"""

from __future__ import annotations

from azure_auth.clients.arm import AzureClient
from azure_auth.clients.base import ResourceClient
from azure_auth.clients.errors import AzureError, GraphError, InvokeCommandError, ResourceError
from azure_auth.clients.exchange import ExchangeClient
from azure_auth.clients.graph import GraphClient
from azure_auth.clients.invoke_command import InvokeCommandClient
from azure_auth.clients.ipps import IppsClient

__all__ = [
    "AzureClient",
    "AzureError",
    "ExchangeClient",
    "GraphClient",
    "GraphError",
    "InvokeCommandClient",
    "InvokeCommandError",
    "IppsClient",
    "ResourceClient",
    "ResourceError",
]
