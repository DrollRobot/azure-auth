"""Blocking version of the Key Vault wrapper. Needs the ``keyvault`` extra."""

from __future__ import annotations

from azure_auth._sync.keyvault import KeyVaultClient

__all__ = ["KeyVaultClient"]
